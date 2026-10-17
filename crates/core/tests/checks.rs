//! Declarative checks run through the real active-scan engine against an in-test server.

use std::io::{Read, Write};
use std::net::TcpListener;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use brainproxy_core::checks;
use brainproxy_core::guard::{Guard, ScopeSpec};
use brainproxy_core::http::{SendOptions, Target};
use brainproxy_core::jobs::JobControl;
use brainproxy_core::scan::active::{self, ActiveConfig, ActiveSummary, PointOptions, ScanTarget, Strength};

/// Serves `respond(full request text)`; returns the port and every request seen.
fn spawn<F>(respond: F) -> (u16, Arc<Mutex<Vec<String>>>)
where
    F: Fn(&str) -> String + Send + Sync + 'static,
{
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let seen = Arc::new(Mutex::new(Vec::new()));
    let (respond, log) = (Arc::new(respond), seen.clone());
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut s) = stream else { continue };
            let (respond, log) = (respond.clone(), log.clone());
            std::thread::spawn(move || {
                let mut buf = Vec::new();
                let mut chunk = [0u8; 8192];
                loop {
                    let n = s.read(&mut chunk).unwrap_or(0);
                    buf.extend_from_slice(&chunk[..n]);
                    let text = String::from_utf8_lossy(&buf).to_string();
                    let Some(end) = text.find("\r\n\r\n") else {
                        if n == 0 {
                            return;
                        }
                        continue;
                    };
                    let len = text[..end]
                        .lines()
                        .find_map(|l| {
                            l.to_ascii_lowercase()
                                .strip_prefix("content-length:")
                                .map(|v| v.trim().parse().unwrap_or(0))
                        })
                        .unwrap_or(0usize);
                    if buf.len() >= end + 4 + len || n == 0 {
                        break;
                    }
                }
                let req = String::from_utf8_lossy(&buf).to_string();
                log.lock().unwrap().push(req.clone());
                let _ = s.write_all(respond(&req).as_bytes());
            });
        }
    });
    (port, seen)
}

fn resp(status: &str, headers: &str, body: &str) -> String {
    format!("HTTP/1.1 {status}\r\n{headers}Content-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len())
}

fn tmp(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("bp-checks-e2e-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn run(port: u16, path: &str, templates: &[(&str, &str)]) -> ActiveSummary {
    let dir = tmp(&format!("t{port}"));
    for (name, text) in templates {
        std::fs::write(dir.join(name), text).unwrap();
    }
    let loaded = checks::load(std::slice::from_ref(&dir)).unwrap();
    assert!(loaded.skipped.is_empty(), "{:?}", loaded.skipped);
    let target = Target::from_url(&format!("http://127.0.0.1:{port}{path}")).unwrap();
    let request = format!("GET {path} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nCookie: sid=abc\r\n\r\n");
    let guard =
        Guard::from_specs(vec![ScopeSpec { name: None, include: vec!["127.0.0.1".into()], exclude: vec![] }]).unwrap();
    let cfg = ActiveConfig {
        strength: Strength::Medium,
        concurrency: 4,
        rate: None,
        send: SendOptions { timeout: Duration::from_secs(5), verify_tls: false, sni: None, guard: Some(guard) },
        points: PointOptions::default(),
        rules: None,
        exclude_rules: vec![],
        no_rules: true,
        checks: checks::into_rules(loaded.checks),
        max_duration: None,
        auth: None,
        oob: None,
        oob_wait: Duration::ZERO,
    };
    let targets = vec![ScanTarget {
        history_id: None,
        target,
        request: request.into_bytes(),
        response: resp("200 OK", "Content-Type: text/html\r\n", "<html>welcome</html>").into_bytes(),
        duration_ms: None,
    }];
    let project = dir.join("p.bpdb");
    let rt = tokio::runtime::Builder::new_multi_thread().enable_all().build().unwrap();
    rt.block_on(active::run(&project, targets, cfg, JobControl::default())).unwrap()
}

const GIT: &str = r#"
id: git-config
info: {name: Git Config, severity: medium, tags: git}
http:
  - method: GET
    path: ["{{BaseURL}}/.git/config"]
    matchers-condition: and
    matchers:
      - type: word
        words: ["[core]"]
      - type: status
        status: [200]
"#;

const LOGIN: &str = r#"
id: default-login
info: {name: Default Login, severity: high}
http:
  - raw:
      - |
        POST /login HTTP/1.1
        Host: {{Hostname}}
        Content-Type: application/x-www-form-urlencoded

        user={{username}}&pass={{password}}
    attack: clusterbomb
    payloads:
      username: [admin, root]
      password: [admin, secret, toor]
    stop-at-first-match: true
    matchers-condition: and
    matchers:
      - type: word
        part: header
        words: ["session="]
      - type: status
        status: [302]
"#;

const CHAIN: &str = r#"
id: token-chain
info: {name: Token chain, severity: low}
http:
  - path: ["{{BaseURL}}/token"]
    extractors:
      - type: regex
        name: tok
        internal: true
        group: 1
        regex: ['"token":"([a-z0-9]+)"']
  - path: ["{{BaseURL}}/admin?t={{tok}}"]
    matchers:
      - type: word
        words: ["admin panel"]
    extractors:
      - type: kval
        kval: [x_version]
"#;

const NEGATIVE: &str = r#"
id: not-here
info: {name: Should not match, severity: info}
http:
  - path: ["{{BaseURL}}/.env", "{{BaseURL}}/other.example/x"]
    matchers:
      - type: word
        words: ["DB_PASSWORD"]
      - type: regex
        part: body
        regex: ["welcome"]
        negative: true
"#;

#[test]
fn nuclei_templates_find_issues() {
    let (port, seen) = spawn(|req| {
        let line = req.lines().next().unwrap_or("");
        match line.split(' ').nth(1).unwrap_or("") {
            "/.git/config" => resp("200 OK", "", "[core]\n\tbare = false\n"),
            "/login" if req.contains("user=root&pass=toor") => {
                resp("302 Found", "Set-Cookie: session=1\r\nLocation: /\r\n", "")
            }
            "/login" => resp("200 OK", "", "bad login"),
            "/token" => resp("200 OK", "", r#"{"token":"abc123"}"#),
            "/admin?t=abc123" => resp("200 OK", "X-Version: 9.1\r\n", "admin panel"),
            _ => resp("404 Not Found", "", "welcome"),
        }
    });
    let s = run(port, "/", &[("git.yaml", GIT), ("login.yaml", LOGIN), ("chain.yaml", CHAIN), ("neg.yaml", NEGATIVE)]);
    assert_eq!(s.raised.get("check:git-config"), Some(&1), "{s:?}");
    assert_eq!(s.raised.get("check:default-login"), Some(&1), "{s:?}");
    assert_eq!(s.raised.get("check:token-chain"), Some(&1), "{s:?}");
    assert!(!s.raised.contains_key("check:not-here"), "{s:?}");

    let seen = seen.lock().unwrap();
    // Raw requests get CRLF line endings and a Content-Length; clusterbomb stopped at
    // the first match (root/toor is the 6th combination).
    let logins: Vec<&String> = seen.iter().filter(|r| r.starts_with("POST /login ")).collect();
    assert_eq!(logins.len(), 6, "{logins:?}");
    assert!(logins[0].contains("\r\nContent-Length: 21\r\n"), "{}", logins[0]);
    // path requests carry the base request's headers (cookies, auth).
    let git = seen.iter().find(|r| r.starts_with("GET /.git/config ")).unwrap();
    assert!(git.contains("Cookie: sid=abc"), "{git}");
    // The chained request used the extracted token.
    assert!(seen.iter().any(|r| r.starts_with("GET /admin?t=abc123 ")));
    // Every path of a block is tried (this one is same-origin, just an odd path).
    assert!(seen.iter().any(|r| r.starts_with("GET /other.example/x ")));
}

#[test]
fn param_scoped_check_compares_with_baseline() {
    const SSTI: &str = r#"
id: bp-ssti
info: {name: SSTI, severity: high}
scope: param
http:
  - inject: ["{{7*191}}"]
    matchers-condition: and
    matchers:
      - type: word
        words: ["1337"]
      - type: word
        part: baseline_body
        words: ["1337"]
        negative: true
"#;
    // Evaluates {{7*191}} in the q parameter.
    let (port, _) = spawn(|req| {
        let target = req.split(' ').nth(1).unwrap_or("");
        let body =
            if target.contains("q=%7B%7B7*191%7D%7D") || target.contains("q={{7*191}}") { "1337" } else { "hello" };
        resp("200 OK", "", body)
    });
    let s = run(port, "/search?q=x", &[("ssti.yaml", SSTI)]);
    assert_eq!(s.raised.get("check:bp-ssti"), Some(&1), "{s:?}");
}

#[test]
fn absolute_urls_to_other_hosts_are_skipped() {
    const ELSEWHERE: &str = r#"
id: elsewhere
info: {name: Elsewhere, severity: info}
http:
  - path: ["http://203.0.113.9/x"]
    matchers:
      - type: status
        status: [200]
"#;
    let (port, seen) = spawn(|_| resp("200 OK", "", "ok"));
    let s = run(port, "/", &[("e.yaml", ELSEWHERE)]);
    assert!(s.raised.is_empty(), "{s:?}");
    assert_eq!(s.requests, 0);
    assert!(seen.lock().unwrap().is_empty());
}

#[test]
fn dsl_matchers_multi_request_conditions_and_flow() {
    // DSL matchers over status, body, and a response header.
    const DSL: &str = r#"
id: dsl-panel
info: {name: DSL panel, severity: info}
http:
  - path: ["{{BaseURL}}/panel"]
    matchers:
      - type: dsl
        condition: and
        dsl:
          - 'status_code == 200 && contains_all(tolower(body), "admin", "panel")'
          - 'contains(x_powered_by, "Express") && len(body) < 100'
          - '!regex("(?i)error", body)'
"#;
    // Numbered parts: a CSRF token from the first response is posted by the
    // second; the matcher sees both responses.
    const LOGIN: &str = r#"
id: dsl-login
info: {name: Login sequence, severity: high}
variables:
  user: "{{to_lower('ADMIN')}}"
http:
  - raw:
      - |
        GET /form HTTP/1.1
        Host: {{Hostname}}

      - |
        POST /form HTTP/1.1
        Host: {{Hostname}}
        Content-Type: application/x-www-form-urlencoded

        user={{user}}&csrf={{csrf}}&sig={{md5(csrf)}}
    extractors:
      - type: regex
        name: csrf
        internal: true
        group: 1
        regex: ['name="csrf" value="([a-z0-9]+)"']
    matchers:
      - type: dsl
        dsl:
          - 'status_code_1 == 200 && contains(body_1, "csrf") && status_code_2 == 302 && contains(set_cookie, "auth=")'
"#;
    // flow: block 2 only runs when the internal matcher of block 1 matched;
    // block 1 alone reports nothing.
    const FLOW: &str = r#"
id: flow-app
info: {name: Flow app, severity: medium}
flow: http(1) && http(2)
http:
  - path: ["{{BaseURL}}/panel"]
    matchers:
      - type: word
        words: ["Admin Panel"]
        internal: true
  - path: ["{{BaseURL}}/api/info"]
    extractors:
      - type: json
        name: app_version
        json: [".app.version"]
    matchers:
      - type: dsl
        dsl: ['compare_versions(app_version, "< 2.0")']
"#;
    const FLOW_MISS: &str = r#"
id: flow-miss
info: {name: Flow miss, severity: medium}
flow: http(1) && http(2)
http:
  - path: ["{{BaseURL}}/nothing-here"]
    matchers:
      - type: status
        status: [200]
        internal: true
  - path: ["{{BaseURL}}/never-requested"]
    matchers:
      - type: status
        status: [404]
"#;
    let (port, seen) = spawn(|req| {
        let line = req.lines().next().unwrap_or("");
        let path = line.split(' ').nth(1).unwrap_or("");
        match (line.split(' ').next().unwrap_or(""), path) {
            (_, "/panel") => resp("200 OK", "X-Powered-By: Express\r\n", "<h1>Admin Panel</h1>"),
            ("GET", "/form") => resp("200 OK", "", r#"<input name="csrf" value="t0k3n">"#),
            ("POST", "/form") if req.contains("user=admin&csrf=t0k3n&sig=") => {
                resp("302 Found", "Set-Cookie: auth=1\r\nLocation: /\r\n", "")
            }
            (_, "/api/info") => resp("200 OK", "Content-Type: application/json\r\n", r#"{"app":{"version":"1.9.3"}}"#),
            _ => resp("404 Not Found", "", "nope"),
        }
    });
    let s = run(port, "/", &[("dsl.yaml", DSL), ("login.yaml", LOGIN), ("flow.yaml", FLOW), ("miss.yaml", FLOW_MISS)]);
    assert_eq!(s.raised.get("check:dsl-panel"), Some(&1), "{s:?}");
    assert_eq!(s.raised.get("check:dsl-login"), Some(&1), "{s:?}");
    assert_eq!(s.raised.get("check:flow-app"), Some(&1), "{s:?}");
    assert!(!s.raised.contains_key("check:flow-miss"), "{s:?}");

    let seen = seen.lock().unwrap();
    let post = seen.iter().find(|r| r.starts_with("POST /form ")).unwrap();
    // {{md5(csrf)}} used the extracted token.
    assert!(post.contains("&sig=15cc41c9fa82806a0b7ef2ada7c86574"), "{post}");
    assert!(seen.iter().any(|r| r.starts_with("GET /nothing-here ")));
    assert!(!seen.iter().any(|r| r.starts_with("GET /never-requested ")));
}
