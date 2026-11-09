//! End-to-end tests for `import har` (and HAR files through `import api` and `scan active
//! --api`) and `history export har`, from the Chrome- and Firefox-shaped files in
//! tests/fixtures/har against a local server. Every secret in them is fake and starts with FAKE.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::{Arc, Mutex};

use brainproxy_core::http::request::split_head_body;
use serde_json::{json, Value};

const SECRETS: &[&str] = &[
    "FAKE-CHROME-SESSION",
    "FAKE-CHROME-BEARER",
    "FAKE-FIREFOX-SESSION",
    "FAKE-FIREFOX-PASSWORD",
    "FAKE-RESPONSE-ONLY",
];

#[derive(Clone, Debug)]
struct Hit {
    method: String,
    target: String,
    head: String,
    body: String,
}

#[derive(Clone)]
struct Server {
    port: u16,
    hits: Arc<Mutex<Vec<Hit>>>,
}

impl Server {
    fn start() -> Server {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let hits: Arc<Mutex<Vec<Hit>>> = Arc::default();
        let shared = hits.clone();
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(s) = stream else { continue };
                let hits = shared.clone();
                std::thread::spawn(move || handle(s, &hits));
            }
        });
        Server { port, hits }
    }

    fn hits(&self) -> Vec<Hit> {
        self.hits.lock().unwrap().clone()
    }
}

fn read_request(s: &mut TcpStream) -> Option<Vec<u8>> {
    let mut buf = Vec::new();
    let mut chunk = [0u8; 8192];
    loop {
        let n = s.read(&mut chunk).ok()?;
        if n == 0 {
            return None;
        }
        buf.extend_from_slice(&chunk[..n]);
        let (head, body) = split_head_body(&buf);
        if !head.ends_with(b"\r\n\r\n") {
            continue;
        }
        let text = String::from_utf8_lossy(head).to_ascii_lowercase();
        let cl =
            text.lines().find_map(|l| l.strip_prefix("content-length:")).map_or(0, |v| v.trim().parse().unwrap_or(0));
        if body.len() >= cl {
            return Some(buf);
        }
    }
}

/// Answers everything with a session cookie and a body that quotes it, as an app may.
fn handle(mut s: TcpStream, hits: &Mutex<Vec<Hit>>) {
    while let Some(raw) = read_request(&mut s) {
        let (head, body) = split_head_body(&raw);
        let head = String::from_utf8_lossy(head).into_owned();
        let line = head.lines().next().unwrap_or_default().to_string();
        let mut words = line.split(' ');
        let (method, target) = (words.next().unwrap_or_default(), words.next().unwrap_or_default());
        hits.lock().unwrap().push(Hit {
            method: method.into(),
            target: target.into(),
            head: head.clone(),
            body: String::from_utf8_lossy(body).into_owned(),
        });
        let text = r#"{"ok":true,"session":"FAKE-SERVER-SESSION-1"}"#;
        let reply = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nSet-Cookie: sid=FAKE-SERVER-SESSION-1; Path=/\r\n\
             Content-Length: {}\r\n\r\n{text}",
            text.len()
        );
        if s.write_all(reply.as_bytes()).is_err() {
            return;
        }
    }
}

fn setup(name: &str) -> (PathBuf, PathBuf) {
    let dir = std::env::temp_dir().join(format!("bp-har-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let project = dir.join("p.bpdb");
    ok(&project, &["engagement", "start", "--target", "127.0.0.1"]);
    (dir, project)
}

/// A fixture written to `dir`, its 18080 now the port of the local server.
fn fixture(dir: &Path, name: &str, port: u16) -> String {
    let manifest = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/har").join(name);
    let text = std::fs::read_to_string(manifest).unwrap().replace("18080", &port.to_string());
    let path = dir.join(name);
    std::fs::write(&path, text).unwrap();
    path.to_str().unwrap().to_string()
}

struct Output {
    code: i32,
    json: Value,
    /// stdout and stderr together.
    all: String,
}

fn run_as(project: &Path, args: &[&str], format: &str) -> Output {
    let out = Command::new(env!("CARGO_BIN_EXE_brainproxy"))
        .args(["--format", format, "--project"])
        .arg(project)
        .args(args)
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
    Output {
        code: out.status.code().unwrap_or(-1),
        json: serde_json::from_str(&stdout).unwrap_or(Value::Null),
        all: format!("{stdout}\n{stderr}"),
    }
}

fn run(project: &Path, args: &[&str]) -> Output {
    run_as(project, args, "json")
}

fn ok(project: &Path, args: &[&str]) -> Value {
    let o = run(project, args);
    assert_eq!(o.code, 0, "{args:?}: {}", o.all);
    o.json["data"].clone()
}

fn refused(project: &Path, args: &[&str], code: i32) -> String {
    let o = run(project, args);
    assert_eq!(o.code, code, "{args:?}: {}", o.all);
    o.json["error"]["message"].as_str().unwrap_or_default().to_string()
}

fn assert_no_secrets(what: &str, text: &str) {
    for s in SECRETS {
        assert!(!text.contains(s), "{s} in {what}: {text}");
    }
}

/// No table but the history's request columns may hold a secret (and those only when kept).
fn assert_absent_from_project(project: &Path, secrets: &[&str]) {
    for s in secrets {
        let n = ok(
            project,
            &["query", "SELECT count(*) FROM history WHERE instr(request, ?1) > 0 OR instr(response, ?1) > 0", "-p", s],
        );
        assert_eq!(n["rows"][0][0], 0, "{s} in history");
    }
}

fn names(d: &Value) -> Vec<String> {
    d["requests"].as_array().unwrap().iter().map(|r| format!("{} {}", r["method"].as_str().unwrap(), path(r))).collect()
}

fn path(r: &Value) -> String {
    let u = r["url"].as_str().unwrap();
    let rest = u.split_once("://").map(|(_, r)| r).unwrap_or(u);
    rest[rest.find('/').unwrap_or(rest.len())..].to_string()
}

#[test]
fn a_chrome_har_is_previewed_without_its_secrets() {
    let (dir, p) = setup("chrome-preview");
    let server = Server::start();
    let src = fixture(&dir, "chrome.har", server.port);
    let o = run(&p, &["import", "har", "--dry-run", "--", &src]);
    assert_eq!(o.code, 0, "{}", o.all);
    assert_no_secrets("the preview", &o.all);
    let d = &o.json["data"];
    assert_eq!(
        (d["format"].as_str(), d["title"].as_str(), d["version"].as_str()),
        (Some("har"), Some("WebInspector"), Some("537.36"))
    );
    assert_eq!(names(d), ["GET /account?tab=orders", "POST /api/orders", "DELETE /api/orders/7", "GET "], "{d}");
    let reasons: Vec<&Value> = d["requests"].as_array().unwrap().iter().map(|r| &r["excluded_reason"]).collect();
    assert_eq!(reasons, [&Value::Null, &Value::Null, &json!("method"), &json!("scope")]);
    // One the scope leaves out shows its method and host only.
    let other = &d["requests"][3];
    assert_eq!(
        (other["name"].as_str(), other["url"].as_str(), other["headers"].as_array().map(Vec::len)),
        (Some("GET http://198.51.100.9:81"), Some("http://198.51.100.9:81"), Some(0)),
        "{other}"
    );
    assert!(!o.all.contains("/collect") && !o.all.contains("id=1"), "{}", o.all);
    let w = d["warnings"].to_string();
    assert!(w.contains("1 static asset") && w.contains("1 repeated request"), "{w}");
    let creds: Vec<String> =
        d["credentials"].as_array().unwrap().iter().map(|c| format!("{}:{}", c["in"], c["name"])).collect();
    for want in [r#""cookie":"sid""#, r#""cookie":"theme""#, r#""header":"Authorization""#] {
        assert!(creds.iter().any(|c| c == want), "{want} in {creds:?}");
    }
    let headers = d["requests"][0]["headers"].to_string();
    assert!(!headers.to_ascii_lowercase().contains("cookie") && !headers.contains("If-None-Match"), "{headers}");
    assert!(server.hits().is_empty(), "a dry run sends nothing");
    // `import api` takes it too, and `import har` takes nothing else.
    assert_eq!(ok(&p, &["import", "api", "--dry-run", "--", &src])["format"], "har");
    let spec = dir.join("spec.json");
    std::fs::write(&spec, r#"{"openapi": "3.0.0", "paths": {}}"#).unwrap();
    let e = refused(&p, &["import", "har", "--dry-run", "--", spec.to_str().unwrap()], 2);
    assert!(e.contains("not a HAR file") && e.contains("import api"), "{e}");
    let e = refused(&p, &["import", "api", "--dry-run", "--keep-static", "--", spec.to_str().unwrap()], 2);
    assert!(e.contains("for HAR files"), "{e}");
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn a_firefox_har_is_sent_in_scope_and_without_credentials() {
    let (dir, p) = setup("firefox-send");
    let server = Server::start();
    let src = fixture(&dir, "firefox.har", server.port);
    let o = run(&p, &["import", "har", "--", &src]);
    assert_eq!(o.code, 0, "{}", o.all);
    assert_no_secrets("the output", &o.all);
    assert_eq!(o.json["data"]["sent"], 3, "{}", o.all);
    let hits = server.hits();
    // Sent at once, so in no set order.
    let mut sent: Vec<String> = hits.iter().map(|h| format!("{} {}", h.method, h.target)).collect();
    sent.sort();
    assert_eq!(sent, ["GET /search?q=shoes", "POST /login", "POST /upload"]);
    let at = |t: &str| hits.iter().find(|h| h.target == t).unwrap();
    let login = at("/login");
    assert!(login.body.starts_with("user=alice&password=") && !login.body.contains("FAKE"), "{login:?}");
    assert!(!login.head.to_ascii_lowercase().contains("cookie:"), "{login:?}");
    let upload = at("/upload");
    assert!(upload.body.contains("filename=\"cv.pdf\"") && upload.body.contains("name=\"title\""), "{upload:?}");
    assert_absent_from_project(&p, SECRETS);
    let rows = ok(&p, &["history", "list", "--source", "import"]);
    assert_eq!(rows["count"], 3);
    // Static assets on request.
    let d = ok(&p, &["import", "har", "--dry-run", "--keep-static", "--", &src]);
    assert!(names(&d).contains(&"GET /static/site.css?v=3".to_string()), "{d}");
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn recorded_credentials_go_out_only_when_kept_and_are_never_shown() {
    let (dir, p) = setup("keep");
    let server = Server::start();
    let src = fixture(&dir, "chrome.har", server.port);
    let o = run(&p, &["import", "har", "--keep-credentials", "--dry-run", "--", &src]);
    assert_eq!(o.code, 0, "{}", o.all);
    assert_no_secrets("the preview", &o.all);
    assert_eq!(o.json["data"]["credentials_kept"], true);
    assert!(o.json["data"]["requests"][0]["headers"].to_string().contains("Cookie: ********"), "{}", o.all);
    let o = run_as(&p, &["import", "har", "--keep-credentials", "--", &src], "text");
    assert_eq!(o.code, 0, "{}", o.all);
    assert_no_secrets("the text output", &o.all);
    let hits = server.hits();
    let page = hits.iter().find(|h| h.target.starts_with("/account")).unwrap();
    assert!(page.head.contains("Cookie: sid=FAKE-CHROME-SESSION; theme=dark"), "{page:?}");
    let api = hits.iter().find(|h| h.target == "/api/orders").unwrap();
    assert!(api.head.contains("Authorization: Bearer FAKE-CHROME-BEARER"), "{api:?}");
    assert!(!hits.iter().any(|h| h.method == "DELETE"));
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn a_scan_takes_a_har_file() {
    let (dir, p) = setup("scan");
    let server = Server::start();
    let src = fixture(&dir, "firefox.har", server.port);
    let arg = format!("--api={src}");
    let r = ok(&p, &["scan", "active", &arg, "--only=2", "--rules", "40012", "--strength", "low"]);
    assert_eq!(r["import"]["format"], "har", "{r}");
    assert_eq!((r["import"]["sent"].as_u64(), r["targets"].as_u64()), (Some(1), Some(1)), "{r}");
    let hits = server.hits();
    assert_eq!(format!("{} {}", hits[0].method, hits[0].target), "GET /search?q=shoes");
    assert!(hits.len() > 1 && hits.iter().all(|h| h.target.starts_with("/search")), "{hits:?}");
    let e = refused(&p, &["scan", "active", "http://127.0.0.1:1/", "--keep-static"], 2);
    assert!(e.contains("need --api"), "{e}");
    let _ = std::fs::remove_dir_all(dir);
}

/// `args` run as an MCP tool call's command, with `stdin` on stdin.
fn run_mcp(project: &Path, args: &[&str], stdin: &[u8]) -> Output {
    run_mcp_env(project, args, stdin, &[])
}

fn run_mcp_env(project: &Path, args: &[&str], stdin: &[u8], env: &[(&str, &Path)]) -> Output {
    let mut child = Command::new(env!("CARGO_BIN_EXE_brainproxy"))
        .env("BRAINPROXY_MCP_CALL", "1")
        .envs(env.iter().copied())
        .args(["--format", "json", "--project"])
        .arg(project)
        .args(args)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    child.stdin.take().unwrap().write_all(stdin).unwrap();
    let out = child.wait_with_output().unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
    Output {
        code: out.status.code().unwrap_or(-1),
        json: serde_json::from_str(&stdout).unwrap_or(Value::Null),
        all: format!("{stdout}\n{stderr}"),
    }
}

#[test]
fn an_agent_imports_only_files_in_the_projects_folder() {
    let (dir, p) = setup("mcp-files");
    let server = Server::start();
    let inside = fixture(&dir, "chrome.har", server.port);
    let elsewhere = std::env::temp_dir().join(format!("bp-har-{}-mcp-elsewhere", std::process::id()));
    let _ = std::fs::remove_dir_all(&elsewhere);
    std::fs::create_dir_all(&elsewhere).unwrap();
    let outside = fixture(&elsewhere, "chrome.har", server.port);
    let private = elsewhere.join("private.txt");
    std::fs::write(&private, "PRIVATE-FILE-CONTENT").unwrap();
    let private = private.to_str().unwrap();

    // A file in the project's folder, and stdin, are read.
    let o = run_mcp(&p, &["import", "har", "--dry-run", "--", &inside], b"");
    assert_eq!((o.code, o.json["data"]["format"].as_str()), (0, Some("har")), "{}", o.all);
    let o = run_mcp(&p, &["import", "har", "--dry-run", "--", "-"], std::fs::read(&inside).unwrap().as_slice());
    assert_eq!((o.code, o.json["data"]["format"].as_str()), (0, Some("har")), "{}", o.all);

    // A file elsewhere, or a link from inside to one, is refused without quoting it.
    #[cfg(unix)]
    std::os::unix::fs::symlink(private, dir.join("link.har")).unwrap();
    let link = dir.join("link.har");
    let mut refused_docs = vec![
        vec!["import", "har", "--dry-run", "--", &outside],
        vec!["import", "api", "--dry-run", "--", private],
        vec!["import", "openapi", "--dry-run", "--", private],
        vec!["import", "postman", "--dry-run", "--", private],
        vec!["import", "graphql", "--dry-run", "--schema", private, "http://127.0.0.1:1/graphql"],
        vec!["scan", "active", "--api", private, "--rules", "40012"],
    ];
    if cfg!(unix) {
        refused_docs.push(vec!["import", "har", "--dry-run", "--", link.to_str().unwrap()]);
    }
    for args in &refused_docs {
        let o = run_mcp(&p, args, b"");
        assert_eq!(o.code, 2, "{args:?}: {}", o.all);
        assert!(o.json["error"]["message"].as_str().unwrap().contains("project's folder"), "{args:?}: {}", o.all);
        assert!(!o.all.contains("PRIVATE-FILE-CONTENT"), "{args:?}: {}", o.all);
    }
    // An environment file elsewhere is refused too.
    let env_arg = format!("--environment={private}");
    let o = run_mcp(&p, &["import", "api", "--dry-run", &env_arg, "--", &inside], b"");
    assert_eq!(o.code, 2, "{}", o.all);
    assert!(o.all.contains("--environment") && o.all.contains("project's folder"), "{}", o.all);
    assert!(!o.all.contains("PRIVATE-FILE-CONTENT"), "{}", o.all);

    // A person may import from anywhere.
    assert_eq!(ok(&p, &["import", "har", "--dry-run", "--", &outside])["format"], "har");
    let _ = std::fs::remove_dir_all(elsewhere);
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn an_agent_s_import_errors_never_quote_the_file() {
    let (dir, p) = setup("mcp-quote");
    let ini = dir.join("credentials");
    std::fs::write(&ini, "[default]\naws_access_key_id = AKIAEXAMPLE\naws_secret_access_key = INISECRET456\n").unwrap();
    let ini = ini.to_str().unwrap();
    for args in [
        vec!["import", "openapi", "--dry-run", "--", ini],
        vec!["import", "postman", "--dry-run", "--", ini],
        vec!["import", "api", "--dry-run", "--", ini],
        vec!["import", "har", "--dry-run", "--", ini],
        vec!["import", "graphql", "--dry-run", "--schema", ini, "http://127.0.0.1:1/graphql"],
    ] {
        let o = run_mcp(&p, &args, b"");
        assert_eq!(o.code, 2, "{args:?}: {}", o.all);
        assert!(o.all.contains("not valid JSON or YAML"), "{args:?}: {}", o.all);
        assert!(!o.all.contains("AKIA") && !o.all.contains("INISECRET"), "{args:?}: {}", o.all);
    }
    // A person sees where and what.
    let o = run(&p, &["import", "openapi", "--dry-run", "--", ini]);
    assert!(o.all.contains("aws_access_key_id"), "{}", o.all);

    // A project kept in the home folder opens no file to an agent: put it in its own folder.
    let o = run_mcp_env(&p, &["import", "openapi", "--dry-run", "--", ini], b"", &[("HOME", &dir)]);
    assert_eq!(o.code, 2, "{}", o.all);
    assert!(o.all.contains("home folder") && o.all.contains("folder of its own"), "{}", o.all);
    assert!(!o.all.contains("AKIA"), "{}", o.all);
    // Stdin is still read.
    let spec = br#"{"openapi": "3.0.0", "servers": [{"url": "http://127.0.0.1:1"}], "paths": {}}"#;
    let o = run_mcp_env(&p, &["import", "openapi", "--dry-run", "--", "-"], spec, &[("HOME", &dir)]);
    assert_eq!(o.code, 0, "{}", o.all);
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn history_exports_as_har_with_secrets_masked() {
    let (dir, p) = setup("export");
    let server = Server::start();
    let url = format!("http://127.0.0.1:{}/me?access_token=FAKE-QUERY-TOKEN-1&x=1", server.port);
    ok(
        &p,
        &[
            "send",
            "--url",
            &url,
            "-H",
            "Cookie: sid=FAKE-CHROME-SESSION",
            "-H",
            "Authorization: Bearer FAKE-CHROME-BEARER",
            "-H",
            "X-Functions-Key: FAKE-FUNCTIONS-KEY",
            "-H",
            "Sec-WebSocket-Protocol: graphql-transport-ws, FAKE-WS-TOKEN-7f3k9Qz1",
        ],
    );
    let form = format!("http://127.0.0.1:{}/login", server.port);
    ok(
        &p,
        &[
            "send",
            "--url",
            &form,
            "-X",
            "POST",
            "-H",
            "Content-Type: application/x-www-form-urlencoded",
            "--data",
            "user=a&password=FAKE-FIREFOX-PASSWORD",
        ],
    );
    let out = dir.join("out.har");
    let out_s = out.to_str().unwrap();
    let d = ok(&p, &["history", "export", "har", "--source", "send", "-o", out_s]);
    assert_eq!((d["entries"].as_u64(), d["truncated"].as_bool()), (Some(2), Some(false)), "{d}");
    assert!(d["redacted"].as_u64().unwrap() > 0, "{d}");
    let text = std::fs::read_to_string(&out).unwrap();
    for s in [
        "FAKE-CHROME-SESSION",
        "FAKE-CHROME-BEARER",
        "FAKE-FIREFOX-PASSWORD",
        "FAKE-QUERY-TOKEN-1",
        "FAKE-SERVER-SESSION-1",
        "FAKE-FUNCTIONS-KEY",
        "FAKE-WS-TOKEN",
    ] {
        assert!(!text.contains(s), "{s} in {text}");
    }
    // A subprotocol token is masked, the subprotocol's name kept.
    assert!(text.contains("graphql-transport-ws, [redacted]"), "{text}");
    let har: Value = serde_json::from_str(&text).unwrap();
    let e = &har["log"]["entries"];
    assert_eq!(har["log"]["version"], "1.2");
    assert_eq!(e[0]["request"]["method"], "GET");
    assert_eq!(e[0]["response"]["status"], 200);
    assert_eq!(e[0]["request"]["queryString"][1], json!({"name": "x", "value": "1"}));
    assert_eq!(e[1]["request"]["postData"]["params"][0], json!({"name": "user", "value": "a"}));
    assert!(e[0]["_brainproxy"]["history_id"].is_i64());
    // An existing file is kept; --limit and truncated; the HAR in the envelope without -o.
    let o = run(&p, &["history", "export", "har", "-o", out_s]);
    assert_eq!(o.json["error"]["kind"], "conflict", "{}", o.all);
    let d = ok(&p, &["history", "export", "--limit", "1"]);
    assert_eq!((d["entries"].as_u64(), d["truncated"].as_bool()), (Some(1), Some(true)), "{d}");
    assert_eq!(d["har"]["log"]["entries"].as_array().unwrap().len(), 1);
    // The filter language chooses rows as it does for history list.
    let d = ok(&p, &["history", "export", "--filter", "method=POST path:/login"]);
    assert_eq!(d["entries"].as_u64(), Some(1), "{d}");
    assert_eq!(d["har"]["log"]["entries"][0]["request"]["method"], "POST");
    // Unmasked on request; text mode prints the file itself.
    let o = run_as(&p, &["history", "export", "har", "--no-redact", "--source", "send"], "text");
    assert_eq!(o.code, 0, "{}", o.all);
    let raw: Value = serde_json::from_str(o.all.trim()).unwrap();
    assert_eq!(raw["log"]["entries"][0]["request"]["cookies"][0]["value"], "FAKE-CHROME-SESSION");

    // The file reads back in as a HAR, with its masks taken for what they are: no credentials.
    let d = ok(&p, &["import", "har", "--dry-run", "--", out_s]);
    assert_eq!(names(&d), ["GET /me?x=1", "POST /login"], "{d}");
    let _ = std::fs::remove_dir_all(dir);
}
