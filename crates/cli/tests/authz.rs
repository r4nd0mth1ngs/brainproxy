//! End-to-end test for `authz`: a local shop API where one order is readable by any
//! logged-in user (the bug), another is checked properly, `/api/me` returns each user's
//! own data, and `/public/info` needs no session.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use serde_json::Value;

struct Server {
    port: u16,
    logouts: Arc<AtomicUsize>,
}

impl Server {
    fn start() -> Server {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let logouts = Arc::new(AtomicUsize::new(0));
        let counter = Arc::new(AtomicUsize::new(0));
        let flaky = Arc::new(AtomicUsize::new(0));
        let shared = logouts.clone();
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(s) = stream else { continue };
                let (logouts, counter, flaky) = (shared.clone(), counter.clone(), flaky.clone());
                std::thread::spawn(move || handle(s, &logouts, &counter, &flaky));
            }
        });
        Server { port, logouts }
    }

    fn url(&self, path: &str) -> String {
        format!("http://127.0.0.1:{}{path}", self.port)
    }
}

fn handle(mut s: TcpStream, logouts: &AtomicUsize, counter: &AtomicUsize, flaky: &AtomicUsize) {
    let mut buf = Vec::new();
    let mut chunk = [0u8; 4096];
    while !buf.windows(4).any(|w| w == b"\r\n\r\n") {
        match s.read(&mut chunk) {
            Ok(0) | Err(_) => return,
            Ok(n) => buf.extend_from_slice(&chunk[..n]),
        }
    }
    let text = String::from_utf8_lossy(&buf).to_string();
    let line = text.lines().next().unwrap_or("").to_string();
    let path = line.split(' ').nth(1).unwrap_or("/").to_string();
    let head_only = line.starts_with("HEAD ");
    let cookie = text
        .lines()
        .find(|l| l.to_ascii_lowercase().starts_with("cookie:"))
        .map(|l| l[7..].trim().to_string())
        .unwrap_or_default();
    let user = if cookie.contains("sid=alice-session") {
        Some("alice")
    } else if cookie.contains("sid=bob-session") {
        Some("bob")
    } else {
        None
    };
    // Changes on every response, like a timestamp.
    let n = counter.fetch_add(1, Ordering::SeqCst);
    let json = |status: &str, body: String| {
        format!(
            "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        )
    };
    let order = |id: u32, owner: &str| {
        format!(r#"{{"id":{id},"owner":"{owner}","email":"{owner}@shop.test","total":"{id}2.50","ts":{n}}}"#)
    };
    let resp = match (path.as_str(), user) {
        ("/static/app.js", _) => {
            "HTTP/1.1 200 OK\r\nContent-Type: text/javascript\r\nContent-Length: 2\r\nConnection: close\r\n\r\n;;"
                .into()
        }
        ("/public/info", _) => json("200 OK", r#"{"shop":"Example","currency":"EUR"}"#.into()),
        (_, None) => json("401 Unauthorized", r#"{"error":"login required"}"#.into()),
        // The bug: any logged-in user may read order 1.
        ("/api/orders/1", Some(_)) => json("200 OK", order(1, "alice")),
        ("/api/orders/3", Some("alice")) => json("200 OK", order(3, "alice")),
        ("/api/orders/3", Some(_)) => json("403 Forbidden", r#"{"error":"not your order"}"#.into()),
        // Checked properly, but alice's third request is rate limited.
        ("/api/orders/7", Some("alice")) if flaky.fetch_add(1, Ordering::SeqCst) == 2 => {
            json("429 Too Many Requests", r#"{"error":"slow down"}"#.into())
        }
        ("/api/orders/7", Some("alice")) => json("200 OK", order(7, "alice")),
        // Not alice's data, and without the requester's name in it either.
        ("/api/orders/7", Some(_)) => json("200 OK", order(8, "carol")),
        // Succeeds for anyone logged in, with nothing in it to compare.
        ("/api/orders/9", Some(_)) => "HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n".to_string(),
        ("/api/me", Some(u)) => json("200 OK", format!(r#"{{"user":"{u}","email":"{u}@shop.test","ts":{n}}}"#)),
        ("/logout", Some(_)) => {
            logouts.fetch_add(1, Ordering::SeqCst);
            json("200 OK", r#"{"ok":true}"#.into())
        }
        _ => json("404 Not Found", "{}".into()),
    };
    let resp = if head_only { resp.split_inclusive("\r\n\r\n").next().unwrap_or("").to_string() } else { resp };
    let _ = s.write_all(resp.as_bytes());
}

fn run(project: &std::path::Path, args: &[&str]) -> (i32, Value) {
    let out = Command::new(env!("CARGO_BIN_EXE_brainproxy"))
        .args(["--format", "json", "--project"])
        .arg(project)
        .args(args)
        .stdin(Stdio::null())
        .output()
        .unwrap();
    let v: Value = serde_json::from_slice(&out.stdout)
        .unwrap_or_else(|e| panic!("bad JSON ({e}): {}", String::from_utf8_lossy(&out.stdout)));
    (out.status.code().unwrap(), v)
}

fn ok(project: &std::path::Path, args: &[&str]) -> Value {
    let (code, v) = run(project, args);
    assert_eq!(code, 0, "{args:?}: {v}");
    v["data"].clone()
}

fn tmp_project(name: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!("bp-authz-{}-{name}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let p = dir.join("p.bpdb");
    let _ = std::fs::remove_file(&p);
    ok(&p, &["engagement", "start", "--target", "127.0.0.1"]);
    for user in ["alice", "bob"] {
        let cookie = format!("Cookie: sid={user}-session");
        ok(&p, &["auth", "add", user, "--username", user, "-H", &cookie]);
    }
    p
}

/// The verdict for `path` and `identity` in a matrix.
fn cell<'a>(m: &'a Value, path: &str, identity: &str) -> &'a Value {
    let r = m["requests"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["url"].as_str().unwrap().ends_with(path))
        .unwrap_or_else(|| panic!("{path} not in {m}"));
    &r["cells"][identity]
}

#[test]
fn finds_the_readable_order_and_nothing_else() {
    let srv = Server::start();
    let p = tmp_project("run");
    for path in ["/api/orders/1", "/api/orders/3", "/api/me", "/public/info", "/logout"] {
        ok(&p, &["send", "--url", &srv.url(path), "--auth", "alice"]);
    }
    assert_eq!(srv.logouts.load(Ordering::SeqCst), 1);

    let r = ok(&p, &["authz", "run", "--as", "bob"]);
    // /logout isn't replayed: that would end the owner's session.
    assert_eq!(srv.logouts.load(Ordering::SeqCst), 1, "{r}");
    assert_eq!(r["skipped"]["excluded_paths"], 1, "{r}");
    assert_eq!(r["requests"], 4, "{r}");
    assert_eq!(r["new_findings"], 1, "{r}");
    let bypasses = r["bypasses"].as_array().unwrap();
    assert_eq!(bypasses.len(), 1, "{r}");
    let b = &bypasses[0];
    assert!(b["url"].as_str().unwrap().ends_with("/api/orders/1"), "{b}");
    assert_eq!(b["identity"], "bob");
    assert_eq!(b["owner"], "alice", "owner from the request's auth placeholders: {b}");
    assert_eq!(b["confidence"], "high", "{b}");

    let run_id = r["run_id"].as_i64().unwrap().to_string();
    let m = ok(&p, &["authz", "matrix", &run_id]);
    assert_eq!(cell(&m, "/api/orders/1", "bob")["verdict"], "bypass", "{m}");
    assert_eq!(cell(&m, "/api/orders/1", "anonymous")["verdict"], "enforced", "{m}");
    assert_eq!(cell(&m, "/api/orders/3", "bob")["verdict"], "enforced", "{m}");
    assert_eq!(cell(&m, "/api/me", "bob")["verdict"], "different", "{m}");
    assert_eq!(cell(&m, "/public/info", "anonymous")["verdict"], "public", "{m}");
    assert_eq!(cell(&m, "/public/info", "bob")["verdict"], "public", "{m}");

    // The replay as bob carried bob's session and none of alice's.
    let replay = b["history_id"].as_i64().unwrap().to_string();
    let h = ok(&p, &["history", "show", &replay, "--part", "request"]);
    let req = h.to_string();
    assert!(req.contains("auth:bob:cookie:sid") && !req.contains("auth:alice"), "{req}");

    let f = ok(&p, &["findings", "list", "--source", "authz"]);
    let text = f.to_string();
    assert!(text.contains("Access Control Bypass") && text.contains("100003"), "{text}");

    let only = ok(&p, &["authz", "results", &run_id, "--verdict", "bypass"]);
    assert_eq!(only["results"].as_array().unwrap().len(), 1, "{only}");
    let runs = ok(&p, &["authz", "list"]);
    assert_eq!(runs["runs"][0]["run_id"].as_i64().unwrap().to_string(), run_id, "{runs}");
    assert_eq!(runs["runs"][0]["state"], "completed", "{runs}");
}

#[test]
fn urls_need_an_owner_and_profiles_must_exist() {
    let srv = Server::start();
    let p = tmp_project("args");
    let (code, v) = run(&p, &["authz", "run", "--as", "bob", &srv.url("/api/orders/1")]);
    assert_eq!(code, 2, "{v}");
    let (code, v) = run(&p, &["authz", "run", "--as", "carol"]);
    assert_eq!(code, 4, "{v}");
    let r = ok(&p, &["authz", "run", "--as", "bob", "--owner", "alice", "--no-anonymous", &srv.url("/api/orders/1")]);
    assert_eq!(r["verdicts"]["bypass"], 1, "{r}");
    assert!(r["verdicts"].get("public").is_none(), "{r}");
}

#[test]
fn a_rate_limited_second_baseline_does_not_hide_differences() {
    let srv = Server::start();
    let p = tmp_project("flaky");
    ok(&p, &["send", "--url", &srv.url("/api/orders/7"), "--auth", "alice"]);
    // Baseline 200, second baseline 429: nothing may be learned from the 429, or
    // another order would look like alice's.
    let r = ok(&p, &["authz", "run", "--as", "bob"]);
    let run_id = r["run_id"].as_i64().unwrap().to_string();
    let m = ok(&p, &["authz", "matrix", &run_id]);
    assert_eq!(cell(&m, "/api/orders/7", "bob")["verdict"], "different", "{m}");
    assert_eq!(r["new_findings"], 0, "{r}");
}

#[test]
fn empty_and_head_responses_are_not_bypasses() {
    let srv = Server::start();
    let p = tmp_project("empty");
    ok(&p, &["send", "--url", &srv.url("/api/orders/9"), "--auth", "alice"]);
    ok(&p, &["send", "-X", "HEAD", "--url", &srv.url("/api/orders/1"), "--auth", "alice"]);
    let r = ok(&p, &["authz", "run", "--as", "bob"]);
    assert_eq!(r["new_findings"], 0, "{r}");
    assert!(r["verdicts"].get("bypass").is_none(), "{r}");
    let run_id = r["run_id"].as_i64().unwrap().to_string();
    let m = ok(&p, &["authz", "matrix", &run_id]);
    assert_eq!(cell(&m, "/api/orders/9", "bob")["verdict"], "inconclusive", "{m}");
    assert_eq!(cell(&m, "/api/orders/1", "bob")["verdict"], "inconclusive", "{m}");
    // A refusal is still a refusal.
    assert_eq!(cell(&m, "/api/orders/9", "anonymous")["verdict"], "enforced", "{m}");
}

/// curl through the proxy as alice; returns the status.
fn curl_as_alice(proxy: &str, url: &str, extra: &[&str]) -> u16 {
    let out = Command::new("curl")
        .args(["-sS", "--noproxy", "", "--max-time", "20", "-x", proxy, "-H", "Cookie: sid=alice-session"])
        .args(extra)
        .args(["-o", if cfg!(windows) { "NUL" } else { "/dev/null" }, "-w", "%{http_code}", url])
        .output()
        .expect("curl must be installed");
    String::from_utf8_lossy(&out.stdout).trim().parse().unwrap_or(0)
}

#[test]
fn live_mode_tests_proxied_requests_as_other_identities() {
    let srv = Server::start();
    let p = tmp_project("live");
    let home = p.with_file_name("home");
    let home = home.to_str().unwrap();
    let started = ok(&p, &["--home", home, "proxy", "start", "--listen", "127.0.0.1:0", "--authz", "bob,anonymous"]);
    let run_id = started["authz_run"].as_i64().unwrap_or_else(|| panic!("no authz_run: {started}")).to_string();
    let proxy = started["usage"]["proxy_url"].as_str().unwrap().to_string();

    for path in ["/api/orders/1", "/api/orders/3", "/api/orders/1", "/logout"] {
        assert_eq!(curl_as_alice(&proxy, &srv.url(path), &[]), 200, "{path}");
    }
    assert_eq!(curl_as_alice(&proxy, &srv.url("/api/me"), &["-X", "POST", "-d", "x=1"]), 200);
    // Static assets and responses other than 2xx aren't tested either.
    assert_eq!(curl_as_alice(&proxy, &srv.url("/static/app.js"), &[]), 200);
    assert_eq!(curl_as_alice(&proxy, &srv.url("/no/such/page"), &[]), 404);
    // Requests without credentials aren't tested.
    let out = Command::new("curl")
        .args(["-sS", "--noproxy", "", "-x", &proxy, "-o", if cfg!(windows) { "NUL" } else { "/dev/null" }])
        .arg(srv.url("/public/info"))
        .status()
        .unwrap();
    assert!(out.success());

    // Tested in the background: wait for both orders to have results.
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
    let m = loop {
        let m = ok(&p, &["authz", "matrix", &run_id]);
        if m["requests"].as_array().unwrap().len() >= 2 || std::time::Instant::now() > deadline {
            break m;
        }
        std::thread::sleep(std::time::Duration::from_millis(200));
    };
    assert_eq!(m["requests"].as_array().unwrap().len(), 2, "{m}");
    assert_eq!(cell(&m, "/api/orders/1", "bob")["verdict"], "bypass", "{m}");
    assert_eq!(cell(&m, "/api/orders/1", "anonymous")["verdict"], "enforced", "{m}");
    assert_eq!(cell(&m, "/api/orders/3", "bob")["verdict"], "enforced", "{m}");
    let row = m["requests"].as_array().unwrap().iter().find(|r| r["url"].as_str().unwrap().ends_with("/1")).unwrap();
    assert_eq!(row["owner"], "alice", "owner from the session value: {row}");
    assert!(row["source_id"].as_i64().is_some(), "points at the proxied request: {row}");
    assert_eq!(srv.logouts.load(Ordering::SeqCst), 1, "/logout isn't replayed");

    // The job's progress is stored every half second, so it may trail the results a little.
    let status = loop {
        let status = ok(&p, &["--home", home, "proxy", "status"]);
        if status["authz"]["progress"]["tested"] == 2 || std::time::Instant::now() > deadline {
            break status;
        }
        std::thread::sleep(std::time::Duration::from_millis(200));
    };
    assert_eq!(status["authz"]["run_id"].as_i64().unwrap().to_string(), run_id, "{status}");
    let progress = &status["authz"]["progress"];
    assert_eq!(progress["tested"], 2, "{status}");
    assert_eq!(progress["duplicates"], 1, "{status}");
    assert_eq!(progress["skipped_excluded_paths"], 1, "{status}");
    assert_eq!(progress["skipped_methods"], 1, "{status}");
    assert_eq!(progress["skipped_no_credentials"], 1, "{status}");
    assert_eq!(progress["skipped_static"], 1, "{status}");
    assert_eq!(progress["skipped_status"], 1, "{status}");
    assert_eq!(progress["dropped_queue_full"], 0, "{status}");

    let f = ok(&p, &["findings", "list", "--source", "authz"]);
    assert!(f.to_string().contains("Access Control Bypass"), "{f}");

    // Stopping the proxy ends the run.
    ok(&p, &["--home", home, "proxy", "stop"]);
    let runs = ok(&p, &["authz", "list"]);
    let run = runs["runs"].as_array().unwrap().iter().find(|r| r["run_id"].as_i64().unwrap().to_string() == run_id);
    assert_eq!(run.unwrap()["state"], "completed", "{runs}");
    let job = ok(&p, &["job", "status", &run_id]);
    assert_eq!(job["result"]["verdicts"]["bypass"], 1, "{job}");
}

#[test]
fn live_mode_needs_known_profiles() {
    let p = tmp_project("live-args");
    let home = p.with_file_name("home");
    let (code, v) =
        run(&p, &["--home", home.to_str().unwrap(), "proxy", "start", "--listen", "127.0.0.1:0", "--authz", "carol"]);
    assert_eq!(code, 4, "{v}");
}

#[test]
fn live_mode_shares_the_proxys_auth_session() {
    let srv = Server::start();
    let p = tmp_project("live-auth");
    let home = p.with_file_name("home");
    let home = home.to_str().unwrap();
    let args = ["--home", home, "proxy", "start", "--listen", "127.0.0.1:0", "--auth", "alice", "--authz", "bob"];
    let started = ok(&p, &args);
    let run_id = started["authz_run"].as_i64().unwrap().to_string();
    let proxy = started["usage"]["proxy_url"].as_str().unwrap().to_string();
    // The proxy adds alice's session; the request itself carries none.
    let out = Command::new("curl")
        .args(["-sS", "--noproxy", "", "-x", &proxy, "-o", if cfg!(windows) { "NUL" } else { "/dev/null" }])
        .args(["-w", "%{http_code}", &srv.url("/api/orders/1")])
        .output()
        .unwrap();
    assert_eq!(String::from_utf8_lossy(&out.stdout), "200");
    // Nothing to compare in an empty response: inconclusive, not a bypass.
    let out = Command::new("curl")
        .args(["-sS", "--noproxy", "", "-x", &proxy, "-o", if cfg!(windows) { "NUL" } else { "/dev/null" }])
        .args(["-w", "%{http_code}", &srv.url("/api/orders/9")])
        .output()
        .unwrap();
    assert_eq!(String::from_utf8_lossy(&out.stdout), "204");
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
    let m = loop {
        let m = ok(&p, &["authz", "matrix", &run_id]);
        if m["requests"].as_array().unwrap().len() >= 2 || std::time::Instant::now() > deadline {
            break m;
        }
        std::thread::sleep(std::time::Duration::from_millis(200));
    };
    assert_eq!(cell(&m, "/api/orders/1", "bob")["verdict"], "bypass", "{m}");
    assert_eq!(cell(&m, "/api/orders/9", "bob")["verdict"], "inconclusive", "{m}");
    assert_eq!(m["requests"][0]["owner"], "alice", "{m}");
    // The options it was started with, for starting it again alike.
    let status = ok(&p, &["--home", home, "proxy", "status"]);
    let started_with = status["proxy"]["args"].to_string();
    assert!(started_with.contains("\"--auth\",\"alice\"") && started_with.contains("\"--authz\",\"bob\""), "{status}");
    ok(&p, &["--home", home, "proxy", "stop"]);
    let job = ok(&p, &["job", "status", &run_id]);
    assert_eq!(job["result"]["verdicts"]["inconclusive"], 1, "{job}");
    assert_eq!(job["result"]["verdicts"]["bypass"], 1, "{job}");
    assert_eq!(job["result"]["new_findings"], 1, "{job}");
}

/// A run whose proxy was killed isn't shown as live for ever.
#[cfg(unix)]
#[test]
fn authz_list_reaps_a_run_whose_proxy_died() {
    let p = tmp_project("live-killed");
    let home = p.with_file_name("home");
    let home = home.to_str().unwrap();
    let started = ok(&p, &["--home", home, "proxy", "start", "--listen", "127.0.0.1:0", "--authz", "anonymous"]);
    let pid = started["pid"].as_i64().unwrap().to_string();
    assert!(Command::new("kill").args(["-9", &pid]).status().unwrap().success());
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(15);
    loop {
        let runs = ok(&p, &["authz", "list"]);
        if runs["runs"][0]["state"] == "failed" {
            break;
        }
        assert!(std::time::Instant::now() < deadline, "{runs}");
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
}

#[test]
fn a_named_request_still_needs_its_opt_ins() {
    let srv = Server::start();
    let p = tmp_project("named");
    let logout = ok(&p, &["send", "--url", &srv.url("/logout"), "--auth", "alice"])["id"].to_string();
    let delete =
        ok(&p, &["send", "-X", "DELETE", "--url", &srv.url("/api/orders/3"), "--auth", "alice"])["id"].to_string();
    assert_eq!(srv.logouts.load(Ordering::SeqCst), 1);

    // Naming a logout doesn't replay it as every identity; nothing is sent.
    let (code, v) = run(&p, &["authz", "run", "--as", "bob", "--history-id", &logout]);
    assert_eq!(code, 2, "{v}");
    assert!(v["error"]["message"].as_str().unwrap().contains("--exclude"), "{v}");
    assert_eq!(srv.logouts.load(Ordering::SeqCst), 1);
    // A pattern it doesn't match says the person means it.
    ok(&p, &["authz", "run", "--as", "bob", "--history-id", &logout, "--exclude", "^$"]);
    assert!(srv.logouts.load(Ordering::SeqCst) > 1);

    // Nor a DELETE without its method.
    let (code, v) = run(&p, &["authz", "run", "--as", "bob", "--history-id", &delete]);
    assert_eq!(code, 2, "{v}");
    assert!(v["error"]["message"].as_str().unwrap().contains("--include-methods DELETE"), "{v}");
    let r = ok(&p, &["authz", "run", "--as", "bob", "--history-id", &delete, "--include-methods", "DELETE"]);
    assert_eq!(r["requests"], 1, "{r}");
}
