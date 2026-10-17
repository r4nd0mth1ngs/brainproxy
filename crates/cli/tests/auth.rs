//! End-to-end tests for authenticated sessions (`auth` and `--auth`) against a
//! local app with a CSRF-protected login form, expiring session cookies, and a
//! JSON login that returns a bearer token.

use std::collections::{HashMap, HashSet};
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};

use serde_json::Value;

const USER: &str = "alice";
/// Needs encoding in a form body.
const PASS: &str = "p&ss w0rd";

#[derive(Default)]
struct App {
    /// Pre-session cookie -> CSRF token issued with the login form.
    csrf: HashMap<String, String>,
    /// Session id -> requests left before it expires.
    sessions: HashMap<String, usize>,
    tokens: HashSet<String>,
    logins: usize,
    counter: usize,
    expire_after: usize,
    /// Protected requests served with a valid session.
    served: usize,
    /// Every request line with its Cookie header, in order.
    log: Vec<String>,
}

struct Server {
    port: u16,
    app: Arc<Mutex<App>>,
}

impl Server {
    fn start(expire_after: usize) -> Server {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let app = Arc::new(Mutex::new(App { expire_after, ..Default::default() }));
        let shared = app.clone();
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(s) = stream else { continue };
                let app = shared.clone();
                std::thread::spawn(move || handle(s, &app));
            }
        });
        Server { port, app }
    }

    fn url(&self, path: &str) -> String {
        format!("http://127.0.0.1:{}{path}", self.port)
    }

    fn logins(&self) -> usize {
        self.app.lock().unwrap().logins
    }

    fn log(&self) -> Vec<String> {
        self.app.lock().unwrap().log.clone()
    }
}

/// Request line, lowercased headers, body.
type Request = (String, Vec<(String, String)>, String);

fn read_request(s: &mut TcpStream) -> Option<Request> {
    let mut buf = Vec::new();
    let mut chunk = [0u8; 8192];
    loop {
        let n = s.read(&mut chunk).ok()?;
        if n == 0 {
            return None;
        }
        buf.extend_from_slice(&chunk[..n]);
        let text = String::from_utf8_lossy(&buf).to_string();
        if let Some(i) = text.find("\r\n\r\n") {
            let head = &text[..i];
            let mut lines = head.split("\r\n");
            let line = lines.next()?.to_string();
            let headers: Vec<(String, String)> = lines
                .filter_map(|l| l.split_once(':'))
                .map(|(k, v)| (k.trim().to_ascii_lowercase(), v.trim().to_string()))
                .collect();
            let cl = headers.iter().find(|(k, _)| k == "content-length").map_or(0, |(_, v)| v.parse().unwrap_or(0));
            if buf.len() >= i + 4 + cl {
                let body = String::from_utf8_lossy(&buf[i + 4..i + 4 + cl]).to_string();
                return Some((line, headers, body));
            }
        }
    }
}

fn form(body: &str) -> HashMap<String, String> {
    url::form_urlencoded::parse(body.as_bytes()).into_owned().collect()
}

fn handle(mut s: TcpStream, app: &Mutex<App>) {
    let Some((line, headers, body)) = read_request(&mut s) else { return };
    let header = |name: &str| headers.iter().find(|(k, _)| k == name).map(|(_, v)| v.clone());
    let cookies: HashMap<String, String> = header("cookie")
        .unwrap_or_default()
        .split(';')
        .filter_map(|c| c.split_once('='))
        .map(|(k, v)| (k.trim().to_string(), v.trim().to_string()))
        .collect();
    let mut parts = line.split(' ');
    let method = parts.next().unwrap_or("").to_string();
    let target = parts.next().unwrap_or("/").to_string();
    let path = target.split('?').next().unwrap_or("/").to_string();

    let mut a = app.lock().unwrap();
    a.log.push(format!("{line} | {}", header("cookie").unwrap_or_default()));
    a.counter += 1;
    let n = a.counter;
    let html = |status: &str, extra: &str, body: &str| {
        format!(
            "HTTP/1.1 {status}\r\nContent-Type: text/html\r\n{extra}Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        )
    };
    let redirect = |to: &str, extra: &str| {
        format!("HTTP/1.1 302 Found\r\nLocation: {to}\r\n{extra}Content-Length: 0\r\nConnection: close\r\n\r\n")
    };
    let resp = match (method.as_str(), path.as_str()) {
        ("GET", "/") => html("200 OK", "", "<a href=\"/home\">home</a>"),
        ("GET", "/login") => {
            let (pre, token) = (format!("pre{n}"), format!("tok{n}x"));
            a.csrf.insert(pre.clone(), token.clone());
            let page = format!(
                "<form method=\"post\" action=\"/login\"><input type=\"hidden\" name=\"csrf\" value=\"{token}\">\
                 <input name=\"user\"><input name=\"pass\" type=\"password\"></form>Please log in"
            );
            html("200 OK", &format!("Set-Cookie: pre={pre}; Path=/\r\n"), &page)
        }
        ("POST", "/login") => {
            let f = form(&body);
            let csrf_ok = cookies.get("pre").and_then(|p| a.csrf.get(p)) == f.get("csrf");
            if csrf_ok
                && f.get("user").map(String::as_str) == Some(USER)
                && f.get("pass").map(String::as_str) == Some(PASS)
            {
                let sid = format!("s{n}");
                let uses = a.expire_after;
                a.sessions.insert(sid.clone(), uses);
                a.logins += 1;
                redirect("/home", &format!("Set-Cookie: sid={sid}; Path=/; HttpOnly\r\n"))
            } else {
                html("200 OK", "", "Invalid credentials. Please log in")
            }
        }
        ("GET", "/logout") => {
            if let Some(sid) = cookies.get("sid") {
                a.sessions.remove(sid);
            }
            redirect("/login", "Set-Cookie: sid=; Max-Age=0\r\n")
        }
        ("POST", "/api/login") => {
            let v: Value = serde_json::from_str(&body).unwrap_or_default();
            if v["username"] == USER && v["password"] == PASS {
                let token = format!("bearer{n}");
                a.tokens.insert(token.clone());
                a.logins += 1;
                let json = format!("{{\"token\":\"{token}\"}}");
                html("200 OK", "", &json)
            } else {
                html("403 Forbidden", "", "{\"error\":\"bad credentials\"}")
            }
        }
        ("GET", "/api/me") => {
            let token = header("authorization").and_then(|h| h.strip_prefix("Bearer ").map(str::to_string));
            if token.is_some_and(|t| a.tokens.contains(&t)) {
                html("200 OK", "", "{\"user\":\"alice\"}")
            } else {
                html("401 Unauthorized", "", "{\"error\":\"login required\"}")
            }
        }
        (_, p) if p == "/home" || p.starts_with("/account") => {
            let valid = match cookies.get("sid").and_then(|sid| a.sessions.get_mut(sid)) {
                Some(left) if *left > 0 => {
                    *left -= 1;
                    a.served += 1;
                    true
                }
                _ => false,
            };
            if valid {
                html(
                    "200 OK",
                    "",
                    &format!(
                        "Welcome {USER} on {p}. <a href=\"/account/orders\">orders</a> \
                         <a href=\"/account/profile?tab=1\">profile</a> <a href=\"/logout\">logout</a>"
                    ),
                )
            } else {
                redirect(&format!("/login?next={p}"), "")
            }
        }
        _ => html("404 Not Found", "", "not found"),
    };
    drop(a);
    let _ = s.write_all(resp.as_bytes());
}

fn bin() -> Command {
    Command::new(env!("CARGO_BIN_EXE_brainproxy"))
}

fn run(project: &std::path::Path, args: &[&str]) -> (i32, Value) {
    let out = bin()
        .args(["--format", "json", "--project"])
        .arg(project)
        .args(args)
        .env("BP_TEST_PASSWORD", PASS)
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
    let dir = std::env::temp_dir().join(format!("bp-auth-{}-{name}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let p = dir.join("p.bpdb");
    let _ = std::fs::remove_file(&p);
    ok(&p, &["engagement", "start", "--target", "127.0.0.1"]);
    p
}

/// Adds the form-login profile "app" for `srv`.
fn add_form_profile(p: &std::path::Path, srv: &Server, password_flag: &[&str]) {
    let login = srv.url("/login");
    let check = srv.url("/home");
    let mut args = vec![
        "auth",
        "add",
        "app",
        "--login-url",
        &login,
        "--login-body",
        "user={{username}}&pass={{password}}&csrf={{csrf}}",
        "--username",
        USER,
        "--csrf-url",
        &login,
        "--csrf-regex",
        r#"name="csrf" value="([^"]+)""#,
        "--logged-in",
        "Welcome alice",
        "--check-url",
        &check,
        "--relogin-interval",
        "0",
    ];
    args.extend_from_slice(password_flag);
    ok(p, &args);
}

#[test]
fn form_login_with_csrf_then_send_and_relogin() {
    let srv = Server::start(3);
    let p = tmp_project("form");
    add_form_profile(&p, &srv, &["--password-env", "BP_TEST_PASSWORD"]);

    let login = ok(&p, &["auth", "login", "app"]);
    assert_eq!(login["login"]["success"], true, "{login}");
    assert!(login["login"]["cookies"].as_array().unwrap().contains(&serde_json::json!("sid")), "{login}");
    assert_eq!(srv.logins(), 1);

    // The session expires after 3 requests (the login check used one); every
    // send still succeeds because brainproxy notices the redirect to /login
    // and logs in again.
    for i in 0..5 {
        let r = ok(&p, &["send", "--url", &srv.url(&format!("/account?i={i}")), "--auth", "app"]);
        assert_eq!(r["response"]["status"], 200, "send {i}: {r}");
        assert!(r["response"]["body"]["content"].as_str().unwrap().contains("Welcome alice"));
    }
    assert!(srv.logins() >= 2, "expected an automatic re-login, got {} logins", srv.logins());

    // Without --auth the same URL redirects to the login page.
    let r = ok(&p, &["send", "--url", &srv.url("/account")]);
    assert_eq!(r["response"]["status"], 302);

    // status checks the session live: whatever it reports matches the check URL.
    let st = ok(&p, &["auth", "status", "app"]);
    assert_eq!(st["session"]["logged_in"], st["check"]["logged_in"], "{st}");
    // A fresh login has uses left (the login check takes one, status another).
    ok(&p, &["auth", "login", "app"]);
    let st = ok(&p, &["auth", "status", "app"]);
    assert_eq!(st["check"]["logged_in"], true, "{st}");
    let st = ok(&p, &["auth", "status", "app", "--offline"]);
    assert!(st.get("check").is_none(), "{st}");
    let headers = ok(&p, &["auth", "headers", "app"]);
    let cookie = headers["headers"][0].as_str().unwrap();
    assert!(cookie.starts_with("Cookie: ") && cookie.contains("sid=s"), "{headers}");

    // The password came from the environment and is not stored.
    let shown = ok(&p, &["auth", "show", "app"]);
    assert_eq!(shown["profile"]["password"], serde_json::json!({"env": "BP_TEST_PASSWORD"}));
    let list = ok(&p, &["auth", "list"]);
    assert_eq!(list["profiles"].as_array().unwrap().len(), 1);
    ok(&p, &["auth", "remove", "app"]);
    let (code, _) = run(&p, &["auth", "show", "app"]);
    assert_eq!(code, 4);
}

#[test]
fn literal_password_is_redacted_and_bad_login_fails() {
    let srv = Server::start(100);
    let p = tmp_project("bad");
    add_form_profile(&p, &srv, &["--password", "wrong"]);
    let shown = ok(&p, &["auth", "show", "app"]);
    assert_eq!(shown["profile"]["password"], serde_json::json!({"literal": "********"}));
    let (code, v) = run(&p, &["auth", "login", "app"]);
    assert_eq!(code, 2, "{v}");
    assert!(v["error"]["message"].as_str().unwrap().contains("login failed"), "{v}");
    // A command using the profile fails the same way instead of scanning logged out.
    let (code, _) = run(&p, &["send", "--url", &srv.url("/account"), "--auth", "app"]);
    assert_eq!(code, 2);
}

#[test]
fn json_login_with_bearer_token() {
    let srv = Server::start(100);
    let p = tmp_project("json");
    ok(
        &p,
        &[
            "auth",
            "add",
            "api",
            "--login-url",
            &srv.url("/api/login"),
            "--login-body",
            r#"{"username":"{{username}}","password":"{{password}}"}"#,
            "--username",
            USER,
            "--password-env",
            "BP_TEST_PASSWORD",
            "--token-regex",
            r#""token":"([^"]+)""#,
            "--token-header",
            "Authorization: Bearer {{token}}",
        ],
    );
    let r = ok(&p, &["send", "--url", &srv.url("/api/me"), "--auth", "api"]);
    assert_eq!(r["response"]["status"], 200, "{r}");
    let h = ok(&p, &["auth", "headers", "api"]);
    assert!(h["headers"][0].as_str().unwrap().starts_with("Authorization: Bearer bearer"), "{h}");
}

#[test]
fn static_header_profile() {
    let srv = Server::start(100);
    let p = tmp_project("static");
    ok(&p, &["auth", "add", "key", "-H", "Authorization: Bearer nope"]);
    let r = ok(&p, &["send", "--url", &srv.url("/api/me"), "--auth", "key"]);
    assert_eq!(r["response"]["status"], 401);
    assert!(srv.log().last().unwrap().starts_with("GET /api/me"));
}

#[test]
fn crawl_with_auth_reaches_protected_pages() {
    let srv = Server::start(4);
    let p = tmp_project("crawl");
    add_form_profile(&p, &srv, &["--password-env", "BP_TEST_PASSWORD"]);
    let s = ok(&p, &["crawl", &srv.url("/"), "--auth", "app", "-c", "1", "--no-forms"]);
    assert!(s["requests"].as_u64().unwrap() > 3, "{s}");
    let q = ok(
        &p,
        &["query", "SELECT path, status FROM history WHERE source = 'crawl' AND path LIKE '/account/%' ORDER BY id"],
    );
    let rows = q["rows"].as_array().unwrap();
    assert!(!rows.is_empty(), "{q}");
    assert!(rows.iter().all(|r| r[1] == 200), "protected pages not reached: {q}");
    // The logout link is excluded by default, and history holds the requests as sent.
    assert!(!srv.log().iter().any(|l| l.starts_with("GET /logout")));
    let q = ok(&p, &["query", "SELECT count(*) FROM history WHERE source = 'crawl' AND req_headers LIKE '%sid=s%'"]);
    assert!(q["rows"][0][0].as_i64().unwrap() > 0, "{q}");
}

#[test]
fn fuzz_with_auth_stays_logged_in() {
    let srv = Server::start(3);
    let p = tmp_project("fuzz");
    add_form_profile(&p, &srv, &["--password-env", "BP_TEST_PASSWORD"]);
    let url = srv.url("/account/profile?tab=§x§");
    ok(&p, &["fuzz", "run", "--url", &url, "-p", "range:1-8", "-c", "1", "--auth", "app"]);
    let q = ok(&p, &["query", "SELECT status, count(*) FROM fuzz_results GROUP BY status"]);
    assert_eq!(q["rows"], serde_json::json!([[200, 8]]), "{q}");
    assert!(srv.logins() >= 3, "logins: {}", srv.logins());
}

#[test]
fn fuzzed_cookie_keeps_its_payload() {
    let srv = Server::start(100);
    let p = tmp_project("fuzzcookie");
    add_form_profile(&p, &srv, &["--password-env", "BP_TEST_PASSWORD"]);
    ok(&p, &["fuzz", "run", "--url", &srv.url("/account"), "-H", "Cookie: sid=§x§", "-p", "list:AAA", "--auth", "app"]);
    // The fuzzed sid is sent as the payload, not replaced by the session's sid.
    let log = srv.log();
    let fuzzed: Vec<&String> = log.iter().filter(|l| l.starts_with("GET /account ")).collect();
    assert!(fuzzed[0].contains("sid=AAA"), "{log:?}");
}

#[test]
fn proxy_adds_session_to_in_scope_requests() {
    let srv = Server::start(3);
    let p = tmp_project("proxy");
    add_form_profile(&p, &srv, &["--password-env", "BP_TEST_PASSWORD"]);
    let home = p.parent().unwrap().join("home");
    let home = home.to_str().unwrap();
    let started = ok(&p, &["--home", home, "proxy", "start", "--listen", "127.0.0.1:0", "--auth", "app"]);
    let listen = started["listen"].as_str().unwrap().to_string();
    let fetch = |path: &str| {
        let mut s = TcpStream::connect(&listen).unwrap();
        let req =
            format!("GET {} HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nConnection: close\r\n\r\n", srv.url(path), srv.port);
        s.write_all(req.as_bytes()).unwrap();
        let mut out = String::new();
        s.read_to_string(&mut out).unwrap();
        out
    };
    // More requests than one session allows: the proxy re-logs in transparently.
    for i in 0..5 {
        let r = fetch(&format!("/account?i={i}"));
        assert!(r.starts_with("HTTP/1.1 200") && r.contains("Welcome alice"), "request {i}: {r}");
    }
    ok(&p, &["--home", home, "proxy", "stop"]);
    assert!(srv.logins() >= 2);
}

#[test]
fn active_scan_with_auth_attacks_logged_in() {
    let srv = Server::start(5);
    let p = tmp_project("active");
    add_form_profile(&p, &srv, &["--password-env", "BP_TEST_PASSWORD"]);
    let url = srv.url("/account/profile?tab=1");
    ok(&p, &["scan", "active", &url, "--auth", "app", "--rules", "30001,30002", "-c", "1"]);
    let a = srv.app.lock().unwrap();
    let attacks = a.log.iter().filter(|l| l.starts_with("GET /account/profile?tab=")).count();
    // The baseline plus the attacks were served logged in, re-logging in as sessions expired.
    assert!(attacks > 5, "{:?}", a.log);
    assert!(a.served > attacks / 2, "served {} of {attacks}: {:?}", a.served, a.log);
    assert!(a.logins >= 2, "logins: {}", a.logins);
}
