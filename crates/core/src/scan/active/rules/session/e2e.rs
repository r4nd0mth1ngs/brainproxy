//! End-to-end: the session rules and SOAP action spoofing through the real engine against an
//! in-test server with a vulnerable and a fixed version of each: a login that keeps the session
//! cookie it was given and says whether the user exists, and one that renews it and doesn't; a
//! page that ignores its session cookie and one that needs every cookie; an upload served back
//! as HTML and one served as a download; a SOAP service that ignores SOAPAction and one that
//! checks it.

use std::collections::{HashMap, HashSet};
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use crate::auth::{AuthProfile, AuthSession, Secret, SessionState};
use crate::guard::{Guard, ScopeSpec};
use crate::http::{Client, SendOptions, Target};
use crate::jobs::JobControl;
use crate::scan::active::{run, ActiveConfig, ActiveSummary, PointOptions, ScanTarget, Strength};

fn reply(status: &str, headers: &str, body: &str) -> String {
    format!("HTTP/1.1 {status}\r\n{headers}Content-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len())
}

fn header<'a>(req: &'a str, name: &str) -> Option<&'a str> {
    let head = req.split("\r\n\r\n").next().unwrap_or_default();
    head.lines().find_map(|l| l.split_once(':').filter(|(k, _)| k.eq_ignore_ascii_case(name)).map(|(_, v)| v.trim()))
}

fn cookie<'a>(req: &'a str, name: &str) -> Option<&'a str> {
    header(req, "cookie")?.split(';').find_map(|c| c.trim().strip_prefix(&format!("{name}=")))
}

#[derive(Default)]
struct App {
    /// Session ids that are logged in.
    authenticated: HashSet<String>,
    /// Uploaded files by name: (content, uploaded through the fixed endpoint).
    files: HashMap<String, (String, bool)>,
    next: u64,
}

impl App {
    fn new_sid(&mut self) -> String {
        self.next += 1;
        format!("s{:x}{}", crate::scan::active::rand_u64(), self.next)
    }

    fn handle(&mut self, req: &str) -> String {
        let line = req.lines().next().unwrap_or_default();
        let mut parts = line.split(' ');
        let (method, target) = (parts.next().unwrap_or(""), parts.next().unwrap_or("/"));
        let path = target.split('?').next().unwrap_or(target);
        let body = req.split_once("\r\n\r\n").map_or("", |(_, b)| b);
        let sid = cookie(req, "SID").map(str::to_string);
        match (method, path) {
            ("GET", "/login" | "/login-fixed") => match sid {
                Some(_) => reply("200 OK", "", "<form>login</form>"),
                None => {
                    let sid = self.new_sid();
                    reply("200 OK", &format!("Set-Cookie: SID={sid}; Path=/\r\n"), "<form>login</form>")
                }
            },
            ("POST", "/login" | "/login-fixed") => {
                let fixed = path == "/login-fixed";
                let form: HashMap<String, String> = url::form_urlencoded::parse(body.as_bytes()).into_owned().collect();
                let (user, pass) =
                    (form.get("user").cloned().unwrap_or_default(), form.get("pass").cloned().unwrap_or_default());
                if user == "alice" && pass == "pw" {
                    // The vulnerable login keeps the session it was given; the fixed one renews it.
                    let (sid, set) = match (sid, fixed) {
                        (Some(s), false) => (s, String::new()),
                        _ => {
                            let s = self.new_sid();
                            let set = format!("Set-Cookie: SID={s}; Path=/\r\n");
                            (s, set)
                        }
                    };
                    self.authenticated.insert(sid);
                    return reply("302 Found", &format!("{set}Location: /me\r\n"), "");
                }
                let text = match (fixed, user == "alice") {
                    (true, _) => "Invalid username or password",
                    (false, true) => "Wrong password",
                    (false, false) => "No such user",
                };
                reply("200 OK", "Content-Type: text/html\r\n", &format!("<p>{text}</p><input value=\"{user}\">"))
            }
            ("GET", "/me") => match sid.filter(|s| self.authenticated.contains(s)) {
                Some(_) => reply("200 OK", "", "Welcome alice"),
                None => reply("200 OK", "", "Please log in"),
            },
            // Ignores its cookies; needs every one of them.
            ("GET", "/slack") => reply("200 OK", "", "the same page for everyone"),
            ("GET", "/strict") => {
                let mut page = "page".to_string();
                for name in ["sessionid", "theme", "SID"] {
                    if cookie(req, name).is_some() {
                        page.push_str(&format!(" with {name}"));
                    }
                }
                reply("200 OK", "", &page)
            }
            ("POST", "/upload" | "/upload-fixed") => {
                let name =
                    body.split("filename=\"").nth(1).and_then(|r| r.split('"').next()).unwrap_or("f").to_string();
                let file = body.split("filename=\"").nth(1).unwrap_or_default();
                let content = file.split("\r\n\r\n").nth(1).and_then(|r| r.split("\r\n--").next()).unwrap_or("");
                let fixed = path == "/upload-fixed";
                self.files.insert(name.clone(), (content.to_string(), fixed));
                let at = if fixed { "/files/" } else { "/uploads/" };
                reply("200 OK", "Content-Type: text/html\r\n", &format!("Saved: <a href=\"{at}{name}\">your file</a>"))
            }
            ("GET", p) if p.starts_with("/uploads/") || p.starts_with("/files/") => {
                let name = p.rsplit('/').next().unwrap_or_default();
                match self.files.get(name) {
                    Some((content, false)) if p.starts_with("/uploads/") => {
                        let ct = if name.ends_with(".svg") {
                            "image/svg+xml"
                        } else if name.ends_with(".txt") {
                            "text/plain"
                        } else {
                            "text/html"
                        };
                        reply("200 OK", &format!("Content-Type: {ct}\r\n"), content)
                    }
                    Some((content, true)) if p.starts_with("/files/") => reply(
                        "200 OK",
                        "Content-Type: application/octet-stream\r\nContent-Disposition: attachment\r\n",
                        content,
                    ),
                    _ => reply("404 Not Found", "", "no"),
                }
            }
            ("POST", "/soap" | "/soap-fixed") => {
                let action = header(req, "soapaction").unwrap_or("");
                let ok = path == "/soap" || action == "\"urn:GetPrice\"";
                let inner = if ok {
                    "<m:GetPriceResponse xmlns:m=\"urn:x\"><m:Price>1</m:Price></m:GetPriceResponse>"
                } else {
                    "<soap:Fault><faultcode>soap:Client</faultcode><faultstring>bad action</faultstring></soap:Fault>"
                };
                let xml = format!(
                    "<?xml version=\"1.0\"?><soap:Envelope xmlns:soap=\"http://schemas.xmlsoap.org/soap/envelope/\"><soap:Body>{inner}</soap:Body></soap:Envelope>"
                );
                reply(if ok { "200 OK" } else { "500 Internal Server Error" }, "Content-Type: text/xml\r\n", &xml)
            }
            _ => reply("200 OK", "", "home"),
        }
    }
}

fn read_request(s: &mut TcpStream) -> String {
    let mut got = Vec::new();
    let mut buf = [0u8; 8192];
    loop {
        let n = s.read(&mut buf).unwrap_or(0);
        if n == 0 {
            break;
        }
        got.extend_from_slice(&buf[..n]);
        let text = String::from_utf8_lossy(&got);
        if let Some((head, body)) = text.split_once("\r\n\r\n") {
            let len = header(&format!("{head}\r\n\r\n"), "content-length").and_then(|v| v.parse().ok()).unwrap_or(0);
            if body.len() >= len {
                break;
            }
        }
    }
    String::from_utf8_lossy(&got).into_owned()
}

fn spawn_app() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let app = Arc::new(Mutex::new(App::default()));
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut s) = stream else { continue };
            let app = app.clone();
            std::thread::spawn(move || {
                let req = read_request(&mut s);
                let resp = app.lock().unwrap().handle(&req);
                let _ = s.write_all(resp.as_bytes());
            });
        }
    });
    port
}

fn send_raw(port: u16, req: &str) -> Vec<u8> {
    let mut s = TcpStream::connect(("127.0.0.1", port)).unwrap();
    s.write_all(req.as_bytes()).unwrap();
    let mut out = Vec::new();
    s.read_to_end(&mut out).unwrap();
    out
}

fn target(port: u16, request: String) -> ScanTarget {
    let response = send_raw(port, &request);
    ScanTarget {
        history_id: None,
        target: Target::from_url(&format!("http://127.0.0.1:{port}")).unwrap(),
        request: request.into_bytes(),
        response,
        duration_ms: None,
    }
}

fn get(port: u16, path: &str, cookies: &str) -> ScanTarget {
    let cookies = if cookies.is_empty() { String::new() } else { format!("Cookie: {cookies}\r\n") };
    target(port, format!("GET {path} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n{cookies}Connection: close\r\n\r\n"))
}

fn post(port: u16, path: &str, headers: &str, body: &str) -> ScanTarget {
    target(
        port,
        format!(
            "POST {path} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n{headers}Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        ),
    )
}

fn upload(port: u16, path: &str) -> ScanTarget {
    let body = "--b\r\nContent-Disposition: form-data; name=\"title\"\r\n\r\nholiday\r\n--b\r\nContent-Disposition: form-data; \
                name=\"photo\"; filename=\"cat.png\"\r\nContent-Type: image/png\r\n\r\nPNGDATA\r\n--b--\r\n";
    post(port, path, "Content-Type: multipart/form-data; boundary=b\r\n", body)
}

fn soap(port: u16, path: &str) -> ScanTarget {
    let body =
        "<?xml version=\"1.0\"?><soap:Envelope xmlns:soap=\"http://schemas.xmlsoap.org/soap/envelope/\"><soap:Body>\
                <m:GetPrice xmlns:m=\"urn:x\"><m:Item>apple</m:Item></m:GetPrice></soap:Body></soap:Envelope>";
    post(port, path, "Content-Type: text/xml; charset=utf-8\r\nSOAPAction: \"urn:GetPrice\"\r\n", body)
}

/// An `--auth` profile for alice whose login is the form at `login`, already logged in.
fn session(db: &std::path::Path, guard: &Arc<Guard>, port: u16, login: &str) -> Arc<AuthSession> {
    let profile = AuthProfile {
        name: "alice".into(),
        login_url: Some(format!("http://127.0.0.1:{port}{login}")),
        login_method: "POST".into(),
        login_body: Some("user={{username}}&pass={{password}}".into()),
        username: Some("alice".into()),
        password: Some(Secret::Literal("pw".into())),
        check_url: Some(format!("http://127.0.0.1:{port}/me")),
        logged_in: Some("Welcome".into()),
        ..Default::default()
    };
    let store = crate::store::Store::open(db).unwrap();
    store.auth_save_profile(&profile).unwrap();
    let state = SessionState { cookies: vec![("SID".into(), "scan".into())], logged_in: true, ..Default::default() };
    store.auth_save_state("alice", &state).unwrap();
    let client = Client::new(SendOptions { guard: Some(guard.clone()), ..Default::default() });
    Arc::new(AuthSession::new(db, profile, state, client).unwrap())
}

struct Scanned {
    refs: Vec<String>,
    risks: Vec<String>,
    summary: ActiveSummary,
}

/// Scans `t` with `rules`; `login` names the `--auth` profile's login form (None: no --auth).
async fn scan(port: u16, t: ScanTarget, rules: &[u32], login: Option<&str>) -> Scanned {
    let guard =
        Guard::from_specs(vec![ScopeSpec { name: None, include: vec!["127.0.0.1".into()], exclude: vec![] }]).unwrap();
    let dir =
        std::env::temp_dir().join(format!("bp-session-{}-{}", std::process::id(), crate::scan::active::rand_u64()));
    std::fs::create_dir_all(&dir).unwrap();
    let db = dir.join("project.db");
    drop(crate::store::Store::open(&db).unwrap());
    let auth = login.map(|l| session(&db, &guard, port, l));
    let cfg = ActiveConfig {
        strength: Strength::Medium,
        tuning: Default::default(),
        concurrency: 2,
        rate: None,
        send: SendOptions { timeout: Duration::from_secs(20), guard: Some(guard), ..Default::default() },
        points: PointOptions::default(),
        rules: Some(rules.to_vec()),
        exclude_rules: vec![],
        no_rules: false,
        checks: vec![],
        max_duration: None,
        auth,
        oob: None,
        oob_wait: Duration::ZERO,
        check_methods: vec![],
        prune: false,
    };
    let summary = run(&db, vec![t], cfg, JobControl::default()).await.unwrap();
    let conn = rusqlite::Connection::open(&db).unwrap();
    let rows: Vec<(String, String)> = conn
        .prepare("SELECT alert_ref, risk FROM findings WHERE source = 'active' ORDER BY alert_ref")
        .unwrap()
        .query_map([], |r| Ok((r.get(0)?, r.get(1)?)))
        .unwrap()
        .map(|r| r.unwrap())
        .collect();
    drop(conn);
    let _ = std::fs::remove_dir_all(&dir);
    Scanned {
        refs: rows.iter().map(|r| r.0.clone()).collect(),
        risks: rows.into_iter().map(|r| r.1).collect(),
        summary,
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn a_login_that_keeps_the_planted_session_is_session_fixation() {
    let port = spawn_app();
    let vulnerable = scan(port, get(port, "/", ""), &[40013], Some("/login")).await;
    assert_eq!(
        (vulnerable.refs.as_slice(), vulnerable.risks.as_slice()),
        (&["40013-4".to_string()][..], &["high".to_string()][..])
    );
    let fixed = scan(port, get(port, "/", ""), &[40013], Some("/login-fixed")).await;
    assert!(fixed.refs.is_empty(), "{:?}", fixed.refs);
    // Without --auth it is left out, and said so.
    let none = scan(port, get(port, "/", ""), &[40013, 90027], None).await;
    assert!(none.refs.is_empty());
    assert_eq!(none.summary.skipped.len(), 1, "{:?}", none.summary.skipped);
    assert_eq!(none.summary.skipped[0].rule, 40013);
    assert!(none.summary.skipped[0].reason.contains("needs --auth with a login"));
}

#[tokio::test(flavor = "multi_thread")]
async fn a_login_that_says_whether_the_user_exists_enumerates_usernames() {
    let port = spawn_app();
    let vulnerable = scan(port, get(port, "/", ""), &[40023], Some("/login")).await;
    assert_eq!(vulnerable.refs, ["40023"]);
    let fixed = scan(port, get(port, "/", ""), &[40023], Some("/login-fixed")).await;
    assert!(fixed.refs.is_empty(), "{:?}", fixed.refs);
}

#[tokio::test(flavor = "multi_thread")]
async fn an_ignored_session_cookie_is_slack_and_a_needed_one_is_not() {
    let port = spawn_app();
    let vulnerable = scan(port, get(port, "/slack", "sessionid=abc; theme=dark"), &[90027], None).await;
    assert_eq!(
        (vulnerable.refs.as_slice(), vulnerable.risks.as_slice()),
        (&["90027".to_string()][..], &["low".to_string()][..])
    );
    assert_eq!(vulnerable.summary.requests, 3, "a baseline and one request per cookie");
    let fixed = scan(port, get(port, "/strict", "sessionid=abc; theme=dark"), &[90027], None).await;
    assert!(fixed.refs.is_empty(), "{:?}", fixed.refs);
}

/// With --auth, the dropped cookie is the session's and stays out: the session neither puts it
/// back nor learns from the answer.
#[tokio::test(flavor = "multi_thread")]
async fn a_dropped_session_cookie_stays_out() {
    let port = spawn_app();
    let s = scan(port, get(port, "/strict", "theme=dark"), &[90027], Some("/login")).await;
    // /strict shows whether SID came: put back, it would look ignored.
    assert!(s.refs.is_empty(), "{:?}", s.refs);
    assert_eq!(s.summary.requests, 3);
}

#[tokio::test(flavor = "multi_thread")]
async fn an_upload_served_back_as_html_is_found_and_a_download_is_not() {
    let port = spawn_app();
    let vulnerable = scan(port, upload(port, "/upload"), &[40041], None).await;
    assert_eq!(vulnerable.refs, ["40041-1", "40041-2"]);
    let fixed = scan(port, upload(port, "/upload-fixed"), &[40041], None).await;
    assert_eq!(fixed.refs, ["40041-2"], "the files left are still listed");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_service_that_ignores_soapaction_is_found_and_one_that_checks_it_is_not() {
    let port = spawn_app();
    let vulnerable = scan(port, soap(port, "/soap"), &[90026], None).await;
    assert_eq!(vulnerable.refs, ["90026"]);
    let fixed = scan(port, soap(port, "/soap-fixed"), &[90026], None).await;
    assert!(fixed.refs.is_empty(), "{:?}", fixed.refs);
    // Not a SOAP request: nothing sent.
    let plain = scan(port, get(port, "/", ""), &[90026], None).await;
    assert_eq!(plain.summary.requests, 0);
}
