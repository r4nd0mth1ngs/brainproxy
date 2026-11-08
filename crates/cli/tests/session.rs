//! End-to-end tests for session handling (`auth macro`, `auth rule`) against a local
//! app whose forms carry CSRF tokens that are good for one use (or three), tied to a
//! session cookie, and whose API wants a bearer token handed out for a valid token.

use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};

use serde_json::Value;

#[derive(Default)]
struct App {
    counter: usize,
    /// CSRF token -> (session cookie, uses left).
    tokens: HashMap<String, (String, usize)>,
    api_tokens: Vec<String>,
    /// Form pages served (macro runs).
    forms: usize,
    /// Protected requests accepted, and refused for a bad token.
    accepted: usize,
    rejected: usize,
    /// "METHOD target | cookie | body | accepted" per request.
    log: Vec<String>,
}

struct Server {
    port: u16,
    app: Arc<Mutex<App>>,
}

impl Server {
    fn start() -> Server {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let app = Arc::new(Mutex::new(App::default()));
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

    fn origin(&self) -> String {
        self.url("")
    }

    fn forms(&self) -> usize {
        self.app.lock().unwrap().forms
    }
}

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

fn params(s: &str) -> HashMap<String, String> {
    url::form_urlencoded::parse(s.as_bytes()).into_owned().collect()
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
    let (path, query) = target.split_once('?').unwrap_or((&target, ""));
    let (path, query) = (path.to_string(), params(query));
    let sid = cookies.get("sid").cloned();

    let mut a = app.lock().unwrap();
    a.counter += 1;
    let n = a.counter;
    let reply = |status: &str, extra: &str, ct: &str, body: &str| {
        format!(
            "HTTP/1.1 {status}\r\nContent-Type: {ct}\r\n{extra}Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        )
    };
    // Uses up one use of a token issued for this session.
    let spend = |a: &mut App, token: Option<&String>| -> bool {
        let ok = match token.and_then(|t| a.tokens.get_mut(t)) {
            Some((owner, left)) if Some(&*owner) == sid.as_ref() && *left > 0 => {
                *left -= 1;
                true
            }
            _ => false,
        };
        if ok {
            a.accepted += 1;
        } else {
            a.rejected += 1;
        }
        ok
    };
    let resp = match (method.as_str(), path.as_str()) {
        ("GET", "/form") => {
            a.forms += 1;
            let (sid, set) = match &sid {
                Some(s) => (s.clone(), String::new()),
                None => (format!("s{n}"), format!("Set-Cookie: sid=s{n}; Path=/\r\n")),
            };
            let token = format!("csrf-tok-{n:04}-abcdef");
            let uses = query.get("uses").and_then(|u| u.parse().ok()).unwrap_or(1);
            a.tokens.insert(token.clone(), (sid, uses));
            let page = format!("<form method=post><input type=\"hidden\" name=\"csrf\" value=\"{token}\"></form>");
            reply("200 OK", &set, "text/html", &page)
        }
        ("POST", "/exchange") => {
            if spend(&mut a, params(&body).get("csrf")) {
                let token = format!("api-{n:04}-0123456789");
                a.api_tokens.push(token.clone());
                reply("200 OK", "", "application/json", &format!("{{\"data\":{{\"token\":\"{token}\"}}}}"))
            } else {
                reply("403 Forbidden", "", "text/plain", "invalid csrf token")
            }
        }
        ("GET", "/api/me") => {
            let token = header("authorization").and_then(|h| h.strip_prefix("Bearer ").map(str::to_string));
            if token.is_some_and(|t| a.api_tokens.contains(&t)) {
                reply("200 OK", "", "application/json", "{\"user\":\"alice\"}")
            } else {
                reply("401 Unauthorized", "", "application/json", "{\"error\":\"login required\"}")
            }
        }
        ("POST", "/transfer") => {
            let f = params(&body);
            if spend(&mut a, f.get("csrf")) {
                reply("200 OK", "", "text/plain", &format!("sent {}", f.get("amount").cloned().unwrap_or_default()))
            } else {
                reply("403 Forbidden", "", "text/plain", "invalid csrf token")
            }
        }
        ("GET", "/search") => {
            if spend(&mut a, query.get("csrf")) {
                reply(
                    "200 OK",
                    "",
                    "text/html",
                    &format!("results for {}", query.get("q").cloned().unwrap_or_default()),
                )
            } else {
                reply("403 Forbidden", "", "text/plain", "invalid csrf token")
            }
        }
        _ => reply("404 Not Found", "", "text/plain", "not found"),
    };
    let status = resp.split(' ').nth(1).unwrap_or("").to_string();
    a.log.push(format!("{line} | {} | {body} | {status}", header("cookie").unwrap_or_default()));
    drop(a);
    let _ = s.write_all(resp.as_bytes());
}

const FORM: &str = "Content-Type: application/x-www-form-urlencoded";

fn run(project: &Path, args: &[&str]) -> (i32, Value) {
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

fn ok(project: &Path, args: &[&str]) -> Value {
    let (code, v) = run(project, args);
    assert_eq!(code, 0, "{args:?}: {v}");
    v["data"].clone()
}

fn query(project: &Path, sql: &str) -> Value {
    ok(project, &["query", sql])["rows"].clone()
}

fn tmp_project(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("bp-session-{}-{name}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let p = dir.join("p.bpdb");
    let _ = std::fs::remove_file(&p);
    ok(&p, &["engagement", "start", "--target", "127.0.0.1"]);
    p
}

/// Writes a raw request (LF line endings, as people write them) next to the project.
fn request_file(project: &Path, name: &str, text: &str) -> String {
    let path = project.parent().unwrap().join(name);
    std::fs::write(&path, text).unwrap();
    path.to_str().unwrap().to_string()
}

/// Macro `csrf`: fetch the form (a token good for `uses` requests) and extract the token.
fn add_csrf_macro(p: &Path, srv: &Server, uses: usize) {
    let form = request_file(
        p,
        "form.txt",
        &format!("GET /form?uses={uses} HTTP/1.1\nHost: 127.0.0.1:{}\nConnection: close\n\n", srv.port),
    );
    let step = format!("{}={form}", srv.origin());
    ok(p, &["auth", "macro", "add", "app", "csrf", "--step", &step, "--extract", "1:csrf=input:csrf"]);
}

#[test]
fn macro_chains_values_and_cookies_and_keeps_them_out_of_history() {
    let srv = Server::start();
    let p = tmp_project("chain");
    // Step 1 comes from history (as if picked in Traffic), the others from files.
    let sent = ok(&p, &["send", "--url", &srv.url("/form")]);
    let id = sent["id"].as_i64().unwrap().to_string();
    let host = format!("Host: 127.0.0.1:{}", srv.port);
    // The recorded csrf value is stale; the step's parameter of that name gets the extracted one.
    let exchange = request_file(
        &p,
        "exchange.txt",
        &format!(
            "POST /exchange HTTP/1.1\n{host}\nContent-Type: application/x-www-form-urlencoded\n\ncsrf=OLD&who={{{{username}}}}"
        ),
    );
    let me =
        request_file(&p, "me.txt", &format!("GET /api/me HTTP/1.1\n{host}\nAuthorization: Bearer {{{{api}}}}\n\n"));
    let (ex, me) = (format!("{}={exchange}", srv.origin()), format!("{}={me}", srv.origin()));
    ok(
        &p,
        &[
            "auth",
            "macro",
            "add",
            "app",
            "login",
            "--step",
            &id,
            "--step",
            &ex,
            "--step",
            &me,
            "--extract",
            "1:csrf=input:csrf",
            "--extract",
            "2:api=json:data.token",
            "--extract",
            "3:me=json:user",
        ],
    );
    // The macro made the profile; `auth add` sets its options and keeps the macro.
    ok(&p, &["auth", "add", "app", "--username", "alice"]);
    let shown = ok(&p, &["auth", "show", "app"]);
    assert_eq!(shown["macros"][0]["vars"], serde_json::json!(["csrf", "api", "me"]), "{shown}");

    let r = ok(&p, &["auth", "macro", "run", "app", "login"]);
    let steps = r["run"]["steps"].as_array().unwrap();
    assert_eq!(steps.len(), 3, "{r}");
    assert!(steps.iter().all(|s| s["status"] == 200), "{r}");
    // Values are shown masked.
    assert_eq!(steps[0]["extracted"][0]["value"], "csrf… (20 chars)", "{r}");
    assert_eq!(steps[1]["extracted"][0]["value"], "api-… (19 chars)", "{r}");
    assert_eq!(steps[2]["extracted"][0]["value"], "******** (5 chars)", "{r}");
    // The session cookie set by step 1 carried through: step 2 was accepted for this session.
    let log = srv.app.lock().unwrap().log.clone();
    let post = log.iter().find(|l| l.starts_with("POST /exchange")).unwrap();
    assert!(post.contains("sid=s") && post.contains("who=alice") && post.ends_with("| 200"), "{log:?}");

    // History holds placeholders, never the extracted token or cookie values.
    let rows = query(
        &p,
        "SELECT req_headers || char(10) || coalesce(req_body_text, '') FROM history WHERE source = 'auth' ORDER BY id",
    );
    let reqs: Vec<&str> = rows.as_array().unwrap().iter().map(|r| r[0].as_str().unwrap()).collect();
    assert_eq!(reqs.len(), 3, "{rows}");
    assert!(reqs[1].contains("csrf=«auth:app:var:csrf#1:form»&who=alice"), "{}", reqs[1]);
    assert!(reqs[1].contains("sid=«auth:app:cookie:sid»"), "{}", reqs[1]);
    assert!(reqs[2].contains("Bearer «auth:app:var:api#1»"), "{}", reqs[2]);
    let leaks = query(
        &p,
        "SELECT count(*) FROM history WHERE source = 'auth' AND (CAST(request AS TEXT) LIKE '%csrf-tok-%' \
         OR CAST(request AS TEXT) LIKE '%api-0%' OR CAST(request AS TEXT) LIKE '%sid=s%')",
    );
    assert_eq!(leaks[0][0], 0);
    // The session remembers the values (names only on display).
    assert_eq!(ok(&p, &["auth", "show", "app"])["session"]["vars"], serde_json::json!(["csrf", "api", "me"]));

    // A value that isn't there fails the run, saying which.
    ok(&p, &["auth", "macro", "add", "app", "bad", "--step", &id, "--extract", "1:nope=input:missing"]);
    let (code, v) = run(&p, &["auth", "macro", "run", "app", "bad"]);
    assert_ne!(code, 0);
    assert!(v["error"]["message"].as_str().unwrap().contains("missing: nope"), "{v}");
}

#[test]
fn fresh_csrf_token_per_request_during_a_fuzz_run() {
    let srv = Server::start();
    let p = tmp_project("fuzz");
    add_csrf_macro(&p, &srv, 1);
    ok(&p, &["auth", "rule", "add", "app", "--tool", "fuzz", "--action", "macro:csrf:each", "--action", "update:csrf"]);
    let url = srv.url("/transfer");
    ok(
        &p,
        &[
            "fuzz",
            "run",
            "--url",
            &url,
            "-X",
            "POST",
            "-H",
            FORM,
            "-d",
            "amount=§x§&csrf=stale",
            "-p",
            "range:1-12",
            "-c",
            "4",
            "--auth",
            "app",
        ],
    );
    // Every payload went out with a token of its own, four at a time.
    let q = query(&p, "SELECT status, count(*) FROM fuzz_results GROUP BY status");
    assert_eq!(q, serde_json::json!([[200, 12]]), "{q} {:?}", srv.app.lock().unwrap().log);
    assert_eq!(srv.forms(), 12);
    let rows = query(&p, "SELECT req_body_text FROM history WHERE source = 'fuzz'");
    assert!(
        rows.as_array().unwrap().iter().all(|r| r[0].as_str().unwrap().contains("&csrf=«auth:app:var:csrf#")),
        "{rows}"
    );

    // The rule is for fuzz only: `send` leaves the stale token alone and runs no macro.
    let r = ok(&p, &["send", "--url", &url, "-X", "POST", "-H", FORM, "-d", "amount=1&csrf=stale", "--auth", "app"]);
    assert_eq!(r["response"]["status"], 403, "{r}");
    assert_eq!(srv.forms(), 12);
}

#[test]
fn fresh_csrf_token_per_request_during_an_active_scan() {
    let srv = Server::start();
    let p = tmp_project("scan");
    add_csrf_macro(&p, &srv, 1);
    let scope = srv.url("/search");
    ok(
        &p,
        &[
            "auth",
            "rule",
            "add",
            "app",
            "--tool",
            "scan,checks",
            "--url",
            &scope,
            "--action",
            "macro:csrf:each",
            "--action",
            "update:csrf",
        ],
    );
    let url = srv.url("/search?q=1&csrf=stale");
    ok(&p, &["scan", "active", &url, "--auth", "app", "--rules", "30001,30002", "-c", "4"]);
    let a = srv.app.lock().unwrap();
    let searches: Vec<&String> = a.log.iter().filter(|l| l.starts_with("GET /search")).collect();
    // The baseline and the attacks on q each carried a fresh token; only attacks on
    // the csrf parameter itself (which keeps its payload) were refused.
    let refused: Vec<&&String> = searches.iter().filter(|l| l.ends_with("| 403")).collect();
    assert!(searches.len() > 5, "{:?}", a.log);
    assert!(refused.iter().all(|l| !l.contains("csrf=csrf-tok-")), "token reused or stale: {refused:?}");
    assert!(a.accepted > searches.len() / 3, "accepted {} of {}: {:?}", a.accepted, searches.len(), a.log);
    assert!(a.forms >= a.accepted, "{:?}", a.log);
}

#[test]
fn cached_values_refresh_when_rejected_and_rules_are_scoped_by_url() {
    let srv = Server::start();
    let p = tmp_project("cached");
    // Tokens good for three requests: the macro runs once, and again only when one is refused.
    add_csrf_macro(&p, &srv, 3);
    let scope = srv.url("/transfer");
    ok(
        &p,
        &[
            "auth",
            "rule",
            "add",
            "app",
            "--url",
            &scope,
            "--action",
            "macro:csrf",
            "--action",
            "update:csrf",
            "--invalid",
            "invalid csrf",
        ],
    );
    let rules = ok(&p, &["auth", "rule", "list", "app"]);
    assert_eq!(
        rules["rules"][0]["actions"][0],
        serde_json::json!({"action": "run_macro", "macro": "csrf", "every": 0})
    );
    let url = srv.url("/transfer");
    ok(
        &p,
        &[
            "fuzz",
            "run",
            "--url",
            &url,
            "-X",
            "POST",
            "-H",
            FORM,
            "-d",
            "amount=§x§&csrf=stale",
            "-p",
            "range:1-7",
            "-c",
            "1",
            "--auth",
            "app",
        ],
    );
    let q = query(&p, "SELECT status, count(*) FROM fuzz_results GROUP BY status");
    assert_eq!(q, serde_json::json!([[200, 7]]), "{q}");
    {
        let a = srv.app.lock().unwrap();
        // Runs for requests 1, 4 and 7; the 4th and 7th were refused once, then resent.
        assert_eq!((a.forms, a.rejected), (3, 2), "{:?}", a.log);
    }

    // Outside the rule's URL nothing is run or changed.
    let r = ok(&p, &["send", "--url", &srv.url("/search?q=1&csrf=stale"), "--auth", "app"]);
    assert_eq!(r["response"]["status"], 403);
    assert_eq!(srv.forms(), 3);
    // Inside it, a new command reuses no cache: one run, then the request.
    let r = ok(&p, &["send", "--url", &url, "-X", "POST", "-H", FORM, "-d", "amount=9&csrf=stale", "--auth", "app"]);
    assert_eq!(r["response"]["status"], 200, "{r}");
    assert_eq!(srv.forms(), 4);

    // A macro a rule runs can't be removed; the rule can, then the macro (once the
    // profile has something else to do).
    let (code, _) = run(&p, &["auth", "macro", "remove", "app", "csrf"]);
    assert_ne!(code, 0);
    ok(&p, &["auth", "rule", "remove", "app", "1"]);
    ok(&p, &["auth", "add", "app", "-H", "X-Client: test"]);
    ok(&p, &["auth", "macro", "remove", "app", "csrf"]);
    assert_eq!(ok(&p, &["auth", "macro", "list", "app"])["macros"], serde_json::json!([]));
}

#[test]
fn a_profile_needs_a_login_a_header_a_macro_or_a_rule() {
    let srv = Server::start();
    let p = tmp_project("empty");
    let (code, v) = run(&p, &["auth", "add", "app", "--username", "alice"]);
    assert_ne!(code, 0);
    assert!(v["error"]["message"].as_str().unwrap().contains("auth macro add app"), "{v}");
    // A rule has nothing to attach to yet.
    let (code, _) = run(&p, &["auth", "rule", "add", "app", "--action", "update:csrf"]);
    assert_ne!(code, 0);
    // A login or a header is enough to add a profile first, then macros and rules.
    ok(&p, &["auth", "add", "key", "-H", "X-Client: test"]);
    let form = request_file(&p, "form.txt", &format!("GET /form HTTP/1.1\nHost: 127.0.0.1:{}\n\n", srv.port));
    let step = format!("{}={form}", srv.origin());
    let added = ok(&p, &["auth", "macro", "add", "key", "csrf", "--step", &step]);
    assert_eq!(added["profile_created"], false);
    ok(&p, &["auth", "rule", "add", "key", "--action", "update:csrf"]);
    // No login at all: the first macro makes the profile.
    let added = ok(&p, &["auth", "macro", "add", "app", "csrf", "--step", &step]);
    assert_eq!(added["profile_created"], true);
    ok(&p, &["auth", "add", "app", "--username", "alice"]);
    // Its last macro can't go, leaving a profile with nothing to do; the profile can.
    let (code, v) = run(&p, &["auth", "macro", "remove", "app", "csrf"]);
    assert_ne!(code, 0);
    assert!(v["error"]["message"].as_str().unwrap().contains("auth remove app"), "{v}");
    ok(&p, &["auth", "remove", "app"]);
    let (code, _) = run(&p, &["auth", "macro", "list", "app"]);
    assert_ne!(code, 0);
    // Nothing of it is left to come back with a new profile of that name.
    ok(&p, &["auth", "add", "app", "-H", "X-Client: test"]);
    assert_eq!(ok(&p, &["auth", "macro", "list", "app"])["macros"], serde_json::json!([]));
}

#[test]
fn update_stays_within_the_rules_macros_and_their_origins() {
    let (a, b, c) = (Server::start(), Server::start(), Server::start());
    let p = tmp_project("origins");
    add_csrf_macro(&p, &a, 100);
    // Another macro's variable, named like a parameter of the requests below.
    let form = request_file(&p, "other.txt", &format!("GET /form HTTP/1.1\nHost: 127.0.0.1:{}\n\n", a.port));
    let step = format!("{}={form}", a.origin());
    ok(&p, &["auth", "macro", "add", "app", "other", "--step", &step, "--extract", "1:amount=input:csrf"]);
    ok(&p, &["auth", "macro", "run", "app", "other"]);
    let last_body = |srv: &Server| srv.app.lock().unwrap().log.last().unwrap().clone();
    let post = |srv: &Server, auth: bool, body: &str| {
        let url = srv.url("/transfer");
        let mut args = vec!["send", "--url", &url, "-X", "POST", "-H", FORM, "-d", body];
        if auth {
            args.extend(["--auth", "app"]);
        }
        run(&p, &args)
    };
    // What a value's placeholder may reach, as a request re-sent from history would.
    let reaches = |srv: &Server| post(srv, false, "csrf=«auth:app:var:csrf:form»").0 == 0;

    // No mapping: this rule's macro only, not every variable the session holds.
    ok(&p, &["auth", "rule", "add", "app", "--action", "macro:csrf", "--action", "update"]);
    let (code, r) = post(&a, true, "amount=5&csrf=stale");
    assert_eq!((code, &r["data"]["response"]["status"]), (0, &serde_json::json!(200)), "{r}");
    let sent = last_body(&a);
    assert!(sent.contains("amount=5&csrf=csrf-tok-"), "{sent}");
    let rows = query(&p, "SELECT req_body_text FROM history WHERE source = 'send' ORDER BY id DESC LIMIT 1");
    let body = rows[0][0].as_str().unwrap();
    assert!(body.starts_with("amount=5&csrf=«auth:app:var:csrf#") && !body.contains("var:amount"), "{body}");

    // No URL on the rule: another origin's requests stay as they are, and the value can't
    // reach that origin afterwards either.
    let (code, _) = post(&b, true, "amount=5&csrf=stale");
    assert_eq!(code, 0);
    assert!(last_body(&b).contains("amount=5&csrf=stale"), "{}", last_body(&b));
    assert!(reaches(&a) && !reaches(&b));

    // Naming the parameter and variable is no way around that without a URL.
    ok(&p, &["auth", "rule", "remove", "app", "1"]);
    ok(&p, &["auth", "rule", "add", "app", "--action", "update:csrf,amount=amount"]);
    let (code, _) = post(&b, true, "amount=5&csrf=stale");
    assert_eq!(code, 0);
    assert!(last_body(&b).contains("amount=5&csrf=stale"), "{}", last_body(&b));
    assert!(!reaches(&b));
    // On the macro's own origin a named variable of any macro is what was asked for.
    let (code, _) = post(&a, true, "amount=5&csrf=stale");
    assert_eq!(code, 0);
    assert!(last_body(&a).contains("amount=csrf-tok-"), "{}", last_body(&a));

    // Rule ids are never reused: the one added above is 2.
    // A URL on the rule says where else the value goes: there, and only there.
    ok(&p, &["auth", "rule", "remove", "app", "2"]);
    ok(&p, &["auth", "rule", "add", "app", "--url", &b.origin(), "--action", "update:csrf"]);
    let (code, _) = post(&b, true, "amount=5&csrf=stale");
    assert_eq!(code, 0);
    assert!(last_body(&b).contains("amount=5&csrf=csrf-tok-"), "{}", last_body(&b));
    assert!(reaches(&b) && !reaches(&c));
}
