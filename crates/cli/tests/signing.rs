//! End-to-end tests for request signing (`auth sign`) against a local API that refuses
//! a request whose HMAC or JWT doesn't verify.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::sync::{Arc, Mutex};

use brainproxy_core::http::request::split_head_body;
use brainproxy_core::sign::{hmac_digest, jwt_token, HmacAlg, JwtAlg};
use serde_json::Value;

const HMAC_KEY: &str = "s3cret-hmac-key-do-not-leak";
const JWT_KEY: &str = "s3cret-jwt-key-do-not-leak";

#[derive(Default)]
struct Seen {
    accepted: usize,
    rejected: usize,
    /// Raw requests as they arrived.
    raw: Vec<String>,
}

struct Server {
    port: u16,
    seen: Arc<Mutex<Seen>>,
}

impl Server {
    fn start() -> Server {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let seen = Arc::new(Mutex::new(Seen::default()));
        let shared = seen.clone();
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(s) = stream else { continue };
                let seen = shared.clone();
                std::thread::spawn(move || handle(s, &seen));
            }
        });
        Server { port, seen }
    }

    fn origin(&self) -> String {
        format!("http://127.0.0.1:{}", self.port)
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

fn header<'a>(head: &'a str, name: &str) -> Option<&'a str> {
    head.lines().find_map(|l| {
        let (k, v) = l.split_once(':')?;
        k.eq_ignore_ascii_case(name).then(|| v.trim())
    })
}

/// Whether the request's signature or token is good, as the API works it out.
fn verified(raw: &[u8]) -> bool {
    let (head, body) = split_head_body(raw);
    let head = String::from_utf8_lossy(head);
    let line = head.lines().next().unwrap_or_default();
    let mut words = line.split(' ');
    let (method, uri) = (words.next().unwrap_or_default(), words.next().unwrap_or_default());
    let (path, query) = uri.split_once('?').unwrap_or((uri, ""));
    if path.starts_with("/jwt") {
        let Some(token) = header(&head, "authorization").and_then(|v| v.strip_prefix("Bearer ")) else { return false };
        let Some((input, _)) = token.rsplit_once('.') else { return false };
        let Some((h, p)) = input.split_once('.') else { return false };
        let dec = |s: &str| brainproxy_core::codec::decode("base64url", s.as_bytes()).unwrap_or_default();
        let Ok(want) = jwt_token(JwtAlg::HS256, JWT_KEY.as_bytes(), &dec(h), &dec(p)) else { return false };
        let claims: Value = serde_json::from_slice(&dec(p)).unwrap_or_default();
        return want == token && claims["sub"] == "admin";
    }
    let (Some(ts), Some(sig)) = (header(&head, "x-timestamp"), header(&head, "x-signature")) else { return false };
    let text = format!("{method}\n{path}\n{query}\n{ts}\n{}", brainproxy_core::codec::hash("sha256", body).unwrap());
    let want = hmac_digest(HmacAlg::Sha256, HMAC_KEY.as_bytes(), text.as_bytes());
    want.iter().map(|b| format!("{b:02x}")).collect::<String>() == sig
}

fn handle(mut s: TcpStream, seen: &Mutex<Seen>) {
    while let Some(raw) = read_request(&mut s) {
        let good = verified(&raw);
        {
            let mut seen = seen.lock().unwrap();
            seen.raw.push(String::from_utf8_lossy(&raw).into_owned());
            if good {
                seen.accepted += 1;
            } else {
                seen.rejected += 1;
            }
        }
        let resp: &[u8] = if good {
            b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"
        } else {
            b"HTTP/1.1 401 Unauthorized\r\nContent-Length: 13\r\n\r\nbad signature"
        };
        if s.write_all(resp).is_err() {
            return;
        }
    }
}

fn bin(project: &Path) -> Command {
    let mut c = Command::new(env!("CARGO_BIN_EXE_brainproxy"));
    c.args(["--format", "json", "--project"])
        .arg(project)
        .env("SIGN_TEST_HMAC", HMAC_KEY)
        .env("SIGN_TEST_JWT", JWT_KEY)
        .env_remove("SIGN_TEST_UNSET");
    c
}

/// Runs a command; no output of any command may hold a key.
fn run_with_stdin(project: &Path, args: &[&str], stdin: Option<&[u8]>) -> (i32, Value) {
    let mut c = bin(project);
    c.args(args).stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped());
    let mut child = c.spawn().unwrap();
    let mut pipe = child.stdin.take().unwrap();
    pipe.write_all(stdin.unwrap_or_default()).unwrap();
    drop(pipe);
    let out: Output = child.wait_with_output().unwrap();
    for text in [&out.stdout, &out.stderr] {
        let text = String::from_utf8_lossy(text);
        assert!(!text.contains(HMAC_KEY) && !text.contains(JWT_KEY), "a key in the output of {args:?}: {text}");
    }
    let v = serde_json::from_slice(&out.stdout)
        .unwrap_or_else(|e| panic!("bad JSON ({e}): {}", String::from_utf8_lossy(&out.stdout)));
    (out.status.code().unwrap(), v)
}

fn run(project: &Path, args: &[&str]) -> (i32, Value) {
    run_with_stdin(project, args, None)
}

fn ok(project: &Path, args: &[&str]) -> Value {
    let (code, v) = run(project, args);
    assert_eq!(code, 0, "{args:?}: {v}");
    v["data"].clone()
}

fn tmp_project(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("bp-signing-{}-{name}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let p = dir.join("p.bpdb");
    let _ = std::fs::remove_file(&p);
    ok(&p, &["engagement", "start", "--target", "127.0.0.1"]);
    p
}

const CANONICAL: &str = r"{{method}}\n{{path}}\n{{query}}\n{{header:X-Timestamp}}\n{{body_sha256}}";

fn add_hmac(p: &Path, srv: &Server) {
    let origin = srv.origin();
    ok(
        p,
        &[
            "auth",
            "sign",
            "add",
            "api",
            "hm",
            "--secret-env",
            "SIGN_TEST_HMAC",
            "--origin",
            &origin,
            "--to",
            "header:X-Signature",
            "--set-header",
            "X-Timestamp: {{timestamp}}",
            "--canonical",
            CANONICAL,
        ],
    );
    ok(p, &["auth", "rule", "add", "api", "--action", "sign:hm"]);
}

/// Nothing a project keeps holds a key or a computed value: only placeholders.
fn assert_history_clean(p: &Path, srv: &Server) {
    let rows = ok(p, &["query", "SELECT url, req_headers, req_body_text, CAST(request AS TEXT) FROM history"]);
    let text = rows.to_string();
    assert!(text.contains("«auth:api:sign:"), "{text}");
    assert!(!text.contains(HMAC_KEY) && !text.contains(JWT_KEY), "{text}");
    // No signature the server was sent is in history.
    for raw in &srv.seen.lock().unwrap().raw {
        if let Some(sig) = header(raw.split("\r\n\r\n").next().unwrap(), "x-signature") {
            assert!(!text.contains(sig), "signature {sig} in history");
        }
    }
    let shown = ok(p, &["auth", "show", "api"]).to_string();
    assert!(shown.contains("SIGN_TEST_") && !shown.contains("s3cret"), "{shown}");
}

#[test]
fn unsigned_requests_are_refused_and_signed_ones_pass() {
    let srv = Server::start();
    let p = tmp_project("send");
    let url = format!("{}/orders?a=1", srv.origin());
    let bare = ok(&p, &["send", "--url", &url, "-X", "POST", "-d", "x=1"]);
    assert_eq!(bare["response"]["status"], 401, "{bare}");
    add_hmac(&p, &srv);
    let signed = ok(&p, &["send", "--url", &url, "-X", "POST", "-d", "x=1", "--auth", "api"]);
    assert_eq!(signed["response"]["status"], 200, "{signed}");
    assert_history_clean(&p, &srv);
}

#[test]
fn every_fuzz_payload_is_signed_after_it_goes_in() {
    let srv = Server::start();
    let p = tmp_project("fuzz");
    add_hmac(&p, &srv);
    // Payloads of different lengths, so Content-Length changes with each; one marker at a
    // time, so two markers and four payloads make eight requests.
    let url = format!("{}/orders?q=§x§", srv.origin());
    let wordlist = p.parent().unwrap().join("w.txt");
    std::fs::write(&wordlist, "a\nbb\nccc\ndddd\n").unwrap();
    let list = format!("file:{}", wordlist.display());
    ok(&p, &["fuzz", "run", "--url", &url, "-X", "POST", "-d", "body=§x§", "-p", &list, "--auth", "api", "-c", "2"]);
    let q = ok(&p, &["query", "SELECT status, count(*) FROM fuzz_results GROUP BY status"]);
    assert_eq!(q["rows"], serde_json::json!([[200, 8]]), "{q} {:?}", srv.seen.lock().unwrap().raw);
    assert_history_clean(&p, &srv);
}

#[test]
fn an_attacked_signature_keeps_its_payload_and_fails() {
    let srv = Server::start();
    let p = tmp_project("attack");
    add_hmac(&p, &srv);
    let url = format!("{}/orders", srv.origin());
    ok(&p, &["fuzz", "run", "--url", &url, "-H", "X-Signature: §x§", "-p", "range:1-3", "--auth", "api"]);
    let q = ok(&p, &["query", "SELECT status, count(*) FROM fuzz_results GROUP BY status"]);
    assert_eq!(q["rows"], serde_json::json!([[401, 3]]), "{q}");
}

#[test]
fn an_active_scan_signs_its_attacks() {
    let srv = Server::start();
    let p = tmp_project("scan");
    add_hmac(&p, &srv);
    let url = format!("{}/orders?q=1", srv.origin());
    ok(&p, &["scan", "active", &url, "--auth", "api", "--rules", "30001,30002", "-c", "4"]);
    let seen = srv.seen.lock().unwrap();
    assert!(seen.accepted > 1, "{:?}", seen.raw);
    assert_eq!(seen.rejected, 0, "{:?}", seen.raw);
    drop(seen);
    let findings = ok(&p, &["query", "SELECT count(*) FROM history WHERE CAST(request AS TEXT) LIKE '%s3cret%'"]);
    assert_eq!(findings["rows"], serde_json::json!([[0]]));
}

#[test]
fn replaying_a_stored_request_signs_it_again() {
    let srv = Server::start();
    let p = tmp_project("replay");
    add_hmac(&p, &srv);
    let url = format!("{}/orders", srv.origin());
    let first = ok(&p, &["send", "--url", &url, "--auth", "api"]);
    assert_eq!(first["response"]["status"], 200, "{first}");
    let q = ok(&p, &["query", "SELECT id FROM history ORDER BY id DESC LIMIT 1"]);
    let id = q["rows"][0][0].as_i64().unwrap().to_string();
    let raw = bin(&p).args(["history", "show", &id, "--part", "request", "--raw"]).output().unwrap().stdout;
    assert!(String::from_utf8_lossy(&raw).contains("«auth:api:sign:hm»"));
    // No --auth: the placeholder is enough.
    let (code, v) = run_with_stdin(&p, &["send", "--scheme", "http", "-"], Some(&raw));
    assert_eq!(code, 0, "{v}");
    assert_eq!(v["data"]["response"]["status"], 200, "{v}");
}

#[test]
fn jwts_are_made_with_chosen_claims_and_resigned() {
    let srv = Server::start();
    let p = tmp_project("jwt");
    let origin = srv.origin();
    let url = format!("{origin}/jwt/me");
    ok(
        &p,
        &[
            "auth",
            "sign",
            "add",
            "api",
            "tok",
            "--jwt",
            "HS256",
            "--secret-env",
            "SIGN_TEST_JWT",
            "--origin",
            &origin,
            "--to",
            "header:Authorization",
            "--wrap",
            "Bearer {{signature}}",
            "--claims",
            r#"{"sub":"admin"}"#,
            "--ttl",
            "300",
            "--resign",
        ],
    );
    ok(&p, &["auth", "rule", "add", "api", "--action", "sign:tok"]);
    let r = ok(&p, &["send", "--url", &url, "--auth", "api"]);
    assert_eq!(r["response"]["status"], 200, "{r}");
    // A token signed with some other key, for someone else, comes out right.
    let forged = jwt_token(JwtAlg::HS256, b"wrong", br#"{"alg":"HS256"}"#, br#"{"sub":"bob","team":7}"#).unwrap();
    let bearer = format!("Authorization: Bearer {forged}");
    let bad = ok(&p, &["send", "--url", &url, "-H", &bearer]);
    assert_eq!(bad["response"]["status"], 401, "{bad}");
    let good = ok(&p, &["send", "--url", &url, "-H", &bearer, "--auth", "api"]);
    assert_eq!(good["response"]["status"], 200, "{good}");
    let seen = srv.seen.lock().unwrap();
    let last = seen.raw.last().unwrap();
    let token = header(last, "authorization").unwrap().strip_prefix("Bearer ").unwrap();
    let v = brainproxy_core::codec::decode_jwt(token).unwrap();
    assert_eq!((v["payload"]["sub"].as_str(), v["payload"]["team"].as_i64()), (Some("admin"), Some(7)));
}

#[test]
fn a_missing_key_fails_the_send_and_signers_stay_on_their_origins() {
    let srv = Server::start();
    let p = tmp_project("missing");
    let origin = srv.origin();
    let add = |name: &str, env: &str, origin: &str| {
        ok(
            &p,
            &[
                "auth",
                "sign",
                "add",
                "api",
                name,
                "--secret-env",
                env,
                "--origin",
                origin,
                "--to",
                "header:X-Signature",
                "--canonical",
                "{{path}}",
            ],
        )
    };
    add("gone", "SIGN_TEST_UNSET", &origin);
    ok(&p, &["auth", "rule", "add", "api", "--action", "sign:gone"]);
    let url = format!("{origin}/orders");
    let (code, v) = run(&p, &["send", "--url", &url, "--auth", "api"]);
    assert_ne!(code, 0, "{v}");
    assert!(v.to_string().contains("SIGN_TEST_UNSET is not set"), "{v}");
    assert!(srv.seen.lock().unwrap().raw.is_empty(), "sent unsigned");

    // A rule can't use a signer that isn't there, and a used signer can't go.
    assert_ne!(run(&p, &["auth", "rule", "add", "api", "--action", "sign:nope"]).0, 0);
    assert_ne!(run(&p, &["auth", "sign", "remove", "api", "gone"]).0, 0);

    // Another origin's signer leaves requests here alone.
    let q = Server::start();
    let p2 = tmp_project("origins");
    let other = q.origin();
    ok(
        &p2,
        &[
            "auth",
            "sign",
            "add",
            "api",
            "hm",
            "--secret-env",
            "SIGN_TEST_HMAC",
            "--origin",
            &other,
            "--to",
            "header:X-Signature",
            "--canonical",
            "{{path}}",
        ],
    );
    ok(&p2, &["auth", "rule", "add", "api", "--action", "sign:hm"]);
    let r = ok(&p2, &["send", "--url", &url, "--auth", "api"]);
    assert_eq!(r["response"]["status"], 401, "{r}");
    let raw = srv.seen.lock().unwrap().raw.last().cloned().unwrap();
    assert!(header(&raw, "x-signature").is_none(), "{raw}");
}
