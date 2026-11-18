//! End-to-end: the JWT rule through the real engine against an in-test server that checks
//! bearer tokens, one path per weakness and one that gets everything right.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::time::Duration;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use ring::hmac;
use serde_json::{json, Map, Value};

use crate::guard::{Guard, ScopeSpec};
use crate::http::{SendOptions, Target};
use crate::jobs::JobControl;
use crate::scan::active::{run, ActiveConfig, PointOptions, ScanTarget, Strength};

const STRONG: &[u8] = b"Zq8vW3nR7tY1uP5sK9dF2gH6jL0xC4bM";
/// A far-off expiry (2100).
const EXP: u64 = 4_102_444_800;
/// The signature the fake RS256 tokens carry; the server takes it as valid.
const RSA_SIG: &[u8] = b"not-really-an-rsa-signature-but-the-server-trusts-it";
const N: &[u8] = &[0xc3, 0x11, 0x5a, 0x9e, 0x42, 0x07, 0x88, 0x6b, 0x1d, 0xf0, 0x33, 0x5c, 0x29, 0xa4, 0x7e, 0x01];

fn jwks() -> Value {
    json!({"keys": [{"kty": "RSA", "kid": "k1", "use": "sig", "e": "AQAB", "n": URL_SAFE_NO_PAD.encode(N)}]})
}

/// The PEM a vulnerable library would use as the HMAC secret.
fn pem() -> String {
    let jwk = jwks()["keys"][0].as_object().unwrap().clone();
    super::jwt::rsa_pems(&jwk).remove(0)
}

/// A key file that isn't in the JWKS, as a server reads it (no final newline), for each
/// path whose server signs with one: one at a common path, one in a directory a recorded
/// listing links to (labelled as Juice Shop's is), one only ever seen inside a recorded
/// JSON response, one in Juice Shop's key directory that nothing links to, and one a listing
/// the passive scan raised Directory Browsing on links to, among many newer pages saying "pub".
fn key_file(path: &str) -> Option<String> {
    let (n, label) = match path {
        "/confusion-common" => (0x11, "PUBLIC KEY"),
        "/confusion-listed" => (0x22, "RSA PUBLIC KEY"),
        "/confusion-seen" => (0x33, "PUBLIC KEY"),
        "/confusion-dir" => (0x44, "RSA PUBLIC KEY"),
        "/confusion-browsed" => (0x55, "PUBLIC KEY"),
        _ => return None,
    };
    let mut jwk = Map::new();
    jwk.insert("kty".into(), "RSA".into());
    jwk.insert("e".into(), "AQAB".into());
    jwk.insert("n".into(), URL_SAFE_NO_PAD.encode([&[0xc5, n][..], &N[2..]].concat()).into());
    let pem = super::jwt::rsa_pems(&jwk).remove(1);
    Some(pem.replace("BEGIN PUBLIC KEY", &format!("BEGIN {label}")).replace("END PUBLIC KEY", &format!("END {label}")))
}

/// What the project's history holds before the scan, for `path`: (request path, response).
fn recorded(path: &str) -> Vec<(&'static str, String)> {
    match path {
        "/confusion-listed" => vec![(
            "/certs/",
            page(
                "200 OK",
                r#"<ul><li><a href="signing.pub">signing.pub</a></li><li><a href="premium.key">k</a></li></ul>"#,
                "text/html",
            ),
        )],
        // The listing first (Directory Browsing is raised on it), then script bundles saying "pub".
        "/confusion-browsed" => {
            let listing = r#"<title>listing directory /rsa/</title><ul id="files"><li><a href="/rsa/app.pem">app.pem</a></li></ul>"#;
            let mut rows = vec![("/rsa/", page("200 OK", listing, "text/html"))];
            rows.extend((0..25).map(|_| ("/bundle.js", page("200 OK", "var pub = 1;", "text/javascript"))));
            rows
        }
        "/confusion-seen" => {
            let body = json!({"publicKey": key_file(path).unwrap()}).to_string();
            vec![("/api/config", page("200 OK", &body, "application/json"))]
        }
        _ => vec![],
    }
}

fn b64(v: &Value) -> String {
    URL_SAFE_NO_PAD.encode(serde_json::to_vec(v).unwrap())
}

fn hs256(key: &[u8], header: &Value, payload: &Value) -> String {
    let input = format!("{}.{}", b64(header), b64(payload));
    let tag = hmac::sign(&hmac::Key::new(hmac::HMAC_SHA256, key), input.as_bytes());
    format!("{input}.{}", URL_SAFE_NO_PAD.encode(tag.as_ref()))
}

fn now() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs()
}

/// The token a path's users log in with.
fn issued(path: &str) -> String {
    let payload = json!({"sub": "alice", "exp": EXP});
    match path {
        "/weak" | "/weak-noexp" => hs256(b"secret", &json!({"alg": "HS256", "typ": "JWT"}), &payload),
        "/kid" => hs256(STRONG, &json!({"alg": "HS256", "typ": "JWT", "kid": "k1"}), &payload),
        "/expired" => hs256(STRONG, &json!({"alg": "HS256", "typ": "JWT"}), &json!({"sub": "alice", "exp": 1})),
        "/confusion" | "/confusion-common" | "/confusion-listed" | "/confusion-seen" | "/confusion-cookie"
        | "/confusion-dir" | "/confusion-browsed" => format!(
            "{}.{}.{}",
            b64(&if path == "/confusion" {
                json!({"alg": "RS256", "typ": "JWT", "kid": "k1"})
            } else {
                json!({"alg": "RS256", "typ": "JWT"})
            }),
            b64(&payload),
            URL_SAFE_NO_PAD.encode(RSA_SIG)
        ),
        _ => hs256(STRONG, &json!({"alg": "HS256", "typ": "JWT"}), &payload),
    }
}

fn object(b64: &str) -> Option<Map<String, Value>> {
    match serde_json::from_slice(&URL_SAFE_NO_PAD.decode(b64).ok()?).ok()? {
        Value::Object(m) => Some(m),
        _ => None,
    }
}

fn hmac_ok(key: &[u8], token: &str) -> bool {
    let Some((input, sig)) = token.rsplit_once('.') else { return false };
    let Ok(sig) = URL_SAFE_NO_PAD.decode(sig) else { return false };
    hmac::verify(&hmac::Key::new(hmac::HMAC_SHA256, key), input.as_bytes(), &sig).is_ok()
}

/// Whether the server at `path` lets `token` in.
fn accepts(path: &str, token: &str) -> bool {
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 3 {
        return false;
    }
    let (Some(header), Some(payload)) = (object(parts[0]), object(parts[1])) else { return false };
    let alg = header.get("alg").and_then(Value::as_str).unwrap_or("");
    let live = payload.get("exp").and_then(Value::as_u64).is_some_and(|e| e > now());
    let safe = |key: &[u8]| alg == "HS256" && hmac_ok(key, token) && live;
    match path {
        "/noverify" => true,
        "/none" => alg.eq_ignore_ascii_case("none") || safe(STRONG),
        "/stripped" => parts[2].is_empty() || safe(STRONG),
        "/weak" => safe(b"secret"),
        "/weak-noexp" => alg == "HS256" && hmac_ok(b"secret", token),
        "/kid" => {
            let kid = header.get("kid").and_then(Value::as_str).unwrap_or("");
            safe(if kid.ends_with("dev/null") { b"" } else { STRONG })
        }
        "/confusion-cookie" => alg.eq_ignore_ascii_case("none") || accepts("/confusion-common", token),
        "/confusion" | "/confusion-common" | "/confusion-listed" | "/confusion-seen" | "/confusion-dir"
        | "/confusion-browsed" => match alg {
            "HS256" => hmac_ok(key_file(path).unwrap_or_else(pem).as_bytes(), token) && live,
            "RS256" => URL_SAFE_NO_PAD.decode(parts[2]).is_ok_and(|s| s == RSA_SIG) && live,
            _ => false,
        },
        _ => safe(STRONG),
    }
}

fn page(status: &str, body: &str, ctype: &str) -> String {
    format!(
        "HTTP/1.1 {status}\r\nContent-Type: {ctype}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    )
}

fn handle(req: &str) -> String {
    let path = req.split(' ').nth(1).unwrap_or("/");
    if path == "/.well-known/jwks.json" {
        return page("200 OK", &jwks().to_string(), "application/json");
    }
    if path == "/jwt.pub" {
        return page("200 OK", &key_file("/confusion-common").unwrap(), "application/octet-stream");
    }
    for (file, owner) in [
        ("/certs/signing.pub", "/confusion-listed"),
        ("/encryptionkeys/jwt.pub", "/confusion-dir"),
        ("/rsa/app.pem", "/confusion-browsed"),
    ] {
        if path == file {
            return page("200 OK", &key_file(owner).unwrap(), "application/octet-stream");
        }
    }
    // Any other path is the app's page, as a single-page app answers it: no key at the common
    // key paths, though each answers 200.
    let pages = ["/safe", "/expired", "/whoami", "/noverify", "/none", "/stripped", "/weak", "/kid", "/ignores"];
    if !path.starts_with("/confusion") && !pages.iter().any(|p| path.starts_with(p)) {
        return page("200 OK", "<!doctype html><html><body><app-root></app-root></body></html>", "text/html");
    }
    let token = req
        .lines()
        .find_map(|l| l.strip_prefix("Authorization: Bearer ").or_else(|| l.strip_prefix("authorization: Bearer ")))
        .unwrap_or("")
        .trim();
    if !token.is_empty() && token.split('.').nth(1).and_then(object).is_none() && path != "/ignores" {
        return page("500 Internal Server Error", "{\"error\":\"Unexpected end of JSON input\"}", "application/json");
    }
    // Reads its user from a cookie, never the bearer token; a middleware in front of every page
    // fails on a token it can't decode (Juice Shop's /rest/user/whoami).
    if path == "/whoami" {
        return page("200 OK", "{\"user\":{}}", "application/json");
    }
    if path == "/confusion-cookie" {
        let cookie = req.lines().find_map(|l| l.strip_prefix("Cookie: token=")).map(str::trim);
        if cookie.is_some_and(|c| c != token) {
            return page(
                "401 Unauthorized",
                "{\"message\":\"Cannot read properties of undefined\"}",
                "application/json",
            );
        }
        // As Juice Shop does, only for a token it didn't issue.
        if accepts(path, token) && token != issued(path) {
            let body = "<html><body><h1>Welcome alice</h1><ul><li>order 1</li><li>order 2</li></ul></body></html>";
            return format!(
                "HTTP/1.1 200 OK\r\nSet-Cookie: token={token}\r\nContent-Type: text/html\r\nContent-Length: {}\r\n\
                 Connection: close\r\n\r\n{body}",
                body.len()
            );
        }
    }
    if path == "/ignores" || accepts(path, token) {
        page(
            "200 OK",
            "<html><body><h1>Welcome alice</h1><ul><li>order 1</li><li>order 2</li></ul></body></html>",
            "text/html",
        )
    } else {
        page("401 Unauthorized", "<html><body><h1>Please log in</h1></body></html>", "text/html")
    }
}

fn spawn_app() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut s) = stream else { continue };
            std::thread::spawn(move || {
                let mut buf = vec![0u8; 16384];
                let n = s.read(&mut buf).unwrap_or(0);
                let _ = s.write_all(handle(&String::from_utf8_lossy(&buf[..n])).as_bytes());
            });
        }
    });
    port
}

/// How the base request carries its token.
#[derive(Clone, Copy, PartialEq)]
enum Carried {
    /// As recorded through the proxy or with a literal header.
    Literal,
    /// As `send --auth` records it: a placeholder the vault fills in as it goes out.
    Placeholder,
    /// [`Carried::Placeholder`], scanned with `--auth`: the session sends every request.
    Session,
}

fn target(port: u16, path: &str, carried: Carried) -> ScanTarget {
    let line = |token: &str| {
        format!(
            "GET {path} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nAuthorization: Bearer {token}\r\nConnection: close\r\n\r\n"
        )
        .into_bytes()
    };
    let wire = line(&issued(path));
    let req = match carried {
        Carried::Literal => wire.clone(),
        Carried::Placeholder | Carried::Session => line(&crate::auth::placeholder("alice", "token")),
    };
    let mut s = TcpStream::connect(("127.0.0.1", port)).unwrap();
    s.write_all(&wire).unwrap();
    let mut response = Vec::new();
    s.read_to_end(&mut response).unwrap();
    ScanTarget {
        history_id: None,
        target: Target::from_url(&format!("http://127.0.0.1:{port}")).unwrap(),
        request: req,
        response,
        duration_ms: None,
    }
}

/// The alert refs the rule raises for `path`, sorted, and how many requests it sent.
async fn scan(port: u16, path: &str, strength: Strength) -> (Vec<String>, u64) {
    let (refs, requests, _) = scan_carried(port, path, strength, Carried::Literal).await;
    (refs, requests)
}

/// [`scan`], also returning every text and blob value the project holds afterwards.
async fn scan_carried(port: u16, path: &str, strength: Strength, carried: Carried) -> (Vec<String>, u64, Vec<String>) {
    let guard =
        Guard::from_specs(vec![ScopeSpec { name: None, include: vec!["127.0.0.1".into()], exclude: vec![] }]).unwrap();
    let dir = std::env::temp_dir().join(format!(
        "bp-jwt-{}-{}-{}",
        path.trim_start_matches('/'),
        std::process::id(),
        crate::scan::active::rand_u64()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let db = dir.join("project.db");
    let mut session = None;
    if carried != Carried::Literal {
        // A profile that logged in earlier: the vault holds its token, as a command's guard would.
        let store = crate::store::Store::open(&db).unwrap();
        let profile = crate::auth::AuthProfile {
            name: "alice".into(),
            login_url: Some(format!("http://127.0.0.1:{port}/login")),
            token_regex: Some(r#""token":"([^"]+)""#.into()),
            token_header: Some("Authorization: Bearer {{token}}".into()),
            ..Default::default()
        };
        store.auth_save_profile(&profile).unwrap();
        let state = crate::auth::SessionState { token: Some(issued(path)), logged_in: true, ..Default::default() };
        store.auth_save_state("alice", &state).unwrap();
        store.auth_fill_vault(&guard.vault).unwrap();
        if carried == Carried::Session {
            let client = crate::http::Client::new(SendOptions { guard: Some(guard.clone()), ..Default::default() });
            session = Some(std::sync::Arc::new(crate::auth::AuthSession::new(&db, profile, state, client).unwrap()));
        }
    }
    let recorded = recorded(path);
    if !recorded.is_empty() {
        let store = crate::store::Store::open(&db).unwrap();
        let origin = Target::from_url(&format!("http://127.0.0.1:{port}")).unwrap();
        let mut ids = Vec::new();
        for (at, resp) in recorded {
            let req = format!("GET {at} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n\r\n");
            let capture =
                crate::capture::Capture::new("proxy", &origin, req.as_bytes(), Some(resp.as_bytes()), None, None);
            ids.push(store.record(&capture).unwrap());
        }
        if path == "/confusion-browsed" {
            store
                .conn
                .execute(
                    "INSERT INTO findings (source, rule_id, alert_ref, name, risk, risk_level, confidence, host,
                        method, url, dedupe, history_id) VALUES ('passive', 10033, '10033', 'Directory Browsing',
                        'medium', 2, 'medium', '127.0.0.1', 'GET', 'u', 'd', ?1)",
                    [ids[0]],
                )
                .unwrap();
        }
    }
    let cfg = ActiveConfig {
        strength,
        tuning: Default::default(),
        concurrency: 4,
        rate: None,
        send: SendOptions { timeout: Duration::from_secs(20), guard: Some(guard), ..Default::default() },
        points: PointOptions::default(),
        rules: Some(vec![100007]),
        exclude_rules: vec![],
        no_rules: false,
        checks: vec![],
        max_duration: None,
        auth: session,
        oob: None,
        oob_wait: Duration::ZERO,
        check_methods: vec![],
        prune: false,
    };
    let summary = run(&db, vec![target(port, path, carried)], cfg, JobControl::default()).await.unwrap();
    let conn = rusqlite::Connection::open(&db).unwrap();
    let mut st = conn.prepare("SELECT alert_ref FROM findings WHERE source = 'active' ORDER BY alert_ref").unwrap();
    let refs: Vec<String> = st.query_map([], |r| r.get(0)).unwrap().map(|r| r.unwrap()).collect();
    drop(st);
    let mut values = Vec::new();
    let tables: Vec<String> = conn
        .prepare("SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'auth!_%' ESCAPE '!'")
        .unwrap()
        .query_map([], |r| r.get(0))
        .unwrap()
        .map(|r| r.unwrap())
        .collect();
    for t in tables {
        let mut st = conn.prepare(&format!("SELECT * FROM \"{t}\"")).unwrap();
        let n = st.column_count();
        let mut rows = st.query([]).unwrap();
        while let Some(row) = rows.next().unwrap() {
            for i in 0..n {
                match row.get_ref(i).unwrap() {
                    rusqlite::types::ValueRef::Text(b) | rusqlite::types::ValueRef::Blob(b) => {
                        values.push(String::from_utf8_lossy(b).into_owned())
                    }
                    _ => {}
                }
            }
        }
    }
    drop(conn);
    let _ = std::fs::remove_dir_all(&dir);
    (refs, summary.requests, values)
}

#[tokio::test(flavor = "multi_thread")]
async fn each_weakness_is_found_and_only_it() {
    let port = spawn_app();
    for (path, strength, want) in [
        ("/safe", Strength::High, vec![]),
        // Refused as recorded: forged tokens are refused alike, which says nothing.
        ("/expired", Strength::High, vec![]),
        ("/whoami", Strength::High, vec![]),
        ("/noverify", Strength::Medium, vec!["100007-1"]),
        ("/none", Strength::Medium, vec!["100007-2"]),
        ("/stripped", Strength::Medium, vec!["100007-3"]),
        ("/weak", Strength::Medium, vec!["100007-4"]),
        ("/weak-noexp", Strength::Medium, vec!["100007-4", "100007-5"]),
        ("/kid", Strength::Medium, vec!["100007-6"]),
        ("/confusion", Strength::Medium, vec!["100007-7"]),
        // Keys not in a JWKS: at a common path, at a path a recorded listing links to, and
        // seen only inside a recorded response.
        ("/confusion-common", Strength::Medium, vec!["100007-7"]),
        ("/confusion-listed", Strength::Medium, vec!["100007-7"]),
        ("/confusion-seen", Strength::Medium, vec!["100007-7"]),
        // Nothing in history: Juice Shop's key directory, among paths a single-page app
        // answers with its page.
        ("/confusion-dir", Strength::Medium, vec!["100007-7"]),
        // A Directory Browsing finding's listing, which newer pages crowd out of a text search.
        ("/confusion-browsed", Strength::Medium, vec!["100007-7"]),
    ] {
        let (refs, _) = scan(port, path, strength).await;
        assert_eq!(refs, want, "{path}");
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn a_token_behind_an_auth_placeholder_is_attacked_and_stays_off_the_record() {
    let port = spawn_app();
    for (path, want) in [
        ("/safe", vec![]),
        ("/noverify", vec!["100007-1"]),
        ("/none", vec!["100007-2"]),
        ("/weak-noexp", vec!["100007-4", "100007-5"]),
        ("/confusion", vec!["100007-7"]),
    ] {
        let (refs, _, values) = scan_carried(port, path, Strength::Medium, Carried::Placeholder).await;
        assert_eq!(refs, want, "{path}");
        // Outside the profile's own session (the auth tables), neither the token nor its
        // signature (which a forged token with the signature kept, or one bit of it changed,
        // would give away) is written anywhere.
        let token = issued(path);
        let signature = token.rsplit('.').next().unwrap();
        let leaked: Vec<&String> = values.iter().filter(|v| v.contains(signature)).collect();
        assert!(leaked.is_empty(), "{path}: {leaked:?}");
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn with_auth_a_cookie_set_for_a_forged_token_does_not_spoil_the_next_tests() {
    let port = spawn_app();
    // The server answers `alg: none` with a cookie holding that token, which the session would
    // otherwise send with every later forged token, and which the server reads first.
    let (refs, _, _) = scan_carried(port, "/confusion-cookie", Strength::Medium, Carried::Session).await;
    assert_eq!(refs, ["100007-2", "100007-7"]);
}

#[tokio::test(flavor = "multi_thread")]
async fn low_strength_skips_kid_and_key_confusion() {
    let port = spawn_app();
    assert_eq!(scan(port, "/kid", Strength::Low).await.0, Vec::<String>::new());
    assert_eq!(scan(port, "/confusion", Strength::Low).await.0, Vec::<String>::new());
}

#[tokio::test(flavor = "multi_thread")]
async fn a_page_that_ignores_the_token_gets_two_requests() {
    let port = spawn_app();
    let (refs, requests) = scan(port, "/ignores", Strength::High).await;
    assert!(refs.is_empty(), "{refs:?}");
    assert_eq!(requests, 2, "the real token and none, then nothing");
}
