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
        "/confusion" => format!(
            "{}.{}.{}",
            b64(&json!({"alg": "RS256", "typ": "JWT", "kid": "k1"})),
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
        "/confusion" => match alg {
            "HS256" => hmac_ok(pem().as_bytes(), token) && live,
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
    let token = req
        .lines()
        .find_map(|l| l.strip_prefix("Authorization: Bearer ").or_else(|| l.strip_prefix("authorization: Bearer ")))
        .unwrap_or("")
        .trim();
    if token.split('.').nth(1).and_then(object).is_none() && path != "/ignores" {
        return page("400 Bad Request", "{\"error\":\"malformed token\"}", "application/json");
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

fn target(port: u16, path: &str) -> ScanTarget {
    let req = format!(
        "GET {path} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nAuthorization: Bearer {}\r\nConnection: close\r\n\r\n",
        issued(path)
    )
    .into_bytes();
    let mut s = TcpStream::connect(("127.0.0.1", port)).unwrap();
    s.write_all(&req).unwrap();
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
    let guard =
        Guard::from_specs(vec![ScopeSpec { name: None, include: vec!["127.0.0.1".into()], exclude: vec![] }]).unwrap();
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
        auth: None,
        oob: None,
        oob_wait: Duration::ZERO,
        check_methods: vec![],
        prune: false,
    };
    let dir = std::env::temp_dir().join(format!(
        "bp-jwt-{}-{}-{}",
        path.trim_start_matches('/'),
        std::process::id(),
        crate::scan::active::rand_u64()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let db = dir.join("project.db");
    let summary = run(&db, vec![target(port, path)], cfg, JobControl::default()).await.unwrap();
    let conn = rusqlite::Connection::open(&db).unwrap();
    let mut st = conn.prepare("SELECT alert_ref FROM findings ORDER BY alert_ref").unwrap();
    let refs: Vec<String> = st.query_map([], |r| r.get(0)).unwrap().map(|r| r.unwrap()).collect();
    drop(st);
    drop(conn);
    let _ = std::fs::remove_dir_all(&dir);
    (refs, summary.requests)
}

#[tokio::test(flavor = "multi_thread")]
async fn each_weakness_is_found_and_only_it() {
    let port = spawn_app();
    for (path, strength, want) in [
        ("/safe", Strength::High, vec![]),
        // Refused as recorded: forged tokens are refused alike, which says nothing.
        ("/expired", Strength::High, vec![]),
        ("/noverify", Strength::Medium, vec!["100007-1"]),
        ("/none", Strength::Medium, vec!["100007-2"]),
        ("/stripped", Strength::Medium, vec!["100007-3"]),
        ("/weak", Strength::Medium, vec!["100007-4"]),
        ("/weak-noexp", Strength::Medium, vec!["100007-4", "100007-5"]),
        ("/kid", Strength::Medium, vec!["100007-6"]),
        ("/confusion", Strength::Medium, vec!["100007-7"]),
    ] {
        let (refs, _) = scan(port, path, strength).await;
        assert_eq!(refs, want, "{path}");
    }
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
    assert_eq!(requests, 2, "the real token and a broken one, then nothing");
}
