//! End-to-end: the GraphQL rule through the real engine against an in-test server with a
//! careless endpoint (introspection, suggestions, array and alias batching, queries over GET
//! and form or text POSTs), a hardened one that allows none of it, and a JSON API whose answers
//! hold `data` but which isn't GraphQL.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::time::Duration;

use serde_json::{json, Value};

use crate::guard::{Guard, ScopeSpec};
use crate::http::request::split_head_body;
use crate::http::{SendOptions, Target};
use crate::jobs::JobControl;
use crate::scan::active::{run, ActiveConfig, ActiveSummary, PointOptions, ScanTarget, Strength};

fn reply(status: &str, body: &Value) -> Vec<u8> {
    let body = body.to_string();
    format!(
        "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    )
    .into_bytes()
}

/// One operation's answer, as a GraphQL server would give it; `aliases` allows many aliases
/// where nothing else careless is.
fn answer(query: &str, careless: bool, aliases: bool) -> Value {
    let error = |m: &str| json!({"errors": [{"message": m}]});
    if query.contains("__schema") {
        return if careless {
            json!({"data": {"__schema": {"queryType": {"name": "Query"}}}})
        } else {
            error("GraphQL introspection is not allowed")
        };
    }
    if query.contains("userx") {
        let hint = if careless { " Did you mean \"user\"?" } else { "" };
        return error(&format!("Cannot query field \"userx\" on type \"Query\".{hint}"));
    }
    if query.contains("a0:") {
        if !careless && !aliases {
            return error("too many aliases");
        }
        let data: serde_json::Map<String, Value> = (0..10).map(|i| (format!("a{i}"), json!("Query"))).collect();
        return json!({ "data": data });
    }
    if query.contains("__typename") {
        return json!({"data": {"__typename": "Query"}});
    }
    if query.contains("mutation") {
        panic!("the rule sent a mutation: {query}");
    }
    if query.contains("user") {
        return json!({"data": {"user": {"name": "ann"}}});
    }
    error("unknown operation")
}

fn handle(raw: &[u8]) -> Vec<u8> {
    let (head, body) = split_head_body(raw);
    let head = String::from_utf8_lossy(head).to_string();
    let line = head.lines().next().unwrap_or_default();
    let mut words = line.split(' ');
    let (method, target) = (words.next().unwrap_or_default(), words.next().unwrap_or_default());
    let (path, query) = target.split_once('?').unwrap_or((target, ""));
    let content_type = head
        .lines()
        .find_map(|l| l.split_once(':').filter(|(k, _)| k.eq_ignore_ascii_case("content-type")).map(|(_, v)| v.trim()))
        .unwrap_or("")
        .to_ascii_lowercase();
    let param =
        |text: &[u8]| url::form_urlencoded::parse(text).find(|(k, _)| k == "query").map(|(_, v)| v.into_owned());
    match path {
        // Takes any transport and batches.
        "/graphql" => {
            if method == "GET" {
                return match param(query.as_bytes()) {
                    Some(q) => reply("200 OK", &answer(&q, true, true)),
                    None => reply("200 OK", &json!({"errors": [{"message": "no query"}]})),
                };
            }
            if content_type.starts_with("application/x-www-form-urlencoded") {
                return reply("200 OK", &answer(&param(body).unwrap_or_default(), true, true));
            }
            match serde_json::from_slice::<Value>(body) {
                Ok(Value::Array(ops)) => {
                    let all: Vec<Value> =
                        ops.iter().map(|o| answer(o["query"].as_str().unwrap_or_default(), true, true)).collect();
                    reply("200 OK", &Value::Array(all))
                }
                Ok(op) if op.pointer("/extensions/persistedQuery").is_some() => {
                    reply("200 OK", &json!({"data": {"user": {"name": "ann"}}}))
                }
                Ok(op) => reply("200 OK", &answer(op["query"].as_str().unwrap_or_default(), true, true)),
                Err(_) => reply("400 Bad Request", &json!({"errors": [{"message": "bad JSON"}]})),
            }
        }
        // POST of one JSON operation only; `/aliases` takes many aliases in it.
        "/hardened" | "/aliases" => {
            if method != "POST" {
                return reply("405 Method Not Allowed", &json!({"errors": [{"message": "POST only"}]}));
            }
            if !content_type.starts_with("application/json") {
                return reply("415 Unsupported Media Type", &json!({"errors": [{"message": "JSON only"}]}));
            }
            match serde_json::from_slice::<Value>(body) {
                Ok(Value::Object(op)) => {
                    reply("200 OK", &answer(op["query"].as_str().unwrap_or_default(), false, path == "/aliases"))
                }
                _ => reply("400 Bad Request", &json!({"errors": [{"message": "batching is off"}]})),
            }
        }
        // A JSON API (not GraphQL) whose answers wrap their records in `data`.
        "/api/items" => reply("200 OK", &json!({"data": [{"id": 1}]})),
        _ => reply("404 Not Found", &json!({})),
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

fn spawn_app() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut s) = stream else { continue };
            std::thread::spawn(move || {
                if let Some(raw) = read_request(&mut s) {
                    let _ = s.write_all(&handle(&raw));
                }
            });
        }
    });
    port
}

fn json_request(port: u16, path: &str, body: &str, cookie: bool) -> String {
    let cookie = if cookie { "Cookie: session=s3cr3t\r\n" } else { "" };
    format!(
        "POST {path} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nContent-Type: application/json\r\n{cookie}\
         X-Requested-With: app\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    )
}

fn target(port: u16, req: String) -> ScanTarget {
    let mut s = TcpStream::connect(("127.0.0.1", port)).unwrap();
    s.write_all(req.as_bytes()).unwrap();
    let mut response = Vec::new();
    s.read_to_end(&mut response).unwrap();
    ScanTarget {
        history_id: None,
        target: Target::from_url(&format!("http://127.0.0.1:{port}")).unwrap(),
        request: req.into_bytes(),
        response,
        duration_ms: None,
    }
}

struct Scanned {
    /// `alert_ref risk` of each finding.
    found: Vec<String>,
    summary: ActiveSummary,
    /// The scan's requests.
    sent: Vec<String>,
}

/// Scans the targets with rule 100012; `history` is recorded first, as the proxy would have.
async fn scan(port: u16, targets: Vec<String>, history: &[String]) -> Scanned {
    let guard =
        Guard::from_specs(vec![ScopeSpec { name: None, include: vec!["127.0.0.1".into()], exclude: vec![] }]).unwrap();
    let dir =
        std::env::temp_dir().join(format!("bp-graphql-{}-{}", std::process::id(), crate::scan::active::rand_u64()));
    std::fs::create_dir_all(&dir).unwrap();
    let db = dir.join("project.db");
    let origin = Target::from_url(&format!("http://127.0.0.1:{port}")).unwrap();
    {
        let store = crate::store::Store::open(&db).unwrap();
        for req in history {
            let t = target(port, req.clone());
            let capture = crate::capture::Capture::new("proxy", &origin, &t.request, Some(&t.response), None, None);
            store.record(&capture).unwrap();
        }
    }
    let cfg = ActiveConfig {
        strength: Strength::Medium,
        tuning: Default::default(),
        concurrency: 2,
        rate: None,
        send: SendOptions { timeout: Duration::from_secs(20), guard: Some(guard), ..Default::default() },
        points: PointOptions::default(),
        rules: Some(vec![100012]),
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
    let targets = targets.into_iter().map(|r| target(port, r)).collect();
    let summary = run(&db, targets, cfg, JobControl::default()).await.unwrap();
    let conn = rusqlite::Connection::open(&db).unwrap();
    let found: Vec<String> = conn
        .prepare("SELECT alert_ref || ' ' || risk FROM findings WHERE source = 'active' ORDER BY alert_ref")
        .unwrap()
        .query_map([], |r| r.get(0))
        .unwrap()
        .map(|r| r.unwrap())
        .collect();
    let mut st = conn.prepare("SELECT request FROM history WHERE source = 'scan' ORDER BY id").unwrap();
    let sent = st
        .query_map([], |r| r.get::<_, Vec<u8>>(0))
        .unwrap()
        .map(|r| String::from_utf8_lossy(&r.unwrap()).into_owned())
        .collect();
    drop(st);
    drop(conn);
    let _ = std::fs::remove_dir_all(&dir);
    Scanned { found, summary, sent }
}

const QUERY: &str = r#"{"query":"query { user(id: 1) { name } }"}"#;

#[tokio::test(flavor = "multi_thread")]
async fn a_careless_endpoint_raises_each_alert_once_and_a_hardened_one_none() {
    let port = spawn_app();
    // Two requests at one endpoint: it is tested once.
    let other = r#"{"query":"{ user(id: 2) { name } }"}"#;
    let s =
        scan(port, vec![json_request(port, "/graphql", QUERY, true), json_request(port, "/graphql", other, true)], &[])
            .await;
    assert_eq!(s.found, ["100012-1 low", "100012-2 info", "100012-3 low", "100012-4 medium"], "{:?}", s.summary);
    assert_eq!(s.summary.requests, 7, "{:#?}", s.sent);
    for r in &s.sent {
        assert!(!r.contains("mutation") && !r.contains("user(id"), "{r}");
    }
    // The misspelt field comes from the base request's query.
    assert!(s.sent.iter().any(|r| r.ends_with(r#"{"query":"query{userx}"}"#)), "{:#?}", s.sent);
    // A batch of exactly 10, and 10 aliases.
    let array = s.sent.iter().find(|r| r.contains("\r\n\r\n[")).unwrap();
    let batch: Value = serde_json::from_slice(split_head_body(array.as_bytes()).1).unwrap();
    assert_eq!(batch.as_array().unwrap().len(), 10);
    assert!(s.sent.iter().any(|r| r.contains("a9:__typename") && !r.contains("a10:")));
    // The GET carries a cache buster; the cross-site requests carry the cookie but not the app's header.
    let get = s.sent.iter().find(|r| r.starts_with("GET ")).unwrap();
    assert!(get.starts_with("GET /graphql?query=query%7B__typename%7D&bp"), "{get}");
    for r in s.sent.iter().filter(|r| r.starts_with("GET ") || r.contains("text/plain") || r.contains("urlencoded")) {
        assert!(r.contains("Cookie: session=s3cr3t") && !r.contains("X-Requested-With"), "{r}");
    }
    assert!(s.sent.iter().any(|r| r.contains("Content-Type: text/plain") && r.contains("Origin: https://bp")));

    let h = scan(port, vec![json_request(port, "/hardened", QUERY, true)], &[]).await;
    assert!(h.found.is_empty(), "{:?}", h.found);
    assert_eq!(h.summary.requests, 7);
}

#[tokio::test(flavor = "multi_thread")]
async fn aliases_alone_are_info_and_no_cookie_keeps_csrf_low() {
    let port = spawn_app();
    let s = scan(port, vec![json_request(port, "/aliases", QUERY, true)], &[]).await;
    assert_eq!(s.found, ["100012-3 info"]);
    // Without a cookie, queries over GET and simple POSTs are Low.
    let s = scan(port, vec![json_request(port, "/graphql", QUERY, false)], &[]).await;
    assert!(s.found.contains(&"100012-4 low".to_string()), "{:?}", s.found);
}

#[tokio::test(flavor = "multi_thread")]
async fn an_answer_with_data_counts_only_where_graphql_was_seen() {
    let port = spawn_app();
    // A persisted query: no document in the request, but the path had a query before.
    let persisted = r#"{"extensions":{"persistedQuery":{"version":1,"sha256Hash":"abc"}}}"#;
    let s = scan(
        port,
        vec![json_request(port, "/graphql", persisted, false)],
        &[json_request(port, "/graphql", QUERY, false)],
    )
    .await;
    assert!(s.found.iter().any(|f| f.starts_with("100012-1")), "{:?}", s.found);
    // The misspelt field comes from the answer's data.
    assert!(s.sent.iter().any(|r| r.ends_with(r#"{"query":"query{userx}"}"#)), "{:#?}", s.sent);
    let unseen = scan(port, vec![json_request(port, "/graphql", persisted, false)], &[]).await;
    assert_eq!(unseen.summary.requests, 0);
    // A JSON API's `data` answer isn't GraphQL.
    let api = format!("GET /api/items HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nConnection: close\r\n\r\n");
    let s = scan(port, vec![api], &[]).await;
    assert_eq!((s.summary.requests, s.found.len()), (0, 0));
}
