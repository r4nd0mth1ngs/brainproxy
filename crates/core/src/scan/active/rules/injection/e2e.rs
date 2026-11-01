//! End-to-end: rules run through the real engine (client, scope guard, store)
//! against a small in-test HTTP server with vulnerable and safe endpoints.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::time::Duration;

use crate::guard::{Guard, ScopeSpec};
use crate::http::{SendOptions, Target};
use crate::jobs::JobControl;
use crate::scan::active::{run, ActiveConfig, ActiveSummary, PointOptions, ScanTarget, Strength};
use crate::scan::message::url_decode;

fn html(body: &str) -> String {
    format!(
        "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    )
}

/// Evaluates "n", "a-b" or "a/b" like a database would for a numeric column.
fn eval(expr: &str) -> Option<i64> {
    if let Ok(n) = expr.parse() {
        return Some(n);
    }
    let (a, op, b) = expr.find(['-', '/']).map(|i| (&expr[..i], &expr[i..i + 1], &expr[i + 1..]))?;
    let (a, b): (i64, i64) = (a.parse().ok()?, b.parse().ok()?);
    if op == "-" {
        Some(a - b)
    } else {
        a.checked_div(b)
    }
}

fn handle(path: &str, query: &str) -> String {
    let param = |name: &str| -> String {
        query.split('&').find_map(|p| p.strip_prefix(&format!("{name}="))).map(url_decode).unwrap_or_default()
    };
    match path {
        // SQL error leaked for a quote.
        "/sqlerr" => {
            let id = param("id");
            if id.contains('\'') {
                html("<b>Warning</b>: You have an error in your SQL syntax; check the manual near ''' at line 1")
            } else {
                html(&format!("<p>item {id}</p>"))
            }
        }
        // Numeric column: the value is evaluated, not reflected.
        "/sqlexpr" => match eval(&param("id")) {
            Some(1) => html("<ul><li>apple</li><li>pear</li></ul>"),
            _ => html("<ul></ul>"),
        },
        // String column, `WHERE name = '<value>'`; errors are not shown.
        "/sqlbool" => {
            let name = param("name");
            let rows = match name.split_once('\'') {
                None => name == "apple",
                Some((head, tail)) if tail.starts_with(" AND '1'='1'") => head == "apple",
                Some((_, tail)) if tail.starts_with(" OR '1'='1'") => true,
                Some(_) => false,
            };
            html(if rows { "<ul><li>apple: 3</li></ul>" } else { "<ul></ul>" })
        }
        // Shell command output in the page.
        "/ping" => {
            let host = param("host");
            if host.contains("cat /etc/passwd") {
                html("PING ok\nroot:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1::/usr/sbin")
            } else {
                html("PING ok")
            }
        }
        // MySQL sleep(n) honoured.
        "/sleepy" => {
            let id = param("id");
            if let Some(n) = id.split("sleep(").nth(1).and_then(|r| r.split(')').next()).and_then(|n| n.parse().ok()) {
                std::thread::sleep(Duration::from_secs(n));
            }
            html("<p>item</p>")
        }
        // Bracketed names reach MongoDB as operators, as with PHP or qs.
        "/mongo" => {
            let pairs: Vec<(String, String)> = query
                .split('&')
                .filter_map(|p| p.split_once('='))
                .map(|(k, v)| (url_decode(k).replace('+', " "), url_decode(v)))
                .collect();
            match pairs.first().map(|(k, v)| (k.as_str(), v.as_str())) {
                Some(("id", "1") | ("id[$eq]", "1")) => html("<ul><li>mine</li></ul>"),
                Some(("id[$ne]" | "id[$regex]" | "id[$gt]", _)) => html("<ul><li>mine</li><li>theirs</li></ul>"),
                _ => html("<ul></ul>"),
            }
        }
        // A plain string column: brackets only ever find nothing, whichever operator.
        "/mongoplain" => {
            if query == "id=1" {
                html("<ul><li>mine</li></ul>")
            } else {
                html("<ul></ul>")
            }
        }
        "/mongocrash" => {
            if param("id").contains('\'') {
                html("com.mongodb.MongoResultException: bad query")
            } else {
                html("<p>item</p>")
            }
        }
        // $where running JavaScript over 1,000 documents: sleep() takes milliseconds.
        "/mongosleep" => {
            let id = param("id");
            let ms = id.split("sleep(").nth(1).and_then(|r| r.split(')').next()).and_then(|n| n.parse::<f64>().ok());
            if let Some(ms) = ms {
                std::thread::sleep(Duration::from_secs_f64(ms));
            }
            html("<p>item</p>")
        }
        // Safe: the same page whatever the parameter is.
        "/safe" => html("<p>static content</p>"),
        // Safe: small pages that echo what they were sent.
        "/echo" => html(&format!("<p>{}</p>", param("q"))),
        p if p.starts_with("/echo/") => html(&format!("<p>You are at {}</p>", url_decode(p))),
        p if p.starts_with("/nowhere/") => format!(
            "HTTP/1.1 404 Not Found\r\nContent-Type: text/html\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{p}",
            p.len()
        ),
        // A quote in the ID leaks an SQL error.
        p if p.starts_with("/rest/item/") => {
            if url_decode(p).contains('\'') {
                html("You have an error in your SQL syntax; check the manual")
            } else {
                html("<p>item</p>")
            }
        }
        _ => "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".to_string(),
    }
}

/// `/mongojson` queries with the JSON value as sent: operators work. `/jsonstrict` takes
/// any object for bad input and answers the same for each, so nothing proves an operator.
fn handle_json(path: &str, body: &str) -> String {
    let v: serde_json::Value = serde_json::from_str(body).unwrap_or_default();
    let id = &v["id"];
    match path {
        "/mongojson" if *id == serde_json::json!(1) || id["$eq"] == serde_json::json!(1) => {
            html("<ul><li>mine</li></ul>")
        }
        "/mongojson" if id.get("$ne").is_some() || id.get("$gt").is_some() || id.get("$regex").is_some() => {
            html("<ul><li>mine</li><li>theirs</li></ul>")
        }
        "/mongojson" => html("<ul></ul>"),
        _ if id.is_object() => html("<p>bad input</p>"),
        _ if *id == serde_json::json!(1) => html("<ul><li>mine</li></ul>"),
        _ => html("<ul></ul>"),
    }
}

fn json_target(port: u16, path: &str, body: &str) -> ScanTarget {
    let req = format!(
        "POST {path} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
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

fn spawn_app() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut s) = stream else { continue };
            std::thread::spawn(move || {
                let mut buf = vec![0u8; 16384];
                let n = s.read(&mut buf).unwrap_or(0);
                let req = String::from_utf8_lossy(&buf[..n]).to_string();
                let target = req.split(' ').nth(1).unwrap_or("/").to_string();
                let (path, query) = target.split_once('?').unwrap_or((&target, ""));
                let response = if req.starts_with("POST ") {
                    handle_json(path, req.split_once("\r\n\r\n").map_or("", |(_, b)| b))
                } else {
                    handle(path, query)
                };
                let _ = s.write_all(response.as_bytes());
            });
        }
    });
    port
}

fn request(port: u16, path_and_query: &str) -> Vec<u8> {
    format!("GET {path_and_query} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nConnection: close\r\n\r\n").into_bytes()
}

/// A target with its baseline response, fetched directly.
fn target(port: u16, path_and_query: &str) -> ScanTarget {
    let req = request(port, path_and_query);
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

fn project(name: &str) -> PathBuf {
    let dir =
        std::env::temp_dir().join(format!("bp-inj-{name}-{}-{}", std::process::id(), crate::scan::active::rand_u64()));
    std::fs::create_dir_all(&dir).unwrap();
    dir.join("project.db")
}

type Found = Vec<(String, String, String, String)>;

/// Runs one rule over `targets`; returns the summary and the stored findings
/// (alert ref, name, param, attack).
async fn scan(name: &str, rule: u32, strength: Strength, targets: Vec<ScanTarget>) -> (ActiveSummary, Found) {
    scan_points(name, rule, strength, PointOptions::default(), targets).await
}

async fn scan_points(
    name: &str,
    rule: u32,
    strength: Strength,
    points: PointOptions,
    targets: Vec<ScanTarget>,
) -> (ActiveSummary, Found) {
    let guard =
        Guard::from_specs(vec![ScopeSpec { name: None, include: vec!["127.0.0.1".into()], exclude: vec![] }]).unwrap();
    let cfg = ActiveConfig {
        strength,
        concurrency: 4,
        rate: None,
        send: SendOptions { timeout: Duration::from_secs(20), guard: Some(guard), ..Default::default() },
        points,
        rules: Some(vec![rule]),
        exclude_rules: vec![],
        no_rules: false,
        checks: vec![],
        max_duration: None,
        auth: None,
        oob: None,
        oob_wait: std::time::Duration::ZERO,
    };
    let path = project(name);
    let summary = run(&path, targets, cfg, JobControl::default()).await.unwrap();
    let conn = rusqlite::Connection::open(&path).unwrap();
    let mut st = conn.prepare("SELECT alert_ref, name, param, attack FROM findings ORDER BY id").unwrap();
    let found =
        st.query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?))).unwrap().map(|r| r.unwrap()).collect();
    drop(st);
    drop(conn);
    let _ = std::fs::remove_dir_all(path.parent().unwrap());
    (summary, found)
}

#[tokio::test(flavor = "multi_thread")]
async fn sql_injection_error_expression_and_boolean_based() {
    let port = spawn_app();
    let targets = vec![
        target(port, "/sqlerr?id=7"),
        target(port, "/sqlexpr?id=1"),
        target(port, "/sqlbool?name=apple"),
        target(port, "/safe?id=1"),
    ];
    let (summary, found) = scan("sqli", 40018, Strength::Medium, targets).await;
    assert_eq!(summary.raised.get("40018"), Some(&3), "{summary:?}");
    assert_eq!(found.len(), 3, "{found:?}");
    let err = found.iter().find(|f| f.1 == "SQL Injection - MySQL").expect("error based finding");
    assert_eq!((err.2.as_str(), err.3.as_str()), ("id", "'"));
    let expr = found.iter().find(|f| f.1 == "SQL Injection" && f.2 == "id").expect("expression based finding");
    assert_eq!((expr.2.as_str(), expr.3.as_str()), ("id", "3-2"));
    let boolean = found.iter().find(|f| f.2 == "name").expect("boolean based finding");
    assert_eq!((boolean.1.as_str(), boolean.3.as_str()), ("SQL Injection", "apple' AND '1'='1' -- "));
}

#[tokio::test(flavor = "multi_thread")]
async fn command_injection_output_based() {
    let port = spawn_app();
    let (s, found) =
        scan("cmd", 90020, Strength::Medium, vec![target(port, "/ping?host=a"), target(port, "/safe?host=a")]).await;
    assert_eq!(s.raised.get("90020"), Some(&1), "{s:?}");
    assert_eq!((found[0].2.as_str(), found[0].3.as_str()), ("host", "cat /etc/passwd"));
    // The safe endpoint got every payload of every OS list (7 each at MEDIUM, 5 for PowerShell).
    assert!(s.requests >= 7 + 7 + 5, "{s:?}");
}

#[tokio::test(flavor = "multi_thread")]
async fn mongodb_operators_in_parameter_names() {
    let port = spawn_app();
    let (s, found) = scan(
        "mongo",
        40033,
        Strength::Medium,
        vec![target(port, "/mongo?id=1"), target(port, "/mongoplain?id=1"), target(port, "/safe?id=1")],
    )
    .await;
    assert_eq!(s.raised.get("40033"), Some(&1), "{found:?}");
    assert_eq!(found[0].2, "id");
    assert_eq!(found[0].3, "id[$ne]");
}

#[tokio::test(flavor = "multi_thread")]
async fn mongodb_unhandled_error_needs_more_than_low_strength() {
    let port = spawn_app();
    let (s, found) = scan("mongoerr", 40033, Strength::Medium, vec![target(port, "/mongocrash?id=1")]).await;
    assert_eq!(s.raised.get("40033"), Some(&1), "{found:?}");
    assert_eq!(found[0].3, "'");
    let (s, _) = scan("mongoerrlow", 40033, Strength::Low, vec![target(port, "/mongocrash?id=1")]).await;
    assert!(s.raised.is_empty(), "{s:?}");
}

#[tokio::test(flavor = "multi_thread")]
async fn mongodb_operators_as_json_values() {
    let port = spawn_app();
    let (s, found) =
        scan("mongojson", 40033, Strength::Medium, vec![json_target(port, "/mongojson", r#"{"id":1}"#)]).await;
    assert_eq!(s.raised.get("40033"), Some(&1), "{found:?}");
    assert_eq!(found[0].3, "$ne0");
    // The counter-proof rejects a server that treats every object as bad input.
    let (s, found) =
        scan("jsonstrict", 40033, Strength::Medium, vec![json_target(port, "/jsonstrict", r#"{"id":1}"#)]).await;
    assert!(s.raised.is_empty(), "{found:?}");
    // LOW proves it too, and still finds the real one.
    let (s, _) = scan("jsonlow", 40033, Strength::Low, vec![json_target(port, "/jsonstrict", r#"{"id":1}"#)]).await;
    assert!(s.raised.is_empty(), "{s:?}");
    let (s, _) = scan("jsonlow2", 40033, Strength::Low, vec![json_target(port, "/mongojson", r#"{"id":1}"#)]).await;
    assert_eq!(s.raised.get("40033"), Some(&1), "{s:?}");
}

#[tokio::test(flavor = "multi_thread")]
async fn mongodb_time_based() {
    // Tests sleep 2s for the high delay.
    let port = spawn_app();
    let (s, found) =
        scan("mongosleep", 90039, Strength::Low, vec![target(port, "/mongosleep?id=1"), target(port, "/safe?id=1")])
            .await;
    assert_eq!(s.raised.get("90039"), Some(&1), "{found:?}");
    assert_eq!(found[0].3, "\"); sleep(2); print(\"");
    assert_eq!(s.requests, 4 + 6, "{s:?}");
}

#[tokio::test(flavor = "multi_thread")]
async fn mysql_time_based() {
    // Tests sleep 2s for the high delay; the vulnerable endpoint needs 2+1+2+1 seconds.
    let port = spawn_app();
    let (s, found) =
        scan("mysql", 40019, Strength::Low, vec![target(port, "/sleepy?id=1"), target(port, "/safe?id=1")]).await;
    assert_eq!(s.raised.get("40019"), Some(&1), "{s:?}");
    assert_eq!(found[0].3, "1 / sleep(2) ");
    // Vulnerable: 4 timed requests; safe: one request per payload (6 at LOW), each
    // giving up at once because the response came back before the requested delay.
    assert_eq!(s.requests, 4 + 6, "{s:?}");
}

#[tokio::test(flavor = "multi_thread")]
async fn safe_endpoint_raises_nothing() {
    let port = spawn_app();
    for rule in [40018, 90019, 90020] {
        let (s, _) = scan(&format!("safe{rule}"), rule, Strength::High, vec![target(port, "/safe?q=1")]).await;
        assert!(s.raised.is_empty(), "rule {rule}: {s:?}");
        assert!(s.requests > 0);
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn sql_injection_ignores_pages_that_echo_their_input() {
    let port = spawn_app();
    let paths = PointOptions { path: true, ..Default::default() };
    let targets = vec![target(port, "/echo/1"), target(port, "/echo/about"), target(port, "/nowhere/x")];
    // Insane is where it counts: the other strengths run out of boolean attacks earlier.
    for strength in [Strength::Medium, Strength::Insane] {
        let (s, found) = scan_points("echopath", 40018, strength, paths.clone(), targets.clone()).await;
        assert!(s.raised.is_empty(), "{s:?} {found:?}");
        let (s, found) = scan("echoq", 40018, strength, vec![target(port, "/echo?q=1")]).await;
        assert!(s.raised.is_empty(), "{s:?} {found:?}");
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn fixed_path_segments_are_attacked_once_per_origin() {
    let port = spawn_app();
    let paths = PointOptions { path: true, ..Default::default() };
    let targets = vec![target(port, "/rest/item/1"), target(port, "/rest/item/2"), target(port, "/rest/other/about")];
    let (s, found) = scan_points("fixed", 40018, Strength::Medium, paths, targets).await;
    // rest, item, 1 and 2, other, about: `rest` and `item` aren't repeated.
    assert_eq!(s.insertion_points, 6, "{s:?}");
    // Each ID is still attacked, and the fault found through it (the two are stored as one).
    assert_eq!(s.raised.get("40018"), Some(&2), "{s:?}");
    assert_eq!(found[0].2, "path[2]", "{found:?}");
}

#[tokio::test(flavor = "multi_thread")]
async fn fixed_path_segments_are_attacked_for_each_method() {
    let port = spawn_app();
    let paths = PointOptions { path: true, ..Default::default() };
    let get = target(port, "/rest/orders");
    let mut post = get.clone();
    post.request = String::from_utf8(post.request).unwrap().replacen("GET ", "POST ", 1).into_bytes();
    let (s, _) = scan_points("methods", 40018, Strength::Low, paths, vec![get, post]).await;
    assert_eq!(s.insertion_points, 4, "{s:?}");
}

#[test]
fn eval_helper() {
    assert_eq!(eval("1"), Some(1));
    assert_eq!(eval("3-2"), Some(1));
    assert_eq!(eval("4/2"), Some(2));
    assert_eq!(eval("1'"), None);
}
