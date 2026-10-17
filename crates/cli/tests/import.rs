//! End-to-end tests for `import`: a local API serving an OpenAPI document and a
//! GraphQL endpoint; imported requests must be sent in scope, recorded, and
//! picked up by `scan active`.

use std::io::{Read, Write};
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};

use serde_json::Value;

fn bin() -> Command {
    Command::new(env!("CARGO_BIN_EXE_brainproxy"))
}

const SPEC: &str = r#"
openapi: 3.0.0
servers:
  - url: /api
paths:
  /items/{id}:
    parameters:
      - {name: id, in: path, required: true, schema: {type: integer, example: 7}}
    get:
      operationId: getItem
      parameters:
        - {name: q, in: query, schema: {type: string}}
      responses:
        200: {description: ok}
    delete:
      operationId: deleteItem
  /items:
    post:
      operationId: createItem
      requestBody:
        content:
          application/json:
            schema:
              properties:
                name: {type: string, example: widget}
                count: {type: integer}
"#;

const INTROSPECTION: &str = r#"{"data": {"__schema": {
  "queryType": {"name": "Query"}, "mutationType": {"name": "Mutation"},
  "types": [
    {"kind": "OBJECT", "name": "Query", "fields": [
      {"name": "item", "args": [{"name": "id", "type": {"kind": "NON_NULL", "name": null, "ofType": {"kind": "SCALAR", "name": "ID", "ofType": null}}}],
       "type": {"kind": "OBJECT", "name": "Item", "ofType": null}}]},
    {"kind": "OBJECT", "name": "Mutation", "fields": [
      {"name": "wipe", "args": [], "type": {"kind": "SCALAR", "name": "Boolean", "ofType": null}}]},
    {"kind": "OBJECT", "name": "Item", "fields": [
      {"name": "id", "args": [], "type": {"kind": "SCALAR", "name": "ID", "ofType": null}},
      {"name": "name", "args": [], "type": {"kind": "SCALAR", "name": "String", "ofType": null}}]}
  ]}}}"#;

type Log = Arc<Mutex<Vec<String>>>;

/// Serves the spec, the API (q is reflected unescaped), and a GraphQL endpoint.
/// Logs "METHOD target body" per request.
fn serve() -> (u16, Log) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let log: Log = Arc::default();
    let l = log.clone();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut s) = stream else { continue };
            let log = l.clone();
            std::thread::spawn(move || {
                let mut buf = [0u8; 8192];
                let mut req = Vec::new();
                let head_end = loop {
                    if let Some(i) = req.windows(4).position(|w| w == b"\r\n\r\n") {
                        break i + 4;
                    }
                    match s.read(&mut buf) {
                        Ok(0) | Err(_) => return,
                        Ok(k) => req.extend_from_slice(&buf[..k]),
                    }
                };
                let head = String::from_utf8_lossy(&req[..head_end]).to_string();
                let len: usize = head
                    .lines()
                    .find_map(|l| {
                        l.to_ascii_lowercase().strip_prefix("content-length:").map(|v| v.trim().parse().unwrap())
                    })
                    .unwrap_or(0);
                while req.len() < head_end + len {
                    match s.read(&mut buf) {
                        Ok(0) | Err(_) => break,
                        Ok(k) => req.extend_from_slice(&buf[..k]),
                    }
                }
                let body = String::from_utf8_lossy(&req[head_end..]).to_string();
                let line = head.lines().next().unwrap_or("").to_string();
                let mut parts = line.split(' ');
                let (method, target) = (parts.next().unwrap_or(""), parts.next().unwrap_or(""));
                log.lock().unwrap().push(format!("{method} {target} {body}"));
                let (ct, resp_body) = if target == "/openapi.yaml" {
                    ("application/yaml", SPEC.to_string())
                } else if target == "/graphql" && body.contains("IntrospectionQuery") {
                    ("application/json", INTROSPECTION.to_string())
                } else if target == "/graphql" {
                    ("application/json", r#"{"data": {"item": {"id": "1", "name": "x"}}}"#.to_string())
                } else {
                    let q = target.split_once("q=").map(|(_, v)| v.split('&').next().unwrap_or("")).unwrap_or("");
                    let q = percent_decode(q);
                    ("text/html", format!("<html><body><p>Results for {q}</p></body></html>"))
                };
                let resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: {ct}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{resp_body}",
                    resp_body.len()
                );
                let _ = s.write_all(resp.as_bytes());
            });
        }
    });
    (port, log)
}

fn percent_decode(s: &str) -> String {
    let b = s.replace('+', " ").into_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' && i + 2 < b.len() {
            if let Ok(v) = u8::from_str_radix(std::str::from_utf8(&b[i + 1..i + 3]).unwrap_or("zz"), 16) {
                out.push(v);
                i += 3;
                continue;
            }
        }
        out.push(b[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn run_stdin(args: &[&str], project: &Path, stdin: &str) -> (i32, Value) {
    let mut child = bin()
        .args(["--format", "json", "--project"])
        .arg(project)
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    child.stdin.take().unwrap().write_all(stdin.as_bytes()).unwrap();
    let out = child.wait_with_output().unwrap();
    let v: Value = serde_json::from_slice(&out.stdout)
        .unwrap_or_else(|e| panic!("bad JSON ({e}): {}", String::from_utf8_lossy(&out.stdout)));
    (out.status.code().unwrap(), v)
}

fn run(args: &[&str], project: &Path) -> (i32, Value) {
    run_stdin(args, project, "")
}

fn setup(name: &str) -> (PathBuf, PathBuf) {
    let dir = std::env::temp_dir().join(format!("bp-import-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let project = dir.join("p.bpdb");
    let (code, v) = run(&["engagement", "start", "--target", "127.0.0.1"], &project);
    assert_eq!(code, 0, "{v}");
    (dir, project)
}

fn sent(log: &Log) -> Vec<String> {
    log.lock().unwrap().clone()
}

#[test]
fn openapi_import_feeds_the_active_scanner() {
    let (dir, project) = setup("openapi");
    let (port, log) = serve();
    let spec_url = format!("http://127.0.0.1:{port}/openapi.yaml");

    // Dry run: builds from the fetched spec (relative server resolves against its URL), sends nothing else.
    let (code, v) = run(&["import", "openapi", &spec_url, "--dry-run"], &project);
    assert_eq!(code, 0, "{v}");
    let d = &v["data"];
    assert_eq!((d["built"].as_u64(), d["skipped_destructive"].as_u64()), (Some(3), Some(1)), "{d}");
    let urls: Vec<&str> = d["requests"].as_array().unwrap().iter().map(|r| r["url"].as_str().unwrap()).collect();
    assert_eq!(
        urls,
        [format!("http://127.0.0.1:{port}/api/items/7?q=test"), format!("http://127.0.0.1:{port}/api/items")]
    );
    assert_eq!(d["requests"][1]["body"]["content"], r#"{"name":"widget","count":1}"#);
    assert_eq!(sent(&log).len(), 1);

    // Real run: in-scope requests are sent and recorded as source 'import'; DELETE is skipped.
    let (code, v) = run(&["import", "openapi", &spec_url], &project);
    assert_eq!(code, 0, "{v}");
    let d = &v["data"];
    assert_eq!(d["sent"], 2, "{d}");
    assert_eq!(d["by_status"]["200"], 2);
    assert!(d["requests"][0]["history_id"].as_i64().unwrap() > 0);
    let log_now = sent(&log);
    assert!(log_now.iter().any(|l| l.starts_with("GET /api/items/7?q=test ")), "{log_now:?}");
    assert!(log_now.iter().any(|l| l == r#"POST /api/items {"name":"widget","count":1}"#), "{log_now:?}");
    assert!(!log_now.iter().any(|l| l.starts_with("DELETE")));
    let (_, q) = run(&["query", "SELECT count(*) FROM history WHERE source = 'import'"], &project);
    assert_eq!(q["data"]["rows"][0][0], 4, "{q}"); // 2 spec fetches + 2 requests

    // `scan active` without targets attacks the imported requests and finds the reflected q.
    let (code, v) = run(&["scan", "active", "--rules", "40012", "--strength", "low"], &project);
    assert_eq!(code, 0, "{v}");
    let found = v["data"]["active_findings"].as_array().unwrap();
    assert!(found.iter().any(|g| g["alert_ref"].as_str().unwrap_or("").starts_with("40012")), "{v}");

    // --include-destructive sends the DELETE too; --base-url origin keeps the server path.
    let (code, v) = run(
        &["import", "openapi", &spec_url, "--include-destructive", "--base-url", &format!("http://127.0.0.1:{port}")],
        &project,
    );
    assert_eq!(code, 0, "{v}");
    assert_eq!(v["data"]["sent"], 3);
    assert!(sent(&log).iter().any(|l| l.starts_with("DELETE /api/items/7 ")));

    // Servers outside the scope are skipped, not sent.
    let (code, v) = run_stdin(&["import", "openapi", "-", "--base-url", "http://example.com"], &project, SPEC);
    assert_eq!(code, 0, "{v}");
    assert_eq!((v["data"]["sent"].as_u64(), v["data"]["skipped_out_of_scope"].as_u64()), (Some(0), Some(2)), "{v}");
    assert_eq!(v["data"]["out_of_scope_hosts"][0], "example.com");

    // Fetching a spec from outside the scope fails before any request; stdin can't go to the background.
    let (code, v) = run(&["import", "openapi", "http://example.com/openapi.json"], &project);
    assert_eq!((code, v["error"]["kind"].as_str()), (6, Some("out_of_scope")), "{v}");
    let (code, v) = run(&["import", "openapi", "-", "--background"], &project);
    assert_eq!(code, 2, "{v}");
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn postman_and_graphql_imports() {
    let (dir, project) = setup("pm-gql");
    let (port, log) = serve();

    let collection = r#"{
      "info": {"schema": "https://schema.getpostman.com/json/collection/v2.1.0/collection.json"},
      "item": [
        {"name": "Search", "request": {"method": "GET", "url": "{{base}}/api/search?q=hello",
          "header": [{"key": "X-Client", "value": "pm"}]}},
        {"name": "Remove", "request": {"method": "DELETE", "url": "{{base}}/api/items/1"}}
      ]}"#;
    let file = dir.join("c.json");
    std::fs::write(&file, collection).unwrap();
    let base = format!("base=http://127.0.0.1:{port}");
    let (code, v) = run(&["import", "postman", file.to_str().unwrap(), "--var", &base, "-H", "X-Extra: 1"], &project);
    assert_eq!(code, 0, "{v}");
    assert_eq!((v["data"]["sent"].as_u64(), v["data"]["skipped_destructive"].as_u64()), (Some(1), Some(1)), "{v}");
    assert!(sent(&log).iter().any(|l| l.starts_with("GET /api/search?q=hello ")));
    // Without the variable the host is unknown: nothing to send, the warning says why.
    let (code, v) = run(&["import", "postman", file.to_str().unwrap()], &project);
    assert_eq!(code, 2, "{v}");
    assert!(v["error"]["message"].as_str().unwrap().contains("--var"), "{v}");

    // GraphQL: introspection through the guarded client, then one query per field; mutations skipped.
    let gql = format!("http://127.0.0.1:{port}/graphql");
    let (code, v) = run(&["import", "graphql", &gql], &project);
    assert_eq!(code, 0, "{v}");
    assert_eq!((v["data"]["built"].as_u64(), v["data"]["sent"].as_u64()), (Some(1), Some(1)), "{v}");
    assert_eq!(v["data"]["requests"][0]["name"], "query item");
    let log_now = sent(&log);
    let q = log_now.iter().find(|l| l.contains("\"operationName\":\"item\"")).expect("item query sent");
    assert!(q.contains(r#""variables":{"id":"1"}"#), "{q}");
    assert!(!log_now.iter().any(|l| l.contains("wipe")));

    // From a saved schema, with mutations.
    let schema = dir.join("schema.json");
    std::fs::write(&schema, INTROSPECTION).unwrap();
    let (code, v) =
        run(&["import", "graphql", &gql, "--schema", schema.to_str().unwrap(), "--include-destructive"], &project);
    assert_eq!(code, 0, "{v}");
    assert_eq!(v["data"]["sent"], 2, "{v}");
    assert!(sent(&log).iter().any(|l| l.contains("mutation wipe")));

    // capabilities describes the command group.
    let (_, caps) = run(&["capabilities", "import"], &project);
    let text = caps.to_string();
    assert!(text.contains("import openapi") && text.contains("--include-destructive"), "{text}");
    let _ = std::fs::remove_dir_all(dir);
}
