//! End-to-end tests for `import api` and `scan active --api`, from the small documents in
//! tests/fixtures/api against a local API. Every secret in them is fake and starts with FAKE.

use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::{Arc, Mutex};

use brainproxy_core::http::request::split_head_body;
use brainproxy_core::sign::{hmac_digest, HmacAlg};
use serde_json::{json, Value};

const HMAC_KEY: &str = "FAKE-HMAC-KEY";
const API_KEY: &str = "FAKE-API-KEY-VALUE";

/// `ENV_VAR` the keys are read from.
const KEY_ENV: &str = "BRAINPROXY_SECRET_API_KEY";

#[derive(Clone, Debug)]
struct Hit {
    method: String,
    target: String,
    head: String,
    body: String,
}

impl Hit {
    fn header(&self, name: &str) -> Option<&str> {
        self.head.lines().find_map(|l| {
            let (k, v) = l.split_once(':')?;
            k.eq_ignore_ascii_case(name).then(|| v.trim())
        })
    }

    fn path(&self) -> &str {
        self.target.split('?').next().unwrap_or_default()
    }
}

#[derive(Clone)]
struct Api {
    port: u16,
    hits: Arc<Mutex<Vec<Hit>>>,
}

impl Api {
    fn start() -> Api {
        Self::with(None, false)
    }

    /// `document` is served at /spec; `signed` refuses what isn't signed with [`HMAC_KEY`].
    fn with(document: Option<String>, signed: bool) -> Api {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let hits: Arc<Mutex<Vec<Hit>>> = Arc::default();
        let shared = hits.clone();
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(s) = stream else { continue };
                let (hits, document) = (shared.clone(), document.clone());
                std::thread::spawn(move || handle(s, &hits, document.as_deref(), signed));
            }
        });
        Api { port, hits }
    }

    fn hits(&self) -> Vec<Hit> {
        self.hits.lock().unwrap().clone()
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

fn handle(mut s: TcpStream, hits: &Mutex<Vec<Hit>>, document: Option<&str>, signed: bool) {
    while let Some(raw) = read_request(&mut s) {
        let (head, body) = split_head_body(&raw);
        let head = String::from_utf8_lossy(head).into_owned();
        let line = head.lines().next().unwrap_or_default().to_string();
        let mut words = line.split(' ');
        let (method, target) = (words.next().unwrap_or_default(), words.next().unwrap_or_default());
        let hit = Hit {
            method: method.into(),
            target: target.into(),
            head: head.clone(),
            body: String::from_utf8_lossy(body).into_owned(),
        };
        let good = !signed || signature_good(&hit);
        hits.lock().unwrap().push(hit);
        let text = match document.filter(|_| target == "/spec") {
            Some(d) => d.to_string(),
            None => r#"{"ok":true}"#.to_string(),
        };
        let reply = if good {
            format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{text}", text.len())
        } else {
            "HTTP/1.1 401 Unauthorized\r\nContent-Length: 13\r\n\r\nbad signature".to_string()
        };
        if s.write_all(reply.as_bytes()).is_err() {
            return;
        }
    }
}

fn signature_good(hit: &Hit) -> bool {
    let (path, query) = hit.target.split_once('?').unwrap_or((&hit.target, ""));
    let Some(sig) = hit.header("x-signature") else { return false };
    let text = format!("{}\n{path}\n{query}", hit.method);
    let want = hmac_digest(HmacAlg::Sha256, HMAC_KEY.as_bytes(), text.as_bytes());
    want.iter().map(|b| format!("{b:02x}")).collect::<String>() == sig
}

/// A project in its own directory, with its scope set.
fn setup(name: &str, scope: &str) -> (PathBuf, PathBuf) {
    let dir = std::env::temp_dir().join(format!("bp-api-scan-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let project = dir.join("p.bpdb");
    ok(&project, &["engagement", "start", "--target", scope]);
    (dir, project)
}

/// A fixture written to `dir`, its 18080 now the port of the local API.
fn fixture(dir: &Path, name: &str, port: u16) -> String {
    let manifest = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/api").join(name);
    let text = std::fs::read_to_string(manifest).unwrap().replace("18080", &port.to_string());
    let path = dir.join(name);
    std::fs::write(&path, text).unwrap();
    path.to_str().unwrap().to_string()
}

fn write_doc(dir: &Path, name: &str, doc: &str) -> String {
    let path = dir.join(name);
    std::fs::write(&path, doc).unwrap();
    path.to_str().unwrap().to_string()
}

struct Output {
    code: i32,
    json: Value,
    /// stdout and stderr together.
    all: String,
}

fn command(project: &Path, args: &[&str], env: &[(&str, &str)], format: &str) -> Output {
    let mut c = Command::new(env!("CARGO_BIN_EXE_brainproxy"));
    c.args(["--format", format, "--project"]).arg(project).args(args);
    c.env("SIGN_KEY", HMAC_KEY).env_remove(KEY_ENV);
    for (k, v) in env {
        c.env(k, v);
    }
    let out = c.output().unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
    Output {
        code: out.status.code().unwrap_or(-1),
        json: serde_json::from_str(&stdout).unwrap_or(Value::Null),
        all: format!("{stdout}\n{stderr}"),
    }
}

fn run(project: &Path, args: &[&str]) -> Output {
    command(project, args, &[], "json")
}

fn ok(project: &Path, args: &[&str]) -> Value {
    let o = run(project, args);
    assert_eq!(o.code, 0, "{args:?}: {}", o.all);
    o.json["data"].clone()
}

/// Asserts the command is refused with this exit code and kind, and returns the message.
fn refused(project: &Path, args: &[&str], code: i32, kind: &str) -> String {
    let o = run(project, args);
    assert_eq!((o.code, o.json["error"]["kind"].as_str()), (code, Some(kind)), "{args:?}: {}", o.all);
    o.json["error"]["message"].as_str().unwrap().to_string()
}

fn preview(project: &Path, source: &str, more: &[&str]) -> Value {
    let mut args = vec!["import", "api", "--dry-run", "--limit=1000"];
    args.extend_from_slice(more);
    args.extend_from_slice(&["--", source]);
    ok(project, &args)
}

fn names(d: &Value) -> Vec<String> {
    d["requests"].as_array().unwrap().iter().map(|r| r["name"].as_str().unwrap().to_string()).collect()
}

fn index_of(d: &Value, name: &str) -> usize {
    names(d).iter().position(|n| n == name).unwrap_or_else(|| panic!("no {name} in {d}"))
}

fn row<'a>(d: &'a Value, name: &str) -> &'a Value {
    &d["requests"][index_of(d, name)]
}

fn included(d: &Value) -> Vec<String> {
    let reqs = d["requests"].as_array().unwrap();
    reqs.iter().filter(|r| r["included"] == true).map(|r| r["name"].as_str().unwrap().to_string()).collect()
}

/// Every table a run writes, as text; only the auth profile itself may hold a key.
fn assert_absent_from_project(project: &Path, secrets: &[&str]) {
    let tables = ok(project, &["query", "SELECT name FROM sqlite_master WHERE type = 'table'"]);
    for t in tables["rows"].as_array().unwrap() {
        let t = t[0].as_str().unwrap();
        if t == "auth_profiles" || t == "sqlite_sequence" || t.contains("_fts_") {
            continue;
        }
        let cols = ok(project, &["query", "SELECT name FROM pragma_table_info(?1)", "-p", t]);
        for c in cols["rows"].as_array().unwrap() {
            let c = c[0].as_str().unwrap();
            for s in secrets {
                let sql = format!("SELECT count(*) FROM \"{t}\" WHERE instr(CAST(\"{c}\" AS TEXT), ?1) > 0");
                let n = ok(project, &["query", &sql, "-p", s]);
                assert_eq!(n["rows"][0][0], 0, "{s} in {t}.{c}");
            }
        }
    }
}

// --- Formats ---

#[test]
fn every_format_is_detected() {
    let (dir, p) = setup("formats", "127.0.0.1");
    let hits_none = Api::start();
    for (name, format, title, version) in [
        ("openapi3.json", "openapi3", "Pets", "1.0"),
        ("openapi3.yaml", "openapi3", "Pets YAML", "2.0"),
        ("swagger2.json", "swagger2", "Store", "1.1"),
        ("swagger2.yaml", "swagger2", "Store YAML", "1.1"),
    ] {
        let d = preview(&p, &fixture(&dir, name, hits_none.port), &[]);
        assert_eq!(d["kind"], "api");
        assert_eq!(d["format"], format, "{name}");
        assert_eq!((d["title"].as_str(), d["version"].as_str()), (Some(title), Some(version)), "{name}");
        assert_eq!(d["document_sha256"].as_str().unwrap().len(), 64);
    }
    let d = preview(&p, &fixture(&dir, "postman.json", hits_none.port), &[]);
    assert_eq!((d["format"].as_str(), d["title"].as_str()), (Some("postman"), Some("Shop")));
    assert!(d["version"].is_null());
    assert!(hits_none.hits().is_empty());
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn a_document_from_a_url_is_fetched_in_scope_and_checked() {
    let (dir, p) = setup("url-source", "127.0.0.1");
    let doc = r#"{"openapi": "3.0.0", "servers": [{"url": "/rel"}], "paths": {"/a": {"get": {"operationId": "a"}}}}"#;
    let api = Api::with(Some(doc.to_string()), false);
    let url = format!("{}/spec", api.origin());
    let d = preview(&p, &url, &[]);
    assert_eq!(d["requests"][0]["url"], format!("{}/rel/a", api.origin()), "relative to the document's URL");
    assert_eq!(api.hits().len(), 1, "only the document");
    let kept = ok(&p, &["query", "SELECT count(*) FROM history"]);
    assert_eq!(kept["rows"][0][0], 0, "the document may hold credentials, so it isn't kept");

    // The hash of what the server gives is what's checked, in the foreground and in a job.
    let sha = d["document_sha256"].as_str().unwrap().to_string();
    let good = format!("--expect-sha256={sha}");
    ok(&p, &["import", "api", &good, "--", &url]);
    assert_eq!(api.hits().iter().filter(|h| h.target == "/rel/a").count(), 1);
    let before = api.hits().iter().filter(|h| h.target == "/rel/a").count();
    let e = refused(&p, &["import", "api", "--expect-sha256=00", "--", &url], 2, "invalid_input");
    assert!(e.contains(&sha), "{e}");
    assert_eq!(api.hits().iter().filter(|h| h.target == "/rel/a").count(), before, "nothing but the document");
    let o = run(&p, &["scan", "active", "--expect-sha256=00", "--background", &format!("--api={url}")]);
    assert_ne!(o.code, 0, "{}", o.all);
    assert!(o.all.contains(&sha), "{}", o.all);
    assert_eq!(api.hits().iter().filter(|h| h.target == "/rel/a").count(), before);

    // Credentials in the URL, or a URL out of scope, stop it before anything goes out.
    let n = api.hits().len();
    let with_key = format!("{url}?api_key=FAKE-URL-KEY");
    let e = refused(&p, &["import", "api", "--dry-run", "--", &with_key], 2, "invalid_input");
    assert!(e.contains("api_key") && !e.contains("FAKE"), "{e}");
    let with_user = format!("http://u:FAKE-URL-PW@127.0.0.1:{}/spec", api.port);
    let e = refused(&p, &["scan", "active", &format!("--api={with_user}")], 2, "invalid_input");
    assert!(!e.contains("FAKE"), "{e}");
    refused(&p, &["import", "api", "--dry-run", "--", "http://198.51.100.9/spec"], 6, "out_of_scope");
    assert_eq!(api.hits().len(), n);
    let _ = std::fs::remove_dir_all(dir);
}

// --- Building ---

#[test]
fn references_are_resolved() {
    let (dir, p) = setup("refs", "127.0.0.1");
    let api = Api::start();
    let d = preview(&p, &fixture(&dir, "openapi3.json", api.port), &[]);
    // A parameter by $ref, on the path item, with its example from the schema.
    assert_eq!(row(&d, "getPet")["url"], format!("{}/v1/pets/7", api.origin()));
    // A request body by $ref to a schema by $ref.
    assert_eq!(row(&d, "createPet")["body"]["content"], r#"{"name":"rex","age":1}"#);
    assert_eq!(row(&d, "createPet")["headers"], json!(["Content-Type: application/json"]));
    let d = preview(&p, &fixture(&dir, "openapi3.yaml", api.port), &[]);
    assert_eq!(row(&d, "getPet")["url"], format!("{}/v1/pets/42", api.origin()));
    let d = preview(&p, &fixture(&dir, "swagger2.json", api.port), &[]);
    assert_eq!(row(&d, "createOrder")["body"]["content"], r#"{"sku":"abc","qty":1}"#);
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn servers_are_chosen_and_their_paths_not_doubled() {
    let (dir, p) = setup("servers", "127.0.0.1");
    let api = Api::start();
    let o = api.origin();
    let src = fixture(&dir, "openapi3.json", api.port);
    let d = preview(&p, &src, &[]);
    assert_eq!(
        d["servers"],
        json!([
            {"index": 0, "url": format!("{o}/v1"), "description": "local"},
            {"index": 1, "url": "https://api.example.test/v2", "description": "prod"},
        ])
    );
    assert_eq!(d["base_url_required"], false);
    assert_eq!(row(&d, "getPet")["url"], format!("{o}/v1/pets/7"));
    let d = preview(&p, &src, &["--server=1"]);
    assert_eq!(row(&d, "getPet")["url"], "https://api.example.test/v2/pets/7");
    assert_eq!(row(&d, "elsewhere")["url"], "https://elsewhere.example.test/elsewhere", "an operation's server wins");
    let e = refused(&p, &["import", "api", "--dry-run", "--server=2", "--", &src], 2, "invalid_input");
    assert!(e.contains("--server 2"), "{e}");

    // --base-url: an origin keeps the server's path; a path replaces it; neither doubles it.
    let d = preview(&p, &src, &[&format!("--base-url={o}")]);
    assert_eq!(row(&d, "getPet")["url"], format!("{o}/v1/pets/7"));
    let d = preview(&p, &src, &[&format!("--base-url={o}/other")]);
    assert_eq!(row(&d, "getPet")["url"], format!("{o}/other/pets/7"));
    assert_eq!(row(&d, "elsewhere")["url"], format!("{o}/other/elsewhere"), "it overrides everything");

    // What goes out has the path once.
    let hit_only = format!("--only={}", index_of(&preview(&p, &src, &[]), "getPet"));
    ok(&p, &["import", "api", &hit_only, "--", &src]);
    assert_eq!(api.hits()[0].target, "/v1/pets/7");

    // Swagger's schemes count as its servers.
    let sw = fixture(&dir, "swagger2.json", api.port);
    let d = preview(&p, &sw, &[]);
    let list: Vec<&str> = d["servers"].as_array().unwrap().iter().map(|s| s["url"].as_str().unwrap()).collect();
    assert_eq!(list, [format!("{o}/api"), format!("https://127.0.0.1:{}/api", api.port)]);
    let d = preview(&p, &sw, &["--server=1"]);
    assert_eq!(row(&d, "listOrders")["url"], format!("https://127.0.0.1:{}/api/orders?page=1", api.port));

    // No server at all.
    let d = preview(&p, &fixture(&dir, "swagger2.yaml", api.port), &[]);
    assert_eq!(d["base_url_required"], true);
    assert_eq!((d["built"].as_u64(), d["requests"].as_array().unwrap().len()), (Some(0), 0));
    assert_eq!(d["skipped"][0]["operation"], "GET /orders/{id}");
    assert!(d["hint"].as_str().unwrap().contains("--base-url"), "{d}");
    let sy = fixture(&dir, "swagger2.yaml", api.port);
    let e = refused(&p, &["import", "api", "--", &sy], 2, "invalid_input");
    assert!(e.contains("--base-url"), "{e}");
    let d = preview(&p, &sy, &[&format!("--base-url={o}")]);
    assert_eq!(d["base_url_required"], false);
    assert_eq!(row(&d, "getOrder")["url"], format!("{o}/api/orders/ord-1"), "with its x-example");
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn postman_variables_are_substituted_and_secret_ones_never() {
    let (dir, p) = setup("postman", "127.0.0.1");
    let api = Api::start();
    let src = fixture(&dir, "postman.json", api.port);
    let d = preview(&p, &src, &[]);
    let var = |d: &Value, n: &str| d["variables"].as_array().unwrap().iter().find(|v| v["name"] == n).unwrap().clone();
    assert_eq!(var(&d, "version")["value"], "v3");
    assert_eq!(var(&d, "version")["source"], "collection");
    for n in ["apiKey", "hidden", "viaAuth"] {
        assert_eq!(var(&d, n)["secret"], true, "{n}");
        assert!(var(&d, n)["value"].is_null(), "{n}");
    }
    assert_eq!(d["unresolved_variables"], json!(["tenant"]), "not the secret ones");
    assert_eq!(row(&d, "Catalog/List items")["headers"], json!(["X-Client: postman"]));
    let warnings = d["warnings"].to_string();
    assert!(warnings.contains("1 pre-request or test script(s) were not run"), "{warnings}");
    assert!(warnings.contains("{{tenant}} stays unresolved in the URL"), "{warnings}");
    assert!(warnings.contains("{{apiKey}} stays unresolved in the body"), "{warnings}");
    let auth = d["credentials"].as_array().unwrap().iter().find(|c| c["source"] == "auth:collection").unwrap().clone();
    assert_eq!((auth["kind"].as_str(), auth["name"].as_str()), (Some("bearer"), Some("Authorization")));

    // Typed values count; one that looks secret is ignored, with a warning, and never sent.
    let d2 = preview(&p, &src, &["--var=tenant=acme", "--var=apiKey=FAKE-CLI-KEY", "--var=version=v9"]);
    assert_eq!(var(&d2, "tenant")["source"], "cli");
    assert_eq!(var(&d2, "apiKey")["source"], "cli");
    assert!(var(&d2, "apiKey")["value"].is_null());
    assert_eq!(d2["unresolved_variables"], json!([]));
    assert!(row(&d2, "Catalog/List items")["url"].as_str().unwrap().contains("/v9/items?t=acme"), "{d2}");
    assert!(d2["warnings"].to_string().contains("--var apiKey looks like a credential"), "{d2}");
    assert!(!d2.to_string().contains("FAKE"), "{d2}");
    // Nor does a value typed for one the collection marks secret go anywhere.
    let d3 = preview(&p, &src, &["--var=hidden=FAKE-CLI-KEY"]);
    assert_eq!(
        (var(&d3, "hidden")["secret"].as_bool(), var(&d3, "hidden")["source"].as_str()),
        (Some(true), Some("cli"))
    );
    assert!(!d3.to_string().contains("FAKE"), "{d3}");

    let o = run(&p, &["import", "api", "--var=apiKey=FAKE-CLI-KEY", "--", &src]);
    assert_eq!(o.code, 0, "{}", o.all);
    assert!(!o.all.contains("FAKE"), "{}", o.all);
    let hits = api.hits();
    assert_eq!(hits.len(), 2, "not the DELETE: {hits:?}");
    let list = hits.iter().find(|h| h.method == "GET").unwrap();
    assert_eq!(list.target, "/v3/items?t={{tenant}}&k={{hidden}}");
    assert_eq!(list.header("x-client"), Some("postman"));
    assert_eq!((list.header("x-api-key"), list.header("authorization")), (None, None));
    let add = hits.iter().find(|h| h.method == "POST").unwrap();
    assert_eq!(add.body, r#"{"name": "v3", "key": "{{apiKey}}"}"#);
    for h in &hits {
        assert!(!h.head.contains("FAKE") && !h.body.contains("FAKE"), "{h:?}");
    }
    assert_absent_from_project(&p, &["FAKE-POSTMAN", "FAKE-CLI-KEY"]);

    // A secret variable can't reach the job table, by its name or by what the document does with it.
    let e =
        refused(&p, &["import", "api", "--background", "--var=apiKey=FAKE-CLI-KEY", "--", &src], 2, "invalid_input");
    assert!(e.contains("apiKey") && !e.contains("FAKE"), "{e}");
    let e =
        refused(&p, &["import", "api", "--background", "--var=viaAuth=FAKE-CLI-KEY", "--", &src], 2, "invalid_input");
    assert!(e.contains("viaAuth") && !e.contains("FAKE"), "{e}");
    let api_arg = format!("--api={src}");
    refused(&p, &["scan", "active", &api_arg, "--background", "--var=hidden=FAKE-CLI-KEY"], 2, "invalid_input");
    assert_eq!(ok(&p, &["job", "list"])["jobs"], json!([]));
    assert_absent_from_project(&p, &["FAKE-CLI-KEY"]);

    // No servers to choose from.
    let e = refused(&p, &["import", "api", "--dry-run", "--server=0", "--", &src], 2, "invalid_input");
    assert!(e.contains("Postman"), "{e}");
    refused(&p, &["scan", "active", &api_arg, "--server=0"], 2, "invalid_input");
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn a_variable_behind_a_secret_name_in_raw_text_stays_hidden() {
    let (dir, p) = setup("postman-raw", "127.0.0.1");
    let api = Api::start();
    let doc = json!({"info": {"name": "v"},
        "variable": [{"key": "t", "value": "FAKE-RAW-TOKEN"}, {"key": "pw", "value": "FAKE-RAW-PASSWORD"},
                     {"key": "form", "value": "FAKE-RAW-FORM"}, {"key": "base", "value": api.origin()}, {"key": "n", "value": "7"}],
        "item": [{"name": "a", "request": {"method": "POST", "url": "{{base}}/a?access_token={{t}}&x={{n}}",
            "body": {"mode": "raw", "raw": "{\"password\": \"{{pw}}\", \"n\": {{n}}}", "options": {"raw": {"language": "json"}}}}},
          {"name": "b", "request": {"method": "POST", "url": "{{base}}/b",
            "header": [{"key": "Content-Type", "value": "application/x-www-form-urlencoded"}],
            "body": {"mode": "raw", "raw": "user=u&password={{form}}"}}}]});
    let src = write_doc(&dir, "raw.json", &doc.to_string());
    let o = run(&p, &["import", "api", "--dry-run", "--", &src]);
    assert_eq!(o.code, 0, "{}", o.all);
    assert!(!o.all.contains("FAKE"), "{}", o.all);
    let d = &o.json["data"];
    let var = |n: &str| d["variables"].as_array().unwrap().iter().find(|v| v["name"] == n).unwrap().clone();
    for n in ["t", "pw", "form"] {
        assert_eq!((var(n)["secret"].as_bool(), var(n)["value"].is_null()), (Some(true), true), "{n}");
    }
    assert_eq!(var("n")["value"], "7");
    assert_eq!(var("base")["secret"], false);
    let o = run(&p, &["import", "api", "--", &src]);
    assert_eq!(o.code, 0, "{}", o.all);
    assert!(!o.all.contains("FAKE"), "{}", o.all);
    let hits = api.hits();
    assert_eq!(hits.len(), 2);
    for h in &hits {
        assert!(!h.head.contains("FAKE") && !h.body.contains("FAKE"), "{h:?}");
    }
    assert_absent_from_project(&p, &["FAKE"]);
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn a_variable_can_give_a_collection_its_address() {
    let (dir, p) = setup("postman-host", "127.0.0.1");
    let api = Api::start();
    let doc = json!({"info": {"name": "n"}, "variable": [{"key": "base", "value": ""}],
        "item": [{"name": "a", "request": {"method": "GET", "url": "{{base}}/a"}}]});
    let src = write_doc(&dir, "n.json", &doc.to_string());
    let d = preview(&p, &src, &[]);
    assert_eq!((d["base_url_required"].as_bool(), d["built"].as_u64()), (Some(true), Some(0)));
    assert_eq!(d["unresolved_variables"], json!(["base"]));
    let var = format!("--var=base={}", api.origin());
    let d = preview(&p, &src, &[&var]);
    assert_eq!(d["base_url_required"], false);
    assert_eq!(d["requests"][0]["url"], format!("{}/a", api.origin()));
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn parameters_get_test_values_and_bodies_their_examples() {
    let (dir, p) = setup("values", "127.0.0.1");
    let api = Api::start();
    let src = fixture(&dir, "openapi3.json", api.port);
    let d = preview(&p, &src, &[]);
    let (list, create) = (index_of(&d, "listPets"), index_of(&d, "createPet"));
    assert_eq!(d["requests"][list]["url"], format!("{}/v1/pets?limit=1&kind=dog", api.origin()));
    ok(&p, &["import", "api", &format!("--only={list},{create}"), "--", &src]);
    let hits = api.hits();
    let get = hits.iter().find(|h| h.method == "GET").unwrap();
    assert_eq!(get.target, "/v1/pets?limit=1&kind=dog", "a typed value, and an enum's first");
    let post = hits.iter().find(|h| h.method == "POST").unwrap();
    assert_eq!(post.body, r#"{"name":"rex","age":1}"#);
    assert_eq!(post.header("content-type"), Some("application/json"));

    // A document's own request body example, on the wire.
    let doc = json!({"openapi": "3.0.0", "servers": [{"url": api.origin()}], "paths": {"/form": {"post": {"requestBody":
        {"content": {"application/json": {"example": {"id": 5, "tags": ["a"]}}}}}}}});
    let doc = write_doc(&dir, "ex.json", &doc.to_string());
    ok(&p, &["import", "api", "--", &doc]);
    assert_eq!(api.hits().last().unwrap().body, r#"{"id":5,"tags":["a"]}"#);
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn malformed_documents_are_refused_without_quoting_them() {
    let (dir, p) = setup("malformed", "127.0.0.1");
    let src = fixture(&dir, "malformed.json", 1);
    let e = refused(&p, &["import", "api", "--dry-run", "--", &src], 2, "invalid_input");
    assert!(e.contains("not valid JSON or YAML") && e.contains("line 5"), "{e}");
    assert!(e.contains("accepted formats"), "{e}");
    assert!(!e.contains("FAKE"), "{e}");
    let arg = format!("--api={src}");
    let o = run(&p, &["scan", "active", &arg]);
    assert_eq!(o.code, 2, "{}", o.all);
    assert!(!o.all.contains("FAKE"), "{}", o.all);
    let other = write_doc(&dir, "other.json", r#"{"log": {"entries": []}}"#);
    let e = refused(&p, &["import", "api", "--dry-run", "--", &other], 2, "invalid_input");
    assert!(e.contains("HAR"), "{e}");
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn what_can_not_be_built_is_listed_with_its_reason() {
    let (dir, p) = setup("partial", "127.0.0.1");
    let api = Api::start();
    let src = fixture(&dir, "partial.yaml", api.port);
    let d = preview(&p, &src, &[]);
    assert_eq!(names(&d), ["good", "externalParam", "externalBody", "binary"]);
    assert_eq!(
        d["skipped"],
        json!([
            {"operation": "/external-item", "reason": "path item $ref \"other.yaml#/paths/item\" is external or broken"},
            {"operation": "GET no-leading-slash", "reason": "the path doesn't start with /"},
            {"operation": "GET /placeholder", "reason": "contains a reserved placeholder"},
            {"operation": "GET /bad-header", "reason": "invalid header \"X-Bad\\r\\nInjected\""},
        ])
    );
    let warnings: Vec<&str> = d["warnings"].as_array().unwrap().iter().map(|w| w.as_str().unwrap()).collect();
    assert!(warnings.contains(&"GET /external-param: external $ref \"other.yaml#/parameters/page\" is not followed"));
    assert!(warnings.contains(&"POST /external-body: external $ref \"other.yaml#/schemas/Thing\" is not followed"));
    assert!(
        warnings.contains(&"POST /binary: request body type \"application/octet-stream\" is sent as a stand-in value"),
        "{warnings:?}"
    );
    // What could be built still goes out, and nothing else.
    // A name only an IP target could allow isn't known until it resolves, and says so.
    let named = json!({"openapi": "3.0.0", "servers": [{"url": "http://named.test"}], "paths": {"/n": {"get": {}}}});
    let named = preview(&p, &write_doc(&dir, "named.json", &named.to_string()), &[]);
    assert_eq!((&named["hosts"][0]["in_scope"], &named["hosts"][0]["scope_confirmed"]), (&json!(true), &json!(false)));
    let d = ok(&p, &["import", "api", "--", &src]);
    assert_eq!(d["sent"], 4, "{d}");
    assert_eq!(d["skipped"].as_array().unwrap().len(), 4, "the real run reports them too");
    assert!(!api.hits().iter().any(|h| h.target.contains("placeholder") || h.head.contains("Injected")));
    let _ = std::fs::remove_dir_all(dir);
}

// --- What goes out ---

#[test]
fn hosts_out_of_scope_are_reported_not_sent() {
    let (dir, p) = setup("scope-ip", "127.0.0.1");
    let api = Api::start();
    let before = ok(&p, &["engagement", "show"]);
    let doc = json!({"openapi": "3.0.0", "servers": [{"url": api.origin()}], "paths": {
        "/in": {"get": {"operationId": "in"}},
        "/out": {"get": {"operationId": "out", "servers": [{"url": "http://198.51.100.9:81"}]}}}});
    let src = write_doc(&dir, "mixed.json", &doc.to_string());
    let d = preview(&p, &src, &[]);
    assert_eq!(included(&d), ["in"]);
    assert_eq!(row(&d, "out")["excluded_reason"], "scope");
    assert_eq!(row(&d, "out")["in_scope"], false);
    assert_eq!(
        d["hosts"],
        json!([
            {"host": "127.0.0.1", "port": api.port, "in_scope": true, "scope_confirmed": true},
            {"host": "198.51.100.9", "port": 81, "in_scope": false, "scope_confirmed": false},
        ])
    );
    let d = ok(&p, &["import", "api", "--", &src]);
    assert_eq!((d["sent"].as_u64(), d["skipped_out_of_scope"].as_u64()), (Some(1), Some(1)), "{d}");
    assert_eq!(d["out_of_scope_hosts"], json!(["198.51.100.9"]));
    assert_eq!(api.hits().len(), 1);

    let d = ok(&p, &["scan", "active", &format!("--api={src}"), "--rules", "40012", "--strength", "low"]);
    assert_eq!((d["import"]["sent"].as_u64(), d["import"]["skipped_out_of_scope"].as_u64()), (Some(1), Some(1)), "{d}");
    assert_eq!(d["import"]["out_of_scope_hosts"], json!(["198.51.100.9"]));

    // All of them out of scope: exit 6, nothing sent, by either command.
    let n = api.hits().len();
    let doc = json!({"openapi": "3.0.0", "servers": [{"url": "http://198.51.100.9:81"}], "paths": {"/a": {"get": {}}}});
    let out = write_doc(&dir, "out.json", &doc.to_string());
    let e = refused(&p, &["import", "api", "--", &out], 6, "out_of_scope");
    assert!(e.contains("198.51.100.9") && e.contains("nothing was sent"), "{e}");
    refused(&p, &["scan", "active", &format!("--api={out}")], 6, "out_of_scope");
    refused(&p, &["scan", "active", &format!("--api={out}"), "--background"], 6, "out_of_scope");
    assert_eq!(api.hits().len(), n);
    let hist = ok(&p, &["query", "SELECT count(*) FROM history WHERE url LIKE '%198.51.100.9%'"]);
    assert_eq!(hist["rows"][0][0], 0);
    assert_eq!(ok(&p, &["engagement", "show"]), before, "the engagement is never widened");
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn a_name_scope_refuses_other_names_up_front() {
    let (dir, p) = setup("scope-name", "localhost");
    let api = Api::start();
    let doc = json!({"openapi": "3.0.0", "servers": [{"url": format!("http://localhost:{}", api.port)}], "paths": {
        "/in": {"get": {"operationId": "in"}},
        "/out": {"get": {"operationId": "out", "servers": [{"url": "https://elsewhere.example.test"}]}}}});
    let src = write_doc(&dir, "mixed.json", &doc.to_string());
    let d = preview(&p, &src, &[]);
    assert_eq!((row(&d, "in")["in_scope"].as_bool(), row(&d, "out")["in_scope"].as_bool()), (Some(true), Some(false)));
    let d = ok(&p, &["import", "api", "--", &src]);
    assert_eq!((d["sent"].as_u64(), d["skipped_out_of_scope"].as_u64()), (Some(1), Some(1)), "{d}");
    assert_eq!(d["out_of_scope_hosts"], json!(["elsewhere.example.test"]));
    assert_eq!(api.hits().iter().map(|h| h.target.as_str()).collect::<Vec<_>>(), ["/in"]);
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn state_changing_methods_need_opting_in() {
    let (dir, p) = setup("methods", "127.0.0.1");
    let api = Api::start();
    let src = fixture(&dir, "openapi3.json", api.port);
    let d = preview(&p, &src, &[]);
    assert_eq!((d["built"].as_u64(), d["selected"].as_u64()), (Some(7), Some(4)));
    for name in ["updatePet", "patchPet", "deletePet"] {
        let r = row(&d, name);
        assert_eq!(r["state_changing"], true, "{name}");
        assert_eq!((r["included"].as_bool(), r["excluded_reason"].as_str()), (Some(false), Some("method")), "{name}");
    }
    assert_eq!(row(&d, "createPet")["state_changing"], false);

    let local = format!("--base-url={}", api.origin());
    let d = ok(&p, &["import", "api", &local, "--", &src]);
    assert_eq!(d["sent"], 4, "{d}");
    let methods = |api: &Api| {
        let mut m: Vec<String> = api.hits().iter().map(|h| h.method.clone()).collect();
        m.sort();
        m.dedup();
        m
    };
    assert_eq!(methods(&api), ["GET", "POST"]);

    let d = preview(&p, &src, &["--include-methods=PUT"]);
    assert_eq!(row(&d, "updatePet")["included"], true);
    assert_eq!(row(&d, "deletePet")["included"], false);
    ok(&p, &["import", "api", &local, "--include-methods=put", "--", &src]);
    assert_eq!(methods(&api), ["GET", "POST", "PUT"]);
    let d = preview(&p, &src, &["--include-destructive"]);
    assert_eq!(
        (row(&d, "deletePet")["included"].as_bool(), row(&d, "patchPet")["included"].as_bool()),
        (Some(true), Some(false))
    );
    let d = ok(&p, &["import", "api", &local, "--include-methods=all", "--", &src]);
    assert_eq!(d["sent"], 7, "{d}");
    assert_eq!(methods(&api), ["DELETE", "GET", "PATCH", "POST", "PUT"]);
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn only_picks_by_index_and_those_indexes_hold_past_the_limit() {
    let (dir, p) = setup("only", "127.0.0.1");
    let api = Api::start();
    let src = fixture(&dir, "openapi3.json", api.port);
    let d = preview(&p, &src, &[]);
    let (get, del) = (index_of(&d, "getPet"), index_of(&d, "deletePet"));
    let d = preview(&p, &src, &[&format!("--only={get}")]);
    assert_eq!(included(&d), ["getPet"]);
    assert_eq!(row(&d, "listPets")["excluded_reason"], "not_selected");
    assert_eq!(row(&d, "getPet")["index"].as_u64(), Some(get as u64));

    // --only doesn't get round the method filter.
    let only_del = format!("--only={del}");
    let e = refused(&p, &["import", "api", &only_del, "--", &src], 2, "invalid_input");
    assert!(e.contains("--include-methods"), "{e}");
    let e = refused(&p, &["import", "api", "--only=7", "--dry-run", "--", &src], 2, "invalid_input");
    assert!(e.contains("--only 7") && e.contains("7 request(s)"), "{e}");
    assert!(api.hits().is_empty());

    ok(&p, &["import", "api", &format!("--only={get}"), "--", &src]);
    assert_eq!(api.hits().iter().map(|h| h.target.as_str()).collect::<Vec<_>>(), ["/v1/pets/7"]);

    // More operations than the preview lists: the rest stay reachable at their own indexes.
    let mut paths = serde_json::Map::new();
    for i in 0..1200 {
        paths.insert(format!("/p/{i}"), json!({"get": {"operationId": format!("op{i}")}}));
    }
    let doc = json!({"openapi": "3.0.0", "servers": [{"url": api.origin()}], "paths": paths});
    let big = write_doc(&dir, "big.json", &doc.to_string());
    let d = preview(&p, &big, &[]);
    assert_eq!((d["built"].as_u64(), d["selected"].as_u64()), (Some(1200), Some(1200)));
    assert_eq!((d["requests_truncated"].as_bool(), d["requests"].as_array().unwrap().len()), (Some(true), 1000));
    assert_eq!((d["requests"][999]["index"].as_u64(), d["requests"][999]["name"].as_str()), (Some(999), Some("op999")));
    let d = ok(&p, &["import", "api", "--only=1100", "--", &big]);
    assert_eq!(d["requests"][0]["name"], "op1100");
    assert_eq!(d["built"], 1200);
    assert!(d.get("requests_truncated").is_some_and(|t| t == false), "{d}");
    assert!(api.hits().iter().any(|h| h.target == "/p/1100"));

    // A run says what --max-requests and --limit left out; a long --only is fine.
    let all: Vec<String> = (0..1000).map(|i| i.to_string()).collect();
    let n = api.hits().len();
    let only = format!("--only={}", all.join(","));
    let d = ok(&p, &["import", "api", &only, "--max-requests=2", "--limit=1", "--", &big]);
    assert_eq!((d["sent"].as_u64(), d["skipped_over_limit"].as_u64()), (Some(2), Some(998)), "{d}");
    assert_eq!((d["requests"].as_array().unwrap().len(), d["requests_truncated"].as_bool()), (1, Some(true)));
    assert_eq!(api.hits().len(), n + 2);
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn expected_sha256_proves_the_document() {
    let (dir, p) = setup("sha", "127.0.0.1");
    let api = Api::start();
    let src = fixture(&dir, "openapi3.json", api.port);
    let sha = preview(&p, &src, &[])["document_sha256"].as_str().unwrap().to_string();
    let good = format!("--expect-sha256={sha}");
    preview(&p, &src, &[&good]);
    preview(&p, &src, &[&format!("--expect-sha256={}", sha.to_uppercase())]);
    let wrong = format!("--expect-sha256={}", "0".repeat(64));
    let e = refused(&p, &["import", "api", &wrong, "--", &src], 2, "invalid_input");
    assert!(e.contains("changed") && e.contains(&sha), "{e}");
    let arg = format!("--api={src}");
    refused(&p, &["scan", "active", &arg, &wrong], 2, "invalid_input");
    refused(&p, &["scan", "active", &arg, &wrong, "--background"], 2, "invalid_input");
    assert!(api.hits().is_empty());
    let hist = ok(&p, &["query", "SELECT count(*) FROM history"]);
    assert_eq!(hist["rows"][0][0], 0);
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn a_dry_run_sends_nothing() {
    let (dir, p) = setup("dry", "127.0.0.1");
    let api = Api::start();
    for name in ["openapi3.json", "swagger2.json", "postman.json", "partial.yaml", "secrets.json"] {
        preview(&p, &fixture(&dir, name, api.port), &[]);
    }
    assert!(api.hits().is_empty(), "{:?}", api.hits());
    let hist = ok(&p, &["query", "SELECT count(*) FROM history"]);
    assert_eq!(hist["rows"][0][0], 0);
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn credentials_in_a_document_are_reported_and_never_used() {
    let (dir, p) = setup("secrets", "127.0.0.1");
    let api = Api::start();
    let src = fixture(&dir, "secrets.json", api.port);
    let o = run(&p, &["import", "api", "--dry-run", "--limit=1000", "--", &src]);
    assert_eq!(o.code, 0, "{}", o.all);
    assert!(!o.all.contains("FAKE"), "{}", o.all);
    let d = &o.json["data"];
    let cred = |at: Option<&str>, name: Option<&str>| {
        d["credentials"]
            .as_array()
            .unwrap()
            .iter()
            .find(|c| c["in"].as_str() == at && c["name"].as_str() == name)
            .cloned()
    };
    for (at, name) in [
        (Some("query"), "api_key"),
        (Some("header"), "X-Auth-Token"),
        (Some("cookie"), "session"),
        (None, "password"),
        (None, "apiKey"),
    ] {
        let c = cred(at, Some(name)).unwrap_or_else(|| panic!("{name} in {}", d["credentials"]));
        assert_eq!(c["embedded"], true, "{name}");
    }
    assert!(cred(None, None).is_some_and(|c| c["kind"] == "basic"), "the server's userinfo: {}", d["credentials"]);
    let r = &d["requests"][0];
    assert_eq!(r["url"], format!("{}/v1/things/1?limit=3", api.origin()), "the operation's path stays");
    assert_eq!(r["headers"], json!(["Content-Type: application/json"]));
    assert_eq!(r["body"]["content"], r#"{"name":"thing","password":"********","nested":{"apiKey":"********"}}"#);
    assert_eq!(d["servers"][0]["url"], format!("{}/v1", api.origin()));

    let o = run(&p, &["import", "api", "--", &src]);
    assert_eq!(o.code, 0, "{}", o.all);
    assert!(!o.all.contains("FAKE"), "{}", o.all);
    let hits = api.hits();
    assert_eq!(hits.len(), 1);
    assert_eq!(hits[0].target, "/v1/things/1?limit=3");
    assert_eq!(hits[0].body, r#"{"name":"thing","password":"test","nested":{"apiKey":"test"}}"#);
    assert!(!hits[0].head.contains("FAKE") && hits[0].header("cookie").is_none(), "{:?}", hits[0]);
    assert_absent_from_project(&p, &["FAKE"]);

    // The same through the scan, attacks and all.
    let arg = format!("--api={src}");
    let o = run(&p, &["scan", "active", &arg, "--rules", "40012", "--strength", "low"]);
    assert_eq!(o.code, 0, "{}", o.all);
    assert!(!o.all.contains("FAKE"), "{}", o.all);
    for h in api.hits() {
        assert!(!h.head.contains("FAKE") && !h.body.contains("FAKE"), "{h:?}");
    }
    assert_absent_from_project(&p, &["FAKE"]);
    let _ = std::fs::remove_dir_all(dir);
}

// --- scan active --api ---

#[test]
fn a_scan_sends_baselines_then_attacks_only_those() {
    let (dir, p) = setup("scan", "127.0.0.1");
    let api = Api::start();
    let src = fixture(&dir, "openapi3.json", api.port);
    // Already in history, so a scan that took everything would attack it.
    ok(&p, &["send", "--url", &format!("{}/unrelated?x=1", api.origin())]);
    let d = preview(&p, &src, &[]);
    let (list, create, put) = (index_of(&d, "listPets"), index_of(&d, "createPet"), index_of(&d, "updatePet"));
    let start = api.hits().len();
    let arg = format!("--api={src}");
    let only = format!("--only={list},{create},{put}");
    let r = ok(
        &p,
        &["scan", "active", &arg, &only, "--include-methods=PUT", "--rules", "30001,30002", "--strength", "low"],
    );
    assert_eq!(r["targets"], 3, "{r}");
    let i = &r["import"];
    assert_eq!(i["format"], "openapi3");
    assert_eq!((i["built"].as_u64(), i["selected"].as_u64(), i["sent"].as_u64()), (Some(7), Some(3), Some(3)), "{r}");
    assert_eq!(i["by_status"], json!({"200": 3}));
    assert_eq!((i["errors"].as_u64(), i["skipped_out_of_scope"].as_u64()), (Some(0), Some(0)));
    for k in ["skipped", "warnings", "credentials", "out_of_scope_hosts"] {
        assert!(i[k].is_array(), "{k}: {i}");
    }
    assert_eq!(i["credentials"][0]["name"], "X-Api-Key");
    assert!(r.get("targets_dropped").is_none(), "{r}");

    // First the baselines, as written; then attacks on them, and on nothing else.
    let hits: Vec<Hit> = api.hits().split_off(start);
    assert!(hits.len() > 3, "the attacks went out: {hits:?}");
    let mut first: Vec<String> = hits[..3].iter().map(|h| format!("{} {}", h.method, h.target)).collect();
    first.sort();
    assert_eq!(first, ["GET /v1/pets?limit=1&kind=dog", "POST /v1/pets", "PUT /v1/pets/7"]);
    for h in &hits {
        assert!(!h.target.contains("unrelated"), "{h:?}");
        assert!(matches!(h.path(), "/v1/pets" | "/v1/pets/7"), "{h:?}");
    }
    assert!(
        hits[3..].iter().any(|h| h.body != r#"{"name":"rex","age":1}"# && h.method == "PUT"),
        "the PUT was attacked"
    );
    assert!(!hits.iter().any(|h| h.method == "DELETE"));
    let q = ok(&p, &["query", "SELECT source, count(*) FROM history WHERE source = 'import' GROUP BY source"]);
    assert_eq!(q["rows"][0][1], 3);
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn a_cap_on_targets_is_reported_and_nothing_selected_is_refused() {
    let (dir, p) = setup("targets", "127.0.0.1");
    let api = Api::start();
    let src = fixture(&dir, "openapi3.json", api.port);
    let arg = format!("--api={src}");
    let base = format!("--base-url={}", api.origin());
    let r = ok(&p, &["scan", "active", &arg, &base, "--max-targets=1", "--rules", "40012", "--strength", "low"]);
    assert_eq!(r["targets"], 1, "{r}");
    assert_eq!(r["import"]["sent"], 4, "{r}");
    assert_eq!(r["targets_dropped"], 3, "{r}");

    // More operations than the usual default of 200 targets aren't cut.
    let mut paths = serde_json::Map::new();
    for i in 0..205 {
        paths.insert(format!("/p/{i}"), json!({"get": {}}));
    }
    let doc = json!({"openapi": "3.0.0", "servers": [{"url": api.origin()}], "paths": paths});
    let big = format!("--api={}", write_doc(&dir, "big.json", &doc.to_string()));
    let r = ok(&p, &["scan", "active", &big, "--rules", "40012", "--strength", "low"]);
    assert_eq!((r["targets"].as_u64(), r["import"]["sent"].as_u64()), (Some(205), Some(205)), "{r}");
    assert!(r.get("targets_dropped").is_none(), "{r}");

    let e = refused(&p, &["scan", "active", &arg, "--only=4"], 2, "invalid_input");
    assert!(e.contains("--include-methods"), "{e}");
    let e = refused(
        &p,
        &["scan", "active", &arg, "--base-url=http://u:FAKE-PW@127.0.0.1:1", "--background"],
        2,
        "invalid_input",
    );
    assert!(!e.contains("FAKE"), "{e}");
    assert_absent_from_project(&p, &["FAKE-PW"]);
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn baselines_with_no_response_are_counted_and_not_scanned() {
    let (dir, p) = setup("no-response", "127.0.0.1");
    let api = Api::start();
    // A port nothing listens on: taken, then released.
    let closed = TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port();
    let doc = json!({"openapi": "3.0.0", "servers": [{"url": api.origin()}], "paths": {
        "/up": {"get": {"operationId": "up", "parameters": [{"name": "q", "in": "query", "example": "a"}]}},
        "/down": {"get": {"operationId": "down", "servers": [{"url": format!("http://127.0.0.1:{closed}")}]}}}});
    let src = write_doc(&dir, "d.json", &doc.to_string());
    let arg = format!("--api={src}");
    let r = ok(&p, &["scan", "active", &arg, "--rules", "40012", "--strength", "low"]);
    assert_eq!(r["targets"], 1, "{r}");
    assert_eq!((r["import"]["sent"].as_u64(), r["import"]["errors"].as_u64()), (Some(2), Some(1)), "{r}");
    assert_eq!(r["import"]["by_status"]["error"], 1, "{r}");

    let doc = json!({"openapi": "3.0.0", "servers": [{"url": format!("http://127.0.0.1:{closed}")}], "paths": {"/a": {"get": {}}}});
    let dead = format!("--api={}", write_doc(&dir, "dead.json", &doc.to_string()));
    let o = run(&p, &["scan", "active", &dead]);
    assert_eq!(o.code, 3, "{}", o.all);
    assert!(o.json["error"]["message"].as_str().unwrap().contains("nothing to scan"), "{}", o.all);
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn a_scan_warns_about_posts() {
    let (dir, p) = setup("post", "127.0.0.1");
    let api = Api::start();
    let src = fixture(&dir, "openapi3.json", api.port);
    let d = preview(&p, &src, &[]);
    let (list, create) = (index_of(&d, "listPets"), index_of(&d, "createPet"));
    let arg = format!("--api={src}");
    let both = format!("--only={list},{create}");
    let scan = ["scan", "active", &arg, &both, "--rules", "40012", "--strength", "low"];
    let r = ok(&p, &scan);
    assert_eq!(r["post_targets"], 1, "{r}");
    assert!(r["post_hint"].as_str().unwrap().contains("POST requests are replayed"), "{r}");
    let o = command(&p, &scan, &[], "text");
    assert_eq!(o.code, 0, "{}", o.all);
    assert!(o.all.contains("warning: 1 POST target(s)"), "{}", o.all);

    let only_get = format!("--only={list}");
    let r = ok(&p, &["scan", "active", &arg, &only_get, "--rules", "40012", "--strength", "low"]);
    assert!(r.get("post_targets").is_none(), "{r}");
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn background_jobs_read_the_file_where_they_were_started_and_report_progress() {
    let (dir, p) = setup("background", "127.0.0.1");
    let api = Api::start();
    fixture(&dir, "openapi3.json", api.port);
    let run_in = |args: &[&str]| {
        let mut c = Command::new(env!("CARGO_BIN_EXE_brainproxy"));
        let out = c.current_dir(&dir).args(["--format", "json", "--project"]).arg(&p).args(args).output().unwrap();
        (out.status.code().unwrap(), serde_json::from_slice::<Value>(&out.stdout).unwrap_or_default())
    };
    let (code, v) = run_in(&[
        "scan",
        "active",
        "--api=openapi3.json",
        "--background",
        "--base-url",
        &api.origin(),
        "--rules",
        "40012",
        "--strength",
        "low",
    ]);
    assert_eq!(code, 0, "{v}");
    let job = v["data"]["job"].as_i64().unwrap().to_string();
    ok(&p, &["job", "wait", &job, "--timeout", "120"]);
    let j = ok(&p, &["job", "status", &job]);
    assert_eq!(j["state"], "completed", "{j}");
    assert_eq!(j["result"]["import"]["sent"], 4, "{j}");
    let args: Vec<&str> = j["args"].as_array().unwrap().iter().map(|a| a.as_str().unwrap()).collect();
    assert!(args.contains(&"--api=openapi3.json"), "{args:?}");

    // A problem with a local file comes back at once, not in a failed job.
    let jobs = ok(&p, &["job", "list"])["jobs"].as_array().unwrap().len();
    let (code, v) = run_in(&["scan", "active", "--api=missing.yaml", "--background"]);
    assert_eq!((code, v["error"]["kind"].as_str()), (2, Some("invalid_input")), "{v}");
    let (code, v) = run_in(&["import", "api", "--background", "--", "missing.yaml"]);
    assert_eq!((code, v["error"]["kind"].as_str()), (2, Some("invalid_input")), "{v}");
    let (code, v) = run_in(&["import", "api", "--background", "-H", "Authorization: FAKE-H", "--", "openapi3.json"]);
    assert_eq!((code, v["error"]["kind"].as_str()), (2, Some("invalid_input")), "{v}");
    assert!(!v.to_string().contains("FAKE"), "{v}");
    assert_eq!(ok(&p, &["job", "list"])["jobs"].as_array().unwrap().len(), jobs);
    assert_absent_from_project(&p, &["FAKE-H"]);

    // `import api` as a job, reading the file relative to the same directory.
    let n = api.hits().len();
    let (code, v) = run_in(&["import", "api", "--background", "--base-url", &api.origin(), "--", "openapi3.json"]);
    assert_eq!(code, 0, "{v}");
    let job = v["data"]["job"].as_i64().unwrap().to_string();
    ok(&p, &["job", "wait", &job, "--timeout", "60"]);
    assert_eq!(ok(&p, &["job", "status", &job])["result"]["sent"], 4);
    assert_eq!(api.hits().len(), n + 4);
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn a_changed_file_fails_a_job_started_with_its_hash() {
    let (dir, p) = setup("changed", "127.0.0.1");
    let api = Api::start();
    let src = fixture(&dir, "openapi3.yaml", api.port);
    let sha = preview(&p, &src, &[])["document_sha256"].as_str().unwrap().to_string();
    std::fs::write(&src, std::fs::read_to_string(&src).unwrap() + "\n# changed\n").unwrap();
    let arg = format!("--api={src}");
    let e =
        refused(&p, &["scan", "active", &arg, &format!("--expect-sha256={sha}"), "--background"], 2, "invalid_input");
    assert!(e.contains("changed"), "{e}");
    assert!(api.hits().is_empty());
    let _ = std::fs::remove_dir_all(dir);
}

// --- API keys ---

/// No output of the commands that show a profile holds the key, and the mask is there.
fn assert_key_redacted(p: &Path, profile: &str) {
    for args in [vec!["auth", "show", profile], vec!["auth", "list"]] {
        let o = run(p, &args);
        assert_eq!(o.code, 0, "{}", o.all);
        assert!(!o.all.contains(API_KEY), "{args:?}: {}", o.all);
    }
    assert!(run(p, &["auth", "show", profile]).all.contains("********"));
}

#[test]
fn a_key_in_a_header_comes_from_the_environment() {
    let (dir, p) = setup("header-key", "127.0.0.1");
    let api = Api::start();
    let src = fixture(&dir, "openapi3.json", api.port);
    let add = |env: &[(&str, &str)], name: &str| {
        command(&p, &["auth", "add", &format!("--header-env=X-Api-Key={KEY_ENV}"), "--", name], env, "json")
    };
    // Unset and empty name the variable. The key never appears, nor is it needed on the command line.
    let o = add(&[], "k");
    assert_eq!((o.code, o.json["error"]["kind"].as_str()), (2, Some("invalid_input")), "{}", o.all);
    assert!(o.all.contains(KEY_ENV) && o.all.contains("not set"), "{}", o.all);
    let o = add(&[(KEY_ENV, "   ")], "k");
    assert_eq!(o.code, 2, "{}", o.all);
    assert!(o.all.contains("empty"), "{}", o.all);
    let o = add(&[(KEY_ENV, "FAKE\r\nInjected: 1")], "k");
    assert_eq!(o.code, 2, "{}", o.all);
    assert!(!o.all.contains("FAKE"), "{}", o.all);
    assert_eq!(ok(&p, &["auth", "list"])["profiles"], json!([]));

    let o = add(&[(KEY_ENV, API_KEY)], "k");
    assert_eq!(o.code, 0, "{}", o.all);
    assert!(!o.all.contains(API_KEY), "{}", o.all);
    assert_key_redacted(&p, "k");

    let d = preview(&p, &src, &[]);
    let (list, create) = (index_of(&d, "listPets"), index_of(&d, "createPet"));
    let o = run(&p, &["import", "api", &format!("--only={list}"), "--auth=k", "--", &src]);
    assert_eq!(o.code, 0, "{}", o.all);
    assert!(!o.all.contains(API_KEY), "{}", o.all);
    assert_eq!(api.hits()[0].header("x-api-key"), Some(API_KEY));
    let id = o.json["data"]["requests"][0]["history_id"].as_i64().unwrap().to_string();
    let shown = ok(&p, &["history", "show", &id]);
    let raw = shown["request"]["content"].as_str().unwrap();
    assert!(raw.contains("«auth:k:header:X-Api-Key»"), "{raw}");

    let arg = format!("--api={src}");
    let only = format!("--only={list},{create}");
    let o = run(&p, &["scan", "active", &arg, &only, "--auth=k", "--rules", "40012", "--strength", "low"]);
    assert_eq!(o.code, 0, "{}", o.all);
    assert!(!o.all.contains(API_KEY), "{}", o.all);
    assert!(api.hits().iter().all(|h| h.header("x-api-key") == Some(API_KEY)), "{:?}", api.hits());
    assert_absent_from_project(&p, &[API_KEY]);

    // A bearer token is the same thing, with its word in the value.
    let bearer = format!("Bearer {API_KEY}");
    let o = command(
        &p,
        &["auth", "add", &format!("--header-env=Authorization={KEY_ENV}"), "--", "b"],
        &[(KEY_ENV, &bearer)],
        "json",
    );
    assert_eq!(o.code, 0, "{}", o.all);
    ok(&p, &["import", "api", &format!("--only={list}"), "--auth=b", "--", &src]);
    assert_eq!(api.hits().last().unwrap().header("authorization"), Some(bearer.as_str()));
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn a_key_in_the_query_stays_on_the_wire_and_on_its_origins() {
    let (dir, p) = setup("query-key", "127.0.0.1");
    let api = Api::start();
    let other = Api::start();
    let doc = json!({"openapi": "3.0.0", "servers": [{"url": api.origin()}], "paths": {
        "/a": {"get": {"operationId": "a", "parameters": [
            {"name": "q", "in": "query", "schema": {"type": "string"}},
            {"name": "api_key", "in": "query", "example": "FAKE-DOCUMENT-KEY"}]}},
        "/b": {"get": {"operationId": "b", "servers": [{"url": other.origin()}],
            "parameters": [{"name": "q", "in": "query", "schema": {"type": "string"}}]}}}});
    let src = write_doc(&dir, "q.json", &doc.to_string());

    // Both flags or neither; a name that would mean something in a query is refused.
    let key = format!("--query-key=api_key={KEY_ENV}");
    let o = command(&p, &["auth", "add", &key, "--", "x"], &[(KEY_ENV, API_KEY)], "json");
    assert_eq!(o.code, 2, "{}", o.all);
    let origin = format!("--key-origin={}", api.origin());
    let bad = format!("--query-key=a&b={KEY_ENV}");
    let o = command(&p, &["auth", "add", &bad, &origin, "--", "x"], &[(KEY_ENV, API_KEY)], "json");
    assert_eq!(o.code, 2, "{}", o.all);
    let o = command(&p, &["auth", "add", &key, &origin, "--", "k"], &[], "json");
    assert_eq!(o.code, 2, "{}", o.all);
    assert!(o.all.contains(KEY_ENV), "{}", o.all);

    let o = command(&p, &["auth", "add", &key, &origin, "--", "k"], &[(KEY_ENV, API_KEY)], "json");
    assert_eq!(o.code, 0, "{}", o.all);
    assert!(!o.all.contains(API_KEY), "{}", o.all);
    assert_key_redacted(&p, "k");

    let o = run(&p, &["import", "api", "--auth=k", "--", &src]);
    assert_eq!(o.code, 0, "{}", o.all);
    assert!(!o.all.contains(API_KEY), "{}", o.all);
    let want = format!("/a?q=test&api_key={API_KEY}");
    assert_eq!(api.hits()[0].target, want, "the document's own key isn't there");
    assert_eq!(other.hits()[0].target, "/b?q=test", "another origin gets no key");

    // History has the placeholder.
    let q = ok(&p, &["query", "SELECT url, CAST(request AS TEXT) FROM history WHERE url LIKE '%/a?%'"]);
    assert!(q["rows"][0][0].as_str().unwrap().contains("api_key=«auth:k:query:api_key»"), "{q}");
    assert!(q["rows"][0][1].as_str().unwrap().contains("api_key=«auth:k:query:api_key» HTTP/1.1"), "{q}");

    // In a scan: every request has the key as it is, so it wasn't a point of attack, and q was.
    let arg = format!("--api={src}");
    let o = run(&p, &["scan", "active", &arg, "--auth=k", "--rules", "40012", "--strength", "low"]);
    assert_eq!(o.code, 0, "{}", o.all);
    assert!(!o.all.contains(API_KEY), "{}", o.all);
    let suffix = format!("api_key={API_KEY}");
    let hits = api.hits();
    assert!(hits.len() > 2, "the attacks went out: {hits:?}");
    assert!(hits.iter().any(|h| !h.target.contains("q=test&")), "q was attacked: {hits:?}");
    for h in &hits {
        let keys: Vec<&str> = h.target.split(['?', '&']).filter(|p| p.starts_with("api_key=")).collect();
        assert_eq!(keys, [suffix.as_str()], "{}", h.target);
    }
    for h in other.hits() {
        assert!(!h.target.contains("api_key"), "{}", h.target);
    }
    assert_absent_from_project(&p, &[API_KEY, "FAKE-DOCUMENT-KEY"]);

    // A key's value is encoded for the query.
    let raw = "FAKE a&b=c";
    let o = command(&p, &["auth", "add", &key, &origin, "--", "enc"], &[(KEY_ENV, raw)], "json");
    assert_eq!(o.code, 0, "{}", o.all);
    ok(&p, &["import", "api", "--only=0", "--auth=enc", "--", &src]);
    assert_eq!(api.hits().last().unwrap().target, "/a?q=test&api_key=FAKE+a%26b%3Dc");

    // A failure doesn't quote the key either.
    let closed = TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port();
    let dead_origin = format!("--key-origin=http://127.0.0.1:{closed}");
    let o = command(&p, &["auth", "add", &key, &dead_origin, "--", "dead"], &[(KEY_ENV, API_KEY)], "json");
    assert_eq!(o.code, 0, "{}", o.all);
    let doc = json!({"openapi": "3.0.0", "servers": [{"url": format!("http://127.0.0.1:{closed}")}], "paths": {"/a": {"get": {}}}});
    let dead = write_doc(&dir, "dead.json", &doc.to_string());
    let o = run(&p, &["import", "api", "--auth=dead", "--", &dead]);
    assert_eq!(o.code, 0, "{}", o.all);
    assert_eq!(o.json["data"]["errors"], 1, "{}", o.all);
    assert!(!o.all.contains(API_KEY), "{}", o.all);
    assert_absent_from_project(&p, &[API_KEY]);
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn replacing_a_profile_keeps_signers_and_rules_but_not_keys() {
    let (dir, p) = setup("replace", "127.0.0.1");
    let api = Api::start();
    let origin = api.origin();
    let key = format!("--query-key=api_key={KEY_ENV}");
    let at = format!("--key-origin={origin}");
    let o = command(&p, &["auth", "add", &key, &at, "--", "k"], &[(KEY_ENV, API_KEY)], "json");
    assert_eq!(o.code, 0, "{}", o.all);
    ok(
        &p,
        &[
            "auth",
            "sign",
            "add",
            "k",
            "hm",
            "--secret-env",
            "SIGN_KEY",
            "--origin",
            &origin,
            "--to",
            "header:X-Signature",
            "--canonical",
            "{{method}}",
        ],
    );
    ok(&p, &["auth", "rule", "add", "k", "--action", "sign:hm"]);

    // `auth add` on a name in use replaces the profile's own fields only.
    let o = command(
        &p,
        &["auth", "add", &format!("--header-env=X-Other={KEY_ENV}"), "--", "k"],
        &[(KEY_ENV, API_KEY)],
        "json",
    );
    assert_eq!(o.code, 0, "{}", o.all);
    let shown = ok(&p, &["auth", "show", "k"]);
    assert_eq!(shown["signers"][0]["name"], "hm", "{shown}");
    assert_eq!(shown["rules"].as_array().unwrap().len(), 1, "{shown}");
    assert!(shown["profile"].get("query_keys").is_none(), "{shown}");
    assert_eq!(shown["profile"]["headers"][0][0], "X-Other");

    // The Settings form re-saves a profile without showing its query keys, and asks to keep them.
    let o = command(&p, &["auth", "add", &key, &at, "--", "k2"], &[(KEY_ENV, API_KEY)], "json");
    assert_eq!(o.code, 0, "{}", o.all);
    ok(&p, &["auth", "add", "--keep-query-keys", "--", "k2"]);
    let doc = json!({"openapi": "3.0.0", "servers": [{"url": origin}], "paths": {"/a": {"get": {}}}});
    let src = write_doc(&dir, "a.json", &doc.to_string());
    ok(&p, &["import", "api", "--auth=k2", "--", &src]);
    assert_eq!(api.hits().last().unwrap().target, format!("/a?api_key={API_KEY}"));
    // With nothing to keep, a new profile still needs something in it.
    refused(&p, &["auth", "add", "--keep-query-keys", "--", "empty"], 2, "invalid_input");
    let _ = std::fs::remove_dir_all(dir);
}

// --- Signing ---

#[test]
fn a_signer_signs_a_scans_baselines_and_attacks() {
    let (dir, p) = setup("signer", "127.0.0.1");
    let api = Api::with(None, true);
    let origin = api.origin();
    let src = fixture(&dir, "openapi3.json", api.port);
    let arg = format!("--api={src}");
    let base = format!("--base-url={origin}");
    let d = preview(&p, &src, &[]);
    let list = index_of(&d, "listPets");
    let only = format!("--only={list}");
    let scan = ["scan", "active", &arg, &base, &only, "--rules", "40012", "--strength", "low"];

    // Unsigned: refused, and the result says so.
    let r = ok(&p, &scan);
    assert_eq!(r["import"]["by_status"], json!({"401": 1}), "{r}");
    assert!(api.hits().iter().all(|h| h.header("x-signature").is_none()));

    // A rule for the scan tool alone is enough for a scan.
    let canonical = r"{{method}}\n{{path}}\n{{query}}";
    ok(
        &p,
        &[
            "auth",
            "sign",
            "add",
            "api",
            "hm",
            "--secret-env",
            "SIGN_KEY",
            "--origin",
            &origin,
            "--to",
            "header:X-Signature",
            "--canonical",
            canonical,
        ],
    );
    ok(&p, &["auth", "rule", "add", "api", "--tool", "scan", "--action", "sign:hm"]);
    let start = api.hits().len();
    let with_auth: Vec<&str> = scan.iter().copied().chain(["--auth=api"]).collect();
    let o = run(&p, &with_auth);
    assert_eq!(o.code, 0, "{}", o.all);
    assert!(!o.all.contains(HMAC_KEY), "{}", o.all);
    assert_eq!(o.json["data"]["import"]["by_status"], json!({"200": 1}), "{}", o.all);
    let hits = api.hits().split_off(start);
    assert!(hits.len() > 1, "{hits:?}");
    assert!(hits.iter().all(signature_good), "{hits:?}");

    // `import api` counts as crawl traffic, so that rule doesn't apply to the GUI's check.
    let o = run(&p, &["import", "api", &base, &only, "--auth=api", "--max-requests=1", "--", &src]);
    assert_eq!(o.code, 0, "{}", o.all);
    assert_eq!(o.json["data"]["by_status"], json!({"401": 1}), "{}", o.all);
    let id = o.json["data"]["requests"][0]["history_id"].as_i64().unwrap().to_string();
    let shown = ok(&p, &["history", "show", &id]);
    assert!(!shown["request"]["content"].as_str().unwrap().contains("«auth:api:sign:hm"), "{shown}");

    // A rule for every tool does.
    ok(&p, &["auth", "rule", "add", "api", "--action", "sign:hm"]);
    let o = run(&p, &["import", "api", &base, &only, "--auth=api", "--max-requests=1", "--", &src]);
    assert_eq!(o.json["data"]["by_status"], json!({"200": 1}), "{}", o.all);
    let id = o.json["data"]["requests"][0]["history_id"].as_i64().unwrap().to_string();
    let shown = ok(&p, &["history", "show", &id]);
    assert!(shown["request"]["content"].as_str().unwrap().contains("«auth:api:sign:hm"), "{shown}");
    assert_absent_from_project(&p, &[HMAC_KEY]);
    let _ = std::fs::remove_dir_all(dir);
}

// --- Hostile documents ---

#[test]
fn hostile_documents_are_contained() {
    let (dir, p) = setup("hostile", "127.0.0.1");
    let api = Api::start();
    let origin = api.origin();
    let server = json!([{"url": origin}]);
    let body_ref = |r: &str| json!({"content": {"application/json": {"schema": {"$ref": r}}}});

    // A long chain of references.
    let mut schemas = serde_json::Map::new();
    for i in 0..100_000 {
        schemas.insert(format!("a{i}"), json!({"$ref": format!("#/components/schemas/a{}", i + 1)}));
    }
    schemas.insert("a100000".into(), json!({"type": "string"}));
    let doc = json!({"openapi": "3.0.0", "servers": server, "components": {"schemas": schemas},
        "paths": {"/a": {"post": {"requestBody": body_ref("#/components/schemas/a0")}}}});
    let d = preview(&p, &write_doc(&dir, "chain.json", &doc.to_string()), &[]);
    assert_eq!(d["built"], 1, "{}", d["skipped"]);

    // Wide schemas that refer to each other: billions of values if followed in full.
    let mut schemas = serde_json::Map::new();
    for i in 0..8 {
        let props: serde_json::Map<String, Value> =
            (0..300).map(|k| (format!("p{k}"), json!({"$ref": format!("#/components/schemas/s{}", i + 1)}))).collect();
        schemas.insert(format!("s{i}"), json!({"type": "object", "properties": props}));
    }
    schemas.insert("s8".into(), json!({"type": "string"}));
    let doc = json!({"openapi": "3.0.0", "servers": server, "components": {"schemas": schemas},
        "paths": {"/a": {"post": {"requestBody": body_ref("#/components/schemas/s0")}}}});
    let d = preview(&p, &write_doc(&dir, "fan.json", &doc.to_string()), &["--max-body=10"]);
    assert_eq!(d["built"], 1, "{}", d["skipped"]);
    assert!(d["requests"][0]["body"]["length"].as_u64().unwrap() < 1 << 20, "{}", d["requests"][0]["body"]);

    // A variable repeated far beyond what it should take in memory.
    let doc = json!({"info": {"name": "v"}, "variable": [{"key": "a", "value": "x".repeat(1 << 20)}],
        "item": [{"name": "b", "request": {"method": "POST", "url": format!("{origin}/b"),
            "body": {"mode": "raw", "raw": "{{a}}".repeat(100_000)}}}]});
    let d = preview(&p, &write_doc(&dir, "vars.json", &doc.to_string()), &["--max-body=10"]);
    assert_eq!(d["built"], 1, "{}", d["skipped"]);
    assert!(d["requests"][0]["body"]["length"].as_u64().unwrap() <= (33 << 20), "{}", d["requests"][0]["body"]);
    assert!(d["warnings"].to_string().contains("{{a}} stays unresolved in the body"), "{}", d["warnings"]);

    // One large example, used by many operations.
    let mut paths = serde_json::Map::new();
    for i in 0..200 {
        paths.insert(
            format!("/p/{i}"),
            json!({"post": {"requestBody": {"content": {"text/plain":
            {"schema": {"$ref": "#/components/schemas/big"}}}}}}),
        );
    }
    let doc = json!({"openapi": "3.0.0", "servers": server, "paths": paths,
        "components": {"schemas": {"big": {"type": "string", "example": "y".repeat(1 << 20)}}}});
    let d = preview(&p, &write_doc(&dir, "repeat.json", &doc.to_string()), &["--max-body=10"]);
    assert_eq!(d["built"], 63, "{}", d["built"]);
    assert_eq!(d["skipped"].as_array().unwrap().len(), 137);
    assert_eq!(d["skipped"][0]["reason"], "the document's requests add up to more than 64 MiB");

    // Too deep to parse, and too large to read.
    let deep = format!(r#"{{"openapi": "3.0.0", "x": {}{}}}"#, "[".repeat(100_000), "]".repeat(100_000));
    let e =
        refused(&p, &["import", "api", "--dry-run", "--", &write_doc(&dir, "deep.json", &deep)], 2, "invalid_input");
    assert!(e.contains("not valid JSON or YAML"), "{e}");
    let deep = format!("openapi: 3.0.0\nx: {}{}\n", "[".repeat(100_000), "]".repeat(100_000));
    let e =
        refused(&p, &["import", "api", "--dry-run", "--", &write_doc(&dir, "deep.yaml", &deep)], 2, "invalid_input");
    assert!(e.contains("not valid JSON or YAML"), "{e}");
    let huge = format!(r#"{{"openapi": "3.0.0", "x": "{}"}}"#, "z".repeat(33 << 20));
    let e =
        refused(&p, &["import", "api", "--dry-run", "--", &write_doc(&dir, "huge.json", &huge)], 2, "invalid_input");
    assert!(e.contains("larger than 32 MiB"), "{e}");
    let _ = std::fs::remove_file(dir.join("huge.json"));

    // The auth placeholder, however it's written and wherever it is: it can't pull a value from the vault.
    let o = command(
        &p,
        &["auth", "add", &format!("--header-env=X-Api-Key={KEY_ENV}"), "--", "victim"],
        &[(KEY_ENV, API_KEY)],
        "json",
    );
    assert_eq!(o.code, 0, "{}", o.all);
    let mark = "«auth:victim:header:X-Api-Key»";
    let doc = json!({"openapi": "3.0.0", "servers": server, "components": {"parameters":
            {"M": {"name": "m", "in": "query", "example": mark}}},
        "paths": {
        "/query": {"get": {"parameters": [{"name": "q", "in": "query", "example": mark}]}},
        "/ref": {"get": {"parameters": [{"$ref": "#/components/parameters/M"}]}},
        "/header": {"get": {"parameters": [{"name": "X-Api-Key-Echo", "in": "header", "example": mark}]}},
        "/id": {"get": {"operationId": mark}},
        "/body": {"post": {"requestBody": {"content": {"application/json": {"example": {"a": mark}}}}}},
        "/encoded": {"get": {"servers": [{"url": format!("{origin}/%C2%ABauth:victim:header:X-Api-Key%C2%BB")}]}},
        "/clean": {"get": {"operationId": "clean"}}}});
    let src = write_doc(&dir, "marks.json", &doc.to_string());
    let d = preview(&p, &src, &[]);
    assert_eq!(names(&d), ["clean"], "{}", d["skipped"]);
    assert_eq!(d["skipped"].as_array().unwrap().len(), 6, "{}", d["skipped"]);
    assert!(d["skipped"].as_array().unwrap().iter().all(|s| s["reason"] == "contains a reserved placeholder"), "{d}");
    let doc = json!({"info": {"name": "m"}, "variable": [{"key": "v", "value": mark}], "item": [
        {"name": "url", "request": {"url": format!("{origin}/{{{{v}}}}")}},
        {"name": "description", "request": {"url": format!("{origin}/x"), "description": mark}},
        {"name": "clean", "request": {"url": format!("{origin}/clean")}}]});
    let pm = write_doc(&dir, "marks-pm.json", &doc.to_string());
    let d = preview(&p, &pm, &[]);
    assert_eq!(names(&d), ["clean"], "{}", d["skipped"]);
    let var = format!("--var=x={mark}");
    let d = preview(&p, &pm, &[&var]);
    assert_eq!(names(&d), ["clean"], "{}", d["skipped"]);
    ok(&p, &["import", "api", "--auth=victim", "--", &src]);
    ok(&p, &["import", "api", "--auth=victim", "--", &pm]);
    let hits = api.hits();
    assert_eq!(hits.iter().map(|h| h.target.as_str()).collect::<Vec<_>>(), ["/clean", "/clean"]);
    assert!(hits.iter().all(|h| h.header("x-api-key") == Some(API_KEY)), "the profile's own use still works");

    // Line breaks in names can't add to a request.
    let doc = json!({"info": {"name": "c"}, "item": [
        {"name": "method", "request": {"method": "GET\r\nX-Injected: 1", "url": format!("{origin}/a")}},
        {"name": "header", "request": {"url": format!("{origin}/a"), "header": [{"key": "X\r\nX-Injected", "value": "1"}]}},
        {"name": "value", "request": {"url": format!("{origin}/a"), "header": [{"key": "X-A", "value": "1\r\nX-Injected: 1"}]}},
        {"name": "url", "request": {"url": format!("{origin}/clean\r\nX-Injected: 1")}},
        {"name": "item\r\nname", "request": {"url": format!("{origin}/fine")}}]});
    let src = write_doc(&dir, "crlf.json", &doc.to_string());
    let n = api.hits().len();
    let d = ok(&p, &["import", "api", "--", &src]);
    assert_eq!(d["skipped"].as_array().unwrap().len(), 3, "{d}");
    assert_eq!(d["sent"], 2, "{d}");
    for h in &api.hits()[n..] {
        assert!(!h.head.to_ascii_lowercase().contains("\r\nx-injected"), "{h:?}");
    }
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn indexes_hold_across_a_preview_and_a_run_of_the_same_options() {
    let (dir, p) = setup("stable", "127.0.0.1");
    let api = Api::start();
    let src = fixture(&dir, "partial.yaml", api.port);
    let d = preview(&p, &src, &[]);
    let by_index: HashMap<u64, String> = d["requests"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| (r["index"].as_u64().unwrap(), r["name"].as_str().unwrap().to_string()))
        .collect();
    assert_eq!(by_index.len(), 4);
    for (i, name) in &by_index {
        let r = ok(&p, &["import", "api", &format!("--only={i}"), "--", &src]);
        assert_eq!(r["requests"][0]["name"].as_str(), Some(name.as_str()), "{r}");
    }
    let _ = std::fs::remove_dir_all(dir);
}
