//! Match-and-replace rules end to end: structured locations, the engines a rule applies to, the
//! host condition, `rules test`, `rules import`, and what a rule-changed exchange keeps.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use serde_json::{json, Value};

const MCP: &str = "BRAINPROXY_MCP_CALL";
const CLIENT: &str = "BRAINPROXY_CLIENT";

struct Env {
    project: PathBuf,
    home: PathBuf,
}

impl Env {
    fn new(name: &str) -> Self {
        let dir = std::env::temp_dir().join(format!("bp-rules-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let env = Env { project: dir.join("p.bpdb"), home: dir.join("home") };
        env.ok(&["engagement", "start", "--target", "127.0.0.1", "--target", "localhost"]);
        env
    }

    /// Runs the CLI with these provenance variables (the test's own are removed) and stdin.
    fn run_as(&self, vars: &[(&str, &str)], args: &[&str], stdin: Option<&[u8]>) -> (i32, Value) {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_brainproxy"));
        cmd.env_remove(MCP).env_remove(CLIENT).envs(vars.iter().copied());
        cmd.args(["--format", "json", "--project"]).arg(&self.project).arg("--home").arg(&self.home).args(args);
        cmd.stdin(if stdin.is_some() { Stdio::piped() } else { Stdio::null() }).stdout(Stdio::piped());
        let mut child = cmd.spawn().unwrap();
        if let Some(input) = stdin {
            child.stdin.take().unwrap().write_all(input).unwrap();
        }
        let out = child.wait_with_output().unwrap();
        let v = serde_json::from_slice(&out.stdout).unwrap_or(Value::Null);
        (out.status.code().unwrap(), v)
    }

    fn run(&self, args: &[&str]) -> (i32, Value) {
        self.run_as(&[], args, None)
    }

    fn ok(&self, args: &[&str]) -> Value {
        let (code, v) = self.run(args);
        assert_eq!(code, 0, "{args:?} -> {v}");
        v["data"].clone()
    }

    fn ok_stdin(&self, args: &[&str], stdin: &[u8]) -> Value {
        let (code, v) = self.run_as(&[], args, Some(stdin));
        assert_eq!(code, 0, "{args:?} -> {v}");
        v["data"].clone()
    }

    /// The error message of a command that must fail.
    fn refused(&self, vars: &[(&str, &str)], args: &[&str], stdin: Option<&[u8]>) -> String {
        let (code, v) = self.run_as(vars, args, stdin);
        assert_ne!(code, 0, "{args:?} -> {v}");
        v["error"]["message"].as_str().unwrap_or_default().to_string()
    }

    fn rows(&self, sql: &str) -> Vec<Value> {
        self.ok(&["query", sql])["rows"].as_array().unwrap().clone()
    }

    fn wait_rows(&self, sql: &str, n: i64) {
        let deadline = Instant::now() + Duration::from_secs(10);
        while self.rows(sql)[0][0].as_i64().unwrap() < n && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(50));
        }
        assert_eq!(self.rows(sql)[0][0].as_i64().unwrap(), n, "{sql}");
    }
}

impl Drop for Env {
    fn drop(&mut self) {
        let _ = self.run(&["proxy", "stop"]);
    }
}

/// Answers every request `403 Forbidden` with the request it got as the body.
fn serve() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut s) = stream else { continue };
            std::thread::spawn(move || {
                let mut buf = vec![0u8; 16384];
                let mut len = 0;
                while !buf[..len].windows(4).any(|w| w == b"\r\n\r\n") {
                    match s.read(&mut buf[len..]) {
                        Ok(0) | Err(_) => return,
                        Ok(n) => len += n,
                    }
                }
                let head = format!(
                    "HTTP/1.1 403 Forbidden\r\nContent-Type: text/plain\r\nX-Frame-Options: DENY\r\n\
                     Content-Length: {len}\r\nConnection: close\r\n\r\n"
                );
                let _ = s.write_all(head.as_bytes());
                let _ = s.write_all(&buf[..len]);
            });
        }
    });
    port
}

/// A request through the proxy at `listen`; returns the whole response.
fn through(listen: &str, port: u16, target: &str, headers: &str) -> String {
    let mut s = TcpStream::connect(listen).unwrap();
    write!(
        s,
        "GET http://127.0.0.1:{port}{target} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n{headers}Connection: close\r\n\r\n"
    )
    .unwrap();
    let mut resp = Vec::new();
    s.read_to_end(&mut resp).unwrap();
    String::from_utf8_lossy(&resp).into_owned()
}

fn wait_for_settings() {
    // The proxy reloads settings every 300 ms.
    std::thread::sleep(Duration::from_millis(700));
}

fn ids(v: &Value) -> Vec<u64> {
    v.as_array().into_iter().flatten().filter_map(Value::as_u64).collect()
}

#[test]
fn structured_rules_change_a_proxied_exchange_and_history_keeps_both_versions() {
    let port = serve();
    let env = Env::new("proxy");
    let add = |args: &[&str]| env.ok(&[&["rules", "add"][..], args].concat());
    add(&["--location", "query-param", "--name", "role", "--replace", "admin"]);
    add(&["--location", "request-header", "--name", "X-Tier", "--match", "^free$", "--replace", "pro"]);
    add(&["--location", "path", "--match-kind", "literal", "--match", "/v1/", "--replace", "/v2/"]);
    add(&["--location", "status", "--match", "403", "--replace", "200"]);
    add(&["--location", "response-header", "--name", "X-Frame-Options", "--action", "remove"]);
    add(&[
        "--location",
        "response-body",
        "--match-kind",
        "literal",
        "--match",
        "role=admin",
        "--replace",
        "role=ADMIN",
    ]);
    // One for another host, and one for another engine: neither applies here.
    add(&["--location", "method", "--replace", "PUT", "--host", "^other\\.test$"]);
    let listed = add(&["--location", "method", "--replace", "DELETE", "--applies-to", "fuzz,scan"]);
    assert_eq!(listed["rules"][7]["applies_to"], json!(["fuzz", "scan"]), "{listed}");
    // A rule that says nothing new is stored as rules always were.
    assert_eq!(
        listed["rules"][3],
        json!({"id": 4, "location": "status", "pattern": "403", "replace": "200", "enabled": true, "origin": "cli"})
    );

    let listen = env.ok(&["proxy", "start", "--listen", "127.0.0.1:0"])["listen"].as_str().unwrap().to_string();
    wait_for_settings();
    let resp = through(&listen, port, "/api/v1/me?role=user&x=1", "X-Tier: free\r\n");
    assert!(resp.starts_with("HTTP/1.1 200 OK\r\n"), "{resp}");
    assert!(!resp.to_ascii_lowercase().contains("x-frame-options"), "{resp}");
    // The server saw the request after the rules; the client its answer after them.
    assert!(resp.contains("GET /api/v2/me?role=ADMIN&x=1 HTTP/1.1"), "{resp}");
    assert!(resp.contains("X-Tier: pro"), "{resp}");

    env.wait_rows("SELECT count(*) FROM history WHERE source = 'proxy'", 1);
    let id = env.rows("SELECT id FROM history WHERE source = 'proxy'")[0][0].to_string();
    let shown = env.ok(&["history", "show", &id]);
    // The row is the request that went out and the response that came back.
    assert!(shown["request"]["content"].as_str().unwrap().starts_with("GET /api/v2/me?role=admin&x=1 "), "{shown}");
    assert_eq!(shown["response"]["status"], 403, "{shown}");
    let edited: Vec<u64> =
        shown["entry"]["edited_by"].as_array().unwrap().iter().filter_map(|e| e["rule"].as_u64()).collect();
    assert_eq!(edited, [1, 2, 3], "{shown}");
    // Beside it: the request before the rules and the response after them, and who changed it.
    let original = shown["original_request"]["content"].as_str().unwrap();
    assert!(
        original.starts_with("GET /api/v1/me?role=user&x=1 HTTP/1.1\r\n") && original.contains("X-Tier: free"),
        "{shown}"
    );
    let modified = shown["modified_response"]["content"].as_str().unwrap();
    assert!(modified.starts_with("HTTP/1.1 200 OK\r\n") && modified.contains("role=ADMIN"), "{shown}");
    let by: Vec<u64> = shown["response_edits"].as_array().unwrap().iter().filter_map(|e| e["rule"].as_u64()).collect();
    assert_eq!(by, [4, 5, 6], "{shown}");
    let (_, raw) = env.run_as(&[], &["history", "show", &id, "--raw", "--part", "original-request"], None);
    assert_eq!(raw, Value::Null, "raw output is the bytes, not JSON");

    // An exchange no rule changed keeps nothing beside its row.
    env.ok(&["rules", "clear"]);
    wait_for_settings();
    through(&listen, port, "/plain", "");
    env.wait_rows("SELECT count(*) FROM history WHERE source = 'proxy'", 2);
    assert_eq!(env.rows("SELECT count(*) FROM rule_edits")[0][0], 1);
    let plain = env.rows("SELECT id FROM history WHERE path = '/plain'")[0][0].to_string();
    let shown = env.ok(&["history", "show", &plain]);
    assert!(shown["original_request"].is_null() && shown["modified_response"].is_null(), "{shown}");
}

#[test]
fn send_and_fuzz_apply_only_the_rules_that_list_them() {
    let port = serve();
    let env = Env::new("engines");
    let url = format!("http://127.0.0.1:{port}/item?id=1");
    // A rule as every rule was before: the proxy's only.
    env.ok(&["rules", "add", "--location", "request-header", "--replace", "X-Proxy-Only: 1"]);
    let sent = env.ok(&["send", "--url", &url, "--max-body", "4096"]);
    assert!(!sent["response"]["body"]["content"].as_str().unwrap().contains("X-Proxy-Only"), "{sent}");
    assert!(sent["rules"].is_null(), "{sent}");
    assert_eq!(env.rows("SELECT count(*) FROM rule_edits")[0][0], 0);

    let add = |args: &[&str]| env.ok(&[&["rules", "add"][..], args].concat());
    add(&["--location", "request-header", "--name", "X-Role", "--replace", "admin", "--applies-to", "send,fuzz"]);
    add(&["--location", "status", "--replace", "200", "--applies-to", "send"]);
    add(&[
        "--location",
        "query-param",
        "--name",
        "id",
        "--replace",
        "2",
        "--applies-to",
        "send",
        "--host",
        "^nowhere$",
    ]);
    let sent = env.ok(&["send", "--url", &url, "--max-body", "4096"]);
    assert_eq!(sent["rules"], json!({"request": [2], "response": [3]}), "{sent}");
    assert_eq!(sent["response"]["status"], 200, "what the rules made of the response is what is shown: {sent}");
    let body = sent["response"]["body"]["content"].as_str().unwrap();
    assert!(body.contains("X-Role: admin") && body.contains("/item?id=1 "), "{sent}");
    // Its row says which rule changed the request, keeps the request as given, and the
    // response both as received and as shown.
    let id = sent["id"].as_i64().unwrap().to_string();
    let shown = env.ok(&["history", "show", &id]);
    assert_eq!(shown["response"]["status"], 403, "{shown}");
    assert_eq!(shown["entry"]["edited_by"], json!([{"by": "cli", "rule": 2}]), "{shown}");
    assert!(!shown["original_request"]["content"].as_str().unwrap().contains("X-Role"), "{shown}");
    assert!(shown["modified_response"]["content"].as_str().unwrap().starts_with("HTTP/1.1 200 OK"), "{shown}");
    assert_eq!(shown["response_edits"], json!([{"by": "cli", "rule": 3}]), "{shown}");
    // A race's copies get the same: each row both responses, the results the one after the rules.
    let raced = env.ok(&["send", "--url", &url, "--race", "2"]);
    assert_eq!(
        raced["distinct_responses"].as_object().unwrap().keys().next().unwrap().split(' ').next(),
        Some("200"),
        "{raced}"
    );
    let rows = env.rows(
        "SELECT h.status, e.original_request IS NOT NULL, e.modified_response IS NOT NULL, h.edited_by \
         FROM history h JOIN rule_edits e ON e.history_id = h.id WHERE h.source = 'race'",
    );
    assert_eq!(rows.len(), 2, "{rows:?}");
    assert!(
        rows.iter().all(|r| r[0] == 403 && r[1] == 1 && r[2] == 1 && r[3].as_str().unwrap().contains("\"rule\":2")),
        "{rows:?}"
    );
    // A send that isn't recorded keeps none of it.
    let quiet = env.ok(&["send", "--url", &url, "--no-store"]);
    assert_eq!(quiet["rules"]["request"], json!([2]), "{quiet}");
    assert_eq!(env.rows("SELECT count(*) FROM rule_edits")[0][0], 3);

    // The fuzzer applies its rules to each request, payload in; the status rule isn't its.
    let fuzz = env.ok(&[
        "fuzz",
        "run",
        "--url",
        &format!("http://127.0.0.1:{port}/f?q=§q§"),
        "-p",
        "list:a,b",
        "--grep",
        "X-Role: admin",
        "--store",
        "all",
    ]);
    assert_eq!(fuzz["matches"].as_array().unwrap().len(), 2, "{fuzz}");
    assert_eq!(fuzz["matches"][0]["status"], 403, "{fuzz}");
    let rows = env.rows(
        "SELECT h.edited_by, e.original_request IS NOT NULL FROM history h JOIN rule_edits e ON e.history_id = h.id \
         WHERE h.source = 'fuzz'",
    );
    assert_eq!(rows.len(), 2, "{rows:?}");
    assert!(rows[0][0].as_str().unwrap().contains("\"rule\":2") && rows[0][1] == 1, "{rows:?}");
    // A run that keeps only its matches says the same on the rows it writes afterwards.
    let url = format!("http://127.0.0.1:{port}/m?q=§q§");
    let fuzz = env.ok(&["fuzz", "run", "--url", &url, "-p", "list:a,b,c", "--grep", "q=b", "--store", "matches"]);
    assert_eq!(fuzz["matches"].as_array().unwrap().len(), 1, "{fuzz}");
    let rows = env.rows(
        "SELECT h.edited_by, e.original_request FROM history h JOIN rule_edits e ON e.history_id = h.id \
         WHERE h.source = 'fuzz' AND h.path = '/m'",
    );
    assert_eq!(rows.len(), 1, "{rows:?}");
    assert!(rows[0][0].as_str().unwrap().contains("\"rule\":2"), "{rows:?}");
    assert!(!rows[0][1].as_str().unwrap().contains("X-Role"), "{rows:?}");
}

#[test]
fn an_active_scan_applies_the_rules_that_list_scans() {
    let port = serve();
    let env = Env::new("scan");
    let url = format!("http://127.0.0.1:{port}/go?next=a");
    env.ok(&[
        "rules",
        "add",
        "--location",
        "request-header",
        "--name",
        "X-Scan",
        "--replace",
        "1",
        "--applies-to",
        "scan",
    ]);
    let scan = env.ok(&["scan", "active", "--rules", "40003", &url]);
    assert!(scan["requests"].as_u64().unwrap() > 0, "{scan}");
    // Every attack request carried the header; the base request the scan fetched did not.
    let attacks = env.rows(
        "SELECT count(*), sum(req_headers LIKE '%X-Scan%'), sum(edited_by LIKE '%\"rule\":1%') FROM history \
         WHERE source = 'scan' AND id > (SELECT min(id) FROM history)",
    );
    assert!(attacks[0][0].as_i64().unwrap() > 0, "{attacks:?}");
    assert_eq!((&attacks[0][0], &attacks[0][0]), (&attacks[0][1], &attacks[0][2]), "{attacks:?}");
    let base = env.rows("SELECT req_headers LIKE '%X-Scan%' FROM history ORDER BY id LIMIT 1");
    assert_eq!(base[0][0], 0);

    // A response rule changes what the scan's rules read, the baseline they compare with
    // included: text it writes into every response isn't taken for an attack's doing.
    let rewrite = [
        "--location",
        "response-body",
        "--match-kind",
        "whole",
        "--replace",
        "libxml2 XPathException",
        "--applies-to",
        "scan",
    ];
    env.ok(&[&["rules", "add"][..], &rewrite].concat());
    let scan = env.ok(&["scan", "active", "--rules", "90021", &url]);
    assert!(scan["requests"].as_u64().unwrap() > 0, "{scan}");
    assert_eq!(env.rows("SELECT count(*) FROM findings WHERE source = 'active'")[0][0], 0, "{scan}");
    assert!(
        env.rows("SELECT count(*) FROM rule_edits WHERE modified_response IS NOT NULL")[0][0].as_i64().unwrap() > 0
    );
}

#[test]
fn rules_test_tries_rules_on_a_message_and_sends_nothing() {
    let env = Env::new("test");
    env.ok(&["rules", "add", "--location", "method", "--match-kind", "whole", "--match", "GET", "--replace", "POST"]);
    env.ok(&["rules", "add", "--location", "status", "--match", "^4..$", "--replace", "200", "--disabled"]);
    env.ok(&["rules", "add", "--location", "path", "--replace", "/x", "--applies-to", "send", "--host", "^a\\.test$"]);
    let request = b"GET /p?a=1 HTTP/1.1\nHost: a.test\n\n";
    // The enabled rules, as the proxy would apply them: bare line feeds are read as `send` reads them.
    let tested = env.ok_stdin(&["rules", "test"], request);
    assert_eq!((ids(&tested["request"]["rules"]), &tested["host"]), (vec![1], &json!("a.test")), "{tested}");
    assert_eq!(tested["request"]["result"]["content"], "POST /p?a=1 HTTP/1.1\r\nHost: a.test\r\n\r\n");
    assert_eq!(tested["request"]["original"]["content"], "GET /p?a=1 HTTP/1.1\r\nHost: a.test\r\n\r\n");
    // As send would: its rule applies where the host matches.
    let tested = env.ok_stdin(&["rules", "test", "--as", "send"], request);
    assert_eq!(ids(&tested["request"]["rules"]), [3], "{tested}");
    // `tried` is the rules that engine applies, not every rule there is.
    assert_eq!(ids(&tested["tried"]), [3], "{tested}");
    let tested = env.ok_stdin(&["rules", "test", "--as", "send", "--target-host", "b.test"], request);
    assert_eq!((ids(&tested["request"]["rules"]), &tested["request"]["changed"]), (vec![], &json!(false)), "{tested}");
    // A picked rule is tried though it is disabled; a response is told by how it starts.
    let response = b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n";
    let tested = env.ok_stdin(&["rules", "test", "--rule", "2"], response);
    assert_eq!(tested["response"]["result"]["content"], "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n", "{tested}");
    assert_eq!(env.ok_stdin(&["rules", "test"], response)["response"]["changed"], false);
    // A rule that isn't saved, from a file, and a WebSocket message.
    let file = env.project.with_extension("req");
    std::fs::write(&file, request).unwrap();
    let draft = ["--location", "query-param", "--name", "a", "--action", "remove"];
    let tested = env.ok(&[&["rules", "test", file.to_str().unwrap()][..], &draft].concat());
    assert_eq!(tested["request"]["result"]["content"], "GET /p HTTP/1.1\r\nHost: a.test\r\n\r\n", "{tested}");
    let ws = [
        "rules",
        "test",
        "--message",
        "ws-to-client",
        "--location",
        "ws-message",
        "--match",
        "\"admin\":false",
        "--replace",
        "\"admin\":true",
    ];
    let tested = env.ok_stdin(&ws, br#"{"admin":false}"#);
    assert_eq!(tested["message"]["result"]["content"], r#"{"admin":true}"#, "{tested}");
    // A draft that couldn't be saved is refused, and nothing was saved or sent.
    let bad = env.refused(&[], &["rules", "test", "--location", "query-param", "--replace", "x"], Some(request));
    assert!(bad.contains("--name"), "{bad}");
    assert_eq!(env.ok(&["rules", "list"])["rules"].as_array().unwrap().len(), 3);
    assert_eq!(env.rows("SELECT count(*) FROM history")[0][0], 0);

    // A history row's request and response are tried together.
    let port = serve();
    let sent = env.ok(&["send", "--url", &format!("http://127.0.0.1:{port}/h")]);
    let id = sent["id"].as_i64().unwrap().to_string();
    let tested = env.ok(&["rules", "test", "--history", &id, "--rule", "1,2"]);
    assert_eq!((ids(&tested["request"]["rules"]), ids(&tested["response"]["rules"])), (vec![1], vec![2]), "{tested}");
    assert_eq!(tested["host"], "127.0.0.1");
    assert_eq!(env.rows("SELECT count(*) FROM history")[0][0], 1);

    // Through MCP the message comes from stdin or history: a file would be read back.
    let agent = [(MCP, "1")];
    let refused = env.refused(&agent, &["rules", "test", file.to_str().unwrap()], None);
    assert!(refused.contains("through MCP") && !refused.contains("a.test"), "{refused}");
    let (code, v) = env.run_as(&agent, &["rules", "test"], Some(request));
    assert_eq!((code, ids(&v["data"]["request"]["rules"])), (0, vec![1]), "{v}");
}

#[test]
fn rules_import_takes_what_rules_list_prints() {
    let env = Env::new("import");
    env.ok(&["rules", "add", "--location", "request-header", "--name", "X-A", "--replace", "1", "--comment", "one"]);
    env.ok(&[
        "rules",
        "add",
        "--location",
        "status",
        "--match",
        "500",
        "--replace",
        "200",
        "--applies-to",
        "proxy,send",
    ]);
    env.ok(&["rules", "remove", "1"]);
    let (_, listed) = env.run(&["rules", "list"]);
    let other = Env::new("import-into");
    other.ok(&["rules", "add", "--location", "method", "--replace", "HEAD", "--disabled"]);
    // The whole answer of `rules list` is read, and so is a bare list.
    let imported = other.ok_stdin(&["rules", "import"], listed.to_string().as_bytes());
    let rules = imported["rules"].as_array().unwrap();
    assert_eq!(rules.len(), 2, "{imported}");
    // A new id here, the importer's origin, the rest as it was.
    assert_eq!(
        rules[1],
        json!({"id": 2, "location": "status", "pattern": "500", "replace": "200", "enabled": true, "origin": "cli", "applies_to": ["proxy", "send"]})
    );
    let bare = json!([{"location": "path", "pattern": "", "replace": "/", "host_header_test": true, "origin": "gui"}]);
    let imported = other.ok_stdin(&["rules", "import", "--replace", "--disabled"], bare.to_string().as_bytes());
    // An id is never handed out twice, even to replace; the file can't say a Host is meant.
    assert_eq!(
        imported["rules"],
        json!([{"id": 3, "location": "path", "pattern": "", "replace": "/", "enabled": false, "origin": "cli"}])
    );
    // One bad rule and none is imported.
    let bad = json!([{"location": "path", "pattern": "", "replace": "/ok"}, {"location": "query-param", "pattern": "", "replace": "x"}]);
    let refused = other.refused(&[], &["rules", "import"], Some(bad.to_string().as_bytes()));
    assert!(refused.contains("rule 2 of the import"), "{refused}");
    assert_eq!(other.ok(&["rules", "list"])["rules"].as_array().unwrap().len(), 1);
    assert!(other.refused(&[], &["rules", "import"], Some(b"{}")).contains("isn't a list of rules"));
    // Through MCP the rules come from the call's stdin.
    let file = other.project.with_extension("rules.json");
    std::fs::write(&file, bare.to_string()).unwrap();
    assert!(other.refused(&[(MCP, "1")], &["rules", "import", file.to_str().unwrap()], None).contains("through MCP"));
}

#[test]
fn an_agents_structured_rule_that_sets_a_foreign_host_is_refused() {
    let port = serve();
    let env = Env::new("host");
    let agent = [(MCP, "1")];
    let gui = [(CLIENT, "gui")];
    let host = [
        "rules",
        "add",
        "--location",
        "request-header",
        "--name",
        "Host",
        "--replace",
        "e.test",
        "--applies-to",
        "proxy,send",
    ];
    // Saving it says so, as for a rule that writes a Host line.
    let refused = env.refused(&agent, &host, None);
    assert!(refused.contains("sets Host e.test") && refused.contains("--host-header-test"), "{refused}");
    let absolute = ["rules", "add", "--location", "path", "--match", "^/", "--replace", "http://e.test/"];
    assert!(env.refused(&agent, &absolute, None).contains("e.test"));
    // What a match inside the Host's value leaves of it is checked too: 127.0.0.1 without its
    // first number is another host.
    let part =
        ["rules", "add", "--location", "request-header", "--name", "Host", "--match", "^127\\.", "--replace", ""];
    assert!(env.refused(&agent, &part, None).contains("--host-header-test"));
    let copied =
        ["rules", "add", "--location", "request-header", "--name", "Host", "--match", "^(.*)$", "--replace", "x.$1"];
    assert!(env.refused(&agent, &copied, None).contains("--host-header-test"));
    let import = json!([{"location": "request-header", "name": "host", "pattern": "", "replace": "e.test", "host_header_test": true}]);
    let refused = env.refused(&agent, &["rules", "import"], Some(import.to_string().as_bytes()));
    assert!(refused.contains("sets Host e.test"), "{refused}");
    assert_eq!(env.ok(&["rules", "list"])["rules"], json!([]));
    // One that only makes a Host of what the request holds passes the check when it is saved;
    // what it makes of a request is refused where the request is sent.
    let (code, v) = env.run_as(
        &agent,
        &[
            "rules",
            "add",
            "--location",
            "request-header",
            "--match-kind",
            "literal",
            "--match",
            "Zz",
            "--replace",
            "st",
            "--applies-to",
            "proxy,send",
        ],
        None,
    );
    assert_eq!(code, 0, "{v}");
    let url = format!("http://127.0.0.1:{port}/frag");
    let refused = env.refused(&gui, &["send", "--url", &url, "-H", "HoZz: e.test"], None);
    assert!(refused.contains("an agent's rule put a host the scope doesn't list"), "{refused}");
    assert_eq!(env.rows("SELECT count(*) FROM history")[0][0], 0, "refused before it was recorded as sent");
    // Saved as a Host-header test it is sent, with the person's usual warning.
    env.ok(&["rules", "clear"]);
    let (code, v) = env.run_as(&agent, &[&host[..], &["--host-header-test"]].concat(), None);
    assert_eq!(code, 0, "{v}");
    let sent = env.run_as(&gui, &["send", "--url", &url, "--max-body", "4096"], None).1["data"].clone();
    assert!(sent["response"]["body"]["content"].as_str().unwrap().contains("Host: e.test"), "{sent}");
    assert!(sent["host_warning"].as_str().unwrap().contains("e.test"), "{sent}");
}

#[test]
fn rules_that_do_not_fit_are_refused_when_they_are_added() {
    let env = Env::new("bad");
    let refused = |args: &[&str]| env.refused(&[], &[&["rules", "add"][..], args].concat(), None);
    assert!(refused(&["--location", "query-param", "--replace", "x"]).contains("--name"));
    assert!(refused(&["--location", "path", "--name", "x"]).contains("--name goes with"));
    assert!(refused(&["--location", "status", "--replace", "20"]).contains("status replacement"));
    assert!(refused(&["--location", "status", "--replace", "103"]).contains("status replacement"));
    assert!(refused(&["--location", "ws-message", "--match", "a", "--applies-to", "proxy"]).contains("ws-to-server"));
    assert!(refused(&["--location", "path", "--replace", "/", "--applies-to", "ws-to-client"]).contains("ws-message"));
    assert!(refused(&["--location", "path", "--replace", "/", "--host", "("]).contains("host pattern"));
    assert!(refused(&["--location", "method", "--replace", "GET\r\nX: y"]).contains("line break"));
    let (code, _) = env.run(&["rules", "add", "--location", "path", "--replace", "/", "--applies-to", "everything"]);
    assert_ne!(code, 0);
    assert_eq!(env.ok(&["rules", "list"])["rules"], json!([]));
}
