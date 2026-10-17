//! End-to-end tests for `mcp serve`: drive the binary over stdio with JSON-RPC.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpListener;
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};

use serde_json::{json, Value};

struct Mcp {
    child: Child,
    stdin: ChildStdin,
    stdout: BufReader<ChildStdout>,
    next_id: i64,
}

impl Mcp {
    fn start(project: &std::path::Path, extra: &[&str]) -> Mcp {
        let mut child = Command::new(env!("CARGO_BIN_EXE_brainproxy"))
            .arg("--project")
            .arg(project)
            .args(["mcp", "serve"])
            .args(extra)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .unwrap();
        let stdin = child.stdin.take().unwrap();
        let stdout = BufReader::new(child.stdout.take().unwrap());
        Mcp { child, stdin, stdout, next_id: 0 }
    }

    fn send_line(&mut self, line: &str) {
        writeln!(self.stdin, "{line}").unwrap();
        self.stdin.flush().unwrap();
    }

    fn read(&mut self) -> Value {
        let mut line = String::new();
        self.stdout.read_line(&mut line).unwrap();
        serde_json::from_str(&line).unwrap_or_else(|e| panic!("bad JSON ({e}): {line:?}"))
    }

    fn request(&mut self, method: &str, params: Value) -> Value {
        self.next_id += 1;
        let id = self.next_id;
        self.send_line(&json!({"jsonrpc": "2.0", "id": id, "method": method, "params": params}).to_string());
        let reply = self.read();
        assert_eq!(reply["id"], id, "{reply}");
        assert_eq!(reply["jsonrpc"], "2.0");
        reply
    }

    /// Calls a tool and returns (isError, envelope parsed from the text content).
    fn call(&mut self, name: &str, arguments: Value) -> (bool, Value) {
        let r = self.request("tools/call", json!({"name": name, "arguments": arguments}));
        let result = &r["result"];
        let text = result["content"][0]["text"].as_str().unwrap_or_else(|| panic!("no text: {r}"));
        let env: Value = serde_json::from_str(text).unwrap_or_else(|e| panic!("bad envelope ({e}): {text}"));
        assert_eq!(result["structuredContent"], env);
        (result["isError"].as_bool().unwrap(), env)
    }
}

impl Drop for Mcp {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn tmp_project(name: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!("bp-test-{}-mcp-{name}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let p = dir.join("p.bpdb");
    let _ = std::fs::remove_file(&p);
    p
}

/// Serves `n` connections with a fixed 200 response naming the request line.
fn serve(n: usize) -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for stream in listener.incoming().take(n) {
            let mut s = stream.unwrap();
            let mut buf = vec![0u8; 8192];
            let mut len = 0;
            while !buf[..len].windows(4).any(|w| w == b"\r\n\r\n") {
                len += s.read(&mut buf[len..]).unwrap();
            }
            let line = String::from_utf8_lossy(&buf[..len]).lines().next().unwrap().to_string();
            let resp = format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{line}", line.len());
            s.write_all(resp.as_bytes()).unwrap();
        }
    });
    port
}

#[test]
fn protocol_and_tool_list() {
    let mut m = Mcp::start(&tmp_project("list"), &[]);
    let r = m.request(
        "initialize",
        json!({"protocolVersion": "2099-01-01", "capabilities": {}, "clientInfo": {"name": "t", "version": "0"}}),
    );
    assert_eq!(r["result"]["protocolVersion"], "2025-06-18");
    assert_eq!(r["result"]["serverInfo"]["name"], "brainproxy");
    assert!(r["result"]["capabilities"]["tools"].is_object());
    // Notifications get no reply: the next line read must answer the ping.
    m.send_line(r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#);
    assert_eq!(m.request("ping", Value::Null)["result"], json!({}));

    let tools = m.request("tools/list", json!({}))["result"]["tools"].as_array().unwrap().clone();
    let tool = |name: &str| tools.iter().find(|t| t["name"] == name).cloned();
    for name in ["send", "history_list", "engagement_start", "scan_active", "job_wait", "query", "capabilities"] {
        assert!(tool(name).is_some(), "missing {name}");
    }
    for name in ["mcp_serve", "proxy_run", "oob_run"] {
        assert!(tool(name).is_none(), "{name} should not be a tool");
    }
    let send = tool("send").unwrap();
    let props = &send["inputSchema"]["properties"];
    assert_eq!(props["stdin"]["type"], "string");
    assert_eq!(props["headers"]["type"], "array");
    assert_eq!(props["max_body"]["type"], "integer");
    assert_eq!(props["no_store"]["type"], "boolean");
    assert!(props.get("project").is_none() && props.get("format").is_none());
    let start = tool("engagement_start").unwrap();
    assert_eq!(start["inputSchema"]["required"], json!(["targets"]));
    assert!(tool("crawl").unwrap()["inputSchema"]["properties"].get("job_id").is_none());
    assert!(tool("history_list").unwrap()["inputSchema"]["properties"].get("stdin").is_none());

    // JSON-RPC errors.
    assert_eq!(m.request("nope", json!({}))["error"]["code"], -32601);
    assert_eq!(m.request("tools/call", json!({"name": "nope"}))["error"]["code"], -32602);
    let r = m.request("tools/call", json!({"name": "history_list", "arguments": {"bogus": 1}}));
    assert_eq!(r["error"]["code"], -32602);
    let r = m.request("tools/call", json!({"name": "history_list", "arguments": {"stdin": "x"}}));
    assert_eq!(r["error"]["code"], -32602);
    m.send_line("{not json");
    assert_eq!(m.read()["error"]["code"], -32700);
}

#[test]
fn calls_run_the_cli_in_scope() {
    let port = serve(2);
    let mut m = Mcp::start(&tmp_project("calls"), &[]);
    m.request("initialize", json!({"protocolVersion": "2025-06-18", "capabilities": {}}));
    let url = format!("http://127.0.0.1:{port}/a");

    // No scope yet: refused by the same guard, reported as a tool error.
    let (err, env) = m.call("send", json!({"url": url}));
    assert!(err);
    assert_eq!(env["error"]["kind"], "out_of_scope");

    let (err, env) = m.call("engagement_start", json!({"targets": ["127.0.0.1"]}));
    assert!(!err, "{env}");
    let (err, env) = m.call("send", json!({"url": url, "headers": ["X-A: 1"]}));
    assert!(!err, "{env}");
    assert_eq!(env["command"], "send");
    assert_eq!(env["data"]["response"]["status"], 200);

    // A raw request through stdin, with a positional '-' after the `--` separator.
    let raw = format!("GET /b HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n\r\n");
    let (err, env) = m.call("send", json!({"file": "-", "scheme": "http", "stdin": raw}));
    assert!(!err, "{env}");

    let (_, env) = m.call("history_list", json!({"limit": 10}));
    assert_eq!(env["data"]["items"].as_array().map(Vec::len), Some(2), "{env}");
    let (_, env) = m.call("query", json!({"sql": "SELECT url FROM history ORDER BY id"}));
    assert_eq!(env["data"]["rows"][1][0], format!("http://127.0.0.1:{port}/b"));

    // Other hosts stay out of scope.
    let (err, env) = m.call("send", json!({"url": "http://10.255.255.1/"}));
    assert!(err);
    assert_eq!(env["error"]["kind"], "out_of_scope");

    // Usage errors from clap come back as the usage envelope.
    let (err, env) = m.call("encode", json!({"kind": "nope", "input": "x"}));
    assert!(err);
    assert_eq!(env["ok"], false);
}

#[test]
fn timeout_and_output_bounds() {
    // A server that accepts and never answers.
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    std::thread::spawn(move || {
        let _held: Vec<_> = listener.incoming().take(1).collect();
        std::thread::sleep(std::time::Duration::from_secs(30));
    });
    let project = tmp_project("bounds");
    let mut m = Mcp::start(&project, &["--timeout", "1", "--max-output", "64"]);
    m.request("tools/call", json!({"name": "engagement_start", "arguments": {"targets": ["127.0.0.1"]}}));
    let started = std::time::Instant::now();
    let (err, env) = m.call("send", json!({"url": format!("http://127.0.0.1:{port}/"), "timeout": 20}));
    assert!(err);
    assert_eq!(env["error"]["kind"], "timeout");
    assert!(started.elapsed().as_secs() < 10);

    let r = m.request("tools/call", json!({"name": "capabilities", "arguments": {}}));
    let text = r["result"]["content"][0]["text"].as_str().unwrap();
    assert!(text.ends_with("[output cut off at 64 bytes]"), "{text}");
    assert!(r["result"].get("structuredContent").is_none());
}

#[test]
fn concurrent_calls_and_cancellation() {
    // A server that never answers, so `send` hangs until killed; reports when the client hangs up.
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let (closed_tx, closed) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let (mut s, _) = listener.accept().unwrap();
        let mut buf = [0u8; 4096];
        while s.read(&mut buf).is_ok_and(|n| n > 0) {}
        let _ = closed_tx.send(());
    });
    let mut m = Mcp::start(&tmp_project("cancel"), &[]);
    m.request("tools/call", json!({"name": "engagement_start", "arguments": {"targets": ["127.0.0.1"]}}));
    let hang = json!({"name": "send", "arguments": {"url": format!("http://127.0.0.1:{port}/"), "timeout": 20}});
    m.send_line(&json!({"jsonrpc": "2.0", "id": "slow", "method": "tools/call", "params": hang}).to_string());

    // Other requests are answered while the call runs.
    assert_eq!(m.request("ping", Value::Null)["result"], json!({}));
    let (err, env) = m.call("encode", json!({"kind": "hex", "input": "A"}));
    assert!(!err);
    assert_eq!(env["data"]["output"]["content"], "41");

    // A duplicate id is refused while the first call runs.
    m.send_line(&json!({"jsonrpc": "2.0", "id": "slow", "method": "tools/call", "params": hang}).to_string());
    assert_eq!(m.read()["error"]["code"], -32600);

    // Cancelled: the child is killed and no response is sent for it.
    let started = std::time::Instant::now();
    m.send_line(r#"{"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":"slow"}}"#);
    closed.recv_timeout(std::time::Duration::from_secs(5)).expect("cancelled send still connected");
    assert!(started.elapsed().as_secs() < 5);
    assert_eq!(m.request("ping", Value::Null)["result"], json!({}));
}
