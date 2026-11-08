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
        Self::start_env(project, extra, &[])
    }

    /// A server started with these environment variables.
    fn start_env(project: &std::path::Path, extra: &[&str], env: &[(&str, &str)]) -> Mcp {
        let mut child = Command::new(env!("CARGO_BIN_EXE_brainproxy"))
            .envs(env.iter().copied())
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
    for name in
        ["send", "history_list", "engagement_start", "scan_active", "import_api", "job_wait", "query", "capabilities"]
    {
        assert!(tool(name).is_some(), "missing {name}");
    }
    for name in ["mcp_serve", "proxy_run", "oob_run", "browser_open", "connection_review"] {
        assert!(tool(name).is_none(), "{name} should not be a tool");
    }
    let send = tool("send").unwrap();
    let props = &send["inputSchema"]["properties"];
    assert_eq!(props["stdin"]["type"], "string");
    assert_eq!(props["headers"]["type"], "array");
    assert_eq!(props["max_body"]["type"], "integer");
    assert_eq!(props["no_store"]["type"], "boolean");
    assert!(props.get("project").is_none() && props.get("format").is_none());
    let import_api = tool("import_api").unwrap();
    assert_eq!(import_api["annotations"]["openWorldHint"], true, "{import_api}");
    assert!(tool("scan_active").unwrap()["inputSchema"]["properties"].get("api").is_some());
    let start = tool("engagement_start").unwrap();
    assert_eq!(start["inputSchema"]["required"], json!(["targets"]));
    assert!(tool("crawl").unwrap()["inputSchema"]["properties"].get("job_id").is_none());
    assert!(tool("history_list").unwrap()["inputSchema"]["properties"].get("stdin").is_none());
    // Saving Replay tabs only adds through MCP and sends nothing; listing only reads.
    let save = tool("replay_tabs_save").unwrap();
    assert_eq!(save["inputSchema"]["properties"]["stdin"]["type"], "string");
    assert_eq!(save["inputSchema"]["properties"]["append"]["type"], "boolean");
    assert_eq!(save["annotations"]["readOnlyHint"], false);
    assert_eq!(save["annotations"]["destructiveHint"], false);
    assert_eq!(save["annotations"]["idempotentHint"], false);
    assert_eq!(save["annotations"]["openWorldHint"], false);
    assert_eq!(tool("replay_tabs_list").unwrap()["annotations"]["readOnlyHint"], true);

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
fn an_agent_can_prepare_replay_tabs() {
    let mut m = Mcp::start(&tmp_project("replay-tabs"), &[]);
    m.request("initialize", json!({"protocolVersion": "2025-06-18", "capabilities": {}}));
    // No scope needed: saving sends nothing.
    let set = json!({"tabs": [{"kind": "ws", "title": "feed", "target": "wss://a.test", "request": "GET / HTTP/1.1\n\n",
        "messages": ["«auth:app:header:X»"], "until": "done"}], "active": 0});
    // Only adding: an agent (or text from the target steering it) can't replace or clear a
    // person's tabs.
    for stdin in [set.to_string(), r#"{"tabs": []}"#.to_string()] {
        let (err, env) = m.call("replay_tabs_save", json!({"stdin": stdin}));
        assert!(err, "{env}");
        assert!(env["error"]["message"].as_str().unwrap().contains("only be added"), "{env}");
    }
    let (err, env) = m.call("replay_tabs_save", json!({"stdin": set.to_string(), "append": true}));
    assert!(!err, "{env}");
    assert_eq!((&env["data"]["count"], &env["data"]["added"]), (&json!(1), &json!(1)));
    let r = m.request("tools/call", json!({"name": "replay_tabs_list", "arguments": {}}));
    assert_eq!(r["result"]["_meta"]["provenance"]["untrusted_content"], true, "{r}");
    let (err, env) = m.call("replay_tabs_list", json!({}));
    assert!(!err, "{env}");
    assert_eq!(env["data"]["tabs"], set["tabs"]);
    assert_eq!(env["data"]["active"], 0);

    // A bad set is a tool error and leaves the saved one alone; list takes no stdin.
    let (err, env) =
        m.call("replay_tabs_save", json!({"stdin": r#"{"tabs": [{"request": "", "response": "x"}]}"#, "append": true}));
    assert!(err);
    assert_eq!(env["error"]["kind"], "invalid_input", "{env}");
    let (err, env) = m.call("replay_tabs_save", json!({"append": true}));
    assert!(err, "no stdin is no set: {env}");
    let r = m.request("tools/call", json!({"name": "replay_tabs_list", "arguments": {"stdin": "{}"}}));
    assert_eq!(r["error"]["code"], -32602, "{r}");
    assert_eq!(m.call("replay_tabs_list", json!({})).1["data"]["count"], 1);
    // A summary and one tab at a time, for sets larger than the output cap.
    let (err, env) = m.call("replay_tabs_list", json!({"summary": true}));
    assert!(!err, "{env}");
    assert!(env["data"]["tabs"][0].get("request").is_none(), "{env}");
    assert_eq!(m.call("replay_tabs_list", json!({"index": 0})).1["data"]["tab"], set["tabs"][0]);
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
    let (connected_tx, connected) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let (mut s, _) = listener.accept().unwrap();
        let _ = connected_tx.send(());
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

    // Cancelled: the child is killed and no response is sent for it. Wait for it to connect
    // first, or a cancel that wins the race leaves nothing to hang up (slow starts on Windows).
    connected.recv_timeout(std::time::Duration::from_secs(20)).expect("send never connected");
    let started = std::time::Instant::now();
    m.send_line(r#"{"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":"slow"}}"#);
    closed.recv_timeout(std::time::Duration::from_secs(5)).expect("cancelled send still connected");
    assert!(started.elapsed().as_secs() < 5);
    assert_eq!(m.request("ping", Value::Null)["result"], json!({}));
}

#[test]
fn annotations_resources_and_progress() {
    let mut m = Mcp::start(&tmp_project("hints"), &[]);
    let r = m.request("initialize", json!({"protocolVersion": "2025-06-18", "capabilities": {}}));
    assert!(r["result"]["capabilities"]["resources"].is_object());

    let tools = m.request("tools/list", json!({}))["result"]["tools"].as_array().unwrap().clone();
    let hints = |name: &str| tools.iter().find(|t| t["name"] == name).unwrap()["annotations"].clone();
    assert_eq!(hints("query")["readOnlyHint"], true);
    assert_eq!(hints("query")["openWorldHint"], false);
    assert_eq!(hints("send")["readOnlyHint"], false);
    assert_eq!(hints("send")["openWorldHint"], true);
    assert_eq!(hints("engagement_start")["destructiveHint"], true);
    assert_eq!(hints("rules_add")["destructiveHint"], false);
    // A restart stops the running proxy, like `proxy stop`.
    for hint in ["readOnlyHint", "destructiveHint", "idempotentHint", "openWorldHint"] {
        assert_eq!(hints("proxy_restart")[hint], hints("proxy_stop")[hint], "{hint}");
    }
    assert_eq!(
        (&hints("proxy_restart")["readOnlyHint"], &hints("proxy_restart")["destructiveHint"]),
        (&false.into(), &true.into())
    );
    assert!(tools.iter().all(|t| t["annotations"]["readOnlyHint"].is_boolean()));

    // Resources: schema and capabilities, read through the same CLI output.
    let list = m.request("resources/list", json!({}))["result"]["resources"].clone();
    let uris: Vec<&str> = list.as_array().unwrap().iter().map(|r| r["uri"].as_str().unwrap()).collect();
    assert_eq!(uris, ["brainproxy://schema", "brainproxy://capabilities"]);
    let r = m.request("resources/read", json!({"uri": "brainproxy://schema"}));
    let content = &r["result"]["contents"][0];
    assert_eq!(content["uri"], "brainproxy://schema");
    assert_eq!(content["mimeType"], "application/json");
    let env: Value = serde_json::from_str(content["text"].as_str().unwrap()).unwrap();
    assert_eq!(env["command"], "schema");
    assert_eq!(m.request("resources/read", json!({"uri": "brainproxy://nope"}))["error"]["code"], -32002);
    assert_eq!(m.request("resources/templates/list", json!({}))["result"]["resourceTemplates"], json!([]));

    // Progress: a target that answers after ~2.5 s; the call reports elapsed time meanwhile.
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    std::thread::spawn(move || {
        let (mut s, _) = listener.accept().unwrap();
        let mut buf = [0u8; 4096];
        let _ = s.read(&mut buf);
        std::thread::sleep(std::time::Duration::from_millis(2500));
        let _ = s.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok");
    });
    m.request("tools/call", json!({"name": "engagement_start", "arguments": {"targets": ["127.0.0.1"]}}));
    let params = json!({"name": "send", "arguments": {"url": format!("http://127.0.0.1:{port}/")}, "_meta": {"progressToken": "p1"}});
    m.send_line(&json!({"jsonrpc": "2.0", "id": "slow", "method": "tools/call", "params": params}).to_string());
    let mut progress = Vec::new();
    let reply = loop {
        let msg = m.read();
        if msg["method"] == "notifications/progress" {
            assert_eq!(msg["params"]["progressToken"], "p1");
            progress.push(msg["params"]["progress"].as_u64().unwrap());
        } else {
            break msg;
        }
    };
    assert_eq!(reply["id"], "slow");
    assert_eq!(reply["result"]["isError"], false, "{reply}");
    assert!(progress.len() >= 2, "{progress:?}");
    assert!(progress.windows(2).all(|w| w[0] < w[1]), "{progress:?}");
}

/// What an agent may not do without a person: attach a collection's script, open the
/// user's browser, or read a secret from any of the server's environment variables.
#[cfg(unix)]
#[test]
fn an_agent_cannot_add_a_script_open_a_browser_or_read_any_variable() {
    use std::os::unix::fs::PermissionsExt;

    let p = tmp_project("guards");
    let dir = p.parent().unwrap().to_path_buf();
    // Stand-ins for the commands that open a browser, leaving a mark when run.
    let bin = dir.join("bin");
    std::fs::create_dir_all(&bin).unwrap();
    let opened = dir.join("opened");
    let _ = std::fs::remove_file(&opened);
    for name in ["open", "xdg-open"] {
        let f = bin.join(name);
        std::fs::write(&f, format!("#!/bin/sh\necho \"$1\" >> '{}'\n", opened.display())).unwrap();
        std::fs::set_permissions(&f, std::fs::Permissions::from_mode(0o755)).unwrap();
    }
    let path = format!("{}:{}", bin.display(), std::env::var("PATH").unwrap_or_default());
    let env = [
        ("PATH", path.as_str()),
        ("OTHER_TOKEN", "FAKE-OTHER-TOKEN"),
        ("BRAINPROXY_SECRET_KEY", "FAKE-KEY"),
        ("SIGN_KEY", "FAKE-SIGN-KEY"),
    ];
    let script = dir.join("sign.js");
    std::fs::write(&script, "pm.request.headers.add({key: 'X-Sig', value: 'x'});\n").unwrap();
    let script = script.to_str().unwrap();
    let cli = |args: &[&str]| {
        Command::new(env!("CARGO_BIN_EXE_brainproxy"))
            .envs(env.iter().copied())
            .args(["--format", "json", "--project"])
            .arg(&p)
            .args(args)
            .output()
            .unwrap()
    };

    let mut m = Mcp::start_env(&p, &[], &env);
    m.request("initialize", json!({"protocolVersion": "2025-06-18", "capabilities": {}}));
    let (err, env_) = m.call("engagement_start", json!({"targets": ["127.0.0.1"]}));
    assert!(!err, "{env_}");
    let origin = "http://127.0.0.1:9";

    // A script signer.
    let (err, e) = m.call("auth_sign_add", json!({"profile": "a", "name": "s", "script": script, "origins": [origin]}));
    assert!(err, "{e}");
    let message = e["error"]["message"].as_str().unwrap();
    assert!(message.contains("isn't offered through MCP") && message.contains("a person"), "{message}");
    assert!(cli(&["auth", "sign", "add", "a", "s", "--script", script, "--origin", origin]).status.success());

    // Environment variables: only the prefix the app uses.
    let (err, e) = m.call("auth_add", json!({"name": "k", "header_env": ["X-Key=OTHER_TOKEN"]}));
    assert!(err, "{e}");
    assert!(e["error"]["message"].as_str().unwrap().contains("BRAINPROXY_SECRET_"), "{e}");
    assert!(!e.to_string().contains("FAKE-OTHER-TOKEN"), "{e}");
    let (err, e) = m.call("auth_add", json!({"name": "k", "header_env": ["X-Key=BRAINPROXY_SECRET_KEY"]}));
    assert!(!err, "{e}");
    let hmac = json!({"profile": "k", "name": "h", "secret_env": "SIGN_KEY", "origins": [origin],
        "to": "header:X-Sig", "canonical": "{{method}}"});
    let (err, e) = m.call("auth_sign_add", hmac);
    assert!(err && e["error"]["message"].as_str().unwrap().contains("--secret-env"), "{e}");
    // Files whose contents go on the wire as they are.
    let secret = dir.join("aws-secret");
    std::fs::write(&secret, "FAKE-AWS-SECRET").unwrap();
    let (err, e) = m.call(
        "auth_sign_add",
        json!({"profile": "k", "name": "aws", "secret_env": "BRAINPROXY_SECRET_KEY",
        "origins": [origin], "sigv4_region": "eu-west-1", "sigv4_service": "execute-api",
        "access_key_file": secret.to_str().unwrap()}),
    );
    assert!(err && e["error"]["message"].as_str().unwrap().contains("--access-key-file"), "{e}");
    for (flag, args) in [
        ("--oauth-client-secret-env", json!({"oauth_client_secret_env": "OTHER_TOKEN"})),
        ("--password-env", json!({"password_env": "OTHER_TOKEN"})),
    ] {
        let mut a = json!({"name": "o", "oauth_flow": "client_credentials",
            "oauth_token_url": format!("{origin}/token"), "oauth_client_id": "c"});
        a.as_object_mut().unwrap().extend(args.as_object().unwrap().clone());
        let (err, e) = m.call("auth_add", a);
        assert!(err && e["error"]["message"].as_str().unwrap().contains(flag), "{e}");
    }

    // A browser sign-in prints its URL but opens nothing.
    let port = TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port().to_string();
    let code = ["auth", "add", "c", "--oauth-flow", "authorization_code", "--oauth-client-id", "pub"];
    let token_url = format!("{origin}/token");
    let more = ["--oauth-token-url", &token_url, "--oauth-authorize-url", "https://id.test/authorize"];
    let o = cli(&[&code[..], &more[..], &["--oauth-redirect-port", &port]].concat());
    assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stdout));
    let (err, _) = m.call("auth_oauth_authorize", json!({"name": "c", "wait": 1}));
    assert!(err, "nobody signed in");
    assert!(!opened.exists(), "a browser was opened");
    // From a terminal it opens one.
    let o = cli(&["auth", "oauth", "authorize", "c", "--wait", "1"]);
    assert!(!o.status.success());
    // The browser is started, not waited for: give the stand-in a moment to write its mark.
    let mut url = String::new();
    for _ in 0..50 {
        url = std::fs::read_to_string(&opened).unwrap_or_default();
        if !url.is_empty() {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    assert!(url.starts_with("https://id.test/authorize?"), "{url}");
}

#[test]
fn an_agent_adds_findings_from_stdin_but_reads_no_files() {
    let p = tmp_project("manual-findings");
    let notes = p.parent().unwrap().join("notes.txt");
    std::fs::write(&notes, "FAKE-PRIVATE-NOTES").unwrap();
    let mut m = Mcp::start(&p, &[]);
    m.request("initialize", json!({"protocolVersion": "2025-06-18", "capabilities": {}}));
    let list = m.request("tools/list", json!({}));
    let tools = list["result"]["tools"].as_array().unwrap();
    let tool = |name: &str| tools.iter().find(|t| t["name"] == name).unwrap_or_else(|| panic!("{name}")).clone();
    assert!(tool("findings_add")["inputSchema"]["properties"]["stdin"].is_object());
    // An agent can't replace the write-up findings of the same title share, nor remove findings.
    assert_eq!(tool("findings_add")["annotations"]["destructiveHint"], false);
    assert!(tools.iter().all(|t| t["name"] != "findings_remove"));

    let base = json!({"title": "Order IDOR", "risk": "high", "url": "https://app.test/orders/7"});
    let mut from_file = base.clone();
    from_file["description_file"] = json!(notes.to_str().unwrap());
    let (err, e) = m.call("findings_add", from_file);
    assert!(err && e["error"]["message"].as_str().unwrap().contains("--description-file"), "{e}");
    assert!(!e.to_string().contains("FAKE-PRIVATE-NOTES"), "{e}");

    let mut from_stdin = base;
    from_stdin["description_file"] = json!("-");
    from_stdin["stdin"] = json!("Any user can read any order.");
    let (err, e) = m.call("findings_add", from_stdin);
    assert!(!err, "{e}");
    assert_eq!(e["data"]["finding"]["description"], "Any user can read any order.");
    // It is on the record as an agent's, like everything else a tool call records.
    assert_eq!(e["data"]["finding"]["origin"], "mcp", "{e}");
    let id = e["data"]["id"].as_i64().unwrap();
    // Texts as JSON on stdin; another description than the shared one is refused, and an agent
    // can't ask to replace it.
    let mut args = json!({"title": "Order IDOR", "risk": "high", "url": "https://app.test/orders/8", "input_json": true,
        "stdin": r#"{"description": "Newer text.", "evidence": "{\"owner\": 2}"}"#});
    let (err, e) = m.call("findings_add", args.clone());
    assert!(err && e["error"]["kind"] == "conflict", "{e}");
    args["replace_text"] = json!(true);
    let (err, e) = m.call("findings_add", args);
    assert!(err && e["error"]["message"].as_str().unwrap().contains("through MCP"), "{e}");
    let args = json!({"title": "Order IDOR", "risk": "high", "url": "https://app.test/orders/8", "input_json": true,
        "stdin": r#"{"evidence": "{\"owner\": 2}"}"#});
    let (err, e) = m.call("findings_add", args);
    assert!(!err, "{e}");
    assert_eq!(
        (e["data"]["finding"]["evidence"].as_str(), e["data"]["finding"]["description"].as_str()),
        (Some(r#"{"owner": 2}"#), Some("Any user can read any order."))
    );
    // Nothing can be removed: the agent marks instead.
    let r = m.request("tools/call", json!({"name": "findings_remove", "arguments": {"ids": [id]}}));
    assert_eq!(r["error"]["code"], -32602, "{r}");
    let (err, e) = m.call("findings_mark", json!({"id": id, "state": "false_positive", "note": "not a bug"}));
    assert!(!err, "{e}");
    let (_, e) = m.call("findings_show", json!({"id": id}));
    assert_eq!(e["data"]["state"], "false_positive", "{e}");
    assert_eq!(e["data"]["state_origin"], "mcp", "{e}");
    // Several at once, as a list under the same name.
    let (err, e) = m.call("findings_mark", json!({"id": [id], "state": "open"}));
    assert!(!err && e["data"]["ids"] == json!([id]), "{e}");
    // But not from a file.
    let (err, e) = m.call("findings_mark", json!({"from": notes.to_str().unwrap(), "state": "false_positive"}));
    assert!(err && e["error"]["message"].as_str().unwrap().contains("through MCP"), "{e}");
}

#[test]
fn an_agent_reads_no_file_through_any_finding_text_flag() {
    let p = tmp_project("manual-files");
    let dir = p.parent().unwrap();
    std::fs::write(dir.join("notes.txt"), "FAKE-PRIVATE-NOTES").unwrap();
    let mut m = Mcp::start(&p, &[]);
    m.request("initialize", json!({"protocolVersion": "2025-06-18", "capabilities": {}}));
    let list = m.request("tools/list", json!({}));
    let tools = list["result"]["tools"].as_array().unwrap();
    let t = tools.iter().find(|t| t["name"] == "findings_add").unwrap();
    assert_eq!(t["annotations"]["readOnlyHint"], false, "{t}");
    let abs = dir.join("notes.txt");
    for flag in ["description_file", "solution_file", "evidence_file"] {
        for path in [abs.to_str().unwrap(), "notes.txt", "/etc/hostname"] {
            let mut args = json!({"title": "Order IDOR", "risk": "high", "url": "https://app.test/orders/7"});
            args[flag] = json!(path);
            let (err, e) = m.call("findings_add", args);
            assert!(err && e["error"]["message"].as_str().unwrap().contains("through MCP"), "{flag} {path}: {e}");
            assert!(!e.to_string().contains("FAKE-PRIVATE-NOTES"), "{e}");
        }
    }
    // Only one flag reads the call's stdin.
    let args = json!({"title": "Order IDOR", "risk": "high", "url": "https://app.test/orders/7",
        "description_file": "-", "solution_file": "-", "stdin": "x"});
    let (err, e) = m.call("findings_add", args);
    assert!(err && e["error"]["message"].as_str().unwrap().contains("stdin"), "{e}");
    // Nothing was added on the way.
    let (err, e) = m.call("findings_list", json!({"source": "manual", "all": true}));
    assert!(!err && e["data"]["count"] == 0, "{e}");
}

#[test]
fn an_agent_cannot_send_unrecorded_or_open_the_proxy_to_the_network() {
    let p = tmp_project("record");
    let mut m = Mcp::start_env(&p, &[], &[]);
    m.request("initialize", json!({"protocolVersion": "2025-06-18", "capabilities": {}}));
    let (err, e) = m.call("engagement_start", json!({"targets": ["127.0.0.1"]}));
    assert!(!err, "{e}");
    let url = "http://127.0.0.1:9/";
    for (tool, args) in [
        ("send", json!({"url": url, "no_store": true})),
        ("send", json!({"url": url, "no_store": true, "race": 2})),
        ("ws_send", json!({"url": "ws://127.0.0.1:9/", "no_store": true})),
    ] {
        let (err, e) = m.call(tool, args);
        assert!(err, "{tool}: {e}");
        assert!(e["error"]["message"].as_str().unwrap().contains("--no-store"), "{tool}: {e}");
    }
    // Fuzzing with fewer exchanges in history: refused before anything is sent.
    let port = serve(0);
    let fuzz_url = format!("http://127.0.0.1:{port}/?q=§x§");
    for store in ["none", "matches"] {
        let (err, e) = m.call("fuzz_run", json!({"url": fuzz_url, "payloads": ["list:1,2"], "store": store}));
        assert!(err, "{store}: {e}");
        let message = e["error"]["message"].as_str().unwrap();
        assert!(message.contains(&format!("--store {store}")) && message.contains("recorded"), "{message}");
    }
    let (err, e) = m.call("history_list", json!({}));
    assert!(!err && e["data"]["items"].as_array().is_some_and(|a| a.is_empty()), "{e}");
    // `browser open` isn't a tool, and a tool call's command refuses it too.
    let o = Command::new(env!("CARGO_BIN_EXE_brainproxy"))
        .env("BRAINPROXY_MCP_CALL", "1")
        .args(["--format", "json", "--project"])
        .arg(&p)
        .args(["browser", "open", "http://127.0.0.1:9/"])
        .output()
        .unwrap();
    assert!(!o.status.success());
    let out = String::from_utf8_lossy(&o.stdout);
    assert!(out.contains("browser open isn't offered through MCP"), "{out}");
    let (err, e) = m.call("proxy_start", json!({"listen": "0.0.0.0:0"}));
    assert!(err, "{e}");
    assert!(e["error"]["message"].as_str().unwrap().contains("loopback"), "{e}");
}

#[test]
fn an_agent_cannot_pass_its_records_off_as_the_apps() {
    // Even a server started from the app's environment marks what its tool calls record as an
    // agent's: tool arguments can't set or clear environment variables.
    let port = serve(1);
    let project = tmp_project("origin");
    let mut m = Mcp::start_env(&project, &[], &[("BRAINPROXY_CLIENT", "gui")]);
    m.request("initialize", json!({"protocolVersion": "2025-06-18", "capabilities": {}}));
    let (err, env) = m.call("engagement_start", json!({"targets": ["127.0.0.1"]}));
    assert!(!err, "{env}");
    let (err, env) = m.call("send", json!({"url": format!("http://127.0.0.1:{port}/")}));
    assert!(!err, "{env}");
    let (_, env) = m.call("history_list", json!({}));
    assert_eq!(env["data"]["items"][0]["origin"], "mcp", "{env}");
    let (_, env) = m.call("history_list", json!({"origin": "gui"}));
    assert_eq!(env["data"]["count"], 0, "{env}");
    // No tool takes the environment or a way to name the client.
    let tools = m.request("tools/list", json!({}))["result"]["tools"].as_array().unwrap().clone();
    for t in &tools {
        let props = t["inputSchema"]["properties"].as_object().cloned().unwrap_or_default();
        for key in props.keys() {
            assert!(!["env", "client", "set_origin"].contains(&key.as_str()), "{}: {key}", t["name"]);
        }
    }
}

#[test]
fn an_agent_cannot_replace_a_persons_layouts_or_files() {
    let p = tmp_project("layouts");
    let dir = p.parent().unwrap().to_path_buf();
    let cli = |args: &[&str]| {
        let o = Command::new(env!("CARGO_BIN_EXE_brainproxy"))
            .args(["--format", "json", "--project"])
            .arg(&p)
            .args(args)
            .output()
            .unwrap();
        assert!(o.status.success(), "{args:?}: {}", String::from_utf8_lossy(&o.stdout));
        serde_json::from_slice::<Value>(&o.stdout).unwrap()
    };
    // A person's branding, and a finding to make a repro pack of.
    cli(&["report-profile", "save", "board", "--company", "Acme"]);
    let added = cli(&["findings", "add", "--title", "Order IDOR", "--risk", "high", "--url", "https://app.test/o/7"]);
    let id = added["data"]["id"].as_i64().unwrap();
    let kept = dir.join("kept.json");
    std::fs::write(&kept, "A PERSON'S FILE").unwrap();

    let mut m = Mcp::start(&p, &[]);
    m.request("initialize", json!({"protocolVersion": "2025-06-18", "capabilities": {}}));
    let tools = m.request("tools/list", json!({}))["result"]["tools"].as_array().unwrap().clone();
    let tool = |name: &str| tools.iter().find(|t| t["name"] == name).unwrap_or_else(|| panic!("{name}")).clone();
    assert!(tools.iter().all(|t| t["name"] != "report_profile_remove"));
    assert_eq!(tool("findings_repro")["annotations"]["destructiveHint"], false);
    assert_eq!(tool("report_profile_save")["annotations"]["destructiveHint"], false);

    // A saved name is kept; a new one is saved.
    let (err, e) = m.call("report_profile_save", json!({"name": "board", "company": "Evil"}));
    assert!(err && e["error"]["message"].as_str().unwrap().contains("new name"), "{e}");
    let (err, e) = m.call("report_profile_save", json!({"name": "agent-draft", "company": "Draft"}));
    assert!(!err, "{e}");
    let shown = cli(&["report-profile", "show", "board"]);
    assert_eq!(shown["data"]["layout"]["company"], "Acme", "{shown}");

    // A repro pack goes to a new file, never over one.
    let (err, e) = m.call("findings_repro", json!({"id": id, "output": kept.to_str().unwrap(), "force": true}));
    assert!(err && e["error"]["message"].as_str().unwrap().contains("--force"), "{e}");
    let (err, e) = m.call("findings_repro", json!({"id": id, "output": kept.to_str().unwrap()}));
    assert!(err, "{e}");
    assert_eq!(std::fs::read_to_string(&kept).unwrap(), "A PERSON'S FILE");
    let fresh = dir.join("fresh.json");
    let _ = std::fs::remove_file(&fresh);
    let (err, e) = m.call("findings_repro", json!({"id": id, "output": fresh.to_str().unwrap()}));
    assert!(!err && fresh.exists(), "{e}");

    // `report-profile remove` isn't a tool, and a tool call's command refuses it too.
    let o = Command::new(env!("CARGO_BIN_EXE_brainproxy"))
        .env("BRAINPROXY_MCP_CALL", "1")
        .args(["--format", "json", "--project"])
        .arg(&p)
        .args(["report-profile", "remove", "board"])
        .output()
        .unwrap();
    assert!(!o.status.success());
    assert!(String::from_utf8_lossy(&o.stdout).contains("refused through MCP"));
    cli(&["report-profile", "show", "board"]);
}

#[test]
fn an_agent_sends_a_foreign_host_only_as_a_stated_host_header_test() {
    let port = serve(2);
    let mut m = Mcp::start(&tmp_project("host"), &[]);
    m.request("initialize", json!({"protocolVersion": "2025-06-18", "capabilities": {}}));
    let (err, e) = m.call("engagement_start", json!({"targets": ["127.0.0.1", "app.test"]}));
    assert!(!err, "{e}");
    let url = format!("http://127.0.0.1:{port}/");
    let foreign = ["Host: other-tenant.test"];
    let raw = "GET / HTTP/1.1\r\nHost: other-tenant.test\r\n\r\n";
    // An in-scope front end could send these to a site the scope doesn't list.
    for (tool, args) in [
        ("send", json!({"url": url, "headers": foreign})),
        ("send", json!({"url": url, "headers": foreign, "race": 2})),
        ("send", json!({"url": url, "headers": foreign, "http2": true})),
        ("send", json!({"file": "-", "target": url, "stdin": raw})),
        ("ws_send", json!({"url": format!("ws://127.0.0.1:{port}/"), "headers": foreign})),
        ("fuzz_run", json!({"url": format!("{url}?q=§x§"), "headers": foreign, "payloads": ["list:1"]})),
    ] {
        let (err, e) = m.call(tool, args);
        assert!(err, "{tool}: {e}");
        assert_eq!(e["error"]["kind"], "out_of_scope", "{tool}: {e}");
        assert!(e["error"]["message"].as_str().unwrap().contains("--host-header-test"), "{tool}: {e}");
    }
    let (_, e) = m.call("history_list", json!({}));
    assert_eq!(e["data"]["count"], 0, "{e}");
    // Saying it is a Host-header test puts the intent on record; the output warns.
    let (err, e) = m.call("send", json!({"url": url, "headers": foreign, "host_header_test": true}));
    assert!(!err, "{e}");
    assert!(e["data"]["host_warning"].as_str().unwrap().contains("other-tenant.test"), "{e}");
    // A name the scope lists needs no flag.
    let (err, e) = m.call("send", json!({"url": url, "headers": ["Host: app.test"]}));
    assert!(!err, "{e}");
    assert!(e["data"].get("host_warning").is_none(), "{e}");
}

#[test]
fn an_agent_sets_a_foreign_host_on_requests_to_come_only_as_a_stated_host_header_test() {
    let project = tmp_project("host-settings");
    let mut m = Mcp::start(&project, &[]);
    m.request("initialize", json!({"protocolVersion": "2025-06-18", "capabilities": {}}));
    let (err, e) = m.call("engagement_start", json!({"targets": ["127.0.0.1", "app.test"]}));
    assert!(!err, "{e}");
    let step = project.with_extension("step.http");
    std::fs::write(&step, "GET / HTTP/1.1\r\nHost: other-tenant.test\r\n\r\n").unwrap();
    let step = format!("http://127.0.0.1:9={}", step.display());
    let foreign = ["Host: other-tenant.test"];
    // Each would put the host on requests an in-scope front end could send to another site.
    let settings = [
        ("auth_add", json!({"name": "p", "headers": foreign})),
        (
            "auth_add",
            json!({"name": "p", "login_url": "http://127.0.0.1:9/", "token_regex": "t=(\\w+)", "token_header": "Host: {{token}}"}),
        ),
        ("auth_add", json!({"name": "p", "login_url": "http://127.0.0.1:9/login", "login_header": foreign})),
        ("auth_macro_add", json!({"profile": "p", "name": "m", "steps": [step]})),
        ("rules_add", json!({"location": "request-header", "replace": "Host: other-tenant.test"})),
        (
            "rules_add",
            json!({"location": "request-header", "pattern": "127\\.0\\.0\\.1", "replace": "other-tenant.test"}),
        ),
        (
            "rules_add",
            json!({"location": "request-line", "pattern": "^GET /", "replace": "GET http://other-tenant.test/"}),
        ),
    ];
    for (tool, args) in &settings {
        let (err, e) = m.call(tool, args.clone());
        assert!(err, "{tool} {args}: {e}");
        assert_eq!(e["error"]["kind"], "out_of_scope", "{tool} {args}: {e}");
        assert!(e["error"]["message"].as_str().unwrap().contains("--host-header-test"), "{tool}: {e}");
    }
    let (_, e) = m.call("rules_list", json!({}));
    assert_eq!(e["data"]["rules"], json!([]), "{e}");
    // Saying it is a Host-header test puts the intent on record; the output warns.
    for (tool, args) in &settings {
        let mut args = args.clone();
        args["host_header_test"] = json!(true);
        let (err, e) = m.call(tool, args.clone());
        assert!(!err, "{tool} {args}: {e}");
        let warning = e["data"]["host_warning"].as_str().unwrap();
        assert!(warning.contains("other-tenant.test") || warning.contains("{{token}}"), "{tool}: {e}");
    }
    // Saving it again unchanged sets no new Host: no flag is needed.
    let (err, e) = m.call("auth_add", json!({"name": "q", "headers": foreign, "host_header_test": true}));
    assert!(!err, "{e}");
    let (err, e) = m.call("auth_add", json!({"name": "q", "headers": foreign}));
    assert!(!err, "{e}");
    // Hosts the scope lists, the login URL's own host, and other headers need none either.
    for (tool, args) in [
        ("auth_add", json!({"name": "r", "headers": ["Host: app.test", "X-Api-Key: 1"]})),
        ("auth_add", json!({"name": "r", "login_url": "http://127.0.0.1:9/", "login_header": ["Host: 127.0.0.1:9"]})),
        ("rules_add", json!({"location": "request-header", "pattern": "^X-Role: user$", "replace": "X-Role: admin"})),
    ] {
        let (err, e) = m.call(tool, args.clone());
        assert!(!err, "{tool} {args}: {e}");
        assert!(e["data"].get("host_warning").is_none(), "{tool}: {e}");
    }
    // A disabled rule changes nothing until it is enabled, which is checked.
    let (err, e) =
        m.call("rules_add", json!({"location": "request-header", "replace": "Host: b.test", "disabled": true}));
    assert!(!err, "{e}");
    let id = e["data"]["rules"].as_array().unwrap().last().unwrap()["id"].clone();
    let (err, e) = m.call("rules_enable", json!({"id": id}));
    assert!(err && e["error"]["message"].as_str().unwrap().contains("Host b.test"), "{e}");
    let (err, e) = m.call("rules_enable", json!({"id": id, "host_header_test": true}));
    assert!(!err, "{e}");
    // A rule that copies a header's name from the request could make it a Host.
    let copied = json!({"location": "request-header", "pattern": "^X-Zz: (.*)$", "replace": "Hos$1"});
    let (err, e) = m.call("rules_add", copied);
    assert!(err && e["error"]["kind"] == "out_of_scope", "{e}");
}

#[test]
fn every_request_is_checked_as_it_goes_out() {
    let port = serve(2);
    let project = tmp_project("host-wire");
    let mut m = Mcp::start(&project, &[]);
    m.request("initialize", json!({"protocolVersion": "2025-06-18", "capabilities": {}}));
    let (err, e) = m.call("engagement_start", json!({"targets": ["127.0.0.1", "app.test"]}));
    assert!(!err, "{e}");
    let url = format!("http://127.0.0.1:{port}/");
    let person = |args: &[&str]| {
        let o = Command::new(env!("CARGO_BIN_EXE_brainproxy"))
            .env_remove("BRAINPROXY_MCP_CALL")
            .args(["--format", "json", "--project"])
            .arg(&project)
            .args(args)
            .output()
            .unwrap();
        serde_json::from_slice::<Value>(&o.stdout).unwrap()
    };
    // A person's profile sets a Host; an agent's send with it is refused as it goes out, after
    // the session applied it, unless the send says it is a Host-header test.
    let saved = person(&["auth", "add", "p", "-H", "Host: other-tenant.test"]);
    assert!(saved["data"]["host_warning"].is_string(), "{saved}");
    let (err, e) = m.call("send", json!({"url": url, "auth": "p"}));
    assert!(err && e["error"]["kind"] == "out_of_scope", "{e}");
    assert!(e["error"]["message"].as_str().unwrap().contains("Host other-tenant.test"), "{e}");
    let (err, e) = m.call("send", json!({"url": url, "auth": "p", "host_header_test": true}));
    assert!(!err, "{e}");
    assert!(e["data"]["host_warning"].as_str().unwrap().contains("other-tenant.test"), "{e}");
    // A line break can't start another header from a profile or -H, for anyone.
    for (tool, args) in [
        ("auth_add", json!({"name": "q", "headers": ["X-A: v\r\nHost: e.test"]})),
        ("auth_add", json!({"name": "q", "headers": ["X-B\r\nHost: e.test"]})),
        ("auth_add", json!({"name": "q", "login_url": url, "login_header": ["X-L: a\r\nHost: e.test"]})),
        (
            "auth_add",
            json!({"name": "q", "login_url": url, "token_regex": "(t)", "token_header": "A: {{token}}\r\nHost: e.test"}),
        ),
        ("send", json!({"url": url, "headers": ["X-A: v\r\nHost: e.test"]})),
    ] {
        let (err, e) = m.call(tool, args.clone());
        assert!(err && e["error"]["kind"] == "invalid_input", "{tool} {args}: {e}");
    }
    let o = person(&["auth", "add", "q", "-H", "X-A: v\r\nHost: e.test"]);
    assert_eq!(o["error"]["kind"], "invalid_input", "{o}");
    // Request lines and heads a lenient server may read otherwise, or a target that isn't a path.
    for raw in [
        "GET .evil.test/ HTTP/2\r\nHost: app.test\r\n\r\n",
        "GET @evil.test/ HTTP/1.1\r\nHost: app.test\r\n\r\n",
        "GET  http://e.test/ HTTP/1.1\r\nHost: app.test\r\n\r\n",
        "GET\thttp://e.test/ HTTP/1.1\r\nHost: app.test\r\n\r\n",
        "GET / HTTP/1.1\r\nX: a\rHost: e.test\r\nHost: app.test\r\n\r\n",
        "GET ws://e.test/ HTTP/1.1\r\nHost: app.test\r\n\r\n",
    ] {
        let (err, e) = m.call("send", json!({"file": "-", "target": url, "stdin": raw, "verbatim": true}));
        assert!(err && e["error"]["kind"] == "out_of_scope", "{raw:?}: {e}");
    }
    // Fuzz payloads that could make a Host: a header name, or a line break into the head.
    let (err, e) = m.call(
        "fuzz_run",
        json!({"file": "-", "target": url, "stdin": "GET / HTTP/1.1\r\n§x§: e.test\r\n\r\n", "payloads": ["list:Host"]}),
    );
    assert!(err && e["error"]["kind"] == "out_of_scope", "{e}");
    let crlf = "GET / HTTP/1.1\r\nHost: app.test\r\nX-Z: §x§\r\n\r\n";
    let (err, e) =
        m.call("fuzz_run", json!({"file": "-", "target": url, "stdin": crlf, "payloads": ["list:a\r\nHost: e.test"]}));
    assert!(err && e["error"]["kind"] == "invalid_input", "{e}");
    // A crawl's and an import's -H are checked as they go out too.
    let (_, e) = m.call("crawl", json!({"urls": [url], "headers": ["Host: e.test"], "max_pages": 1}));
    assert_eq!((&e["data"]["requests"], &e["data"]["errors"]), (&json!(1), &json!(1)), "{e}");
    let coll = json!({"info": {"name": "c", "schema": "https://schema.getpostman.com/json/collection/v2.1.0/collection.json"},
        "item": [{"name": "r", "request": {"method": "GET", "header": [{"key": "Host", "value": "e.test"}], "url": url}}]});
    let (_, e) = m.call("import_postman", json!({"source": "-", "stdin": coll.to_string()}));
    assert_eq!(e["data"]["out_of_scope_hosts"], json!(["e.test"]), "{e}");
    // A Host given with -H takes the place of the target's rather than adding a second.
    let (err, e) = m.call("send", json!({"url": url, "headers": ["Host: app.test"]}));
    assert!(!err, "{e}");
    let id = e["data"]["id"].to_string();
    let (_, e) = m.call("query", json!({"sql": format!("SELECT req_headers FROM history WHERE id = {id}")}));
    let head = e["data"]["rows"][0][0].as_str().unwrap().to_ascii_lowercase();
    assert_eq!(head.matches("[\"host\",").count(), 1, "{head}");
    let (_, e) = m.call("history_list", json!({}));
    // Only requests that got as far as the wire have rows (two sends, one refused, and the
    // crawl's refused one): a refused one says so.
    assert_eq!(e["data"]["count"], 4, "{e}");
    let refused = e["data"]["items"][0]["error"].as_str().unwrap();
    assert!(refused.contains("out of scope: Host other-tenant.test"), "{refused}");
}

#[test]
fn an_agent_overwrites_no_file_and_keeps_the_ca() {
    let p = tmp_project("force");
    let dir = p.parent().unwrap().to_path_buf();
    let home = dir.join("home");
    let _ = std::fs::remove_dir_all(&home);
    let home_s = home.to_str().unwrap().to_string();
    let kept = dir.join("kept.txt");
    std::fs::write(&kept, "A PERSON'S FILE").unwrap();
    let mut m = Mcp::start_env(&p, &[], &[("BRAINPROXY_HOME", &home_s)]);
    m.request("initialize", json!({"protocolVersion": "2025-06-18", "capabilities": {}}));
    let tools = m.request("tools/list", json!({}))["result"]["tools"].as_array().unwrap().clone();
    for name in ["report", "ca_export", "ca_init", "findings_repro"] {
        let t = tools.iter().find(|t| t["name"] == name).unwrap_or_else(|| panic!("{name}"));
        assert_eq!(t["annotations"]["destructiveHint"], false, "{name}");
    }

    // The CA is made when missing, and kept: a new one is refused.
    let (err, e) = m.call("ca_init", json!({}));
    assert!(!err, "{e}");
    let sha = e["data"]["sha256"].clone();
    let (err, e) = m.call("ca_init", json!({"force": true}));
    assert!(err && e["error"]["message"].as_str().unwrap().contains("--force is refused through MCP"), "{e}");
    let (_, e) = m.call("ca_init", json!({}));
    assert_eq!(e["data"]["sha256"], sha);

    // Nothing is written over a file, with --force or without it; a new file is written.
    let path = kept.to_str().unwrap();
    for (tool, args) in [
        ("report", json!({"output": path, "force": true})),
        ("ca_export", json!({"out": path, "force": true})),
        ("report", json!({"output": path})),
        ("ca_export", json!({"out": path})),
    ] {
        let (err, e) = m.call(tool, args.clone());
        assert!(err, "{tool} {args}: {e}");
        if args["force"] == true {
            assert!(e["error"]["message"].as_str().unwrap().contains("--force is refused through MCP"), "{e}");
        }
    }
    assert_eq!(std::fs::read_to_string(&kept).unwrap(), "A PERSON'S FILE");
    let fresh = dir.join("fresh.md");
    let _ = std::fs::remove_file(&fresh);
    let (err, e) = m.call("report", json!({"kind": "markdown", "output": fresh.to_str().unwrap()}));
    assert!(!err && fresh.exists(), "{e}");
    let _ = std::fs::remove_dir_all(&home);
}
