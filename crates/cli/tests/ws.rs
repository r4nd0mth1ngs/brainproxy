//! WebSockets end to end: a client through the real proxy to an in-process echo server
//! (with permessage-deflate), recording, intercept, and `ws send` replay.

use std::path::PathBuf;
use std::process::Command;
use std::time::Duration;

use brainproxy_core::http::{RawRequest, WireReader};
use brainproxy_core::ws::{
    accept_key, close_payload, encode_frame, parse_frame, random_mask, Assembler, Deflate, Direction, MAX_MESSAGE,
    OP_BINARY, OP_CLOSE, OP_PING, OP_PONG, OP_TEXT,
};
use flate2::{Compress, Compression, FlushCompress};
use serde_json::Value;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

struct Env {
    dir: PathBuf,
    project: PathBuf,
    home: PathBuf,
}

impl Env {
    fn new(name: &str) -> Self {
        let dir = std::env::temp_dir().join(format!("bp-ws-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let env = Self { project: dir.join("p.bpdb"), home: dir.join("home"), dir };
        env.ok(&["engagement", "start", "--target", "127.0.0.1"]);
        env
    }

    fn run(&self, args: &[&str]) -> (i32, Value) {
        let out = Command::new(env!("CARGO_BIN_EXE_brainproxy"))
            .args(["--format", "json", "--project"])
            .arg(&self.project)
            .arg("--home")
            .arg(&self.home)
            .args(args)
            .output()
            .unwrap();
        let v = serde_json::from_slice(&out.stdout)
            .unwrap_or_else(|e| panic!("bad JSON ({e}): {}", String::from_utf8_lossy(&out.stdout)));
        (out.status.code().unwrap(), v)
    }

    /// Runs a command with `stdin`, expecting success.
    fn ok_with_stdin(&self, args: &[&str], stdin: &[u8]) -> Value {
        use std::io::Write;
        let mut child = Command::new(env!("CARGO_BIN_EXE_brainproxy"))
            .args(["--format", "json", "--project"])
            .arg(&self.project)
            .arg("--home")
            .arg(&self.home)
            .args(args)
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .spawn()
            .unwrap();
        // A command that fails on its arguments may exit before reading its stdin.
        let _ = child.stdin.take().unwrap().write_all(stdin);
        let out = child.wait_with_output().unwrap();
        let v: Value = serde_json::from_slice(&out.stdout).unwrap();
        assert_eq!(out.status.code(), Some(0), "{args:?} -> {v}");
        v["data"].clone()
    }

    fn ok(&self, args: &[&str]) -> Value {
        let (code, v) = self.run(args);
        assert_eq!(code, 0, "{args:?} -> {v}");
        v["data"].clone()
    }

    /// Polls `ws list` until the newest connection is closed (the recorder writes in the background).
    fn closed_connection(&self) -> Value {
        for _ in 0..50 {
            let list = self.ok(&["ws", "list"]);
            if let Some(c) = list["items"].as_array().and_then(|a| a.last()).filter(|c| c["state"] == "closed") {
                return c.clone();
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        panic!("no closed connection: {}", self.ok(&["ws", "list"]));
    }
}

impl Drop for Env {
    fn drop(&mut self) {
        let _ = self.run(&["proxy", "stop"]);
    }
}

/// WebSocket echo server: accepts permessage-deflate when offered (keeping its compression
/// window between messages), answers each text/binary message with "echo: " + payload,
/// pings with pongs, and a close with a close.
fn spawn_ws_echo() -> u16 {
    let std_listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = std_listener.local_addr().unwrap().port();
    std_listener.set_nonblocking(true).unwrap();
    std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_multi_thread().enable_all().build().unwrap();
        rt.block_on(async move {
            let listener = TcpListener::from_std(std_listener).unwrap();
            loop {
                let (tcp, _) = listener.accept().await.unwrap();
                tokio::spawn(echo(tcp));
            }
        });
    });
    port
}

async fn echo(mut s: TcpStream) {
    let mut reader = WireReader::new();
    let Ok(Some(req)) = reader.read_request(&mut s).await else { return };
    let head = RawRequest::from_bytes(req).head().unwrap();
    let header = |n: &str| head.headers.iter().find(|(k, _)| k.eq_ignore_ascii_case(n)).map(|(_, v)| v.clone());
    let Some(key) = header("sec-websocket-key") else {
        let _ = s.write_all(b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n").await;
        return;
    };
    if head.target.contains("deny") {
        let _ = s.write_all(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 2\r\n\r\nno").await;
        return;
    }
    if head.target.contains("hints") {
        s.write_all(b"HTTP/1.1 103 Early Hints\r\nLink: </app.js>; rel=preload\r\n\r\n").await.unwrap();
    }
    let closes = head.target.contains("closes");
    let deflate = header("sec-websocket-extensions").is_some_and(|e| e.contains("permessage-deflate"));
    let ext = if deflate { "Sec-WebSocket-Extensions: permessage-deflate\r\n" } else { "" };
    let resp = format!(
        "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\
         Sec-WebSocket-Accept: {}\r\n{ext}\r\n",
        accept_key(&key)
    );
    s.write_all(resp.as_bytes()).await.unwrap();
    if closes {
        // Goes away by itself, whatever the client is doing.
        tokio::time::sleep(Duration::from_millis(300)).await;
        return;
    }
    let negotiated = Deflate { enabled: deflate, ..Default::default() };
    let mut assembler = Assembler::new(negotiated, Direction::ToServer, MAX_MESSAGE);
    let mut compress = Compress::new(Compression::default(), false);
    let mut buf = reader.into_leftover();
    loop {
        while let Some((frame, n)) = parse_frame(&buf, MAX_MESSAGE).unwrap() {
            buf.drain(..n);
            let Some(m) = assembler.push(&frame).unwrap() else { continue };
            let reply = match m.opcode {
                OP_CLOSE => {
                    let _ = s.write_all(&encode_frame(true, 0, OP_CLOSE, &m.payload, None)).await;
                    let _ = s.shutdown().await;
                    return;
                }
                OP_PING => encode_frame(true, 0, OP_PONG, &m.payload, None),
                OP_PONG => continue,
                op => {
                    let mut text = b"echo: ".to_vec();
                    text.extend_from_slice(&m.payload);
                    if deflate {
                        let mut out = Vec::with_capacity(text.len() + 64);
                        compress.compress_vec(&text, &mut out, FlushCompress::Sync).unwrap();
                        out.truncate(out.len() - 4);
                        encode_frame(true, 4, op, &out, None)
                    } else {
                        encode_frame(true, 0, op, &text, None)
                    }
                }
            };
            if s.write_all(&reply).await.is_err() {
                return;
            }
        }
        let mut chunk = [0u8; 4096];
        match s.read(&mut chunk).await {
            Ok(0) | Err(_) => return,
            Ok(n) => buf.extend_from_slice(&chunk[..n]),
        }
    }
}

/// A WebSocket client speaking through the proxy (plain HTTP, absolute-form upgrade).
struct WsClient {
    s: TcpStream,
    buf: Vec<u8>,
    assembler: Assembler,
}

impl WsClient {
    async fn connect(proxy: &str, url: &str, deflate: bool) -> Self {
        let mut s = TcpStream::connect(proxy).await.unwrap();
        let host = url.trim_start_matches("http://").split('/').next().unwrap();
        let ext = if deflate { "Sec-WebSocket-Extensions: permessage-deflate; client_max_window_bits\r\n" } else { "" };
        let req = format!(
            "GET {url} HTTP/1.1\r\nHost: {host}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\
             Sec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n{ext}\r\n"
        );
        s.write_all(req.as_bytes()).await.unwrap();
        let mut reader = WireReader::new();
        let resp = reader.read_response(&mut s, "GET").await.unwrap();
        assert!(resp.starts_with(b"HTTP/1.1 101"), "{}", String::from_utf8_lossy(&resp));
        let head = brainproxy_core::http::parse_response_head(&resp).unwrap();
        assert_eq!(head.header("sec-websocket-accept"), Some("s3pPLMBiTxaQ9kYGzzhZRbK+xOo="));
        let negotiated = Deflate::from_response(&head);
        assert_eq!(negotiated.enabled, deflate);
        Self { s, buf: reader.into_leftover(), assembler: Assembler::new(negotiated, Direction::ToClient, MAX_MESSAGE) }
    }

    async fn send(&mut self, opcode: u8, payload: &[u8]) {
        self.s.write_all(&encode_frame(true, 0, opcode, payload, Some(random_mask()))).await.unwrap();
    }

    /// Sends a message in two fragments with a ping between them.
    async fn send_fragmented(&mut self, payload: &[u8]) {
        let (a, b) = payload.split_at(payload.len() / 2);
        let mut bytes = encode_frame(false, 0, OP_TEXT, a, Some(random_mask()));
        bytes.extend(encode_frame(true, 0, OP_PING, b"are you there", Some(random_mask())));
        bytes.extend(encode_frame(true, 0, 0, b, Some(random_mask())));
        self.s.write_all(&bytes).await.unwrap();
    }

    /// The next message, or None if the connection ends or nothing comes within `wait`.
    async fn recv(&mut self, wait: Duration) -> Option<(u8, Vec<u8>, bool)> {
        recv_on(&mut self.s, &mut self.buf, &mut self.assembler, wait).await
    }
}

async fn recv_on<S: AsyncRead + AsyncWrite + Unpin>(
    s: &mut S,
    buf: &mut Vec<u8>,
    assembler: &mut Assembler,
    wait: Duration,
) -> Option<(u8, Vec<u8>, bool)> {
    let deadline = tokio::time::Instant::now() + wait;
    loop {
        while let Some((frame, n)) = parse_frame(buf, MAX_MESSAGE).unwrap() {
            buf.drain(..n);
            assert!(frame.mask.is_none(), "server frames are not masked");
            if let Some(m) = assembler.push(&frame).unwrap() {
                return Some((m.opcode, m.payload, m.compressed));
            }
        }
        let mut chunk = [0u8; 4096];
        match tokio::time::timeout_at(deadline, s.read(&mut chunk)).await {
            Ok(Ok(0)) | Ok(Err(_)) | Err(_) => return None,
            Ok(Ok(n)) => buf.extend_from_slice(&chunk[..n]),
        }
    }
}

fn start_proxy(env: &Env) -> String {
    let started = env.ok(&["proxy", "start", "--listen", "127.0.0.1:0"]);
    started["listen"].as_str().unwrap().to_string()
}

#[test]
fn websocket_traffic_through_the_proxy_is_recorded() {
    let env = Env::new("record");
    let port = spawn_ws_echo();
    let proxy = start_proxy(&env);
    let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
    rt.block_on(async {
        let mut c = WsClient::connect(&proxy, &format!("http://127.0.0.1:{port}/chat?room=1"), true).await;
        c.send(OP_TEXT, b"hello hello").await;
        let (op, payload, compressed) = c.recv(Duration::from_secs(5)).await.unwrap();
        assert_eq!((op, payload.as_slice(), compressed), (OP_TEXT, &b"echo: hello hello"[..], true));
        // The server's second answer refers back into the first (context takeover).
        c.send(OP_TEXT, b"hello hello").await;
        assert_eq!(c.recv(Duration::from_secs(5)).await.unwrap().1, b"echo: hello hello");
        c.send_fragmented(b"a fragmented secret_value message").await;
        let pong = c.recv(Duration::from_secs(5)).await.unwrap();
        assert_eq!((pong.0, pong.1.as_slice()), (OP_PONG, &b"are you there"[..]));
        assert_eq!(c.recv(Duration::from_secs(5)).await.unwrap().1, b"echo: a fragmented secret_value message");
        c.send(OP_BINARY, &[0, 159, 146, 150]).await;
        assert_eq!(c.recv(Duration::from_secs(5)).await.unwrap().1, b"echo: \x00\x9f\x92\x96");
        c.send(OP_CLOSE, &close_payload(1000, "bye")).await;
        let (op, payload, _) = c.recv(Duration::from_secs(5)).await.unwrap();
        assert_eq!((op, payload), (OP_CLOSE, close_payload(1000, "bye")));
    });

    let conn = env.closed_connection();
    assert_eq!(conn["url"], format!("ws://127.0.0.1:{port}/chat?room=1"));
    assert_eq!(conn["source"], "proxy");
    assert_eq!(conn["close_code"], 1000);
    assert_eq!(conn["close_reason"], "bye");
    assert_eq!(conn["extensions"], "permessage-deflate");
    assert_eq!(conn["error"], Value::Null);
    let id = conn["id"].as_i64().unwrap().to_string();

    let shown = env.ok(&["ws", "show", &id]);
    assert_eq!(shown["handshake"]["response"]["status"], 101);
    assert_eq!(shown["handshake"]["id"], conn["history_id"]);

    let msgs = env.ok(&["ws", "messages", &id]);
    let items = msgs["items"].as_array().unwrap();
    let summary: Vec<(String, String, String)> = items
        .iter()
        .map(|m| {
            (
                m["direction"].as_str().unwrap().into(),
                m["opcode"].as_str().unwrap().into(),
                m["payload"]["content"].as_str().unwrap().into(),
            )
        })
        .collect();
    let row = |d: &str, o: &str, p: &str| (d.to_string(), o.to_string(), p.to_string());
    assert!(summary.contains(&row("to-server", "text", "hello hello")), "{summary:?}");
    assert!(summary.contains(&row("to-client", "text", "echo: hello hello")), "{summary:?}");
    assert!(summary.contains(&row("to-server", "ping", "are you there")), "{summary:?}");
    assert!(summary.contains(&row("to-server", "text", "a fragmented secret_value message")), "{summary:?}");
    let binary = items.iter().find(|m| m["opcode"] == "binary" && m["direction"] == "to-server").unwrap();
    assert_eq!(binary["payload"]["encoding"], "base64");
    let fragmented = items.iter().find(|m| m["fragments"] == 2).unwrap();
    assert_eq!(fragmented["payload"]["content"], "a fragmented secret_value message");
    assert!(items
        .iter()
        .filter(|m| m["direction"] == "to-client" && m["opcode"] == "text")
        .all(|m| m["compressed"] == true));
    assert_eq!(items.len(), 12, "{summary:?}");

    // Filters, SQL, and full-text search.
    let only = env.ok(&["ws", "messages", &id, "--direction", "to-client", "--opcode", "text"]);
    assert_eq!(only["count"], 3);
    let found = env.ok(&["ws", "messages", &id, "--contains", "secret_value"]);
    assert_eq!(found["count"], 2);
    let fts = env.ok(&[
        "query",
        "SELECT direction FROM ws_messages WHERE id IN (SELECT rowid FROM ws_messages_fts WHERE ws_messages_fts MATCH 'secret_value') ORDER BY id",
    ]);
    assert_eq!(fts["rows"], serde_json::json!([["to-server"], ["to-client"]]));
    let schema = env.ok(&["schema"]);
    assert!(schema["tables"].as_array().unwrap().iter().any(|t| t["name"] == "ws_messages"));
}

#[test]
fn websocket_rules_rewrite_messages_each_way() {
    let env = Env::new("rules");
    let port = spawn_ws_echo();
    let proxy = start_proxy(&env);
    let add = |args: &[&str]| env.ok(&[&["rules", "add", "--location"][..], args].concat());
    add(&[
        "ws-message",
        "--match-kind",
        "literal",
        "--match",
        "user",
        "--replace",
        "admin",
        "--applies-to",
        "ws-to-server",
    ]);
    add(&["ws-message", "--match", "^echo: ", "--replace", "", "--applies-to", "ws-to-client"]);
    // Neither a rule for HTTP bodies nor one for another host touches these messages.
    add(&["request-body", "--match", "role", "--replace", "x"]);
    add(&["ws-message", "--match", "role", "--replace", "x", "--host", "^other\\.test$"]);
    std::thread::sleep(Duration::from_millis(700));
    let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
    rt.block_on(async {
        let mut c = WsClient::connect(&proxy, &format!("http://127.0.0.1:{port}/rules"), true).await;
        // The server gets `role admin` and echoes it; the client gets the echo without its prefix.
        c.send(OP_TEXT, b"role user").await;
        let (op, payload, compressed) = c.recv(Duration::from_secs(5)).await.unwrap();
        assert_eq!((op, payload.as_slice(), compressed), (OP_TEXT, &b"role admin"[..], false));
        // A binary message is ruled too, and a ping is not a message to rule.
        c.send(OP_BINARY, b"user\x00").await;
        assert_eq!(c.recv(Duration::from_secs(5)).await.unwrap().1, b"admin\x00");
        c.send(OP_PING, b"user").await;
        assert_eq!(c.recv(Duration::from_secs(5)).await.unwrap(), (OP_PONG, b"user".to_vec(), false));
        c.send(OP_CLOSE, &close_payload(1000, "bye")).await;
        assert_eq!(c.recv(Duration::from_secs(5)).await.unwrap().0, OP_CLOSE);
    });
    // What is recorded is what went on, marked as a rule's doing.
    let id = env.closed_connection()["id"].as_i64().unwrap().to_string();
    let msgs = env.ok(&["ws", "messages", &id]);
    let data: Vec<(&str, &str, &str)> = msgs["items"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|m| m["opcode"] == "text")
        .map(|m| {
            (
                m["direction"].as_str().unwrap(),
                m["payload"]["content"].as_str().unwrap(),
                m["intercept"].as_str().unwrap_or(""),
            )
        })
        .collect();
    assert_eq!(data, [("to-server", "role admin", "rule"), ("to-client", "role admin", "rule")], "{msgs}");
}

#[test]
fn websocket_messages_can_be_intercepted() {
    let env = Env::new("intercept");
    let port = spawn_ws_echo();
    let proxy = start_proxy(&env);
    env.ok(&["intercept", "enable", "--ws-to-server", "--ws-to-client", "--path", "^/held", "--timeout", "30"]);
    // The proxy reloads settings every 300 ms.
    std::thread::sleep(Duration::from_millis(700));

    let (tx, rx) = std::sync::mpsc::channel::<Vec<(u8, Vec<u8>)>>();
    let p = proxy.clone();
    let client = std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
        rt.block_on(async move {
            // The upgrade request itself isn't held: only WebSocket messages are.
            let mut c = WsClient::connect(&p, &format!("http://127.0.0.1:{port}/held"), false).await;
            c.send(OP_TEXT, b"original").await;
            let mut got = Vec::new();
            got.push(c.recv(Duration::from_secs(20)).await.map(|m| (m.0, m.1)).unwrap());
            c.send(OP_TEXT, b"drop me").await;
            c.send(OP_TEXT, b"third").await;
            got.push(c.recv(Duration::from_secs(20)).await.map(|m| (m.0, m.1)).unwrap());
            tx.send(got).unwrap();
            c.send(OP_CLOSE, &close_payload(1000, "")).await;
            c.recv(Duration::from_secs(5)).await;
        });
    });

    let next = |dir: &str| -> String {
        let listed = env.ok(&["intercept", "list", "--wait", "10"]);
        assert_eq!(listed["count"], 1, "{listed}");
        let item = &listed["items"][0];
        assert_eq!((item["direction"].as_str(), item["method"].as_str()), (Some(dir), Some("WS")));
        assert_eq!(item["url"], format!("ws://127.0.0.1:{port}/held"));
        item["id"].as_i64().unwrap().to_string()
    };
    // Edit the client's message, then let the server's answer through unchanged.
    let id = next("ws-to-server");
    let held = env.ok(&["intercept", "show", &id]);
    assert_eq!(held["message"]["content"], "original");
    let edited = env.dir.join("edited.txt");
    // No line-ending or Content-Length fixes on a WebSocket payload.
    std::fs::write(&edited, "edited\n").unwrap();
    env.ok(&["intercept", "forward", &id, "--file", edited.to_str().unwrap()]);
    let id = next("ws-to-client");
    env.ok(&["intercept", "forward", &id]);
    // Drop the next one; the one after goes through.
    let id = next("ws-to-server");
    env.ok(&["intercept", "drop", &id]);
    let id = next("ws-to-server");
    env.ok(&["intercept", "forward", &id]);
    let id = next("ws-to-client");
    env.ok(&["intercept", "forward", &id]);
    let got = rx.recv_timeout(Duration::from_secs(20)).unwrap();
    assert_eq!(got, vec![(OP_TEXT, b"echo: edited\n".to_vec()), (OP_TEXT, b"echo: third".to_vec())]);
    client.join().unwrap();
    env.ok(&["intercept", "disable"]);

    let conn = env.closed_connection();
    let id = conn["id"].as_i64().unwrap().to_string();
    let rows = env.ok(&[
        "query",
        "SELECT payload_text, intercept FROM ws_messages WHERE connection_id = ?1 AND intercept IS NOT NULL ORDER BY id",
        "-p",
        &id,
    ]);
    assert_eq!(rows["rows"], serde_json::json!([["edited\n", "edited"], ["drop me", "dropped"]]));
}

#[test]
fn websocket_messages_are_held_by_their_handshake_request() {
    let env = Env::new("intercept-filter");
    let port = spawn_ws_echo();
    let proxy = start_proxy(&env);
    env.ok(&["intercept", "enable", "--ws-to-server", "--filter", "path:/held", "--timeout", "30"]);
    let (code, v) = env.run(&["intercept", "enable", "--ws-to-server", "--responses", "--filter", "status=101"]);
    assert_eq!((code, v["error"]["kind"].as_str()), (2, Some("invalid_input")), "{v}");
    std::thread::sleep(Duration::from_millis(700));
    let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
    rt.block_on(async {
        let mut c = WsClient::connect(&proxy, &format!("http://127.0.0.1:{port}/free"), false).await;
        c.send(OP_TEXT, b"one").await;
        let got = c.recv(Duration::from_secs(10)).await.map(|m| m.1);
        assert_eq!(got.as_deref(), Some(&b"echo: one"[..]), "not held");
        assert_eq!(env.ok(&["intercept", "list", "--state", "all"])["count"], 0);

        // A new filter is asked again on a connection already open.
        env.ok(&["intercept", "enable", "--ws-to-server", "--filter", "path:/free", "--timeout", "30"]);
        tokio::time::sleep(Duration::from_millis(700)).await;
        c.send(OP_TEXT, b"two").await;
        let listed = env.ok(&["intercept", "list", "--wait", "10"]);
        assert_eq!(listed["count"], 1, "{listed}");
        assert_eq!(listed["items"][0]["url"], format!("ws://127.0.0.1:{port}/free"));
        env.ok(&["intercept", "forward", &listed["items"][0]["id"].as_i64().unwrap().to_string()]);
        let got = c.recv(Duration::from_secs(10)).await.map(|m| m.1);
        assert_eq!(got.as_deref(), Some(&b"echo: two"[..]));
        c.send(OP_CLOSE, &close_payload(1000, "")).await;
        c.recv(Duration::from_secs(5)).await;
    });
    env.ok(&["intercept", "disable"]);
}

#[test]
fn a_filter_on_time_is_asked_again_for_each_websocket_message() {
    let env = Env::new("intercept-time");
    let port = spawn_ws_echo();
    let proxy = start_proxy(&env);
    let cut = env.ok(&["query", "SELECT strftime('%Y-%m-%dT%H:%M:%fZ', 'now', '+3 seconds')"])["rows"][0][0]
        .as_str()
        .unwrap()
        .to_string();
    env.ok(&["intercept", "enable", "--ws-to-server", "--filter", &format!("time>={cut}"), "--timeout", "30"]);
    std::thread::sleep(Duration::from_millis(700));
    let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
    rt.block_on(async {
        let mut c = WsClient::connect(&proxy, &format!("http://127.0.0.1:{port}/clock"), false).await;
        c.send(OP_TEXT, b"early").await;
        let got = c.recv(Duration::from_secs(10)).await.map(|m| m.1);
        assert_eq!(got.as_deref(), Some(&b"echo: early"[..]), "before the cut: not held");
        // Past the cut, on the same connection and with the same filter: held.
        tokio::time::sleep(Duration::from_secs(4)).await;
        c.send(OP_TEXT, b"late").await;
        let listed = env.ok(&["intercept", "list", "--wait", "10"]);
        assert_eq!(listed["count"], 1, "{listed}");
        env.ok(&["intercept", "forward", &listed["items"][0]["id"].as_i64().unwrap().to_string()]);
        let got = c.recv(Duration::from_secs(10)).await.map(|m| m.1);
        assert_eq!(got.as_deref(), Some(&b"echo: late"[..]));
        c.send(OP_CLOSE, &close_payload(1000, "")).await;
        c.recv(Duration::from_secs(5)).await;
    });
    env.ok(&["intercept", "disable"]);
}

#[test]
fn a_held_message_is_resolved_when_its_connection_ends() {
    let env = Env::new("abandoned");
    let port = spawn_ws_echo();
    let proxy = start_proxy(&env);
    env.ok(&["intercept", "enable", "--ws-to-server", "--timeout", "120"]);
    std::thread::sleep(Duration::from_millis(700));
    let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
    rt.block_on(async {
        let mut c = WsClient::connect(&proxy, &format!("http://127.0.0.1:{port}/closes"), false).await;
        c.send(OP_TEXT, b"never decided").await;
        assert_eq!(env.ok(&["intercept", "list", "--wait", "10"])["count"], 1);
        // The server has gone: after the linger the held message gives up, without a decision.
        let deadline = std::time::Instant::now() + Duration::from_secs(20);
        loop {
            if env.ok(&["intercept", "list", "--state", "dropped"])["count"] == 1 {
                break;
            }
            assert!(std::time::Instant::now() < deadline, "{}", env.ok(&["intercept", "list", "--state", "all"]));
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
    });
    assert_eq!(env.ok(&["intercept", "list"])["count"], 0);
    assert_eq!(env.closed_connection()["state"], "closed");
}

#[test]
fn ws_send_reads_messages_from_stdin() {
    let env = Env::new("stdin");
    let port = spawn_ws_echo();
    // Over the 128 KiB a single argument may have on Linux (and Windows' 32 KB command line).
    let big = "x".repeat(200_000);
    let handshake = format!("GET /json HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n\r\n");
    let input = serde_json::json!({"handshake": handshake, "messages": [big, "token=secret"]});
    let target = format!("--target=http://127.0.0.1:{port}");
    let r = env.ok_with_stdin(
        &["ws", "send", &target, "--input-json", "--until", "echo: token", "--max-body=300000"],
        input.to_string().as_bytes(),
    );
    assert_eq!((r["upgraded"].as_bool(), r["stopped"].as_str()), (Some(true), Some("until")), "{r}");
    let last = r["messages"].as_array().unwrap().iter().rfind(|m| m["opcode"] == "text").unwrap().clone();
    assert_eq!(last["payload"]["content"], "echo: token=secret");
    assert!(r["messages"].as_array().unwrap().iter().any(|m| m["payload"]["length"] == 200_006), "{r}");

    // Messages alone, with the handshake from another source; a bad shape is refused.
    let r = env.ok_with_stdin(
        &["ws", "send", "--url", &format!("ws://127.0.0.1:{port}/x"), "--input-json", "--until", "echo"],
        br#"{"messages": ["hi"]}"#,
    );
    assert_eq!(r["stopped"], "until");
    let mut child = Command::new(env!("CARGO_BIN_EXE_brainproxy"))
        .args(["--format", "json", "--project"])
        .arg(&env.project)
        .args(["ws", "send", "--url", "ws://127.0.0.1:1/x", "--input-json"])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    use std::io::Write;
    let _ = child.stdin.take().unwrap().write_all(br#"{"mesages": []}"#);
    let out = child.wait_with_output().unwrap();
    assert_eq!(out.status.code(), Some(2), "{}", String::from_utf8_lossy(&out.stdout));
}

#[test]
fn ws_send_replays_a_connection() {
    let env = Env::new("replay");
    let port = spawn_ws_echo();
    let proxy = start_proxy(&env);
    let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
    rt.block_on(async {
        let mut c = WsClient::connect(&proxy, &format!("http://127.0.0.1:{port}/chat"), true).await;
        c.send(OP_TEXT, b"{\"op\":\"subscribe\"}").await;
        c.recv(Duration::from_secs(5)).await.unwrap();
        c.send(OP_CLOSE, &close_payload(1000, "")).await;
        c.recv(Duration::from_secs(5)).await;
    });
    let conn = env.closed_connection();
    let conn_id = conn["id"].as_i64().unwrap().to_string();
    let first = env.ok(&["ws", "messages", &conn_id, "--direction", "to-server", "--limit", "1"]);
    let msg_id = first["items"][0]["id"].as_i64().unwrap().to_string();

    // Replay the recorded handshake, resend the recorded message, add one, stop on a match.
    let r = env.ok(&["ws", "send", "--from", &conn_id, "--resend", &msg_id, "-m", "second", "--until", "echo: second"]);
    assert_eq!(r["upgraded"], true);
    assert_eq!(r["accept_ok"], true);
    assert_eq!(r["stopped"], "until");
    assert_eq!(r["received"], 2);
    assert_eq!(r["extensions"], "permessage-deflate");
    let texts: Vec<(&str, &str)> = r["messages"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|m| m["opcode"] == "text")
        .map(|m| (m["direction"].as_str().unwrap(), m["payload"]["content"].as_str().unwrap()))
        .collect();
    assert_eq!(
        texts,
        vec![
            ("to-server", "{\"op\":\"subscribe\"}"),
            ("to-server", "second"),
            ("to-client", "echo: {\"op\":\"subscribe\"}"),
            ("to-client", "echo: second")
        ]
    );
    let replay = r["connection_id"].as_i64().unwrap();
    assert!(r["messages"][0]["id"].as_i64().is_some());
    let replayed = env.ok(&["ws", "show", &replay.to_string()]);
    assert_eq!(replayed["connection"]["source"], "replay");
    assert_eq!(replayed["connection"]["state"], "closed");
    let history = env.ok(&["query", "SELECT source, status FROM history ORDER BY id DESC LIMIT 1"]);
    assert_eq!(history["rows"], serde_json::json!([["ws", 101]]));

    // A new handshake from a URL, binary messages, and the wait window.
    let started = std::time::Instant::now();
    let r = env.ok(&[
        "ws",
        "send",
        "--url",
        &format!("ws://127.0.0.1:{port}/fresh"),
        "--binary",
        "-m",
        "AJ+Slg==",
        "--wait",
        "0.5",
        "--no-store",
    ]);
    assert_eq!(r["stopped"], "wait");
    assert_eq!(r["connection_id"], Value::Null);
    assert_eq!(r["messages"][1]["payload"]["encoding"], "base64");
    // --no-store keeps the handshake's request line, and nothing of the connection.
    let row = env.ok(&[
        "query",
        "SELECT request, status, error FROM history WHERE id = ?1",
        "-p",
        &r["history_id"].to_string(),
    ]);
    assert_eq!(
        row["rows"],
        serde_json::json!([[
            "GET /fresh HTTP/1.1\r\n\r\n",
            null,
            "not stored (--no-store): content omitted; response status 101"
        ]])
    );
    assert!(started.elapsed() < Duration::from_secs(5));

    // A 101 after 103 Early Hints is an upgrade; closing on --until still records the server's close.
    let r = env.ok(&["ws", "send", "--url", &format!("ws://127.0.0.1:{port}/hints"), "-m", "x", "--until", "echo"]);
    assert_eq!((r["upgraded"].as_bool(), r["stopped"].as_str()), (Some(true), Some("until")), "{r}");
    assert_eq!(r["close"]["code"], 1000);
    let c = env.ok(&["ws", "show", &r["connection_id"].to_string()]);
    assert_eq!(c["connection"]["close_code"], 1000);

    // A refused upgrade comes back as the response.
    let r = env.ok(&["ws", "send", "--url", &format!("ws://127.0.0.1:{port}/deny"), "-m", "x"]);
    assert_eq!((r["upgraded"].as_bool(), r["response"]["status"].as_u64()), (Some(false), Some(403)));

    // The engagement scope applies.
    let (code, v) = env.run(&["ws", "send", "--url", "ws://192.0.2.1/x", "-m", "x"]);
    assert_eq!((code, v["error"]["kind"].as_str()), (6, Some("out_of_scope")), "{v}");
}

/// Starts `ws send` that keeps listening, and waits until its message and the echo are recorded.
fn ws_send_listening(env: &Env, port: u16) -> std::process::Child {
    let mut child = Command::new(env!("CARGO_BIN_EXE_brainproxy"))
        .args(["--format", "json", "--project"])
        .arg(&env.project)
        .arg("--home")
        .arg(&env.home)
        .args(["ws", "send", "--url", &format!("ws://127.0.0.1:{port}/live"), "-m", "hello", "--wait", "60"])
        .stdout(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    for _ in 0..100 {
        let rows = env.ok(&["query", "SELECT direction, payload_text FROM ws_messages ORDER BY id"])["rows"].clone();
        if rows.as_array().unwrap().len() == 2 {
            assert_eq!(rows, serde_json::json!([["to-server", "hello"], ["to-client", "echo: hello"]]));
            return child;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    let _ = child.kill();
    let _ = child.wait();
    panic!("ws send didn't record its messages as they happened");
}

#[test]
fn ws_send_records_as_it_goes() {
    let env = Env::new("live");
    let port = spawn_ws_echo();
    // Killed while listening: the handshake, the connection, and both messages are on record.
    let mut child = ws_send_listening(&env, port);
    child.kill().unwrap();
    child.wait().unwrap();
    let sql =
        "SELECT c.source, c.state, h.status, h.source FROM ws_connections c JOIN history h ON h.id = c.history_id";
    let c = env.ok(&["query", sql]);
    assert_eq!(c["rows"], serde_json::json!([["replay", "open", 101, "ws"]]));
    // The next look at the connections closes it: its `ws send` no longer holds its lock.
    let l = env.ok(&["ws", "list"]);
    assert_eq!(l["items"][0]["state"], "closed", "{l}");
    assert_eq!(l["items"][0]["error"], "ws send ended without closing it (killed)", "{l}");
    // One whose `ws send` still runs is left open.
    let env = Env::new("live-running");
    let mut child = ws_send_listening(&env, port);
    let l = env.ok(&["ws", "list"]);
    assert_eq!(l["items"][0]["state"], "open", "{l}");
    child.kill().unwrap();
    child.wait().unwrap();
    let l = env.ok(&["ws", "show", &l["items"][0]["id"].to_string()]);
    assert_eq!(l["connection"]["state"], "closed", "{l}");

    // Stopped with SIGTERM: the close is recorded with why.
    #[cfg(unix)]
    {
        let env = Env::new("live-term");
        let child = ws_send_listening(&env, port);
        Command::new("kill").args(["-TERM", &child.id().to_string()]).status().unwrap();
        let out = child.wait_with_output().unwrap();
        assert_ne!(out.status.code(), Some(0));
        let c = env.ok(&["query", "SELECT state, error FROM ws_connections"]);
        assert_eq!(c["rows"], serde_json::json!([["closed", "cancelled by user before a response was recorded"]]));
    }
}
