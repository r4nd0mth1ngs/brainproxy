//! Provenance: every history entry and finding says who or what recorded it (the desktop app,
//! a terminal, or an agent through MCP), proxy entries name the client, and an overridden TLS
//! server name is kept.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant};

use serde_json::Value;

const MCP: &str = "BRAINPROXY_MCP_CALL";
const CLIENT: &str = "BRAINPROXY_CLIENT";

struct Env {
    project: PathBuf,
    home: PathBuf,
}

impl Env {
    fn new(name: &str) -> Self {
        let dir = std::env::temp_dir().join(format!("bp-prov-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let env = Env { project: dir.join("p.bpdb"), home: dir.join("home") };
        env.ok(&[], &["engagement", "start", "--target", "127.0.0.1"]);
        env
    }

    /// Runs the CLI with exactly these provenance variables (the test's own are removed).
    fn run(&self, vars: &[(&str, &str)], args: &[&str]) -> (i32, Value, String) {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_brainproxy"));
        cmd.env_remove(MCP).env_remove(CLIENT).envs(vars.iter().copied());
        let out = cmd
            .args(["--format", "json", "--project"])
            .arg(&self.project)
            .arg("--home")
            .arg(&self.home)
            .args(args)
            .output()
            .unwrap();
        let text = String::from_utf8_lossy(&out.stdout).into_owned();
        let v = serde_json::from_str(&text).unwrap_or(Value::Null);
        (out.status.code().unwrap(), v, text)
    }

    fn ok(&self, vars: &[(&str, &str)], args: &[&str]) -> Value {
        let (code, v, text) = self.run(vars, args);
        assert_eq!(code, 0, "{args:?} -> {text}");
        v["data"].clone()
    }

    fn text(&self, args: &[&str]) -> String {
        let out = Command::new(env!("CARGO_BIN_EXE_brainproxy"))
            .args(["--format", "text", "--project"])
            .arg(&self.project)
            .args(args)
            .output()
            .unwrap();
        String::from_utf8_lossy(&out.stdout).into_owned()
    }

    fn rows(&self, sql: &str) -> Vec<Value> {
        self.ok(&[], &["query", sql])["rows"].as_array().unwrap().clone()
    }
}

impl Drop for Env {
    fn drop(&mut self) {
        let _ = self.run(&[], &["proxy", "stop"]);
    }
}

/// Answers every connection with a small HTML page (no security headers, so the passive scan
/// has findings), or 101 for a WebSocket upgrade.
fn serve() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut s) = stream else { continue };
            std::thread::spawn(move || {
                let mut buf = vec![0u8; 8192];
                let mut len = 0;
                while !buf[..len].windows(4).any(|w| w == b"\r\n\r\n") {
                    match s.read(&mut buf[len..]) {
                        Ok(0) | Err(_) => return,
                        Ok(n) => len += n,
                    }
                }
                let req = String::from_utf8_lossy(&buf[..len]).to_ascii_lowercase();
                if req.contains("\r\nupgrade: websocket") {
                    let _ = s.write_all(
                        b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\
                          Sec-WebSocket-Accept: x\r\n\r\n",
                    );
                    let _ = s.read(&mut buf);
                    return;
                }
                let body = "<html><head><title>t</title></head><body>hi</body></html>";
                let resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = s.write_all(resp.as_bytes());
            });
        }
    });
    port
}

fn wait_for(env: &Env, sql: &str, n: i64) {
    let deadline = Instant::now() + Duration::from_secs(10);
    while env.rows(sql)[0][0].as_i64().unwrap() < n && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(50));
    }
    assert_eq!(env.rows(sql)[0][0].as_i64().unwrap(), n, "{sql}");
}

#[test]
fn history_says_who_recorded_each_entry() {
    let port = serve();
    let env = Env::new("origin");
    let url = format!("http://127.0.0.1:{port}/");
    env.ok(&[], &["send", "--url", &url]);
    env.ok(&[(CLIENT, "gui")], &["send", "--url", &url]);
    // An MCP tool call wins over anything else in the environment.
    env.ok(&[(MCP, "1"), (CLIENT, "gui")], &["send", "--url", &url]);
    // Only "gui" means the app.
    env.ok(&[(CLIENT, "mcp")], &["send", "--url", &url]);

    let rows = env.rows("SELECT origin FROM history ORDER BY id");
    let origins: Vec<&str> = rows.iter().map(|r| r[0].as_str().unwrap()).collect();
    assert_eq!(origins, ["cli", "gui", "mcp", "cli"]);

    let list = env.ok(&[], &["history", "list", "--origin", "mcp"]);
    assert_eq!(list["count"], 1, "{list}");
    assert_eq!(list["items"][0]["id"], 3);
    assert_eq!(list["items"][0]["origin"], "mcp");
    assert_eq!(env.ok(&[], &["history", "list", "--origin", "unknown"])["count"], 0);
    let (code, _, _) = env.run(&[], &["history", "list", "--origin", "nobody"]);
    assert_eq!(code, 2);

    let show = env.ok(&[], &["history", "show", "3"]);
    assert_eq!(show["entry"]["origin"], "mcp");
    assert_eq!(show["origin_text"], "recorded via MCP (an agent)");
    assert!(env.text(&["history", "show", "2"]).starts_with("#2 send recorded from the desktop app\n"));
    assert!(env.text(&["history", "list"]).lines().nth(2).unwrap().ends_with("mcp"));
}

#[test]
fn a_background_job_records_the_origin_that_started_it() {
    let port = serve();
    let env = Env::new("job");
    let site = format!("http://127.0.0.1:{port}/");
    let started = env.ok(&[(CLIENT, "gui")], &["crawl", "--background", "--no-robots", "--no-sitemap", "--", &site]);
    let id = started["job"].as_i64().unwrap().to_string();
    let done = env.ok(&[], &["job", "wait", &id, "--timeout", "30"]);
    assert_eq!(done["state"], "completed", "{done}");
    let rows = env.rows("SELECT DISTINCT origin FROM history WHERE source = 'crawl'");
    assert_eq!(rows, vec![serde_json::json!(["gui"])]);
}

#[test]
fn a_proxy_started_by_an_agent_records_mcp_and_each_client() {
    let port = serve();
    let env = Env::new("proxy");
    let started = env.ok(&[(MCP, "1")], &["proxy", "start", "--listen", "127.0.0.1:0"]);
    let listen = started["listen"].as_str().unwrap().to_string();

    // A plain proxied request.
    let mut s = TcpStream::connect(&listen).unwrap();
    let local = s.local_addr().unwrap().to_string();
    write!(s, "GET http://127.0.0.1:{port}/page HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nConnection: close\r\n\r\n")
        .unwrap();
    let mut resp = Vec::new();
    s.read_to_end(&mut resp).unwrap();
    assert!(resp.starts_with(b"HTTP/1.1 200"), "{}", String::from_utf8_lossy(&resp));

    // A WebSocket upgrade, recorded when the connection opens.
    let mut ws = TcpStream::connect(&listen).unwrap();
    let ws_local = ws.local_addr().unwrap().to_string();
    write!(
        ws,
        "GET http://127.0.0.1:{port}/ws HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nUpgrade: websocket\r\n\
         Connection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n"
    )
    .unwrap();
    let mut head = [0u8; 12];
    ws.read_exact(&mut head).unwrap();
    assert_eq!(&head, b"HTTP/1.1 101");

    wait_for(&env, "SELECT count(*) FROM history WHERE source = 'proxy'", 2);
    let rows = env.rows("SELECT path, origin, client_addr FROM history WHERE source = 'proxy' ORDER BY path");
    assert_eq!(rows[0], serde_json::json!(["/page", "mcp", local]));
    assert_eq!(rows[1], serde_json::json!(["/ws", "mcp", ws_local]));
    drop(ws);
    let list = env.ok(&[], &["history", "list", "--source", "proxy"]);
    assert_eq!(list["items"][0]["client_addr"], local.as_str());

    // The proxy's passive scan added the findings: an agent's, as the proxy is.
    wait_for(&env, "SELECT count(*) > 0 FROM findings", 1);
    let all = env.ok(&[], &["findings", "list", "--all"]);
    let first = &all["items"][0];
    assert_eq!(first["origin"], "mcp", "{all}");
    assert!(first["state_origin"].is_null() && first["state_changed_at"].is_null());
    let id = first["id"].as_i64().unwrap().to_string();
    let shown = env.ok(&[], &["findings", "show", &id]);
    assert_eq!(shown["origin_text"], "added via MCP (an agent)");

    // Hiding a finding says who did it, and when.
    env.ok(&[(MCP, "1")], &["findings", "mark", &id, "--state", "false-positive"]);
    let shown = env.ok(&[], &["findings", "show", &id]);
    assert_eq!(shown["state_origin"], "mcp");
    assert!(shown["state_changed_at"].as_str().is_some_and(|t| t.ends_with('Z')), "{shown}");
    // A note alone isn't a state change.
    env.ok(&[(CLIENT, "gui")], &["findings", "mark", &id, "--note", "checked"]);
    assert_eq!(env.ok(&[], &["findings", "show", &id])["state_origin"], "mcp");
    env.ok(&[(CLIENT, "gui")], &["findings", "mark", &id, "--state", "open"]);
    assert_eq!(env.ok(&[], &["findings", "show", &id])["state_origin"], "gui");

    for (kind, needle) in [
        ("markdown", "added via MCP (an agent)"),
        ("html", "via MCP (an agent)"),
        ("sarif", "\"origin\": \"mcp\""),
        ("json", "\"origin\": \"mcp\""),
    ] {
        let out = Path::new(&env.home).with_extension(format!("report.{kind}"));
        env.ok(&[], &["report", kind, "--output", out.to_str().unwrap()]);
        let text = std::fs::read_to_string(&out).unwrap();
        assert!(text.contains(needle), "{kind}: {needle}");
    }
}

#[test]
fn an_overridden_server_name_is_recorded() {
    // Accepts and closes: the TLS handshake fails, and the attempt is recorded with its SNI.
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for s in listener.incoming() {
            drop(s);
        }
    });
    let http = serve();
    let env = Env::new("sni");
    let https = format!("https://127.0.0.1:{port}/");
    let (code, _, _) = env.run(&[], &["send", "--url", &https, "--sni", "app.test"]);
    assert_ne!(code, 0);
    let (code, _, _) = env.run(&[], &["send", "--url", &https]);
    assert_ne!(code, 0);
    // Plain HTTP sends no server name at all.
    env.ok(&[], &["send", "--url", &format!("http://127.0.0.1:{http}/"), "--sni", "app.test"]);

    let rows = env.rows("SELECT sni FROM history ORDER BY id");
    assert_eq!(rows, vec![serde_json::json!(["app.test"]), serde_json::json!([null]), serde_json::json!([null])]);
    assert_eq!(env.ok(&[], &["history", "show", "1"])["entry"]["sni"], "app.test");
    assert!(env.text(&["history", "show", "1"]).lines().next().unwrap().ends_with("TLS server name (SNI) app.test"));
}
