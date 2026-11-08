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
        Self::with_scope(name, &["--target", "127.0.0.1"])
    }

    /// A project whose engagement is started with `scope`.
    fn with_scope(name: &str, scope: &[&str]) -> Self {
        let dir = std::env::temp_dir().join(format!("bp-prov-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let env = Env { project: dir.join("p.bpdb"), home: dir.join("home") };
        env.ok(&[], &[&["engagement", "start"][..], scope].concat());
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
    assert_eq!(env.rows("SELECT origin FROM jobs"), vec![serde_json::json!(["gui"])]);
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
    wait_for(&env, "SELECT count(*) FROM ws_connections WHERE origin = 'mcp'", 1);
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
    // The scope lists app.test by name, so it may be sent in place of 127.0.0.1.
    let env = Env::with_scope("sni", &["--target", "127.0.0.1", "--target", "app.test"]);
    let https = format!("https://127.0.0.1:{port}/");
    let (code, _, _) = env.run(&[], &["send", "--url", &https, "--sni", "app.test"]);
    assert_ne!(code, 0);
    let (code, _, _) = env.run(&[], &["send", "--url", &https]);
    assert_ne!(code, 0);
    // Plain HTTP sends no server name at all.
    env.ok(&[], &["send", "--url", &format!("http://127.0.0.1:{http}/"), "--sni", "app.test"]);
    // Nor does an IP address: it can't be a server name.
    let (code, _, _) = env.run(&[], &["send", "--url", &https, "--sni", "127.0.0.1"]);
    assert_ne!(code, 0);
    // HTTP/2, a race and a WebSocket handshake record it too.
    let (code, _, _) = env.run(&[], &["send", "--url", &https, "--sni", "app.test", "--http2"]);
    assert_ne!(code, 0);
    // A race reports each copy's failure, as its rows do.
    env.ok(&[], &["send", "--url", &https, "--sni", "app.test", "--race", "2"]);
    let wss = format!("wss://127.0.0.1:{port}/");
    let (code, _, _) = env.run(&[], &["ws", "send", "--url", &wss, "--sni", "app.test", "--wait", "1"]);
    assert_ne!(code, 0);
    let fuzz = format!("{https}?q=§x§");
    env.run(&[], &["fuzz", "run", "--url", &fuzz, "-p", "list:a,b", "-c", "1", "--sni", "app.test"]);
    // A name the scope doesn't list is refused before a row could say it was sent.
    let refused: [&[&str]; 4] = [
        &["send", "--url", &https],
        &["send", "--url", &https, "--race", "2"],
        &["ws", "send", "--url", &wss],
        &["fuzz", "run", "--url", &fuzz, "-p", "list:a"],
    ];
    for args in refused {
        let (code, v, _) = env.run(&[], &[args, &["--sni", "other-tenant.test"]].concat());
        assert_ne!(code, 0, "{args:?}");
        assert!(v["error"]["message"].as_str().unwrap().contains("--sni other-tenant.test"), "{v}");
    }

    let rows = env.rows("SELECT sni FROM history ORDER BY id");
    let (app, null) = (serde_json::json!(["app.test"]), serde_json::json!([null]));
    let want = [&app, &null, &null, &null, &app, &app, &app, &app, &app, &app].map(Clone::clone);
    assert_eq!(rows, want.to_vec());
    assert_eq!(env.ok(&[], &["history", "show", "1"])["entry"]["sni"], "app.test");
    assert!(env.text(&["history", "show", "1"]).lines().next().unwrap().ends_with("TLS server name (SNI) app.test"));
}

#[test]
fn a_foreign_host_is_sent_with_a_warning_but_an_agent_must_say_it_is_a_test() {
    let port = serve();
    // The scope lists app.test by name, so a Host naming it is not another site's.
    let env = Env::with_scope("host", &["--target", "127.0.0.1", "--target", "app.test"]);
    let url = format!("http://127.0.0.1:{port}/");
    let ws = format!("ws://127.0.0.1:{port}/");
    let fuzz = format!("{url}?q=§x§");
    let senders: [&[&str]; 4] = [
        &["send", "--url", &url],
        &["send", "--url", &url, "--race", "2"],
        &["ws", "send", "--url", &ws, "--wait", "0"],
        &["fuzz", "run", "--url", &fuzz, "-p", "list:a", "-c", "1"],
    ];
    let agent = [(MCP, "1")];
    let count = || env.rows("SELECT count(*) FROM history")[0][0].as_i64().unwrap();
    for sender in senders {
        let args = [sender, &["-H", "Host: other-tenant.test"]].concat();
        // Refused to an agent before a row could say it was sent.
        let before = count();
        let (code, v, _) = env.run(&agent, &args);
        assert_ne!(code, 0, "{args:?}");
        assert_eq!(v["error"]["kind"], "out_of_scope", "{v}");
        let message = v["error"]["message"].as_str().unwrap();
        assert!(message.contains("Host other-tenant.test") && message.contains("--host-header-test"), "{v}");
        assert_eq!(count(), before, "{args:?}");
        // Sent with a warning for a person, and for an agent that says it is a Host-header test.
        for (vars, test) in [(&[][..], &[][..]), (&agent[..], &["--host-header-test"][..])] {
            let data = env.ok(vars, &[&args[..], test].concat());
            assert!(data["host_warning"].as_str().unwrap().contains("other-tenant.test"), "{args:?}: {data}");
        }
        // The target's own host and a name the scope lists are no one else's.
        for host in [format!("Host: 127.0.0.1:{port}"), "Host: APP.test".into()] {
            let data = env.ok(&agent, &[sender, &["-H", &host]].concat());
            assert!(data.get("host_warning").is_none(), "{args:?}: {data}");
        }
    }
    // A payload position in the Host header is a Host-header test too.
    let (code, v, _) = env.run(&agent, &["fuzz", "run", "--url", &url, "-p", "list:a", "-H", "Host: §x§.app.test"]);
    assert_ne!(code, 0);
    assert!(v["error"]["message"].as_str().unwrap().contains("--host-header-test"), "{v}");
    // So is an absolute request target naming another host, sent to an in-scope one.
    let raw = std::env::temp_dir().join(format!("bp-prov-{}-host.http", std::process::id()));
    std::fs::write(&raw, "GET http://other-tenant.test/ HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n").unwrap();
    let raw_send = ["send", raw.to_str().unwrap(), "--target", &url];
    let (code, v, _) = env.run(&agent, &raw_send);
    assert_eq!((code != 0, &v["error"]["kind"]), (true, &"out_of_scope".into()), "{v}");
    // In text mode the warning goes to stderr, before anything is sent.
    let out = Command::new(env!("CARGO_BIN_EXE_brainproxy"))
        .env_remove(MCP)
        .args(["--format", "text", "--project"])
        .arg(&env.project)
        .args(raw_send)
        .output()
        .unwrap();
    assert!(out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.starts_with("warning: the Host names other-tenant.test"), "{stderr}");
    let _ = std::fs::remove_file(raw);
}

#[test]
fn a_request_target_that_isnt_a_path_is_never_sent_over_http2_and_a_listed_port_is_enough() {
    let port = serve();
    let env = Env::with_scope("h2-target", &["--target", "127.0.0.1", "--target", "app.test:8443"]);
    let raw = env.project.with_extension("h2.http");
    let target = format!("http://127.0.0.1:{port}");
    // `.evil.test/` would run into the authority (app.test.evil.test), for anyone.
    for t in [".evil.test/", "@evil.test/"] {
        std::fs::write(&raw, format!("GET {t} HTTP/2\r\nHost: app.test\r\n\r\n")).unwrap();
        let (code, v, _) = env.run(&[], &["send", raw.to_str().unwrap(), "--target", &target]);
        assert_ne!(code, 0, "{t}");
        assert!(v["error"]["message"].as_str().unwrap().contains("isn't a path"), "{v}");
    }
    // A name the scope lists on another port is listed, with that port or without one.
    for host in ["Host: app.test", "Host: app.test:8443"] {
        let saved = env.ok(&[(MCP, "1")], &["auth", "add", "p", "-H", host]);
        assert!(saved.get("host_warning").is_none(), "{host}: {saved}");
    }
    assert_eq!(env.rows("SELECT count(*) FROM history")[0][0], 0);
}

#[test]
fn a_person_sets_a_foreign_host_on_requests_to_come_with_a_warning() {
    let env = Env::new("host-settings");
    let profile = env.ok(&[], &["auth", "add", "p", "-H", "Host: other-tenant.test"]);
    assert!(profile["host_warning"].as_str().unwrap().contains("auth profile p: header sets the Host"), "{profile}");
    let args = ["rules", "add", "--location", "request-header", "--replace", "Host: other-tenant.test"];
    let rules = env.ok(&[], &args);
    assert!(rules["host_warning"].as_str().unwrap().contains("rule 1 sets the Host to other-tenant.test"), "{rules}");
    // An agent's is refused without saying it is a Host-header test.
    let (code, v, _) = env.run(&[(MCP, "1")], &args);
    assert_ne!(code, 0);
    assert_eq!(v["error"]["kind"], "out_of_scope", "{v}");
}

/// Sends one request through the proxy and returns the response.
fn through(listen: &str, port: u16, path: &str, headers: &str) -> String {
    let mut s = TcpStream::connect(listen).unwrap();
    write!(
        s,
        "GET http://127.0.0.1:{port}{path} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n{headers}Connection: close\r\n\r\n"
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

#[test]
fn an_agents_intercept_edit_and_rule_in_a_proxy_the_app_started_say_so() {
    let port = serve();
    let env = Env::new("edits");
    let gui = [(CLIENT, "gui")];
    let agent = [(MCP, "1")];
    let started = env.ok(&gui, &["proxy", "start", "--listen", "127.0.0.1:0"]);
    let listen = started["listen"].as_str().unwrap().to_string();

    // A person's request is held, and the agent forwards an edited one.
    env.ok(&gui, &["intercept", "enable", "--timeout", "30"]);
    wait_for_settings();
    let l = listen.clone();
    let person = std::thread::spawn(move || through(&l, port, "/human", ""));
    let listed = env.ok(&agent, &["intercept", "list", "--wait", "10"]);
    let id = listed["items"][0]["id"].as_i64().unwrap();
    let held = env.ok(&agent, &["intercept", "show", &id.to_string()]);
    let edited = env.project.with_extension("edited.http");
    std::fs::write(&edited, held["message"]["content"].as_str().unwrap().replace("/human", "/agent-edited")).unwrap();
    let fwd = env.ok(&agent, &["intercept", "forward", &id.to_string(), "--file", edited.to_str().unwrap()]);
    assert_eq!(fwd["resolved_by"], "mcp");
    assert!(person.join().unwrap().starts_with("HTTP/1.1 200"));

    // The intercept says who resolved it and that it was edited.
    let all = env.ok(&[], &["intercept", "list", "--state", "all"]);
    assert_eq!((&all["items"][0]["resolved_by"], &all["items"][0]["edited"]), (&"mcp".into(), &true.into()), "{all}");

    // The row is the GUI proxy's, and names the agent's edit.
    wait_for(&env, "SELECT count(*) FROM history WHERE path = '/agent-edited'", 1);
    let rows = env.rows("SELECT id, origin, edited_by FROM history WHERE path = '/agent-edited'");
    assert_eq!(rows[0][1], "gui");
    let edits: Value = serde_json::from_str(rows[0][2].as_str().unwrap()).unwrap();
    assert_eq!(edits, serde_json::json!([{"by": "mcp", "intercept": id}]));
    let hid = rows[0][0].as_i64().unwrap().to_string();
    let shown = env.ok(&[], &["history", "show", &hid]);
    assert_eq!(shown["entry"]["edited_by"], edits);
    assert_eq!(shown["origin_text"], "recorded by a proxy started from the desktop app");
    let text = env.text(&["history", "show", &hid]);
    let about = text.lines().next().unwrap();
    assert!(
        about.starts_with(&format!(
            "#{hid} proxy recorded by a proxy started from the desktop app · sent by proxy client "
        )),
        "{about}"
    );
    assert!(about.contains(&format!("edited in intercept {id} via MCP (an agent)")), "{about}");
    assert!(env
        .text(&["history", "list"])
        .lines()
        .any(|l| l.contains("/agent-edited") && l.ends_with("gui  edited by mcp")));

    // An edit that brings in a Host the scope doesn't list must say it is a Host-header test.
    let l = listen.clone();
    // The person's request names a foreign host of its own, which the edit keeps: the one it adds
    // is still checked.
    let person = std::thread::spawn(move || through(&l, port, "/tenant", "Host: first-tenant.test\r\n"));
    let listed = env.ok(&agent, &["intercept", "list", "--wait", "10"]);
    let id3 = listed["items"][0]["id"].as_i64().unwrap().to_string();
    let held = env.ok(&agent, &["intercept", "show", &id3]);
    let mut lines: Vec<&str> = held["message"]["content"].as_str().unwrap().lines().filter(|l| !l.is_empty()).collect();
    lines.push("Host: other-tenant.test");
    std::fs::write(&edited, format!("{}\r\n\r\n", lines.join("\r\n"))).unwrap();
    let forward = ["intercept", "forward", &id3, "--file", edited.to_str().unwrap()];
    let (code, v, _) = env.run(&agent, &forward);
    assert_ne!(code, 0);
    assert_eq!(v["error"]["kind"], "out_of_scope", "{v}");
    assert!(v["error"]["message"].as_str().unwrap().contains("--host-header-test"), "{v}");
    let fwd = env.ok(&agent, &[&forward[..], &["--host-header-test"]].concat());
    assert!(fwd["host_warning"].as_str().unwrap().contains("other-tenant.test"), "{fwd}");
    assert!(person.join().unwrap().starts_with("HTTP/1.1 200"));

    // Forwarded unchanged: no edit on either record.
    let l = listen.clone();
    let person = std::thread::spawn(move || through(&l, port, "/as-is", ""));
    let listed = env.ok(&gui, &["intercept", "list", "--wait", "10"]);
    let id2 = listed["items"][0]["id"].as_i64().unwrap().to_string();
    env.ok(&gui, &["intercept", "forward", &id2]);
    person.join().unwrap();
    env.ok(&gui, &["intercept", "disable"]);
    wait_for(&env, "SELECT count(*) FROM history WHERE path = '/as-is'", 1);
    assert_eq!(env.rows("SELECT edited_by FROM history WHERE path = '/as-is'")[0][0], Value::Null);
    let all = env.ok(&[], &["intercept", "list", "--state", "all"]);
    assert_eq!((&all["items"][2]["resolved_by"], &all["items"][2]["edited"]), (&"gui".into(), &false.into()));

    // A rule the agent added changes the person's request: the row names the rule and the agent.
    let rules = env.ok(
        &agent,
        &["rules", "add", "--location", "request-header", "--match", "^X-Role: user$", "--replace", "X-Role: admin"],
    );
    assert_eq!(rules["rules"][0]["origin"], "mcp");
    // One that matches nothing changes nothing.
    env.ok(&gui, &["rules", "add", "--location", "request-line", "--match", "^NEVER ", "--replace", "X "]);
    wait_for_settings();
    through(&listen, port, "/ruled", "X-Role: user\r\n");
    through(&listen, port, "/unruled", "");
    wait_for(&env, "SELECT count(*) FROM history WHERE path IN ('/ruled', '/unruled')", 2);
    let rows = env.rows(
        "SELECT path, origin, edited_by, req_headers FROM history WHERE path IN ('/ruled', '/unruled') ORDER BY path",
    );
    assert_eq!(rows[0][1], "gui");
    assert_eq!(
        serde_json::from_str::<Value>(rows[0][2].as_str().unwrap()).unwrap(),
        serde_json::json!([{"by": "mcp", "rule": 1}])
    );
    assert!(rows[0][3].as_str().unwrap().contains("admin"));
    assert_eq!(rows[1][2], Value::Null);
}

#[test]
fn a_rescan_keeps_a_persons_triage() {
    let port = serve();
    let env = Env::new("rescan");
    let url = format!("http://127.0.0.1:{port}/");
    env.ok(&[(CLIENT, "gui")], &["send", "--url", &url]);
    let all = env.ok(&[(CLIENT, "gui")], &["findings", "list", "--all"]);
    let count = all["count"].as_i64().unwrap();
    assert!(count >= 2, "{all}");
    let (fp, open) = (all["items"][0]["id"].as_i64().unwrap(), all["items"][1]["id"].as_i64().unwrap());
    env.ok(
        &[(CLIENT, "gui")],
        &["findings", "mark", &fp.to_string(), "--state", "false-positive", "--note", "checked by a person"],
    );

    // The agent rescans: the same findings, with their ids, state, note and who set them.
    let stats = env.ok(&[(MCP, "1")], &["scan", "passive", "--rescan"]);
    assert_eq!((stats["new_findings"].as_i64(), stats["removed"].as_i64()), (Some(0), Some(0)), "{stats}");
    let f = env.ok(&[], &["findings", "show", &fp.to_string()]);
    assert_eq!((f["state"].as_str(), f["note"].as_str()), (Some("false_positive"), Some("checked by a person")));
    assert_eq!(
        (f["origin"].as_str(), f["state_origin"].as_str(), f["note_origin"].as_str()),
        (Some("gui"), Some("gui"), Some("gui"))
    );
    assert_eq!(f["hits"], 1);
    assert_eq!(env.ok(&[], &["findings", "show", &open.to_string()])["origin"], "gui");
    assert_eq!(env.rows("SELECT count(*) FROM findings")[0][0].as_i64(), Some(count));

    // Rules turned off: the untriaged finding goes, the triaged one stays, with 0 hits.
    let rule = |id: i64| env.ok(&[], &["findings", "show", &id.to_string()])["rule_id"].to_string();
    env.ok(&[(MCP, "1")], &["scan", "disable", &rule(fp), &rule(open)]);
    let stats = env.ok(&[(MCP, "1")], &["scan", "passive", "--rescan"]);
    assert_eq!(stats["kept_not_found"], 1, "{stats}");
    assert!(stats["removed"].as_i64().unwrap() >= 1, "{stats}");
    let f = env.ok(&[], &["findings", "show", &fp.to_string()]);
    assert_eq!(
        (f["state"].as_str(), f["hits"].as_i64(), f["state_origin"].as_str()),
        (Some("false_positive"), Some(0), Some("gui"))
    );
    let (code, _, _) = env.run(&[], &["findings", "show", &open.to_string()]);
    assert_ne!(code, 0);
}

#[test]
fn reports_say_who_triaged_each_finding() {
    let port = serve();
    let env = Env::new("report");
    env.ok(&[], &["send", "--url", &format!("http://127.0.0.1:{port}/")]);
    let all = env.ok(&[], &["findings", "list", "--all"]);
    assert!(all["count"].as_i64().unwrap() >= 3, "{all}");
    let id = |i: usize| all["items"][i]["id"].as_i64().unwrap();
    let (by_agent, by_person, hidden) = (id(0), id(1), id(2));
    env.ok(&[(MCP, "1")], &["findings", "mark", &by_agent.to_string(), "--state", "confirmed"]);
    env.ok(
        &[(CLIENT, "gui")],
        &["findings", "mark", &by_person.to_string(), "--state", "confirmed", "--note", "seen it"],
    );
    env.ok(&[(MCP, "1")], &["findings", "mark", &hidden.to_string(), "--state", "false-positive", "--note", "noise"]);

    let report = |kind: &str| {
        let out = env.project.with_extension(format!("report.{kind}"));
        env.ok(&[], &["report", kind, "--output", out.to_str().unwrap(), "--force"]);
        std::fs::read_to_string(&out).unwrap()
    };

    let json: Value = serde_json::from_str(&report("json")).unwrap();
    let insts: Vec<&Value> =
        json["alerts"].as_array().unwrap().iter().flat_map(|g| g["instances"].as_array().unwrap()).collect();
    let inst = |id: i64| *insts.iter().find(|i| i["id"] == id).unwrap();
    assert_eq!(inst(by_agent)["state_origin"], "mcp");
    assert!(inst(by_agent)["state_changed_at"].as_str().is_some_and(|t| t.ends_with('Z')));
    assert!(inst(by_agent)["state_text"].as_str().unwrap().starts_with("confirmed via MCP (an agent) at "));
    assert_eq!((&inst(by_person)["state_origin"], &inst(by_person)["note_origin"]), (&"gui".into(), &"gui".into()));
    assert!(insts.iter().all(|i| i["id"] != hidden), "a false positive isn't listed as an issue");
    assert_eq!(json["summary"]["false_positives_left_out"], serde_json::json!([{"origin": "mcp", "count": 1}]));
    assert_eq!(json["agent_false_positives"][0]["id"], hidden);
    assert_eq!(json["agent_false_positives"][0]["note"], "noise");

    let md = report("markdown");
    assert!(
        md.contains(&format!("Finding #{by_agent} · ")) && md.contains("· confirmed via MCP (an agent) at "),
        "{md}"
    );
    assert!(md.contains("· confirmed from the desktop app at "), "{md}");
    assert!(md.contains("- Note (written from the desktop app at "), "{md}");
    assert!(md.contains("1 finding marked false positive is left out of this report: 1 via MCP (an agent)."), "{md}");
    assert!(md.contains("## Marked false positive by an agent") && md.contains(&format!("- #{hidden} ")), "{md}");

    let html = report("html");
    // The tag says who confirmed it; only a person's confirmation reads as the tester's.
    // Once on the finding, once where "About this report" explains it.
    assert_eq!(html.matches("<span class=\"tag\">confirmed via MCP (an agent)</span>").count(), 2, "{html}");
    assert!(html.contains("<span class=\"tag\">confirmed</span></td>"), "{html}");
    assert!(html.contains("checked by the tester, from the desktop app or the command line"));
    assert!(html.contains("<h2 id=\"agent-fp\">Marked false positive by an agent</h2>"));

    let sarif: Value = serde_json::from_str(&report("sarif")).unwrap();
    let results = sarif["runs"][0]["results"].as_array().unwrap();
    let res = results.iter().find(|r| r["properties"]["findingId"] == by_agent).unwrap();
    assert_eq!(res["properties"]["stateOrigin"], "mcp");
    assert!(res["properties"]["stateChangedAt"].is_string());
    assert_eq!(sarif["runs"][0]["properties"]["agentFalsePositives"][0]["id"], hidden);

    // With false positives asked for, they are in the report and not counted as left out.
    let out = env.project.with_extension("fp.json");
    env.ok(&[], &["report", "json", "--state", "all", "--output", out.to_str().unwrap()]);
    let all: Value = serde_json::from_str(&std::fs::read_to_string(&out).unwrap()).unwrap();
    assert_eq!(all["summary"]["false_positives_left_out"], serde_json::json!([]));
    assert_eq!(all["agent_false_positives"], serde_json::json!([]));
}

/// A finding added by hand says who added it everywhere it shows, and removing it or replacing
/// its title's shared text records who did that and when. An agent's never reads as found by
/// hand, and an agent can do neither of the two.
#[test]
fn findings_added_by_hand_say_who_added_and_removed_them() {
    let env = Env::new("manual");
    let add = |vars: &[(&str, &str)], title: &str, url: &str, more: &[&str]| {
        let mut args = vec!["findings", "add", "--title", title, "--risk", "high", "--url", url];
        args.extend_from_slice(more);
        env.ok(vars, &args)["finding"]["id"].as_i64().unwrap()
    };
    let by_agent = add(&[(MCP, "1")], "Agent IDOR", "http://127.0.0.1:9/agent", &["--description", "agent text"]);
    let by_person = add(&[(CLIENT, "gui")], "Person IDOR", "http://127.0.0.1:9/person", &["--description", "first"]);

    // findings list and show.
    let items = env.ok(&[], &["findings", "list", "--all", "--source", "manual"])["items"].as_array().unwrap().clone();
    let item = |id: i64| items.iter().find(|i| i["id"] == id).unwrap().clone();
    assert_eq!((item(by_agent)["origin"].as_str(), item(by_person)["origin"].as_str()), (Some("mcp"), Some("gui")));
    let show = |id: i64| env.ok(&[], &["findings", "show", &id.to_string()]);
    assert_eq!(show(by_agent)["origin_text"], "added via MCP (an agent)");
    assert_eq!(show(by_person)["origin_text"], "added from the desktop app");

    // Every report format.
    let report = |kind: &str, more: &[&str]| {
        let out = env.project.with_extension(format!("manual.{kind}"));
        let mut args = vec!["report", kind, "--output", out.to_str().unwrap(), "--force"];
        args.extend_from_slice(more);
        env.ok(&[], &args);
        std::fs::read_to_string(&out).unwrap()
    };
    let json: Value = serde_json::from_str(&report("json", &[])).unwrap();
    let insts: Vec<&Value> =
        json["alerts"].as_array().unwrap().iter().flat_map(|g| g["instances"].as_array().unwrap()).collect();
    let inst = |id: i64| *insts.iter().find(|i| i["id"] == id).unwrap();
    assert_eq!((inst(by_agent)["origin"].as_str(), inst(by_person)["origin"].as_str()), (Some("mcp"), Some("gui")));
    let md = report("markdown", &[]);
    assert!(
        md.contains(&format!("Finding #{by_agent} · manual · ")) && md.contains("added via MCP (an agent)"),
        "{md}"
    );
    assert!(md.contains("added from the desktop app"), "{md}");
    let html = report("html", &[]);
    let row = |path: &str| {
        let at = html.find(&format!("http://127.0.0.1:9/{path}</code>")).unwrap();
        html[at..at + html[at..].find("</td>").unwrap()].to_string()
    };
    assert!(row("agent").contains("added via MCP (an agent)") && !row("agent").contains("found by hand"), "{html}");
    assert!(row("person").contains("found by hand") && !row("person").contains("via MCP"), "{html}");
    let sarif: Value = serde_json::from_str(&report("sarif", &[])).unwrap();
    let res = |id: i64| {
        sarif["runs"][0]["results"]
            .as_array()
            .unwrap()
            .iter()
            .find(|r| r["properties"]["findingId"] == id)
            .unwrap()
            .clone()
    };
    assert_eq!(
        (res(by_agent)["properties"]["origin"].as_str(), res(by_person)["properties"]["origin"].as_str()),
        (Some("mcp"), Some("gui"))
    );

    // compare items.
    let cmp = env.ok(&[], &["findings", "compare"]);
    let new = cmp["new"].as_array().unwrap();
    let origin = |id: i64| new.iter().find(|f| f["id"] == id).unwrap()["origin"].clone();
    assert_eq!((origin(by_agent), origin(by_person)), ("mcp".into(), "gui".into()));

    // An agent can neither replace a title's shared text nor remove a finding.
    let refused = |args: &[&str]| {
        let (code, v, _) = env.run(&[(MCP, "1")], args);
        assert_eq!(code, 2, "{v}");
    };
    refused(&[
        "findings",
        "add",
        "--title",
        "Person IDOR",
        "--risk",
        "high",
        "--url",
        "http://127.0.0.1:9/b",
        "--description",
        "agent's",
        "--replace-text",
    ]);
    refused(&["findings", "remove", &by_person.to_string()]);
    assert_eq!(show(by_person)["state"], "open");

    // A person replacing it: the earlier text is kept with who replaced it.
    add(&[], "Person IDOR", "http://127.0.0.1:9/c", &["--description", "second", "--replace-text"]);
    let earlier = show(by_person)["replaced_texts"].clone();
    assert_eq!(
        (earlier[0]["description"].as_str(), earlier[0]["by"].as_str()),
        (Some("first"), Some("cli")),
        "{earlier}"
    );

    // A person removing it: the tombstone says who removed it, and when, as `findings mark` does.
    env.ok(&[(CLIENT, "gui")], &["findings", "mark", &by_person.to_string(), "--state", "confirmed"]);
    env.ok(&[(CLIENT, "gui")], &["findings", "remove", &by_person.to_string()]);
    let f = show(by_person);
    assert_eq!((f["state"].as_str(), f["state_origin"].as_str()), (Some("removed"), Some("gui")), "{f}");
    assert_eq!(f["removed"]["by"], "gui", "{f}");
    assert_eq!(f["state_changed_at"], f["removed"]["time"], "{f}");
    // The state it had, and who set that.
    assert_eq!(
        (f["removed"]["state"].as_str(), f["removed"]["state_origin"].as_str()),
        (Some("confirmed"), Some("gui"))
    );
    let html = report("html", &["--state", "all"]);
    assert!(html.contains("<span class=\"tag\">removed from the desktop app</span>"), "{html}");
}

#[test]
fn narrowing_what_the_proxy_records_says_who_did_it() {
    let env = Env::new("recording");
    let gui = [(CLIENT, "gui")];
    let agent = [(MCP, "1")];

    // The agent narrows the recording scope: the change says it came through MCP.
    env.ok(&agent, &["scope", "set", "--include", r"^a\.test$"]);
    let shown = env.ok(&[], &["scope", "show"]);
    let last = &shown["recording_changes"][0];
    assert_eq!(
        (last["by"].as_str(), last["setting"].as_str(), last["narrowed"].as_bool()),
        (Some("mcp"), Some("scope"), Some(true)),
        "{shown}"
    );
    assert_eq!(last["summary"], r"include: added ^a\.test$");
    assert_eq!(last["before"]["include"], serde_json::json!([]));
    assert_eq!(last["after"]["include"], serde_json::json!([r"^a\.test$"]));
    assert_eq!(shown["narrowed_by_agent"][0]["time"], last["time"], "{shown}");

    // `proxy status` says so too, and in words.
    let status = env.ok(&[], &["proxy", "status"]);
    assert_eq!(status["recording_narrowed_by_agent"][0]["summary"], last["summary"], "{status}");
    assert_eq!(status["recording_last_change"]["time"], last["time"]);
    let text = env.text(&["proxy", "status"]);
    assert!(text.contains("not reviewed: recording scope changed via MCP (an agent) at "), "{text}");
    assert!(text.contains(r", narrowing recording: include: added ^a\.test$"), "{text}");

    // Widening it a little afterwards doesn't hide the narrowing.
    env.ok(&agent, &["scope", "add", "--include", r"^b\.test$"]);
    let shown = env.ok(&[], &["scope", "show"]);
    assert_eq!(shown["recording_changes"][0]["narrowed"], false);
    assert_eq!(shown["narrowed_by_agent"][0]["summary"], r"include: added ^a\.test$", "{shown}");

    // A pass-through pattern the agent adds narrows recording too.
    env.ok(&agent, &["connection", "passthrough", "add", "c.test"]);
    let shown = env.ok(&[], &["scope", "show"]);
    let last = &shown["recording_changes"][0];
    assert_eq!((last["setting"].as_str(), last["summary"].as_str()), (Some("passthrough"), Some("added c.test")));
    assert_eq!(shown["narrowed_by_agent"].as_array().unwrap().len(), 2, "{shown}");

    // A person saving the scope in the app, even unchanged, has seen it; the pass-through stays flagged.
    env.ok(&gui, &["scope", "set", "--include", r"^a\.test$", "--include", r"^b\.test$"]);
    let shown = env.ok(&[], &["scope", "show"]);
    let flagged = shown["narrowed_by_agent"].as_array().unwrap();
    assert_eq!((flagged.len(), flagged[0]["setting"].as_str()), (1, Some("passthrough")), "{shown}");
    // Saved unchanged, it isn't logged as a change.
    assert_eq!(shown["recording_changes"][0]["setting"], "passthrough");
    env.ok(&gui, &["connection", "passthrough", "remove", "c.test"]);
    let shown = env.ok(&[], &["scope", "show"]);
    assert_eq!(shown["narrowed_by_agent"], serde_json::json!([]));
    assert_eq!(
        (shown["recording_changes"][0]["by"].as_str(), shown["recording_changes"][0]["narrowed"].as_bool()),
        (Some("gui"), Some(false))
    );
    assert!(!env.text(&["proxy", "status"]).contains("not reviewed"));
}

#[test]
fn an_agents_narrowing_stays_listed_however_many_changes_follow() {
    let env = Env::new("recording-kept");
    let agent = [(MCP, "1")];
    // The agent narrows recording to nothing, and puts it back once its traffic is sent.
    env.ok(&agent, &["scope", "set", "--include", "^nothing$"]);
    env.ok(&agent, &["scope", "clear"]);
    // Then buries it under more changes than `scope show` lists.
    for _ in 0..11 {
        env.ok(&agent, &["connection", "passthrough", "add", "z.test"]);
        env.ok(&agent, &["connection", "passthrough", "remove", "z.test"]);
    }
    let shown = env.ok(&[], &["scope", "show"]);
    assert_eq!(shown["narrowed_by_agent"], serde_json::json!([]), "{shown}");
    let narrowing = |list: &Value| {
        list.as_array().unwrap().iter().any(|c| c["setting"] == "scope" && c["by"] == "mcp" && c["narrowed"] == true)
    };
    assert!(narrowing(&shown["recording_changes"]), "{shown}");
    let status = env.ok(&[], &["proxy", "status"]);
    assert!(narrowing(&status["recording_kept_changes"]), "{status}");
    assert_eq!(status["recording_kept_changes"].as_array().unwrap().len(), 24, "{status}");
}

#[test]
fn an_agent_rerouting_traffic_is_logged() {
    let env = Env::new("routing");
    let agent = [(MCP, "1")];
    env.ok(&agent, &["connection", "upstream", "add", "--host", "*", "--proxy", "http://192.0.2.7:3128"]);
    env.ok(&agent, &["connection", "hosts", "add", "app.test", "10.0.0.7"]);
    let shown = env.ok(&[], &["scope", "show"]);
    let changes = shown["recording_changes"].as_array().unwrap();
    let find = |setting: &str| changes.iter().find(|c| c["setting"] == setting).unwrap_or_else(|| panic!("{shown}"));
    let (up, hosts) = (find("upstream"), find("hosts"));
    assert_eq!((up["by"].as_str(), up["summary"].as_str()), (Some("mcp"), Some("added * via http://192.0.2.7:3128")));
    assert_eq!(hosts["summary"], "added app.test -> 10.0.0.7");
    // Routing doesn't narrow recording, but an agent changing it is flagged, apart from narrowing.
    assert!(changes.iter().all(|c| c["narrowed"] == false), "{shown}");
    assert_eq!(shown["narrowed_by_agent"], serde_json::json!([]));
    assert_eq!(shown["routing_changed_by_agent"].as_array().unwrap().len(), 2, "{shown}");
    let status = env.ok(&[], &["proxy", "status"]);
    assert_eq!(status["recording_kept_changes"].as_array().unwrap().len(), 2, "{status}");
    assert_eq!(status["routing_changed_by_agent"].as_array().unwrap().len(), 2, "{status}");
    assert_eq!(status["recording_narrowed_by_agent"], serde_json::json!([]));
    let text = env.text(&["proxy", "status"]);
    assert!(text.contains("not reviewed: host overrides changed via MCP (an agent)"), "{text}");
    let text = env.text(&["scope", "show"]);
    assert!(text.contains("last change: host overrides changed via MCP (an agent)"), "{text}");
    // A pass-through change doesn't log the untouched routing again, nor clear its flags.
    env.ok(&[], &["connection", "passthrough", "add", "c.test"]);
    let shown = env.ok(&[], &["scope", "show"]);
    assert_eq!(shown["recording_changes"].as_array().unwrap().len(), 3, "{shown}");
    assert_eq!(shown["routing_changed_by_agent"].as_array().unwrap().len(), 2, "{shown}");
    // The agent can't approve its own changes.
    let (code, v, _) = env.run(&agent, &["connection", "review"]);
    assert_eq!(code, 2, "{v}");
    // A person changing the host overrides clears theirs; reviewing clears the rest, as they are.
    env.ok(&[], &["connection", "hosts", "add", "app.test", "10.0.0.7"]);
    let shown = env.ok(&[], &["scope", "show"]);
    let flagged = shown["routing_changed_by_agent"].as_array().unwrap();
    assert_eq!((flagged.len(), flagged[0]["setting"].as_str()), (1, Some("upstream")), "{shown}");
    let reviewed = env.ok(&[], &["connection", "review"]);
    assert_eq!(reviewed["reviewed"][0]["setting"], "upstream", "{reviewed}");
    let shown = env.ok(&[], &["scope", "show"]);
    assert_eq!(shown["routing_changed_by_agent"], serde_json::json!([]));
    let up = env.ok(&[], &["connection", "show"]);
    assert_eq!(up["upstream"][0]["proxy"], "http://192.0.2.7:3128", "{up}");
    // The notice says everything since the agent's first change, not just its latest one,
    // and keeping it needs exactly what was shown.
    env.ok(&agent, &["connection", "upstream", "add", "--host", "*.corp.test", "--proxy", "http://192.0.2.9:8080"]);
    env.ok(&agent, &["connection", "upstream", "add", "--host", "x.test", "--direct"]);
    env.ok(&agent, &["connection", "upstream", "remove", "--host", "x.test"]);
    let shown = env.ok(&[], &["scope", "show"]);
    let flag = &shown["routing_changed_by_agent"][0];
    assert_eq!(flag["summary"], "added *.corp.test via http://192.0.2.9:8080", "{shown}");
    let (code, v, _) = env.run(&[], &["connection", "review", "--seen", "2000-01-01T00:00:00.000Z"]);
    assert_eq!(code, 2, "{v}");
    let time = flag["time"].as_str().unwrap();
    env.ok(&[], &["connection", "review", "--seen", time]);
    assert_eq!(env.ok(&[], &["scope", "show"])["routing_changed_by_agent"], serde_json::json!([]));
    // The agent putting it back as it was clears its flag too.
    env.ok(&agent, &["connection", "hosts", "add", "b.test", "10.0.0.8"]);
    env.ok(&agent, &["connection", "hosts", "remove", "b.test"]);
    let shown = env.ok(&[], &["scope", "show"]);
    assert_eq!(shown["routing_changed_by_agent"], serde_json::json!([]), "{shown}");
}

#[test]
fn a_change_log_that_doesnt_parse_is_reported_and_kept() {
    let env = Env::new("recording-corrupt");
    let store = brainproxy_core::store::Store::open(&env.project).unwrap();
    store.meta_set("proxy.recording_changes", Some("{not json")).unwrap();
    // Status and scope show still answer, and say what's wrong.
    let status = env.ok(&[], &["proxy", "status"]);
    assert!(status["recording_changes_problem"].as_str().unwrap().contains("doesn't parse"), "{status}");
    assert_eq!(status["running"], false);
    assert!(env.text(&["proxy", "status"]).contains("warning: the log of changes to what the proxy records"));
    let shown = env.ok(&[], &["scope", "show"]);
    assert!(shown["recording_changes_problem"].is_string(), "{shown}");
    // Saves refuse, so the log isn't silently reset.
    let (code, _, text) = env.run(&[], &["scope", "add", "--include", "^a$"]);
    assert_ne!(code, 0, "{text}");
    assert!(text.contains("repaired by hand"), "{text}");
    let (code, _, _) = env.run(&[], &["connection", "passthrough", "add", "a.test"]);
    assert_ne!(code, 0);
    assert_eq!(store.meta_get("proxy.recording_changes").unwrap().as_deref(), Some("{not json"));
}

#[test]
fn the_session_a_proxy_puts_on_requests_says_who_set_it_up() {
    let port = serve();
    let env = Env::new("session");
    let gui = [(CLIENT, "gui")];
    let agent = [(MCP, "1")];
    env.ok(&gui, &["auth", "add", "app", "-H", "X-Api-Key: k"]);
    let rule = env.ok(&agent, &["auth", "rule", "add", "app", "--action", "update:x=y"]);
    assert_eq!((&rule["rule"]["id"], &rule["rule"]["origin"]), (&1.into(), &"mcp".into()), "{rule}");
    let shown = env.ok(&[], &["auth", "show", "app"]);
    assert_eq!((&shown["profile"]["origin"], &shown["rules"][0]["origin"]), (&"gui".into(), &"mcp".into()));
    assert!(shown["session_origin"].is_null(), "{shown}");

    // The person's proxy puts the profile's header on: the row names the profile, with who
    // added it. The agent's rule applied, but the request has no x to update: it isn't named.
    // (Rules and macros that change a request are named too; see the session module's tests.)
    let started = env.ok(&gui, &["proxy", "start", "--listen", "127.0.0.1:0", "--auth", "app"]);
    let listen = started["listen"].as_str().unwrap().to_string();
    assert!(started["schema"].is_i64(), "{started}");
    assert!(through(&listen, port, "/with-session", "").starts_with("HTTP/1.1 200"));
    wait_for(&env, "SELECT count(*) FROM history WHERE path = '/with-session'", 1);
    let rows = env.rows("SELECT id, origin, edited_by FROM history WHERE path = '/with-session'");
    assert_eq!(rows[0][1], "gui");
    let edits: Value = serde_json::from_str(rows[0][2].as_str().unwrap()).unwrap();
    assert_eq!(edits, serde_json::json!([{"by": "gui", "auth": "app"}]));
    let about = env.text(&["history", "show", &rows[0][0].to_string()]);
    let first = about.lines().next().unwrap();
    assert!(first.contains("given the session of auth profile app") && !first.contains("session rule"), "{about}");
    // A proxy this build started is up to date.
    assert!(env.ok(&[], &["proxy", "status"])["proxy_outdated"].is_null());
    env.ok(&[], &["proxy", "stop"]);

    // Saving the rules again unchanged keeps who added each.
    env.ok(&gui, &["auth", "rule", "add", "app", "--action", "update:a=b"]);
    let rules = env.ok(&[], &["auth", "rule", "list", "app"])["rules"].clone();
    assert_eq!((&rules[0]["origin"], &rules[1]["origin"]), (&"mcp".into(), &"gui".into()), "{rules}");

    // A removed rule's id is never handed out again, of a session rule or a proxy rule.
    env.ok(&gui, &["auth", "rule", "remove", "app", "2"]);
    let again = env.ok(&gui, &["auth", "rule", "add", "app", "--action", "update:a=b"]);
    assert_eq!(again["rule"]["id"], 3);
    let add = ["rules", "add", "--location", "request-header", "--match", "^A: 1$", "--replace", "A: 2"];
    env.ok(&gui, &add);
    env.ok(&gui, &["rules", "remove", "1"]);
    assert_eq!(env.ok(&agent, &add)["rules"][0]["id"], 2);

    // Who saved which setting is logged, without its value.
    let logged = env.rows("SELECT origin FROM setting_changes WHERE key = 'rules' ORDER BY id");
    assert_eq!(logged, ["gui", "gui", "mcp"].map(|o| serde_json::json!([o])).to_vec());
}

#[test]
fn a_profile_saved_unchanged_keeps_who_saved_it() {
    let env = Env::new("profile-resave");
    let gui = [(CLIENT, "gui")];
    let agent = [(MCP, "1")];
    let origin = || env.ok(&[], &["auth", "show", "app"])["profile"]["origin"].clone();
    env.ok(&gui, &["auth", "add", "app", "-H", "X-Api-Key: k"]);
    // Re-saved as `auth show` gives it (header values masked), as the app's edit form does.
    env.ok(&agent, &["auth", "add", "app", "-H", "X-Api-Key: ********"]);
    assert_eq!(origin(), "gui");
    env.ok(&agent, &["auth", "add", "app", "-H", "X-Api-Key: other"]);
    assert_eq!(origin(), "mcp");
    env.ok(&gui, &["auth", "add", "app", "-H", "X-Api-Key: ********"]);
    assert_eq!(origin(), "mcp");
}

#[test]
fn a_titles_text_filled_in_later_says_who_wrote_it() {
    let env = Env::new("texts");
    let add = |vars: &[(&str, &str)], path: &str, more: &[&str]| {
        let url = format!("http://127.0.0.1:9/{path}");
        let mut args = vec!["findings", "add", "--title", "Open redirect", "--risk", "low", "--url", &url];
        args.extend_from_slice(more);
        env.ok(vars, &args)["finding"]["id"].as_i64().unwrap()
    };
    add(&[(CLIENT, "gui")], "a", &["--solution", "check the target"]);
    // The person left the description blank: the agent's fills it in, and says so.
    let id = add(&[(MCP, "1")], "b", &["--description", "agent text"]);
    let sql = "SELECT description, description_origin, solution, solution_origin FROM finding_types \
               WHERE name = 'Open redirect'";
    assert_eq!(env.rows(sql)[0], serde_json::json!(["agent text", "mcp", "check the target", "gui"]));
    // The same text given again isn't written by anyone new.
    add(&[(CLIENT, "gui")], "c", &["--description", "agent text"]);
    assert_eq!(env.rows(sql)[0][1], "mcp");
    let shown = env.ok(&[], &["findings", "show", &id.to_string()]);
    assert_eq!((&shown["description_origin"], &shown["solution_origin"]), (&"mcp".into(), &"gui".into()));
}
