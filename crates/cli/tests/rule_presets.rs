//! Response modification presets end to end: `rules presets list` and `add`, the rules they
//! save, and what they make of pages the proxy relays from a local server.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::Duration;

use serde_json::Value;

const MCP: &str = "BRAINPROXY_MCP_CALL";
const CLIENT: &str = "BRAINPROXY_CLIENT";

/// A page with something for every HTML preset.
const PAGE: &str = r#"<html><head><script src="/app.js"></script><script>check()</script></head><body>
<form action="/save" onsubmit="return check()"><input type="hidden" name="csrf" value="t0k">
<input name="user" maxlength="8" disabled><textarea readonly></textarea>
<object data="old.swf"><param name="a" value="b"></object><embed src="old.swf"></form></body></html>"#;

struct Env {
    project: PathBuf,
    home: PathBuf,
}

impl Env {
    fn new(name: &str) -> Self {
        let dir = std::env::temp_dir().join(format!("bp-presets-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let env = Env { project: dir.join("p.bpdb"), home: dir.join("home") };
        env.ok(&["engagement", "start", "--target", "127.0.0.1"]);
        env
    }

    /// Runs the CLI with these provenance variables (the test's own are removed) and stdin.
    fn run_with(&self, vars: &[(&str, &str)], args: &[&str], stdin: Option<&[u8]>) -> (i32, Value) {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_brainproxy"));
        cmd.env_remove(MCP).env_remove(CLIENT).envs(vars.iter().copied());
        cmd.args(["--format", "json", "--project"]).arg(&self.project).arg("--home").arg(&self.home).args(args);
        cmd.stdin(if stdin.is_some() { Stdio::piped() } else { Stdio::null() }).stdout(Stdio::piped());
        let mut child = cmd.spawn().unwrap();
        if let Some(input) = stdin {
            child.stdin.take().unwrap().write_all(input).unwrap();
        }
        let out = child.wait_with_output().unwrap();
        (out.status.code().unwrap(), serde_json::from_slice(&out.stdout).unwrap_or(Value::Null))
    }

    fn run_as(&self, vars: &[(&str, &str)], args: &[&str]) -> (i32, Value) {
        self.run_with(vars, args, None)
    }

    fn ok(&self, args: &[&str]) -> Value {
        self.ok_stdin(args, None)
    }

    fn ok_stdin(&self, args: &[&str], stdin: Option<&[u8]>) -> Value {
        let (code, v) = self.run_with(&[], args, stdin);
        assert_eq!(code, 0, "{args:?} -> {v}");
        v["data"].clone()
    }
}

impl Drop for Env {
    fn drop(&mut self) {
        let _ = self.run_as(&[], &["proxy", "stop"]);
    }
}

/// Serves `/page` as HTML (`/page.gz` gzipped), `/data` as JSON holding the same markup, and
/// `/plain` with no Content-Type; every response sets two cookies.
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
                let request = String::from_utf8_lossy(&buf[..len]);
                let path = request.split(' ').nth(1).unwrap_or("/");
                let (content_type, body): (&str, Vec<u8>) = match path {
                    "/page" => ("Content-Type: text/html; charset=utf-8\r\n", PAGE.into()),
                    "/page.gz" => {
                        let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
                        gz.write_all(PAGE.as_bytes()).unwrap();
                        ("Content-Type: text/html\r\nContent-Encoding: gzip\r\n", gz.finish().unwrap())
                    }
                    "/data" => ("Content-Type: application/json\r\n", serde_json::to_vec(&PAGE).unwrap()),
                    _ => ("", PAGE.into()),
                };
                let head = format!(
                    "HTTP/1.1 200 OK\r\n{content_type}Set-Cookie: sid=1; Path=/; Secure; HttpOnly\r\n\
                     Set-Cookie: pref=a; HttpOnly; SameSite=Lax\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    body.len()
                );
                let _ = s.write_all(head.as_bytes());
                let _ = s.write_all(&body);
            });
        }
    });
    port
}

/// A GET through the proxy at `listen`: the response's head and its body.
fn through(listen: &str, port: u16, path: &str) -> (String, String) {
    let mut s = TcpStream::connect(listen).unwrap();
    write!(s, "GET http://127.0.0.1:{port}{path} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nConnection: close\r\n\r\n")
        .unwrap();
    let mut resp = Vec::new();
    s.read_to_end(&mut resp).unwrap();
    let at = resp.windows(4).position(|w| w == b"\r\n\r\n").expect("a whole response") + 4;
    (String::from_utf8_lossy(&resp[..at]).into_owned(), String::from_utf8_lossy(&resp[at..]).into_owned())
}

fn ids(v: &Value) -> Vec<u64> {
    v.as_array().into_iter().flatten().filter_map(Value::as_u64).collect()
}

#[test]
fn presets_add_ordinary_rules_that_rewrite_proxied_html_and_cookies() {
    let port = serve();
    let env = Env::new("proxy");
    let listed = env.ok(&["rules", "presets", "list"]);
    let names: Vec<&str> = listed["presets"].as_array().unwrap().iter().filter_map(|p| p["name"].as_str()).collect();
    assert_eq!(names.len(), 8, "{listed}");
    // The rules a preset would add are shown, and listing saves nothing.
    assert_eq!(listed["presets"][4]["rules"][1]["name"], "Content-Security-Policy", "{listed}");
    assert!(env.ok(&["rules", "list"])["rules"].as_array().unwrap().is_empty());

    let mut args = vec!["rules", "presets", "add"];
    args.extend(names.iter().copied());
    let added = env.ok(&args);
    let first = ids(&added["added"]);
    assert_eq!(first.len(), added["rules"].as_array().unwrap().len(), "{added}");
    assert!(ids(&added["present"]).is_empty(), "{added}");
    for rule in added["rules"].as_array().unwrap() {
        assert!(rule["comment"].as_str().unwrap().starts_with("preset "), "{rule}");
        assert_eq!(rule["origin"], "cli", "{rule}");
        assert!(rule.get("applies_to").is_none(), "proxy only: {rule}");
    }
    // Adding them again adds nothing: they are there, and said to be.
    let again = env.ok(&args);
    assert!(ids(&again["added"]).is_empty(), "{again}");
    assert_eq!(ids(&again["present"]), first, "{again}");
    // And an agent's call adds them as its own.
    let (code, v) = env.run_as(&[(MCP, "1")], &["rules", "presets", "add", "remove-objects", "--host", "^other$"]);
    assert_eq!(code, 0, "{v}");
    let theirs = ids(&v["data"]["added"]);
    assert_eq!(theirs.len(), 2, "{v}");
    let rules = v["data"]["rules"].as_array().unwrap();
    for rule in rules.iter().filter(|r| theirs.contains(&r["id"].as_u64().unwrap())) {
        assert_eq!((rule["origin"].as_str(), rule["host"].as_str()), (Some("mcp"), Some("^other$")), "{rule}");
    }
    let (code, v) = env.run_as(&[], &["rules", "presets", "add", "convert-https-links"]);
    assert_ne!(code, 0, "{v}");

    let listen = env.ok(&["proxy", "start", "--listen", "127.0.0.1:0"])["listen"].as_str().unwrap().to_string();
    // The proxy reloads settings every 300 ms.
    std::thread::sleep(Duration::from_millis(700));
    for path in ["/page", "/page.gz"] {
        let (head, body) = through(&listen, port, path);
        assert!(head.contains("\r\nContent-Security-Policy: script-src 'none'\r\n"), "{path}: {head}");
        assert!(head.contains("\r\nSet-Cookie: sid=1; Path=/\r\n"), "{path}: {head}");
        assert!(head.contains("\r\nSet-Cookie: pref=a; SameSite=Lax\r\n"), "{path}: {head}");
        // Decoded to be rewritten, and sent on without its coding.
        assert!(!head.to_ascii_lowercase().contains("content-encoding"), "{path}: {head}");
        assert!(head.contains(&format!("\r\nContent-Length: {}\r\n", body.len())), "{path}: {head}");
        assert!(!body.contains("<script") && !body.contains("<object") && !body.contains("<embed"), "{body}");
        assert!(body.contains(r#"<form novalidate action="/save">"#), "{body}");
        assert!(body.contains(r#" type="text" name="csrf" value="t0k">"#), "{body}");
        assert!(body.contains(r#"<input name="user"><textarea></textarea>"#), "{body}");
    }
    // Not HTML: the markup in the JSON goes through as it came; the cookies lose their flags all the same.
    let (head, body) = through(&listen, port, "/data");
    assert_eq!(body, serde_json::to_string(PAGE).unwrap());
    assert!(!head.contains("Content-Security-Policy") && head.contains("Set-Cookie: sid=1; Path=/\r\n"), "{head}");
    let (head, body) = through(&listen, port, "/plain");
    assert_eq!(body, PAGE, "no Content-Type is no HTML");
    assert!(head.contains("Set-Cookie: pref=a; SameSite=Lax\r\n"), "{head}");

    // They are rules like any other: one switched off stops changing the page.
    let csp = rules.iter().find(|r| r["name"] == "Content-Security-Policy").unwrap()["id"].to_string();
    env.ok(&["rules", "disable", &csp]);
    std::thread::sleep(Duration::from_millis(700));
    let (head, body) = through(&listen, port, "/page");
    assert!(!head.contains("Content-Security-Policy") && !body.contains("<script"), "{head}{body}");
    // And a preset added again leaves the one switched off as it is, and says so.
    let v = env.ok(&["rules", "presets", "add", "remove-scripts"]);
    assert!(ids(&v["added"]).is_empty() && ids(&v["present"]).contains(&csp.parse().unwrap()), "{v}");
}

#[test]
fn a_content_type_condition_is_refused_where_there_is_no_response() {
    let env = Env::new("refused");
    let (code, v) =
        env.run_as(&[], &["rules", "add", "--location", "request-body", "--match", "a", "--content-type", "html"]);
    assert_ne!(code, 0, "{v}");
    assert!(v["error"]["message"].as_str().unwrap().contains("--content-type goes with a response location"), "{v}");
    let added = env.ok(&[
        "rules",
        "add",
        "--location",
        "response-header",
        "--name",
        "X-Json",
        "--action",
        "add",
        "--replace",
        "1",
        "--content-type",
        "json",
    ]);
    assert_eq!(added["rules"][0]["content_type"], "json", "{added}");
    // `rules test` reads it, for saved rules and an unsaved one.
    let draft = ["--location", "response-body", "--match", "a", "--replace", "b", "--content-type", "^text/plain"];
    let test = [&["rules", "test", "--message", "response", "--rule", "1"][..], &draft].concat();
    let response = |content_type: &str| format!("HTTP/1.1 200 OK\r\n{content_type}Content-Length: 1\r\n\r\na");
    let tested = env.ok_stdin(&test, Some(response("Content-Type: text/plain\r\n").as_bytes()));
    assert_eq!(
        tested["response"]["result"]["content"],
        "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 1\r\n\r\nb",
        "{tested}"
    );
    let tested = env.ok_stdin(&test, Some(response("Content-Type: application/json\r\n").as_bytes()));
    assert_eq!(
        tested["response"]["result"]["content"],
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 1\r\nX-Json: 1\r\n\r\na",
        "{tested}"
    );
}
