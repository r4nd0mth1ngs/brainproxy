//! End-to-end tests for proof-of-concept pages: requests recorded with `send` to a local
//! server, then `poc csrf` and `poc clickjacking` from history and from stdin.

use std::io::{Read, Write};
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use serde_json::Value;

/// /login sets a SameSite=Lax session cookie; /settings may not be framed; anything else is a page.
fn serve() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let mut s = stream.unwrap();
            let mut buf = [0u8; 8192];
            let mut req = Vec::new();
            while !req.windows(4).any(|w| w == b"\r\n\r\n") {
                let k = s.read(&mut buf).unwrap_or(0);
                if k == 0 {
                    break;
                }
                req.extend_from_slice(&buf[..k]);
            }
            let line = String::from_utf8_lossy(&req).lines().next().unwrap_or("").to_string();
            let extra = if line.contains(" /login ") {
                "Set-Cookie: sid=abc; Path=/; HttpOnly; SameSite=Lax\r\n"
            } else if line.contains(" /settings ") {
                "X-Frame-Options: DENY\r\n"
            } else {
                ""
            };
            let body = "<html><body>hi</body></html>";
            let resp = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n{extra}Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            let _ = s.write_all(resp.as_bytes());
        }
    });
    port
}

/// Runs the CLI with `format`; `agent` runs it as an MCP tool call would.
fn run_with(project: &Path, format: &str, args: &[&str], stdin: Option<&str>, agent: bool) -> (i32, Vec<u8>, String) {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_brainproxy"));
    cmd.env_remove("BRAINPROXY_PROJECT").args(["--format", format, "--project"]).arg(project).args(args);
    if agent {
        cmd.env("BRAINPROXY_MCP_CALL", "1");
    } else {
        cmd.env_remove("BRAINPROXY_MCP_CALL");
    }
    let mut child = cmd.stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped()).spawn().unwrap();
    // A command that fails on its arguments may exit before reading its stdin.
    let _ = child.stdin.take().unwrap().write_all(stdin.unwrap_or("").as_bytes());
    let out = child.wait_with_output().unwrap();
    (out.status.code().unwrap(), out.stdout, String::from_utf8_lossy(&out.stderr).into_owned())
}

fn run_as(project: &Path, args: &[&str], stdin: Option<&str>, agent: bool) -> (i32, Value) {
    let (code, stdout, stderr) = run_with(project, "json", args, stdin, agent);
    let v: Value = serde_json::from_slice(&stdout)
        .unwrap_or_else(|e| panic!("{args:?}: bad JSON ({e}): {} {stderr}", String::from_utf8_lossy(&stdout)));
    (code, v)
}

fn ok(project: &Path, args: &[&str]) -> Value {
    ok_in(project, args, None)
}

fn ok_in(project: &Path, args: &[&str], stdin: Option<&str>) -> Value {
    let (code, v) = run_as(project, args, stdin, false);
    assert_eq!(code, 0, "{args:?}: {v}");
    v["data"].clone()
}

fn setup(name: &str) -> (PathBuf, PathBuf) {
    let dir = std::env::temp_dir().join(format!("bp-poc-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let project = dir.join("p.bpdb");
    ok(&project, &["engagement", "start", "--target", "127.0.0.1"]);
    (dir, project)
}

/// Sends a raw request and returns its history id.
fn record(project: &Path, base: &str, raw: &str) -> String {
    let sent = ok_in(project, &["send", "--target", base, "-"], Some(raw));
    let id = sent["id"].as_i64().unwrap_or_else(|| panic!("no history id in {sent}"));
    id.to_string()
}

fn warnings(v: &Value) -> String {
    v["warnings"].as_array().unwrap().iter().map(|w| w.as_str().unwrap()).collect::<Vec<_>>().join("\n")
}

#[test]
fn csrf_pages_from_history_and_stdin() {
    let port = serve();
    let (dir, project) = setup("csrf");
    let base = format!("http://127.0.0.1:{port}");
    ok(&project, &["send", "--url", &format!("{base}/login")]);

    let form = "POST /account/email HTTP/1.1\r\nHost: 127.0.0.1\r\nCookie: sid=abc\r\nContent-Type: \
                application/x-www-form-urlencoded\r\n\r\nemail=a%40b.test&csrf_token=t0k&password=hunter2";
    let id = record(&project, &base, form);
    let page = ok(&project, &["poc", "csrf", "--history-id", &id]);
    assert_eq!(page["kind"], "csrf");
    assert_eq!(page["history_id"].as_i64().map(|i| i.to_string()), Some(id.clone()));
    assert_eq!(page["method"], "POST");
    assert_eq!(page["action"], format!("{base}/account/email"));
    assert_eq!(page["encoding"], "urlencoded");
    assert_eq!(page["technique"], "form");
    assert_eq!(page["auto_submit"], false);
    assert!(page["path"].is_null());
    let fields: Vec<(&str, &str)> = page["fields"]
        .as_array()
        .unwrap()
        .iter()
        .map(|f| (f["name"].as_str().unwrap(), f["value"].as_str().unwrap()))
        .collect();
    assert_eq!(fields, [("email", "a@b.test"), ("csrf_token", "t0k"), ("password", "hunter2")]);
    let w = warnings(&page);
    assert!(w.contains("csrf_token looks like an anti-CSRF token"), "{w}");
    assert!(w.contains("password looks like a password"), "{w}");
    // The session cookie's SameSite comes from the Set-Cookie recorded for the host.
    assert!(w.contains("cookie sid is SameSite=Lax"), "{w}");
    let html = page["html"].as_str().unwrap();
    assert!(html.contains("<input type=\"hidden\" name=\"csrf_token\" value=\"t0k\">"), "{html}");

    let dropped = ok(
        &project,
        &["poc", "csrf", "--history-id", &id, "--drop-param", "csrf_token", "--technique", "fetch", "--auto-submit"],
    );
    assert_eq!(dropped["technique"], "fetch");
    assert_eq!(dropped["auto_submit"], true);
    assert_eq!(dropped["fields"].as_array().unwrap().len(), 2);
    assert!(!warnings(&dropped).contains("anti-CSRF"));
    assert!(dropped["html"].as_str().unwrap().contains("send();"));

    let json = "POST /api/profile HTTP/1.1\r\nHost: 127.0.0.1\r\nCookie: sid=abc\r\nX-Requested-With: \
                XMLHttpRequest\r\nContent-Type: application/json\r\n\r\n{\"name\":\"</script><b>\"}";
    let id = record(&project, &base, json);
    let page = ok(&project, &["poc", "csrf", "--history-id", &id]);
    assert_eq!(page["encoding"], "json");
    let w = warnings(&page);
    assert!(w.contains("Content-Type text/plain instead of application/json"), "{w}");
    assert!(w.contains("X-Requested-With"), "{w}");
    assert!(w.contains("40040"), "{w}");
    // The one text/plain field, sent as name=value CR LF, is the JSON again (plus the member holding '=').
    let f = &page["fields"][0];
    let sent = format!("{}={}", f["name"].as_str().unwrap(), f["value"].as_str().unwrap());
    let v: Value = serde_json::from_str(&sent).unwrap();
    assert_eq!(v["name"], "</script><b>");
    assert!(!page["html"].as_str().unwrap().contains("<b>"));

    // From stdin, as Replay pipes a tab's request: no history id, no project needed.
    let none = dir.join("none.bpdb");
    let page = ok_in(&none, &["poc", "csrf", "--file", "-", "--target", "https://shop.test"], Some(form));
    assert!(page["history_id"].is_null());
    assert_eq!(page["action"], "https://shop.test/account/email");
    assert!(!none.exists(), "a page from stdin doesn't create a project");
    let (code, v) = run_as(&project, &["poc", "csrf", "--file", "-"], Some(form), false);
    assert_ne!(code, 0, "--file needs --target: {v}");
    let (code, v) = run_as(&project, &["poc", "csrf"], None, false);
    assert_ne!(code, 0, "a request must be named: {v}");

    // Text: the page itself on stdout, the warnings on stderr.
    let (code, stdout, stderr) = run_with(&project, "text", &["poc", "csrf", "--history-id", &id], None, false);
    assert_eq!(code, 0, "{stderr}");
    assert!(String::from_utf8_lossy(&stdout).starts_with("<!doctype html>"));
    assert!(stderr.contains("warning: the JSON body goes as Content-Type text/plain"), "{stderr}");
    assert!(stderr.contains("outside brainproxy's scope checks"), "{stderr}");

    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn output_files_and_mcp() {
    let port = serve();
    let (dir, project) = setup("mcp");
    let base = format!("http://127.0.0.1:{port}");
    let id = record(&project, &base, "GET /transfer?to=bob HTTP/1.1\r\nHost: 127.0.0.1\r\nCookie: s=1\r\n\r\n");
    let file = dir.join("poc.html");
    let f = file.to_str().unwrap();

    let (code, v) = run_as(&project, &["poc", "csrf", "--history-id", &id, "--output", f, "--force"], None, true);
    assert_ne!(code, 0);
    assert!(v["error"]["message"].as_str().unwrap().contains("--force is refused through MCP"), "{v}");
    let (code, v) =
        run_as(&project, &["poc", "clickjacking", "--history-id", &id, "--output", f, "--force"], None, true);
    assert_ne!(code, 0);
    assert!(v["error"]["message"].as_str().unwrap().contains("--force is refused through MCP"), "{v}");
    assert!(!file.exists());

    // A new file is written through MCP too; an existing one is kept.
    let (code, v) = run_as(&project, &["poc", "csrf", "--history-id", &id, "--output", f], None, true);
    assert_eq!(code, 0, "{v}");
    assert_eq!(v["data"]["path"], f);
    assert_eq!(v["data"]["encoding"], "query");
    assert_eq!(std::fs::read_to_string(&file).unwrap(), v["data"]["html"].as_str().unwrap());
    let (code, v) = run_as(&project, &["poc", "csrf", "--history-id", &id, "--output", f], None, true);
    assert_ne!(code, 0, "{v}");
    assert_eq!(v["error"]["kind"], "conflict");
    ok(&project, &["poc", "csrf", "--history-id", &id, "--output", f, "--force"]);

    // Through MCP, --file is read only from the project's folder.
    let outside = std::env::temp_dir().join(format!("bp-poc-outside-{}.txt", std::process::id()));
    std::fs::write(&outside, "GET / HTTP/1.1\r\nHost: a\r\n\r\n").unwrap();
    let (code, v) = run_as(
        &project,
        &["poc", "csrf", "--file", outside.to_str().unwrap(), "--target", "https://a.test"],
        None,
        true,
    );
    assert_ne!(code, 0, "{v}");
    assert!(v["error"]["message"].as_str().unwrap().contains("project's folder"), "{v}");
    std::fs::remove_file(&outside).ok();

    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn clickjacking_pages() {
    let port = serve();
    let (dir, project) = setup("click");
    let base = format!("http://127.0.0.1:{port}");
    ok(&project, &["send", "--url", &format!("{base}/login")]);
    let settings = record(&project, &base, "GET /settings HTTP/1.1\r\nHost: 127.0.0.1\r\nCookie: sid=abc\r\n\r\n");

    let page =
        ok(&project, &["poc", "clickjacking", "--history-id", &settings, "--opacity", "0.2", "--decoy", "<Win>"]);
    assert_eq!(page["kind"], "clickjacking");
    assert_eq!(page["url"], format!("{base}/settings"));
    assert_eq!(page["framing"]["x_frame_options"], "DENY");
    assert!(page["framing"]["frame_ancestors"].is_null());
    assert_eq!(page["framing"]["blocked"], true);
    let w = warnings(&page);
    assert!(w.contains("can't be framed (X-Frame-Options: DENY)"), "{w}");
    assert!(w.contains("cookie sid is SameSite=Lax"), "{w}");
    let html = page["html"].as_str().unwrap();
    assert!(html.contains("&lt;Win&gt;") && html.contains("value=\"0.2\""), "{html}");

    // --url finds its newest recorded response; one never recorded has unknown framing.
    let by_url = ok(&project, &["poc", "clickjacking", "--url", &format!("{base}/settings")]);
    assert_eq!(by_url["framing"]["blocked"], true);
    assert_eq!(by_url["history_id"].as_i64().map(|i| i.to_string()), Some(settings));
    let home = ok(&project, &["poc", "clickjacking", "--url", &format!("{base}/login")]);
    assert_eq!(home["framing"]["blocked"], false);
    let unknown = ok(&project, &["poc", "clickjacking", "--url", &format!("{base}/never")]);
    assert!(unknown["framing"]["blocked"].is_null());
    assert!(warnings(&unknown).contains("no response is recorded"));

    let (code, v) = run_as(&project, &["poc", "clickjacking", "--url", "javascript:alert(1)"], None, false);
    assert_ne!(code, 0, "{v}");
    assert_eq!(v["error"]["kind"], "invalid_input");
    let (code, v) = run_as(&project, &["poc", "clickjacking", "--url", &base, "--opacity", "2"], None, false);
    assert_ne!(code, 0, "{v}");

    std::fs::remove_dir_all(&dir).ok();
}
