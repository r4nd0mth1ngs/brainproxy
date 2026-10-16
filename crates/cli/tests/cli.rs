//! End-to-end tests: run the real binary against a local HTTP server.

use std::io::{Read, Write};
use std::net::TcpListener;
use std::process::{Command, Stdio};

use serde_json::Value;

fn bin() -> Command {
    Command::new(env!("CARGO_BIN_EXE_brainproxy"))
}

/// Serves `n` connections, echoing back the request line and body in a fixed response.
fn serve(n: usize) -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for stream in listener.incoming().take(n) {
            let mut s = stream.unwrap();
            let mut buf = vec![0u8; 65536];
            let mut len = 0;
            // Read the head, then Content-Length bytes of body.
            loop {
                len += s.read(&mut buf[len..]).unwrap();
                let text = String::from_utf8_lossy(&buf[..len]).to_string();
                if let Some(i) = text.find("\r\n\r\n") {
                    let cl = text
                        .lines()
                        .find_map(|l| {
                            l.to_ascii_lowercase()
                                .strip_prefix("content-length:")
                                .map(|v| v.trim().parse::<usize>().unwrap())
                        })
                        .unwrap_or(0);
                    if len >= i + 4 + cl {
                        break;
                    }
                }
            }
            let req = String::from_utf8_lossy(&buf[..len]).to_string();
            let line = req.lines().next().unwrap().to_string();
            let body = req.split("\r\n\r\n").nth(1).unwrap_or("").to_string();
            let payload = format!("{line}|{body}");
            let resp = format!(
                "HTTP/1.1 201 Created\r\nX-Test: yes\r\nTransfer-Encoding: chunked\r\n\r\n{:x}\r\n{payload}\r\n0\r\n\r\n",
                payload.len()
            );
            s.write_all(resp.as_bytes()).unwrap();
        }
    });
    port
}

fn run(args: &[&str], project: &std::path::Path, stdin: Option<&[u8]>) -> (i32, Value) {
    let mut child = bin()
        .args(["--format", "json", "--project"])
        .arg(project)
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    {
        let mut stdin_pipe = child.stdin.take().unwrap();
        if let Some(data) = stdin {
            stdin_pipe.write_all(data).unwrap();
        }
    }
    let out = child.wait_with_output().unwrap();
    let v: Value = serde_json::from_slice(&out.stdout)
        .unwrap_or_else(|e| panic!("bad JSON ({e}): {}", String::from_utf8_lossy(&out.stdout)));
    (out.status.code().unwrap(), v)
}

fn tmp_project(name: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!("bp-test-{}-{name}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let p = dir.join("p.bpdb");
    let _ = std::fs::remove_file(&p);
    let status = bin()
        .args(["--format", "json", "--project"])
        .arg(&p)
        .args(["engagement", "start", "--target", "127.0.0.1", "--target", "localhost"])
        .output()
        .unwrap();
    assert!(status.status.success(), "{}", String::from_utf8_lossy(&status.stdout));
    p
}

#[test]
fn send_raw_from_stdin_then_history() {
    let port = serve(1);
    let project = tmp_project("raw");
    // Unix line endings and a wrong Content-Length: both get fixed.
    let req = format!("POST /echo?a=1 HTTP/1.1\nHost: 127.0.0.1:{port}\nContent-Length: 99\n\nhi=there");
    let (code, v) = run(&["send", "--scheme", "http"], &project, Some(req.as_bytes()));
    assert_eq!(code, 0, "{v}");
    assert_eq!(v["ok"], true);
    let resp = &v["data"]["response"];
    assert_eq!(resp["status"], 201);
    assert_eq!(resp["body"]["content"], "POST /echo?a=1 HTTP/1.1|hi=there");
    let id = v["data"]["id"].as_i64().unwrap();

    let (code, v) = run(&["history", "list", "--status", "201"], &project, None);
    assert_eq!(code, 0);
    assert_eq!(v["data"]["count"], 1);
    assert_eq!(v["data"]["items"][0]["url"], format!("http://127.0.0.1:{port}/echo?a=1"));

    let (code, v) = run(&["history", "show", &id.to_string()], &project, None);
    assert_eq!(code, 0);
    assert!(v["data"]["request"]["content"].as_str().unwrap().contains("Content-Length: 8\r\n"));
}

#[test]
fn send_url_mode() {
    let port = serve(1);
    let project = tmp_project("url");
    let url = format!("http://127.0.0.1:{port}/x");
    let (code, v) = run(&["send", "--url", &url, "-X", "PUT", "-d", "abc", "-H", "X-A: 1"], &project, None);
    assert_eq!(code, 0, "{v}");
    assert_eq!(v["data"]["response"]["body"]["content"], "PUT /x HTTP/1.1|abc");
}

#[test]
fn connection_errors_are_structured() {
    // Bind and drop to get a port with nothing listening.
    let port = TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port();
    let project = tmp_project("err");
    let url = format!("http://127.0.0.1:{port}/");
    let (code, v) = run(&["send", "--url", &url], &project, None);
    assert_eq!(code, 3);
    assert_eq!(v["ok"], false);
    assert_eq!(v["error"]["kind"], "connect");
    // Failures are recorded too.
    let (_, v) = run(&["history", "list"], &project, None);
    assert_eq!(v["data"]["count"], 1);
}

#[test]
fn usage_and_not_found_errors() {
    let project = tmp_project("usage");
    let (code, v) = run(&["send", "--bogus"], &project, None);
    assert_eq!((code, v["error"]["kind"].as_str()), (2, Some("usage")));
    let (code, v) = run(&["history", "show", "42"], &project, None);
    assert_eq!((code, v["error"]["kind"].as_str()), (4, Some("not_found")));
}

#[test]
fn codecs_chain() {
    let project = tmp_project("codec");
    let (code, v) = run(&["encode", "url,base64", "a b"], &project, None);
    assert_eq!(code, 0);
    assert_eq!(v["data"]["output"]["content"], "YSUyMGI=");
    let (_, v) = run(&["decode", "base64,url", "-"], &project, Some(b"YSUyMGI="));
    assert_eq!(v["data"]["output"]["content"], "a b");
    let (_, v) = run(&["hash", "sha1", "abc"], &project, None);
    assert_eq!(v["data"]["output"]["content"], "a9993e364706816aba3e25717850c26c9cd0d89d");
}

#[test]
fn capabilities_lists_all_commands() {
    let project = tmp_project("caps");
    let (code, v) = run(&["capabilities"], &project, None);
    assert_eq!(code, 0);
    let names: Vec<&str> =
        v["data"]["commands"].as_array().unwrap().iter().map(|c| c["command"].as_str().unwrap()).collect();
    for want in [
        "send",
        "history",
        "query",
        "schema",
        "proxy",
        "ca",
        "scope",
        "rules",
        "intercept",
        "encode",
        "decode",
        "hash",
        "project",
    ] {
        assert!(names.contains(&want), "{want} missing from {names:?}");
    }
    assert_eq!(v["data"]["conventions"]["interactive_prompts"], false);
}

#[test]
fn query_schema_and_tags() {
    let port = serve(2);
    let project = tmp_project("query");
    for path in ["/a?x=1", "/b"] {
        let url = format!("http://127.0.0.1:{port}{path}");
        assert_eq!(run(&["send", "--url", &url], &project, None).0, 0);
    }

    let (code, v) = run(
        &["query", "SELECT id, path, header(resp_headers, 'x-test') AS h FROM history WHERE query = ?1", "-p", "x=1"],
        &project,
        None,
    );
    assert_eq!(code, 0, "{v}");
    assert_eq!(v["data"]["columns"], serde_json::json!(["id", "path", "h"]));
    assert_eq!(v["data"]["rows"], serde_json::json!([[1, "/a", "yes"]]));

    // FTS over the decoded (dechunked) body, objects shape, row limit.
    let (_, v) = run(
        &[
            "query",
            "--shape",
            "objects",
            "--limit",
            "1",
            "SELECT rowid AS id FROM history_fts WHERE history_fts MATCH 'GET'",
        ],
        &project,
        None,
    );
    assert_eq!(v["data"]["truncated"], true);
    assert_eq!(v["data"]["rows"][0]["id"], 1);

    // Read-only: writes are rejected as invalid input.
    let (code, v) = run(&["query", "DELETE FROM history"], &project, None);
    assert_eq!((code, v["error"]["kind"].as_str()), (2, Some("invalid_input")));

    let (_, v) = run(&["history", "tag", "2", "--add", "idor", "--add", "todo"], &project, None);
    assert_eq!(v["data"]["tags"], serde_json::json!(["idor", "todo"]));
    let (_, v) = run(&["history", "list", "--tag", "idor"], &project, None);
    assert_eq!(v["data"]["count"], 1);

    let (_, v) = run(&["schema"], &project, None);
    let cols = v["data"]["tables"][0]["columns"].as_array().unwrap();
    assert!(cols.iter().any(|c| c["name"] == "resp_body_text"));
    assert!(!v["data"]["examples"].as_array().unwrap().is_empty());
}

#[test]
fn capabilities_for_one_command() {
    let project = tmp_project("caps-one");
    let (code, v) = run(&["capabilities", "history", "list"], &project, None);
    assert_eq!(code, 0);
    assert_eq!(v["data"]["command"], "history list");
    let (code, _) = run(&["capabilities", "nope"], &project, None);
    assert_eq!(code, 4);
}
