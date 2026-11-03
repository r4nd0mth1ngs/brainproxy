//! A request that went on the wire always leaves a history row: `send` records it before it
//! goes out, so cancelling (SIGTERM), killing (SIGKILL), a failed HTTP/2 race, and
//! `--no-store` all leave one. Local servers only.

use std::io::{Read, Write};
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::time::Duration;

use serde_json::Value;

fn bin() -> Command {
    Command::new(env!("CARGO_BIN_EXE_brainproxy"))
}

fn project(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("bp-sent-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let p = dir.join("p.bpdb");
    run(&p, &["engagement", "start", "--target", "127.0.0.1"]);
    p
}

fn run(project: &Path, args: &[&str]) -> (i32, Value) {
    let out = bin().args(["--format", "json", "--project"]).arg(project).args(args).output().unwrap();
    let v = serde_json::from_slice(&out.stdout)
        .unwrap_or_else(|e| panic!("bad JSON ({e}): {}", String::from_utf8_lossy(&out.stdout)));
    (out.status.code().unwrap(), v)
}

fn rows(project: &Path, sql: &str) -> Vec<Value> {
    let (code, v) = run(project, &["query", sql]);
    assert_eq!(code, 0, "{v}");
    v["data"]["rows"].as_array().unwrap().clone()
}

fn spawn(project: &Path, args: &[&str]) -> Child {
    bin()
        .args(["--format", "json", "--project"])
        .arg(project)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap()
}

/// A server that reads one request, hands it over, and never answers.
fn silent() -> (u16, mpsc::Receiver<Vec<u8>>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let mut held = Vec::new();
        for stream in listener.incoming() {
            let mut s = stream.unwrap();
            let mut buf = vec![0u8; 65536];
            let mut len = 0;
            while !buf[..len].windows(4).any(|w| w == b"\r\n\r\n") {
                match s.read(&mut buf[len..]) {
                    Ok(0) | Err(_) => break,
                    Ok(n) => len += n,
                }
            }
            let _ = tx.send(buf[..len].to_vec());
            held.push(s);
        }
    });
    (port, rx)
}

/// One request answered 200 with a body.
fn answering() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let mut s = stream.unwrap();
            let mut buf = [0u8; 4096];
            let _ = s.read(&mut buf);
            let _ = s.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 6\r\nX-Secret: s3cr3t\r\n\r\nhidden");
        }
    });
    port
}

/// Starts `send` to a server that never answers and waits until the request has arrived.
fn send_and_wait(name: &str) -> (PathBuf, Child, Vec<u8>) {
    let p = project(name);
    let (port, got) = silent();
    let url = format!("http://127.0.0.1:{port}/slow?q=1");
    let child = spawn(&p, &["send", "--url", &url, "-H", "X-Test: yes", "--timeout", "60"]);
    let received = got.recv_timeout(Duration::from_secs(20)).expect("the request never arrived");
    (p, child, received)
}

#[cfg(unix)]
#[test]
fn sigterm_records_the_request_as_cancelled() {
    let (p, child, received) = send_and_wait("term");
    let status = Command::new("kill").args(["-TERM", &child.id().to_string()]).status().unwrap();
    assert!(status.success());
    let out = child.wait_with_output().unwrap();
    assert_ne!(out.status.code(), Some(0));
    let v: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert!(v["error"]["message"].as_str().unwrap().contains("cancelled by user after the request was sent"), "{v}");

    let r = rows(&p, "SELECT source, error, status, request FROM history");
    assert_eq!(r.len(), 1, "{r:?}");
    assert_eq!(r[0][0], "send");
    assert_eq!(r[0][1], "cancelled by user after the request was sent");
    assert_eq!(r[0][2], Value::Null);
    // Recorded exactly as it went out.
    assert_eq!(r[0][3].as_str().unwrap().as_bytes(), &received[..]);
}

#[test]
fn a_killed_send_leaves_its_pending_row() {
    let (p, mut child, received) = send_and_wait("kill");
    child.kill().unwrap();
    child.wait().unwrap();
    let r = rows(&p, "SELECT source, error, url, request FROM history");
    assert_eq!(r.len(), 1, "{r:?}");
    assert_eq!(r[0][1], "sent; no response recorded (cancelled or interrupted)");
    assert!(r[0][2].as_str().unwrap().ends_with("/slow?q=1"));
    assert_eq!(r[0][3].as_str().unwrap().as_bytes(), &received[..]);
}

#[test]
fn a_finished_send_completes_its_row() {
    let p = project("done");
    let port = answering();
    let (code, v) = run(&p, &["send", "--url", &format!("http://127.0.0.1:{port}/ok")]);
    assert_eq!(code, 0, "{v}");
    let r = rows(&p, "SELECT id, status, error, resp_body_text FROM history");
    assert_eq!(r, vec![serde_json::json!([v["data"]["id"], 200, null, "hidden"])]);
}

#[test]
fn no_store_keeps_a_row_without_content() {
    let p = project("nostore");
    let port = answering();
    let url = format!("http://127.0.0.1:{port}/private?token=abc");
    let (code, v) = run(&p, &["send", "--url", &url, "-X", "POST", "-d", "pw=hunter2", "--no-store"]);
    assert_eq!(code, 0, "{v}");
    // The output still shows the exchange.
    assert_eq!(v["data"]["response"]["status"], 200);
    let r = rows(&p, "SELECT id, source, method, url, status, error, request, response, req_body FROM history");
    assert_eq!(r.len(), 1);
    assert_eq!(r[0][0], v["data"]["id"]);
    assert_eq!((r[0][1].as_str(), r[0][2].as_str()), (Some("send"), Some("POST")));
    assert_eq!(r[0][3].as_str(), Some(url.as_str()));
    assert_eq!(r[0][4], Value::Null);
    assert_eq!(r[0][5], "not stored (--no-store): content omitted; response status 200");
    assert_eq!(r[0][6], "POST /private?token=abc HTTP/1.1\r\n\r\n");
    assert_eq!((r[0][7].as_str(), r[0][8].as_str()), (Some(""), Some("")));

    // Races too: one row per copy.
    let (code, v) = run(&p, &["send", "--url", &url, "--race", "3", "--no-store"]);
    assert_eq!(code, 0, "{v}");
    let r = rows(&p, "SELECT count(*) FROM history WHERE source = 'race' AND error LIKE 'not stored (--no-store)%'");
    assert_eq!(r[0][0], 3);
}

#[test]
fn a_failed_http2_race_records_every_copy() {
    let p = project("h2race");
    // Not an HTTP/2 server: the single-packet race fails after connecting.
    let port = answering();
    let url = format!("http://127.0.0.1:{port}/race");
    let (code, v) = run(&p, &["send", "--http2", "--race", "3", "--url", &url]);
    assert_eq!(code, 0, "{v}");
    let items = v["data"]["results"].as_array().unwrap();
    assert_eq!(items.len(), 3);
    let ids: Vec<i64> = items.iter().map(|i| i["id"].as_i64().expect("error items carry their history id")).collect();
    assert!(items.iter().all(|i| i["error"].is_string()), "{v}");
    let r = rows(&p, "SELECT id, source, status, error FROM history ORDER BY id");
    assert_eq!(r.len(), 3);
    for (row, id) in r.iter().zip(ids) {
        assert_eq!((row[0].as_i64(), row[1].as_str(), &row[2]), (Some(id), Some("race"), &Value::Null));
        assert!(row[3].as_str().unwrap().contains("HTTP/2"), "{row:?}");
    }
}
