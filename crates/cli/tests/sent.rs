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
    assert!(
        v["error"]["message"].as_str().unwrap().contains("cancelled by user before a response was recorded"),
        "{v}"
    );

    let r = rows(&p, "SELECT source, error, status, request FROM history");
    assert_eq!(r.len(), 1, "{r:?}");
    assert_eq!(r[0][0], "send");
    assert_eq!(r[0][1], "cancelled by user before a response was recorded");
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
    // The query string is left out too: it often holds a token.
    assert_eq!(r[0][3].as_str(), Some(format!("http://127.0.0.1:{port}/private").as_str()));
    assert_eq!(r[0][4], Value::Null);
    assert_eq!(r[0][5], "not stored (--no-store): content omitted; query string omitted; response status 200");
    assert_eq!(r[0][6], "POST /private HTTP/1.1\r\n\r\n");
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
    // Not an HTTP/2 server: the single-packet race fails after connecting, as a whole.
    let port = answering();
    let url = format!("http://127.0.0.1:{port}/race");
    let (code, v) = run(&p, &["send", "--http2", "--race", "3", "--url", &url]);
    assert_eq!((code, v["ok"].as_bool(), v["error"]["kind"].as_str()), (3, Some(false), Some("protocol")), "{v}");
    let items = v["data"]["results"].as_array().unwrap();
    assert_eq!(items.len(), 3);
    let ids: Vec<i64> = items.iter().map(|i| i["id"].as_i64().expect("error items carry their history id")).collect();
    assert!(items.iter().all(|i| i["error"].is_string()), "{v}");
    for id in &ids {
        assert!(v["error"]["message"].as_str().unwrap().contains(&format!("#{id}")), "{v}");
    }
    let r = rows(&p, "SELECT id, source, status, error FROM history ORDER BY id");
    assert_eq!(r.len(), 3);
    for (row, id) in r.iter().zip(ids) {
        assert_eq!((row[0].as_i64(), row[1].as_str(), &row[2]), (Some(id), Some("race"), &Value::Null));
        assert!(row[3].as_str().unwrap().contains("HTTP/2"), "{row:?}");
    }
}

/// A login site: POST /login answers "Welcome alice" with a new session cookie (from the
/// second login on, after `relogin_delay`); GET /api is 401 unless it has the latest cookie.
/// Each request's first line goes to the returned channel.
fn login_site(relogin_delay: Duration) -> (u16, mpsc::Receiver<String>) {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let (tx, rx) = mpsc::channel();
    let logins = Arc::new(AtomicUsize::new(0));
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let (mut s, tx, logins) = (stream.unwrap(), tx.clone(), logins.clone());
            std::thread::spawn(move || loop {
                let mut buf = Vec::new();
                let mut byte = [0u8; 1];
                while !buf.ends_with(b"\r\n\r\n") {
                    match s.read(&mut byte) {
                        Ok(1) => buf.push(byte[0]),
                        _ => return,
                    }
                }
                let head = String::from_utf8_lossy(&buf).to_string();
                let length = head
                    .lines()
                    .find_map(|l| {
                        l.to_ascii_lowercase().strip_prefix("content-length:").map(|v| v.trim().parse().unwrap())
                    })
                    .unwrap_or(0usize);
                let mut body = vec![0u8; length];
                let _ = s.read_exact(&mut body);
                let line = head.lines().next().unwrap_or_default().to_string();
                let _ = tx.send(line.clone());
                let reply = if line.starts_with("POST /login") {
                    let n = logins.fetch_add(1, Ordering::SeqCst) + 1;
                    if n > 1 {
                        std::thread::sleep(relogin_delay);
                    }
                    let body = "Welcome alice";
                    format!("HTTP/1.1 200 OK\r\nSet-Cookie: sid=s{n}\r\nContent-Length: {}\r\n\r\n{body}", body.len())
                } else {
                    let current = format!("sid=s{}", logins.load(Ordering::SeqCst));
                    // The first session is never good enough: the request needs a fresh login.
                    if head.contains(&current) && !current.ends_with("s1") {
                        "HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nfresh".to_string()
                    } else {
                        "HTTP/1.1 401 Unauthorized\r\nContent-Length: 10\r\n\r\nlogged out".to_string()
                    }
                };
                if s.write_all(reply.as_bytes()).is_err() {
                    return;
                }
            });
        }
    });
    (port, rx)
}

/// A project with profile `app` for `login_site`, logged in once.
fn logged_in(name: &str, port: u16) -> PathBuf {
    let p = project(name);
    let login = format!("http://127.0.0.1:{port}/login");
    let (code, v) = run(
        &p,
        &["auth", "add", "app", "--login-url", &login, "--login-body", "u=alice", "--logged-in", "Welcome alice"],
    );
    assert_eq!(code, 0, "{v}");
    let (code, v) = run(&p, &["auth", "login", "app"]);
    assert_eq!(code, 0, "{v}");
    p
}

#[cfg(unix)]
#[test]
fn stopping_during_a_relogin_keeps_the_answered_row() {
    let (port, lines) = login_site(Duration::from_secs(60));
    let p = logged_in("relogin-stop", port);
    let url = format!("http://127.0.0.1:{port}/api");
    let child = spawn(&p, &["send", "--auth", "app", "--url", &url, "--timeout", "90"]);
    // Wait for the second login: the 401 is in, the retry hasn't gone out.
    let mut logins = 0;
    while logins < 2 {
        let line = lines.recv_timeout(Duration::from_secs(20)).expect("no re-login");
        logins += usize::from(line.starts_with("POST /login"));
    }
    std::thread::sleep(Duration::from_millis(300));
    Command::new("kill").args(["-TERM", &child.id().to_string()]).status().unwrap();
    let out = child.wait_with_output().unwrap();
    assert_ne!(out.status.code(), Some(0));
    let r = rows(&p, "SELECT source, path, status, error FROM history WHERE id > 1 ORDER BY id");
    assert_eq!(
        r,
        serde_json::json!([
            ["send", "/api", 401, null],
            // The login the stop cut short: sent, never answered.
            ["auth", "/login", null, "sent; no response recorded (cancelled or interrupted)"]
        ])
        .as_array()
        .unwrap()
        .clone()
    );
}

#[test]
fn no_store_covers_the_session_requests_and_the_query() {
    let (port, _lines) = login_site(Duration::ZERO);
    let p = logged_in("nostore-auth", port);
    let url = format!("http://127.0.0.1:{port}/api?api_key=SECRET123");
    let (code, v) = run(&p, &["send", "--no-store", "--auth", "app", "--url", &url]);
    assert_eq!(code, 0, "{v}");
    assert_eq!(v["data"]["response"]["status"], 200);
    // The 401, the re-login, and the retry: all without content.
    let r = rows(&p, "SELECT source, request, error FROM history WHERE id > 1 ORDER BY id");
    assert_eq!(r.len(), 3, "{r:?}");
    let expect = [
        ("send", "GET /api HTTP/1.1\r\n\r\n", "; query string omitted; response status 401"),
        ("auth", "POST /login HTTP/1.1\r\n\r\n", "; response status 200"),
        ("send", "GET /api HTTP/1.1\r\n\r\n", "; query string omitted; response status 200"),
    ];
    for (row, (source, request, end)) in r.iter().zip(expect) {
        assert_eq!((row[0].as_str(), row[1].as_str()), (Some(source), Some(request)));
        assert_eq!(row[2].as_str().unwrap(), format!("not stored (--no-store): content omitted{end}"));
    }
    let leaks =
        "SELECT count(*) FROM history WHERE id > 1 AND (instr(url, 'SECRET123') OR instr(request, 'SECRET123') \
        OR length(response) > 0 OR query IS NOT NULL)";
    assert_eq!(rows(&p, leaks)[0][0], 0);
    let fts = "SELECT count(*) FROM history_fts WHERE history_fts MATCH 'SECRET123'";
    assert_eq!(rows(&p, fts)[0][0], 0);
}

#[test]
fn a_proxy_relogin_records_the_first_exchange() {
    let (port, _lines) = login_site(Duration::ZERO);
    let p = logged_in("proxy-relogin", port);
    let home = p.parent().unwrap().join("home");
    let home = home.to_str().unwrap();
    let (code, v) = run(&p, &["--home", home, "proxy", "start", "--listen", "127.0.0.1:0", "--auth", "app"]);
    assert_eq!(code, 0, "{v}");
    let listen = v["data"]["listen"].as_str().unwrap().to_string();
    let mut s = std::net::TcpStream::connect(&listen).unwrap();
    write!(s, "GET http://127.0.0.1:{port}/api HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nConnection: close\r\n\r\n")
        .unwrap();
    let mut answer = String::new();
    s.read_to_string(&mut answer).unwrap();
    assert!(answer.starts_with("HTTP/1.1 200") && answer.ends_with("fresh"), "{answer}");
    let (code, v) = run(&p, &["--home", home, "proxy", "stop"]);
    assert_eq!(code, 0, "{v}");
    // The 401 that started the re-login has its row, then the retry's.
    let r = rows(&p, "SELECT path, status FROM history WHERE source = 'proxy' ORDER BY id");
    assert_eq!(r, serde_json::json!([["/api", 401], ["/api", 200]]).as_array().unwrap().clone());
}
