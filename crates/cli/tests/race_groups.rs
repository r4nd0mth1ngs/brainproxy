//! A race group is validated as a whole, then sends each distinct request in blocking order.
use serde_json::{json, Value};
use std::io::{Read, Write};
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    mpsc, Arc,
};
use std::time::Duration;

fn run(p: &Path, args: &[&str], stdin: Option<&str>, mcp: bool) -> (i32, Value) {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_brainproxy"));
    cmd.args(["--format", "json", "--project"])
        .arg(p)
        .args(args)
        .env_remove("BRAINPROXY_SYSTEM_SCOPE")
        .env_remove("BRAINPROXY_MCP_CALL")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    if mcp {
        cmd.env("BRAINPROXY_MCP_CALL", "1");
    }
    let mut child = cmd.spawn().unwrap();
    if let Some(data) = stdin {
        child.stdin.take().unwrap().write_all(data.as_bytes()).unwrap();
    }
    drop(child.stdin.take());
    let out = child.wait_with_output().unwrap();
    let value =
        serde_json::from_slice(&out.stdout).unwrap_or_else(|e| panic!("{e}: {}", String::from_utf8_lossy(&out.stdout)));
    (out.status.code().unwrap(), value)
}

fn project(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("bp-race-group-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let p = dir.join("p.bpdb");
    assert_eq!(run(&p, &["engagement", "start", "--target", "127.0.0.1"], None, false).0, 0);
    p
}

fn raw(p: &Path, name: &str, host: &str) -> String {
    let file = p.with_extension(format!("{name}.http"));
    std::fs::write(&file, format!("POST /{name} HTTP/1.1\nHost: {host}\n\n{name}")).unwrap();
    file.to_str().unwrap().to_string()
}

fn server() -> (u16, Arc<AtomicUsize>, mpsc::Receiver<String>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let hits = Arc::new(AtomicUsize::new(0));
    let count = hits.clone();
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let mut stream = stream.unwrap();
            count.fetch_add(1, Ordering::SeqCst);
            let tx = tx.clone();
            std::thread::spawn(move || {
                stream.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
                let mut bytes = Vec::new();
                loop {
                    let mut buf = [0u8; 4096];
                    let n = stream.read(&mut buf).unwrap();
                    if n == 0 {
                        return;
                    }
                    bytes.extend_from_slice(&buf[..n]);
                    if let Some(at) = bytes.windows(4).position(|b| b == b"\r\n\r\n") {
                        let head = String::from_utf8_lossy(&bytes[..at]);
                        let len: usize = head
                            .lines()
                            .filter_map(|l| l.split_once(':'))
                            .find(|(k, _)| k.eq_ignore_ascii_case("content-length"))
                            .map(|(_, v)| v.trim().parse().unwrap())
                            .unwrap_or(0);
                        if bytes.len() >= at + 4 + len {
                            break;
                        }
                    }
                }
                let request = String::from_utf8(bytes).unwrap();
                let status = if request.starts_with("POST /checkout ") { "201 Created" } else { "200 OK" };
                let _ = tx.send(request);
                let _ = write!(stream, "HTTP/1.1 {status}\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok");
            });
        }
    });
    (port, hits, rx)
}

#[test]
fn distinct_requests_are_multiplied_and_recorded_with_full_positions() {
    for (name, count) in [("default", 1), ("multiply", 3)] {
        let p = project(name);
        let (port, hits, got) = server();
        let host = format!("127.0.0.1:{port}");
        let primary = raw(&p, "coupon", &host);
        let also = raw(&p, "checkout", &host);
        let count_arg = count.to_string();
        let mut args = vec!["send", &primary, "--scheme=http", "--also", &also];
        if count != 1 {
            args.extend(["--race", &count_arg]);
        }
        let (code, v) = run(&p, &args, None, false);
        assert_eq!(code, 0, "{v}");
        let d = &v["data"];
        assert_eq!(d["race"], count);
        assert_eq!(d["total"], 2 * count);
        assert_eq!(d["sync"], "last-byte");
        assert_eq!(
            d["requests"],
            json!([
                {"index": 0, "request_line": "POST /coupon HTTP/1.1"},
                {"index": 1, "request_line": "POST /checkout HTTP/1.1"}
            ])
        );
        let results = d["results"].as_array().unwrap();
        assert_eq!(results.len(), 2 * count);
        assert_eq!(hits.load(Ordering::SeqCst), 2 * count);
        let received: Vec<_> = (0..2 * count).map(|_| got.recv_timeout(Duration::from_secs(1)).unwrap()).collect();
        assert_eq!(received.iter().filter(|r| r.starts_with("POST /coupon ") && r.ends_with("coupon")).count(), count);
        assert_eq!(
            received.iter().filter(|r| r.starts_with("POST /checkout ") && r.ends_with("checkout")).count(),
            count
        );
        for (i, r) in results.iter().enumerate() {
            let member = i / count;
            assert_eq!(r["request"], member);
            assert_eq!(r["status"], if member == 0 { 200 } else { 201 });
            let id = r["id"].to_string();
            let (code, history) = run(&p, &["history", "show", &id], None, false);
            assert_eq!(code, 0, "{history}");
            assert_eq!(
                history["data"]["entry"]["tags"],
                json!([
                    format!("race:{}", d["race_id"].as_str().unwrap()),
                    "race-sync:last-byte".to_string(),
                    format!("race-pos:{}/{}", i + 1, 2 * count)
                ])
            );
        }
    }
}

#[test]
fn mixed_origins_are_refused_before_any_connection() {
    let p = project("origins");
    let (port, hits, _) = server();
    let (other, other_hits, _) = server();
    let a = raw(&p, "coupon", &format!("127.0.0.1:{port}"));
    let b = raw(&p, "checkout", &format!("127.0.0.1:{other}"));
    let (code, v) = run(&p, &["send", &a, "--scheme=http", "--also", &b], None, false);
    assert_eq!(code, 2, "{v}");
    let message = v["error"]["message"].as_str().unwrap();
    assert!(
        message.contains("same origin")
            && message.contains(&format!("http://127.0.0.1:{port}"))
            && message.contains(&format!("http://127.0.0.1:{other}")),
        "{v}"
    );
    assert_eq!(hits.load(Ordering::SeqCst) + other_hits.load(Ordering::SeqCst), 0);
    let (_, v) = run(&p, &["query", "SELECT count(*) FROM history"], None, false);
    assert_eq!(v["data"]["rows"][0][0], 0);
}

#[test]
fn additional_scope_and_host_checks_precede_every_send() {
    let p = project("checks");
    let (port, hits, _) = server();
    let a = raw(&p, "coupon", &format!("127.0.0.1:{port}"));
    let b = raw(&p, "checkout", "unlisted.invalid");
    // Additional target is outside the scope, even though the primary is allowed.
    let (code, v) = run(&p, &["send", &a, "--scheme=http", "--also", &b], None, false);
    assert_eq!(code, 6, "{v}");
    assert_eq!(hits.load(Ordering::SeqCst), 0);
    // An explicit target applies to the whole group; through MCP a foreign Host still needs opt-in.
    let target = format!("http://127.0.0.1:{port}");
    let (code, v) = run(&p, &["send", &a, "--target", &target, "--also", &b], None, true);
    assert_eq!(code, 6, "{v}");
    assert!(v["error"]["message"].as_str().unwrap().contains("--host-header-test"), "{v}");
    assert_eq!(hits.load(Ordering::SeqCst), 0);
    let (code, v) = run(&p, &["send", &a, "--target", &target, "--also", &b, "--host-header-test"], None, true);
    assert_eq!(code, 0, "{v}");
    assert_eq!(hits.load(Ordering::SeqCst), 2);
}

#[test]
fn stdin_is_available_once_and_total_limits_are_checked() {
    let p = project("inputs");
    let (port, hits, _) = server();
    let url = format!("http://127.0.0.1:{port}/primary");
    let b = format!("GET /secondary HTTP/1.1\nHost: 127.0.0.1:{port}\n\n");
    let (code, v) = run(&p, &["send", "--url", &url, "--also=-"], Some(&b), false);
    assert_eq!(code, 0, "{v}");
    assert_eq!(v["data"]["total"], 2);
    let (code, v) = run(&p, &["send", "-", "--also=-"], None, false);
    assert_eq!(code, 2, "{v}");
    assert!(v["error"]["message"].as_str().unwrap().contains("stdin may be read only once"));
    let file = raw(&p, "secondary", &format!("127.0.0.1:{port}"));
    for opts in [["--http2", "--race=51"], ["--race=501", "--scheme=http"]] {
        let (code, v) = run(&p, &["send", "--url", &url, "--also", &file, opts[0], opts[1]], None, false);
        assert_eq!(code, 2, "{v}");
        assert!(
            v["error"]["message"].as_str().unwrap().contains(if opts[0] == "--http2" { "100" } else { "1000" }),
            "{v}"
        );
    }
    assert_eq!(hits.load(Ordering::SeqCst), 2);
}

#[test]
fn auth_is_applied_to_every_distinct_request() {
    let p = project("auth");
    let (port, _, got) = server();
    let a = raw(&p, "coupon", &format!("127.0.0.1:{port}"));
    let b = raw(&p, "checkout", &format!("127.0.0.1:{port}"));
    let (code, v) = run(&p, &["auth", "add", "app", "--header", "X-Session: secret123"], None, false);
    assert_eq!(code, 0, "{v}");
    let (code, v) = run(&p, &["send", &a, "--also", &b, "--auth=app", "--scheme=http"], None, false);
    assert_eq!(code, 0, "{v}");
    for _ in 0..2 {
        let request = got.recv_timeout(Duration::from_secs(1)).unwrap();
        assert!(request.contains("X-Session: secret123\r\n"), "{request}");
    }
}

#[test]
fn auth_profile_host_header_is_not_re_checked_against_scope_under_mcp() {
    // An MCP race with --auth and an in-scope Host succeeds: the session's prepared request (which
    // may carry provenance markers) is not re-checked against the scope as if its Host were foreign.
    let p = project("auth-host");
    let (port, hits, _) = server();
    let host = format!("127.0.0.1:{port}");
    let a = raw(&p, "coupon", &host);
    let b = raw(&p, "checkout", &host);
    let (code, v) = run(&p, &["auth", "add", "app", "--header", &format!("Host: {host}")], None, false);
    assert_eq!(code, 0, "{v}");
    let (code, v) = run(&p, &["send", &a, "--also", &b, "--auth=app", "--scheme=http", "--race=2"], None, true);
    assert_eq!(code, 0, "{v}");
    assert_eq!(hits.load(Ordering::SeqCst), 4);
}

#[test]
fn an_http2_request_line_does_not_force_the_auth_login_onto_http2() {
    // The race honours an HTTP/2 request line itself (single_packet opens its own connection); the
    // --auth login still goes out over HTTP/1.1, not as an HTTP/2 preface to a login endpoint.
    let login = TcpListener::bind("127.0.0.1:0").unwrap();
    let login_port = login.local_addr().unwrap().port();
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        for stream in login.incoming() {
            let mut stream = stream.unwrap();
            let mut buf = [0u8; 1024];
            let n = stream.read(&mut buf).unwrap();
            let first = String::from_utf8_lossy(&buf[..n]).lines().next().unwrap_or("").to_string();
            let _ = tx.send(first);
            let _ = stream
                .write_all(b"HTTP/1.1 200 OK\r\nSet-Cookie: s=1\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
        }
    });
    let p = project("http2-login");
    let (port, _, _) = server();
    let login_url = format!("http://127.0.0.1:{login_port}/login");
    let (code, v) = run(
        &p,
        &[
            "auth",
            "add",
            "app",
            "--login-url",
            &login_url,
            "--login-body",
            "user={{username}}&pass={{password}}",
            "--username",
            "a",
            "--password",
            "b",
        ],
        None,
        false,
    );
    assert_eq!(code, 0, "{v}");
    // Primary request line says HTTP/2; the login must still go out over HTTP/1.1.
    let primary = p.with_extension("coupon-h2.http");
    std::fs::write(&primary, format!("GET /coupon HTTP/2\r\nHost: 127.0.0.1:{port}\r\n\r\n")).unwrap();
    let also = raw(&p, "checkout", &format!("127.0.0.1:{port}"));
    // The race itself (single-packet to a plain server) may fail; we only check the login request.
    let _ = run(&p, &["send", primary.to_str().unwrap(), "--also", &also, "--auth=app", "--race=2"], None, false);
    let login_line = rx.recv_timeout(Duration::from_secs(5)).expect("login request never arrived");
    assert!(login_line.contains("HTTP/1.1") && login_line.contains("/login"), "login went out as {login_line:?}");
}

#[cfg(unix)]
#[test]
fn fd_budget_applies_to_the_total_not_the_copy_count() {
    use std::os::unix::process::CommandExt;
    let p = project("fd-budget");
    let file = raw(&p, "checkout", "127.0.0.1:1");
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_brainproxy"));
    cmd.args(["--format", "json", "--project"]).arg(&p).args([
        "send",
        "--url=http://127.0.0.1:1/coupon",
        "--also",
        &file,
        "--race=25",
    ]);
    // The CLI raises the soft limit to the hard one, so constrain both in this child only.
    unsafe {
        cmd.pre_exec(|| {
            let limit = libc::rlimit { rlim_cur: 96, rlim_max: 96 };
            if libc::setrlimit(libc::RLIMIT_NOFILE, &limit) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let out = cmd.output().unwrap();
    let v: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(out.status.code(), Some(2), "{v}");
    assert!(v["error"]["message"].as_str().unwrap().contains("needs 50 connections"), "{v}");
}
