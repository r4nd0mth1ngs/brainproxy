//! `send --sequence`: a group sent in order, over one connection or a new connection each, each
//! request recorded, and a stop that says how far the group got.
use serde_json::Value;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::Duration;

fn run(p: &Path, args: &[&str]) -> (i32, Value) {
    let out = Command::new(env!("CARGO_BIN_EXE_brainproxy"))
        .args(["--format", "json", "--project"])
        .arg(p)
        .args(args)
        .env_remove("BRAINPROXY_SYSTEM_SCOPE")
        .env_remove("BRAINPROXY_MCP_CALL")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .unwrap();
    let value =
        serde_json::from_slice(&out.stdout).unwrap_or_else(|e| panic!("{e}: {}", String::from_utf8_lossy(&out.stdout)));
    (out.status.code().unwrap(), value)
}

/// As an MCP tool call runs it: `stdin` is the call's stdin.
fn run_mcp(p: &Path, args: &[&str], stdin: &str) -> (i32, Value) {
    let mut child = Command::new(env!("CARGO_BIN_EXE_brainproxy"))
        .args(["--format", "json", "--project"])
        .arg(p)
        .args(args)
        .env_remove("BRAINPROXY_SYSTEM_SCOPE")
        .env("BRAINPROXY_MCP_CALL", "1")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    // A command that fails on its arguments may exit before reading its stdin.
    let _ = child.stdin.take().unwrap().write_all(stdin.as_bytes());
    let out = child.wait_with_output().unwrap();
    let value =
        serde_json::from_slice(&out.stdout).unwrap_or_else(|e| panic!("{e}: {}", String::from_utf8_lossy(&out.stdout)));
    (out.status.code().unwrap(), value)
}

fn project(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("bp-sequence-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let p = dir.join("p.bpdb");
    assert_eq!(run(&p, &["engagement", "start", "--target", "127.0.0.1"]).0, 0);
    p
}

/// A raw request file `name` for `POST /name` with `name` as its body.
fn raw(p: &Path, name: &str, port: u16) -> String {
    let file = p.with_extension(format!("{name}.http"));
    std::fs::write(&file, format!("POST /{name} HTTP/1.1\nHost: 127.0.0.1:{port}\n\n{name}")).unwrap();
    file.to_str().unwrap().to_string()
}

/// What the server saw: each request in the order it arrived, with the connection it came on
/// (counted from 1, in the order they were accepted).
type Seen = Arc<Mutex<Vec<(usize, String)>>>;

/// An HTTP/1.1 server that answers the k-th request on a connection (from 0) with
/// `answer(k, request)`, and closes the connection without answering when that is None.
fn server(answer: fn(usize, &str) -> Option<String>) -> (u16, Seen) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let seen: Seen = Arc::default();
    let log = seen.clone();
    std::thread::spawn(move || {
        for (conn, stream) in listener.incoming().enumerate() {
            let Ok(mut stream) = stream else { return };
            let log = log.clone();
            std::thread::spawn(move || {
                stream.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
                let mut buf = Vec::new();
                for k in 0.. {
                    let request = loop {
                        if let Some(at) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                            let head = String::from_utf8_lossy(&buf[..at]).to_string();
                            let len: usize = head
                                .lines()
                                .filter_map(|l| l.split_once(':'))
                                .find(|(k, _)| k.eq_ignore_ascii_case("content-length"))
                                .map_or(0, |(_, v)| v.trim().parse().unwrap());
                            if buf.len() >= at + 4 + len {
                                break String::from_utf8_lossy(&buf.drain(..at + 4 + len).collect::<Vec<u8>>())
                                    .to_string();
                            }
                        }
                        let mut chunk = [0u8; 4096];
                        match stream.read(&mut chunk) {
                            Ok(0) | Err(_) => return,
                            Ok(n) => buf.extend_from_slice(&chunk[..n]),
                        }
                    };
                    log.lock().unwrap().push((conn + 1, request.clone()));
                    match answer(k, &request) {
                        Some(a) => {
                            let _ = stream.write_all(a.as_bytes());
                        }
                        None => return,
                    }
                }
            });
        }
    });
    (port, seen)
}

fn ok(body: &str) -> String {
    format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{body}", body.len())
}

/// Each request is answered with its own path, on a kept-alive connection.
fn echo(_: usize, request: &str) -> Option<String> {
    Some(ok(request.split(' ').nth(1).unwrap_or("")))
}

/// Lines of the requests the server saw, with their connection.
fn lines(seen: &Seen) -> Vec<(usize, String)> {
    seen.lock().unwrap().iter().map(|(c, r)| (*c, r.lines().next().unwrap_or("").to_string())).collect()
}

fn history_tags(p: &Path, id: &Value) -> Value {
    let (code, v) = run(p, &["history", "show", &id.to_string()]);
    assert_eq!(code, 0, "{v}");
    v["data"]["entry"]["tags"].clone()
}

#[test]
fn single_sends_in_order_over_one_connection_and_separate_over_one_each() {
    for (how, connections) in [("single", [1, 1, 1]), ("separate", [1, 2, 3])] {
        let p = project(how);
        let (port, seen) = server(echo);
        let (a, b, c) = (raw(&p, "a", port), raw(&p, "b", port), raw(&p, "c", port));
        let (code, v) = run(&p, &["send", &a, "--scheme=http", "--also", &b, "--also", &c, "--sequence", how]);
        assert_eq!(code, 0, "{v}");
        let d = &v["data"];
        assert_eq!(
            (d["sequence"].as_str(), d["total"].as_u64(), d["answered"].as_u64()),
            (Some(how), Some(3), Some(3))
        );
        assert_eq!((d["complete"].as_bool(), d["connections"].as_u64()), (Some(true), Some(connections[2] as u64)));
        assert!(d["stopped"].is_null(), "{d}");
        // The server saw them in order, on the connections the mode says.
        let want: Vec<(usize, String)> =
            ["a", "b", "c"].iter().zip(connections).map(|(n, c)| (c, format!("POST /{n} HTTP/1.1"))).collect();
        assert_eq!(lines(&seen), want);
        // The results are in order, each the request's own response, and each recorded.
        let results = d["results"].as_array().unwrap();
        let sequence_id = d["sequence_id"].as_str().unwrap();
        for (i, (r, name)) in results.iter().zip(["a", "b", "c"]).enumerate() {
            assert_eq!(r["request"], i, "{r}");
            assert_eq!(r["outcome"], "answered", "{r}");
            assert_eq!(r["request_line"], format!("POST /{name} HTTP/1.1"));
            assert_eq!(r["response"]["status"], 200);
            assert_eq!(r["response"]["body"]["content"], format!("/{name}"));
            let tags = history_tags(&p, &r["id"]);
            for tag in
                [format!("sequence:{sequence_id}"), format!("sequence-conn:{how}"), format!("sequence-pos:{}/3", i + 1)]
            {
                assert!(tags.as_array().unwrap().iter().any(|t| t == &tag), "{tag} not in {tags}");
            }
        }
        let (_, rows) = run(&p, &["query", "SELECT source, status FROM history ORDER BY id"]);
        assert_eq!(rows["data"]["rows"].to_string(), r#"[["send",200],["send",200],["send",200]]"#);
    }
}

#[test]
fn a_server_that_closes_early_stops_the_sequence_and_says_how_far_it_got() {
    // The first answer says Connection: close: the rest aren't sent at all.
    let p = project("close-header");
    let (port, seen) =
        server(|_, _| Some("HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok".into()));
    let (a, b, c) = (raw(&p, "a", port), raw(&p, "b", port), raw(&p, "c", port));
    let (code, v) = run(&p, &["send", &a, "--scheme=http", "--also", &b, "--also", &c, "--sequence", "single"]);
    assert_eq!((code, v["ok"].as_bool()), (3, Some(false)), "{v}");
    assert_eq!(v["error"]["kind"], "protocol");
    let message = v["error"]["message"].as_str().unwrap();
    assert!(
        message.contains("stopped after request 0, so requests 1 to 2 weren't sent")
            && message.contains("Connection: close"),
        "{message}"
    );
    let d = &v["error"]["data"];
    assert_eq!((d["answered"].as_u64(), d["complete"].as_bool()), (Some(1), Some(false)), "{d}");
    assert_eq!((d["stopped"]["request"].as_u64(), d["stopped"]["cause"].as_str()), (Some(1), Some("closed")));
    assert_eq!(d["stopped"]["reason"], "the response said Connection: close");
    let outcomes: Vec<&str> = d["results"].as_array().unwrap().iter().map(|r| r["outcome"].as_str().unwrap()).collect();
    assert_eq!(outcomes, ["answered", "not_sent", "not_sent"]);
    assert_eq!(lines(&seen), [(1, "POST /a HTTP/1.1".to_string())]);
    let (_, rows) = run(&p, &["query", "SELECT count(*) FROM history"]);
    assert_eq!(rows["data"]["rows"][0][0], 1, "only what was sent is recorded");

    // The server closes without a word after the first answer: the second request fails (its
    // row says so), and the third isn't sent.
    let p = project("close-silent");
    let (port, seen) = server(|k, r| (k == 0).then(|| echo(k, r)).flatten());
    let (a, b, c) = (raw(&p, "a", port), raw(&p, "b", port), raw(&p, "c", port));
    let (code, v) = run(&p, &["send", &a, "--scheme=http", "--also", &b, "--also", &c, "--sequence", "single"]);
    assert_eq!((code, v["ok"].as_bool()), (3, Some(false)), "{v}");
    let message = v["error"]["message"].as_str().unwrap();
    assert!(message.contains("request 1 of the sequence of 3 failed, so request 2 wasn't sent"), "{message}");
    let d = &v["error"]["data"];
    let results = d["results"].as_array().unwrap();
    assert_eq!(results[1]["outcome"], "failed", "{d}");
    assert_eq!(results[2]["outcome"], "not_sent", "{d}");
    assert_eq!((d["stopped"]["request"].as_u64(), d["stopped"]["cause"].as_str()), (Some(1), Some("failed")));
    assert_eq!(lines(&seen), [(1, "POST /a HTTP/1.1".to_string()), (1, "POST /b HTTP/1.1".to_string())]);
    let (_, show) = run(&p, &["history", "show", &results[1]["id"].to_string()]);
    let error = show["data"]["entry"]["error"].as_str().unwrap_or("");
    assert!(!error.is_empty() && !error.starts_with("sent; no response"), "the failed row says how: {show}");

    // A separate connection each carries on past a server that closes after every answer.
    let p = project("close-separate");
    let (port, seen) =
        server(|_, _| Some("HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok".into()));
    let (a, b) = (raw(&p, "a", port), raw(&p, "b", port));
    let (code, v) = run(&p, &["send", &a, "--scheme=http", "--also", &b, "--sequence", "separate"]);
    assert_eq!(code, 0, "{v}");
    assert_eq!(lines(&seen).len(), 2);
}

#[test]
fn a_url_request_keeps_the_connection_open_and_the_session_carries_cookies_along() {
    let p = project("url-auth");
    // The first answer sets a cookie; every answer echoes the request's Connection and Cookie.
    let (port, seen) = server(|k, r| {
        let header = |n: &str| {
            r.lines().find_map(|l| l.split_once(':').filter(|(k, _)| k.eq_ignore_ascii_case(n))).map(|(_, v)| v.trim())
        };
        let body = format!("{} {}", header("connection").unwrap_or("-"), header("cookie").unwrap_or("-"));
        let cookie = if k == 0 { "Set-Cookie: step=one\r\n" } else { "" };
        Some(format!("HTTP/1.1 200 OK\r\n{cookie}Content-Length: {}\r\n\r\n{body}", body.len()))
    });
    assert_eq!(run(&p, &["auth", "add", "app", "-H", "X-App: 1"]).0, 0);
    let b = raw(&p, "b", port);
    let url = format!("http://127.0.0.1:{port}/a");
    let (code, v) = run(&p, &["send", "--url", &url, "--also", &b, "--sequence", "single", "--auth", "app"]);
    assert_eq!(code, 0, "{v}");
    let results = v["data"]["results"].as_array().unwrap();
    // --url says keep-alive, not its usual close, so the second request has a connection to go on.
    assert_eq!(results[0]["response"]["body"]["content"], "keep-alive -");
    // The cookie the first response set goes with the second request.
    assert_eq!(results[1]["response"]["body"]["content"], "- step=one");
    assert!(lines(&seen).iter().all(|(c, _)| *c == 1), "{:?}", lines(&seen));
}

#[test]
fn refused_before_anything_is_sent() {
    let p = project("refused");
    let (port, seen) = server(echo);
    let (a, b) = (raw(&p, "a", port), raw(&p, "b", port));
    // Not with --race, --raw or --http3; and the whole group is checked against the scope.
    for extra in [&["--race", "2"][..], &["--raw"], &["--http3"], &["--stream-wait", "1"]] {
        let mut args = vec!["send", &a, "--scheme=http", "--also", &b, "--sequence", "single"];
        args.extend(extra);
        let (code, v) = run(&p, &args);
        assert_eq!(code, 2, "{extra:?}: {v}");
    }
    let outside = p.with_extension("outside.http");
    std::fs::write(&outside, "GET / HTTP/1.1\nHost: 127.0.0.2:9\n\n").unwrap();
    let (code, v) =
        run(&p, &["send", &a, "--scheme=http", "--also", outside.to_str().unwrap(), "--sequence", "single"]);
    assert_eq!((code, v["error"]["kind"].as_str()), (6, Some("out_of_scope")), "{v}");
    // Through MCP, a member whose Host names an unlisted host (sent to the target) needs
    // --host-header-test, as in a race; the group's other members come from the call's stdin.
    let target = format!("http://127.0.0.1:{port}");
    let member = "GET /x HTTP/1.1\nHost: elsewhere.test\n\n";
    let (code, v) = run_mcp(&p, &["send", &a, "--target", &target, "--also=-", "--sequence", "single"], member);
    assert_eq!((code, v["error"]["kind"].as_str()), (6, Some("out_of_scope")), "{v}");
    assert!(lines(&seen).is_empty());
    let (_, rows) = run(&p, &["query", "SELECT count(*) FROM history"]);
    assert_eq!(rows["data"]["rows"][0][0], 0);
}
