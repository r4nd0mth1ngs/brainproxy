//! End-to-end tests for HTTP/2: send, single-packet race, and fuzz against an
//! in-test h2c (prior knowledge) server.

use std::io::Write;
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use bytes::Bytes;
use serde_json::Value;

/// An h2c server answering `<method> <path> <body>`; counts connections.
fn serve() -> (u16, Arc<AtomicU64>) {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    listener.set_nonblocking(true).unwrap();
    let accepted = Arc::new(AtomicU64::new(0));
    let count = accepted.clone();
    std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_multi_thread().enable_all().build().unwrap();
        rt.block_on(async move {
            let listener = tokio::net::TcpListener::from_std(listener).unwrap();
            while let Ok((tcp, _)) = listener.accept().await {
                count.fetch_add(1, Ordering::Relaxed);
                tokio::spawn(async move {
                    let Ok(mut conn) = h2::server::handshake(tcp).await else { return };
                    while let Some(Ok((req, mut respond))) = conn.accept().await {
                        tokio::spawn(async move {
                            let (parts, mut body) = req.into_parts();
                            let mut data = Vec::new();
                            while let Some(Ok(c)) = body.data().await {
                                let _ = body.flow_control().release_capacity(c.len());
                                data.extend_from_slice(&c);
                            }
                            let text =
                                format!("{} {} {}", parts.method, parts.uri.path(), String::from_utf8_lossy(&data));
                            let resp = http::Response::builder().header("content-type", "text/plain").body(()).unwrap();
                            if let Ok(mut send) = respond.send_response(resp, false) {
                                let _ = send.send_data(Bytes::from(text), true);
                            }
                        });
                    }
                });
            }
        });
    });
    (port, accepted)
}

fn run(args: &[&str], project: &std::path::Path, stdin: Option<&[u8]>) -> Value {
    let mut child = Command::new(env!("CARGO_BIN_EXE_brainproxy"))
        .args(["--format", "json", "--project"])
        .arg(project)
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    if let Some(data) = stdin {
        child.stdin.take().unwrap().write_all(data).unwrap();
    }
    drop(child.stdin.take());
    let out = child.wait_with_output().unwrap();
    let v: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(v["ok"], true, "{v}");
    v["data"].clone()
}

#[test]
fn send_race_and_fuzz_over_http2() {
    let (port, accepted) = serve();
    let dir = std::env::temp_dir().join(format!("bp-test-{}-http2", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let p = dir.join("p.bpdb");
    let _ = std::fs::remove_file(&p);
    run(&["engagement", "start", "--target", "127.0.0.1"], &p, None);
    let base = format!("http://127.0.0.1:{port}");

    let d = run(&["send", "--http2", "--url", &format!("{base}/a"), "-X", "POST", "-d", "hi"], &p, None);
    assert_eq!(d["response"]["status"], 200, "{d}");
    let id = d["id"].as_i64().unwrap().to_string();
    let h = run(&["history", "show", &id], &p, None);
    let text = h.to_string();
    assert!(text.contains("POST /a HTTP/2") && text.contains("POST /a hi"), "{text}");

    // A recorded HTTP/2 request goes back over HTTP/2 without --http2.
    let raw = format!("GET /again HTTP/2\r\nhost: 127.0.0.1:{port}\r\n\r\n");
    let d = run(&["send", "--target", &base], &p, Some(raw.as_bytes()));
    assert_eq!(d["response"]["status"], 200, "{d}");

    let d = run(&["send", "--http2", "--race", "8", "--url", &format!("{base}/race")], &p, None);
    assert_eq!((d["sync"].as_str(), d["synced"].as_u64()), (Some("single-packet"), Some(8)), "{d}");
    assert_eq!(d["distinct_responses"].as_object().unwrap().values().map(|v| v.as_u64().unwrap()).sum::<u64>(), 8);

    let d = run(&["fuzz", "run", "--http2", "--url", &format!("{base}/f?q=§x§"), "-p", "list:a,b,c,d"], &p, None);
    assert_eq!(d["run"]["done"], 4, "{d}");
    // send, send, race, and fuzz: one connection each.
    assert_eq!(accepted.load(Ordering::Relaxed), 4);
}
