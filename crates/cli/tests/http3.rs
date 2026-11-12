//! End-to-end tests for HTTP/3: send, fuzz and the TCP fallback against in-test servers (a
//! QUIC server with the test CA's certificate, which the client doesn't check by default), and
//! the scope's refusals with nothing sent.

use std::io::Write;
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use brainproxy_core::proxy::ca::CertAuthority;
use bytes::{Buf, Bytes};
use serde_json::Value;

fn tls(dir: &std::path::Path, alpn: &[&[u8]]) -> tokio_rustls::rustls::ServerConfig {
    let (ca, _) = CertAuthority::load_or_create(&dir.join("ca")).unwrap();
    let mut cfg = (*ca.server_config("127.0.0.1").unwrap()).clone();
    cfg.alpn_protocols = alpn.iter().map(|a| a.to_vec()).collect();
    cfg
}

/// Runs `serve` on a runtime of its own, in a thread of its own.
fn spawn<F: std::future::Future<Output = ()> + Send + 'static>(serve: F) {
    std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_multi_thread().enable_all().build().unwrap();
        rt.block_on(serve);
    });
}

/// An HTTP/3 server on 127.0.0.1:`port` (any when 0) offering `alpn`, answering
/// `<method> <path> <body>`. Returns its port and the connections it accepted.
fn h3_server(dir: &std::path::Path, port: u16, alpn: &[&[u8]]) -> (u16, Arc<AtomicU64>) {
    let crypto = quinn::crypto::rustls::QuicServerConfig::try_from(tls(dir, alpn)).unwrap();
    let config = quinn::ServerConfig::with_crypto(Arc::new(crypto));
    let socket = std::net::UdpSocket::bind(("127.0.0.1", port)).unwrap();
    let port = socket.local_addr().unwrap().port();
    let accepted = Arc::new(AtomicU64::new(0));
    let count = accepted.clone();
    spawn(async move {
        let endpoint =
            quinn::Endpoint::new(quinn::EndpointConfig::default(), Some(config), socket, Arc::new(quinn::TokioRuntime))
                .unwrap();
        while let Some(incoming) = endpoint.accept().await {
            let count = count.clone();
            tokio::spawn(async move {
                let Ok(conn) = incoming.await else { return };
                count.fetch_add(1, Ordering::Relaxed);
                let Ok(mut h3) = h3::server::Connection::<_, Bytes>::new(h3_quinn::Connection::new(conn)).await else {
                    return;
                };
                while let Ok(Some(resolver)) = h3.accept().await {
                    tokio::spawn(async move {
                        let Ok((req, mut stream)) = resolver.resolve_request().await else { return };
                        let mut body = Vec::new();
                        while let Ok(Some(mut c)) = stream.recv_data().await {
                            body.extend_from_slice(&c.copy_to_bytes(c.remaining()));
                        }
                        let resp = http::Response::builder().header("content-type", "text/plain").body(()).unwrap();
                        let _ = stream.send_response(resp).await;
                        let text = format!("{} {} {}", req.method(), req.uri().path(), String::from_utf8_lossy(&body));
                        let _ = stream.send_data(Bytes::from(text)).await;
                        let _ = stream.finish().await;
                    });
                }
            });
        }
    });
    (port, accepted)
}

/// An HTTP/1.1 server over TLS on 127.0.0.1 answering `h1 <request line>` with `status`, and
/// `alt_svc` as its Alt-Svc header if given.
fn h1_server(dir: &std::path::Path, status: u16, alt_svc: Option<String>) -> u16 {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let port = listener.local_addr().unwrap().port();
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(tls(dir, &[b"http/1.1"])));
    spawn(async move {
        let listener = tokio::net::TcpListener::from_std(listener).unwrap();
        while let Ok((tcp, _)) = listener.accept().await {
            let (acceptor, alt_svc) = (acceptor.clone(), alt_svc.clone());
            tokio::spawn(async move {
                let Ok(mut s) = acceptor.accept(tcp).await else { return };
                let mut buf = Vec::new();
                let mut chunk = [0u8; 4096];
                while !buf.windows(4).any(|w| w == b"\r\n\r\n") {
                    match s.read(&mut chunk).await {
                        Ok(0) | Err(_) => return,
                        Ok(n) => buf.extend_from_slice(&chunk[..n]),
                    }
                }
                let line = String::from_utf8_lossy(&buf).lines().next().unwrap_or_default().to_string();
                let body = format!("h1 {line}");
                let alt = alt_svc.map(|a| format!("Alt-Svc: {a}\r\n")).unwrap_or_default();
                let resp = format!(
                    "HTTP/1.1 {status} X\r\n{alt}Content-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = s.write_all(resp.as_bytes()).await;
                let _ = s.shutdown().await;
            });
        }
    });
    port
}

/// A UDP socket on 127.0.0.1 that counts the datagrams it gets and never answers.
fn udp_sink() -> (u16, Arc<AtomicU64>) {
    let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    let port = socket.local_addr().unwrap().port();
    let got = Arc::new(AtomicU64::new(0));
    let count = got.clone();
    std::thread::spawn(move || {
        let mut buf = [0u8; 2048];
        while socket.recv_from(&mut buf).is_ok() {
            count.fetch_add(1, Ordering::Relaxed);
        }
    });
    (port, got)
}

fn exec(args: &[&str], project: &std::path::Path, stdin: Option<&[u8]>) -> Value {
    let mut child = Command::new(env!("CARGO_BIN_EXE_brainproxy"))
        .args(["--format", "json", "--project"])
        .arg(project)
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    if let Some(data) = stdin {
        let _ = child.stdin.take().unwrap().write_all(data);
    }
    drop(child.stdin.take());
    serde_json::from_slice(&child.wait_with_output().unwrap().stdout).unwrap()
}

fn run(args: &[&str], project: &std::path::Path, stdin: Option<&[u8]>) -> Value {
    let v = exec(args, project, stdin);
    assert_eq!(v["ok"], true, "{v}");
    v["data"].clone()
}

fn project(name: &str) -> (std::path::PathBuf, std::path::PathBuf) {
    let dir = std::env::temp_dir().join(format!("bp-test-{}-{name}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let p = dir.join("p.bpdb");
    let _ = std::fs::remove_file(&p);
    (dir, p)
}

#[test]
fn send_and_fuzz_over_http3() {
    let (dir, p) = project("http3");
    let (port, accepted) = h3_server(&dir, 0, &[b"h3"]);
    run(&["engagement", "start", "--target", "127.0.0.1"], &p, None);
    let base = format!("https://127.0.0.1:{port}");

    let d = run(&["send", "--http3", "--url", &format!("{base}/a"), "-X", "POST", "-d", "hi"], &p, None);
    assert_eq!(d["response"]["status"], 200, "{d}");
    assert!(d.get("http3_notes").is_none(), "{d}");
    let h = run(&["history", "show", &d["id"].to_string()], &p, None);
    let text = h.to_string();
    assert!(text.contains("POST /a HTTP/3") && text.contains("POST /a hi"), "{text}");
    assert!(text.contains("HTTP/3"), "{text}");

    // A recorded HTTP/3 request goes back over HTTP/3 without --http3.
    let raw = format!("GET /again HTTP/3\r\nhost: 127.0.0.1:{port}\r\n\r\n");
    let d = run(&["send", "--target", &base], &p, Some(raw.as_bytes()));
    assert_eq!(d["response"]["status"], 200, "{d}");

    // --http3 doesn't race.
    let v = exec(&["send", "--http3", "--race", "2", "--url", &format!("{base}/r")], &p, None);
    assert_eq!(v["ok"], false, "{v}");

    let d = run(&["fuzz", "run", "--http3", "--url", &format!("{base}/f?q=§x§"), "-p", "list:a,b,c,d"], &p, None);
    assert_eq!(d["run"]["done"], 4, "{d}");
    // send, send, and fuzz: one connection each.
    assert_eq!(accepted.load(Ordering::Relaxed), 3);
}

#[test]
fn falls_back_to_tcp_and_says_why() {
    let (dir, p) = project("http3-fallback");
    let port = h1_server(&dir, 200, None);
    // QUIC on the same port, without h3: the handshake fails fast.
    h3_server(&dir, port, &[b"not-h3"]);
    run(&["engagement", "start", "--target", "127.0.0.1"], &p, None);
    let d = run(&["send", "--http3", "--url", &format!("https://127.0.0.1:{port}/a")], &p, None);
    assert_eq!(d["response"]["status"], 200, "{d}");
    let notes = d["http3_notes"].to_string();
    assert!(notes.contains("did not negotiate HTTP/3") && notes.contains("sent over TCP"), "{d}");
    let text = run(&["history", "show", &d["id"].to_string()], &p, None).to_string();
    assert!(text.contains("GET /a HTTP/1.1") && text.contains("h1 GET /a HTTP/1.1"), "{text}");

    // A race of a recorded HTTP/3 request goes over TCP as HTTP/1.1.
    let raw = format!("GET /r HTTP/3\r\nhost: 127.0.0.1:{port}\r\n\r\n");
    let d = run(&["send", &format!("--target=https://127.0.0.1:{port}"), "--race=2", "-"], &p, Some(raw.as_bytes()));
    let id = d["results"][0]["id"].to_string();
    let text = run(&["history", "show", &id], &p, None).to_string();
    assert!(text.contains("h1 GET /r HTTP/1.1"), "{text}");
}

#[test]
fn the_active_scan_finds_access_control_that_only_covers_tcp() {
    let (dir, p) = project("http3-rule");
    // HTTP/3 at an advertised endpoint answers 200; TCP refuses with 403.
    let (alt, accepted) = h3_server(&dir, 0, &[b"h3"]);
    let port = h1_server(&dir, 403, Some(format!(r#"h3=":{alt}""#)));
    h3_server(&dir, port, &[b"not-h3"]);
    run(&["engagement", "start", "--target", "127.0.0.1"], &p, None);
    let url = format!("https://127.0.0.1:{port}/admin");
    let d = run(&["scan", "active", &url, "--http3", "--rules=100006"], &p, None);
    assert_eq!(d["raised"]["100006-1"], 1, "{d}");
    assert!(accepted.load(Ordering::Relaxed) >= 1, "{d}");
    let f = run(&["findings", "list", "--source", "active"], &p, None).to_string();
    assert!(f.contains("Access Control Differs over HTTP/3"), "{f}");
}

#[test]
fn refuses_http3_destinations_outside_the_scope() {
    let (_dir, p) = project("http3-scope");
    let (sink, got) = udp_sink();
    run(&["engagement", "start", "--target", "127.0.0.1:1"], &p, None);
    for args in [
        vec!["send".to_string(), "--http3".into(), "--url".into(), format!("https://127.0.0.1:{sink}/")],
        vec![
            "fuzz".into(),
            "run".into(),
            "--http3".into(),
            "--url".into(),
            format!("https://127.0.0.1:{sink}/?q=§x§"),
            "-p".into(),
            "list:a".into(),
        ],
    ] {
        let args: Vec<&str> = args.iter().map(String::as_str).collect();
        let v = exec(&args, &p, None);
        assert_eq!((v["ok"].as_bool(), v["error"]["kind"].as_str()), (Some(false), Some("out_of_scope")), "{v}");
    }
    std::thread::sleep(std::time::Duration::from_millis(200));
    assert_eq!(got.load(Ordering::Relaxed), 0, "nothing reaches the refused port");
}
