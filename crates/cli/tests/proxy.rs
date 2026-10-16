//! End-to-end proxy tests: the real binary in the background, curl as the
//! client, and in-process HTTP/HTTPS echo servers as upstreams.

use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant};

use brainproxy_core::http::WireReader;
use brainproxy_core::proxy::CertAuthority;
use serde_json::Value;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

struct Env {
    dir: PathBuf,
    project: PathBuf,
    home: PathBuf,
}

impl Env {
    fn new(name: &str) -> Self {
        let dir = std::env::temp_dir().join(format!("bp-proxy-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let env = Self { project: dir.join("p.bpdb"), home: dir.join("home"), dir };
        env.ok(&["engagement", "start", "--target", "127.0.0.1", "--target", "localhost"]);
        env
    }

    fn run(&self, args: &[&str]) -> (i32, Value) {
        let out = Command::new(env!("CARGO_BIN_EXE_brainproxy"))
            .args(["--format", "json", "--project"])
            .arg(&self.project)
            .arg("--home")
            .arg(&self.home)
            .args(args)
            .output()
            .unwrap();
        let v = serde_json::from_slice(&out.stdout)
            .unwrap_or_else(|e| panic!("bad JSON ({e}): {}", String::from_utf8_lossy(&out.stdout)));
        (out.status.code().unwrap(), v)
    }

    fn ok(&self, args: &[&str]) -> Value {
        let (code, v) = self.run(args);
        assert_eq!(code, 0, "{args:?} -> {v}");
        v["data"].clone()
    }

    fn ca(&self) -> PathBuf {
        self.home.join("ca/ca.pem")
    }

    fn count(&self, sql: &str) -> i64 {
        self.ok(&["query", sql])["rows"][0][0].as_i64().unwrap()
    }
}

impl Drop for Env {
    fn drop(&mut self) {
        let _ = self.run(&["proxy", "stop"]);
    }
}

/// curl through the proxy; returns (status, body).
fn curl(proxy: &str, ca: &Path, url: &str, extra: &[&str]) -> (u16, String) {
    let out = Command::new("curl")
        .args(["-s", "--noproxy", "", "--max-time", "20", "-x", proxy, "--cacert"])
        .arg(ca)
        .args(extra)
        .args(["-w", "\n%{http_code}", url])
        .output()
        .expect("curl must be installed");
    let text = String::from_utf8_lossy(&out.stdout).into_owned();
    let (body, code) = text.rsplit_once('\n').unwrap_or(("", "0"));
    (code.trim().parse().unwrap_or(0), body.to_string())
}

/// Echo server: replies 200 with the raw request as the body. With `Upgrade`,
/// replies 101 and then echoes raw bytes.
fn spawn_echo(tls: bool, dir: &Path) -> u16 {
    let acceptor = tls.then(|| {
        let (ca, _) = CertAuthority::load_or_create(&dir.join("upstream-ca")).unwrap();
        tokio_rustls::TlsAcceptor::from(ca.server_config("localhost").unwrap())
    });
    let std_listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = std_listener.local_addr().unwrap().port();
    std_listener.set_nonblocking(true).unwrap();
    std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_multi_thread().enable_all().build().unwrap();
        rt.block_on(async move {
            let listener = TcpListener::from_std(std_listener).unwrap();
            loop {
                let (tcp, _) = listener.accept().await.unwrap();
                let acceptor = acceptor.clone();
                tokio::spawn(async move {
                    match acceptor {
                        Some(a) => {
                            if let Ok(s) = a.accept(tcp).await {
                                echo(s).await
                            }
                        }
                        None => echo(tcp).await,
                    }
                });
            }
        });
    });
    port
}

async fn echo<S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin>(mut s: S) {
    let mut reader = WireReader::new();
    while let Ok(Some(req)) = reader.read_request(&mut s).await {
        let text = String::from_utf8_lossy(&req).to_ascii_lowercase();
        if text.contains("\r\nupgrade:") {
            s.write_all(b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n")
                .await
                .unwrap();
            let mut buf = reader.into_leftover();
            loop {
                if !buf.is_empty() {
                    s.write_all(&buf).await.unwrap();
                }
                let mut chunk = [0u8; 1024];
                match s.read(&mut chunk).await {
                    Ok(0) | Err(_) => return,
                    Ok(n) => buf = chunk[..n].to_vec(),
                }
            }
        }
        let head = format!("HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {}\r\n\r\n", req.len());
        if s.write_all(head.as_bytes()).await.is_err() || s.write_all(&req).await.is_err() {
            return;
        }
    }
}

fn wait_for_settings() {
    // The proxy reloads settings every 300 ms.
    std::thread::sleep(Duration::from_millis(700));
}

#[test]
fn proxy_end_to_end() {
    let env = Env::new("e2e");
    let http_port = spawn_echo(false, &env.dir);
    let https_port = spawn_echo(true, &env.dir);

    let started = env.ok(&["proxy", "start", "--listen", "127.0.0.1:0"]);
    let proxy = started["usage"]["proxy_url"].as_str().unwrap().to_string();
    assert!(env.ca().exists());
    let (code, v) = env.run(&["proxy", "start", "--listen", "127.0.0.1:0"]);
    assert_eq!((code, v["error"]["kind"].as_str()), (2, Some("conflict")));

    // Plain HTTP and intercepted HTTPS.
    let (status, body) = curl(&proxy, &env.ca(), &format!("http://127.0.0.1:{http_port}/plain?x=1"), &[]);
    assert_eq!(status, 200);
    assert!(body.starts_with("GET /plain?x=1 HTTP/1.1\r\n"), "{body}");
    assert!(!body.to_ascii_lowercase().contains("proxy-connection"));
    let (status, body) = curl(&proxy, &env.ca(), &format!("https://localhost:{https_port}/secure"), &["-d", "a=1"]);
    assert_eq!(status, 200);
    assert!(body.starts_with("POST /secure HTTP/1.1\r\n") && body.ends_with("\r\n\r\na=1"), "{body}");

    std::thread::sleep(Duration::from_millis(300));
    assert_eq!(env.count("SELECT count(*) FROM history WHERE source = 'proxy'"), 2);
    assert_eq!(
        env.count("SELECT count(*) FROM history WHERE scheme = 'https' AND path = '/secure' AND req_body_text = 'a=1'"),
        1
    );

    // Match-and-replace: add a request header.
    env.ok(&["rules", "add", "--location", "request-header", "--replace", "X-Injected: yes"]);
    wait_for_settings();
    let (_, body) = curl(&proxy, &env.ca(), &format!("https://localhost:{https_port}/r"), &[]);
    assert!(body.contains("\r\nX-Injected: yes\r\n"), "{body}");
    env.ok(&["rules", "clear"]);

    // Intercept a request, edit it, forward it.
    env.ok(&["intercept", "enable", "--timeout", "30"]);
    wait_for_settings();
    let (p, ca, url) = (proxy.clone(), env.ca(), format!("https://localhost:{https_port}/original"));
    let client = std::thread::spawn(move || curl(&p, &ca, &url, &[]));
    let listed = env.ok(&["intercept", "list", "--wait", "10"]);
    assert_eq!(listed["count"], 1, "{listed}");
    let id = listed["items"][0]["id"].as_i64().unwrap().to_string();
    let edited = env.dir.join("edited.http");
    let held = env.ok(&["intercept", "show", &id]);
    let original = held["message"]["content"].as_str().unwrap();
    std::fs::write(&edited, original.replace("/original", "/edited")).unwrap();
    env.ok(&["intercept", "forward", &id, "--file", edited.to_str().unwrap()]);
    let (status, body) = client.join().unwrap();
    assert_eq!(status, 200);
    assert!(body.starts_with("GET /edited HTTP/1.1"), "{body}");
    let (code, v) = env.run(&["intercept", "forward", &id]);
    assert_eq!((code, v["error"]["kind"].as_str()), (2, Some("conflict")));

    // Intercept a response and drop it.
    env.ok(&["intercept", "enable", "--responses"]);
    wait_for_settings();
    let (p, ca, url) = (proxy.clone(), env.ca(), format!("http://127.0.0.1:{http_port}/resp"));
    let client = std::thread::spawn(move || curl(&p, &ca, &url, &[]));
    let listed = env.ok(&["intercept", "list", "--wait", "10"]);
    assert_eq!(listed["items"][0]["direction"], "response");
    assert_eq!(listed["items"][0]["status"], 200);
    env.ok(&["intercept", "drop", &listed["items"][0]["id"].as_i64().unwrap().to_string()]);
    assert_eq!(client.join().unwrap().0, 502);
    env.ok(&["intercept", "disable"]);

    // Out-of-scope traffic still flows but is not recorded.
    env.ok(&["scope", "set", "--include", r"^example\.test$"]);
    wait_for_settings();
    let before = env.count("SELECT count(*) FROM history");
    let (status, _) = curl(&proxy, &env.ca(), &format!("http://127.0.0.1:{http_port}/oos"), &[]);
    assert_eq!(status, 200);
    std::thread::sleep(Duration::from_millis(300));
    assert_eq!(env.count("SELECT count(*) FROM history"), before);
    env.ok(&["scope", "clear"]);

    let status = env.ok(&["proxy", "status"]);
    assert_eq!(status["running"], true);
    env.ok(&["proxy", "stop"]);
    assert_eq!(env.ok(&["proxy", "status"])["running"], false);
}

#[test]
fn proxy_websocket_upgrade_and_intercept_timeout() {
    let env = Env::new("ws");
    let http_port = spawn_echo(false, &env.dir);
    let started = env.ok(&["proxy", "start", "--listen", "127.0.0.1:0"]);
    let listen = started["listen"].as_str().unwrap().to_string();

    let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
    rt.block_on(async {
        let mut s = tokio::net::TcpStream::connect(&listen).await.unwrap();
        let req = format!(
            "GET http://127.0.0.1:{http_port}/ws HTTP/1.1\r\nHost: 127.0.0.1:{http_port}\r\n\
             Upgrade: websocket\r\nConnection: Upgrade\r\n\r\n"
        );
        s.write_all(req.as_bytes()).await.unwrap();
        let resp = WireReader::new().read_response(&mut s, "GET").await.unwrap();
        assert!(resp.starts_with(b"HTTP/1.1 101"));
        s.write_all(b"ping").await.unwrap();
        let mut buf = [0u8; 4];
        tokio::time::timeout(Duration::from_secs(5), s.read_exact(&mut buf)).await.unwrap().unwrap();
        assert_eq!(&buf, b"ping");
    });

    // A held request that nobody resolves is forwarded after the timeout.
    env.ok(&["intercept", "enable", "--timeout", "1"]);
    wait_for_settings();
    let started = Instant::now();
    let (status, _) = curl(&format!("http://{listen}"), &env.ca(), &format!("http://127.0.0.1:{http_port}/slow"), &[]);
    assert_eq!(status, 200);
    assert!(started.elapsed() >= Duration::from_millis(900));
    assert_eq!(env.ok(&["intercept", "list", "--state", "expired"])["count"], 1);
}

#[test]
fn fuzz_race_and_diff() {
    let env = Env::new("fuzz");
    let port = spawn_echo(false, &env.dir);
    let base = format!("http://127.0.0.1:{port}");

    // Sniper over two positions; the echo body reflects the request line.
    let s = env.ok(&[
        "fuzz",
        "run",
        "--url",
        &format!("{base}/item?a=§1§&b=§2§"),
        "-p",
        "list:x,y,z",
        "--grep",
        "a=y",
        "--extract",
        "b=(\\w+)",
    ]);
    assert_eq!(s["run"]["total"], 6);
    assert_eq!(s["run"]["done"], 6);
    assert_eq!(s["run"]["state"], "completed");
    assert_eq!(s["matches"].as_array().unwrap().len(), 1);
    assert_eq!(s["matches"][0]["payloads"], serde_json::json!(["y"]));
    assert_eq!(s["matches"][0]["extract"], "2");
    let run = s["run"]["id"].as_i64().unwrap().to_string();
    let r = env.ok(&["fuzz", "results", &run, "--matched"]);
    assert_eq!(r["row_count"], 1);
    let r = env.ok(&["fuzz", "results", &run, "--after", "3"]);
    assert_eq!(r["row_count"], 2);

    // Cluster bomb with processing and stop-on-match.
    let s = env.ok(&[
        "fuzz",
        "run",
        "--url",
        &format!("{base}/login"),
        "-X",
        "POST",
        "-d",
        "u=§u§&p=§p§",
        "--mode",
        "cluster-bomb",
        "-p",
        "list:a,b",
        "-p",
        "range:1-3",
        "--process",
        "2=prefix:pw",
        "-c",
        "1",
        "--grep",
        "u=b&p=pw2",
        "--stop-on-match",
        "--store",
        "matches",
    ]);
    assert_eq!(s["outcome"], "stopped-on-match");
    assert_eq!(s["matches"][0]["payloads"], serde_json::json!(["b", "pw2"]));
    // Content-Length was fixed after substitution: the echo shows the full body.
    let hid = s["matches"][0]["history_id"].as_i64().unwrap();
    assert_eq!(env.count(&format!("SELECT count(*) FROM history WHERE id = {hid} AND req_body_text = 'u=b&p=pw2'")), 1);

    // Pitchfork needs one set per position.
    let (code, v) =
        env.run(&["fuzz", "run", "--url", &format!("{base}/?a=§1§&b=§2§"), "--mode", "pitchfork", "-p", "list:1"]);
    assert_eq!((code, v["error"]["kind"].as_str()), (2, Some("invalid_input")));

    // Race: N identical requests, all recorded.
    let r = env.ok(&["send", "--url", &format!("{base}/race"), "-X", "POST", "-d", "x=1", "--race", "5"]);
    assert_eq!(r["results"].as_array().unwrap().len(), 5);
    assert!(r["results"].as_array().unwrap().iter().all(|i| i["status"] == 200));
    assert_eq!(env.count("SELECT count(*) FROM history WHERE source = 'race'"), 5);

    // Diff two different fuzz responses.
    let ids = env.ok(&["query", "SELECT min(id), max(id) FROM history WHERE source = 'fuzz'"]);
    let (a, b) = (ids["rows"][0][0].to_string(), ids["rows"][0][1].to_string());
    let d = env.ok(&["diff", &a, &b, "--part", "response-body"]);
    assert_eq!(d["identical"], false);
    assert!(d["unified"].as_str().unwrap().contains("@@"));
    let d = env.ok(&["diff", &a, &a]);
    assert_eq!(d["identical"], true);
}

/// Serves the same raw response to every request.
fn spawn_fixed(response: &'static str) -> u16 {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut s) = stream else { continue };
            std::thread::spawn(move || {
                use std::io::{Read, Write};
                let mut buf = [0u8; 8192];
                let mut seen = Vec::new();
                while !seen.windows(4).any(|w| w == b"\r\n\r\n") {
                    match s.read(&mut buf) {
                        Ok(0) | Err(_) => return,
                        Ok(n) => seen.extend_from_slice(&buf[..n]),
                    }
                }
                let _ = s.write_all(response.as_bytes());
            });
        }
    });
    port
}

#[test]
fn passive_scan_and_findings() {
    let env = Env::new("passive");
    let port = spawn_fixed(
        "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nSet-Cookie: session=abc; Path=/\r\n\
         Content-Length: 13\r\nConnection: close\r\n\r\n<html></html>",
    );
    for path in ["/a", "/b", "/a"] {
        env.ok(&["send", "--url", &format!("http://127.0.0.1:{port}{path}")]);
    }

    // Grouped view: one alert type; /a twice counts as one instance with 2 hits.
    let list = env.ok(&["findings", "list", "--alert", "10010"]);
    assert_eq!(list["alert_types"], 1, "{list}");
    let group = &list["groups"][0];
    assert_eq!(group["name"], "Cookie No HttpOnly Flag");
    assert_eq!(group["instances"], 2);
    assert_eq!(group["hits"], 3);

    let all = env.ok(&["findings", "list", "--all", "--alert", "10010"]);
    let id = all["items"][0]["id"].as_i64().unwrap().to_string();
    let shown = env.ok(&["findings", "show", &id]);
    assert_eq!(shown["param"], "session");
    assert!(shown["solution"].as_str().unwrap().contains("HttpOnly"));
    assert_eq!(shown["cwe"], 1004);

    // Triage: false positives drop out of the default view.
    env.ok(&["findings", "mark", &id, "--state", "false-positive", "--note", "test cookie"]);
    let list = env.ok(&["findings", "list", "--alert", "10010"]);
    assert_eq!(list["groups"][0]["instances"], 1);

    // Disabling a rule and rescanning removes its findings.
    env.ok(&["scan", "disable", "10010"]);
    let stats = env.ok(&["scan", "passive", "--rescan"]);
    assert_eq!(stats["scanned"], 3);
    assert_eq!(env.ok(&["findings", "list", "--alert", "10010"])["alert_types"], 0);
    let rules = env.ok(&["scan", "rules", "--filter", "10010"]);
    assert_eq!(rules["rules"][0]["enabled"], false);
    let (code, v) = env.run(&["scan", "disable", "99999999"]);
    assert_eq!((code, v["error"]["kind"].as_str()), (4, Some("not_found")));
}
