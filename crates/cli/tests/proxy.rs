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
        .args(["-sS", "--noproxy", "", "--max-time", "20", "-x", proxy, "--cacert"])
        .arg(ca)
        // Windows curl (Schannel) also wants a revocation check, which a local CA can't answer.
        .args(if cfg!(windows) { &["--ssl-no-revoke"][..] } else { &[] })
        .args(extra)
        .args(["-w", "\n%{http_code}", url])
        .output()
        .expect("curl must be installed");
    let text = String::from_utf8_lossy(&out.stdout).into_owned();
    if !out.stderr.is_empty() {
        eprintln!("curl {url}: {}", String::from_utf8_lossy(&out.stderr));
    }
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

    // Captures are written in the background, after the first passive scan (~300 ms in debug builds).
    let deadline = Instant::now() + Duration::from_secs(5);
    while env.count("SELECT count(*) FROM history WHERE source = 'proxy'") < 2 && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(50));
    }
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

    // Requests outside the engagement are refused at once, never held for a decision.
    env.ok(&["intercept", "enable", "--requests"]);
    wait_for_settings();
    let started = std::time::Instant::now();
    let (status, _) = curl(&proxy, &env.ca(), "http://10.255.255.1/held?", &[]);
    assert!(status >= 400, "{status}");
    assert!(started.elapsed() < Duration::from_secs(5));
    assert_eq!(env.ok(&["intercept", "list"])["count"], 0);
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

/// A server that closes before sending all of its Content-Length: the client gets what came,
/// then the connection ends, as it would without the proxy, instead of waiting for the rest.
#[test]
fn a_body_cut_short_ends_the_connection() {
    let env = Env::new("short");
    let upstream = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = upstream.local_addr().unwrap().port();
    std::thread::spawn(move || {
        use std::io::{Read, Write};
        for tcp in upstream.incoming() {
            let mut tcp = tcp.unwrap();
            let mut buf = [0; 4096];
            let _ = tcp.read(&mut buf);
            let _ = tcp.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\nConnection: keep-alive\r\n\r\nshort");
        }
    });
    let started = env.ok(&["proxy", "start", "--listen", "127.0.0.1:0"]);
    let listen = started["listen"].as_str().unwrap().to_string();

    let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
    rt.block_on(async {
        let mut s = tokio::net::TcpStream::connect(&listen).await.unwrap();
        let req = format!("GET http://127.0.0.1:{port}/ HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n\r\n");
        s.write_all(req.as_bytes()).await.unwrap();
        let mut got = Vec::new();
        tokio::time::timeout(Duration::from_secs(10), s.read_to_end(&mut got))
            .await
            .expect("the proxy keeps the connection open")
            .unwrap();
        let got = String::from_utf8_lossy(&got);
        assert!(got.starts_with("HTTP/1.1 200") && got.ends_with("short"), "{got}");
    });
    assert_eq!(env.count("SELECT COUNT(*) FROM history"), 1);
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
fn a_rule_that_changes_the_method_frames_the_response_by_it() {
    let env = Env::new("method");
    // Answers like a server answering HEAD: a Content-Length, no body, and keeps the
    // connection open (read as a GET's response, it never ends).
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    std::thread::spawn(move || {
        use std::io::{Read, Write};
        for mut s in listener.incoming().flatten() {
            std::thread::spawn(move || {
                let mut buf = [0u8; 8192];
                let mut seen = Vec::new();
                while !seen.windows(4).any(|w| w == b"\r\n\r\n") {
                    match s.read(&mut buf) {
                        Ok(0) | Err(_) => return,
                        Ok(n) => seen.extend_from_slice(&buf[..n]),
                    }
                }
                let _ = s.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\n");
                std::thread::sleep(Duration::from_secs(60));
            });
        }
    });
    let proxy = env.ok(&["proxy", "start", "--listen", "127.0.0.1:0"])["listen"].as_str().unwrap().to_string();
    env.ok(&["rules", "add", "--location", "request-line", "--match", "^GET ", "--replace", "HEAD "]);
    wait_for_settings();
    use std::io::{Read, Write};
    let mut s = std::net::TcpStream::connect(&proxy).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
    write!(s, "GET http://127.0.0.1:{port}/h HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n\r\n").unwrap();
    let mut head = Vec::new();
    let mut byte = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") && s.read(&mut byte).unwrap_or(0) == 1 {
        head.push(byte[0]);
    }
    let head = String::from_utf8_lossy(&head);
    assert!(head.starts_with("HTTP/1.1 200 OK"), "{head}");
}

#[test]
fn passive_scan_and_findings() {
    let env = Env::new("passive");
    let port = spawn_fixed(
        "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nSet-Cookie: session=abc; Path=/\r\n\
         Server: Werkzeug/3.0.3 Python/3.11.17\r\nServer: Werkzeug/3.0.3 Python/3.11\r\n\
         Content-Length: 13\r\nConnection: close\r\n\r\n<html></html>",
    );
    for path in ["/a", "/b", "/a"] {
        env.ok(&["send", "--url", &format!("http://127.0.0.1:{port}{path}")]);
    }

    // Two versioned Server headers (different evidence) are one finding per page.
    let server = env.ok(&["findings", "list", "--alert", "10036-2"]);
    assert_eq!(
        (server["groups"][0]["instances"].as_i64(), server["groups"][0]["hits"].as_i64()),
        (Some(2), Some(6)),
        "{server}"
    );

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

/// A small app with known issues: /go reflects the decoded `next` parameter into a
/// Location header unsanitised, and /.env is readable. /safe has a parameter but
/// no issue.
fn spawn_vulnerable_app() -> u16 {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut s) = stream else { continue };
            std::thread::spawn(move || {
                use std::io::{Read, Write};
                let mut buf = vec![0u8; 16384];
                let n = s.read(&mut buf).unwrap_or(0);
                let req = String::from_utf8_lossy(&buf[..n]).to_string();
                let target = req.split(' ').nth(1).unwrap_or("/").to_string();
                let (path, query) = target.split_once('?').unwrap_or((&target, ""));
                let param = |name: &str| -> String {
                    query
                        .split('&')
                        .find_map(|p| p.strip_prefix(&format!("{name}=")))
                        .map(brainproxy_core::scan::message::url_decode)
                        .unwrap_or_default()
                };
                let resp = match path {
                    "/go" => format!("HTTP/1.1 302 Found\r\nLocation: /{}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n", param("next")),
                    "/.env" => "HTTP/1.1 200 OK\r\nContent-Length: 30\r\nConnection: close\r\n\r\nDB_PASSWORD=hunter2\nDEBUG=true".to_string(),
                    "/safe" => {
                        let body = format!("<html>hello {}</html>", param("name").len());
                        format!("HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len())
                    }
                    _ => "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".to_string(),
                };
                let _ = s.write_all(resp.as_bytes());
            });
        }
    });
    port
}

#[test]
fn active_scan_finds_known_issues() {
    let env = Env::new("active");
    let port = spawn_vulnerable_app();
    let base = format!("http://127.0.0.1:{port}");
    let rules = env.ok(&["scan", "rules", "--active"]);
    assert!(rules["count"].as_u64().unwrap() >= 2);

    let s = env.ok(&["scan", "active", &format!("{base}/go?next=home"), &format!("{base}/safe?name=x")]);
    assert_eq!(s["targets"], 2, "{s}");
    let raised = &s["raised"];
    assert_eq!(raised["40003"], 1, "CRLF should be found once, on /go: {s}");
    assert_eq!(raised["40034-1"], 1, ".env should be found once for the shared directory: {s}");

    let all = env.ok(&["findings", "list", "--all", "--source", "active"]);
    let crlf = all["items"].as_array().unwrap().iter().find(|f| f["alert_ref"] == "40003").unwrap();
    assert_eq!(crlf["param"], "next");
    assert!(crlf["url"].as_str().unwrap().contains("/go?"));
    let shown = env.ok(&["findings", "show", &crlf["id"].to_string()]);
    assert!(shown["attack"].as_str().unwrap().contains("Set-cookie: Tamper="), "{shown}");
    // The proving exchange is in history as source=scan.
    let hid = shown["history_id"].as_i64().unwrap();
    assert_eq!(env.count(&format!("SELECT count(*) FROM history WHERE id = {hid} AND source = 'scan'")), 1);

    // Rule selection, history targets, and background mode.
    let s = env.ok(&["scan", "active", "--rules", "40003", "--where", "path = '/safe'"]);
    assert_eq!(s["rules"], 1);
    assert!(s["raised"].as_object().unwrap().is_empty(), "{s}");
    let (code, v) = env.run(&["scan", "active", "--rules", "999999", &format!("{base}/safe")]);
    assert_eq!((code, v["error"]["kind"].as_str()), (4, Some("not_found")));
    let job = env.ok(&["scan", "active", "--background", "--rules", "40003", &format!("{base}/go?next=a")]);
    let done = env.ok(&["job", "wait", &job["job"].to_string(), "--timeout", "60"]);
    assert_eq!(done["state"], "completed", "{done}");
    assert_eq!(done["result"]["raised"]["40003"], 1);
}

/// curl through the proxy; returns (HTTP version, status, body).
fn curl_version(proxy: &str, ca: &Path, url: &str, extra: &[&str]) -> (String, u16, String) {
    let out = Command::new("curl")
        .args(["-sS", "--noproxy", "", "--max-time", "20", "-x", proxy, "--cacert"])
        .arg(ca)
        // Windows curl (Schannel) also wants a revocation check, which a local CA can't answer.
        .args(if cfg!(windows) { &["--ssl-no-revoke"][..] } else { &[] })
        .args(extra)
        .args(["-w", "\n%{http_version} %{http_code}", url])
        .output()
        .expect("curl must be installed");
    let text = String::from_utf8_lossy(&out.stdout).into_owned();
    let (body, tail) = text.rsplit_once('\n').unwrap_or(("", "0 0"));
    let (version, code) = tail.split_once(' ').unwrap_or(("0", "0"));
    (version.to_string(), code.trim().parse().unwrap_or(0), body.to_string())
}

/// HTTP/2 over TLS (ALPN h2) for `localhost`, answering `<method> <uri>`, the
/// headers, and the body. Returns the port and the accepted-connection count.
fn spawn_h2_echo(dir: &Path) -> (u16, std::sync::Arc<std::sync::atomic::AtomicU64>) {
    use std::sync::atomic::Ordering;
    let (ca, _) = CertAuthority::load_or_create(&dir.join("upstream-ca")).unwrap();
    let mut cfg = (*ca.server_config("localhost").unwrap()).clone();
    cfg.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    let acceptor = tokio_rustls::TlsAcceptor::from(std::sync::Arc::new(cfg));
    let std_listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = std_listener.local_addr().unwrap().port();
    std_listener.set_nonblocking(true).unwrap();
    let accepted = std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0));
    let count = accepted.clone();
    std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_multi_thread().enable_all().build().unwrap();
        rt.block_on(async move {
            let listener = TcpListener::from_std(std_listener).unwrap();
            while let Ok((tcp, _)) = listener.accept().await {
                count.fetch_add(1, Ordering::Relaxed);
                let acceptor = acceptor.clone();
                tokio::spawn(async move {
                    let Ok(tls) = acceptor.accept(tcp).await else { return };
                    let Ok(mut conn) = h2::server::handshake(tls).await else { return };
                    while let Some(Ok((req, mut respond))) = conn.accept().await {
                        tokio::spawn(async move {
                            let (parts, mut body) = req.into_parts();
                            let mut data = Vec::new();
                            while let Some(Ok(c)) = body.data().await {
                                let _ = body.flow_control().release_capacity(c.len());
                                data.extend_from_slice(&c);
                            }
                            let mut text = format!("{} {}\n", parts.method, parts.uri);
                            for (k, v) in &parts.headers {
                                text.push_str(&format!("{k}: {}\n", v.to_str().unwrap_or("?")));
                            }
                            text.push('\n');
                            text.push_str(&String::from_utf8_lossy(&data));
                            let resp = http::Response::builder().header("content-type", "text/plain").body(()).unwrap();
                            if let Ok(mut send) = respond.send_response(resp, false) {
                                let _ = send.send_data(bytes::Bytes::from(text), true);
                            }
                        });
                    }
                });
            }
        });
    });
    (port, accepted)
}

#[test]
fn proxy_serves_http2() {
    let curl_h2 = Command::new("curl").arg("--version").output().expect("curl must be installed");
    if !String::from_utf8_lossy(&curl_h2.stdout).contains("HTTP2") {
        eprintln!("skipping: curl was built without HTTP/2");
        return;
    }
    let env = Env::new("h2");
    let (h2_port, accepted) = spawn_h2_echo(&env.dir);
    let h1_port = spawn_echo(true, &env.dir);
    let started = env.ok(&["proxy", "start", "--listen", "127.0.0.1:0"]);
    let proxy = started["usage"]["proxy_url"].as_str().unwrap().to_string();
    let h2_url = |path: &str| format!("https://localhost:{h2_port}{path}");

    // HTTP/2 on both sides, one upstream connection for both requests.
    for _ in 0..2 {
        let (version, status, body) =
            curl_version(&proxy, &env.ca(), &h2_url("/h2?q=1"), &["--http2", "-d", "a=1", "-H", "Cookie: c=1"]);
        assert_eq!((version.as_str(), status), ("2", 200), "{body}");
        assert!(body.starts_with(&format!("POST https://localhost:{h2_port}/h2?q=1\n")), "{body}");
        assert!(body.contains("\ncookie: c=1\n") && body.ends_with("\n\na=1"), "{body}");
    }
    assert_eq!(accepted.load(std::sync::atomic::Ordering::Relaxed), 1);

    // HTTP/2 client, HTTP/1.1-only origin: sent upstream as HTTP/1.1.
    let (version, status, body) =
        curl_version(&proxy, &env.ca(), &format!("https://localhost:{h1_port}/fallback"), &["--http2", "-d", "abc"]);
    assert_eq!((version.as_str(), status), ("2", 200), "{body}");
    assert!(body.starts_with("POST /fallback HTTP/1.1\r\n"), "{body}");
    assert!(body.contains("\r\ncontent-length: 3\r\n") && body.ends_with("\r\n\r\nabc"), "{body}");

    std::thread::sleep(Duration::from_millis(300));
    assert_eq!(
        env.count(
            "SELECT count(*) FROM history WHERE source = 'proxy' AND path = '/h2' AND status = 200 \
             AND CAST(request AS TEXT) LIKE 'POST /h2?q=1 HTTP/2%' AND CAST(response AS TEXT) LIKE 'HTTP/2 200%'"
        ),
        2
    );
    assert_eq!(
        env.count("SELECT count(*) FROM history WHERE path = '/fallback' AND CAST(request AS TEXT) LIKE '% HTTP/1.1%'"),
        1
    );

    // Rules and intercept apply to HTTP/2 streams.
    env.ok(&["rules", "add", "--location", "request-header", "--replace", "X-Injected: yes"]);
    env.ok(&["intercept", "enable", "--timeout", "30"]);
    wait_for_settings();
    let (p, ca, url) = (proxy.clone(), env.ca(), h2_url("/original"));
    let client = std::thread::spawn(move || curl_version(&p, &ca, &url, &["--http2"]));
    let listed = env.ok(&["intercept", "list", "--wait", "10"]);
    assert_eq!(listed["count"], 1, "{listed}");
    let id = listed["items"][0]["id"].as_i64().unwrap().to_string();
    let held = env.ok(&["intercept", "show", &id]);
    let original = held["message"]["content"].as_str().unwrap();
    assert!(original.starts_with("GET /original HTTP/2\r\n"), "{original}");
    let edited = env.dir.join("edited-h2.http");
    std::fs::write(&edited, original.replace("/original", "/edited")).unwrap();
    env.ok(&["intercept", "forward", &id, "--file", edited.to_str().unwrap()]);
    let (version, status, body) = client.join().unwrap();
    assert_eq!((version.as_str(), status), ("2", 200), "{body}");
    assert!(body.starts_with(&format!("GET https://localhost:{h2_port}/edited\n")), "{body}");
    assert!(body.contains("\nx-injected: yes\n"), "{body}");
    env.ok(&["intercept", "disable"]);
    env.ok(&["rules", "clear"]);
    env.ok(&["proxy", "stop"]);

    // --no-http2 keeps clients on HTTP/1.1.
    let started = env.ok(&["proxy", "start", "--listen", "127.0.0.1:0", "--no-http2"]);
    let proxy = started["usage"]["proxy_url"].as_str().unwrap().to_string();
    let url = format!("https://localhost:{h1_port}/h1");
    let (version, status, body) = curl_version(&proxy, &env.ca(), &url, &["--http2"]);
    assert_eq!((version.as_str(), status), ("1.1", 200), "{body}");
}

/// A small app with a CSRF-protected login form and a session cookie. Returns its port.
fn spawn_login_app() -> u16 {
    use std::collections::HashSet;
    use std::io::{Read, Write};
    use std::sync::{Arc, Mutex};
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let state = Arc::new(Mutex::new((HashSet::<String>::new(), HashSet::<String>::new(), 0u32))); // (csrf, sessions, n)
    std::thread::spawn(move || {
        for s in listener.incoming() {
            let Ok(mut s) = s else { continue };
            let state = state.clone();
            std::thread::spawn(move || {
                let mut buf = Vec::new();
                let mut chunk = [0u8; 4096];
                let req = loop {
                    let n = s.read(&mut chunk).unwrap_or(0);
                    buf.extend_from_slice(&chunk[..n]);
                    let text = String::from_utf8_lossy(&buf).to_string();
                    if let Some(end) = text.find("\r\n\r\n") {
                        let len = text[..end]
                            .lines()
                            .find_map(|l| {
                                l.to_ascii_lowercase()
                                    .strip_prefix("content-length:")
                                    .map(|v| v.trim().parse().unwrap_or(0))
                            })
                            .unwrap_or(0usize);
                        if buf.len() >= end + 4 + len || n == 0 {
                            break text;
                        }
                    } else if n == 0 {
                        break text;
                    }
                };
                let line = req.lines().next().unwrap_or("").to_string();
                let cookie = req
                    .lines()
                    .find_map(|l| l.strip_prefix("Cookie: ").or_else(|| l.strip_prefix("cookie: ")))
                    .unwrap_or("");
                let sid = cookie.split(';').find_map(|c| c.trim().strip_prefix("sid=")).unwrap_or("").to_string();
                let body = req.split_once("\r\n\r\n").map(|x| x.1).unwrap_or("").to_string();
                let mut st = state.lock().unwrap();
                st.2 += 1;
                let n = st.2;
                let page = |extra: &str, html: &str| {
                    format!("HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n{extra}Content-Length: {}\r\nConnection: close\r\n\r\n{html}", html.len())
                };
                let form = |st: &mut (HashSet<String>, HashSet<String>, u32)| {
                    let token = format!("t0k{:08x}{n}", n.wrapping_mul(2654435761));
                    st.0.insert(token.clone());
                    page(
                        &format!("Set-Cookie: sid=anon{n}; Path=/\r\n"),
                        &format!(
                            r#"<form method=post action=/login><input type=hidden name=csrf value="{token}"><input name=user><input type=password name=pass></form>"#
                        ),
                    )
                };
                let resp = if line.starts_with("GET /login") {
                    form(&mut st)
                } else if line.starts_with("POST /login") {
                    let f: std::collections::HashMap<_, _> =
                        body.split('&').filter_map(|p| p.split_once('=')).collect();
                    if f.get("user") == Some(&"alice")
                        && f.get("pass") == Some(&"Wonder-1")
                        && st.0.remove(*f.get("csrf").unwrap_or(&""))
                    {
                        let live = format!("live{n}");
                        st.1.insert(live.clone());
                        format!("HTTP/1.1 302 Found\r\nLocation: /account\r\nSet-Cookie: sid={live}; Path=/\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                    } else {
                        form(&mut st)
                    }
                } else if line.starts_with("GET /account") && st.1.contains(&sid) {
                    page("", "<p>Welcome alice</p><a href=/logout>Log out</a>")
                } else {
                    "HTTP/1.1 302 Found\r\nLocation: /login\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                        .to_string()
                };
                let _ = s.write_all(resp.as_bytes());
            });
        }
    });
    port
}

#[test]
fn auth_record_turns_a_browser_login_into_a_working_profile() {
    let env = Env::new("record");
    let app = spawn_login_app();
    let started = env.ok(&["proxy", "start", "--listen", "127.0.0.1:0"]);
    let proxy = started["usage"]["proxy_url"].as_str().unwrap().to_string();
    let jar = env.dir.join("jar.txt");
    let jar = jar.to_str().unwrap();
    let base = format!("http://127.0.0.1:{app}");

    // The "browser": open the form, log in with its token, open the account page.
    let (_, form) = curl(&proxy, &env.ca(), &format!("{base}/login"), &["-c", jar, "-b", jar]);
    let token = form.split("value=\"").nth(1).unwrap().split('"').next().unwrap().to_string();
    let body = format!("csrf={token}&user=alice&pass=Wonder-1");
    let (code, _) = curl(&proxy, &env.ca(), &format!("{base}/login"), &["-c", jar, "-b", jar, "-d", &body]);
    assert_eq!(code, 302);
    let (code, page) = curl(&proxy, &env.ca(), &format!("{base}/account"), &["-c", jar, "-b", jar]);
    assert_eq!((code, page.contains("Welcome alice")), (200, true));
    // The proxy records in the background (the first page also compiles the passive rules).
    let deadline = Instant::now() + Duration::from_secs(30);
    while env.count("SELECT count(*) FROM history WHERE source = 'proxy'") < 3 && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(100));
    }

    let v = env.ok(&["auth", "record", "finish", "app", "--since", "0", "--save"]);
    assert_eq!(v["mode"], "replay", "{v}");
    let p = &v["profile"];
    assert_eq!(p["csrf_url"], format!("{base}/login"), "{v}");
    assert_eq!(p["check_url"], format!("{base}/account"), "{v}");
    assert_eq!(p["username"], "alice");
    assert_eq!(p["password"]["literal"], "********");

    // The saved profile logs in by itself: a fresh token, the password, the session.
    let login = env.ok(&["auth", "login", "app"]);
    assert_eq!(login["login"]["success"], true, "{login}");
    assert_eq!(login["login"]["reason"], "logged-in pattern matched", "{login}");
    let status = env.ok(&["auth", "status", "app"]);
    assert_eq!(status["check"]["logged_in"], true, "{status}");
}

/// Rewrites the saved state as another container would see it: the same pid, another namespace.
#[cfg(target_os = "linux")]
fn pretend_other_namespace(project: &Path, key: &str) {
    let store = brainproxy_core::store::Store::open(project).unwrap();
    let saved = store.meta_get(key).unwrap().unwrap();
    let mut state: Value = serde_json::from_str(&saved).unwrap();
    assert!(state["pid_ns"].as_str().is_some_and(|ns| ns.starts_with("pid:[")), "{state}");
    state["pid_ns"] = "pid:[1]".into();
    store.meta_set(key, Some(&state.to_string())).unwrap();
}

#[cfg(target_os = "linux")]
#[test]
fn proxy_in_another_namespace_is_not_taken_for_dead() {
    use brainproxy_core::proxy::STATE_KEY;
    let env = Env::new("namespace");
    let pid = env.ok(&["proxy", "start", "--listen", "127.0.0.1:0"])["pid"].as_u64().unwrap();
    let status = env.ok(&["proxy", "status"]);
    assert_eq!((&status["running"], &status["other_pid_namespace"]), (&true.into(), &false.into()));

    // Its state survives being looked at, however many times, and blocks a second proxy.
    pretend_other_namespace(&env.project, STATE_KEY);
    for _ in 0..2 {
        let status = env.ok(&["proxy", "status"]);
        assert_eq!((&status["running"], &status["other_pid_namespace"]), (&true.into(), &true.into()), "{status}");
    }
    let (code, v) = env.run(&["proxy", "run", "--listen", "127.0.0.1:0"]);
    assert_ne!(code, 0, "{v}");
    assert!(v.to_string().contains("another container"), "{v}");

    // A stop can't signal it, so it goes through the project file.
    let stopped = env.ok(&["proxy", "stop"]);
    assert_eq!((stopped["stopped"].as_u64(), &stopped["forced"]), (Some(pid), &false.into()));
    assert_eq!(env.ok(&["proxy", "status"])["running"], false);

    // Once it is killed outright, it is told from a running one right away, and the state goes.
    let pid = env.ok(&["proxy", "start", "--listen", "127.0.0.1:0"])["pid"].as_u64().unwrap();
    pretend_other_namespace(&env.project, STATE_KEY);
    assert!(Command::new("kill").args(["-9", &pid.to_string()]).status().unwrap().success());
    let deadline = Instant::now() + Duration::from_secs(5);
    while env.ok(&["proxy", "status"])["running"] == true {
        assert!(Instant::now() < deadline, "the dead proxy still looks like it runs");
        std::thread::sleep(Duration::from_millis(50));
    }
    let store = brainproxy_core::store::Store::open(&env.project).unwrap();
    assert_eq!(store.meta_get(STATE_KEY).unwrap(), None);
    env.ok(&["proxy", "start", "--listen", "127.0.0.1:0"]);
}

/// A proxy elsewhere whose lock file can't be read here: not called running, not cleared, and
/// `stop --forget` is the way out. Permissions don't bind root, so that part is skipped there.
#[cfg(target_os = "linux")]
#[test]
fn proxy_record_that_cannot_be_verified() {
    use brainproxy_core::proxy::STATE_KEY;
    use std::os::unix::fs::PermissionsExt;
    let env = Env::new("unverified");
    let lock = env.dir.join("p.bpdb-proxy.lock");
    let chmod = |mode| std::fs::set_permissions(&lock, std::fs::Permissions::from_mode(mode)).unwrap();

    assert_eq!(env.run(&["proxy", "stop", "--forget"]).0, 4, "nothing recorded");
    let pid = env.ok(&["proxy", "start", "--listen", "127.0.0.1:0"])["pid"].as_u64().unwrap();
    assert_eq!(std::fs::metadata(&lock).unwrap().permissions().mode() & 0o777, 0o644);
    pretend_other_namespace(&env.project, STATE_KEY);

    // Known to be running: its record stays.
    let (code, v) = env.run(&["proxy", "stop", "--forget"]);
    assert_ne!(code, 0, "{v}");
    assert_eq!(v["error"]["kind"], "conflict", "{v}");
    assert_eq!(env.ok(&["proxy", "status"])["running"], true);

    assert!(Command::new("kill").args(["-9", &pid.to_string()]).status().unwrap().success());
    chmod(0o000);
    if std::fs::File::open(&lock).is_ok() {
        chmod(0o644);
        return;
    }
    let deadline = Instant::now() + Duration::from_secs(2);
    while Path::new(&format!("/proc/{pid}")).exists() {
        assert!(Instant::now() < deadline, "the proxy survived SIGKILL");
        std::thread::sleep(Duration::from_millis(50));
    }

    for _ in 0..2 {
        let status = env.ok(&["proxy", "status"]);
        assert_eq!(status["running"], false, "{status}");
        assert_eq!(status["unverified"]["pid"].as_u64(), Some(pid), "{status}");
        assert_eq!(status["unverified"]["next"], "brainproxy proxy stop --forget", "{status}");
    }
    for args in [
        &["proxy", "start", "--listen", "127.0.0.1:0"][..],
        &["proxy", "run", "--listen", "127.0.0.1:0"],
        &["proxy", "restart", "--listen", "127.0.0.1:0"],
    ] {
        let (code, v) = env.run(args);
        assert_ne!(code, 0, "{v}");
        assert!(v.to_string().contains("stop --forget"), "{v}");
    }
    let (code, v) = env.run(&["proxy", "stop"]);
    assert_ne!(code, 0, "{v}");
    assert!(v.to_string().contains("stop --forget"), "{v}");

    assert_eq!(env.ok(&["proxy", "stop", "--forget"])["forgotten"].as_u64(), Some(pid));
    let status = env.ok(&["proxy", "status"]);
    assert_eq!((&status["running"], &status["unverified"]), (&false.into(), &Value::Null), "{status}");
    chmod(0o644);
    env.ok(&["proxy", "start", "--listen", "127.0.0.1:0"]);
}

#[test]
fn proxy_start_on_a_port_in_use_says_so() {
    let env = Env::new("port-in-use");
    let holder = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let listen = holder.local_addr().unwrap().to_string();

    let (code, v) = env.run(&["proxy", "start", "--listen", &listen]);
    assert_eq!((code, v["error"]["kind"].as_str()), (2, Some("conflict")), "{v}");
    let message = v["error"]["message"].as_str().unwrap();
    assert!(message.contains(&format!("cannot listen on {listen}")), "{message}");
    assert!(message.contains("already in use"), "{message}");
    assert_eq!(env.ok(&["proxy", "status"])["running"], false);
}

#[test]
fn proxy_start_on_a_chosen_port() {
    let env = Env::new("chosen-port");
    // Free the port just before asking for it: another process could take it in between.
    let free = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let listen = free.local_addr().unwrap().to_string();
    drop(free);

    let started = env.ok(&["proxy", "start", "--listen", &listen]);
    assert_eq!(started["listen"].as_str(), Some(listen.as_str()), "{started}");
    assert_eq!(started["usage"]["proxy_url"].as_str(), Some(format!("http://{listen}").as_str()), "{started}");

    let status = env.ok(&["proxy", "status"]);
    assert_eq!(status["running"], true, "{status}");
    assert_eq!(status["proxy"]["listen"].as_str(), Some(listen.as_str()), "{status}");
    assert_eq!(status["proxy"]["usage"]["proxy_url"].as_str(), Some(format!("http://{listen}").as_str()), "{status}");
}

/// Starts racing a restart, from a shell or an agent, never get in between its stop and its
/// start: each one fails, and what runs afterwards is the restart's proxy.
#[test]
fn proxy_restart_keeps_other_starts_out() {
    use std::sync::atomic::{AtomicBool, Ordering};
    let env = Env::new("restart-race");
    let mut pid = env.ok(&["proxy", "start", "--listen", "127.0.0.1:0"])["pid"].as_u64().unwrap();
    let mut held_off = 0;
    for _ in 0..3 {
        let done = AtomicBool::new(false);
        let ((code, v), starts) = std::thread::scope(|s| {
            let racer = s.spawn(|| {
                let mut starts = Vec::new();
                while !done.load(Ordering::SeqCst) {
                    starts.push(env.run(&["proxy", "start", "--listen", "127.0.0.1:0"]));
                }
                starts
            });
            let restarted = env.run(&["proxy", "restart", "--listen", "127.0.0.1:0"]);
            done.store(true, Ordering::SeqCst);
            (restarted, racer.join().unwrap())
        });
        assert_eq!(code, 0, "{v}");
        let restarted = &v["data"];
        assert_eq!(restarted["replaced"]["pid"].as_u64(), Some(pid), "{v}");
        assert!(!starts.is_empty());
        for (code, v) in &starts {
            assert_eq!((*code, v["error"]["kind"].as_str()), (2, Some("conflict")), "a start got in: {v}");
            held_off += v["error"]["message"].as_str().unwrap().contains("being restarted") as usize;
        }
        pid = restarted["pid"].as_u64().unwrap();
        let status = env.ok(&["proxy", "status"]);
        assert_eq!(status["proxy"]["pid"].as_u64(), Some(pid), "{status}");
        assert_eq!(status["proxy"]["listen"], restarted["listen"], "{status}");
    }
    eprintln!("{held_off} starts found the proxy being restarted");
}

#[test]
fn proxy_restart_to_a_taken_port_goes_back() {
    let env = Env::new("restart-back");
    let old = env.ok(&["proxy", "start", "--listen", "127.0.0.1:0", "--timeout", "12"]);
    let was = old["listen"].as_str().unwrap();
    let holder = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let taken = holder.local_addr().unwrap().to_string();

    let (code, v) = env.run(&["proxy", "restart", "--listen", &taken]);
    assert_eq!((code, v["error"]["kind"].as_str()), (2, Some("conflict")), "{v}");
    let message = v["error"]["message"].as_str().unwrap();
    assert!(message.contains(&format!("cannot listen on {taken}: the port is already in use")), "{message}");

    // Started again where it was, with its options, and the error says so.
    let status = env.ok(&["proxy", "status"]);
    assert_eq!(status["proxy"]["listen"].as_str(), Some(was), "{status}");
    let pid = status["proxy"]["pid"].as_u64().unwrap();
    assert_ne!(Some(pid), old["pid"].as_u64());
    assert!(message.ends_with(&format!("; the proxy was started again on {was} (pid {pid})")), "{message}");
    let args: Vec<&str> = status["proxy"]["args"].as_array().unwrap().iter().map(|a| a.as_str().unwrap()).collect();
    assert!(args.windows(2).any(|w| w == ["--timeout", "12"]), "{args:?}");
}

/// When neither the new proxy nor the old one comes up, the record is let go and the error says
/// the proxy is off.
#[test]
fn proxy_restart_that_cannot_go_back_says_the_proxy_is_off() {
    let env = Env::new("restart-off");
    env.ok(&["auth", "add", "key", "-H", "Authorization: Bearer x"]);
    let was = env.ok(&["proxy", "start", "--listen", "127.0.0.1:0", "--auth", "key"])["listen"].clone();
    env.ok(&["auth", "remove", "key"]);
    let holder = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let taken = holder.local_addr().unwrap().to_string();

    let (code, v) = env.run(&["proxy", "restart", "--listen", &taken]);
    assert_eq!((code, v["error"]["kind"].as_str()), (2, Some("conflict")), "{v}");
    let message = v["error"]["message"].as_str().unwrap();
    let back = format!("; the proxy couldn't be started again on {}: ", was.as_str().unwrap());
    assert!(message.contains(&back), "{message}");
    assert!(message.ends_with(". It is off now"), "{message}");
    let status = env.ok(&["proxy", "status"]);
    assert_eq!((&status["running"], &status["restarting"]), (&false.into(), &false.into()), "{status}");
    env.ok(&["proxy", "start", "--listen", "127.0.0.1:0"]);
}

#[test]
fn proxy_restart_with_nothing_running_starts_nothing() {
    let env = Env::new("restart-none");
    let (code, v) = env.run(&["proxy", "restart", "--listen", "127.0.0.1:0"]);
    assert_eq!((code, v["error"]["kind"].as_str()), (4, Some("not_found")), "{v}");
    assert!(v["error"]["message"].as_str().unwrap().contains("brainproxy proxy start"), "{v}");
    assert_eq!(env.ok(&["proxy", "status"])["running"], false);
}

/// While a restart holds the record, no other start, stop or restart acts on it, and there is
/// no proxy to connect to. The hold goes with the restart's process.
#[cfg(unix)]
#[test]
fn a_restart_in_progress_holds_off_the_rest() {
    use brainproxy_core::proxy::STATE_KEY;
    let env = Env::new("restart-held");
    let mut restarting = Command::new("sleep").arg("30").spawn().unwrap();
    let hold = serde_json::json!({"pid": restarting.id(), "listen": "127.0.0.1:1", "started": "0", "ca_cert": "/x",
        "log": null, "restart": "test"});
    let store = brainproxy_core::store::Store::open(&env.project).unwrap();
    store.meta_set(STATE_KEY, Some(&hold.to_string())).unwrap();

    for args in [
        &["proxy", "start", "--listen", "127.0.0.1:0"][..],
        &["proxy", "run", "--listen", "127.0.0.1:0"],
        &["proxy", "restart", "--listen", "127.0.0.1:0"],
        &["proxy", "stop"],
        &["proxy", "stop", "--forget"],
    ] {
        let (code, v) = env.run(args);
        assert_eq!((code, v["error"]["kind"].as_str()), (2, Some("conflict")), "{args:?}: {v}");
        assert!(v["error"]["message"].as_str().unwrap().contains("being restarted"), "{args:?}: {v}");
    }
    let status = env.ok(&["proxy", "status"]);
    assert_eq!((&status["running"], &status["restarting"]), (&false.into(), &true.into()), "{status}");
    assert!(restarting.try_wait().unwrap().is_none(), "the restart was signalled");

    restarting.kill().unwrap();
    restarting.wait().unwrap();
    assert_eq!(env.ok(&["proxy", "status"])["restarting"], false);
    env.ok(&["proxy", "start", "--listen", "127.0.0.1:0"]);
}

/// The project's proxy record as stored.
fn proxy_record(env: &Env) -> Option<String> {
    let store = brainproxy_core::store::Store::open(&env.project).unwrap();
    store.meta_get(brainproxy_core::proxy::STATE_KEY).unwrap()
}

/// Waits up to 10 s for `done`.
fn wait_for(what: &str, mut done: impl FnMut() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(10);
    while !done() {
        assert!(Instant::now() < deadline, "timed out waiting for {what}");
        std::thread::sleep(Duration::from_millis(20));
    }
}

#[cfg(unix)]
fn signal(sig: &str, pid: u64) {
    assert!(Command::new("kill").args([sig, &pid.to_string()]).status().unwrap().success());
}

#[cfg(target_os = "linux")]
fn wait_gone(pid: u64) {
    wait_for(&format!("pid {pid} to exit"), || {
        std::fs::read_to_string(format!("/proc/{pid}/stat")).map_or(true, |s| s.contains(") Z "))
    });
}

fn strs(v: &Value) -> Vec<&str> {
    v.as_array().unwrap().iter().map(|a| a.as_str().unwrap()).collect()
}

/// A restart takes the options it is given (start's defaults for the rest, not the old proxy's)
/// and answers like `proxy start`, plus what it replaced.
#[cfg(target_os = "linux")]
#[test]
fn proxy_restart_moves_the_proxy_with_the_options_given() {
    let env = Env::new("restart-moves");
    let old = env.ok(&["proxy", "start", "--listen", "127.0.0.1:0", "--timeout", "12", "--invisible"]);
    let old_pid = old["pid"].as_u64().unwrap();

    let new = env.ok(&["proxy", "restart", "--listen", "127.0.0.1:0", "--no-http2"]);
    let pid = new["pid"].as_u64().unwrap();
    assert_ne!(pid, old_pid);
    assert_eq!(new["replaced"], serde_json::json!({"pid": old_pid, "listen": old["listen"], "forced": false}));
    let mut keys: Vec<&String> = new.as_object().unwrap().keys().filter(|k| *k != "replaced").collect();
    let mut start_keys: Vec<&String> = old.as_object().unwrap().keys().collect();
    keys.sort();
    start_keys.sort();
    assert_eq!(keys, start_keys, "{new}");

    let args = strs(&new["args"]);
    assert!(args.contains(&"--no-http2") && !args.contains(&"--invisible"), "{args:?}");
    assert!(args.windows(2).any(|w| w == ["--timeout", "30"]), "{args:?}");
    let status = env.ok(&["proxy", "status"]);
    assert_eq!((status["proxy"]["pid"].as_u64(), &status["restarting"]), (Some(pid), &false.into()), "{status}");
    assert_eq!(status["proxy"]["listen"], new["listen"]);
    wait_gone(old_pid);
    std::net::TcpStream::connect(new["listen"].as_str().unwrap()).expect("the new proxy listens");
}

/// Everything a restart can check is checked before the running proxy is touched.
#[test]
fn proxy_restart_with_bad_options_leaves_the_proxy_alone() {
    let env = Env::new("restart-bad");
    let pid = env.ok(&["proxy", "start", "--listen", "127.0.0.1:0"])["pid"].as_u64().unwrap();
    let before = proxy_record(&env);
    for args in [
        &["proxy", "restart", "--listen", "127.0.0.1:0", "--auth", "nobody"][..],
        &["proxy", "restart", "--listen", "127.0.0.1:0", "--redirect", "not a url"],
        &["proxy", "restart", "--listen", "127.0.0.1:0", "--authz", "nobody"],
    ] {
        let (code, v) = env.run(args);
        assert_ne!(code, 0, "{args:?}: {v}");
        assert!(!v["error"]["message"].as_str().unwrap().contains("; the proxy"), "{args:?}: {v}");
        assert_eq!(proxy_record(&env), before, "{args:?}");
        let store = brainproxy_core::store::Store::open(&env.project).unwrap();
        assert_eq!(store.meta_get("proxy.stop").unwrap(), None, "{args:?} asked the proxy to stop");
    }
    let status = env.ok(&["proxy", "status"]);
    assert_eq!((status["proxy"]["pid"].as_u64(), &status["restarting"]), (Some(pid), &false.into()), "{status}");
}

/// A proxy whose recorded options can't be read couldn't be started again, so it isn't stopped.
#[test]
fn proxy_restart_refuses_a_proxy_it_could_not_start_again() {
    let env = Env::new("restart-unreadable");
    let pid = env.ok(&["proxy", "start", "--listen", "127.0.0.1:0"])["pid"].as_u64().unwrap();
    let store = brainproxy_core::store::Store::open(&env.project).unwrap();
    let mut record: Value = serde_json::from_str(&proxy_record(&env).unwrap()).unwrap();
    record["args"] = serde_json::json!(["proxy", "run", "--from-the-future"]);
    store.meta_set(brainproxy_core::proxy::STATE_KEY, Some(&record.to_string())).unwrap();

    let (code, v) = env.run(&["proxy", "restart", "--listen", "127.0.0.1:0"]);
    assert_eq!((code, v["error"]["kind"].as_str()), (2, Some("conflict")), "{v}");
    assert!(v["error"]["message"].as_str().unwrap().contains("can't restart the proxy"), "{v}");
    assert_eq!(proxy_record(&env), Some(record.to_string()));
    assert_eq!(env.ok(&["proxy", "status"])["proxy"]["pid"].as_u64(), Some(pid));
    assert_eq!(env.ok(&["proxy", "stop"])["stopped"].as_u64(), Some(pid));
}

/// Going back starts the old proxy with all of its options, not only --listen and --timeout.
#[test]
fn proxy_restart_goes_back_with_every_option() {
    let env = Env::new("restart-back-all");
    env.ok(&["auth", "add", "key", "-H", "Authorization: Bearer x"]);
    let flags = ["--auth", "key", "--invisible", "--no-http2", "--verify-tls", "--timeout", "12"];
    let old = env.ok(&[&["proxy", "start", "--listen", "127.0.0.1:0"][..], &flags].concat());
    let holder = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let taken = holder.local_addr().unwrap().to_string();

    let (code, v) = env.run(&["proxy", "restart", "--listen", &taken]);
    assert_eq!(code, 2, "{v}");
    let status = env.ok(&["proxy", "status"]);
    assert_eq!(status["proxy"]["listen"], old["listen"], "{status}");
    // The same, but on the address it had rather than the one asked for (port 0).
    let listen = old["listen"].as_str().unwrap();
    let was: Vec<&str> = strs(&old["args"]).into_iter().map(|a| if a == "127.0.0.1:0" { listen } else { a }).collect();
    assert_eq!(strs(&status["proxy"]["args"]), was);
}

/// A restart that has stopped the old proxy and not yet started the new one, held there by
/// pausing the old proxy: every other start, stop or restart is turned away until it is done,
/// and the restart's proxy is what runs afterwards. The old proxy never exits, so it is killed.
#[cfg(target_os = "linux")]
#[test]
fn proxy_restart_holds_off_everything_between_its_stop_and_start() {
    let env = Env::new("restart-window");
    let old = env.ok(&["proxy", "start", "--listen", "127.0.0.1:0"]);
    let old_pid = old["pid"].as_u64().unwrap();
    signal("-STOP", old_pid);
    let store = brainproxy_core::store::Store::open(&env.project).unwrap();
    std::thread::scope(|s| {
        let restart = s.spawn(|| env.run(&["proxy", "restart", "--listen", "127.0.0.1:0"]));
        wait_for("the restart to ask the old proxy to stop", || {
            store.meta_get("proxy.stop").unwrap() == Some(old_pid.to_string())
        });
        let hold: Value = serde_json::from_str(&proxy_record(&env).unwrap()).unwrap();
        assert!(hold["restart"].is_string(), "{hold}");
        assert_ne!(hold["pid"].as_u64(), Some(old_pid), "{hold}");

        for args in [
            &["proxy", "start", "--listen", "127.0.0.1:0"][..],
            &["proxy", "run", "--listen", "127.0.0.1:0"],
            &["proxy", "restart", "--listen", "127.0.0.1:0"],
            &["proxy", "stop"],
            &["proxy", "stop", "--forget"],
            &["project", "stop"],
        ] {
            let (code, v) = env.run(args);
            assert_eq!((code, v["error"]["kind"].as_str()), (2, Some("conflict")), "{args:?}: {v}");
            assert!(v["error"]["message"].as_str().unwrap().contains("being restarted"), "{args:?}: {v}");
        }
        let status = env.ok(&["proxy", "status"]);
        assert_eq!((&status["running"], &status["restarting"]), (&false.into(), &true.into()), "{status}");

        let (code, v) = restart.join().unwrap();
        assert_eq!(code, 0, "{v}");
        let new = &v["data"];
        assert_eq!(new["replaced"]["pid"].as_u64(), Some(old_pid), "{v}");
        assert_eq!(new["replaced"]["forced"], true, "{v}");
        let status = env.ok(&["proxy", "status"]);
        assert_eq!(status["proxy"]["pid"], new["pid"], "{status}");
        assert_eq!(status["restarting"], false, "{status}");
    });
    wait_gone(old_pid);
}

/// Two restarts at once: one proxy runs afterwards, the last successful restart's, and a restart
/// that lost never stopped anything.
#[test]
fn proxy_restarts_racing_each_other_leave_one_proxy() {
    let env = Env::new("restart-restart");
    let mut pid = env.ok(&["proxy", "start", "--listen", "127.0.0.1:0"])["pid"].as_u64().unwrap();
    for _ in 0..3 {
        let barrier = std::sync::Barrier::new(2);
        let results: Vec<(i32, Value)> = std::thread::scope(|s| {
            let racers: Vec<_> = (0..2)
                .map(|_| {
                    s.spawn(|| {
                        barrier.wait();
                        env.run(&["proxy", "restart", "--listen", "127.0.0.1:0"])
                    })
                })
                .collect();
            racers.into_iter().map(|r| r.join().unwrap()).collect()
        });
        let ok: Vec<&Value> = results.iter().filter(|(c, _)| *c == 0).map(|(_, v)| &v["data"]).collect();
        for (code, v) in results.iter().filter(|(c, _)| *c != 0) {
            assert_eq!((*code, v["error"]["kind"].as_str()), (2, Some("conflict")), "{v}");
            let message = v["error"]["message"].as_str().unwrap();
            assert!(message.contains("being restarted") || message.contains("while restarting it"), "{message}");
        }
        // Each restart that succeeded replaced the proxy running before it: the old one, or the
        // other restart's.
        let last = match ok.as_slice() {
            [one] => {
                assert_eq!(one["replaced"]["pid"].as_u64(), Some(pid), "{one}");
                one
            }
            [a, b] => {
                let (first, second) = if b["replaced"]["pid"] == a["pid"] { (a, b) } else { (b, a) };
                assert_eq!(first["replaced"]["pid"].as_u64(), Some(pid), "{first} / {second}");
                assert_eq!(second["replaced"]["pid"], first["pid"], "{first} / {second}");
                second
            }
            _ => panic!("no restart succeeded: {results:?}"),
        };
        pid = last["pid"].as_u64().unwrap();
        let status = env.ok(&["proxy", "status"]);
        assert_eq!(status["proxy"]["pid"].as_u64(), Some(pid), "{status}");
    }
}

/// Plain starts racing on a project with no proxy: only one records itself and runs, the others
/// fail as a conflict (not a timeout: their proxies gave up and exited).
#[test]
fn concurrent_proxy_starts_record_only_one() {
    let env = Env::new("start-race");
    // The CA exists first, so the race is only over the record.
    env.ok(&["proxy", "start", "--listen", "127.0.0.1:0"]);
    env.ok(&["proxy", "stop"]);
    for _ in 0..3 {
        let barrier = std::sync::Barrier::new(4);
        let results: Vec<(i32, Value)> = std::thread::scope(|s| {
            let racers: Vec<_> = (0..4)
                .map(|_| {
                    s.spawn(|| {
                        barrier.wait();
                        env.run(&["proxy", "start", "--listen", "127.0.0.1:0"])
                    })
                })
                .collect();
            racers.into_iter().map(|r| r.join().unwrap()).collect()
        });
        let ok: Vec<&Value> = results.iter().filter(|(c, _)| *c == 0).map(|(_, v)| &v["data"]).collect();
        assert_eq!(ok.len(), 1, "{results:?}");
        for (code, v) in results.iter().filter(|(c, _)| *c != 0) {
            assert_eq!((*code, v["error"]["kind"].as_str()), (2, Some("conflict")), "{v}");
        }
        let status = env.ok(&["proxy", "status"]);
        assert_eq!(status["proxy"]["pid"], ok[0]["pid"], "{status}");
        env.ok(&["proxy", "stop"]);
    }
}

/// A proxy in another container is restarted through the project file, as `proxy stop` does.
#[cfg(target_os = "linux")]
#[test]
fn proxy_restart_of_a_proxy_in_another_namespace() {
    use brainproxy_core::proxy::STATE_KEY;
    let env = Env::new("restart-namespace");
    let old_pid = env.ok(&["proxy", "start", "--listen", "127.0.0.1:0"])["pid"].as_u64().unwrap();
    pretend_other_namespace(&env.project, STATE_KEY);
    let new = env.ok(&["proxy", "restart", "--listen", "127.0.0.1:0"]);
    assert_eq!((new["replaced"]["pid"].as_u64(), &new["replaced"]["forced"]), (Some(old_pid), &false.into()), "{new}");
    let status = env.ok(&["proxy", "status"]);
    assert_eq!(status["proxy"]["pid"], new["pid"], "{status}");
    assert_eq!(status["other_pid_namespace"], false, "{status}");
}
