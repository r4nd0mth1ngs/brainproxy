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
        self.run_env(args, &[])
    }

    /// [`Env::run`] with these environment variables set.
    fn run_env(&self, args: &[&str], vars: &[(&str, &str)]) -> (i32, Value) {
        let out = Command::new(env!("CARGO_BIN_EXE_brainproxy"))
            .envs(vars.iter().copied())
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

    // Out-of-scope traffic still flows, and leaves a row that keeps only the request line.
    env.ok(&["scope", "set", "--include", r"^example\.test$"]);
    wait_for_settings();
    let before = env.count("SELECT max(id) FROM history");
    let url = format!("http://127.0.0.1:{http_port}/oos?token=secret");
    let (status, _) = curl(&proxy, &env.ca(), &url, &["-H", "Cookie: sid=secret"]);
    assert_eq!(status, 200);
    // A CONNECT outside the scope is tunnelled, not decrypted, and leaves a row for the tunnel.
    let (status, _) = curl(&proxy, &env.ca(), &format!("https://localhost:{https_port}/tunnelled"), &["-k"]);
    assert_eq!(status, 200);
    let rows = |sql: &str| env.ok(&["query", sql])["rows"].clone();
    let deadline = Instant::now() + Duration::from_secs(5);
    while env.count(&format!("SELECT count(*) FROM history WHERE id > {before}")) < 2 && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(50));
    }
    let r = rows(&format!(
        "SELECT method, url, query, status, error, req_headers, CAST(request AS TEXT), length(response), client_addr \
         FROM history WHERE id > {before} ORDER BY id"
    ));
    assert_eq!(r.as_array().unwrap().len(), 2, "{r}");
    assert_eq!(
        (r[0][0].as_str(), r[0][1].as_str()),
        (Some("GET"), Some(&*format!("http://127.0.0.1:{http_port}/oos")))
    );
    assert!(r[0][2].is_null() && r[0][3].is_null(), "{r}");
    assert_eq!(
        r[0][4], "outside the recording scope: content omitted; query string omitted; response status 200",
        "{r}"
    );
    assert_eq!((&r[0][5], &r[0][6], &r[0][7]), (&"[]".into(), &"GET /oos HTTP/1.1\r\n\r\n".into(), &0.into()));
    assert!(r[0][8].as_str().is_some_and(|a| a.starts_with("127.0.0.1:")), "{r}");
    assert_eq!(
        (r[1][0].as_str(), r[1][1].as_str()),
        (Some("CONNECT"), Some(&*format!("https://localhost:{https_port}")))
    );
    assert!(r[1][4].as_str().unwrap().starts_with("outside the recording scope: tunnelled, not decrypted: "), "{r}");
    assert!(!r.to_string().contains("secret") && !r.to_string().contains("/tunnelled"), "{r}");
    // Nothing for the passive checks: the rows keep no response.
    std::thread::sleep(Duration::from_millis(500));
    let scanned = format!("SELECT count(*) FROM findings WHERE history_id > {before} OR last_history_id > {before}");
    assert_eq!(env.count(&scanned), 0);
    // Recording out-of-scope traffic too keeps all of it.
    env.ok(&["scope", "set", "--include", r"^example\.test$", "--record-out-of-scope"]);
    wait_for_settings();
    let (status, _) = curl(&proxy, &env.ca(), &format!("http://127.0.0.1:{http_port}/recorded?q=1"), &[]);
    assert_eq!(status, 200);
    let deadline = Instant::now() + Duration::from_secs(5);
    while env.count("SELECT count(*) FROM history WHERE path = '/recorded'") < 1 && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(50));
    }
    let r = rows("SELECT status, query, error FROM history WHERE path = '/recorded'");
    assert_eq!(r, serde_json::json!([[200, "q=1", null]]));
    env.ok(&["scope", "clear"]);

    // Every entry, intercepted ones included, names the client it came from.
    assert_eq!(env.count("SELECT count(*) FROM history WHERE source = 'proxy' AND client_addr IS NULL"), 0);
    let status = env.ok(&["proxy", "status"]);
    assert_eq!(status["running"], true);
    env.ok(&["proxy", "stop"]);
    assert_eq!(env.ok(&["proxy", "status"])["running"], false);
}

/// A tunnel outside the recording scope still open when the proxy stops leaves its row all the
/// same: the proxy doesn't wait for it, and it would otherwise be recorded only as it closes.
#[test]
fn a_tunnel_still_open_when_the_proxy_stops_leaves_a_row() {
    use std::io::{Read, Write};
    let env = Env::new("open-tunnel");
    let http_port = spawn_echo(false, &env.dir);
    env.ok(&["scope", "set", "--include", r"^example\.test$"]);
    let started = env.ok(&["proxy", "start", "--listen", "127.0.0.1:0"]);
    let listen = started["listen"].as_str().unwrap().to_string();
    let mut tunnel = std::net::TcpStream::connect(&listen).unwrap();
    write!(tunnel, "CONNECT 127.0.0.1:{http_port} HTTP/1.1\r\nHost: 127.0.0.1:{http_port}\r\n\r\n").unwrap();
    tunnel.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
    let mut reply = [0u8; 12];
    tunnel.read_exact(&mut reply).unwrap();
    assert_eq!(&reply, b"HTTP/1.1 200", "{}", String::from_utf8_lossy(&reply));
    // The row is there while the tunnel is open, so a proxy that is killed still leaves it.
    let open = "outside the recording scope: tunnelled, not decrypted: open, no close recorded yet";
    let deadline = Instant::now() + Duration::from_secs(5);
    while env.count("SELECT count(*) FROM history") < 1 && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(50));
    }
    let rows = env.ok(&["query", "SELECT method, status, error FROM history"])["rows"].clone();
    assert_eq!(rows, serde_json::json!([["CONNECT", null, open]]));
    let stopped = Instant::now();
    env.ok(&["proxy", "stop"]);
    // Not held up by the tunnel, as it is by a request still waiting for its response.
    assert!(stopped.elapsed() < Duration::from_secs(10));
    let rows = env.ok(&["query", "SELECT method, url, error FROM history"])["rows"].clone();
    assert_eq!(rows.as_array().map(Vec::len), Some(1), "{rows}");
    assert_eq!(rows[0][0], "CONNECT");
    assert_eq!(rows[0][1], format!("https://127.0.0.1:{http_port}"));
    assert_eq!(rows[0][2], "outside the recording scope: tunnelled, not decrypted: still open when the proxy stopped");
    drop(tunnel);
}

/// A tunnel's row is written as it opens and completed with the byte counts as it closes.
#[test]
fn a_tunnel_row_is_written_as_it_opens_and_completed_as_it_closes() {
    use std::io::{Read, Write};
    let env = Env::new("tunnel-row");
    let http_port = spawn_echo(false, &env.dir);
    env.ok(&["scope", "set", "--include", r"^example\.test$"]);
    let started = env.ok(&["proxy", "start", "--listen", "127.0.0.1:0"]);
    let listen = started["listen"].as_str().unwrap().to_string();
    let mut tunnel = std::net::TcpStream::connect(&listen).unwrap();
    write!(tunnel, "CONNECT 127.0.0.1:{http_port} HTTP/1.1\r\nHost: 127.0.0.1:{http_port}\r\n\r\n").unwrap();
    tunnel.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
    let mut reply = [0u8; 39];
    tunnel.read_exact(&mut reply).unwrap();
    assert_eq!(&reply, b"HTTP/1.1 200 Connection established\r\n\r\n");
    let rows = |sql: &str| env.ok(&["query", sql])["rows"].clone();
    let sql = "SELECT method, status, error, duration_ms FROM history";
    let open = "outside the recording scope: tunnelled, not decrypted: open, no close recorded yet";
    let deadline = Instant::now() + Duration::from_secs(5);
    while env.count("SELECT count(*) FROM history") < 1 && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(50));
    }
    assert_eq!(rows(sql), serde_json::json!([["CONNECT", null, open, null]]));
    // Bytes through the tunnel, then the client closes it.
    write!(tunnel, "GET /x HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n").unwrap();
    let mut answer = [0u8; 12];
    tunnel.read_exact(&mut answer).unwrap();
    assert_eq!(&answer, b"HTTP/1.1 200");
    tunnel.shutdown(std::net::Shutdown::Write).unwrap();
    let mut rest = Vec::new();
    let _ = tunnel.read_to_end(&mut rest);
    let deadline = Instant::now() + Duration::from_secs(5);
    while rows(sql)[0][2] == open && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(50));
    }
    let r = rows(sql);
    assert_eq!(r.as_array().map(Vec::len), Some(1), "{r}");
    let error = r[0][2].as_str().unwrap();
    assert!(error.starts_with("outside the recording scope: tunnelled, not decrypted: 36 bytes sent, "), "{r}");
    assert!(error.ends_with(" received") && r[0][1].is_null() && r[0][3].is_i64(), "{r}");
    env.ok(&["proxy", "stop"]);
    // Stopping leaves a closed tunnel's row as it is.
    assert_eq!(rows(sql), r);
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
    // What Replay's Race shows: the technique, and per request a history id, length and time.
    assert_eq!((r["sync"].as_str(), r["synced"].is_null()), (Some("last-byte"), true));
    let first = &r["results"][0];
    assert!(first["id"].is_i64() && first["length"].is_u64() && first["duration_ms"].is_u64(), "{first}");

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

    // The rows are written after the client has its response: wait for them under load.
    let deadline = Instant::now() + Duration::from_secs(10);
    while env.count("SELECT count(*) FROM history WHERE source = 'proxy' AND status IS NOT NULL") < 3
        && Instant::now() < deadline
    {
        std::thread::sleep(Duration::from_millis(50));
    }
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
    // HTTP/2 streams run on tasks of their own: they still name the client.
    assert_eq!(env.count("SELECT count(*) FROM history WHERE source = 'proxy' AND client_addr IS NULL"), 0);

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
    // `project stop` stops the rest all the same, and says why the proxy wasn't.
    let oob = env.ok(&["oob", "start", "--listen", "127.0.0.1:0"])["pid"].as_u64().unwrap();
    let (code, v) = env.run(&["project", "stop"]);
    assert_eq!((code, v["error"]["kind"].as_str()), (2, Some("conflict")), "{v}");
    assert!(v["error"]["message"].as_str().unwrap().contains("stop --forget"), "{v}");
    assert_eq!((v["error"]["data"]["oob"].as_u64(), &v["error"]["data"]["proxy"]), (Some(oob), &Value::Null), "{v}");
    assert_eq!(env.ok(&["oob", "status"])["running"], false);

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
/// start: each one fails, and what runs afterwards is the restart's proxy. Whether any of them
/// lands between the two is down to timing; `proxy_restart_blocked_on_a_login_holds_off_starts`
/// holds a restart there.
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
    // The same, for a caller to act on without reading the message.
    let failure = message.strip_suffix(&format!("; the proxy was started again on {was} (pid {pid})")).unwrap();
    assert_eq!(
        v["error"]["data"],
        serde_json::json!({"stopped": true, "failure": failure, "restarted": {"pid": pid, "listen": was}}),
        "{v}"
    );
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
    let data = &v["error"]["data"];
    assert_eq!((&data["stopped"], &data["restarted"]), (&true.into(), &Value::Null), "{v}");
    assert!(message.starts_with(data["failure"].as_str().unwrap()), "{v}");
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

/// While a restart holds the record, no other start or restart acts on it, nor `stop --forget`,
/// and there is no proxy to connect to. The hold goes with the restart's process. (`proxy stop`
/// calls a restart off: `proxy_stop_calls_off_a_restart`.)
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
        &["proxy", "stop", "--forget"],
    ] {
        let (code, v) = env.run(args);
        assert_eq!((code, v["error"]["kind"].as_str()), (2, Some("conflict")), "{args:?}: {v}");
        assert!(v["error"]["message"].as_str().unwrap().contains("being restarted"), "{args:?}: {v}");
    }
    // Not the proxy that `stop --pid` names.
    let (code, v) = env.run(&["proxy", "stop", "--pid", &restarting.id().to_string()]);
    assert_eq!((code, v["error"]["kind"].as_str()), (4, Some("not_found")), "{v}");
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
#[cfg(unix)]
fn wait_for(what: &str, mut done: impl FnMut() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(10);
    while !done() {
        assert!(Instant::now() < deadline, "timed out waiting for {what}");
        std::thread::sleep(Duration::from_millis(20));
    }
}

#[cfg(target_os = "linux")]
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
    // `args` shows what the old proxy ran with, so what was left out.
    assert_eq!(
        new["replaced"],
        serde_json::json!({"pid": old_pid, "listen": old["listen"], "forced": false, "args": old["args"]})
    );
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
        // Its new proxy couldn't be waited for, so nothing would answer or go back.
        &["proxy", "restart", "--listen", "127.0.0.1:0", "--wait", "inf"],
        &["proxy", "restart", "--listen", "127.0.0.1:0", "--wait", "NaN"],
        &["proxy", "restart", "--listen", "127.0.0.1:0", "--wait=-1"],
        // A restart holds off every other start while it waits, so not for long.
        &["proxy", "restart", "--listen", "127.0.0.1:0", "--wait", "61"],
    ] {
        let (code, v) = env.run(args);
        assert_ne!(code, 0, "{args:?}: {v}");
        assert!(!v["error"]["message"].as_str().unwrap().contains("; the proxy"), "{args:?}: {v}");
        assert_eq!(v["error"]["data"], serde_json::json!({"stopped": false}), "{args:?}: {v}");
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

/// Through MCP a restart, like a start, listens on loopback only, and it leaves alone a proxy
/// that doesn't: if it failed, it couldn't start that one again where it was.
#[test]
fn proxy_restart_through_mcp_stays_on_loopback() {
    let agent = [("BRAINPROXY_MCP_CALL", "1")];
    let env = Env::new("restart-mcp");
    let pid = env.ok(&["proxy", "start", "--listen", "127.0.0.1:0"])["pid"].as_u64().unwrap();
    let before = proxy_record(&env);
    let (code, v) = env.run_env(&["proxy", "restart", "--listen", "0.0.0.0:0"], &agent);
    assert_eq!((code, v["error"]["kind"].as_str()), (2, Some("invalid_input")), "{v}");
    assert!(v["error"]["message"].as_str().unwrap().contains("loopback only"), "{v}");
    assert_eq!(v["error"]["data"], serde_json::json!({"stopped": false}), "{v}");
    assert_eq!(proxy_record(&env), before);
    env.ok(&["proxy", "stop"]);

    // A person's proxy on every address.
    let pid2 = env.ok(&["proxy", "start", "--listen", "0.0.0.0:0"])["pid"].as_u64().unwrap();
    assert_ne!(pid, pid2);
    let before = proxy_record(&env);
    let (code, v) = env.run_env(&["proxy", "restart", "--listen", "127.0.0.1:0"], &agent);
    assert_eq!((code, v["error"]["kind"].as_str()), (2, Some("invalid_input")), "{v}");
    assert!(v["error"]["message"].as_str().unwrap().contains("can't restart the proxy through MCP"), "{v}");
    assert_eq!(v["error"]["data"], serde_json::json!({"stopped": false}), "{v}");
    assert_eq!(proxy_record(&env), before);
    // A person can.
    let moved = env.ok(&["proxy", "restart", "--listen", "127.0.0.1:0"]);
    assert_eq!(moved["replaced"]["pid"].as_u64(), Some(pid2), "{moved}");
}

/// Through MCP no proxy is started, or restarted, with a redirect or invisible mode: either
/// would send the person's browsing where an agent chose. Nor is a person's such proxy restarted.
#[test]
fn an_agent_cannot_reroute_the_persons_proxy() {
    let agent = [("BRAINPROXY_MCP_CALL", "1")];
    let env = Env::new("reroute-mcp");
    for flags in [&["--redirect", "http://127.0.0.1:9"][..], &["--invisible"][..]] {
        let (code, v) = env.run_env(&[&["proxy", "start", "--listen", "127.0.0.1:0"][..], flags].concat(), &agent);
        assert_eq!((code, v["error"]["kind"].as_str()), (2, Some("invalid_input")), "{flags:?}: {v}");
        assert!(v["error"]["message"].as_str().unwrap().contains("aren't offered through MCP"), "{v}");
    }
    assert!(!env.ok(&["proxy", "status"])["running"].as_bool().unwrap());

    let pid = env.ok(&["proxy", "start", "--listen", "127.0.0.1:0"])["pid"].as_u64().unwrap();
    let before = proxy_record(&env);
    let args = ["proxy", "restart", "--listen", "127.0.0.1:0", "--redirect", "http://127.0.0.1:9"];
    let (code, v) = env.run_env(&args, &agent);
    assert_eq!((code, v["error"]["kind"].as_str()), (2, Some("invalid_input")), "{v}");
    assert_eq!(proxy_record(&env), before, "the person's proxy wasn't touched");
    assert_eq!(env.ok(&["proxy", "status"])["proxy"]["pid"].as_u64(), Some(pid));
    env.ok(&["proxy", "stop"]);

    // A person's invisible proxy: the agent couldn't start it again if its restart failed.
    env.ok(&["proxy", "start", "--listen", "127.0.0.1:0", "--invisible"]);
    let before = proxy_record(&env);
    let (code, v) = env.run_env(&["proxy", "restart", "--listen", "127.0.0.1:0"], &agent);
    assert_eq!((code, v["error"]["kind"].as_str()), (2, Some("invalid_input")), "{v}");
    assert!(v["error"]["message"].as_str().unwrap().contains("can't restart the proxy through MCP"), "{v}");
    assert_eq!(proxy_record(&env), before);
    env.ok(&["proxy", "stop"]);
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
/// pausing the old proxy: every other start or restart is turned away until it is done,
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
            &["proxy", "stop", "--forget"],
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
            assert!(
                ["being restarted", "while restarting it", "another proxy restart is already running"]
                    .iter()
                    .any(|m| message.contains(m)),
                "{message}"
            );
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

/// A login server that answers each request with "Welcome", holding the first answer until
/// `release` is sent: `true` answers it, `false` hangs up instead, so that login fails. `arrived`
/// gets a message as that first request comes in.
fn held_login_server() -> (String, std::sync::mpsc::Receiver<()>, std::sync::mpsc::Sender<bool>) {
    use std::io::{BufRead, BufReader, Read, Write};
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://{}/login", listener.local_addr().unwrap());
    let (arrived_tx, arrived) = std::sync::mpsc::channel();
    let (release, release_rx) = std::sync::mpsc::channel::<bool>();
    std::thread::spawn(move || {
        for (i, conn) in listener.incoming().enumerate() {
            let Ok(mut conn) = conn else { return };
            let mut reader = BufReader::new(conn.try_clone().unwrap());
            let mut length = 0;
            loop {
                let mut line = String::new();
                if reader.read_line(&mut line).unwrap_or(0) == 0 || line == "\r\n" {
                    break;
                }
                if let Some((name, value)) = line.split_once(':') {
                    if name.eq_ignore_ascii_case("content-length") {
                        length = value.trim().parse().unwrap_or(0);
                    }
                }
            }
            let _ = reader.read_exact(&mut vec![0; length]);
            if i == 0 {
                let _ = arrived_tx.send(());
                if !release_rx.recv().unwrap_or(true) {
                    continue;
                }
            }
            let body = "Welcome";
            let _ =
                write!(conn, "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len());
        }
    });
    (url, arrived, release)
}

/// A restart whose new proxy is logging in (`--auth`) has stopped the old proxy and not started
/// the new one. The login is held there: a start is turned away, also from another container,
/// and the restart's proxy is what runs once it is let go.
#[test]
fn proxy_restart_blocked_on_a_login_holds_off_starts() {
    let env = Env::new("restart-login");
    let (login, arrived, release) = held_login_server();
    env.ok(&["auth", "add", "slow", "--login-url", &login, "--login-body", "a=b", "--logged-in", "Welcome"]);
    let old_pid = env.ok(&["proxy", "start", "--listen", "127.0.0.1:0"])["pid"].as_u64().unwrap();
    std::thread::scope(|s| {
        let restart = s.spawn(|| env.run(&["proxy", "restart", "--listen", "127.0.0.1:0", "--auth", "slow"]));
        arrived.recv_timeout(Duration::from_secs(10)).expect("the new proxy logs in");

        let refused = |when: &str| {
            let (code, v) = env.run(&["proxy", "start", "--listen", "127.0.0.1:0"]);
            assert_eq!((code, v["error"]["kind"].as_str()), (2, Some("conflict")), "{when}: a start got in: {v}");
            assert!(v["error"]["message"].as_str().unwrap().contains("being restarted"), "{when}: {v}");
            let status = env.ok(&["proxy", "status"]);
            assert_eq!((&status["running"], &status["restarting"]), (&false.into(), &true.into()), "{when}: {status}");
        };
        refused("here");
        // Seen from another container, where the restart's pid means nothing, its lock vouches
        // for it: the proxy's own lock is free until the new proxy is up.
        #[cfg(target_os = "linux")]
        {
            pretend_other_namespace(&env.project, brainproxy_core::proxy::STATE_KEY);
            refused("from another namespace");
        }

        release.send(true).unwrap();
        let (code, v) = restart.join().unwrap();
        assert_eq!(code, 0, "{v}");
        let new = &v["data"];
        assert_eq!(new["replaced"]["pid"].as_u64(), Some(old_pid), "{v}");
        let status = env.ok(&["proxy", "status"]);
        assert_eq!((&status["proxy"]["pid"], &status["restarting"]), (&new["pid"], &false.into()), "{status}");
        assert_eq!(status["proxy"]["listen"], new["listen"], "{status}");
    });
}

/// A restart's hold written in another container is judged by the restart's lock: held, nothing
/// here clears the hold or starts a proxy; free, the restart is gone and so is its hold.
#[cfg(target_os = "linux")]
#[test]
fn a_restart_in_another_namespace_holds_off_starts_here() {
    use brainproxy_core::proxy::STATE_KEY;
    let env = Env::new("restart-held-elsewhere");
    // A proxy ran and stopped, so its lock file is there and free, as between a restart's stop
    // and its start.
    env.ok(&["proxy", "start", "--listen", "127.0.0.1:0"]);
    env.ok(&["proxy", "stop"]);
    let hold = serde_json::json!({"pid": 1, "start_time": 1, "listen": "127.0.0.1:1", "started": "0", "ca_cert": "/x",
        "log": null, "pid_ns": "pid:[1]", "restart": "test"})
    .to_string();
    let store = brainproxy_core::store::Store::open(&env.project).unwrap();
    store.meta_set(STATE_KEY, Some(&hold)).unwrap();
    let mut lock_path = env.project.clone().into_os_string();
    lock_path.push("-proxy-restart.lock");
    let lock = std::fs::OpenOptions::new().create(true).truncate(false).write(true).open(&lock_path).unwrap();
    lock.lock().unwrap();

    for args in [&["proxy", "start", "--listen", "127.0.0.1:0"][..], &["proxy", "restart", "--listen", "127.0.0.1:0"]] {
        let (code, v) = env.run(args);
        assert_eq!((code, v["error"]["kind"].as_str()), (2, Some("conflict")), "{args:?} got in: {v}");
        assert!(v["error"]["message"].as_str().unwrap().contains("being restarted"), "{args:?}: {v}");
    }
    let status = env.ok(&["proxy", "status"]);
    assert_eq!((&status["running"], &status["restarting"]), (&false.into(), &true.into()), "{status}");
    assert_eq!(proxy_record(&env), Some(hold));

    drop(lock);
    assert_eq!(env.ok(&["proxy", "status"])["restarting"], false);
    assert_eq!(proxy_record(&env), None);
    env.ok(&["proxy", "start", "--listen", "127.0.0.1:0"]);
}

/// `project stop` during a restart calls it off, stops the OOB listener and the rest at once, then
/// waits for the restart to let go of the record and stops whatever proxy it left.
#[cfg(unix)]
#[test]
fn project_stop_during_a_restart_stops_the_rest_and_then_the_proxy() {
    use brainproxy_core::proxy::STATE_KEY;
    let env = Env::new("restart-project-stop");
    let oob = env.ok(&["oob", "start", "--listen", "127.0.0.1:0"])["pid"].as_u64().unwrap();
    let mut restarting = Command::new("sleep").arg("30").spawn().unwrap();
    let hold = serde_json::json!({"pid": restarting.id(), "listen": "127.0.0.1:1", "started": "0", "ca_cert": "/x",
        "log": null, "restart": "test"});
    let store = brainproxy_core::store::Store::open(&env.project).unwrap();
    store.meta_set(STATE_KEY, Some(&hold.to_string())).unwrap();

    let (code, v) = std::thread::scope(|s| {
        let stop = s.spawn(|| env.run(&["project", "stop"]));
        wait_for("the OOB listener to stop", || env.ok(&["oob", "status"])["running"] == false);
        assert!(!stop.is_finished(), "project stop didn't wait for the restart");
        assert_eq!(env.ok(&["proxy", "status"])["restarting"], true);
        assert_eq!(store.meta_get("proxy.restart.cancel").unwrap().as_deref(), Some("test"));
        // The restart ends (here it doesn't look: its process goes, and its hold with it).
        restarting.kill().unwrap();
        restarting.wait().unwrap();
        stop.join().unwrap()
    });
    assert_eq!(code, 0, "{v}");
    assert_eq!((v["data"]["oob"].as_u64(), &v["data"]["proxy"]), (Some(oob), &Value::Null), "{v}");
    assert_eq!(env.ok(&["proxy", "status"])["restarting"], false);
}

/// A restart started while a `proxy stop` is under way leaves the proxy to that stop, so it ends
/// up off as asked. The old proxy is paused, so the stop takes a while and has to kill it.
#[cfg(target_os = "linux")]
#[test]
fn proxy_restart_leaves_a_stop_under_way_alone() {
    let env = Env::new("restart-during-stop");
    let old_pid = env.ok(&["proxy", "start", "--listen", "127.0.0.1:0"])["pid"].as_u64().unwrap();
    signal("-STOP", old_pid);
    let store = brainproxy_core::store::Store::open(&env.project).unwrap();
    let (stopped, (code, v)) = std::thread::scope(|s| {
        let stop = s.spawn(|| env.ok(&["proxy", "stop"]));
        wait_for("the stop to ask", || store.meta_get("proxy.stop").unwrap() == Some(old_pid.to_string()));
        let restarted = env.run(&["proxy", "restart", "--listen", "127.0.0.1:0"]);
        (stop.join().unwrap(), restarted)
    });
    assert_eq!((code, v["error"]["kind"].as_str()), (2, Some("conflict")), "{v}");
    assert!(v["error"]["message"].as_str().unwrap().contains("being stopped"), "{v}");
    assert_eq!(stopped["stopped"].as_u64(), Some(old_pid), "{stopped}");
    let status = env.ok(&["proxy", "status"]);
    assert_eq!((&status["running"], &status["restarting"]), (&false.into(), &false.into()), "{status}");
    wait_gone(old_pid);
}

/// `start` and `restart` refuse a --wait they couldn't keep before they start anything.
#[test]
fn proxy_start_refuses_a_wait_it_cannot_keep() {
    let env = Env::new("start-wait");
    for wait in ["inf", "NaN", "-1", "3601"] {
        let (code, v) = env.run(&["proxy", "start", "--listen", "127.0.0.1:0", &format!("--wait={wait}")]);
        assert_eq!((code, v["error"]["kind"].as_str()), (2, Some("invalid_input")), "{wait}: {v}");
        assert!(v["error"]["message"].as_str().unwrap().contains("--wait must be from 0 to 3600"), "{v}");
        assert_eq!(env.ok(&["proxy", "status"])["running"], false, "{wait}");
    }
    env.ok(&["proxy", "start", "--listen", "127.0.0.1:0", "--wait", "3600"]);
    let (code, v) = env.run(&["proxy", "restart", "--listen", "127.0.0.1:0", "--wait=60.5"]);
    assert_eq!((code, v["error"]["kind"].as_str()), (2, Some("invalid_input")), "{v}");
    assert!(v["error"]["message"].as_str().unwrap().contains("--wait must be from 0 to 60 seconds"), "{v}");
    env.ok(&["proxy", "restart", "--listen", "127.0.0.1:0", "--wait", "60"]);
}

/// A proxy that has taken a stop's request and is finishing (as on Windows, or from another
/// container, where it is never signalled) is still being stopped: a restart then leaves it to
/// that stop, and it ends up off. Here the proxy is paused as it has taken the request.
#[cfg(target_os = "linux")]
#[test]
fn proxy_restart_after_the_proxy_took_a_stop_leaves_it_off() {
    use brainproxy_core::proxy::STATE_KEY;
    let env = Env::new("restart-stop-taken");
    let old_pid = env.ok(&["proxy", "start", "--listen", "127.0.0.1:0"])["pid"].as_u64().unwrap();
    // Asked through the project file only, as from another container.
    pretend_other_namespace(&env.project, STATE_KEY);
    signal("-STOP", old_pid);
    let store = brainproxy_core::store::Store::open(&env.project).unwrap();
    let (stopped, (code, v)) = std::thread::scope(|s| {
        let stop = s.spawn(|| env.ok(&["proxy", "stop"]));
        wait_for("the stop to ask", || store.meta_get("proxy.stop").unwrap() == Some(old_pid.to_string()));
        // The proxy takes the request, as it does, and is on its way out once it resumes.
        store.meta_set("proxy.stop", None).unwrap();
        signal("-TERM", old_pid);
        let restart = s.spawn(|| env.run(&["proxy", "restart", "--listen", "127.0.0.1:0"]));
        wait_for("the restart to give up or hold the record", || {
            restart.is_finished() || proxy_record(&env).is_some_and(|r| r.contains("\"restart\""))
        });
        signal("-CONT", old_pid);
        (stop.join().unwrap(), restart.join().unwrap())
    });
    assert_eq!((code, v["error"]["kind"].as_str()), (2, Some("conflict")), "{v}");
    assert!(v["error"]["message"].as_str().unwrap().contains("being stopped"), "{v}");
    assert_eq!(stopped["stopped"].as_u64(), Some(old_pid), "{stopped}");
    let status = env.ok(&["proxy", "status"]);
    assert_eq!((&status["running"], &status["restarting"]), (&false.into(), &false.into()), "{status}");
    wait_gone(old_pid);
}

/// A proxy that took the record while a stop waited for the old one isn't passed off as stopped.
#[cfg(target_os = "linux")]
#[test]
fn proxy_stop_says_so_when_another_proxy_has_the_record_since() {
    use brainproxy_core::proxy::STATE_KEY;
    let env = Env::new("stop-replaced");
    let old_pid = env.ok(&["proxy", "start", "--listen", "127.0.0.1:0"])["pid"].as_u64().unwrap();
    signal("-STOP", old_pid);
    let mut other = Command::new("sleep").arg("30").spawn().unwrap();
    let store = brainproxy_core::store::Store::open(&env.project).unwrap();
    let (code, v) = std::thread::scope(|s| {
        let stop = s.spawn(|| env.run(&["proxy", "stop"]));
        wait_for("the stop to ask", || store.meta_get("proxy.stop").unwrap() == Some(old_pid.to_string()));
        let record = serde_json::json!({"pid": other.id(), "listen": "127.0.0.1:1", "started": "0", "ca_cert": "/x",
            "log": null});
        store.meta_set(STATE_KEY, Some(&record.to_string())).unwrap();
        signal("-CONT", old_pid);
        stop.join().unwrap()
    });
    assert_eq!((code, v["error"]["kind"].as_str()), (2, Some("conflict")), "{v}");
    let message = v["error"]["message"].as_str().unwrap();
    let expected = format!(
        "stopped the proxy (pid {old_pid}), but another one has started since, on 127.0.0.1:1 (pid {})",
        other.id()
    );
    assert!(message.contains(&expected), "{message}");
    wait_gone(old_pid);
    assert_eq!(env.ok(&["proxy", "status"])["proxy"]["pid"].as_u64(), Some(other.id().into()));
    other.kill().unwrap();
    other.wait().unwrap();
}

/// `proxy restart` with these arguments in the background, as an MCP call runs it, to be killed.
#[cfg(unix)]
fn restart_in_background(env: &Env, args: &[&str]) -> std::process::Child {
    Command::new(env!("CARGO_BIN_EXE_brainproxy"))
        .args(["--format", "json", "--project"])
        .arg(&env.project)
        .arg("--home")
        .arg(&env.home)
        .args(["proxy", "restart"])
        .args(args)
        .stdout(std::process::Stdio::null())
        .spawn()
        .unwrap()
}

/// A restart killed (by an MCP timeout or cancel, say) while it stops the old proxy, here paused
/// so that it doesn't exit until it is let go. The guard the restart started first finishes the
/// stop and starts the old proxy again where it was, with its options; the hold lasts meanwhile.
#[cfg(target_os = "linux")]
#[test]
fn a_restart_killed_while_stopping_the_proxy_starts_it_again() {
    let env = Env::new("restart-interrupted");
    let old = env.ok(&["proxy", "start", "--listen", "127.0.0.1:0", "--timeout", "12"]);
    let old_pid = old["pid"].as_u64().unwrap();
    signal("-STOP", old_pid);
    let store = brainproxy_core::store::Store::open(&env.project).unwrap();
    let mut restart = restart_in_background(&env, &["--listen", "127.0.0.1:0"]);
    wait_for("the restart to ask the old proxy to stop", || {
        store.meta_get("proxy.stop").unwrap() == Some(old_pid.to_string())
    });
    let hold: Value = serde_json::from_str(&proxy_record(&env).unwrap()).unwrap();
    assert!(hold["starting"].is_array(), "no guard recorded before the stop: {hold}");
    restart.kill().unwrap();
    restart.wait().unwrap();

    let (code, v) = env.run(&["proxy", "start", "--listen", "127.0.0.1:0"]);
    assert_eq!((code, v["error"]["kind"].as_str()), (2, Some("conflict")), "a start got in: {v}");
    assert!(v["error"]["message"].as_str().unwrap().contains("being restarted"), "{v}");
    let status = env.ok(&["proxy", "status"]);
    assert_eq!((&status["running"], &status["restarting"]), (&false.into(), &true.into()), "{status}");
    signal("-CONT", old_pid);
    wait_gone(old_pid);
    wait_for("the old proxy to be back", || env.ok(&["proxy", "status"])["running"] == true);
    let status = env.ok(&["proxy", "status"]);
    assert_eq!((&status["proxy"]["listen"], &status["restarting"]), (&old["listen"], &false.into()), "{status}");
    assert_ne!(status["proxy"]["pid"], old["pid"], "{status}");
    assert!(strs(&status["proxy"]["args"]).windows(2).any(|w| w == ["--timeout", "12"]), "{status}");
    let log = || std::fs::read_to_string(env.project.with_extension("proxy.log")).unwrap_or_default();
    let said = format!("\"data\":{{\"restarted\":{{\"pid\":{},", status["proxy"]["pid"]);
    wait_for("the guard to log what it did", || log().contains(&said));
}

/// A stop after a restart was killed while stopping the old proxy calls off the restart's guard:
/// the old proxy is stopped, and nothing starts it again.
#[cfg(target_os = "linux")]
#[test]
fn a_stop_calls_off_the_guard_of_a_killed_restart() {
    let env = Env::new("restart-guard-called-off");
    let old_pid = env.ok(&["proxy", "start", "--listen", "127.0.0.1:0"])["pid"].as_u64().unwrap();
    signal("-STOP", old_pid);
    let store = brainproxy_core::store::Store::open(&env.project).unwrap();
    let mut restart = restart_in_background(&env, &["--listen", "127.0.0.1:0"]);
    wait_for("the restart to ask the old proxy to stop", || {
        store.meta_get("proxy.stop").unwrap() == Some(old_pid.to_string())
    });
    restart.kill().unwrap();
    restart.wait().unwrap();

    let stopped = std::thread::scope(|s| {
        let stop = s.spawn(|| env.ok(&["proxy", "stop"]));
        wait_for("the stop to mark the record", || proxy_record(&env).is_some_and(|r| r.contains("\"stopping\":true")));
        signal("-CONT", old_pid);
        stop.join().unwrap()
    });
    assert_eq!(stopped["stopped"].as_u64(), Some(old_pid), "{stopped}");
    assert_eq!(stopped["restart_called_off"].as_u64(), Some(restart.id().into()), "{stopped}");
    wait_gone(old_pid);
    std::thread::sleep(Duration::from_secs(1));
    let status = env.ok(&["proxy", "status"]);
    assert_eq!((&status["running"], &status["restarting"]), (&false.into(), &false.into()), "{status}");
    assert_eq!(proxy_record(&env), None);
}

/// `project stop` stops a proxy that took the record while it stopped the last one, too, rather
/// than failing as `proxy stop` does. The other proxy is another project's, recorded here.
#[cfg(target_os = "linux")]
#[test]
fn project_stop_also_stops_a_proxy_started_meanwhile() {
    use brainproxy_core::proxy::STATE_KEY;
    let env = Env::new("project-stop-since");
    let other = Env::new("project-stop-since-other");
    let old_pid = env.ok(&["proxy", "start", "--listen", "127.0.0.1:0"])["pid"].as_u64().unwrap();
    let other_pid = other.ok(&["proxy", "start", "--listen", "127.0.0.1:0"])["pid"].as_u64().unwrap();
    let other_record = proxy_record(&other).unwrap();
    signal("-STOP", old_pid);
    let store = brainproxy_core::store::Store::open(&env.project).unwrap();
    let (code, v) = std::thread::scope(|s| {
        let stop = s.spawn(|| env.run(&["project", "stop"]));
        wait_for("the stop to ask", || store.meta_get("proxy.stop").unwrap() == Some(old_pid.to_string()));
        store.meta_set(STATE_KEY, Some(&other_record)).unwrap();
        signal("-CONT", old_pid);
        stop.join().unwrap()
    });
    assert_eq!(code, 0, "{v}");
    assert_eq!(v["data"]["proxy"].as_u64(), Some(old_pid), "{v}");
    wait_gone(old_pid);
    wait_gone(other_pid);
    assert_eq!(env.ok(&["proxy", "status"])["running"], false);
}

/// `proxy stop` during a restart calls it off: the proxy it was starting is killed, the one it
/// replaced stays off, and the restart's error says so in its data too. Not tied to a platform.
#[test]
fn proxy_stop_calls_off_a_restart() {
    let env = Env::new("restart-called-off");
    let (login, arrived, release) = held_login_server();
    env.ok(&["auth", "add", "slow", "--login-url", &login, "--login-body", "a=b", "--logged-in", "Welcome"]);
    let old_pid = env.ok(&["proxy", "start", "--listen", "127.0.0.1:0"])["pid"].as_u64().unwrap();
    let ((code, v), stopped) = std::thread::scope(|s| {
        let restart = s.spawn(|| env.run(&["proxy", "restart", "--listen", "127.0.0.1:0", "--auth", "slow"]));
        arrived.recv_timeout(Duration::from_secs(10)).expect("the new proxy logs in");
        // The restart holds the record, so a start is still turned away.
        let (code, v) = env.run(&["proxy", "start", "--listen", "127.0.0.1:0"]);
        assert_eq!((code, v["error"]["kind"].as_str()), (2, Some("conflict")), "a start got in: {v}");
        assert!(v["error"]["message"].as_str().unwrap().contains("being restarted"), "{v}");
        let stopped = env.ok(&["proxy", "stop"]);
        (restart.join().unwrap(), stopped)
    });
    let _ = release.send(true);
    assert_eq!((code, v["error"]["kind"].as_str()), (2, Some("conflict")), "{v}");
    let message = v["error"]["message"].as_str().unwrap();
    assert!(message.contains("called off by `brainproxy proxy stop`"), "{v}");
    let failure = message.strip_suffix("; the proxy is off").unwrap();
    assert_eq!(
        v["error"]["data"],
        serde_json::json!({"stopped": true, "failure": failure, "restarted": null, "called_off": true}),
        "{v}"
    );
    assert_eq!(stopped["stopped"].as_u64(), Some(old_pid), "{stopped}");
    assert!(stopped["restart_called_off"].is_u64(), "{stopped}");
    let status = env.ok(&["proxy", "status"]);
    assert_eq!((&status["running"], &status["restarting"]), (&false.into(), &false.into()), "{status}");
    assert_eq!(proxy_record(&env), None);
    env.ok(&["proxy", "start", "--listen", "127.0.0.1:0"]);
}

/// A restart killed while its new proxy starts (by an MCP timeout or cancel, say) still gets the
/// old proxy back: the new one fails to come up with nobody to go back for it, so it does that.
#[cfg(unix)]
#[test]
fn a_restart_killed_midway_still_goes_back() {
    let env = Env::new("restart-killed");
    let (login, arrived, release) = held_login_server();
    env.ok(&["auth", "add", "slow", "--login-url", &login, "--login-body", "a=b", "--logged-in", "Welcome"]);
    let old = env.ok(&["proxy", "start", "--listen", "127.0.0.1:0", "--timeout", "12"]);
    let mut restart = Command::new(env!("CARGO_BIN_EXE_brainproxy"))
        .args(["--format", "json", "--project"])
        .arg(&env.project)
        .arg("--home")
        .arg(&env.home)
        .args(["proxy", "restart", "--listen", "127.0.0.1:0", "--auth", "slow"])
        .stdout(std::process::Stdio::null())
        .spawn()
        .unwrap();
    arrived.recv_timeout(Duration::from_secs(10)).expect("the new proxy logs in");
    restart.kill().unwrap();
    restart.wait().unwrap();
    release.send(false).unwrap();

    wait_for("the old proxy to be back", || env.ok(&["proxy", "status"])["running"] == true);
    let status = env.ok(&["proxy", "status"]);
    assert_eq!(status["proxy"]["listen"], old["listen"], "{status}");
    assert_ne!(status["proxy"]["pid"], old["pid"], "{status}");
    assert!(strs(&status["proxy"]["args"]).windows(2).any(|w| w == ["--timeout", "12"]), "{status}");
    // The failed proxy logs why once it has started the old one again, so it may still be writing.
    let log = || std::fs::read_to_string(env.project.with_extension("proxy.log")).unwrap_or_default();
    wait_for("the failed proxy to log why", || {
        log().contains("the restart that started it had gone, so the proxy was started again on")
    });
}

/// A restart killed while its new proxy logs in (`--auth`) to a server that never answers: once
/// the restart's wait is over, that proxy gives up and goes back to the old one, rather than
/// holding off every start for as long as the login hangs.
#[cfg(unix)]
#[test]
fn a_restarted_proxy_stuck_logging_in_gives_up_once_the_restart_has_gone() {
    let env = Env::new("restart-stuck");
    let (login, arrived, release) = held_login_server();
    env.ok(&["auth", "add", "slow", "--login-url", &login, "--login-body", "a=b", "--logged-in", "Welcome"]);
    let old = env.ok(&["proxy", "start", "--listen", "127.0.0.1:0"]);
    let mut restart = restart_in_background(&env, &["--listen", "127.0.0.1:0", "--auth", "slow", "--wait", "2"]);
    arrived.recv_timeout(Duration::from_secs(10)).expect("the new proxy logs in");
    restart.kill().unwrap();
    restart.wait().unwrap();

    wait_for("the old proxy to be back", || env.ok(&["proxy", "status"])["running"] == true);
    let status = env.ok(&["proxy", "status"]);
    assert_eq!((&status["proxy"]["listen"], &status["restarting"]), (&old["listen"], &false.into()), "{status}");
    assert_ne!(status["proxy"]["pid"], old["pid"], "{status}");
    let log = || std::fs::read_to_string(env.project.with_extension("proxy.log")).unwrap_or_default();
    wait_for("the stuck proxy to log why", || {
        log().contains(
            "gave up: not up within the restart's wait (2 s); the restart that started it had gone, so the proxy was \
             started again on",
        )
    });
    drop(release);
}

/// `proxy stop --pid` stops the proxy only while it is that pid: what the app does on closing a
/// project, so that a proxy started since from a shell or an agent is left alone.
#[test]
fn proxy_stop_for_a_pid_stops_only_that_one() {
    let env = Env::new("stop-pid");
    let pid = env.ok(&["proxy", "start", "--listen", "127.0.0.1:0"])["pid"].as_u64().unwrap();
    let (code, v) = env.run(&["proxy", "stop", "--pid", &(pid + 1).to_string()]);
    assert_eq!((code, v["error"]["kind"].as_str()), (4, Some("not_found")), "{v}");
    assert_eq!(env.ok(&["proxy", "status"])["proxy"]["pid"].as_u64(), Some(pid));
    assert_eq!(env.ok(&["proxy", "stop", "--pid", &pid.to_string()])["stopped"].as_u64(), Some(pid));
    let (code, v) = env.run(&["proxy", "stop", "--pid", &pid.to_string()]);
    assert_eq!((code, v["error"]["kind"].as_str()), (4, Some("not_found")), "{v}");
    let (code, v) = env.run(&["proxy", "stop", "--pid", "1", "--forget"]);
    assert_eq!((code, v["error"]["kind"].as_str()), (2, Some("usage")), "{v}");
}

/// A stop after a restart was killed while its new proxy starts calls that proxy off too: the
/// stop stops it, and it doesn't go back to the old proxy afterwards, so the proxy stays off.
#[cfg(target_os = "linux")]
#[test]
fn a_stop_calls_off_the_proxy_a_killed_restart_was_starting() {
    let env = Env::new("restart-killed-stop");
    let (login, arrived, release) = held_login_server();
    env.ok(&["auth", "add", "slow", "--login-url", &login, "--login-body", "a=b", "--logged-in", "Welcome"]);
    let old_pid = env.ok(&["proxy", "start", "--listen", "127.0.0.1:0"])["pid"].as_u64().unwrap();
    let mut restart = Command::new(env!("CARGO_BIN_EXE_brainproxy"))
        .args(["--format", "json", "--project"])
        .arg(&env.project)
        .arg("--home")
        .arg(&env.home)
        .args(["proxy", "restart", "--listen", "127.0.0.1:0", "--auth", "slow"])
        .stdout(std::process::Stdio::null())
        .spawn()
        .unwrap();
    arrived.recv_timeout(Duration::from_secs(10)).expect("the new proxy logs in");
    restart.kill().unwrap();
    restart.wait().unwrap();
    // The hold names the proxy being started, and lasts as long as it does.
    let hold: Value = serde_json::from_str(&proxy_record(&env).unwrap()).unwrap();
    let starting = hold["starting"][0].as_u64().expect("the hold names the proxy it starts");
    assert_eq!(env.ok(&["proxy", "status"])["restarting"], true);

    let stopped = env.ok(&["proxy", "stop"]);
    assert_eq!(stopped["stopped"].as_u64(), Some(old_pid), "{stopped}");
    assert_eq!(stopped["restart_called_off"].as_u64(), Some(u64::from(restart.id())), "{stopped}");
    wait_gone(starting);
    let _ = release.send(false);
    std::thread::sleep(Duration::from_millis(500));
    let status = env.ok(&["proxy", "status"]);
    assert_eq!((&status["running"], &status["restarting"]), (&false.into(), &false.into()), "{status}");
}

/// `project stop` that fails on a job still running lists only what did stop as stopped.
#[cfg(unix)]
#[test]
fn project_stop_reports_only_the_work_that_stopped() {
    let env = Env::new("project-stop-work");
    let mut busy = Command::new("sleep").arg("60").spawn().unwrap();
    let store = brainproxy_core::store::Store::open(&env.project).unwrap();
    let running = store.job_create("scan", "running", &[]).unwrap();
    store.job_set_state(running, "running", Some(busy.id()), None, false).unwrap();
    let queued = store.job_create("scan", "queued", &[]).unwrap();

    let (code, v) = env.run(&["project", "stop"]);
    busy.kill().unwrap();
    busy.wait().unwrap();
    assert_eq!((code, v["error"]["kind"].as_str()), (2, Some("conflict")), "{v}");
    assert!(v["error"]["message"].as_str().unwrap().contains(&format!("job {running} (")), "{v}");
    assert_eq!(v["error"]["data"]["work"], serde_json::json!([{"kind": "job", "id": queued}]), "{v}");
}

#[test]
fn proxy_setup_is_saved_in_the_project_file() {
    let env = Env::new("setup");
    let defaults = |v: &Value| {
        assert_eq!(v["network"], "local", "{v}");
        assert_eq!(v["invisible"], false, "{v}");
        assert!(v["redirect"].is_null(), "{v}");
        assert_eq!(v["host"], "127.0.0.1", "{v}");
    };
    defaults(&env.ok(&["proxy", "setup", "show"]));

    // Saved as an origin; the redirect implies invisible mode.
    let saved = env.ok(&["proxy", "setup", "set", "--network=all", "--redirect=HTTPS://App.Example.Test:443/x?y"]);
    assert_eq!(saved["redirect"], "https://app.example.test", "{saved}");
    assert_eq!(saved["invisible"], true);
    assert_eq!(saved["host"], "0.0.0.0");
    assert_eq!(saved["start_options"], serde_json::json!(["--redirect=https://app.example.test"]));
    assert_eq!(env.ok(&["proxy", "setup", "show"]), saved);

    // It belongs to the file: a copy has it, a new project at another path doesn't.
    let copy = env.dir.join("copy.bpdb");
    std::fs::copy(&env.project, &copy).unwrap();
    let show = |project: &Path| {
        let out = Command::new(env!("CARGO_BIN_EXE_brainproxy"))
            .args(["--format", "json", "--project"])
            .arg(project)
            .args(["proxy", "setup", "show"])
            .output()
            .unwrap();
        serde_json::from_slice::<Value>(&out.stdout).unwrap()["data"].clone()
    };
    assert_eq!(show(&copy), saved);
    defaults(&show(&env.dir.join("fresh.bpdb")));

    // An agent can't open the proxy to the network, and a refused set changes nothing.
    let out = Command::new(env!("CARGO_BIN_EXE_brainproxy"))
        .args(["--format", "json", "--project"])
        .arg(&env.project)
        .args(["proxy", "setup", "set", "--network=all"])
        .env("BRAINPROXY_MCP_CALL", "1")
        .output()
        .unwrap();
    let v: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(out.status.code(), Some(2), "{v}");
    assert!(v["error"]["message"].as_str().unwrap().contains("isn't offered through MCP"), "{v}");
    // Nor plant a redirect or invisible mode that the app would start the person's proxy with.
    for args in [
        &["--redirect=http://127.0.0.1:8081"][..],
        &["--invisible"],
        &["--network=local", "--redirect=http://127.0.0.1:8081"],
    ] {
        let (code, v) = env.run_env(&[&["proxy", "setup", "set"][..], args].concat(), &[("BRAINPROXY_MCP_CALL", "1")]);
        assert_eq!((code, v["error"]["kind"].as_str()), (2, Some("invalid_input")), "{args:?}: {v}");
        assert!(v["error"]["message"].as_str().unwrap().contains("aren't offered through MCP"), "{v}");
    }
    assert_eq!(env.ok(&["proxy", "setup", "show"]), saved);
    // Going back to the defaults is fine: it only narrows what the proxy does.
    let (code, v) = env.run_env(&["proxy", "setup", "set", "--network=local"], &[("BRAINPROXY_MCP_CALL", "1")]);
    assert_eq!(code, 0, "{v}");
    defaults(&v["data"]);
    assert_eq!(env.ok(&["proxy", "setup", "set", "--network=all", "--redirect=https://app.example.test"]), saved);
    for bad in ["--redirect=ftp://app.example.test", "--redirect=http://127.0.0.1:0"] {
        let (code, v) = env.run(&["proxy", "setup", "set", bad]);
        assert_eq!(code, 2, "{bad}: {v}");
    }
    assert_eq!(env.ok(&["proxy", "setup", "show"]), saved);

    // Set replaces the whole setup.
    let invisible = env.ok(&["proxy", "setup", "set", "--invisible"]);
    assert_eq!((invisible["network"].as_str(), invisible["invisible"].as_bool()), (Some("local"), Some(true)));
    assert!(invisible["redirect"].is_null());
    defaults(&env.ok(&["proxy", "setup", "set"]));
    defaults(&env.ok(&["proxy", "setup", "show"]));
}

#[test]
fn stopping_the_proxy_records_requests_still_waiting() {
    use std::io::{Read, Write};
    let env = Env::new("drain");
    // Upstream: /slow is answered after a second, /never not at all.
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let (got, arrived) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let mut s = stream.unwrap();
            let got = got.clone();
            std::thread::spawn(move || {
                let mut buf = [0u8; 4096];
                let n = s.read(&mut buf).unwrap_or(0);
                let slow = String::from_utf8_lossy(&buf[..n]).starts_with("GET /slow");
                let _ = got.send(());
                if slow {
                    std::thread::sleep(Duration::from_secs(1));
                    let _ = s.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\nlate");
                }
                std::thread::sleep(Duration::from_secs(60));
            });
        }
    });
    let proxy = env.ok(&["proxy", "start", "--listen", "127.0.0.1:0"])["listen"].as_str().unwrap().to_string();
    let mut clients = Vec::new();
    for path in ["/slow", "/never"] {
        let mut c = std::net::TcpStream::connect(&proxy).unwrap();
        write!(c, "GET http://127.0.0.1:{port}{path} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n\r\n").unwrap();
        clients.push(c);
    }
    for _ in 0..2 {
        arrived.recv_timeout(Duration::from_secs(20)).expect("the proxy didn't forward the request");
    }
    let stopped = env.ok(&["proxy", "stop"]);
    assert_eq!(stopped["forced"], false, "{stopped}");
    let rows = env.ok(&["query", "SELECT path, status, error FROM history ORDER BY path"])["rows"].clone();
    assert_eq!(
        rows,
        serde_json::json!([["/never", null, "proxy stopped before the response arrived"], ["/slow", 200, null]])
    );
}
