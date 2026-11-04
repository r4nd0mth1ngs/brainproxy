//! Connection options end to end with the real binary: TLS pass-through, settings
//! picked up by a running proxy, the proxy's upstream side through an upstream
//! proxy, invisible proxying and redirect, and platform auth from an auth profile.

use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use brainproxy_core::http::WireReader;
use brainproxy_core::proxy::CertAuthority;
use serde_json::Value;
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpListener, TcpStream};

struct Env {
    dir: PathBuf,
    project: PathBuf,
    home: PathBuf,
}

impl Env {
    fn new(name: &str, engagement: &[&str]) -> Self {
        let dir = std::env::temp_dir().join(format!("bp-conn-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let env = Self { project: dir.join("p.bpdb"), home: dir.join("home"), dir };
        let mut args = vec!["engagement", "start", "--target", "127.0.0.1", "--target", "localhost"];
        args.extend_from_slice(engagement);
        env.ok(&args);
        env
    }

    fn run(&self, args: &[&str]) -> (i32, Value) {
        let out = Command::new(env!("CARGO_BIN_EXE_brainproxy"))
            .args(["--format", "json", "--project"])
            .arg(&self.project)
            .arg("--home")
            .arg(&self.home)
            .args(args)
            .env("BP_CONN_TEST_PW", "pw")
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

    fn rows(&self, sql: &str) -> Value {
        self.ok(&["query", sql])["rows"].clone()
    }
}

impl Drop for Env {
    fn drop(&mut self) {
        let _ = self.run(&["proxy", "stop"]);
    }
}

/// curl with extra arguments; returns (status, body).
fn curl(args: &[&str]) -> (u16, String) {
    let out = Command::new("curl")
        // With -x, NO_PROXY mustn't bypass it; without, no proxy from the environment either.
        .args(["-sS", "--noproxy", if args.contains(&"-x") { "" } else { "*" }, "--max-time", "20"])
        .args(if cfg!(windows) { &["--ssl-no-revoke"][..] } else { &[] })
        .args(args)
        .args(["-w", "\n%{http_code}"])
        .output()
        .expect("curl must be installed");
    if !out.stderr.is_empty() {
        eprintln!("curl {args:?}: {}", String::from_utf8_lossy(&out.stderr));
    }
    let text = String::from_utf8_lossy(&out.stdout).into_owned();
    let (body, code) = text.rsplit_once('\n').unwrap_or(("", "0"));
    (code.trim().parse().unwrap_or(0), body.to_string())
}

fn background<F: std::future::Future<Output = ()> + Send + 'static>(
    f: impl FnOnce(TcpListener) -> F + Send + 'static,
) -> u16 {
    let std_listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = std_listener.local_addr().unwrap().port();
    std_listener.set_nonblocking(true).unwrap();
    std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_multi_thread().enable_all().build().unwrap();
        rt.block_on(async move { f(TcpListener::from_std(std_listener).unwrap()).await });
    });
    port
}

/// Echo server (the request head as the body), with TLS from its own CA in `dir`.
fn spawn_echo(tls: bool, dir: &Path) -> u16 {
    let acceptor = tls.then(|| {
        let (ca, _) = CertAuthority::load_or_create(&dir.join("upstream-ca")).unwrap();
        tokio_rustls::TlsAcceptor::from(ca.server_config("localhost").unwrap())
    });
    background(move |listener| async move {
        while let Ok((tcp, _)) = listener.accept().await {
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
    })
}

async fn echo<S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin>(mut s: S) {
    let mut reader = WireReader::new();
    while let Ok(Some(req)) = reader.read_request(&mut s).await {
        let head = brainproxy_core::http::request::split_head_body(&req).0.to_vec();
        let out = format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n", head.len());
        if s.write_all(out.as_bytes()).await.is_err() || s.write_all(&head).await.is_err() {
            return;
        }
    }
}

/// An HTTP CONNECT proxy that records what it was asked to connect to.
fn spawn_connect_proxy() -> (u16, Arc<Mutex<Vec<String>>>) {
    let seen: Arc<Mutex<Vec<String>>> = Arc::default();
    let log = seen.clone();
    let port = background(move |listener| async move {
        while let Ok((mut s, _)) = listener.accept().await {
            let log = log.clone();
            tokio::spawn(async move {
                let Ok(Some(req)) = WireReader::new().read_request(&mut s).await else { return };
                let line = String::from_utf8_lossy(&req).lines().next().unwrap_or_default().to_string();
                let authority = line.split_whitespace().nth(1).unwrap_or_default().to_string();
                log.lock().unwrap().push(authority.clone());
                let Ok(mut up) = TcpStream::connect(authority.as_str()).await else { return };
                let _ = s.write_all(b"HTTP/1.1 200 Connection established\r\n\r\n").await;
                let _ = tokio::io::copy_bidirectional(&mut s, &mut up).await;
            });
        }
    });
    (port, seen)
}

fn wait_for_settings() {
    // The proxy reloads settings every 300 ms.
    std::thread::sleep(Duration::from_millis(800));
}

#[test]
fn passthrough_and_upstream_proxy_apply_to_a_running_proxy() {
    let env = Env::new("passthrough", &[]);
    let https = spawn_echo(true, &env.dir);
    let http = spawn_echo(false, &env.dir);
    let upstream_ca = env.dir.join("upstream-ca/ca.pem");
    let started = env.ok(&["proxy", "start", "--listen", "127.0.0.1:0"]);
    let proxy = started["usage"]["proxy_url"].as_str().unwrap().to_string();
    let url = format!("https://localhost:{https}/secret");

    // Intercepted: the client sees brainproxy's certificate, not the server's.
    assert_eq!(curl(&["-x", &proxy, "--cacert", upstream_ca.to_str().unwrap(), &url]).0, 0);
    // Pass-through, added while the proxy runs: the server's own certificate comes through.
    env.ok(&["connection", "passthrough", "add", "localhost"]);
    wait_for_settings();
    let (status, body) = curl(&["-x", &proxy, "--cacert", upstream_ca.to_str().unwrap(), &url]);
    assert_eq!(status, 200);
    assert!(body.starts_with("GET /secret HTTP/1.1"), "{body}");
    std::thread::sleep(Duration::from_millis(300));
    // Recorded as a connection only: nothing decrypted, no request path.
    let rows = env.rows("SELECT method, host, port, status, error, url FROM history WHERE method = 'CONNECT'");
    assert_eq!(rows.as_array().unwrap().len(), 1, "{rows}");
    assert_eq!(rows[0][1], "localhost");
    assert!(rows[0][3].is_null() && rows[0][4].as_str().unwrap().starts_with("TLS pass-through, not decrypted: "));
    assert_eq!(rows[0][5], format!("https://localhost:{https}"), "{rows}");
    assert_eq!(env.rows("SELECT count(*) FROM history WHERE path = '/secret'")[0][0], 0);
    // Every proxy entry names the client it came from.
    let clients = env.rows("SELECT count(*) FROM history WHERE source = 'proxy' AND client_addr LIKE '127.0.0.1:%'");
    assert_eq!(clients[0][0], env.rows("SELECT count(*) FROM history WHERE source = 'proxy'")[0][0]);
    // Still scope-checked: out-of-engagement hosts aren't tunnelled.
    env.ok(&["connection", "passthrough", "add", "*"]);
    wait_for_settings();
    assert_ne!(curl(&["-x", &proxy, "-k", "https://10.255.255.1/"]).0, 200);

    // The proxy's upstream side through an upstream proxy, also picked up while running.
    let (up, seen) = spawn_connect_proxy();
    env.ok(&["connection", "passthrough", "clear"]);
    env.ok(&["connection", "upstream", "add", "--host", "*", "--proxy", &format!("http://127.0.0.1:{up}")]);
    wait_for_settings();
    let (status, body) = curl(&["-x", &proxy, &format!("http://localhost:{http}/via")]);
    assert_eq!(status, 200, "{body}");
    assert!(body.contains(&format!("Host: localhost:{http}")), "{body}");
    // Asked for the checked address, not the name.
    let asked = seen.lock().unwrap().clone();
    assert!(asked.iter().all(|a| a.ends_with(&format!(":{http}")) && !a.starts_with("localhost")), "{asked:?}");
    assert!(!asked.is_empty());
    let route = env.ok(&["connection", "route", &format!("http://localhost:{http}/")]);
    assert_eq!(route["proxy"]["allowed"], true, "{route}");
}

#[test]
fn upstream_proxies_off_this_machine_need_the_engagement_to_list_them() {
    let env = Env::new("proxy-allow", &[]);
    let saved = env.ok(&["connection", "upstream", "add", "--host", "*", "--proxy", "http://192.0.2.7:3128"]);
    assert!(saved["warnings"][0].as_str().unwrap().contains("engagement start --proxy"), "{saved}");
    let (code, v) = env.run(&["send", "--url", "http://127.0.0.1:9/"]);
    assert_eq!((code, v["error"]["kind"].as_str()), (6, Some("out_of_scope")), "{v}");
    let listed = Env::new("proxy-listed", &["--proxy", "192.0.2.7:3128"]);
    let saved = listed.ok(&["connection", "upstream", "add", "--host", "*", "--proxy", "http://192.0.2.7:3128"]);
    assert_eq!(saved["warnings"].as_array().unwrap().len(), 0, "{saved}");
    assert_eq!(listed.ok(&["engagement", "show"])["engagement_proxies"][0], "192.0.2.7:3128");
    // The password is never stored, only the variable's name.
    let saved = listed.ok(&[
        "connection",
        "upstream",
        "add",
        "--host",
        "*.corp.test",
        "--proxy",
        "socks5://127.0.0.1:1080",
        "--username",
        "u",
        "--password-env",
        "BP_CONN_TEST_PW",
        "--first",
    ]);
    assert_eq!(saved["upstream"][0]["password_env"], "BP_CONN_TEST_PW");
    let (code, _) = listed.run(&["connection", "upstream", "add", "--host", "x", "--proxy", "socks5h://127.0.0.1:1"]);
    assert_eq!(code, 2);
}

#[test]
fn host_overrides_to_internal_addresses_need_the_scope_to_list_them() {
    let env =
        Env::new("override", &["--target", "app.corp.test", "--target", "listed.corp.test", "--target", "10.9.9.9"]);
    env.ok(&["connection", "hosts", "add", "app.corp.test", "10.0.0.7"]);
    let (code, v) = env.run(&["send", "--url", "http://app.corp.test/"]);
    assert_eq!((code, v["error"]["kind"].as_str()), (6, Some("out_of_scope")), "{v}");
    let route = env.ok(&["connection", "route", "http://app.corp.test/"]);
    assert_eq!(route["allowed"], false, "{route}");
    assert!(route["reason"].as_str().unwrap().contains("host override"), "{route}");
    env.ok(&["connection", "hosts", "add", "listed.corp.test", "10.9.9.9"]);
    let route = env.ok(&["connection", "route", "http://listed.corp.test/"]);
    assert_eq!((&route["allowed"], &route["addresses"][0]), (&Value::Bool(true), &Value::from("10.9.9.9")), "{route}");
}

#[test]
fn invisible_proxy_routes_by_host_and_redirects() {
    let env = Env::new("invisible", &[]);
    let http = spawn_echo(false, &env.dir);
    let https = spawn_echo(true, &env.dir);
    // Routed by the Host header: the client talks to the listener as if it were the server.
    let listen =
        env.ok(&["proxy", "start", "--listen", "127.0.0.1:0", "--invisible"])["listen"].as_str().unwrap().to_string();
    let (status, body) = curl(&["-H", &format!("Host: 127.0.0.1:{http}"), &format!("http://{listen}/hidden")]);
    assert_eq!(status, 200);
    assert!(body.starts_with("GET /hidden HTTP/1.1"), "{body}");
    // Ordinary proxy requests still work on the same listener.
    assert_eq!(curl(&["-x", &format!("http://{listen}"), &format!("http://127.0.0.1:{http}/normal")]).0, 200);
    env.ok(&["proxy", "stop"]);

    // A redirect sends TLS clients (decrypted with brainproxy's CA, by SNI) to one origin.
    let listen =
        env.ok(&["proxy", "start", "--listen", "127.0.0.1:0", "--redirect", &format!("https://localhost:{https}")])
            ["listen"]
            .as_str()
            .unwrap()
            .to_string();
    let port = listen.rsplit(':').next().unwrap();
    let (status, body) = curl(&[
        "--cacert",
        env.ca().to_str().unwrap(),
        "--resolve",
        &format!("localhost:{port}:127.0.0.1"),
        &format!("https://localhost:{port}/redirected"),
    ]);
    assert_eq!(status, 200, "{body}");
    assert!(body.starts_with("GET /redirected HTTP/1.1"), "{body}");
    std::thread::sleep(Duration::from_millis(300));
    let rows = env.rows("SELECT port FROM history WHERE path = '/redirected'");
    assert_eq!(rows[0][0], https, "{rows}");
    let rows = env.rows("SELECT count(*) FROM history WHERE source = 'proxy' AND client_addr IS NULL");
    assert_eq!(rows[0][0], 0, "every invisible-proxy entry names its client");
}

#[test]
fn platform_auth_from_an_auth_profile_on_every_command() {
    let env = Env::new("platform", &[]);
    let port = background(|listener| async move {
        while let Ok((mut s, _)) = listener.accept().await {
            tokio::spawn(async move {
                let mut reader = WireReader::new();
                let ok = "Basic YWxpY2U6cHc="; // alice:pw
                while let Ok(Some(req)) = reader.read_request(&mut s).await {
                    let authed = String::from_utf8_lossy(&req).contains(&format!("Authorization: {ok}\r\n"));
                    let out: &[u8] = if authed {
                        b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nin"
                    } else {
                        b"HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: Basic realm=\"lab\"\r\nContent-Length: 0\r\n\r\n"
                    };
                    if s.write_all(out).await.is_err() {
                        return;
                    }
                }
            });
        }
    });
    let url = format!("http://127.0.0.1:{port}/");
    assert_eq!(env.ok(&["send", "--url", &url])["response"]["status"], 401);
    env.ok(&[
        "auth",
        "add",
        "corp",
        "--platform",
        "basic",
        "--platform-host",
        "127.0.0.1",
        "--username",
        "alice",
        "--password-env",
        "BP_CONN_TEST_PW",
    ]);
    // No --auth: platform credentials answer the challenge on any command.
    let sent = env.ok(&["send", "--url", &url]);
    assert_eq!(sent["response"]["status"], 200, "{sent}");
    let rows = env.rows("SELECT count(*) FROM history WHERE request LIKE '%Authorization%'");
    assert_eq!(rows[0][0], 0, "the credentials never reach history");
    let route = env.ok(&["connection", "route", &url]);
    assert_eq!(
        (route["platform_auth"]["profile"].as_str(), route["platform_auth"]["scheme"].as_str()),
        (Some("corp"), Some("basic"))
    );
    // Through the proxy too.
    let proxy =
        env.ok(&["proxy", "start", "--listen", "127.0.0.1:0"])["usage"]["proxy_url"].as_str().unwrap().to_string();
    assert_eq!(curl(&["-x", &proxy, &url]), (200, "in".into()));
    let (code, v) = env.run(&["auth", "add", "bad", "--platform", "basic", "--platform-host", "*"]);
    assert_eq!(code, 2, "platform auth needs a username: {v}");
    let (code, v) = env.run(&["auth", "add", "bad", "--platform", "basic", "--platform-host", "*", "--username", "u"]);
    assert_eq!(code, 2, "platform auth needs a password: {v}");
    let (code, _) = env.run(&["auth", "add", "bad", "--platform", "ntlm", "--username", "u"]);
    assert_eq!(code, 2, "--platform needs --platform-host");
}
