//! Server-sent events end to end: clients through the real proxy to in-process event stream
//! servers that send an event and then wait, so a client that has the event got it while the
//! stream was open. Recording, `sse` commands, and `send` reading a stream for a bounded time.

use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use brainproxy_core::http::WireReader;
use brainproxy_core::proxy::CertAuthority;
use serde_json::Value;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Semaphore;

struct Env {
    dir: PathBuf,
    project: PathBuf,
    home: PathBuf,
}

impl Env {
    fn new(name: &str) -> Self {
        let dir = std::env::temp_dir().join(format!("bp-sse-{}-{name}", std::process::id()));
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

    fn start_proxy(&self) -> Value {
        self.ok(&["proxy", "start", "--listen", "127.0.0.1:0"])
    }

    /// Polls `sse list` until its newest stream passes `ready` (the recorder writes in the background).
    fn stream(&self, what: &str, ready: impl Fn(&Value) -> bool) -> Value {
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            let list = self.ok(&["sse", "list"]);
            if let Some(s) = list["items"].as_array().and_then(|a| a.last()).filter(|s| ready(s)) {
                return s.clone();
            }
            assert!(Instant::now() < deadline, "no stream {what}: {list}");
            std::thread::sleep(Duration::from_millis(50));
        }
    }

    fn closed_stream(&self) -> Value {
        self.stream("closed", |s| s["state"] == "closed")
    }
}

impl Drop for Env {
    fn drop(&mut self) {
        let _ = self.run(&["proxy", "stop"]);
    }
}

/// What an event stream server speaks.
#[derive(Clone, Copy, PartialEq)]
enum Mode {
    /// HTTP/1.1, no TLS.
    Plain,
    /// HTTP/1.1 over TLS (a client that offers HTTP/2 gets HTTP/1.1).
    TlsH1,
    /// HTTP/2 over TLS.
    TlsH2,
}

/// An event stream server and the test's hold on it.
struct Sse {
    port: u16,
    /// A permit lets a gated stream take its next step.
    gate: Arc<Semaphore>,
    /// A write to a client failed: the connection is gone.
    client_gone: Arc<AtomicBool>,
}

const FIRST: &str = "retry: 2000\n\nid: 1\nevent: greeting\ndata: hello\n\n";
const SECOND: &str = "data: second secret_value\ndata: line two\n\n";

/// Serves event streams. `/events` sends [`FIRST`], waits for a permit, sends [`SECOND`], waits
/// for another, and ends the response. `/forever` sends an event every 20 ms until its client
/// is gone. `/gzip` is `/events` compressed, each step flushed. `/plain` isn't a stream.
fn spawn_sse(dir: &Path, mode: Mode) -> Sse {
    let acceptor = (mode != Mode::Plain).then(|| {
        let (ca, _) = CertAuthority::load_or_create(&dir.join("upstream-ca")).unwrap();
        let mut cfg = (*ca.server_config("localhost").unwrap()).clone();
        cfg.alpn_protocols =
            if mode == Mode::TlsH2 { vec![b"h2".to_vec(), b"http/1.1".to_vec()] } else { vec![b"http/1.1".to_vec()] };
        tokio_rustls::TlsAcceptor::from(Arc::new(cfg))
    });
    let std_listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = std_listener.local_addr().unwrap().port();
    std_listener.set_nonblocking(true).unwrap();
    let sse = Sse { port, gate: Arc::new(Semaphore::new(0)), client_gone: Arc::default() };
    let (gate, gone) = (sse.gate.clone(), sse.client_gone.clone());
    std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_multi_thread().enable_all().build().unwrap();
        rt.block_on(async move {
            let listener = TcpListener::from_std(std_listener).unwrap();
            while let Ok((tcp, _)) = listener.accept().await {
                let (acceptor, gate, gone) = (acceptor.clone(), gate.clone(), gone.clone());
                tokio::spawn(async move {
                    match acceptor {
                        None => serve_h1(tcp, gate, gone).await,
                        Some(a) => {
                            let Ok(tls) = a.accept(tcp).await else { return };
                            if mode == Mode::TlsH2 {
                                serve_h2(tls, gate).await
                            } else {
                                serve_h1(tls, gate, gone).await
                            }
                        }
                    }
                });
            }
        });
    });
    sse
}

fn chunk(data: &[u8]) -> Vec<u8> {
    [format!("{:x}\r\n", data.len()).as_bytes(), data, b"\r\n"].concat()
}

/// Waits for a permit to go on with a gated stream; false if its client closed first (it has
/// nothing more to send, so anything read is the end).
async fn permit<S: AsyncRead + Unpin>(s: &mut S, gate: &Semaphore) -> bool {
    let mut byte = [0u8; 1];
    tokio::select! {
        permit = gate.acquire() => {
            permit.unwrap().forget();
            true
        }
        _ = s.read(&mut byte) => false,
    }
}

async fn serve_h1<S: AsyncRead + AsyncWrite + Unpin>(mut s: S, gate: Arc<Semaphore>, gone: Arc<AtomicBool>) {
    let mut reader = WireReader::new();
    while let Ok(Some(req)) = reader.read_request(&mut s).await {
        let line = String::from_utf8_lossy(&req).lines().next().unwrap_or_default().to_string();
        let path = line.split(' ').nth(1).unwrap_or("/").to_string();
        let head = |extra: &str| {
            format!(
                "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nCache-Control: no-cache\r\n\
                 Transfer-Encoding: chunked\r\n{extra}\r\n"
            )
        };
        match path.as_str() {
            "/events" => {
                let steps = [FIRST, SECOND];
                let _ = s.write_all(head("").as_bytes()).await;
                for step in steps {
                    if s.write_all(&chunk(step.as_bytes())).await.is_err() || s.flush().await.is_err() {
                        return;
                    }
                    if !permit(&mut s, &gate).await {
                        return;
                    }
                }
                let _ = s.write_all(b"0\r\n\r\n").await;
            }
            "/gzip" => {
                use std::io::Write;
                let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
                let _ = s.write_all(head("Content-Encoding: gzip\r\n").as_bytes()).await;
                for step in [FIRST, SECOND] {
                    gz.write_all(step.as_bytes()).unwrap();
                    gz.flush().unwrap();
                    let out = std::mem::take(gz.get_mut());
                    if s.write_all(&chunk(&out)).await.is_err() || s.flush().await.is_err() {
                        return;
                    }
                    if !permit(&mut s, &gate).await {
                        return;
                    }
                }
                let _ = s.write_all(&chunk(&gz.finish().unwrap())).await;
                let _ = s.write_all(b"0\r\n\r\n").await;
            }
            "/flood" => {
                // More events than a stream may store, at once; then the stream stays open.
                let _ = s.write_all(head("").as_bytes()).await;
                let events = "data: x\n\n".repeat(brainproxy_core::sse::MAX_STREAM_EVENTS + 50);
                if s.write_all(&chunk(events.as_bytes())).await.is_err() || s.flush().await.is_err() {
                    return;
                }
                if !permit(&mut s, &gate).await {
                    return;
                }
            }
            "/forever" => {
                let _ = s.write_all(head("").as_bytes()).await;
                for n in 0.. {
                    let event = format!("id: {n}\ndata: tick {n}\n\n");
                    if s.write_all(&chunk(event.as_bytes())).await.is_err() || s.flush().await.is_err() {
                        gone.store(true, Ordering::Relaxed);
                        return;
                    }
                    tokio::time::sleep(Duration::from_millis(20)).await;
                }
            }
            _ => {
                let _ =
                    s.write_all(b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 5\r\n\r\nplain").await;
            }
        }
    }
}

async fn serve_h2<S: AsyncRead + AsyncWrite + Unpin + Send + 'static>(s: S, gate: Arc<Semaphore>) {
    let Ok(mut conn) = h2::server::handshake(s).await else { return };
    while let Some(Ok((_req, mut respond))) = conn.accept().await {
        let gate = gate.clone();
        tokio::spawn(async move {
            let resp = http::Response::builder().header("content-type", "text/event-stream").body(()).unwrap();
            let Ok(mut send) = respond.send_response(resp, false) else { return };
            for step in [FIRST, SECOND] {
                if send.send_data(bytes::Bytes::from_static(step.as_bytes()), false).is_err() {
                    return;
                }
                gate.acquire().await.unwrap().forget();
            }
            let _ = send.send_data(bytes::Bytes::new(), true);
        });
    }
}

/// Reads from `s` until what has been read contains `want`, or panics after five seconds.
async fn read_until<S: AsyncRead + Unpin>(s: &mut S, got: &mut Vec<u8>, want: &str) {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    while !String::from_utf8_lossy(got).contains(want) {
        let mut buf = [0u8; 4096];
        match tokio::time::timeout_at(deadline, s.read(&mut buf)).await {
            Ok(Ok(n)) if n > 0 => got.extend_from_slice(&buf[..n]),
            other => panic!("waiting for {want:?}: {other:?}; got {:?}", String::from_utf8_lossy(got)),
        }
    }
}

/// Opens `url` through the proxy as a plain HTTP client would.
async fn open(proxy: &str, url: &str) -> TcpStream {
    let mut s = TcpStream::connect(proxy).await.unwrap();
    let host = url.trim_start_matches("http://").split('/').next().unwrap();
    let req = format!("GET {url} HTTP/1.1\r\nHost: {host}\r\nAccept: text/event-stream\r\n\r\n");
    s.write_all(req.as_bytes()).await.unwrap();
    s
}

fn data(event: &Value) -> &str {
    event["data"]["content"].as_str().unwrap_or("(none)")
}

#[test]
fn an_event_stream_reaches_the_client_as_it_is_sent_and_is_recorded() {
    let env = Env::new("relay");
    let sse = spawn_sse(&env.dir, Mode::Plain);
    let proxy = env.start_proxy()["listen"].as_str().unwrap().to_string();
    let url = format!("http://127.0.0.1:{}/events", sse.port);
    // Rules and intercept that need a whole response mustn't hold the stream back.
    env.ok(&["rules", "add", "--location", "response-header", "--replace", "X-Rule: applied"]);
    env.ok(&["rules", "add", "--location", "response-body", "--match", "hello", "--replace", "rewritten"]);
    env.ok(&["intercept", "enable", "--responses"]);
    std::thread::sleep(Duration::from_millis(700));

    let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
    let (mut client, mut got) = rt.block_on(async {
        let mut client = open(&proxy, &url).await;
        let mut got = Vec::new();
        // The server sent this much and is waiting: the client has it while the stream is open.
        read_until(&mut client, &mut got, "data: hello\n\n").await;
        (client, got)
    });
    let text = String::from_utf8_lossy(&got).into_owned();
    assert!(text.starts_with("HTTP/1.1 200 OK\r\n"), "{text}");
    // The header rule applied to the head; the body rule and the intercept left the stream alone.
    assert!(text.contains("\r\nX-Rule: applied\r\n") && !text.contains("rewritten"), "{text}");
    assert!(!text.contains("second"), "{text}");

    // Its row and the events so far are in the project while it is open.
    let open_stream = env.stream("open with two events", |s| s["events"] == 2);
    assert_eq!((&open_stream["state"], &open_stream["source"]), (&Value::from("open"), &Value::from("proxy")));
    assert_eq!(open_stream["url"], url);
    let id = open_stream["id"].as_i64().unwrap().to_string();
    let history = open_stream["history_id"].as_i64().unwrap().to_string();
    let row = env.ok(&["history", "show", &history]);
    assert_eq!((&row["response"]["status"], &row["response"]["body"]["length"]), (&Value::from(200), &Value::from(0)));
    assert_eq!(row["stream"]["id"], open_stream["id"]);
    let events = env.ok(&["sse", "events", &id]);
    assert_eq!((&events["state"], &events["count"]), (&Value::from("open"), &Value::from(2)));
    let items = events["items"].as_array().unwrap();
    assert_eq!(
        (&items[0]["event"], &items[0]["retry"], &items[0]["data"]),
        (&Value::from("message"), &Value::from(2000), &Value::Null)
    );
    assert_eq!(
        (&items[1]["event"], &items[1]["event_id"], data(&items[1])),
        (&Value::from("greeting"), &Value::from("1"), "hello")
    );
    assert!(items[1]["time"].as_str().is_some_and(|t| t.ends_with('Z')));

    // The next event, then the end of the response.
    rt.block_on(async {
        sse.gate.add_permits(1);
        read_until(&mut client, &mut got, "data: line two\n\n").await;
        sse.gate.add_permits(1);
        read_until(&mut client, &mut got, "0\r\n\r\n").await;
        // The connection ends with the stream.
        let mut rest = Vec::new();
        let n = tokio::time::timeout(Duration::from_secs(5), client.read_to_end(&mut rest)).await;
        assert!(matches!(n, Ok(Ok(0))), "{n:?}");
    });

    let closed = env.closed_stream();
    assert_eq!(
        (&closed["ended"], &closed["events"], &closed["truncated"]),
        (&Value::from("server"), &Value::from(3), &Value::from(false)),
        "{}",
        env.ok(&["sse", "events", &id])
    );
    assert_eq!(closed["error"], Value::Null);
    // The history row has the body now, as the server sent it.
    let row = env.ok(&["history", "show", &history]);
    assert_eq!(row["response"]["body"]["content"], format!("{FIRST}{SECOND}"));
    assert!(row["entry"]["duration_ms"].as_i64().is_some());

    // Listing, filters, one event, and full-text search.
    let found = env.ok(&["sse", "events", &id, "--contains", "secret_value"]);
    assert_eq!((&found["count"], data(&found["items"][0])), (&Value::from(1), "second secret_value\nline two"));
    let event_id = found["items"][0]["id"].as_i64().unwrap();
    assert_eq!(env.ok(&["sse", "events", &id, "--event", "greeting"])["count"], 1);
    assert_eq!(env.ok(&["sse", "events", &id, "--after", &(event_id - 1).to_string()])["count"], 1);
    let one = env.ok(&["sse", "event", &event_id.to_string(), "--max-body", "6"]);
    assert_eq!(
        (&one["stream_id"], data(&one), &one["data"]["truncated"]),
        (&closed["id"], "second", &Value::from(true))
    );
    let shown = env.ok(&["sse", "show", &id]);
    assert_eq!(
        (&shown["exchange"]["response"]["status"], &shown["exchange"]["id"]),
        (&Value::from(200), &closed["history_id"])
    );
    assert_eq!(
        shown["event_counts"],
        serde_json::json!([{"event": "greeting", "count": 1}, {"event": "message", "count": 2}])
    );
    let fts = env.ok(&[
        "query",
        "SELECT s.url FROM sse_events e JOIN sse_streams s ON s.id = e.stream_id \
         WHERE e.id IN (SELECT rowid FROM sse_events_fts WHERE sse_events_fts MATCH 'secret_value')",
    ]);
    assert_eq!(fts["rows"], serde_json::json!([[url]]));
    // What the target sent is marked as such, for an agent reading it through MCP.
    let (_, envelope) = env.run(&["sse", "events", &id]);
    assert_eq!(envelope["_meta"]["provenance"]["untrusted_content"], true);
    let (code, missing) = env.run(&["sse", "events", "99"]);
    assert_eq!((code, &missing["error"]["kind"]), (4, &Value::from("not_found")));
    // Nothing was held for the response intercept.
    assert_eq!(env.ok(&["intercept", "list"])["count"], 0);
}

#[test]
fn a_stream_ends_when_its_client_goes_away_or_the_proxy_stops() {
    let env = Env::new("ends");
    let sse = spawn_sse(&env.dir, Mode::Plain);
    let proxy = env.start_proxy()["listen"].as_str().unwrap().to_string();
    let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();

    // The client closes: the proxy closes its connection to the server too.
    rt.block_on(async {
        let mut client = open(&proxy, &format!("http://127.0.0.1:{}/forever", sse.port)).await;
        read_until(&mut client, &mut Vec::new(), "data: tick 2\n\n").await;
    });
    let closed = env.closed_stream();
    assert_eq!(closed["ended"], "client");
    assert!(closed["events"].as_i64().unwrap() >= 3, "{closed}");
    let deadline = Instant::now() + Duration::from_secs(5);
    while !sse.client_gone.load(Ordering::Relaxed) {
        assert!(Instant::now() < deadline, "the server's connection stayed open");
        std::thread::sleep(Duration::from_millis(20));
    }
    // What passed before is in its history row, which reads as a response.
    let row = env.ok(&["history", "show", &closed["history_id"].to_string()]);
    assert!(row["response"]["body"]["content"].as_str().unwrap().starts_with("id: 0\ndata: tick 0\n\n"), "{row}");

    // A stream that goes over what one may store says so while it is still open.
    let flood = rt.block_on(async {
        let mut client = open(&proxy, &format!("http://127.0.0.1:{}/flood", sse.port)).await;
        read_until(&mut client, &mut Vec::new(), "data: x\n\n").await;
        client
    });
    let cut = env.stream("open and truncated", |s| s["state"] == "open" && s["truncated"] == true);
    assert!(cut["url"].as_str().unwrap().ends_with("/flood"), "{cut}");
    assert!(cut["error"].as_str().unwrap().contains("10000 events"), "{cut}");
    let cut = env.stream("with every event it may store", |s| s["events"] == 10000);
    assert_eq!(env.ok(&["sse", "events", &cut["id"].to_string(), "--limit", "1"])["truncated"], true);
    drop(flood);
    let cut = env.stream("closed", |s| s["id"] == cut["id"] && s["state"] == "closed");
    assert_eq!(
        (&cut["truncated"], &cut["ended"], &cut["events"]),
        (&Value::from(true), &Value::from("client"), &Value::from(10000))
    );

    // A compressed stream is relayed as it is and its events are read all the same.
    let mut client = rt.block_on(async {
        let mut client = open(&proxy, &format!("http://127.0.0.1:{}/gzip", sse.port)).await;
        read_until(&mut client, &mut Vec::new(), "Content-Encoding: gzip\r\n").await;
        client
    });
    let gz = env.stream("open with two events", |s| s["state"] == "open" && s["events"] == 2);
    let events = env.ok(&["sse", "events", &gz["id"].to_string()]);
    assert_eq!(data(&events["items"][1]), "hello");

    // The proxy stops with the stream open: its row gets what was stored, and says so.
    env.ok(&["proxy", "stop"]);
    let stopped = env.closed_stream();
    assert_eq!((&stopped["id"], &stopped["ended"]), (&gz["id"], &Value::from("stopped")));
    assert!(stopped["error"].as_str().unwrap().contains("still open when the proxy stopped"), "{stopped}");
    let row = env.ok(&["history", "show", &stopped["history_id"].to_string()]);
    assert_eq!(row["response"]["body"]["content"], FIRST);
    drop(rt.block_on(async { client.shutdown().await }));
}

/// curl reading `url` through the proxy without buffering, its output a line at a time.
fn curl_lines(proxy: &str, ca: &Path, url: &str) -> (std::process::Child, std::sync::mpsc::Receiver<String>) {
    let mut child = Command::new("curl")
        .args(["-sS", "-N", "--http2", "--noproxy", "", "--max-time", "30", "-x", proxy, "--cacert"])
        .arg(ca)
        .args(if cfg!(windows) { &["--ssl-no-revoke"][..] } else { &[] })
        .args(["-w", "\nversion %{http_version}\n", url])
        .stdout(Stdio::piped())
        .spawn()
        .expect("curl must be installed");
    let out = child.stdout.take().unwrap();
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        for line in BufReader::new(out).lines().map_while(Result::ok) {
            if tx.send(line).is_err() {
                return;
            }
        }
    });
    (child, rx)
}

/// Lines from curl up to and including `want`.
fn lines_until(rx: &std::sync::mpsc::Receiver<String>, want: &str) -> Vec<String> {
    let mut lines = Vec::new();
    loop {
        match rx.recv_timeout(Duration::from_secs(10)) {
            Ok(line) => {
                let done = line == want;
                lines.push(line);
                if done {
                    return lines;
                }
            }
            Err(e) => panic!("waiting for {want:?}: {e}; got {lines:?}"),
        }
    }
}

#[test]
fn an_http2_client_gets_an_event_stream_as_it_is_sent() {
    let curl = Command::new("curl").arg("--version").output().expect("curl must be installed");
    if !String::from_utf8_lossy(&curl.stdout).contains("HTTP2") {
        eprintln!("skipping: curl was built without HTTP/2");
        return;
    }
    let env = Env::new("h2");
    let proxy = env.start_proxy()["usage"]["proxy_url"].as_str().unwrap().to_string();
    // HTTP/2 on both sides, then an HTTP/2 client and an HTTP/1.1 origin (a chunked stream).
    for (mode, version) in [(Mode::TlsH2, "HTTP/2 200"), (Mode::TlsH1, "HTTP/1.1 200")] {
        let sse = spawn_sse(&env.dir, mode);
        let url = format!("https://localhost:{}/events", sse.port);
        let (mut child, rx) = curl_lines(&proxy, &env.ca(), &url);
        // The first events arrive while the server waits to send the next.
        let first = lines_until(&rx, "data: hello");
        assert!(!first.iter().any(|l| l.contains("second")), "{first:?}");
        let open_stream = env.stream("open with two events", |s| s["state"] == "open" && s["events"] == 2);
        assert_eq!(open_stream["url"], url);
        sse.gate.add_permits(1);
        lines_until(&rx, "data: line two");
        sse.gate.add_permits(1);
        // The response ends for the client when it does for the server.
        lines_until(&rx, "version 2");
        assert!(child.wait().unwrap().success());

        let closed = env.closed_stream();
        assert_eq!(
            (&closed["id"], &closed["ended"], &closed["events"]),
            (&open_stream["id"], &Value::from("server"), &Value::from(3))
        );
        let raw = Command::new(env!("CARGO_BIN_EXE_brainproxy"))
            .arg("--project")
            .arg(&env.project)
            .args(["history", "show", &closed["history_id"].to_string(), "--raw", "--part", "response"])
            .output()
            .unwrap();
        let raw = String::from_utf8_lossy(&raw.stdout).into_owned();
        assert!(raw.starts_with(version), "{raw}");
        let row = env.ok(&["history", "show", &closed["history_id"].to_string()]);
        assert_eq!(row["response"]["body"]["content"], format!("{FIRST}{SECOND}"), "{mode:?}", mode = version);
    }
}

#[test]
fn send_reads_an_event_stream_for_a_bounded_time() {
    let env = Env::new("send");
    let sse = spawn_sse(&env.dir, Mode::Plain);
    let base = format!("http://127.0.0.1:{}", sse.port);

    // A stream that never ends: three events, then stop.
    let started = Instant::now();
    let d = env.ok(&["send", "--url", &format!("{base}/forever"), "--max-events", "3"]);
    assert!(started.elapsed() < Duration::from_secs(4), "{:?}", started.elapsed());
    assert_eq!((&d["response"]["status"], &d["stream"]["stopped"]), (&Value::from(200), &Value::from("max-events")));
    // Events that arrived together with the third are read too: every event in the body is listed.
    let count = d["stream"]["count"].as_i64().unwrap();
    assert!((3..10).contains(&count), "{d}");
    assert_eq!(d["response"]["body"]["content"].as_str().unwrap().matches("data: tick").count() as i64, count);
    assert_eq!(data(&d["stream"]["events"][2]), "tick 2");
    assert!(d["response"]["body"]["content"].as_str().unwrap().starts_with("id: 0\ndata: tick 0\n\n"), "{d}");
    // It is recorded like a proxied one.
    let stream = env.closed_stream();
    assert_eq!(
        (&stream["id"], &stream["source"], &stream["history_id"]),
        (&d["stream"]["stream_id"], &Value::from("send"), &d["id"])
    );
    assert_eq!((&stream["ended"], &stream["events"]), (&Value::from("stopped"), &d["stream"]["count"]));
    // It opened when its head arrived, before its first event.
    assert!(stream["time"].as_str().unwrap() <= d["stream"]["events"][0]["time"].as_str().unwrap(), "{stream}");
    assert!(stream["error"].as_str().unwrap().contains("--max-events"), "{stream}");
    assert_eq!(env.ok(&["sse", "events", &stream["id"].to_string(), "--contains", "tick 1"])["count"], 1);

    // A server that goes quiet: stop after the wait, with what arrived.
    let started = Instant::now();
    let d = env.ok(&["send", "--url", &format!("{base}/events"), "--stream-wait", "0.4"]);
    assert!(started.elapsed() < Duration::from_secs(4), "{:?}", started.elapsed());
    assert_eq!((&d["stream"]["stopped"], &d["stream"]["count"]), (&Value::from("wait"), &Value::from(2)));
    assert_eq!(d["response"]["body"]["content"], FIRST);

    // A stream the server ends is read to its end.
    sse.gate.add_permits(2);
    let d = env.ok(&["send", "--url", &format!("{base}/events")]);
    assert_eq!((&d["stream"]["stopped"], &d["stream"]["count"]), (&Value::from("closed"), &Value::from(3)));
    assert_eq!(env.closed_stream()["ended"], "server");

    // Over HTTP/2 too.
    let h2 = spawn_sse(&env.dir, Mode::TlsH2);
    let d =
        env.ok(&["send", "--http2", "--url", &format!("https://localhost:{}/events", h2.port), "--stream-wait", "0.4"]);
    assert_eq!((&d["stream"]["stopped"], &d["stream"]["count"]), (&Value::from("wait"), &Value::from(2)));
    assert_eq!(d["response"]["body"]["content"], FIRST);

    // Any other response is as before: no stream, read whole.
    let d = env.ok(&["send", "--url", &format!("{base}/plain")]);
    assert_eq!((&d["stream"], &d["response"]["body"]["content"]), (&Value::Null, &Value::from("plain")));
    // --no-store keeps no events either.
    let before = env.ok(&["sse", "list"])["count"].clone();
    let d = env.ok(&["send", "--url", &format!("{base}/forever"), "--max-events", "1", "--no-store"]);
    assert_eq!(d["stream"]["stream_id"], Value::Null);
    assert!(d["stream"]["count"].as_i64().unwrap() >= 1, "{d}");
    assert_eq!(env.ok(&["sse", "list"])["count"], before);
    assert_eq!(env.run(&["send", "--url", &format!("{base}/plain"), "--stream-wait", "-1"]).0, 2);
    // A race reads whole responses: the stream limits don't go with it.
    let (code, v) = env.run(&["send", "--url", &format!("{base}/plain"), "--race", "2", "--max-events", "1"]);
    assert_eq!((code, &v["error"]["kind"]), (2, &Value::from("usage")), "{v}");
}
