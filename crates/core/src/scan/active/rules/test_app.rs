//! A small in-test HTTP server and a one-rule scan through the real engine (client, scope
//! guard, store), for end-to-end tests of rules whose fixtures need the method, headers or
//! body of each request (the injection and probe suites answer by path alone).

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::Arc;
use std::time::Duration;

use crate::guard::{Guard, ScopeSpec};
use crate::http::{SendOptions, Target};
use crate::jobs::JobControl;
use crate::oob::Endpoint;
use crate::scan::active::{run, ActiveConfig, ActiveSummary, PointOptions, ScanTarget, Strength};
use crate::scan::message::url_decode;

/// One request as the server read it.
#[derive(Debug, Clone)]
pub(crate) struct Req {
    pub method: String,
    /// The request target as sent (path and query).
    pub target: String,
    pub path: String,
    pub query: String,
    pub headers: Vec<(String, String)>,
    pub body: String,
}

impl Req {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers.iter().find(|(k, _)| k.eq_ignore_ascii_case(name)).map(|(_, v)| v.as_str())
    }

    /// A query (or form body) parameter, decoded.
    pub fn param(&self, name: &str) -> Option<String> {
        let form = self.header("content-type").is_some_and(|c| c.contains("x-www-form-urlencoded"));
        let sources = [Some(self.query.as_str()), form.then_some(self.body.as_str())];
        sources.into_iter().flatten().flat_map(|s| s.split('&')).find_map(|p| {
            let (k, v) = p.split_once('=').unwrap_or((p, ""));
            (url_decode(k) == name).then(|| url_decode(v))
        })
    }
}

/// A response with `Content-Length` and `Connection: close`.
pub(crate) fn resp(status: u16, content_type: &str, extra: &[(&str, &str)], body: &str) -> String {
    let mut head = format!("HTTP/1.1 {status} X\r\n");
    if !content_type.is_empty() {
        head.push_str(&format!("Content-Type: {content_type}\r\n"));
    }
    for (k, v) in extra {
        head.push_str(&format!("{k}: {v}\r\n"));
    }
    format!("{head}Content-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len())
}

pub(crate) fn html(body: &str) -> String {
    resp(200, "text/html", &[], body)
}

pub(crate) fn not_found() -> String {
    resp(404, "text/html", &[], "<html><body>Not found</body></html>")
}

fn read_request(s: &mut TcpStream) -> Option<Req> {
    let (mut buf, mut got) = (vec![0u8; 65536], Vec::new());
    let head_end = loop {
        if let Some(i) = got.windows(4).position(|w| w == b"\r\n\r\n") {
            break i + 4;
        }
        let n = s.read(&mut buf).ok().filter(|&n| n > 0)?;
        got.extend_from_slice(&buf[..n]);
    };
    let head = String::from_utf8_lossy(&got[..head_end]).into_owned();
    let mut lines = head.split("\r\n");
    let mut first = lines.next()?.split(' ');
    let (method, target) = (first.next()?.to_string(), first.next()?.to_string());
    let headers: Vec<(String, String)> =
        lines.filter_map(|l| l.split_once(':').map(|(k, v)| (k.trim().to_string(), v.trim().to_string()))).collect();
    let len = headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("content-length"))
        .and_then(|(_, v)| v.parse::<usize>().ok())
        .unwrap_or(0);
    while got.len() < head_end + len {
        let n = s.read(&mut buf).ok().filter(|&n| n > 0)?;
        got.extend_from_slice(&buf[..n]);
    }
    let body = String::from_utf8_lossy(&got[head_end..head_end + len]).into_owned();
    let (path, query) = target.split_once('?').map_or((target.clone(), String::new()), |(p, q)| (p.into(), q.into()));
    Some(Req { method, target, path, query, headers, body })
}

/// Serves every connection with `answer` on a thread of its own; returns the port.
pub(crate) fn serve(answer: impl Fn(&Req) -> String + Send + Sync + 'static) -> u16 {
    let answer = Arc::new(answer);
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut s) = stream else { continue };
            let answer = answer.clone();
            std::thread::spawn(move || {
                if let Some(req) = read_request(&mut s) {
                    let _ = s.write_all(answer(&req).as_bytes());
                }
            });
        }
    });
    port
}

/// Serves binary bodies by path (query left out): `body(path)` is a 200 with those bytes, None
/// a 404.
pub(crate) fn serve_bytes(body: impl Fn(&str) -> Option<Vec<u8>> + Send + Sync + 'static) -> u16 {
    let body = Arc::new(body);
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut s) = stream else { continue };
            let body = body.clone();
            std::thread::spawn(move || {
                let Some(req) = read_request(&mut s) else { return };
                let (status, data) = match body(&req.path) {
                    Some(d) => ("200 OK", d),
                    None => ("404 Not Found", b"not found".to_vec()),
                };
                let head = format!("HTTP/1.1 {status}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", data.len());
                let _ = s.write_all(&[head.as_bytes(), &data].concat());
            });
        }
    });
    port
}

/// `request` (a full raw request) as a scan target, with its response fetched directly.
pub(crate) fn target_raw(port: u16, request: &str) -> ScanTarget {
    let mut s = TcpStream::connect(("127.0.0.1", port)).unwrap();
    s.write_all(request.as_bytes()).unwrap();
    let mut response = Vec::new();
    s.read_to_end(&mut response).unwrap();
    ScanTarget {
        history_id: None,
        target: Target::from_url(&format!("http://127.0.0.1:{port}")).unwrap(),
        request: request.as_bytes().to_vec(),
        response,
        duration_ms: None,
    }
}

/// A GET for `path_and_query` as a scan target.
pub(crate) fn get(port: u16, path_and_query: &str) -> ScanTarget {
    target_raw(port, &format!("GET {path_and_query} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nConnection: close\r\n\r\n"))
}

/// A POST of `body` with `content_type` as a scan target.
pub(crate) fn post(port: u16, path: &str, content_type: &str, body: &str) -> ScanTarget {
    target_raw(
        port,
        &format!(
            "POST {path} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\n\
             Connection: close\r\n\r\n{body}",
            body.len()
        ),
    )
}

/// A finding as stored, with the request that backs it.
#[derive(Debug, Clone)]
pub(crate) struct Found {
    pub alert_ref: String,
    pub risk: String,
    pub param: String,
    pub attack: String,
    pub evidence: String,
    pub other_info: String,
    /// The backing request's method and URL.
    pub method: String,
    pub url: String,
}

/// How a test scan runs besides its rule and targets.
#[derive(Default)]
pub(crate) struct Opts {
    pub strength: Option<Strength>,
    /// `--include-methods`.
    pub methods: Vec<String>,
    /// An OOB listener (DNS mode, domain `oob.test`) on these sockets.
    pub oob: Option<(tokio::net::TcpListener, tokio::net::UdpSocket)>,
}

/// Runs rule `rule` over `targets`; returns the summary and the stored findings.
pub(crate) async fn scan(rule: u32, targets: Vec<ScanTarget>, opts: Opts) -> (ActiveSummary, Vec<Found>) {
    let guard =
        Guard::from_specs(vec![ScopeSpec { name: None, include: vec!["127.0.0.1".into()], exclude: vec![] }]).unwrap();
    let dir =
        std::env::temp_dir().join(format!("bp-rule-{rule}-{}-{}", std::process::id(), crate::scan::active::rand_u64()));
    std::fs::create_dir_all(&dir).unwrap();
    let db = dir.join("project.db");
    drop(crate::store::Store::open(&db).unwrap());
    let oob = opts.oob.is_some();
    let (stop, endpoint) = match opts.oob {
        Some((tcp, udp)) => {
            let public_port = tcp.local_addr().unwrap().port();
            let serve_opts = crate::oob::server::ServeOptions {
                project: db.clone(),
                domain: Some("oob.test".into()),
                public_ip: None,
            };
            let (tx, rx) = tokio::sync::oneshot::channel::<()>();
            tokio::spawn(crate::oob::server::serve(tcp, Some(udp), serve_opts, async move {
                let _ = rx.await;
            }));
            let ep = Endpoint {
                domain: Some("oob.test".into()),
                public_host: "127.0.0.1".into(),
                public_port,
                auto_host: false,
            };
            (Some(tx), Some(ep))
        }
        None => (None, None),
    };
    let cfg = ActiveConfig {
        strength: opts.strength.unwrap_or(Strength::Medium),
        tuning: Default::default(),
        concurrency: 2,
        rate: None,
        send: SendOptions { timeout: Duration::from_secs(30), guard: Some(guard), ..Default::default() },
        points: PointOptions::default(),
        rules: Some(vec![rule]),
        exclude_rules: vec![],
        no_rules: false,
        checks: vec![],
        max_duration: None,
        auth: None,
        oob: endpoint,
        oob_wait: if oob { Duration::from_secs(3) } else { Duration::ZERO },
        check_methods: opts.methods,
        prune: false,
    };
    let summary = run(&db, targets, cfg, JobControl::default()).await.unwrap();
    if let Some(tx) = stop {
        let _ = tx.send(());
    }
    let conn = rusqlite::Connection::open(&db).unwrap();
    let mut st = conn
        .prepare(
            "SELECT f.alert_ref, f.risk, COALESCE(f.param, ''), COALESCE(f.attack, ''), COALESCE(f.evidence, ''), \
             COALESCE(f.other_info, ''), COALESCE(h.method, ''), COALESCE(h.url, '') \
             FROM findings f LEFT JOIN history h ON h.id = f.history_id WHERE f.source = 'active' ORDER BY f.id",
        )
        .unwrap();
    let found = st
        .query_map([], |r| {
            Ok(Found {
                alert_ref: r.get(0)?,
                risk: r.get(1)?,
                param: r.get(2)?,
                attack: r.get(3)?,
                evidence: r.get(4)?,
                other_info: r.get(5)?,
                method: r.get(6)?,
                url: r.get(7)?,
            })
        })
        .unwrap()
        .map(|r| r.unwrap())
        .collect();
    drop(st);
    drop(conn);
    let _ = std::fs::remove_dir_all(&dir);
    (summary, found)
}

/// The request lines a scan sent, for asserting what went out.
pub(crate) type Seen = Arc<std::sync::Mutex<Vec<Req>>>;

pub(crate) fn seen() -> Seen {
    Arc::new(std::sync::Mutex::new(Vec::new()))
}
