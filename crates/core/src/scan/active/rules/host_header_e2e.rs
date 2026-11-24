//! End-to-end: the Host header rule through the real engine against an in-test server with a
//! page and a password-reset form that build links from X-Forwarded-Host, the same two built
//! from a configured host, a reset form that "emails" a link which a mail scanner opens, and
//! a page that fetches the host it is told.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::time::Duration;

use crate::guard::{Guard, ScopeSpec};
use crate::http::client::HostPolicy;
use crate::http::{SendOptions, Target};
use crate::jobs::JobControl;
use crate::oob::Endpoint;
use crate::scan::active::{run, ActiveConfig, ActiveSummary, PointOptions, ScanTarget, Strength};

fn page(body: &str) -> String {
    format!(
        "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    )
}

fn header<'a>(req: &'a str, name: &str) -> Option<&'a str> {
    req.lines().find_map(|l| l.split_once(':').filter(|(k, _)| k.eq_ignore_ascii_case(name)).map(|(_, v)| v.trim()))
}

/// What the server answers; a link a mail scanner would open is fetched after the answer.
fn handle(req: &str) -> (String, Option<String>) {
    let path = req.split(' ').nth(1).unwrap_or("/");
    let path = path.split('?').next().unwrap_or(path);
    let own = header(req, "host").unwrap_or("app.test").to_string();
    let forwarded = header(req, "x-forwarded-host").map(str::to_string);
    match path {
        // Trusts X-Forwarded-Host, as an app behind a proxy that sets it might.
        "/login" => {
            let host = forwarded.unwrap_or(own);
            (page(&format!("<html><body><form action=\"http://{host}/login\" method=post></form></body></html>")), None)
        }
        "/login-fixed" => (page("<html><body><form action=\"http://app.test/login\"></form></body></html>"), None),
        // A development build shows the reset link it emailed.
        "/forgot" => {
            let host = forwarded.unwrap_or(own);
            (
                page(&format!("<html><body>Sent. <a href=\"http://{host}/reset?token=t0k3n\">link</a></body></html>")),
                None,
            )
        }
        "/forgot-fixed" => {
            (page("<html><body>Sent. <a href=\"http://app.test/reset?token=t0k3n\">link</a></body></html>"), None)
        }
        // Emails the link, which a mail scanner then opens.
        "/forgot-mail" => (page("<html><body>Check your email.</body></html>"), forwarded),
        // Checks the "upstream" it is told about.
        "/status" => (page("<html><body>up</body></html>"), forwarded),
        _ => (page("<html><body>not here</body></html>"), None),
    }
}

/// Opens `http://<host>/reset?token=...` as a mail scanner would: `host` names the OOB
/// listener on this machine, whatever its name says.
fn open_link(host: &str) {
    let Some(port) = host.rsplit_once(':').and_then(|(_, p)| p.parse::<u16>().ok()) else { return };
    let Ok(mut s) = TcpStream::connect(("127.0.0.1", port)) else { return };
    let _ =
        s.write_all(format!("GET /reset?token=t0k3n HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n").as_bytes());
    let mut sink = Vec::new();
    let _ = s.read_to_end(&mut sink);
}

fn spawn_app() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut s) = stream else { continue };
            std::thread::spawn(move || {
                let mut buf = vec![0u8; 16384];
                let n = s.read(&mut buf).unwrap_or(0);
                let (resp, link) = handle(&String::from_utf8_lossy(&buf[..n]));
                let _ = s.write_all(resp.as_bytes());
                drop(s);
                if let Some(host) = link {
                    open_link(&host);
                }
            });
        }
    });
    port
}

fn target(port: u16, path: &str) -> ScanTarget {
    let req = if path.starts_with("/forgot") {
        format!(
            "POST {path} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nContent-Type: application/x-www-form-urlencoded\r\n\
             Content-Length: 13\r\nConnection: close\r\n\r\nemail=a%40b.c"
        )
    } else {
        format!("GET {path} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nConnection: close\r\n\r\n")
    };
    let mut s = TcpStream::connect(("127.0.0.1", port)).unwrap();
    s.write_all(req.as_bytes()).unwrap();
    let mut response = Vec::new();
    s.read_to_end(&mut response).unwrap();
    ScanTarget {
        history_id: None,
        target: Target::from_url(&format!("http://127.0.0.1:{port}")).unwrap(),
        request: req.into_bytes(),
        response,
        duration_ms: None,
    }
}

struct Scanned {
    refs: Vec<String>,
    summary: ActiveSummary,
    /// The request lines of the scan's requests.
    lines: Vec<String>,
}

/// Scans `path` with rule 100010; `oob` runs an OOB listener in DNS mode for it.
async fn scan(port: u16, path: &str, strength: Strength, host: HostPolicy, oob: bool) -> Scanned {
    let guard =
        Guard::from_specs(vec![ScopeSpec { name: None, include: vec!["127.0.0.1".into()], exclude: vec![] }]).unwrap();
    let dir = std::env::temp_dir().join(format!(
        "bp-hosthdr-{}-{}-{}",
        path.trim_start_matches('/'),
        std::process::id(),
        crate::scan::active::rand_u64()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let db = dir.join("project.db");
    drop(crate::store::Store::open(&db).unwrap());
    let (stop, endpoint) = if oob {
        let tcp = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let oob_port = tcp.local_addr().unwrap().port();
        let opts =
            crate::oob::server::ServeOptions { project: db.clone(), domain: Some("oob.test".into()), public_ip: None };
        let (tx, rx) = tokio::sync::oneshot::channel::<()>();
        tokio::spawn(crate::oob::server::serve(tcp, None, opts, async move {
            let _ = rx.await;
        }));
        let ep = Endpoint {
            domain: Some("oob.test".into()),
            public_host: "127.0.0.1".into(),
            public_port: oob_port,
            auto_host: false,
        };
        (Some(tx), Some(ep))
    } else {
        (None, None)
    };
    let cfg = ActiveConfig {
        strength,
        tuning: Default::default(),
        concurrency: 2,
        rate: None,
        send: SendOptions { timeout: Duration::from_secs(20), guard: Some(guard), host, ..Default::default() },
        points: PointOptions::default(),
        rules: Some(vec![100010]),
        exclude_rules: vec![],
        no_rules: false,
        checks: vec![],
        max_duration: None,
        auth: None,
        oob: endpoint,
        oob_wait: if oob { Duration::from_secs(4) } else { Duration::ZERO },
        check_methods: vec![],
        prune: false,
    };
    let summary = run(&db, vec![target(port, path)], cfg, JobControl::default()).await.unwrap();
    if let Some(tx) = stop {
        let _ = tx.send(());
    }
    let conn = rusqlite::Connection::open(&db).unwrap();
    let refs: Vec<String> = conn
        .prepare("SELECT alert_ref FROM findings WHERE source = 'active' ORDER BY alert_ref")
        .unwrap()
        .query_map([], |r| r.get(0))
        .unwrap()
        .map(|r| r.unwrap())
        .collect();
    let mut st = conn.prepare("SELECT request FROM history WHERE source = 'scan' ORDER BY id").unwrap();
    let lines = st
        .query_map([], |r| r.get::<_, Vec<u8>>(0))
        .unwrap()
        .map(|r| String::from_utf8_lossy(&r.unwrap()).lines().next().unwrap_or_default().to_string())
        .collect();
    drop(st);
    drop(conn);
    let _ = std::fs::remove_dir_all(&dir);
    Scanned { refs, summary, lines }
}

#[tokio::test(flavor = "multi_thread")]
async fn a_host_built_from_x_forwarded_host_is_found_and_a_fixed_one_is_not() {
    let port = spawn_app();
    let vulnerable = scan(port, "/login", Strength::Medium, HostPolicy::Warn, false).await;
    assert_eq!(vulnerable.refs, ["100010-1"]);
    // Every place is tried, each with a cache buster.
    assert_eq!(vulnerable.summary.requests, 7, "{:?}", vulnerable.lines);
    for l in &vulnerable.lines {
        assert!(l.contains("?bp") && l.contains('='), "no cache buster: {l}");
    }
    assert!(vulnerable.lines.iter().any(|l| l.starts_with("GET http://bp") && l.contains(".invalid/login?bp")));
    let fixed = scan(port, "/login-fixed", Strength::Medium, HostPolicy::Warn, false).await;
    assert!(fixed.refs.is_empty(), "{:?}", fixed.refs);
    assert_eq!(fixed.summary.requests, 7);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_reset_form_gets_one_request_below_high_and_all_at_high() {
    let port = spawn_app();
    let medium = scan(port, "/forgot", Strength::Medium, HostPolicy::Warn, false).await;
    assert_eq!(medium.refs, ["100010-1"]);
    assert_eq!(medium.summary.requests, 1, "{:?}", medium.lines);
    let high = scan(port, "/forgot", Strength::High, HostPolicy::Warn, false).await;
    assert_eq!(high.refs, ["100010-1"]);
    assert_eq!(high.summary.requests, 7);
    let fixed = scan(port, "/forgot-fixed", Strength::High, HostPolicy::Warn, false).await;
    assert!(fixed.refs.is_empty(), "{:?}", fixed.refs);
}

#[tokio::test(flavor = "multi_thread")]
async fn an_emailed_link_that_is_opened_raises_reset_poisoning() {
    let port = spawn_app();
    let s = scan(port, "/forgot-mail", Strength::Medium, HostPolicy::Warn, true).await;
    assert_eq!(s.refs, ["100010-3"], "{:?}", s.summary);
    assert_eq!(s.summary.requests, 1);
    // A page that fetches the host it is told: routing-based SSRF, from all seven requests.
    let s = scan(port, "/status", Strength::Medium, HostPolicy::Warn, true).await;
    assert_eq!(s.refs, ["100010-2"], "{:?}", s.summary);
    assert_eq!(s.summary.oob.as_ref().map(|o| o.payloads), Some(7));
    // The fixed form builds its link from its own host: nothing calls back.
    let fixed = scan(port, "/forgot-fixed", Strength::Medium, HostPolicy::Warn, true).await;
    assert!(fixed.refs.is_empty(), "{:?}", fixed.refs);
}
