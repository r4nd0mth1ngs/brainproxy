//! End-to-end tests for the page/host probe rules: run them through the real
//! active-scan engine against tiny in-test HTTP servers.

use std::io::{Read, Write};
use std::net::TcpListener;
use std::path::PathBuf;
use std::time::Duration;

use brainproxy_core::guard::{Guard, ScopeSpec};
use brainproxy_core::http::{SendOptions, Target};
use brainproxy_core::jobs::JobControl;
use brainproxy_core::scan::active::{self, ActiveConfig, ActiveSummary, PointOptions, ScanTarget, Strength};

/// Spawns an HTTP server; `respond` maps a request path to a raw HTTP response.
fn spawn<F>(respond: F) -> u16
where
    F: Fn(&str) -> String + Send + Sync + 'static,
{
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let respond = std::sync::Arc::new(respond);
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut s) = stream else { continue };
            let respond = respond.clone();
            std::thread::spawn(move || {
                let mut buf = vec![0u8; 16384];
                let n = s.read(&mut buf).unwrap_or(0);
                let req = String::from_utf8_lossy(&buf[..n]);
                let path = req.split(' ').nth(1).unwrap_or("/");
                let _ = s.write_all(respond(path).as_bytes());
            });
        }
    });
    port
}

fn ok(status: &str, content_type: &str, body: &str) -> String {
    format!(
        "HTTP/1.1 {status}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    )
}

fn not_found() -> String {
    "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".to_string()
}

fn project() -> PathBuf {
    let dir = std::env::temp_dir().join(format!("bp-probes-{}-{}", std::process::id(), rand_tag()));
    std::fs::create_dir_all(&dir).unwrap();
    dir.join("p.bpdb")
}

fn rand_tag() -> u64 {
    use std::hash::{BuildHasher, Hasher};
    let mut h = std::collections::hash_map::RandomState::new().build_hasher();
    h.write_u64(std::time::SystemTime::now().elapsed().map(|d| d.as_nanos() as u64).unwrap_or(0));
    h.write_usize(&0u8 as *const u8 as usize);
    h.finish()
}

/// Runs the given rule ids against one baseline (GET path, 200 html by default).
fn run_scan(port: u16, path: &str, rules: &[u32], baseline: Option<&str>) -> ActiveSummary {
    let base = format!("http://127.0.0.1:{port}");
    let target = Target::from_url(&format!("{base}{path}")).unwrap();
    let request = format!("GET {path} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nUser-Agent: brainproxy-test\r\n\r\n");
    let response =
        baseline.map(str::to_string).unwrap_or_else(|| ok("200 OK", "text/html", "<html><body>base</body></html>"));
    let guard =
        Guard::from_specs(vec![ScopeSpec { name: None, include: vec!["127.0.0.1".into()], exclude: vec![] }]).unwrap();
    let cfg = ActiveConfig {
        strength: Strength::Medium,
        concurrency: 4,
        rate: None,
        send: SendOptions { timeout: Duration::from_secs(5), verify_tls: false, sni: None, guard: Some(guard) },
        points: PointOptions::default(),
        rules: Some(rules.to_vec()),
        exclude_rules: vec![],
        max_duration: None,
    };
    let targets =
        vec![ScanTarget { history_id: None, target, request: request.into_bytes(), response: response.into_bytes() }];
    let project = project();
    let rt = tokio::runtime::Builder::new_multi_thread().enable_all().build().unwrap();
    rt.block_on(active::run(&project, targets, cfg, JobControl::default())).unwrap()
}

#[test]
fn finds_hidden_file_and_directory_listing() {
    // A server exposing a readable .git/config and a directory listing at /files/.
    let port = spawn(|path| match path {
        "/.git/config" => ok("200 OK", "text/plain", "[core]\n\trepositoryformatversion = 0\n\tbare = false\n"),
        "/files/" => ok(
            "200 OK",
            "text/html",
            "<html><head><title>Index of /files</title></head><body><h1>Index of /files</h1>\
             <a href=\"../\">Parent Directory</a><a href=\"a.txt\">a.txt</a></body></html>",
        ),
        _ => not_found(),
    });

    // Hidden File Finder (host rule) locates .git/config.
    let s = run_scan(port, "/", &[40035], None);
    assert_eq!(s.raised.get("40035").copied(), Some(1), "hidden file should be found once: {s:?}");

    // Directory Browsing (page rule) flags the listing at /files/.
    let s = run_scan(port, "/files", &[0], None);
    assert_eq!(s.raised.get("0").copied(), Some(1), "directory listing should be found: {s:?}");
}

#[test]
fn clean_and_soft_404_servers_raise_nothing() {
    // A server that answers 200 with the same body for every path (soft 404).
    let soft = spawn(|_| ok("200 OK", "text/html", "<html><body>Welcome to our site</body></html>"));
    let s = run_scan(soft, "/", &[40035, 40032, 40029, 40028], None);
    assert!(s.raised.is_empty(), "soft-404 server must not produce file findings: {s:?}");

    // A clean server: 404 for every probe path.
    let clean = spawn(|path| if path == "/" { ok("200 OK", "text/html", "<html>home</html>") } else { not_found() });
    let s = run_scan(clean, "/", &[40035, 40032, 40029, 40028, 0], None);
    assert!(s.raised.is_empty(), "clean server must raise nothing: {s:?}");
}

#[test]
fn spring_actuator_health_leak() {
    let port = spawn(|path| match path {
        "/actuator/health" => ok("200 OK", "application/vnd.spring-boot.actuator.v3+json", r#"{"status":"UP"}"#),
        _ => not_found(),
    });
    let s = run_scan(port, "/", &[40042], None);
    assert_eq!(s.raised.get("40042").copied(), Some(1), "spring actuator leak should be found: {s:?}");
}

#[test]
fn https_as_http_not_applicable_over_http() {
    // The HTTPS-as-HTTP rule only applies to https baselines, so an http target raises nothing.
    let port = spawn(|_| ok("200 OK", "text/html", "<html>home</html>"));
    let s = run_scan(port, "/", &[10047], None);
    assert!(s.raised.is_empty(), "https-as-http should not fire on an http target: {s:?}");
}
