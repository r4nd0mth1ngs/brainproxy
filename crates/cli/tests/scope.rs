//! The engagement scope is the hard boundary: these tests check that nothing is
//! sent without one, that it can't be changed once set, that every sending path
//! honours it, and that the system scope file is enforced on top.

use std::io::{Read, Write};
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use serde_json::Value;

fn project(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("bp-scope-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir.join("p.bpdb")
}

fn run_env(project: &Path, env: &[(&str, &str)], args: &[&str]) -> (i32, Value) {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_brainproxy"));
    cmd.args(["--format", "json", "--project"]).arg(project).arg("--home").arg(project.with_extension("home"));
    cmd.env_remove("BRAINPROXY_SYSTEM_SCOPE");
    for (k, v) in env {
        cmd.env(k, v);
    }
    let out = cmd.args(args).output().unwrap();
    let v = serde_json::from_slice(&out.stdout)
        .unwrap_or_else(|e| panic!("bad JSON ({e}): {}", String::from_utf8_lossy(&out.stdout)));
    (out.status.code().unwrap(), v)
}

fn run(project: &Path, args: &[&str]) -> (i32, Value) {
    run_env(project, &[], args)
}

fn assert_out_of_scope((code, v): (i32, Value)) {
    assert_eq!(code, 6, "{v}");
    assert_eq!(v["error"]["kind"], "out_of_scope", "{v}");
}

/// A server that counts connections, so tests can prove nothing reached it.
fn counting_server() -> (u16, Arc<AtomicUsize>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let hits = Arc::new(AtomicUsize::new(0));
    let h = hits.clone();
    std::thread::spawn(move || {
        for s in listener.incoming() {
            let Ok(mut s) = s else { continue };
            h.fetch_add(1, Ordering::SeqCst);
            let mut buf = [0u8; 4096];
            let _ = s.read(&mut buf);
            let _ = s.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok");
        }
    });
    (port, hits)
}

#[test]
fn nothing_is_sent_without_an_engagement() {
    let (port, hits) = counting_server();
    let p = project("none");
    let url = format!("http://127.0.0.1:{port}/");
    assert_out_of_scope(run(&p, &["send", "--url", &url]));
    assert_out_of_scope(run(&p, &["send", "--url", &url, "--race", "3"]));
    assert_out_of_scope(run(&p, &["fuzz", "run", "--url", &format!("{url}?a=§1§"), "-p", "list:1,2"]));
    assert_out_of_scope(run(&p, &["crawl", &url]));
    assert_out_of_scope(run(&p, &["proxy", "start", "--listen", "127.0.0.1:0"]));
    assert_eq!(hits.load(Ordering::SeqCst), 0);
}

#[test]
fn engagement_is_write_once_and_enforced_everywhere() {
    let (port, hits) = counting_server();
    let p = project("locked");
    let (code, v) = run(&p, &["engagement", "start", "--target", "localhost", "--name", "test"]);
    assert_eq!(code, 0, "{v}");
    assert_eq!(v["data"]["locked"], true);

    // It can't be replaced or widened.
    let (code, v) = run(&p, &["engagement", "start", "--target", "127.0.0.0/8"]);
    assert_eq!((code, v["error"]["kind"].as_str()), (2, Some("conflict")));
    let (_, v) = run(&p, &["engagement", "show"]);
    assert_eq!(v["data"]["engagement"]["include"], serde_json::json!(["localhost"]));

    // In scope: the hostname works.
    let (code, v) = run(&p, &["send", "--url", &format!("http://localhost:{port}/")]);
    assert_eq!(code, 0, "{v}");
    let before = hits.load(Ordering::SeqCst);

    // Out of scope: the same server by IP is refused on every path, before connecting.
    let url = format!("http://127.0.0.1:{port}/");
    assert_out_of_scope(run(&p, &["send", "--url", &url]));
    assert_out_of_scope(run(&p, &["send", "--url", &url, "--race", "3"]));
    assert_out_of_scope(run(&p, &["fuzz", "run", "--url", &format!("{url}?a=§1§"), "-p", "list:1,2"]));
    assert_out_of_scope(run(&p, &["crawl", &url]));
    assert_out_of_scope(run(&p, &["crawl", &url, "--background"]));
    // A raw request whose Host header points elsewhere is refused too.
    let raw = p.with_extension("req.http");
    std::fs::write(&raw, format!("GET / HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n\r\n")).unwrap();
    assert_out_of_scope(run(&p, &["send", raw.to_str().unwrap(), "--scheme", "http"]));
    assert_eq!(hits.load(Ordering::SeqCst), before, "an out-of-scope request reached the server");

    let (_, v) = run(&p, &["engagement", "check", &format!("127.0.0.1:{port}")]);
    assert_eq!(v["data"]["results"][0]["allowed"], false);
    let (_, v) = run(&p, &["engagement", "check", &format!("localhost:{port}")]);
    assert_eq!(v["data"]["results"][0]["allowed"], true);
}

#[test]
fn proxy_refuses_out_of_scope_traffic() {
    let (port, hits) = counting_server();
    let p = project("proxy");
    run(&p, &["engagement", "start", "--target", "localhost"]);
    let (code, v) = run(&p, &["proxy", "start", "--listen", "127.0.0.1:0"]);
    assert_eq!(code, 0, "{v}");
    let proxy = v["data"]["listen"].as_str().unwrap().to_string();

    let raw = |req: &str| -> String {
        let mut s = std::net::TcpStream::connect(&proxy).unwrap();
        s.write_all(req.as_bytes()).unwrap();
        let mut out = String::new();
        let _ = s.read_to_string(&mut out);
        out
    };
    let plain =
        raw(&format!("GET http://127.0.0.1:{port}/ HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nConnection: close\r\n\r\n"));
    assert!(plain.starts_with("HTTP/1.1 403"), "{plain}");
    assert!(plain.contains("X-Brainproxy-Error: out_of_scope"));
    let tunnel = raw(&format!("CONNECT 127.0.0.1:{port} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n\r\n"));
    assert!(tunnel.starts_with("HTTP/1.1 403"), "{tunnel}");
    let ok =
        raw(&format!("GET http://localhost:{port}/ HTTP/1.1\r\nHost: localhost:{port}\r\nConnection: close\r\n\r\n"));
    assert!(ok.starts_with("HTTP/1.1 200"), "{ok}");
    assert_eq!(hits.load(Ordering::SeqCst), 1);
    run(&p, &["proxy", "stop"]);
}

#[test]
fn system_scope_is_enforced_on_top() {
    let (port, _) = counting_server();
    let p = project("system");
    let system = p.with_extension("system.json");
    std::fs::write(&system, r#"{"name": "runner", "include": ["localhost"]}"#).unwrap();
    let env = [("BRAINPROXY_SYSTEM_SCOPE", system.to_str().unwrap())];

    // The system scope alone is enough to send in scope...
    let (code, v) = run_env(&p, &env, &["send", "--url", &format!("http://localhost:{port}/")]);
    assert_eq!(code, 0, "{v}");
    // ...and an engagement can't widen it: the engagement allows 127.0.0.1 by
    // address, but the system scope only allows the name localhost.
    run_env(&p, &env, &["engagement", "start", "--target", "127.0.0.1"]);
    assert_out_of_scope(run_env(&p, &env, &["send", "--url", &format!("http://127.0.0.1:{port}/")]));
    // Both scopes allow localhost (by name, and by its address 127.0.0.1).
    let (code, v) = run_env(&p, &env, &["send", "--url", &format!("http://localhost:{port}/")]);
    assert_eq!(code, 0, "{v}");
    let (_, v) = run_env(&p, &env, &["engagement", "show"]);
    assert_eq!(v["data"]["system"]["name"], "runner");

    // A broken system file blocks everything rather than being ignored.
    std::fs::write(&system, "{not json").unwrap();
    assert_out_of_scope(run_env(&p, &env, &["send", "--url", &format!("http://localhost:{port}/")]));
}
