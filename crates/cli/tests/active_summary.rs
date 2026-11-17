//! End-to-end tests for what `scan active` says when it is done: requests the target never
//! answered, and the findings of this scan rather than of the whole project.

use std::io::{Read, Write};
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::Command;

use serde_json::Value;

/// `/xss?q=` shows `q` unescaped. `/hang?q=` answers its baseline (`q=hi`) and closes the
/// connection without a word for anything else, as a target that fell over would.
fn serve() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut s) = stream else { continue };
            std::thread::spawn(move || {
                let mut buf = [0u8; 8192];
                let mut req = Vec::new();
                while !req.windows(4).any(|w| w == b"\r\n\r\n") {
                    let k = s.read(&mut buf).unwrap_or(0);
                    if k == 0 {
                        break;
                    }
                    req.extend_from_slice(&buf[..k]);
                }
                let text = String::from_utf8_lossy(&req).to_string();
                let target = text.split(' ').nth(1).unwrap_or("/").to_string();
                let (path, query) = target.split_once('?').unwrap_or((&target, ""));
                let q = query.strip_prefix("q=").unwrap_or("");
                if path == "/hang" && q != "hi" {
                    return;
                }
                let body = format!("<html><body><p>Hello {}</p></body></html>", decode(q));
                let resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = s.write_all(resp.as_bytes());
            });
        }
    });
    port
}

/// Percent-decodes a query value (`+` is a space).
fn decode(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            b'%' => match s.get(i + 1..i + 3).and_then(|h| u8::from_str_radix(h, 16).ok()) {
                Some(v) => {
                    out.push(v);
                    i += 3;
                    continue;
                }
                None => out.push(b'%'),
            },
            b'+' => out.push(b' '),
            c => out.push(c),
        }
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn run(project: &Path, args: &[&str]) -> Value {
    let out = Command::new(env!("CARGO_BIN_EXE_brainproxy"))
        .env_remove("BRAINPROXY_PROJECT")
        .args(["--format", "json", "--project"])
        .arg(project)
        .args(args)
        .output()
        .unwrap();
    let v: Value = serde_json::from_slice(&out.stdout)
        .unwrap_or_else(|e| panic!("bad JSON ({e}): {}", String::from_utf8_lossy(&out.stdout)));
    assert_eq!(out.status.code(), Some(0), "{args:?}: {v}");
    v["data"].clone()
}

fn setup(name: &str) -> (PathBuf, PathBuf) {
    let dir = std::env::temp_dir().join(format!("bp-active-summary-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let project = dir.join("p.bpdb");
    run(&project, &["engagement", "start", "--target", "127.0.0.1"]);
    (dir, project)
}

#[test]
fn unanswered_requests_and_this_scans_findings() {
    let port = serve();
    let (dir, project) = setup("summary");
    let scan = |path: &str| {
        let url = format!("http://127.0.0.1:{port}{path}");
        run(&project, &["scan", "active", &url, "--rules", "40012", "--strength", "low", "--timeout", "5"])
    };

    let v = scan("/xss?q=hi");
    let found = v["active_findings"].as_array().unwrap();
    assert!(found.iter().any(|g| g["alert_ref"] == "40012"), "{v}");
    assert_eq!(v["finding_ids"].as_array().map(Vec::len), Some(1), "{v}");
    assert_eq!(v["failed_requests"], 0, "{v}");

    // Nothing answers the attacks: no finding of its own, and not the one the project holds.
    let v = scan("/hang?q=hi");
    assert_eq!(v["errors"], 0, "no rule crashed: {v}");
    let failed = v["failed_requests"].as_u64().unwrap();
    assert!(failed > 0 && failed <= v["requests"].as_u64().unwrap(), "{v}");
    assert!(v["failed_requests_hint"].is_string(), "{v}");
    assert_eq!(v["active_findings"], serde_json::json!([]), "the earlier scan's finding isn't this one's: {v}");
    assert_eq!(v["finding_ids"], serde_json::json!([]), "{v}");

    let _ = std::fs::remove_dir_all(dir);
}
