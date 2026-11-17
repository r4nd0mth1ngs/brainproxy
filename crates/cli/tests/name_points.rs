//! End-to-end tests for name insertion points (`scan active --inject-names`): a page that takes
//! its input from a parameter's or a cookie's name, as code walking `getParameterNames` does.

use std::io::{Read, Write};
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::Command;

use serde_json::Value;

/// `/names` shows, unescaped, the name of the query parameter whose value is `pick`, and the
/// name of the cookie whose value is `pick`; the values themselves are never shown.
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
                let query = target.split_once('?').map_or("", |(_, q)| q);
                let picked = |pairs: Vec<(&str, &str)>| {
                    pairs.into_iter().find(|(_, v)| *v == "pick").map(|(k, _)| decode(k)).unwrap_or_default()
                };
                let param = picked(query.split('&').map(|p| p.split_once('=').unwrap_or((p, ""))).collect());
                let cookie = text
                    .lines()
                    .find_map(|l| l.strip_prefix("Cookie: "))
                    .map(|c| picked(c.split("; ").map(|p| p.split_once('=').unwrap_or((p, ""))).collect()))
                    .unwrap_or_default();
                let body = format!("<html><body><p>Param {param}</p><p>Cookie {cookie}</p></body></html>");
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

/// Percent-decodes a query or cookie name (`+` is a space).
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
    let dir = std::env::temp_dir().join(format!("bp-names-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let project = dir.join("p.bpdb");
    run(&project, &["engagement", "start", "--target", "127.0.0.1"]);
    (dir, project)
}

/// The params of the XSS findings a scan raised.
fn xss_params(v: &Value) -> Vec<String> {
    let mut out: Vec<String> = v["active_findings"]
        .as_array()
        .into_iter()
        .flatten()
        .filter(|g| g["alert_ref"] == "40012")
        .flat_map(|g| g["examples"].as_array().cloned().unwrap_or_default())
        .filter_map(|e| e["param"].as_str().map(str::to_string))
        .collect();
    out.sort();
    out.dedup();
    out
}

#[test]
fn a_name_the_page_reads_is_attacked_only_when_asked() {
    let port = serve();
    let (dir, project) = setup("xss");
    let sent = run(
        &project,
        &["send", "--url", &format!("http://127.0.0.1:{port}/names?q=pick&other=1"), "--header", "Cookie: c=pick"],
    );
    let base = sent["id"].as_i64().unwrap_or_else(|| panic!("{sent}")).to_string();
    let scan = |extra: &[&str]| {
        let mut args = vec!["scan", "active", "--history-id", &base, "--rules", "40012", "--cookies", "--timeout", "5"];
        args.extend_from_slice(extra);
        run(&project, &args)
    };

    let v = scan(&["--strength", "low"]);
    assert_eq!(v["inject_names"], false, "{v}");
    assert!(xss_params(&v).is_empty(), "values only: the page never shows them: {v}");

    let v = scan(&["--strength", "low", "--inject-names"]);
    assert_eq!(v["inject_names"], true, "{v}");
    assert_eq!(xss_params(&v), ["name:c", "name:q"], "{v}");

    // On at high strength, unless turned off.
    let v = scan(&["--strength", "high", "--no-inject-names"]);
    assert!(xss_params(&v).is_empty(), "{v}");
    let v = scan(&["--strength", "high"]);
    assert_eq!(v["inject_names"], true, "{v}");

    // A finding on a name can be verified: its baseline is the request with the name as it was.
    let list = run(&project, &["findings", "list", "--all", "--source", "active"]);
    let f = list["items"]
        .as_array()
        .unwrap()
        .iter()
        .find(|f| f["param"] == "name:q")
        .unwrap_or_else(|| panic!("{list}"))
        .clone();
    let id = f["id"].to_string();
    let shown = run(&project, &["findings", "show", &id]);
    let attack = run(&project, &["history", "show", &shown["history_id"].to_string()]);
    let request = attack["request"]["content"].as_str().unwrap_or_default();
    assert!(request.contains("=pick&other=1 "), "the value stays, the name is the payload: {attack}");
    let v = run(&project, &["findings", "verify", &id]);
    assert_eq!(v["baseline_from"], "scan", "{v}");
    assert_eq!(v["without"]["request_history_id"].to_string(), base, "{v}");
    assert_eq!(v["with"]["sends"][0]["evidence"], true, "{v}");
    assert_eq!(v["without"]["sends"][0]["evidence"], false, "{v}");

    // A policy can turn names on below high strength.
    run(&project, &["scan", "policy", "save", "names", "--inject-names", "on"]);
    let v = scan(&["--policy", "names", "--strength", "low"]);
    assert_eq!((v["inject_names"].clone(), v["policy"]["inject_names"].clone()), (true.into(), true.into()), "{v}");

    let _ = std::fs::remove_dir_all(dir);
}
