//! End-to-end tests for `oob`: a background listener, an app that calls back
//! like vulnerable Log4j (JNDI over LDAP) and a vulnerable XML parser (external
//! entity over HTTP), active rules confirming both, and manual payloads.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

use serde_json::Value;

fn bin() -> Command {
    Command::new(env!("CARGO_BIN_EXE_brainproxy"))
}

fn run(args: &[&str], project: &Path) -> (i32, Value) {
    let out = bin().args(["--format", "json", "--project"]).arg(project).args(args).output().unwrap();
    let v: Value = serde_json::from_slice(&out.stdout)
        .unwrap_or_else(|e| panic!("bad JSON ({e}): {}", String::from_utf8_lossy(&out.stdout)));
    (out.status.code().unwrap(), v)
}

fn url_decode(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            b'%' if i + 2 < b.len() => {
                out.push(u8::from_str_radix(std::str::from_utf8(&b[i + 1..i + 3]).unwrap_or("00"), 16).unwrap_or(0));
                i += 3;
            }
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            c => {
                out.push(c);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// What vulnerable Log4j does with `${jndi:ldap://HOST:PORT/DN}`: bind, then search for DN.
fn jndi_ldap(hostport: &str, dn: &str) {
    let Ok(mut s) = TcpStream::connect(hostport) else { return };
    s.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
    let _ = s.write_all(&[0x30, 0x0c, 0x02, 0x01, 0x01, 0x60, 0x07, 0x02, 0x01, 0x03, 0x04, 0x00, 0x80, 0x00]);
    let mut reply = [0u8; 14];
    if s.read_exact(&mut reply).is_err() || reply[5] != 0x61 {
        return;
    }
    let mut search =
        vec![0x30, (7 + dn.len()) as u8, 0x02, 0x01, 0x02, 0x63, (2 + dn.len()) as u8, 0x04, dn.len() as u8];
    search.extend_from_slice(dn.as_bytes());
    let _ = s.write_all(&search);
}

fn http_get(url: &str) {
    let rest = url.strip_prefix("http://").unwrap_or(url);
    let (hostport, path) = rest.split_once('/').map(|(h, p)| (h, format!("/{p}"))).unwrap_or((rest, "/".into()));
    let Ok(mut s) = TcpStream::connect(hostport) else { return };
    let _ = s.write_all(format!("GET {path} HTTP/1.1\r\nHost: {hostport}\r\nConnection: close\r\n\r\n").as_bytes());
    let mut sink = Vec::new();
    let _ = s.read_to_end(&mut sink);
}

/// The app: `/log?q=` logs q through "Log4j"; `/xml` resolves external entities.
fn spawn_app() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut s) = stream else { continue };
            std::thread::spawn(move || {
                let mut req = Vec::new();
                let mut buf = [0u8; 8192];
                loop {
                    let Ok(n) = s.read(&mut buf) else { return };
                    if n == 0 {
                        break;
                    }
                    req.extend_from_slice(&buf[..n]);
                    if let Some(end) = req.windows(4).position(|w| w == b"\r\n\r\n") {
                        let head = String::from_utf8_lossy(&req[..end]).to_ascii_lowercase();
                        let len = head
                            .lines()
                            .find_map(|l| l.strip_prefix("content-length:"))
                            .and_then(|v| v.trim().parse::<usize>().ok())
                            .unwrap_or(0);
                        if req.len() >= end + 4 + len {
                            break;
                        }
                    }
                }
                let text = url_decode(&String::from_utf8_lossy(&req));
                let line = text.lines().next().unwrap_or("").to_string();
                if line.contains(" /log") {
                    // Only the plain lookup; the obfuscated variants are ignored.
                    if let Some(i) = text.find("${jndi:ldap://") {
                        let rest = &text[i + "${jndi:ldap://".len()..];
                        if let Some(end) = rest.find('}') {
                            if let Some((hostport, dn)) = rest[..end].split_once('/') {
                                jndi_ldap(hostport, dn);
                            }
                        }
                    }
                } else if line.contains(" /xml") {
                    if let Some(i) = text.find("SYSTEM \"http://") {
                        let rest = &text[i + "SYSTEM \"".len()..];
                        if let Some(end) = rest.find('"') {
                            http_get(&rest[..end]);
                        }
                    }
                }
                let body = "<html><body>ok</body></html>";
                let _ = s.write_all(
                    format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                        body.len()
                    )
                    .as_bytes(),
                );
            });
        }
    });
    port
}

fn setup(name: &str) -> (PathBuf, PathBuf) {
    let dir = std::env::temp_dir().join(format!("bp-oob-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let project = dir.join("p.bpdb");
    let (code, v) = run(&["engagement", "start", "--target", "127.0.0.1"], &project);
    assert_eq!(code, 0, "{v}");
    (dir, project)
}

#[test]
fn oob_confirms_log4shell_and_xxe_and_manual_payloads() {
    let (dir, project) = setup("e2e");
    let app = spawn_app();

    // Without a listener the OOB checks are skipped and say so.
    let (code, v) = run(&["oob", "payload"], &project);
    assert_eq!(code, 4, "{v}");
    let (code, v) =
        run(&["scan", "active", &format!("http://127.0.0.1:{app}/log?q=hello"), "--rules", "40043"], &project);
    assert_eq!(code, 0, "{v}");
    assert!(v["data"]["oob"].is_null(), "{v}");
    assert_eq!(v["data"]["requests"], 0, "{v}");
    assert!(v["data"]["oob_hint"].as_str().unwrap().contains("oob start"), "{v}");

    // Start the listener (host mode on loopback).
    let (code, v) = run(&["oob", "start", "--listen", "127.0.0.1:0"], &project);
    assert_eq!(code, 0, "{v}");
    let ep = &v["data"]["endpoint"];
    assert_eq!(ep["public_host"], "127.0.0.1");
    assert!(ep["domain"].is_null());
    let (code, v) = run(&["oob", "start", "--listen", "127.0.0.1:0"], &project);
    assert_eq!(code, 2, "already running is a conflict: {v}");
    assert_eq!(v["error"]["kind"], "conflict");

    // An XML endpoint in history for the XXE rule.
    let (code, v) = run(
        &[
            "send",
            "--url",
            &format!("http://127.0.0.1:{app}/xml"),
            "-X",
            "POST",
            "-H",
            "Content-Type: application/xml",
            "--data",
            "<a>b</a>",
        ],
        &project,
    );
    assert_eq!(code, 0, "{v}");
    let xml_id = v["data"]["id"].as_i64().unwrap().to_string();

    let (code, v) = run(
        &[
            "scan",
            "active",
            &format!("http://127.0.0.1:{app}/log?q=hello"),
            "--history-id",
            &xml_id,
            "--rules",
            "40043,90023",
            "--strength",
            "low",
            "--oob-wait",
            "5",
        ],
        &project,
    );
    assert_eq!(code, 0, "{v}");
    let d = &v["data"];
    assert_eq!(d["raised"]["40043-1"], 1, "{d}");
    assert_eq!(d["raised"]["90023"], 1, "{d}");
    assert!(d["raised"].get("40043-2").is_none(), "45046 patterns need DNS mode: {d}");
    // 10 Log4Shell patterns minus jndi:dns, plus one XXE payload.
    assert_eq!(d["oob"]["payloads"], 10, "{d}");
    assert!(d["oob"]["matched"].as_u64().unwrap() >= 2, "{d}");
    assert!(d["new_findings"].as_u64().unwrap() >= 2, "{d}");

    let (code, v) = run(&["findings", "list", "--source", "active", "--all"], &project);
    assert_eq!(code, 0, "{v}");
    let findings = v["data"]["items"].as_array().unwrap();
    let log4 = findings.iter().find(|f| f["alert_ref"] == "40043-1").expect("log4shell finding");
    assert_eq!(log4["param"], "q");
    let hid = log4["history_id"].as_i64().expect("attack recorded in history").to_string();
    let (code, v) = run(&["history", "show", &hid], &project);
    assert_eq!(code, 0, "{v}");
    assert!(v["data"]["request"].to_string().contains("jndi"), "{v}");
    let (code, v) = run(&["findings", "show", &log4["id"].to_string()], &project);
    assert_eq!(code, 0, "{v}");
    assert!(v["data"].to_string().contains("Received ldap interaction"), "{v}");
    assert!(v["data"].to_string().contains("${jndi:ldap://127.0.0.1:"), "{v}");

    // Manual payload, hit by hand, then polled.
    let (code, v) = run(&["oob", "payload", "--note", "ssrf in ?url="], &project);
    assert_eq!(code, 0, "{v}");
    let p = &v["data"]["payloads"][0];
    let token = p["token"].as_str().unwrap().to_string();
    http_get(p["url"].as_str().unwrap());
    let (code, v) = run(&["oob", "poll", "--token", &token, "--wait", "5"], &project);
    assert_eq!(code, 0, "{v}");
    let d = &v["data"];
    assert_eq!(d["count"], 1, "{d}");
    let i = &d["interactions"][0];
    assert_eq!(i["protocol"], "http");
    assert_eq!(i["payload"]["source"], "manual");
    assert_eq!(i["payload"]["note"], "ssrf in ?url=");
    assert!(i["summary"].as_str().unwrap().contains(&token));
    let next = d["next_since"].to_string();
    let (code, v) = run(&["oob", "poll", "--since", &next], &project);
    assert_eq!(code, 0, "{v}");
    assert_eq!(v["data"]["count"], 0, "{v}");
    let (code, v) = run(&["oob", "poll", "--token", "bpaaaaaaaaaaaaaaaaaa"], &project);
    assert_eq!(code, 4, "{v}");

    // Tables are queryable and described.
    let (code, v) =
        run(&["query", "SELECT protocol, COUNT(*) AS n FROM oob_interactions GROUP BY protocol ORDER BY 1"], &project);
    assert_eq!(code, 0, "{v}");
    let protos = v["data"]["rows"].to_string();
    assert!(protos.contains("ldap") && protos.contains("http"), "{protos}");
    let (_, v) = run(&["capabilities", "oob"], &project);
    let subs: Vec<String> = v["data"]["subcommands"]
        .as_array()
        .unwrap()
        .iter()
        .map(|c| c["command"].as_str().unwrap().to_string())
        .collect();
    for c in ["oob start", "oob stop", "oob status", "oob poll", "oob payload"] {
        assert!(subs.iter().any(|s| s == c), "{c} missing from {subs:?}");
    }

    let (code, v) = run(&["oob", "status"], &project);
    assert_eq!(code, 0, "{v}");
    assert_eq!(v["data"]["running"], true);
    assert_eq!(v["data"]["payloads"], 11, "{v}");
    let (code, v) = run(&["oob", "stop"], &project);
    assert_eq!(code, 0, "{v}");
    let (_, v) = run(&["oob", "status"], &project);
    assert_eq!(v["data"]["running"], false);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn oob_run_validates_arguments() {
    let (dir, project) = setup("args");
    let (code, v) = run(&["oob", "run", "--listen", "127.0.0.1:0", "--dns-listen", "127.0.0.1:0"], &project);
    assert_eq!(code, 2, "{v}");
    assert!(v["error"]["message"].as_str().unwrap().contains("--domain"), "{v}");
    let (code, v) = run(&["oob", "start", "--listen", "127.0.0.1:0", "--domain", "bad/domain"], &project);
    assert_eq!(code, 2, "{v}");
    let _ = std::fs::remove_dir_all(&dir);
}
