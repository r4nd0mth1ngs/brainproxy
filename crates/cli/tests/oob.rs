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

/// The app: `/log?q=` logs q through "Log4j"; `/xml` resolves external entities;
/// `/fetch?url=` fetches the URL (SSRF).
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
                } else if line.contains(" /fetch?url=http://") {
                    let url = line.split(" /fetch?url=").nth(1).and_then(|r| r.split(' ').next()).unwrap_or("");
                    http_get(url);
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
    // 10 Log4Shell patterns minus jndi:dns at each of `q` and the XML value, plus one XXE payload.
    assert_eq!(d["oob"]["payloads"], 19, "{d}");
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
    assert_eq!(v["data"]["payloads"], 20, "{v}");
    let (code, v) = run(&["oob", "stop"], &project);
    assert_eq!(code, 0, "{v}");
    let (_, v) = run(&["oob", "status"], &project);
    assert_eq!(v["data"]["running"], false);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn oob_confirms_ssrf() {
    let (dir, project) = setup("ssrf");
    let app = spawn_app();
    let url = format!("http://127.0.0.1:{app}/fetch?url=home");

    // Nothing to correlate with, so nothing is sent.
    let (code, v) = run(&["scan", "active", &url, "--rules", "40046"], &project);
    assert_eq!(code, 0, "{v}");
    assert_eq!(v["data"]["requests"], 0, "{v}");

    let (code, v) = run(&["oob", "start", "--listen", "127.0.0.1:0"], &project);
    assert_eq!(code, 0, "{v}");
    let (code, v) = run(&["scan", "active", &url, "--rules", "40046", "--oob-wait", "5"], &project);
    assert_eq!(code, 0, "{v}");
    let d = &v["data"];
    assert_eq!(d["raised"]["40046"], 1, "{d}");
    // Host mode can't tell an https fetch: only the http payload goes out.
    assert_eq!(d["oob"]["payloads"], 1, "{d}");

    let (code, v) = run(&["findings", "list", "--source", "active", "--all"], &project);
    assert_eq!(code, 0, "{v}");
    let found = v["data"]["items"].as_array().unwrap();
    let ssrf = found.iter().find(|f| f["alert_ref"] == "40046").expect("ssrf finding");
    assert_eq!(ssrf["param"], "url");

    let (code, v) = run(&["oob", "stop"], &project);
    assert_eq!(code, 0, "{v}");
    let _ = std::fs::remove_dir_all(&dir);
}

#[cfg(target_os = "linux")]
#[test]
fn listener_in_another_namespace_is_not_taken_for_dead() {
    use brainproxy_core::oob::STATE_KEY;
    let (dir, project) = setup("namespace");
    let (code, v) = run(&["oob", "start", "--listen", "127.0.0.1:0"], &project);
    assert_eq!(code, 0, "{v}");

    // As another container sees it: the same pid, another namespace.
    let store = brainproxy_core::store::Store::open(&project).unwrap();
    let mut state: Value = serde_json::from_str(&store.meta_get(STATE_KEY).unwrap().unwrap()).unwrap();
    assert!(state["pid_ns"].as_str().is_some_and(|ns| ns.starts_with("pid:[")), "{state}");
    state["pid_ns"] = "pid:[1]".into();
    store.meta_set(STATE_KEY, Some(&state.to_string())).unwrap();

    for _ in 0..2 {
        let (code, v) = run(&["oob", "status"], &project);
        assert_eq!(code, 0, "{v}");
        assert_eq!((&v["data"]["running"], &v["data"]["other_pid_namespace"]), (&true.into(), &true.into()), "{v}");
    }
    let (code, v) = run(&["oob", "start", "--listen", "127.0.0.1:0"], &project);
    assert_ne!(code, 0, "{v}");
    assert!(v.to_string().contains("another container"), "{v}");

    let (code, v) = run(&["oob", "stop"], &project);
    assert_eq!((code, &v["data"]["forced"]), (0, &false.into()), "{v}");
    let (_, v) = run(&["oob", "status"], &project);
    assert_eq!(v["data"]["running"], false, "{v}");
    let _ = std::fs::remove_dir_all(dir);
}

/// Its lock file can't be read here: see the proxy's test. Permissions don't bind root.
#[cfg(target_os = "linux")]
#[test]
fn listener_record_that_cannot_be_verified() {
    use brainproxy_core::oob::STATE_KEY;
    use std::os::unix::fs::PermissionsExt;
    let (dir, project) = setup("unverified");
    let lock = dir.join("p.bpdb-oob.lock");
    let (code, v) = run(&["oob", "start", "--listen", "127.0.0.1:0"], &project);
    assert_eq!(code, 0, "{v}");
    let pid = v["data"]["pid"].as_u64().unwrap();

    let store = brainproxy_core::store::Store::open(&project).unwrap();
    let mut state: Value = serde_json::from_str(&store.meta_get(STATE_KEY).unwrap().unwrap()).unwrap();
    state["pid_ns"] = "pid:[1]".into();
    store.meta_set(STATE_KEY, Some(&state.to_string())).unwrap();

    let (code, v) = run(&["oob", "stop", "--forget"], &project);
    assert_eq!((code, v["error"]["kind"].as_str()), (2, Some("conflict")), "{v}");

    assert!(Command::new("kill").args(["-9", &pid.to_string()]).status().unwrap().success());
    std::fs::set_permissions(&lock, std::fs::Permissions::from_mode(0o000)).unwrap();
    if std::fs::File::open(&lock).is_err() {
        std::thread::sleep(std::time::Duration::from_millis(200));
        let (_, v) = run(&["oob", "status"], &project);
        assert_eq!(v["data"]["running"], false, "{v}");
        assert_eq!(v["data"]["unverified"]["pid"].as_u64(), Some(pid), "{v}");
        let (code, v) = run(&["oob", "start", "--listen", "127.0.0.1:0"], &project);
        assert_ne!(code, 0, "{v}");
        assert!(v.to_string().contains("stop --forget"), "{v}");
        let (code, v) = run(&["oob", "stop", "--forget"], &project);
        assert_eq!((code, v["data"]["forgotten"].as_u64()), (0, Some(pid)), "{v}");
        let (_, v) = run(&["oob", "status"], &project);
        assert_eq!(v["data"]["unverified"], Value::Null, "{v}");
    }
    let _ = std::fs::remove_dir_all(dir);
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

/// Nuclei interactsh templates: `{{interactsh-url}}` becomes a listener
/// payload, and interactsh matchers decide at correlation.
#[test]
fn interactsh_templates_use_the_listener() {
    let (dir, project) = setup("interactsh");
    let app = spawn_app();
    let checks = dir.join("checks");
    std::fs::create_dir_all(&checks).unwrap();
    let t = |id: &str, path: &str, matchers: &str| {
        format!(
            "id: {id}\ninfo: {{name: {id}, severity: high, tags: oast}}\nhttp:\n  - method: GET\n    path: ['{{{{BaseURL}}}}{path}']\n    matchers-condition: and\n    matchers:\n{matchers}"
        )
    };
    let proto = |p: &str| format!("      - type: word\n        part: interactsh_protocol\n        words: [{p}]\n");
    let status = |c: u16| format!("      - type: status\n        status: [{c}]\n");
    let files = [
        ("ssrf", t("ssrf", "/fetch?url=http://{{interactsh-url}}/a", &(proto("http") + &status(200)))),
        // The callback is HTTP; host mode has no DNS.
        (
            "ssrf-dns",
            t(
                "ssrf-dns",
                "/fetch?url=http://{{interactsh-url}}/b",
                "      - type: dsl\n        dsl: ['contains(interactsh_protocol, \"dns\") && status_code == 200']\n",
            ),
        ),
        ("no-callback", t("no-callback", "/other?url=http://{{interactsh-url}}/c", &proto("http"))),
        // The response fails the other matcher: nothing to wait for.
        ("wrong-status", t("wrong-status", "/fetch?url=http://{{interactsh-url}}/d", &(proto("http") + &status(418)))),
    ];
    for (name, text) in &files {
        std::fs::write(checks.join(format!("{name}.yaml")), text).unwrap();
    }
    let dir_arg = checks.to_str().unwrap();

    let (code, v) = run(&["checks", "validate", dir_arg], &project);
    assert_eq!(code, 0, "{v}");
    assert_eq!(v["data"]["ok"], 0, "{v}");
    assert_eq!(
        v["data"]["files"][0]["reason"], "interactsh (out-of-band): needs an OOB listener (brainproxy oob start)",
        "{v}"
    );

    let (code, v) = run(&["oob", "start", "--listen", "127.0.0.1:0"], &project);
    assert_eq!(code, 0, "{v}");
    let (code, v) = run(&["checks", "validate", dir_arg], &project);
    assert_eq!((code, v["data"]["ok"].as_i64()), (0, Some(4)), "{v}");

    let url = format!("http://127.0.0.1:{app}/");
    let (code, v) = run(
        &["scan", "active", &url, "--checks", dir_arg, "--no-rules", "--check-exclude-tags", "", "--oob-wait", "3"],
        &project,
    );
    assert_eq!(code, 0, "{v}");
    let d = &v["data"];
    assert_eq!(d["raised"]["check:ssrf"], 1, "{d}");
    for id in ["ssrf-dns", "no-callback", "wrong-status"] {
        assert!(d["raised"].get(format!("check:{id}")).is_none(), "{id}: {d}");
    }
    assert_eq!(d["oob"]["payloads"], 3, "wrong-status isn't registered: {d}");
    assert_eq!(d["oob"]["matched"], 1, "{d}");

    let (code, v) = run(&["findings", "list", "--source", "active", "--all"], &project);
    assert_eq!(code, 0, "{v}");
    let f = v["data"]["items"].as_array().unwrap().iter().find(|f| f["alert_ref"] == "check:ssrf").cloned().unwrap();
    assert!(f["url"].as_str().unwrap().contains("/fetch?url=http://127.0.0.1:"), "{f}");
    let (code, v) = run(&["findings", "show", &f["id"].to_string()], &project);
    assert_eq!(code, 0, "{v}");
    let info = v["data"]["other_info"].as_str().unwrap();
    assert!(info.contains("Check ssrf") && info.contains("Received http interaction"), "{info}");
    assert_eq!(v["data"]["risk"], "high");

    let (code, _) = run(&["oob", "stop"], &project);
    assert_eq!(code, 0);
    std::fs::remove_dir_all(&dir).unwrap();
}
