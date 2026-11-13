//! End-to-end tests for saved scan policies: `scan policy list|show|save|remove`, and
//! `scan active --policy NAME` with the flags that win over it.

use std::io::{Read, Write};
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use brainproxy_core::store::Store;
use serde_json::{json, Value};

/// Serves a `.env` file (active rule 40034, medium confidence) and a plain page otherwise.
fn serve() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let mut s = stream.unwrap();
            std::thread::spawn(move || {
                let mut buf = [0u8; 8192];
                let mut req = Vec::new();
                while !req.windows(4).any(|w| w == b"\r\n\r\n") {
                    match s.read(&mut buf) {
                        Ok(0) | Err(_) => return,
                        Ok(k) => req.extend_from_slice(&buf[..k]),
                    }
                }
                let resp = if req.starts_with(b"GET /.env ") {
                    let body = "DB_PASSWORD=hunter2\n";
                    format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len())
                } else {
                    let body = "<html><body>hi</body></html>";
                    format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                        body.len()
                    )
                };
                let _ = s.write_all(resp.as_bytes());
            });
        }
    });
    port
}

fn run_with(project: &Path, args: &[&str], stdin: Option<&str>, mcp: bool) -> (i32, Value) {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_brainproxy"));
    cmd.env_remove("BRAINPROXY_PROJECT").args(["--format", "json", "--project"]).arg(project).args(args);
    if mcp {
        cmd.env("BRAINPROXY_MCP_CALL", "1");
    }
    let mut child = cmd.stdin(Stdio::piped()).stdout(Stdio::piped()).spawn().unwrap();
    {
        let mut pipe = child.stdin.take().unwrap();
        if let Some(s) = stdin {
            // A command that fails on its arguments may exit before reading its stdin.
            let _ = pipe.write_all(s.as_bytes());
        }
    }
    let out = child.wait_with_output().unwrap();
    let v: Value = serde_json::from_slice(&out.stdout)
        .unwrap_or_else(|e| panic!("bad JSON ({e}): {}", String::from_utf8_lossy(&out.stdout)));
    (out.status.code().unwrap(), v)
}

fn run(project: &Path, args: &[&str]) -> (i32, Value) {
    run_with(project, args, None, false)
}

fn ok(project: &Path, args: &[&str]) -> Value {
    let (code, v) = run(project, args);
    assert_eq!(code, 0, "{args:?}: {v}");
    v["data"].clone()
}

fn project(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("bp-policy-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let p = dir.join("p.bpdb");
    ok(&p, &["engagement", "start", "--target", "127.0.0.1"]);
    p
}

#[test]
fn policies_are_saved_shown_listed_and_removed() {
    let p = project("crud");
    assert_eq!(ok(&p, &["scan", "policy", "list"])["policies"], json!([]));
    let saved = ok(
        &p,
        &[
            "scan",
            "policy",
            "save",
            "api",
            "--strength",
            "high",
            "--threshold",
            "medium",
            "--disable",
            "40012,40014",
            "--rule-strength",
            "40018=insane",
            "--rule-threshold",
            "40018=high",
        ],
    );
    assert_eq!((saved["strength"].as_str(), saved["threshold"].as_str()), (Some("high"), Some("medium")), "{saved}");
    assert_eq!(saved["rules_disabled"], 2);
    assert_eq!(saved["rules"]["40018"], json!({"strength": "insane", "threshold": "high"}));

    let shown = ok(&p, &["scan", "policy", "show", "api"]);
    let table = shown["rule_table"].as_array().unwrap();
    assert_eq!(table.len(), 56);
    let rule = |id: u64| table.iter().find(|r| r["id"] == id).unwrap().clone();
    assert_eq!(
        rule(40018),
        json!({"id": 40018, "name": rule(40018)["name"], "enabled": true, "strength": "insane", "threshold": "high", "own": true})
    );
    assert_eq!((rule(40012)["enabled"].as_bool(), rule(40034)["strength"].as_str()), (Some(false), Some("high")));

    // From another, changing only what's given; from JSON on stdin.
    let copy = ok(&p, &["scan", "policy", "save", "api2", "--from", "api", "--enable", "40012", "--reset", "40018"]);
    assert_eq!((copy["rules_disabled"].as_u64(), copy["rules"].get("40018")), (Some(1), None), "{copy}");
    let (code, v) = run_with(
        &p,
        &["scan", "policy", "save", "only-env", "--json", "-"],
        Some(r#"{"enabled": false, "rules": {"40034": {"enabled": true}}}"#),
        false,
    );
    assert_eq!(code, 0, "{v}");
    assert_eq!(v["data"]["rules_enabled"], 1);
    let names: Vec<_> = ok(&p, &["scan", "policy", "list"])["policies"]
        .as_array()
        .unwrap()
        .iter()
        .map(|p| p["name"].as_str().unwrap().to_string())
        .collect();
    assert_eq!(names, ["api", "api2", "only-env"]);

    // Bad input.
    assert_eq!(run(&p, &["scan", "policy", "save", "x", "--disable", "1"]).0, 4, "no rule 1");
    assert_eq!(run(&p, &["scan", "policy", "save", "x", "--rule-strength", "40018"]).0, 2);
    assert_eq!(run(&p, &["scan", "policy", "save", "x", "--json", r#"{"threshold": "off"}"#]).0, 2);
    // A misspelt field is refused, not dropped.
    let (code, v) =
        run(&p, &["scan", "policy", "save", "x", "--json", r#"{"rules": {"40018": {"treshold": "high"}}}"#]);
    assert_eq!(code, 2, "{v}");
    assert!(v["error"]["message"].as_str().unwrap().contains("treshold"), "{v}");
    assert_eq!(run(&p, &["scan", "policy", "show", "nope"]).0, 4);

    ok(&p, &["scan", "policy", "remove", "api2"]);
    assert_eq!(run(&p, &["scan", "policy", "show", "api2"]).0, 4);
    assert_eq!(run(&p, &["scan", "policy", "remove", "api2"]).0, 4);
}

/// Through MCP a policy is saved under a new name only, and none is removed.
#[test]
fn an_agent_adds_policies_and_changes_none() {
    let p = project("mcp");
    ok(&p, &["scan", "policy", "save", "mine", "--strength", "low"]);
    let (code, v) = run_with(&p, &["scan", "policy", "save", "mine", "--strength", "insane"], None, true);
    assert_eq!((code, v["error"]["kind"].as_str()), (2, Some("conflict")), "{v}");
    assert!(v["error"]["message"].as_str().unwrap().contains("new name"), "{v}");
    let (code, v) = run_with(&p, &["scan", "policy", "save", "agents", "--strength", "insane"], None, true);
    assert_eq!(code, 0, "{v}");
    let (code, v) = run_with(&p, &["scan", "policy", "remove", "mine"], None, true);
    assert_ne!(code, 0, "{v}");
    assert!(v["error"]["message"].as_str().unwrap().contains("refused through MCP"), "{v}");
    assert_eq!(ok(&p, &["scan", "policy", "show", "mine"])["strength"], "low");
}

#[test]
fn a_scan_runs_as_its_policy_says_and_flags_win() {
    let port = serve();
    let p = project("scan");
    let url = format!("http://127.0.0.1:{port}/");
    ok(&p, &["scan", "policy", "save", "env", "--others", "off", "--enable", "40034", "--strength", "low"]);
    let (code, v) = run(&p, &["scan", "active", &url, "--policy", "nope", "--no-oob"]);
    assert_eq!(code, 4, "{v}");

    let d = ok(&p, &["scan", "active", &url, "--policy", "env", "--no-oob"]);
    assert_eq!(d["rules"], 1, "{d}");
    assert_eq!(d["policy"]["name"], "env");
    assert_eq!(d["policy"]["strength"], "low");
    assert_eq!(d["policy"]["rules"], json!([40034]));
    assert_eq!(d["policy"]["flags_over_policy"], json!([]));
    assert_eq!(d["new_findings"], 1, "{d}");
    assert!(d.get("below_threshold").is_none(), "{d}");

    // Above the finding's confidence: counted, not raised.
    ok(&p, &["scan", "policy", "save", "strict", "--from", "env", "--rule-threshold", "40034=high"]);
    let d = ok(&p, &["scan", "active", &url, "--policy", "strict", "--no-oob"]);
    assert_eq!(d["raised"], json!({}), "{d}");
    assert_eq!(d["below_threshold"].as_object().unwrap().values().filter_map(Value::as_u64).sum::<u64>(), 1, "{d}");
    assert_eq!(d["policy"]["rule_thresholds"], json!({"40034": "high"}));
    assert!(d["threshold_hint"].is_string());

    // --threshold and --strength win over the policy, its rules' own settings included.
    let d =
        ok(&p, &["scan", "active", &url, "--policy", "strict", "--threshold", "low", "--strength", "high", "--no-oob"]);
    assert_eq!(d["raised"].as_object().unwrap().len(), 1, "{d}");
    assert_eq!(d["policy"]["flags_over_policy"], json!(["--strength", "--threshold"]));
    assert_eq!((d["policy"]["strength"].as_str(), d["policy"]["rule_thresholds"].clone()), (Some("high"), json!({})));

    // --rules runs what it names instead of the policy's rules.
    let d = ok(&p, &["scan", "active", &url, "--policy", "env", "--rules", "40018", "--no-oob"]);
    assert_eq!((d["rules"].as_u64(), d["policy"]["rules"].clone()), (Some(1), json!([40018])), "{d}");

    // Without a policy, --threshold on its own.
    let d = ok(&p, &["scan", "active", &url, "--rules", "40034", "--threshold", "high", "--no-oob"]);
    assert!(d.get("policy").is_none() && !d["below_threshold"].is_null(), "{d}");
}

/// A comparison with a --policy scan covers what its result says ran: not the rules it turned
/// off, and not findings below its thresholds.
#[test]
fn compare_reads_what_a_policy_scan_ran() {
    let p = project("compare");
    let store = Store::open(&p).unwrap();
    let args: Vec<String> =
        ["scan", "active", "http://127.0.0.1:1/", "--policy", "x"].iter().map(|s| s.to_string()).collect();
    let id = store.job_create("active-scan", "running", &args).unwrap();
    store.job_set_state(id, "completed", None, None, true).unwrap();
    let result = json!({"policy": {"name": "x", "strength": "medium", "threshold": "medium",
        "rule_strengths": {}, "rule_thresholds": {"40018": "high"}, "exclude_rules": [40012], "flags_over_policy": []}});
    store.job_result(id, &result).unwrap();
    let d = ok(&p, &["findings", "compare", "--scan", &id.to_string()]);
    let scope = &d["baseline"]["scope"];
    assert_eq!(scope["threshold"], "medium", "{d}");
    assert_eq!(scope["rule_thresholds"], json!({"40018": "high"}));
    assert_eq!(scope["exclude_rules"], json!([40012]));
    assert_eq!(scope["ported_rules"], true);

    // A result that doesn't say: no ported rule is covered.
    let unknown = store.job_create("active-scan", "running", &args).unwrap();
    store.job_set_state(unknown, "completed", None, None, true).unwrap();
    let d = ok(&p, &["findings", "compare", "--scan", &unknown.to_string()]);
    assert_eq!(d["baseline"]["scope"]["ported_rules"], false, "{d}");
    assert!(d["warnings"][0].as_str().unwrap().contains("policy"), "{d}");
}
