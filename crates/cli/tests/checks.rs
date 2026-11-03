//! End-to-end tests for declarative checks (`checks ...`, `scan active --checks`)
//! and runtime rule data (`scan data ...`) through the real binary.

use std::io::{Read, Write};
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::Command;

use serde_json::Value;

fn run(args: &[&str], project: &Path, home: &Path) -> (i32, Value) {
    let out = Command::new(env!("CARGO_BIN_EXE_brainproxy"))
        .args(["--format", "json", "--project"])
        .arg(project)
        .arg("--home")
        .arg(home)
        .args(args)
        .output()
        .unwrap();
    let v: Value = serde_json::from_slice(&out.stdout)
        .unwrap_or_else(|e| panic!("bad JSON ({e}): {}", String::from_utf8_lossy(&out.stdout)));
    (out.status.code().unwrap(), v)
}

/// A site with an exposed .env and a debug page.
fn serve() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut s) = stream else { continue };
            let mut buf = [0u8; 8192];
            let mut req = Vec::new();
            while !req.windows(4).any(|w| w == b"\r\n\r\n") {
                let k = s.read(&mut buf).unwrap_or(0);
                if k == 0 {
                    break;
                }
                req.extend_from_slice(&buf[..k]);
            }
            let req = String::from_utf8_lossy(&req);
            let path = req.split(' ').nth(1).unwrap_or("/");
            let (status, body) = match path {
                "/.env" => ("200 OK", "APP_KEY=base64:abc\nDB_PASSWORD=hunter2\n"),
                "/" => ("200 OK", "<html>home</html>"),
                // ZAP debug-error message that only an updated data file knows.
                "/debug" => ("200 OK", "<html>Brainproxy Test Debug Banner</html>"),
                _ => ("404 Not Found", "nope"),
            };
            let resp = format!(
                "HTTP/1.1 {status}\r\nContent-Type: text/html\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            let _ = s.write_all(resp.as_bytes());
        }
    });
    port
}

fn setup(name: &str) -> (PathBuf, PathBuf, PathBuf) {
    let dir = std::env::temp_dir().join(format!("bp-checks-cli-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join("home")).unwrap();
    let project = dir.join("p.bpdb");
    let (code, v) = run(&["engagement", "start", "--target", "127.0.0.1"], &project, &dir.join("home"));
    assert_eq!(code, 0, "{v}");
    (dir.clone(), project, dir.join("home"))
}

const ENV: &str = r#"
id: dotenv-exposed
info:
  name: Laravel .env exposed
  severity: high
  remediation: Block access to .env files.
  classification: {cwe-id: CWE-538}
  tags: exposure,config
http:
  - path: ["{{BaseURL}}/.env"]
    matchers-condition: and
    matchers:
      - type: regex
        regex: ['(?m)^DB_PASSWORD=']
      - type: status
        status: [200]
    extractors:
      - type: regex
        regex: ['APP_KEY=\S+']
"#;

#[test]
fn checks_validate_list_and_scan() {
    let (dir, project, home) = setup("scan");
    let local = home.join("checks/local");
    std::fs::create_dir_all(&local).unwrap();
    std::fs::write(local.join("env.yaml"), ENV).unwrap();
    std::fs::write(local.join("dsl.yaml"), "id: d\ninfo: {severity: low}\nhttp:\n  - path: ['{{BaseURL}}']\n    matchers:\n      - type: dsl\n        dsl: ['date_time(\"%Y\") != \"\"']\n").unwrap();

    let (code, v) = run(&["checks", "validate", local.to_str().unwrap()], &project, &home);
    assert_eq!(code, 0, "{v}");
    assert_eq!(v["data"]["ok"], 1);
    let bad = v["data"]["files"].as_array().unwrap().iter().find(|f| f["ok"] == false).unwrap();
    assert_eq!(bad["reason"], "DSL function `date_time`");
    assert_eq!(bad["kind"], "unsupported");

    let (code, v) = run(&["checks", "list", "--tags", "exposure"], &project, &home);
    assert_eq!(code, 0, "{v}");
    assert_eq!(v["data"]["matching"], 1);
    assert_eq!(v["data"]["checks"][0]["id"], "dotenv-exposed");
    assert_eq!(v["data"]["not_loaded_reasons"][0][0], "DSL function `date_time`");

    let (code, v) = run(&["checks", "status"], &project, &home);
    assert_eq!(code, 0, "{v}");
    assert_eq!(v["data"]["local_files"], 2);
    assert!(v["data"]["nuclei"].is_null());

    let port = serve();
    let url = format!("http://127.0.0.1:{port}/");
    let (code, v) = run(&["scan", "active", &url, "--checks", "local", "--no-rules"], &project, &home);
    assert_eq!(code, 0, "{v}");
    let d = &v["data"];
    assert_eq!(d["checks"]["selected"], 1, "{d}");
    assert_eq!(d["checks"]["not_loaded"], 1, "{d}");
    assert_eq!(d["rules"], 1, "only the check runs: {d}");
    assert_eq!(d["raised"]["check:dotenv-exposed"], 1, "{d}");

    let (code, v) = run(&["findings", "list", "--all"], &project, &home);
    assert_eq!(code, 0, "{v}");
    let f = v["data"]["items"].as_array().unwrap().iter().find(|f| f["alert_ref"] == "check:dotenv-exposed").cloned();
    let f = f.unwrap_or_else(|| panic!("{v}"));
    assert_eq!(f["risk"], "high");
    assert!(f["url"].as_str().unwrap().ends_with("/.env"), "{f}");
    assert!(f["evidence"].as_str().unwrap().starts_with("DB_PASSWORD="), "{f}");
    let (code, v) = run(&["findings", "show", &f["id"].to_string()], &project, &home);
    assert_eq!(code, 0, "{v}");
    assert_eq!(v["data"]["cwe"], 538, "{v}");
    assert!(v["data"]["other_info"].as_str().unwrap().contains("APP_KEY=base64:abc"), "{v}");

    // The report carries the template's remediation as the solution.
    let (code, v) = run(&["report", "--alert", "check:dotenv-exposed"], &project, &home);
    assert_eq!(code, 0, "{v}");
    assert_eq!(v["data"]["alerts"][0]["solution"], "Block access to .env files.", "{v}");

    // Filters that select nothing are an error, not a silent no-op; so is --no-rules alone.
    let (code, v) = run(&["scan", "active", &url, "--checks", "local", "--check-tags", "nope"], &project, &home);
    assert_eq!(code, 2, "{v}");
    let (code, v) = run(&["scan", "active", &url, "--no-rules"], &project, &home);
    assert_eq!(code, 2, "{v}");
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn check_severity_band() {
    let (dir, project, home) = setup("band");
    let local = home.join("checks/local");
    std::fs::create_dir_all(&local).unwrap();
    for sev in ["low", "medium", "high", "critical"] {
        let t =
            ENV.replace("dotenv-exposed", &format!("sev-{sev}")).replace("severity: high", &format!("severity: {sev}"));
        std::fs::write(local.join(format!("{sev}.yaml")), t).unwrap();
    }
    // An included tag runs whatever the bounds say.
    let tagged = ENV.replace("dotenv-exposed", "sev-tagged").replace("severity: high", "severity: critical");
    std::fs::write(local.join("tagged.yaml"), tagged.replace("tags: exposure,config", "tags: pick")).unwrap();
    let port = serve();
    let url = format!("http://127.0.0.1:{port}/");
    let scan = |extra: &[&str]| {
        let mut args = vec!["scan", "active", &url, "--checks", "local", "--no-rules"];
        args.extend_from_slice(extra);
        let (code, v) = run(&args, &project, &home);
        assert_eq!(code, 0, "{v}");
        let mut raised: Vec<String> = v["data"]["raised"]
            .as_object()
            .unwrap()
            .keys()
            .filter_map(|k| k.strip_prefix("check:sev-").map(String::from))
            .collect();
        raised.sort();
        raised
    };
    assert_eq!(scan(&["--check-severity-max", "medium"]), ["low", "medium"]);
    assert_eq!(scan(&["--check-severity", "high", "--check-severity-max", "high"]), ["high"]);
    assert_eq!(scan(&["--check-severity", "critical"]), ["critical", "tagged"]);
    assert_eq!(scan(&["--check-severity-max", "low", "--check-include-tags", "pick"]), ["low", "tagged"]);

    let (code, v) = run(
        &["scan", "active", &url, "--checks", "local", "--check-severity", "high", "--check-severity-max", "low"],
        &project,
        &home,
    );
    assert_eq!(code, 2, "{v}");
    assert!(
        v["error"]["message"].as_str().unwrap().contains("--check-severity-max low is below --check-severity high"),
        "{v}"
    );

    let (code, v) = run(&["checks", "list", "local", "--severity-max", "medium"], &project, &home);
    assert_eq!(code, 0, "{v}");
    let mut ids: Vec<&str> =
        v["data"]["checks"].as_array().unwrap().iter().map(|c| c["id"].as_str().unwrap()).collect();
    ids.sort();
    assert_eq!(ids, ["sev-low", "sev-medium"], "{v}");
    let (code, v) = run(&["checks", "list", "local", "--severity", "high", "--severity-max", "low"], &project, &home);
    assert_eq!(code, 2, "{v}");
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn checks_update_from_dir_and_scan_nuclei_store() {
    let (dir, project, home) = setup("nuclei");
    let src = dir.join("nuclei-templates");
    std::fs::create_dir_all(src.join("http/exposures/configs")).unwrap();
    std::fs::write(src.join("http/exposures/configs/env.yaml"), ENV).unwrap();
    std::fs::write(
        src.join("http/exposures/configs/flow.yaml"),
        "id: f\ninfo: {severity: low}\nself-contained: true\nhttp: []\n",
    )
    .unwrap();
    // A template taking an input (`{{env_file}}`) is stored for later --check-var.
    let input = ENV.replace("dotenv-exposed", "dotenv-input").replace("/.env", "/{{env_file}}");
    std::fs::write(src.join("http/exposures/configs/input.yaml"), input).unwrap();
    let (code, v) = run(&["checks", "update", "--from", src.to_str().unwrap()], &project, &home);
    assert_eq!(code, 0, "{v}");
    assert_eq!(v["data"]["templates"], 3);
    assert_eq!(v["data"]["stored"], 2);

    let port = serve();
    let url = format!("http://127.0.0.1:{port}/");
    let (code, v) =
        run(&["scan", "active", &url, "--checks", "nuclei", "--no-rules", "--check-severity", "high"], &project, &home);
    assert_eq!(code, 0, "{v}");
    assert_eq!(v["data"]["raised"]["check:dotenv-exposed"], 1, "{v}");
    assert!(v["data"]["raised"]["check:dotenv-input"].is_null(), "{v}");
    assert_eq!(
        v["data"]["checks"]["not_loaded_reasons"][0][0], "template inputs without a value (--check-var): env_file",
        "{v}"
    );
    let (code, v) = run(&["checks", "list", "nuclei", "--check-var", "env_file=.env"], &project, &home);
    assert_eq!((code, v["data"]["loaded"].as_i64()), (0, Some(2)), "{v}");
    let (code, v) = run(
        &[
            "scan",
            "active",
            &url,
            "--checks",
            "nuclei",
            "--no-rules",
            "--check-ids",
            "dotenv-input",
            "--check-var",
            "env_file=.env",
        ],
        &project,
        &home,
    );
    assert_eq!(code, 0, "{v}");
    assert_eq!(v["data"]["raised"]["check:dotenv-input"], 1, "{v}");
    let (code, v) = run(&["checks", "list", "--check-var", "no-equals"], &project, &home);
    assert_eq!(code, 2, "{v}");

    // Background mode returns a job.
    let (code, v) = run(&["checks", "update", "--from", src.to_str().unwrap(), "--background"], &project, &home);
    assert_eq!(code, 0, "{v}");
    let job = v["data"]["job"].as_i64().unwrap().to_string();
    let (code, v) = run(&["job", "wait", &job, "--timeout", "60"], &project, &home);
    assert_eq!(code, 0, "{v}");
    assert_eq!(v["data"]["state"], "completed", "{v}");
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn scan_data_update_status_reset() {
    let (dir, project, home) = setup("data");
    let (code, v) = run(&["scan", "data", "status"], &project, &home);
    assert_eq!(code, 0, "{v}");
    assert!(v["data"]["files"].as_array().unwrap().iter().all(|f| f["active"] == "embedded"));

    // A directory holding the files by name; only debug-error-messages.txt differs.
    let src = dir.join("zapdata");
    std::fs::create_dir_all(&src).unwrap();
    let repo = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let sync: Value = serde_json::from_slice(&std::fs::read(repo.join("zap-sync.json")).unwrap()).unwrap();
    for f in sync["data_files"].as_array().unwrap() {
        let ours = repo.join(f["ours"].as_str().unwrap());
        std::fs::copy(&ours, src.join(ours.file_name().unwrap())).unwrap();
    }
    let debug = src.join("debug-error-messages.txt");
    let mut text = std::fs::read_to_string(&debug).unwrap();
    text.push_str("\nBrainproxy Test Debug Banner\n");
    std::fs::write(&debug, text).unwrap();

    let (code, v) = run(&["scan", "data", "update", "--from", src.to_str().unwrap()], &project, &home);
    assert_eq!(code, 0, "{v}");
    assert_eq!(v["data"]["updated"].as_array().unwrap().len(), sync["data_files"].as_array().unwrap().len(), "{v}");
    let (_, v) = run(&["scan", "data", "status"], &project, &home);
    let dbg = v["data"]["files"].as_array().unwrap().iter().find(|f| f["name"] == "debug-error-messages.txt").unwrap();
    assert_eq!(dbg["active"], "downloaded");
    assert_eq!(dbg["entries"].as_u64().unwrap(), dbg["embedded_entries"].as_u64().unwrap() + 1);

    // The passive rule picks up the new message.
    let port = serve();
    let (code, v) = run(&["send", "--url", &format!("http://127.0.0.1:{port}/debug")], &project, &home);
    assert_eq!(code, 0, "{v}");
    let (_, v) = run(&["findings", "list"], &project, &home);
    assert!(v.to_string().contains("\"10023\""), "debug error finding expected: {v}");

    let (code, v) = run(&["scan", "data", "reset"], &project, &home);
    assert_eq!(code, 0, "{v}");
    assert_eq!(v["data"]["removed"], true);
    std::fs::remove_dir_all(&dir).unwrap();
}

/// A JSON API on `/` that, with `decode`, reads Brotli request bodies like Express 5
/// (the probe's two streams stand for "{}" and "{"), and otherwise refuses them with
/// 415 like Express 4.
fn serve_json(decode: bool) -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut s) = stream else { continue };
            let mut buf = [0u8; 8192];
            let mut req = Vec::new();
            let body = loop {
                let k = s.read(&mut buf).unwrap_or(0);
                req.extend_from_slice(&buf[..k]);
                let Some(end) = req.windows(4).position(|w| w == b"\r\n\r\n") else {
                    if k == 0 {
                        break Vec::new();
                    }
                    continue;
                };
                let head = String::from_utf8_lossy(&req[..end]).to_ascii_lowercase();
                let len: usize = head
                    .lines()
                    .find_map(|l| l.strip_prefix("content-length:"))
                    .and_then(|v| v.trim().parse().ok())
                    .unwrap_or(0);
                if req.len() >= end + 4 + len || k == 0 {
                    break req[end + 4..].to_vec();
                }
            };
            let head = String::from_utf8_lossy(&req).to_ascii_lowercase();
            let br = head.contains("content-encoding: br");
            let text = match (br, body.as_slice()) {
                (false, b) => String::from_utf8_lossy(b).into_owned(),
                (true, [0x8f, 0x00, 0x80, 0x7b, 0x7d, 0x03]) => "{}".into(),
                (true, [0x0f, 0x00, 0x80, 0x7b, 0x03]) => "{".into(),
                (true, _) => "?".into(),
            };
            let status = if br && !decode {
                "415 Unsupported Media Type"
            } else if text == "{}" || text.is_empty() {
                "404 Not Found"
            } else {
                "400 Bad Request"
            };
            let resp = format!("HTTP/1.1 {status}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
            let _ = s.write_all(resp.as_bytes());
        }
    });
    port
}

#[test]
fn feed_checks_update_scan_and_switch_off() {
    let (dir, project, home) = setup("feed");
    let repo = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let (code, v) =
        run(&["checks", "update", "--source", "brainproxy", "--from", repo.to_str().unwrap()], &project, &home);
    assert_eq!(code, 0, "{v}");
    assert!(!v["data"]["signed_by"].as_str().unwrap().is_empty());
    assert!(v["data"]["changes"]["added"].as_array().unwrap().len() >= 2, "{v}");
    let (_, v) =
        run(&["checks", "update", "--source", "brainproxy", "--from", repo.to_str().unwrap()], &project, &home);
    assert_eq!(v["data"]["changes"]["added"].as_array().unwrap().len(), 0, "nothing new the second time: {v}");

    // The active probe: Express 5-like servers decode Brotli bodies, Express 4-like ones refuse them.
    let found = |port: u16| {
        let url = format!("http://127.0.0.1:{port}/");
        let (code, v) = run(
            &[
                "scan",
                "active",
                &url,
                "--no-rules",
                "--checks",
                "brainproxy",
                "--check-ids",
                "bp-brotli-request-body-decoded",
            ],
            &project,
            &home,
        );
        assert_eq!(code, 0, "{v}");
        let (_, f) = run(
            &["query", &format!("select count(*) from findings where alert_ref = 'check:bp-brotli-request-body-decoded' and url like '%:{port}/%'")],
            &project,
            &home,
        );
        f["data"]["rows"][0][0].as_i64().unwrap()
    };
    assert_eq!(found(serve_json(true)), 1);
    assert_eq!(found(serve_json(false)), 0);

    // Passive feed checks are listed with the passive rules and can be switched off.
    let (code, v) = run(&["scan", "disable", "bp-brotli-request-body-accepted"], &project, &home);
    assert_eq!(code, 0, "{v}");
    assert_eq!(v["data"]["disabled_checks"][0], "bp-brotli-request-body-accepted");
    let (_, v) = run(&["scan", "rules", "--filter", "brotli"], &project, &home);
    let rule = &v["data"]["rules"][0];
    assert_eq!(
        (rule["id"].as_str(), rule["enabled"].as_bool()),
        (Some("bp-brotli-request-body-accepted"), Some(false))
    );
    let (code, _) = run(&["scan", "disable", "no-such-check"], &project, &home);
    assert_eq!(code, 4);
    std::fs::remove_dir_all(&dir).unwrap();
}

/// A template an agent could write anywhere: a DELETE whose matcher never matches.
const DELETE_PROBE: &str = r#"
id: delete-probe
info: {name: Delete probe, severity: info}
http:
  - raw:
      - |
        DELETE /items/1 HTTP/1.1
        Host: {{Hostname}}

    matchers:
      - type: word
        words: ["never in a response"]
"#;

#[test]
fn a_check_file_from_a_tool_call_sends_only_what_is_opted_in_and_on_record() {
    let (dir, project, home) = setup("mcp-file");
    let file = dir.join("probe.yaml");
    std::fs::write(&file, DELETE_PROBE).unwrap();
    let port = serve();
    let url = format!("http://127.0.0.1:{port}/");
    let scan = |extra: &[&str]| {
        let out = Command::new(env!("CARGO_BIN_EXE_brainproxy"))
            .env("BRAINPROXY_MCP_CALL", "1")
            .args(["--format", "json", "--project"])
            .arg(&project)
            .arg("--home")
            .arg(&home)
            .args(["scan", "active", &url, "--no-rules", "--checks", file.to_str().unwrap()])
            .args(extra)
            .output()
            .unwrap();
        let v: Value = serde_json::from_slice(&out.stdout).unwrap();
        assert_eq!(out.status.code(), Some(0), "{v}");
        v
    };
    let rows = || {
        let sql = "SELECT method, path, source, origin FROM history WHERE method = 'DELETE'";
        run(&["query", sql], &project, &home).1["data"]["rows"].clone()
    };
    let v = scan(&[]);
    assert_eq!(v["data"]["check_skipped_methods"], 1, "{v}");
    assert!(v["data"]["check_methods_hint"].as_str().unwrap().contains("--include-methods"), "{v}");
    assert_eq!(rows(), serde_json::json!([]));
    let v = scan(&["--include-methods", "DELETE"]);
    assert_eq!(v["data"]["check_skipped_methods"], 0, "{v}");
    assert_eq!(rows(), serde_json::json!([["DELETE", "/items/1", "scan", "mcp"]]));
    std::fs::remove_dir_all(&dir).unwrap();
}
