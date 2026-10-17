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
    std::fs::write(local.join("dsl.yaml"), "id: d\ninfo: {severity: low}\nhttp:\n  - path: ['{{BaseURL}}']\n    matchers:\n      - type: dsl\n        dsl: ['true']\n").unwrap();

    let (code, v) = run(&["checks", "validate", local.to_str().unwrap()], &project, &home);
    assert_eq!(code, 0, "{v}");
    assert_eq!(v["data"]["ok"], 1);
    let bad = v["data"]["files"].as_array().unwrap().iter().find(|f| f["ok"] == false).unwrap();
    assert_eq!(bad["reason"], "matcher `dsl`");
    assert_eq!(bad["kind"], "unsupported");

    let (code, v) = run(&["checks", "list", "--tags", "exposure"], &project, &home);
    assert_eq!(code, 0, "{v}");
    assert_eq!(v["data"]["matching"], 1);
    assert_eq!(v["data"]["checks"][0]["id"], "dotenv-exposed");
    assert_eq!(v["data"]["not_loaded_reasons"][0][0], "matcher `dsl`");

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
fn checks_update_from_dir_and_scan_nuclei_store() {
    let (dir, project, home) = setup("nuclei");
    let src = dir.join("nuclei-templates");
    std::fs::create_dir_all(src.join("http/exposures/configs")).unwrap();
    std::fs::write(src.join("http/exposures/configs/env.yaml"), ENV).unwrap();
    std::fs::write(
        src.join("http/exposures/configs/flow.yaml"),
        "id: f\ninfo: {severity: low}\nflow: http(1)\nhttp: []\n",
    )
    .unwrap();
    let (code, v) = run(&["checks", "update", "--from", src.to_str().unwrap()], &project, &home);
    assert_eq!(code, 0, "{v}");
    assert_eq!(v["data"]["templates"], 2);
    assert_eq!(v["data"]["stored"], 1);

    let port = serve();
    let url = format!("http://127.0.0.1:{port}/");
    let (code, v) =
        run(&["scan", "active", &url, "--checks", "nuclei", "--no-rules", "--check-severity", "high"], &project, &home);
    assert_eq!(code, 0, "{v}");
    assert_eq!(v["data"]["raised"]["check:dotenv-exposed"], 1, "{v}");

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
    assert_eq!(v["data"]["updated"].as_array().unwrap().len(), 4, "{v}");
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
