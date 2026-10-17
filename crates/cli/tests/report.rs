//! End-to-end tests for `report`: capture traffic that triggers passive findings,
//! then render every format through the real binary.

use std::io::{Read, Write};
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::Command;

use serde_json::Value;

fn bin() -> Command {
    Command::new(env!("CARGO_BIN_EXE_brainproxy"))
}

/// Serves `n` requests with a response that trips several passive rules and
/// reflects markup that a report must never render as live HTML.
fn serve(n: usize) -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for stream in listener.incoming().take(n) {
            let mut s = stream.unwrap();
            let mut buf = [0u8; 8192];
            let mut req = Vec::new();
            while !req.windows(4).any(|w| w == b"\r\n\r\n") {
                let k = s.read(&mut buf).unwrap();
                if k == 0 {
                    break;
                }
                req.extend_from_slice(&buf[..k]);
            }
            let body = "<html><body><script>alert('x')</script> ```fence``` </body></html>";
            let resp = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nX-Powered-By: PHP/5.4.0\r\nServer: Apache/2.4.1\r\n\
                 Set-Cookie: sid=abc; Path=/\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            s.write_all(resp.as_bytes()).unwrap();
        }
    });
    port
}

fn run(args: &[&str], project: &Path) -> (i32, Value) {
    let out = bin().args(["--format", "json", "--project"]).arg(project).args(args).output().unwrap();
    let v: Value = serde_json::from_slice(&out.stdout)
        .unwrap_or_else(|e| panic!("bad JSON ({e}): {}", String::from_utf8_lossy(&out.stdout)));
    (out.status.code().unwrap(), v)
}

fn setup(name: &str) -> (PathBuf, PathBuf, u16) {
    let dir = std::env::temp_dir().join(format!("bp-report-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let project = dir.join("p.bpdb");
    let (code, v) = run(&["engagement", "start", "--target", "127.0.0.1"], &project);
    assert_eq!(code, 0, "{v}");
    let port = serve(2);
    for path in ["/a?q=1", "/b"] {
        let (code, v) = run(&["send", "--url", &format!("http://127.0.0.1:{port}{path}")], &project);
        assert_eq!(code, 0, "{v}");
    }
    (dir, project, port)
}

#[test]
fn report_formats_filters_and_files() {
    let (dir, project, port) = setup("all");

    // JSON to stdout: the envelope's data is the report.
    let (code, v) = run(&["report"], &project);
    assert_eq!(code, 0, "{v}");
    let r = &v["data"];
    let total = r["summary"]["total"].as_u64().unwrap();
    assert!(total >= 4, "{r}");
    assert_eq!(r["summary"]["truncated"], false);
    assert_eq!(r["scope"]["include"][0], "127.0.0.1");
    let alerts = r["alerts"].as_array().unwrap();
    let xpb = alerts.iter().find(|a| a["alert_ref"] == "10037").expect("X-Powered-By alert");
    assert!(!xpb["solution"].as_str().unwrap().is_empty());
    assert_eq!(xpb["instances"].as_array().unwrap().len(), 2);
    let inst = &xpb["instances"][0];
    assert_eq!(inst["request"]["method"], "GET");
    assert_eq!(inst["response"]["status"], 200);
    assert!(inst["response"]["body"]["text"].as_str().unwrap().contains("<script>"));

    // Files for every format.
    for (kind, file) in [("json", "r.json"), ("markdown", "r.md"), ("html", "r.html"), ("sarif", "r.sarif")] {
        let path = dir.join(file);
        let (code, v) = run(&["report", kind, "--output", path.to_str().unwrap()], &project);
        assert_eq!(code, 0, "{v}");
        assert_eq!(v["data"]["kind"], kind);
        assert_eq!(v["data"]["total"].as_u64().unwrap(), total);
        let content = std::fs::read_to_string(&path).unwrap();
        assert_eq!(v["data"]["bytes"].as_u64().unwrap() as usize, content.len());
        match kind {
            "json" => assert_eq!(serde_json::from_str::<Value>(&content).unwrap()["summary"]["total"], total),
            "markdown" => {
                assert!(content.starts_with("# brainproxy security report"));
                assert!(content.contains(&format!("GET http://127.0.0.1:{port}/a?q=1")));
                // The body's triple backticks can't close the evidence block early.
                assert!(content.contains("````http"));
            }
            "html" => {
                assert!(content.starts_with("<!doctype html>"));
                assert!(!content.contains("<script"));
                assert!(content.contains("&lt;script&gt;"));
                assert!(!content.contains("src=\"http") && !content.contains("<link "));
            }
            "sarif" => {
                let s: Value = serde_json::from_str(&content).unwrap();
                assert_eq!(s["version"], "2.1.0");
                assert_eq!(s["runs"][0]["results"].as_array().unwrap().len() as u64, total);
                assert_eq!(s["runs"][0]["tool"]["driver"]["name"], "brainproxy");
            }
            _ => unreachable!(),
        }
    }

    // Non-JSON formats travel as a string in the envelope.
    let (code, v) = run(&["report", "md", "--no-evidence", "--title", "Acme test"], &project);
    assert_eq!(code, 0, "{v}");
    let md = v["data"]["content"].as_str().unwrap();
    assert!(md.starts_with("# Acme test") && !md.contains("<details>"));

    // Bounded output and filters.
    let (_, v) = run(&["report", "--limit", "1", "--no-evidence"], &project);
    assert_eq!(v["data"]["summary"]["included"], 1);
    assert_eq!(v["data"]["summary"]["truncated"], true);
    let (_, v) = run(&["report", "--risk", "low", "--confidence", "medium"], &project);
    for a in v["data"]["alerts"].as_array().unwrap() {
        assert_ne!(a["risk"], "info");
        for i in a["instances"].as_array().unwrap() {
            assert_ne!(i["confidence"], "low");
        }
    }
    let (_, v) = run(&["report", "--source", "active"], &project);
    assert_eq!(v["data"]["summary"]["total"], 0);

    // Triage: false positives drop out unless asked for.
    let fid = inst["id"].as_i64().unwrap().to_string();
    let (code, _) = run(&["findings", "mark", &fid, "--state", "false_positive"], &project);
    assert_eq!(code, 0);
    let (_, v) = run(&["report", "--no-evidence"], &project);
    assert_eq!(v["data"]["summary"]["total"].as_u64().unwrap(), total - 1);
    let (_, v) = run(&["report", "--state", "false_positive"], &project);
    assert_eq!(v["data"]["summary"]["total"], 1);
    let (_, v) = run(&["findings", "list", "--all", "--confidence", "high"], &project);
    assert!(v["data"]["items"].as_array().unwrap().iter().all(|i| i["confidence"] == "high"));

    // Text mode prints the rendered report itself.
    let out = bin().args(["--format", "text", "--project"]).arg(&project).args(["report", "sarif"]).output().unwrap();
    assert!(out.status.success());
    let s: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(s["version"], "2.1.0");

    // Usage errors.
    let (code, v) = run(&["report", "pdf"], &project);
    assert_eq!(code, 2, "{v}");
    let (code, v) = run(&["report", "--limit", "0"], &project);
    assert_eq!((code, v["error"]["kind"].as_str()), (2, Some("invalid_input")));

    // capabilities describes it.
    let (_, v) = run(&["capabilities", "report"], &project);
    let flags: Vec<&str> = v["data"]["args"].as_array().unwrap().iter().filter_map(|a| a["flag"].as_str()).collect();
    for f in ["--output", "--risk", "--confidence", "--source", "--state", "--limit", "--max-evidence"] {
        assert!(flags.contains(&f), "{f} missing from {flags:?}");
    }
    let _ = std::fs::remove_dir_all(&dir);
}
