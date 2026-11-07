//! End-to-end tests for findings as records: issues, triage of a whole issue, retests against
//! a server that stops leaking, the timeline, regressions, and the posture a scan job leaves.

use std::io::{Read, Write};
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use serde_json::Value;

/// Answers every request with a page; while `leak` is set it names its framework
/// (X-Powered-By, a passive finding), and while `down` is set it answers 503.
fn serve(leak: Arc<AtomicBool>, down: Arc<AtomicBool>) -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let mut s = stream.unwrap();
            let mut buf = [0u8; 8192];
            let mut req = Vec::new();
            while !req.windows(4).any(|w| w == b"\r\n\r\n") {
                let k = s.read(&mut buf).unwrap_or(0);
                if k == 0 {
                    break;
                }
                req.extend_from_slice(&buf[..k]);
            }
            let body = "<html><body><a href=\"/a\">a</a></body></html>";
            let powered = if leak.load(Ordering::SeqCst) { "X-Powered-By: Express\r\n" } else { "" };
            let status = if down.load(Ordering::SeqCst) { "503 Service Unavailable" } else { "200 OK" };
            let resp = format!(
                "HTTP/1.1 {status}\r\nContent-Type: text/html\r\n{powered}Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            let _ = s.write_all(resp.as_bytes());
        }
    });
    port
}

fn run(project: &Path, args: &[&str]) -> (i32, Value) {
    let out = Command::new(env!("CARGO_BIN_EXE_brainproxy"))
        .env_remove("BRAINPROXY_PROJECT")
        .args(["--format", "json", "--project"])
        .arg(project)
        .args(args)
        .output()
        .unwrap();
    let v: Value = serde_json::from_slice(&out.stdout)
        .unwrap_or_else(|e| panic!("bad JSON ({e}): {}", String::from_utf8_lossy(&out.stdout)));
    (out.status.code().unwrap(), v)
}

fn ok(project: &Path, args: &[&str]) -> Value {
    let (code, v) = run(project, args);
    assert_eq!(code, 0, "{args:?}: {v}");
    v["data"].clone()
}

fn setup(name: &str) -> (PathBuf, PathBuf) {
    let dir = std::env::temp_dir().join(format!("bp-findings-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let project = dir.join("p.bpdb");
    ok(&project, &["engagement", "start", "--target", "127.0.0.1"]);
    (dir, project)
}

fn kinds(project: &Path, id: i64) -> Vec<String> {
    let t = ok(project, &["findings", "timeline", &id.to_string()]);
    t["events"].as_array().unwrap().iter().map(|e| e["kind"].as_str().unwrap().to_string()).collect()
}

#[test]
fn issues_retests_and_the_timeline() {
    let leak = Arc::new(AtomicBool::new(true));
    let down = Arc::new(AtomicBool::new(false));
    let port = serve(leak.clone(), down.clone());
    let (dir, project) = setup("retest");
    let base = format!("http://127.0.0.1:{port}");
    for path in ["/a", "/b"] {
        ok(&project, &["send", "--url", &format!("{base}{path}")]);
    }

    // One issue for the header, with both pages as its instances.
    let issues = ok(&project, &["findings", "issues"]);
    let issue = issues["issues"].as_array().unwrap().iter().find(|i| i["alert_ref"] == "10037").unwrap().clone();
    assert_eq!((issue["instances"].as_i64(), issue["host"].as_str()), (Some(2), Some("127.0.0.1")), "{issue}");
    let issue_id = issue["id"].as_i64().unwrap().to_string();
    let shown = ok(&project, &["findings", "issue", "show", &issue_id]);
    let ids: Vec<i64> = shown["findings"].as_array().unwrap().iter().map(|f| f["id"].as_i64().unwrap()).collect();
    assert_eq!(ids.len(), 2);

    // The whole issue at once.
    let marked = ok(&project, &["findings", "mark", "--issue", &issue_id, "--state", "confirmed"]);
    assert_eq!(marked["ids"].as_array().unwrap().len(), 2, "{marked}");
    let a = ids[0].to_string();

    // Still there: the state stays confirmed. Then the server stops leaking: fixed.
    let r = ok(&project, &["findings", "retest", &a]);
    assert_eq!((r["outcome"].as_str(), r["state"].as_str()), (Some("still_present"), Some("confirmed")), "{r}");
    leak.store(false, Ordering::SeqCst);
    // An error page can't show the header: that isn't taken as fixed.
    down.store(true, Ordering::SeqCst);
    let (code, v) = run(&project, &["findings", "retest", &a]);
    down.store(false, Ordering::SeqCst);
    assert_eq!((code, v["error"]["kind"].as_str()), (2, Some("conflict")), "{v}");
    assert_eq!(ok(&project, &["findings", "show", &a])["state"], "confirmed");
    let r = ok(&project, &["findings", "retest", &a]);
    assert_eq!((r["outcome"].as_str(), r["state"].as_str()), (Some("not_reproduced"), Some("fixed")), "{r}");
    assert!(r["history_id"].is_i64());
    assert_eq!(kinds(&project, ids[0]), ["created", "state", "retest", "retest", "state"]);

    // Fixed findings leave the default list. Still there again: with --no-mark only the
    // outcome is recorded, and the request is no "send" that a passive scan would reopen it by.
    let open = ok(&project, &["findings", "list", "--all"]);
    assert!(open["items"].as_array().unwrap().iter().all(|f| f["id"] != ids[0]));
    leak.store(true, Ordering::SeqCst);
    let r = ok(&project, &["findings", "retest", &a, "--no-mark"]);
    assert_eq!((r["outcome"].as_str(), r["state"].as_str()), (Some("still_present"), Some("fixed")), "{r}");
    assert_eq!(ok(&project, &["findings", "show", &a])["state"], "fixed");
    // A rule switched off can't tell, so the retest is refused rather than calling it fixed.
    ok(&project, &["scan", "disable", "10037"]);
    let (code, v) = run(&project, &["findings", "retest", &a]);
    assert_eq!((code, v["error"]["kind"].as_str()), (2, Some("conflict")), "{v}");
    ok(&project, &["scan", "enable", "10037"]);
    // A fixed one a scanner sees again in new traffic is open: a regression.
    let url = ok(&project, &["findings", "show", &a])["url"].as_str().unwrap().to_string();
    ok(&project, &["send", "--url", &url]);
    assert_eq!(ok(&project, &["findings", "show", &a])["state"], "open");
    assert_eq!(kinds(&project, ids[0]).last().unwrap(), "regressed");

    // A finding added by hand is retested by hand; an unsafe request needs --allow-unsafe.
    let manual =
        ok(&project, &["findings", "add", "--title", "IDOR", "--risk", "critical", "--url", &format!("{base}/x")]);
    let (code, v) = run(&project, &["findings", "retest", &manual["id"].to_string()]);
    assert_eq!(code, 2, "{v}");
    ok(&project, &["send", "--url", &format!("{base}/post"), "-X", "POST", "-d", "x=1"]);
    let post = ok(&project, &["findings", "list", "--all"])["items"]
        .as_array()
        .unwrap()
        .iter()
        .find(|f| f["method"] == "POST" && f["alert_ref"] == "10037")
        .unwrap()["id"]
        .to_string();
    let (code, v) = run(&project, &["findings", "retest", &post]);
    assert_eq!(code, 2, "{v}");
    assert!(v["error"]["message"].as_str().unwrap().contains("--allow-unsafe"), "{v}");

    // Split one finding off, name it, then merge it back.
    let split = ok(&project, &["findings", "issue", "split", &ids[1].to_string(), "--title", "Second app"]);
    let new = split["issue"].to_string();
    assert_eq!(ok(&project, &["findings", "issue", "show", &new])["title"], "Second app");
    assert_eq!(ok(&project, &["findings", "issue", "merge", &issue_id, &new])["moved"], 1);
    assert_eq!(kinds(&project, ids[1]).last().unwrap(), "moved");

    // Posture: the critical issue added by hand leads; the retests are counted.
    let p = ok(&project, &["findings", "posture"]);
    assert_eq!(p["open"]["issues"]["critical"], 1, "{p}");
    assert_eq!((p["retests"]["still_present"].as_i64(), p["retests"]["not_reproduced"].as_i64()), (Some(2), Some(1)));
    assert_eq!(p["regressed"], 1);
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn a_completed_scan_job_leaves_its_observations() {
    let port = serve(Arc::new(AtomicBool::new(true)), Arc::new(AtomicBool::new(false)));
    let (dir, project) = setup("observe");
    let url = format!("http://127.0.0.1:{port}/");
    let v = ok(&project, &["scan", "active", "--crawl", &url, "--rules=10045", "--background"]);
    let job = v["job"].as_i64().unwrap();
    let waited = ok(&project, &["job", "wait", &job.to_string(), "--timeout", "120"]);
    assert_eq!(waited["state"], "completed", "{waited}");
    let p = ok(&project, &["findings", "posture"]);
    let scan = p["scans"].as_array().unwrap().iter().find(|s| s["job"] == job).unwrap_or_else(|| panic!("{p}"));
    assert!(scan["new"].as_i64().unwrap() > 0, "{scan}");
    assert_eq!(scan["state"], "completed");
    std::fs::remove_dir_all(&dir).unwrap();
}
