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
            let mut powered = if leak.load(Ordering::SeqCst) { "X-Powered-By: Express\r\n" } else { "" }.to_string();
            // /c sets a session cookie, without its flags, only for a request that has none.
            let text = String::from_utf8_lossy(&req).to_ascii_lowercase();
            if text.starts_with("get /c ") && !text.contains("\r\ncookie:") {
                powered.push_str("Set-Cookie: sid=abc123; Path=/\r\n");
            }
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
    assert_eq!(issue["hosts"][0], "127.0.0.1", "{issue}");
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
    // Nor is it a sighting: the finding is left exactly as it was.
    let before = ok(&project, &["findings", "show", &a]);
    let r = ok(&project, &["findings", "retest", &a, "--no-mark"]);
    assert_eq!((r["outcome"].as_str(), r["state"].as_str()), (Some("still_present"), Some("fixed")), "{r}");
    let after = ok(&project, &["findings", "show", &a]);
    assert_eq!(
        (after["state"].as_str(), &after["hits"], &after["last_history_id"]),
        (Some("fixed"), &before["hits"], &before["last_history_id"])
    );
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
    // So is a GET that a method-override header turns into a DELETE.
    ok(&project, &["send", "--url", &format!("{base}/del"), "-H", "X-HTTP-Method-Override: DELETE"]);
    let del = ok(&project, &["findings", "list", "--all"])["items"]
        .as_array()
        .unwrap()
        .iter()
        .find(|f| f["url"].as_str().unwrap().ends_with("/del") && f["alert_ref"] == "10037")
        .unwrap()["id"]
        .to_string();
    let (code, v) = run(&project, &["findings", "retest", &del]);
    assert!(code == 2 && v["error"]["message"].as_str().unwrap().contains("DELETE"), "{v}");

    // A cookie the server sets only for a request without one: retested with a session, the
    // reply sets no cookie at all, which isn't "fixed".
    ok(&project, &["send", "--url", &format!("{base}/c")]);
    let cookie = ok(&project, &["findings", "list", "--all"])["items"]
        .as_array()
        .unwrap()
        .iter()
        .find(|f| f["url"].as_str().unwrap().ends_with("/c") && f["alert_ref"] == "10010")
        .expect("a cookie without HttpOnly")["id"]
        .to_string();
    ok(&project, &["auth", "add", "u", "--header", "Cookie: sid=valid"]);
    let (code, v) = run(&project, &["findings", "retest", &cookie, "--auth", "u"]);
    assert_eq!((code, v["error"]["kind"].as_str()), (2, Some("conflict")), "{v}");
    assert_eq!(ok(&project, &["findings", "show", &cookie])["state"], "open");

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

/// An item page whose `q` goes into SQL as it is: a quote in it gets a database error.
fn serve_sql() -> u16 {
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
                        return;
                    }
                    req.extend_from_slice(&buf[..k]);
                }
                let line = String::from_utf8_lossy(&req).lines().next().unwrap_or_default().to_string();
                let quoted = ["'", "%27", "\"", "%22"].iter().any(|q| line.contains(q));
                let (status, body) = if quoted {
                    (
                        "500 Internal Server Error",
                        "<p>You have an error in your SQL syntax; check the manual that corresponds to your MySQL \
                         server version for the right syntax to use</p>"
                            .to_string(),
                    )
                } else {
                    ("200 OK", "<html><body><p>item</p></body></html>".to_string())
                };
                let resp = format!(
                    "HTTP/1.1 {status}\r\nContent-Type: text/html\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = s.write_all(resp.as_bytes());
            });
        }
    });
    port
}

#[test]
fn a_finding_is_sent_with_and_without_its_payload() {
    let port = serve_sql();
    let (dir, project) = setup("verify");
    let sent = ok(&project, &["send", "--url", &format!("http://127.0.0.1:{port}/item?q=hi")]);
    let base = sent["id"].as_i64().unwrap_or_else(|| panic!("{sent}"));
    ok(&project, &["scan", "active", "--history-id", &base.to_string(), "--rules=40018", "--strength", "low"]);
    let list = ok(&project, &["findings", "list", "--all", "--source", "active"]);
    let f = list["items"]
        .as_array()
        .unwrap_or_else(|| panic!("{list}"))
        .iter()
        .find(|f| f["alert_ref"].as_str().unwrap().starts_with("40018"))
        .unwrap_or_else(|| panic!("{list}"))
        .clone();
    let id = f["id"].to_string();

    // The finding names the request the scan started from.
    let shown = ok(&project, &["findings", "show", &id]);
    assert_eq!(shown["base_history_id"], base, "{shown}");
    assert!(!shown["attack"].as_str().unwrap().is_empty(), "{shown}");

    // Sent again, twice each: the error only with the payload.
    let v = ok(&project, &["findings", "verify", &id, "--repeat", "2"]);
    assert_eq!(v["baseline_from"], "scan", "{v}");
    assert_eq!((v["without"]["status"].as_u64(), v["with"]["status"].as_u64()), (Some(200), Some(500)), "{v}");
    assert_eq!(v["without"]["request_history_id"], base);
    assert_eq!(v["with"]["request_history_id"], shown["history_id"]);
    assert_eq!(
        (v["without"]["history_ids"].as_array().unwrap().len(), v["with"]["sends"].as_array().unwrap().len()),
        (2, 2)
    );
    assert_eq!((v["without"]["evidence"].as_u64(), v["with"]["evidence"].as_u64()), (Some(0), Some(2)), "{v}");
    let d = &v["differences"];
    assert_eq!(
        (d["status_changed"].as_bool(), d["evidence_only_with_payload"].as_bool()),
        (Some(true), Some(true)),
        "{d}"
    );
    assert!(d["length_delta"].as_i64().unwrap() > 0, "{d}");
    assert_eq!(d["body"]["identical"], false, "{d}");
    // Recorded like a retest's requests, which the background passive scan leaves alone.
    let row = ok(&project, &["history", "show", &v["with"]["history_ids"][0].to_string()]);
    assert_eq!(row["entry"]["source"], "retest", "{row}");

    // An edited attack from stdin: no quote, so no error either.
    let edited = format!("GET /item?q=hi2 HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n\r\n");
    let out = Command::new(env!("CARGO_BIN_EXE_brainproxy"))
        .args(["--format", "json", "--project"])
        .arg(&project)
        .args(["findings", "verify", &id, "--request", "-"])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .spawn()
        .and_then(|mut c| {
            c.stdin.take().unwrap().write_all(edited.as_bytes())?;
            c.wait_with_output()
        })
        .unwrap();
    let e: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(
        (e["data"]["edited_request"].as_bool(), e["data"]["with"]["status"].as_u64()),
        (Some(true), Some(200)),
        "{e}"
    );
    assert_eq!(e["data"]["differences"]["status_changed"], false, "{e}");

    // A finding from before the baseline was recorded: one in history with only the payload
    // changed stands in for it.
    let conn = rusqlite::Connection::open(&project).unwrap();
    conn.execute("UPDATE findings SET base_history_id = NULL", []).unwrap();
    drop(conn);
    let v = ok(&project, &["findings", "verify", &id]);
    assert_eq!(
        (v["baseline_from"].as_str(), v["without"]["request_history_id"].as_i64()),
        (Some("history"), Some(base)),
        "{v}"
    );
    // With none of those either, it is refused.
    let conn = rusqlite::Connection::open(&project).unwrap();
    conn.execute("UPDATE history SET path = '/elsewhere' WHERE id = ?1", [base]).unwrap();
    drop(conn);
    let (code, v) = run(&project, &["findings", "verify", &id]);
    assert_eq!(code, 2, "{v}");
    assert!(v["error"]["message"].as_str().unwrap().contains("has no baseline"), "{v}");

    // A finding with no payload has nothing to compare without.
    let manual = ok(
        &project,
        &[
            "findings",
            "add",
            "--title",
            "Seen by hand",
            "--risk",
            "low",
            "--url",
            &format!("http://127.0.0.1:{port}/item"),
        ],
    );
    let (code, v) = run(&project, &["findings", "verify", &manual["id"].to_string()]);
    assert_eq!(code, 2, "{v}");
    assert!(v["error"]["message"].as_str().unwrap().contains("no payload"), "{v}");
    std::fs::remove_dir_all(&dir).unwrap();
}
