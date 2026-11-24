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
fn an_alert_filter_re_rates_what_a_scan_finds_and_the_report_says_so() {
    let port = serve(Arc::new(AtomicBool::new(true)), Arc::new(AtomicBool::new(false)));
    let (dir, project) = setup("filter");
    let base = format!("http://127.0.0.1:{port}");
    ok(&project, &["send", "--url", &format!("{base}/a")]);
    let of = |path: &str| {
        let all = ok(&project, &["findings", "list", "--all", "--alert", "10037", "--state", "all"]);
        all["items"].as_array().unwrap().iter().find(|f| f["url"].as_str().unwrap().ends_with(path)).cloned()
    };
    let scanner = of("/a").unwrap()["risk"].as_str().unwrap().to_string();
    assert_ne!(scanner, "high");

    // A false positive isn't a rating.
    let o = Command::new(env!("CARGO_BIN_EXE_brainproxy"))
        .args(["--format", "json", "--project"])
        .arg(&project)
        .args(["findings", "filter", "add", "--alert", "10037", "--risk", "false_positive", "--reason", "x"])
        .output()
        .unwrap();
    let said = format!("{}{}", String::from_utf8_lossy(&o.stdout), String::from_utf8_lossy(&o.stderr));
    assert!(!o.status.success() && said.contains("findings suppress"), "{said}");

    let host = format!("127.0.0.1:{port}");
    let add = ok(
        &project,
        &[
            "findings",
            "filter",
            "add",
            "--alert",
            "10037",
            "--host",
            &host,
            "--url-regex",
            "/b$",
            "--risk",
            "high",
            "--reason",
            "the admin app",
        ],
    );
    assert_eq!(add["rated"], 0, "{add}");
    let id = add["id"].as_i64().unwrap();
    // Scanned again: the new finding arrives re-rated, the other keeps the scanner's rating.
    ok(&project, &["send", "--url", &format!("{base}/b")]);
    let b = of("/b").unwrap();
    assert_eq!((b["risk"].as_str(), b["rated"]["filter"].as_i64()), (Some("high"), Some(id)), "{b}");
    assert_eq!(b["rated"]["scanner_risk"].as_str(), Some(scanner.as_str()), "{b}");
    assert!(of("/a").unwrap()["rated"].is_null());
    let shown = ok(&project, &["findings", "show", &b["id"].to_string()]);
    assert_eq!(shown["rated_by"], id, "{shown}");
    assert!(kinds(&project, b["id"].as_i64().unwrap()).contains(&"rated".to_string()));

    let report = dir.join("r.json");
    ok(&project, &["report", "json", "--no-evidence", "--output", report.to_str().unwrap()]);
    let r: Value = serde_json::from_str(&std::fs::read_to_string(&report).unwrap()).unwrap();
    let group = r["alerts"].as_array().unwrap().iter().find(|g| g["alert_ref"] == "10037").unwrap();
    let inst = group["instances"].as_array().unwrap().iter().find(|i| i["id"] == b["id"]).unwrap();
    assert_eq!((inst["risk"].as_str(), inst["rated"]["filter"].as_i64()), (Some("high"), Some(id)), "{inst}");
    assert_eq!(group["risk"], "high");

    let list = ok(&project, &["findings", "filter", "list"]);
    assert_eq!((list["count"].as_i64(), list["filters"][0]["holds"].as_i64()), (Some(1), Some(1)), "{list}");
    assert_eq!(list["filters"][0]["url_regex"], "/b$");
    // Suppression rules are listed apart.
    assert_eq!(ok(&project, &["findings", "suppress", "list"])["count"], 0);
    let gone = ok(&project, &["findings", "filter", "remove", &id.to_string(), "--unrate"]);
    assert_eq!(gone["unrated"], 1, "{gone}");
    assert_eq!(of("/b").unwrap()["risk"].as_str(), Some(scanner.as_str()));
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

/// jwt.io's example token: HS256 signed with "your-256-bit-secret", a secret the JWT rule knows.
const JWT_ISSUED: &str = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";

/// An orders page that lets in the token it issues (`POST /login`) and, wrongly, any token
/// whose header says `alg: none`; without a token it asks to log in. While `open` is set it
/// lets anyone in.
fn serve_jwt(open: Arc<AtomicBool>) -> u16 {
    use base64::Engine;
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut s) = stream else { continue };
            let open = open.clone();
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
                let text = String::from_utf8_lossy(&req).to_string();
                let token = text
                    .lines()
                    .find_map(|l| l.to_ascii_lowercase().starts_with("authorization: bearer ").then(|| l[22..].trim()))
                    .unwrap_or("")
                    .to_string();
                let header = token.split('.').next().unwrap_or("");
                let header = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(header).unwrap_or_default();
                let none = String::from_utf8_lossy(&header).to_ascii_lowercase().contains("\"alg\":\"none\"");
                let (status, body, ctype) = if text.starts_with("POST /login ") {
                    ("200 OK", format!("{{\"token\":\"{JWT_ISSUED}\"}}"), "application/json")
                } else if open.load(Ordering::SeqCst) || token == JWT_ISSUED || none {
                    ("200 OK", "<h1>Orders of alice</h1><ul><li>order 1</li><li>order 2</li></ul>".into(), "text/html")
                } else {
                    ("401 Unauthorized", "<h1>Please log in</h1>".into(), "text/html")
                };
                let resp = format!(
                    "HTTP/1.1 {status}\r\nContent-Type: {ctype}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = s.write_all(resp.as_bytes());
            });
        }
    });
    port
}

#[test]
fn a_forged_jwt_is_verified_against_the_valid_token_and_none() {
    let open = Arc::new(AtomicBool::new(false));
    let port = serve_jwt(open.clone());
    let (dir, project) = setup("verify-jwt");
    let url = format!("http://127.0.0.1:{port}/orders");
    let bearer = format!("Authorization: Bearer {JWT_ISSUED}");
    let sent = ok(&project, &["send", "--url", &url, "-H", &bearer]);
    let base = sent["id"].as_i64().unwrap_or_else(|| panic!("{sent}"));
    ok(&project, &["scan", "active", "--history-id", &base.to_string(), "--rules=100007", "--strength", "medium"]);
    let list = ok(&project, &["findings", "list", "--all", "--source", "active"]);
    let id_of = |r: &str| {
        let items = list["items"].as_array().unwrap_or_else(|| panic!("{list}"));
        let f = items.iter().find(|f| f["alert_ref"] == r).unwrap_or_else(|| panic!("{r}: {list}"));
        f["id"].to_string()
    };
    let (none, weak) = (id_of("100007-2"), id_of("100007-4"));

    // The finding names both answers it was judged against.
    let shown = ok(&project, &["findings", "show", &none]);
    let other = shown["other_info"].as_str().unwrap();
    assert!(other.contains("answered 200") && other.contains("without a token (history"), "{other}");

    // The valid and the forged token are answered alike: the proof is the request without one.
    let v = ok(&project, &["findings", "verify", &none]);
    let status = |side: &str| v[side]["status"].as_u64();
    assert_eq!((status("without"), status("with"), status("control")), (Some(200), Some(200), Some(401)), "{v}");
    assert_eq!(v["control"]["request_history_id"], Value::Null, "{v}");
    let p = &v["proof"];
    assert_eq!((p["reproduced"].as_bool(), p["forged_like_valid"].as_bool()), (Some(true), Some(true)), "{v}");
    assert_eq!(p["control_like_valid"], false, "{v}");
    assert!(p["summary"].as_str().unwrap().starts_with("reproduced:"), "{v}");
    let control = ok(&project, &["history", "show", &v["control"]["history_ids"][0].to_string()]);
    let request = control["request"]["content"].as_str().unwrap_or_default().to_string();
    assert!(!request.contains("eyJ") && request.contains("Bearer"), "the token taken out: {control}");

    let out = Command::new(env!("CARGO_BIN_EXE_brainproxy"))
        .args(["--format", "text", "--project"])
        .arg(&project)
        .args(["findings", "verify", &none])
        .output()
        .unwrap();
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(text.contains("no token") && text.contains("reproduced: the forged token"), "{text}");

    // With a session the forged token is still the one sent, not the session's own.
    let login = format!("http://127.0.0.1:{port}/login");
    ok(
        &project,
        &[
            "auth",
            "add",
            "alice",
            "--login-url",
            &login,
            "--login-body",
            "{}",
            "--token-regex",
            r#""token":"([^"]+)""#,
            "--token-header",
            "Authorization: Bearer {{token}}",
        ],
    );
    let v = ok(&project, &["findings", "verify", &none, "--auth", "alice"]);
    let forged = ok(&project, &["history", "show", &v["with"]["history_ids"][0].to_string()]);
    let attack = shown["attack"].as_str().unwrap();
    assert!(forged["request"]["content"].as_str().unwrap_or_default().contains(attack), "{forged}");
    assert_eq!(v["proof"]["reproduced"], true, "{v}");

    // Once the page lets anyone in, the forged token proves nothing.
    open.store(true, Ordering::SeqCst);
    let v = ok(&project, &["findings", "verify", &none]);
    assert_eq!(
        (v["proof"]["reproduced"].as_bool(), v["proof"]["control_like_valid"].as_bool()),
        (Some(false), Some(true)),
        "{v}"
    );

    // A weak secret was found offline: there is nothing to send.
    let (code, v) = run(&project, &["findings", "verify", &weak]);
    assert_eq!(code, 2, "{v}");
    assert!(v["error"]["message"].as_str().unwrap().contains("found offline"), "{v}");
    std::fs::remove_dir_all(&dir).unwrap();
}
