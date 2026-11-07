//! End-to-end tests for proof and agent work: narratives a person reviews, the executive
//! summary, an agent's trail, repro packs, tickets, and the CSV, JUnit and DefectDojo exports.

use std::io::{Read, Write};
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use serde_json::Value;

fn serve() -> u16 {
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
            let body = "<html><body>hi</body></html>";
            let resp = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nX-Powered-By: Express\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            let _ = s.write_all(resp.as_bytes());
        }
    });
    port
}

/// Runs the CLI; `agent` runs it as an MCP tool call would (its origin is mcp).
fn run_as(project: &Path, args: &[&str], stdin: Option<&str>, agent: bool) -> (i32, Value) {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_brainproxy"));
    cmd.env_remove("BRAINPROXY_PROJECT").args(["--format", "json", "--project"]).arg(project).args(args);
    if agent {
        cmd.env("BRAINPROXY_MCP_CALL", "1");
    } else {
        cmd.env_remove("BRAINPROXY_MCP_CALL");
    }
    let mut child = cmd.stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped()).spawn().unwrap();
    child.stdin.take().unwrap().write_all(stdin.unwrap_or("").as_bytes()).unwrap();
    let out = child.wait_with_output().unwrap();
    let v: Value = serde_json::from_slice(&out.stdout).unwrap_or_else(|e| {
        panic!(
            "{args:?}: bad JSON ({e}): {} {}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        )
    });
    (out.status.code().unwrap(), v)
}

fn ok(project: &Path, args: &[&str]) -> Value {
    let (code, v) = run_as(project, args, None, false);
    assert_eq!(code, 0, "{args:?}: {v}");
    v["data"].clone()
}

fn setup(name: &str) -> (PathBuf, PathBuf) {
    let dir = std::env::temp_dir().join(format!("bp-proof-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let project = dir.join("p.bpdb");
    ok(&project, &["engagement", "start", "--target", "127.0.0.1"]);
    (dir, project)
}

#[test]
fn narratives_trails_repro_tickets_and_exports() {
    let port = serve();
    let (dir, project) = setup("all");
    let base = format!("http://127.0.0.1:{port}");
    ok(&project, &["send", "--url", &format!("{base}/a")]);
    let issues = ok(&project, &["findings", "issues"]);
    let issue = issues["issues"].as_array().unwrap().iter().find(|i| i["alert_ref"] == "10037").unwrap().clone();
    let (issue_id, f) = (
        issue["id"].to_string(),
        ok(&project, &["findings", "issue", "show", &issue["id"].to_string()])["findings"][0]["id"].to_string(),
    );
    let html = |args: &[&str]| -> String {
        let v = ok(&project, &[&["report", "html"], args].concat());
        v["content"].as_str().unwrap().to_string()
    };

    // An agent drafts the write-up; reports leave it out until a person reviews it.
    let (code, v) = run_as(
        &project,
        &["findings", "issue", "narrative", &issue_id, "--file", "-"],
        Some("Express tells attackers what to aim at."),
        true,
    );
    assert_eq!(code, 0, "{v}");
    assert!(!html(&[]).contains("Express tells attackers"));
    assert!(html(&["--drafts"]).contains("Write-up (draft, not reviewed)"));
    let hash =
        ok(&project, &["findings", "issue", "show", &issue_id])["narrative"]["hash"].as_str().unwrap().to_string();
    let (code, v) = run_as(&project, &["findings", "issue", "review", &issue_id, "--hash", &hash], None, true);
    assert_eq!((code, v["error"]["kind"].as_str()), (2, Some("invalid_input")), "{v}");
    // The agent changes the text after the person read it: their review is refused.
    let (code, _) = run_as(
        &project,
        &["findings", "issue", "narrative", &issue_id, "--file", "-"],
        Some("Express tells attackers what to aim at!"),
        true,
    );
    assert_eq!(code, 0);
    let (code, v) = run_as(&project, &["findings", "issue", "review", &issue_id, "--hash", &hash], None, false);
    assert_eq!((code, v["error"]["kind"].as_str()), (2, Some("conflict")), "{v}");
    let hash =
        ok(&project, &["findings", "issue", "show", &issue_id])["narrative"]["hash"].as_str().unwrap().to_string();
    ok(&project, &["findings", "issue", "review", &issue_id, "--hash", &hash]);
    let page = html(&[]);
    assert!(
        page.contains("Express tells attackers what to aim at!") && page.contains("drafted via MCP (an agent)"),
        "{page}"
    );
    assert!(page.contains("reviewed from the command line"));

    // The executive summary, the same way.
    let (code, v) = run_as(&project, &["report-summary", "set", "--file", "-"], Some("One low-risk issue."), true);
    assert_eq!(code, 0, "{v}");
    assert!(!html(&[]).contains("One low-risk issue."));
    let hash = ok(&project, &["report-summary", "show"])["summary"]["hash"].as_str().unwrap().to_string();
    ok(&project, &["report-summary", "review", "--hash", &hash]);
    assert!(html(&[]).contains("One low-risk issue."));

    // An agent's trail: its request and its confirmation, then a person's note.
    let (code, _) = run_as(&project, &["send", "--url", &format!("{base}/a")], None, true);
    assert_eq!(code, 0);
    let (code, _) = run_as(&project, &["findings", "mark", &f, "--state", "confirmed"], None, true);
    assert_eq!(code, 0);
    let t = ok(&project, &["findings", "trail", &f]);
    assert!(
        t["agent_involved"] == true && t["requests_total"].as_i64().unwrap() >= 1 && t["reviewed_by"].is_null(),
        "{t}"
    );
    assert!(html(&[]).contains("agent&#x27;s work not reviewed") || html(&[]).contains("agent's work not reviewed"));
    std::thread::sleep(std::time::Duration::from_millis(5));
    ok(&project, &["findings", "mark", &f, "--note", "Seen it myself"]);
    assert_eq!(ok(&project, &["findings", "trail", &f])["reviewed_by"], "from the command line");

    // A repro pack and a ticket.
    let pack = ok(&project, &["findings", "repro", &f]);
    assert!(pack["curl"].as_str().unwrap().starts_with("curl -sS --globoff --path-as-is -X 'GET'"), "{pack}");
    assert_eq!(pack["check"], format!("brainproxy findings retest {f}"));
    assert!(pack["response_excerpt"].as_str().unwrap().contains("X-Powered-By: Express"));
    // A credential in a write-up or a ticket link is masked like any other.
    ok(&project, &["findings", "ticket", &f, "--record", "https://tracker.test/i/1?token=TICKETSECRET77"]);
    assert!(!html(&[]).contains("TICKETSECRET77"));
    let t = ok(&project, &["findings", "ticket", &f, "--to", "github", "--repo", "acme/web"]);
    assert!(t["command"].as_str().unwrap().starts_with("gh issue create --repo 'acme/web' --title '[Low] "), "{t}");
    assert!(t["body"].as_str().unwrap().contains("fingerprint `"));
    assert!(t["body"].as_str().unwrap().contains("**Where:** `GET http://127.0.0.1:"), "{t}");
    let j = ok(&project, &["findings", "ticket", &f, "--to", "jira", "--key", "SEC"]);
    assert_eq!(j["payload"]["fields"]["project"]["key"], "SEC");
    ok(&project, &["findings", "ticket", &f, "--record", "https://github.com/acme/web/issues/9"]);
    let report = ok(&project, &["report", "json"]);
    let inst = report["alerts"]
        .as_array()
        .unwrap()
        .iter()
        .flat_map(|g| g["instances"].as_array().unwrap().clone())
        .find(|i| i["id"].as_i64().map(|x| x.to_string()).as_deref() == Some(f.as_str()))
        .unwrap();
    assert_eq!(inst["tickets"][1]["url"], "https://github.com/acme/web/issues/9");
    let fingerprint = inst["fingerprint"].as_str().unwrap().to_string();

    // Exports for other tools.
    let csv = ok(&project, &["report", "csv"])["content"].as_str().unwrap().to_string();
    assert!(csv.starts_with("finding_id,issue_id,fingerprint,") && csv.contains(&fingerprint));
    let junit = ok(&project, &["report", "junit"])["content"].as_str().unwrap().to_string();
    assert!(junit.contains("<testsuites") && junit.contains("<failure type=\"low\""));
    let dd: Value = serde_json::from_str(ok(&project, &["report", "defectdojo"])["content"].as_str().unwrap()).unwrap();
    let ddf = dd["findings"].as_array().unwrap().iter().find(|x| x["unique_id_from_tool"] == fingerprint).unwrap();
    assert_eq!((ddf["severity"].as_str(), ddf["verified"].as_bool()), (Some("Low"), Some(true)));
    assert_eq!(ddf["endpoints"][0]["port"], port);
    std::fs::remove_dir_all(&dir).unwrap();
}
