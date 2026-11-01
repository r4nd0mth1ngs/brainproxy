//! End-to-end tests for `findings compare`: baselines from every source, what happens when one
//! is missing, and the exit codes CI relies on. The server trips passive rules on every page.

use std::io::{Read, Write};
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::Command;

use brainproxy_core::store::Store;
use serde_json::Value;

/// Responds to any number of requests with a page that trips passive rules.
fn serve() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
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
            let body = "<html><body>hi</body></html>";
            let resp = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nX-Powered-By: Express\r\n\
                 Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
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
    v
}

struct Env {
    dir: PathBuf,
    project: PathBuf,
    port: u16,
}

impl Env {
    fn new(name: &str) -> Self {
        Self::on(name, serve())
    }

    /// A project of its own against a server already running: a later CI run of the same
    /// target (a finding's identity includes the port).
    fn on(name: &str, port: u16) -> Self {
        let dir = std::env::temp_dir().join(format!("bp-compare-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let project = dir.join("p.bpdb");
        ok(&project, &["engagement", "start", "--target", "127.0.0.1"]);
        Self { dir, project, port }
    }

    fn send(&self, path: &str) {
        ok(&self.project, &["send", "--url", &format!("http://127.0.0.1:{}{path}", self.port)]);
    }

    fn path(&self, name: &str) -> String {
        self.dir.join(name).to_str().unwrap().to_string()
    }

    /// `report json` written to a file, as a CI baseline is.
    fn save_baseline(&self, name: &str) -> String {
        let path = self.path(name);
        ok(&self.project, &["report", "json", "--state", "all", "--no-evidence", "--output", &path, "--force"]);
        path
    }

    fn compare(&self, args: &[&str]) -> (i32, Value) {
        run(&self.project, &[&["findings", "compare"], args].concat())
    }

    /// The ids of every finding on `path`.
    fn ids_on(&self, path: &str) -> Vec<i64> {
        let v = ok(&self.project, &["findings", "list", "--all", "--state", "all", "--limit", "10000"]);
        v["data"]["items"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|f| f["url"].as_str().unwrap().ends_with(path))
            .map(|f| f["id"].as_i64().unwrap())
            .collect()
    }
}

fn urls(list: &Value) -> Vec<String> {
    let mut u: Vec<String> = list.as_array().unwrap().iter().map(|f| f["url"].as_str().unwrap().to_string()).collect();
    u.sort();
    u.dedup();
    u
}

fn ends_with(list: &Value, path: &str) -> bool {
    urls(list).iter().all(|u| u.ends_with(path)) && !list.as_array().unwrap().is_empty()
}

/// The server trips nothing above medium, so `high` and `info` gates sit on either side of it.
#[test]
fn compare_with_a_saved_report_and_gate_new_findings() {
    let env = Env::new("report");
    env.send("/old");
    env.send("/fixed");
    let baseline = env.save_baseline("base.json");

    // A new project, as a CI run has: /old found again, /new first found, /fixed not found.
    let run2 = Env::on("report-run2", env.port);
    run2.send("/old");
    run2.send("/new");

    let (code, v) = run2.compare(&["--baseline", &baseline]);
    assert_eq!(code, 0, "{v}");
    let d = &v["data"];
    assert_eq!(v["_meta"]["provenance"]["untrusted_content"], true);
    assert_eq!(d["baseline"]["kind"], "report");
    assert!(ends_with(&d["fixed"], "/fixed"), "{d}");
    assert!(urls(&d["unchanged"]).iter().all(|u| u.ends_with("/old")), "{d}");
    assert!(!d["unchanged"].as_array().unwrap().is_empty());
    assert!(urls(&d["new"]).iter().any(|u| u.ends_with("/new")), "{d}");
    assert_eq!(d["summary"]["fixed"], d["fixed"].as_array().unwrap().len());
    assert_eq!(d["gate"], Value::Null);

    // Below the risk of what is there: passes.
    let (code, v) = run2.compare(&["--baseline", &baseline, "--fail-on", "high"]);
    assert_eq!(code, 0, "{v}");
    assert_eq!(v["data"]["gate"]["passed"], true);
    assert_eq!(v["data"]["gate"]["count"], 0);
    assert_eq!(v["data"]["gate"]["exit_code"], 0);

    // At or above it: exit code 5, still one complete envelope with ok true.
    let (code, v) = run2.compare(&["--baseline", &baseline, "--fail-on", "info"]);
    assert_eq!(code, 5, "{v}");
    assert_eq!(v["ok"], true);
    assert_eq!(v["data"]["gate"]["passed"], false);
    assert_eq!(v["data"]["gate"]["exit_code"], 5);
    assert!(v["data"]["gate"]["count"].as_u64().unwrap() > 0);
    assert!(!v["data"]["new"].as_array().unwrap().is_empty());

    // New only: a run with nothing new passes, though the same findings fail the plain gate.
    let same = env.save_baseline("same.json");
    let (code, v) = env.compare(&["--baseline", &same, "--fail-on", "info", "--new-only"]);
    assert_eq!(code, 0, "{v}");
    assert_eq!(v["data"]["summary"]["new"], 0);
    let (code, v) = env.compare(&["--baseline", &same, "--fail-on", "info"]);
    assert_eq!(code, 5, "{v}");
    // New since then: the new-only gate fails too.
    env.send("/later");
    let (code, v) = env.compare(&["--baseline", &same, "--fail-on", "info", "--new-only"]);
    assert_eq!(code, 5, "{v}");
    assert!(ends_with(&v["data"]["gate"]["findings"], "/later"), "{v}");
}

#[test]
fn no_baseline_means_every_finding_is_new() {
    let env = Env::new("none");
    env.send("/a");
    let (code, v) = env.compare(&[]);
    assert_eq!(code, 0, "{v}");
    assert_eq!(v["data"]["baseline"]["kind"], "none");
    assert_eq!(v["data"]["summary"]["unchanged"], 0);
    assert!(ends_with(&v["data"]["new"], "/a"));
    // A gate list cut at --limit says so, even when the groups listed aren't cut.
    let (code, v) = env.compare(&["--state", "confirmed", "--fail-on", "info", "--limit", "1"]);
    assert_eq!(code, 5, "{v}");
    assert_eq!(v["data"]["summary"]["new"], 0);
    assert_eq!(v["data"]["gate"]["findings"].as_array().unwrap().len(), 1);
    assert!(v["data"]["gate"]["count"].as_u64().unwrap() > 1);
    assert_eq!(v["data"]["summary"]["truncated"], true);
    // The plain severity gate, with no baseline at all.
    assert_eq!(env.compare(&["--fail-on", "high"]).0, 0);
    assert_eq!(env.compare(&["--fail-on", "info"]).0, 5);
}

#[test]
fn a_missing_baseline_fails_unless_allowed() {
    let env = Env::new("missing");
    env.send("/a");
    let path = env.path("nope.json");
    let (code, v) = env.compare(&["--baseline", &path, "--fail-on", "high"]);
    assert_eq!(code, 4, "{v}");
    assert_eq!(v["ok"], false);
    assert_eq!(v["error"]["kind"], "not_found");

    // Allowed: an empty baseline, so the gate still sees everything.
    let (code, v) = env.compare(&["--baseline", &path, "--allow-missing-baseline"]);
    assert_eq!(code, 0, "{v}");
    assert_eq!(v["data"]["baseline"]["missing"], true);
    assert!(!v["data"]["warnings"].as_array().unwrap().is_empty());
    assert!(ends_with(&v["data"]["new"], "/a"));
    let args = ["--baseline", &path, "--allow-missing-baseline", "--fail-on", "info", "--new-only"];
    assert_eq!(env.compare(&args).0, 5);

    // A file that exists but isn't a baseline is never treated as empty.
    let bad = env.path("bad.json");
    std::fs::write(&bad, "").unwrap();
    let (code, v) = env.compare(&["--baseline", &bad, "--allow-missing-baseline"]);
    assert_eq!(code, 2, "{v}");
    assert_eq!(v["error"]["kind"], "invalid_input");

    // --new-only and --allow-missing-baseline are usage errors alone.
    assert_eq!(env.compare(&["--new-only"]).0, 2);
    assert_eq!(env.compare(&["--allow-missing-baseline"]).0, 2);
    assert_eq!(env.compare(&["--scan", "1", "--baseline", &path]).0, 2);
}

#[test]
fn a_gate_cant_pass_on_the_wrong_files() {
    let env = Env::new("wrong");
    env.send("/a");

    // A mistyped project isn't created and passed as empty.
    let typo = env.dir.join("typo.bpdb");
    let (code, v) = run(&typo, &["findings", "compare", "--fail-on", "high"]);
    assert_eq!(code, 4, "{v}");
    assert!(!typo.exists());

    // A baseline that is the project itself would show nothing new, ever.
    let own = env.project.to_str().unwrap();
    let (code, v) = env.compare(&["--baseline", own, "--fail-on", "info", "--new-only"]);
    assert_eq!(code, 2, "{v}");

    // A report cut off at its limit can't say what is new.
    let cut = env.path("cut.json");
    ok(&env.project, &["report", "json", "--limit", "1", "--no-evidence", "--output", &cut]);
    let (code, v) = env.compare(&["--baseline", &cut]);
    assert_eq!(code, 2, "{v}");
    assert!(v["error"]["message"].as_str().unwrap().contains("--limit"), "{v}");
}

#[test]
fn two_files_need_no_open_project() {
    let env = Env::new("files");
    env.send("/a");
    let before = env.save_baseline("before.json");
    env.send("/b");
    let after = env.save_baseline("after.json");

    // --current from a file: --project isn't read or created.
    let unused = env.dir.join("unused.bpdb");
    let args = ["findings", "compare", "--baseline", &before, "--current", &after, "--fail-on", "info", "--new-only"];
    let (code, v) = run(&unused, &args);
    assert_eq!(code, 5, "{v}");
    assert_eq!(v["data"]["current"]["kind"], "report");
    assert!(ends_with(&v["data"]["new"], "/b"), "{v}");
    assert!(v["data"]["new"][0]["id"].is_null());
    assert!(!unused.exists());

    // A narrowed set can't pass a gate, though it can be compared with a warning.
    let narrowed = env.path("narrowed.json");
    ok(&env.project, &["report", "json", "--host", "other.test", "--no-evidence", "--output", &narrowed]);
    let (code, v) = run(&unused, &["findings", "compare", "--current", &narrowed, "--fail-on", "info"]);
    assert_eq!(code, 2, "{v}");
    assert!(v["error"]["message"].as_str().unwrap().contains("host"), "{v}");
    let (code, v) = run(&unused, &["findings", "compare", "--current", &narrowed]);
    assert_eq!(code, 0, "{v}");
    assert!(!v["data"]["warnings"].as_array().unwrap().is_empty());

    // A project file is neither, with the way to get a report from it.
    let copy = env.path("copy.bpdb");
    std::fs::copy(&env.project, &copy).unwrap();
    for flag in ["--baseline", "--current"] {
        let (code, v) = env.compare(&[flag, &copy]);
        assert_eq!(code, 2, "{v}");
        assert!(v["error"]["message"].as_str().unwrap().contains("report json"), "{v}");
    }
}

#[test]
fn a_failed_gate_in_text_mode_names_what_tripped_it() {
    let env = Env::new("text");
    env.send("/a");
    let baseline = env.save_baseline("base.json");
    let out = Command::new(env!("CARGO_BIN_EXE_brainproxy"))
        .env_remove("BRAINPROXY_PROJECT")
        .args(["--format", "text", "--project"])
        .arg(&env.project)
        .args(["findings", "compare", "--baseline", &baseline, "--fail-on", "info"])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(5));
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(text.contains("0 new,") && text.contains("gate FAILED"), "{text}");
    // Unchanged findings aren't listed otherwise, so the gate lists them.
    assert!(text.lines().any(|l| l.starts_with("gate ") && l.contains("/a")), "{text}");
}

#[test]
fn false_positives_in_the_baseline_stay_triaged() {
    let env = Env::new("triage");
    env.send("/a");
    for id in env.ids_on("/a") {
        ok(&env.project, &["findings", "mark", &id.to_string(), "--state", "false_positive"]);
    }
    assert_eq!(env.compare(&["--fail-on", "info"]).0, 0);
    let baseline = env.save_baseline("base.json");

    // A new project finds them again, open: the baseline's mark still holds.
    let run2 = Env::on("triage-run2", env.port);
    run2.send("/a");
    assert_eq!(run2.compare(&["--fail-on", "info"]).0, 5);
    let (code, v) = run2.compare(&["--baseline", &baseline, "--fail-on", "info"]);
    assert_eq!(code, 0, "{v}");
    assert_eq!(v["data"]["summary"]["unchanged"], 0);
    let (_, v) = run2.compare(&["--baseline", &baseline, "--state", "all"]);
    assert_eq!(v["data"]["unchanged"][0]["state"], "false_positive");
}

/// A scan job as `scan active --background` stores it, around the sightings in `during`.
fn scan_job(env: &Env, args: &[String], state: &str, during: impl FnOnce()) -> i64 {
    let store = Store::open(&env.project).unwrap();
    let id = store.job_create("active-scan", "running", args).unwrap();
    std::thread::sleep(std::time::Duration::from_millis(5));
    during();
    std::thread::sleep(std::time::Duration::from_millis(5));
    store.job_set_state(id, state, None, None, true).unwrap();
    id
}

#[test]
fn compare_with_a_scan_and_gate_it() {
    let env = Env::new("scan");
    env.send("/still");
    env.send("/gone");
    std::thread::sleep(std::time::Duration::from_millis(5));
    let url = format!("http://127.0.0.1:{}/", env.port);
    let args: Vec<String> = ["scan", "active", "--crawl", &url].iter().map(|s| s.to_string()).collect();
    let job = scan_job(&env, &args, "completed", || {
        env.send("/still");
        env.send("/new");
    });

    let id = job.to_string();
    let (code, v) = env.compare(&["--scan", &id]);
    assert_eq!(code, 0, "{v}");
    let d = &v["data"];
    assert_eq!(d["baseline"]["kind"], "scan");
    assert_eq!(d["baseline"]["state"], "completed");
    assert!(urls(&d["new"]).iter().any(|u| u.ends_with("/new")), "{d}");
    assert!(urls(&d["unchanged"]).iter().any(|u| u.ends_with("/still")), "{d}");
    assert!(ends_with(&d["fixed"], "/gone"), "{d}");
    assert!(d["new"][0]["id"].is_i64());

    // The gate counts what the scan found: new, or found again unless --new-only.
    assert_eq!(env.compare(&["--scan", &id, "--fail-on", "high"]).0, 0);
    assert_eq!(env.compare(&["--scan", &id, "--fail-on", "info"]).0, 5);
    assert_eq!(env.compare(&["--scan", &id, "--fail-on", "info", "--new-only"]).0, 5);

    // No such job; not a scan.
    let (code, _) = env.compare(&["--scan", "999"]);
    assert_eq!(code, 4);
    let store = Store::open(&env.project).unwrap();
    let crawl = store.job_create("crawl", "completed", &[]).unwrap().to_string();
    assert_eq!(env.compare(&["--scan", &crawl]).0, 2);

    // A scan that didn't complete: a comparison warns, a gate refuses to vouch for it.
    let failed = scan_job(&env, &args, "failed", || {}).to_string();
    let (code, v) = env.compare(&["--scan", &failed]);
    assert_eq!(code, 0, "{v}");
    assert!(!v["data"]["warnings"].as_array().unwrap().is_empty());
    let (code, v) = env.compare(&["--scan", &failed, "--fail-on", "high"]);
    assert_eq!(code, 2, "{v}");
    assert_eq!(v["error"]["kind"], "conflict");

    // --max-minutes ends a scan early and it still completes: only the result says so.
    for result in [serde_json::json!({"timed_out": true}), serde_json::json!({"crawl": {"timed_out": true}})] {
        let timed = scan_job(&env, &args, "completed", || {});
        Store::open(&env.project).unwrap().job_result(timed, &result).unwrap();
        let timed = timed.to_string();
        let (code, v) = env.compare(&["--scan", &timed]);
        assert_eq!(code, 0, "{v}");
        assert!(v["data"]["warnings"][0].as_str().unwrap().contains("timed out"), "{v}");
        let (code, v) = env.compare(&["--scan", &timed, "--fail-on", "high"]);
        assert_eq!(code, 2, "{v}");
        assert!(v["error"]["message"].as_str().unwrap().contains("timed out"), "{v}");
    }
}

/// A finding first seen by a run that failed is found again by the next one. Against that run
/// alone it is unchanged, so a new-only gate never sees it; since the last completed scan, new.
#[test]
fn since_scan_counts_what_a_failed_run_saw_first_as_new() {
    let env = Env::new("since");
    env.send("/old");
    let url = format!("http://127.0.0.1:{}/", env.port);
    let args: Vec<String> = ["scan", "active", "--crawl", &url].iter().map(|s| s.to_string()).collect();
    let good = scan_job(&env, &args, "completed", || env.send("/old"));
    let _failed = scan_job(&env, &args, "failed", || env.send("/sqli"));
    let job = scan_job(&env, &args, "completed", || {
        env.send("/old");
        env.send("/sqli");
    });
    let (job, good) = (job.to_string(), good.to_string());

    // Without --since-scan: unchanged, and the new-only gate passes.
    let (code, v) = env.compare(&["--scan", &job, "--fail-on", "info", "--new-only"]);
    assert_eq!(code, 0, "{v}");
    assert_eq!(v["data"]["summary"]["new"], 0);
    assert!(urls(&v["data"]["unchanged"]).iter().any(|u| u.ends_with("/sqli")), "{v}");
    assert!(v["data"]["baseline"].get("since_scan").is_none(), "{v}");

    // Since the last completed scan: new, and the gate fails on it alone.
    let (code, v) = env.compare(&["--scan", &job, "--since-scan", &good, "--fail-on", "info", "--new-only"]);
    assert_eq!(code, 5, "{v}");
    let d = &v["data"];
    assert!(ends_with(&d["new"], "/sqli"), "{d}");
    assert!(ends_with(&d["gate"]["findings"], "/sqli"), "{d}");
    assert!(ends_with(&d["unchanged"], "/old"), "{d}");
    assert_eq!(d["baseline"]["since_scan"]["job"], good.parse::<i64>().unwrap());
    assert_eq!(d["baseline"]["scope"]["new_since"], d["baseline"]["since_scan"]["start"]);
}

#[test]
fn since_scan_must_be_a_completed_scan_before_the_compared_one() {
    let env = Env::new("since-refused");
    let url = format!("http://127.0.0.1:{}/", env.port);
    let args: Vec<String> = ["scan", "active", "--crawl", &url].iter().map(|s| s.to_string()).collect();
    let store = Store::open(&env.project).unwrap();
    let running = store.job_create("active-scan", "running", &args).unwrap();
    let failed = scan_job(&env, &args, "failed", || {});
    let stopped = scan_job(&env, &args, "stopped", || {});
    let timed = scan_job(&env, &args, "completed", || {});
    store.job_result(timed, &serde_json::json!({"timed_out": true})).unwrap();
    let crawl = store.job_create("crawl", "completed", &[]).unwrap();
    let job = scan_job(&env, &args, "completed", || {});
    let later = scan_job(&env, &args, "completed", || {});
    let job = job.to_string();

    for (since, kind) in [
        (running, "conflict"),
        (failed, "conflict"),
        (stopped, "conflict"),
        (timed, "conflict"),
        (crawl, "invalid_input"),
        (later, "invalid_input"),
        (job.parse().unwrap(), "invalid_input"),
    ] {
        let (code, v) = env.compare(&["--scan", &job, "--since-scan", &since.to_string()]);
        assert_eq!((code, v["error"]["kind"].as_str()), (2, Some(kind)), "since {since}: {v}");
    }
    assert_eq!(env.compare(&["--scan", &job, "--since-scan", "999"]).0, 4);
    // Only with --scan.
    assert_eq!(env.compare(&["--since-scan", &later.to_string()]).0, 2);
}

#[test]
fn described_in_capabilities_and_offered_over_mcp() {
    let env = Env::new("described");
    let caps = ok(&env.project, &["capabilities"]);
    assert!(caps["data"]["exit_codes"]["5"].as_str().unwrap().contains("--fail-on"));
    let one = ok(&env.project, &["capabilities", "findings", "compare"]);
    let flags: Vec<&str> = one["data"]["args"].as_array().unwrap().iter().filter_map(|a| a["flag"].as_str()).collect();
    for flag in ["--baseline", "--scan", "--since-scan", "--fail-on", "--new-only", "--allow-missing-baseline"] {
        assert!(flags.contains(&flag), "{flags:?}");
    }

    let mut child = Command::new(env!("CARGO_BIN_EXE_brainproxy"))
        .args(["--project"])
        .arg(&env.project)
        .args(["mcp", "serve"])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    let mut stdin = child.stdin.take().unwrap();
    let mut stdout = std::io::BufReader::new(child.stdout.take().unwrap());
    // One at a time: a server whose client hangs up cancels what is running.
    let mut ask = |msg: &str| -> Value {
        writeln!(stdin, "{msg}").unwrap();
        let mut line = String::new();
        std::io::BufRead::read_line(&mut stdout, &mut line).unwrap();
        serde_json::from_str(&line).unwrap()
    };
    let list = ask(r#"{"jsonrpc":"2.0","id":1,"method":"tools/list"}"#);
    let call = ask(
        r#"{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"findings_compare","arguments":{"fail_on":"high"}}}"#,
    );
    drop(stdin);
    let _ = child.wait();
    let tools = list["result"]["tools"].as_array().unwrap();
    let tool = tools.iter().find(|t| t["name"] == "findings_compare").expect("findings_compare tool");
    assert_eq!(tool["annotations"]["readOnlyHint"], true);
    assert!(tool["inputSchema"]["properties"]["fail_on"].is_object());
    let result = &call["result"];
    assert_eq!(result["isError"], false, "{result}");
    assert_eq!(result["structuredContent"]["data"]["gate"]["passed"], true);
}
