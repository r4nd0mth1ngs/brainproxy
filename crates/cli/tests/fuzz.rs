//! End-to-end tests for `fuzz`: generated payload sources, recursive grep (an extracted value
//! feeding the next request), OOB tokens as payloads, pause and resume, and what is refused.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use serde_json::Value;

fn bin() -> Command {
    Command::new(env!("CARGO_BIN_EXE_brainproxy"))
}

fn parse(out: &Output) -> (i32, Value) {
    let v: Value = serde_json::from_slice(&out.stdout).unwrap_or_else(|e| {
        panic!("bad JSON ({e}): {} / {}", String::from_utf8_lossy(&out.stdout), String::from_utf8_lossy(&out.stderr))
    });
    (out.status.code().unwrap_or(-1), v)
}

fn run(args: &[&str], project: &Path) -> (i32, Value) {
    parse(&bin().args(["--format", "json", "--project"]).arg(project).args(args).output().unwrap())
}

/// As an MCP tool call runs it.
fn run_mcp(args: &[&str], project: &Path) -> (i32, Value) {
    let mut cmd = bin();
    cmd.env("BRAINPROXY_MCP_CALL", "1").args(["--format", "json", "--project"]).arg(project).args(args);
    parse(&cmd.output().unwrap())
}

fn setup(name: &str) -> (PathBuf, PathBuf) {
    let dir = std::env::temp_dir().join(format!("bp-fuzz-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let project = dir.join("p.bpdb");
    let (code, v) = run(&["engagement", "start", "--target", "127.0.0.1"], &project);
    assert_eq!(code, 0, "{v}");
    (dir, project)
}

/// A keep-alive HTTP/1.1 server: `answer(request line)` gives the body (status 200), each
/// answer after `delay`. Returns its port and how many requests it has had.
fn serve(delay: Duration, answer: impl Fn(&str) -> String + Send + Sync + 'static) -> (u16, Arc<AtomicU64>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let (answer, hits) = (Arc::new(answer), Arc::new(AtomicU64::new(0)));
    let counter = hits.clone();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(stream) = stream else { continue };
            let (answer, hits) = (answer.clone(), counter.clone());
            std::thread::spawn(move || {
                let mut reader = BufReader::new(stream.try_clone().unwrap());
                let mut stream = stream;
                loop {
                    let mut line = String::new();
                    if reader.read_line(&mut line).unwrap_or(0) == 0 {
                        return;
                    }
                    let mut len = 0;
                    loop {
                        let mut h = String::new();
                        if reader.read_line(&mut h).unwrap_or(0) == 0 {
                            return;
                        }
                        if h == "\r\n" || h == "\n" {
                            break;
                        }
                        if let Some(v) = h.to_ascii_lowercase().strip_prefix("content-length:") {
                            len = v.trim().parse().unwrap_or(0);
                        }
                    }
                    let mut body = vec![0; len];
                    if reader.read_exact(&mut body).is_err() {
                        return;
                    }
                    hits.fetch_add(1, Ordering::SeqCst);
                    std::thread::sleep(delay);
                    let text = answer(line.trim_end());
                    let reply = format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{text}", text.len());
                    if stream.write_all(reply.as_bytes()).is_err() {
                        return;
                    }
                }
            });
        }
    });
    (port, hits)
}

fn results(project: &Path, run_id: &str) -> Vec<Value> {
    let (code, v) = run(
        &[
            "query",
            &format!("SELECT idx, payloads, extract, status FROM fuzz_results WHERE run_id = {run_id} ORDER BY idx"),
        ],
        project,
    );
    assert_eq!(code, 0, "{v}");
    v["data"]["rows"].as_array().unwrap().clone()
}

fn status(project: &Path, run_id: &str) -> Value {
    let (code, v) = run(&["fuzz", "status", run_id], project);
    assert_eq!(code, 0, "{v}");
    v["data"]["run"].clone()
}

fn wait_for(project: &Path, run_id: &str, what: impl Fn(&Value) -> bool) -> Value {
    let deadline = Instant::now() + Duration::from_secs(60);
    loop {
        let s = status(project, run_id);
        if what(&s) {
            return s;
        }
        assert!(Instant::now() < deadline, "timed out waiting on run {run_id}: {s}");
        std::thread::sleep(Duration::from_millis(100));
    }
}

#[test]
fn recursive_grep_carries_each_extracted_value_into_the_next_request() {
    let (dir, project) = setup("extract");
    // Each answer names the token the next request must carry; the fifth names none.
    let (port, _) = serve(Duration::ZERO, |line| {
        let token = line.split("t=").nth(1).and_then(|r| r.split([' ', '&']).next()).unwrap_or("");
        match token.strip_prefix("tok").and_then(|n| n.parse::<u32>().ok()) {
            Some(n) if n < 4 => format!("ok next=tok{}", n + 1),
            Some(_) => "done".into(),
            None => "wrong token".into(),
        }
    });
    let url = format!("http://127.0.0.1:{port}/?t=§tok0§&n=§1§");
    let base = ["fuzz", "run", "--url", &url, "--mode", "pitchfork", "-p", "extract", "-p", "range:1-100"];
    // An extract set needs --extract, and a run of extract sets alone needs a limit.
    let (code, v) = run(&base, &project);
    assert_eq!(code, 2, "{v}");
    assert!(v["error"]["message"].as_str().unwrap().contains("--extract"), "{v}");
    let only = ["fuzz", "run", "--url", &url, "--mode", "pitchfork", "-p", "extract", "-p", "copy:1"];
    let (code, v) = run(&[&only[..], &["--extract", "next=(\\w+)"]].concat(), &project);
    assert_eq!(code, 2, "{v}");
    assert!(v["error"]["message"].as_str().unwrap().contains("--max-requests"), "{v}");
    let (code, v) = run(&[&base[..], &["--mode", "cluster-bomb", "--extract", "x"]].concat(), &project);
    assert_eq!(code, 2, "{v}");

    let (code, v) = run(&[&base[..], &["--extract", "next=(\\w+)", "-c", "8"]].concat(), &project);
    assert_eq!(code, 0, "{v}");
    let d = &v["data"];
    assert_eq!(d["outcome"], "extract-ended", "{d}");
    assert_eq!(d["run"]["config"]["concurrency"], 1, "{d}");
    assert!(d["run"]["config"]["note"].as_str().unwrap().contains("one at a time"), "{d}");
    assert_eq!(d["run"]["state"], "completed");
    let rows = results(&project, &d["run"]["id"].to_string());
    let chain: Vec<String> = rows.iter().map(|r| r[1].as_str().unwrap().to_string()).collect();
    assert_eq!(chain, [r#"["tok0","1"]"#, r#"["tok1","2"]"#, r#"["tok2","3"]"#, r#"["tok3","4"]"#, r#"["tok4","5"]"#]);
    assert_eq!(rows[4][2], Value::Null, "the last response gave nothing: {rows:?}");

    // Extract alone, bounded by --max-requests, with a copy riding along.
    let (code, v) = run(&[&only[..], &["--extract", "next=(\\w+)", "--max-requests", "3"]].concat(), &project);
    assert_eq!(code, 0, "{v}");
    assert_eq!(v["data"]["outcome"], "completed", "{v}");
    let rows = results(&project, &v["data"]["run"]["id"].to_string());
    assert_eq!(rows.len(), 3);
    assert_eq!(rows[2][1], r#"["tok2","tok2"]"#);
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn generated_sources_are_sent() {
    let (dir, project) = setup("generated");
    let (port, hits) = serve(Duration::ZERO, |_| "ok".into());
    let url = format!("http://127.0.0.1:{port}/?q=§x§");
    for (spec, n) in [
        ("null:3", 3),
        ("brute:ab:1-2", 6),
        ("case:ab", 4),
        ("dates:2024-01-01..2024-01-10:3d", 4),
        ("usernames:list:Ada Lovelace", 10),
        ("subst:es", 6),
        ("bitflip", 16),
    ] {
        let url = if spec == "bitflip" { url.replace("§x§", "§ok§") } else { url.clone() };
        let (code, v) = run(&["fuzz", "run", "--url", &url, "-p", spec], &project);
        assert_eq!(code, 0, "{spec}: {v}");
        assert_eq!(v["data"]["run"]["done"], n, "{spec}: {v}");
    }
    assert_eq!(hits.load(Ordering::SeqCst), 3 + 6 + 4 + 4 + 10 + 6 + 16);
    let (code, v) = run(&["fuzz", "run", "--url", &url, "-p", "brute:a-z0-9:1-5"], &project);
    assert_eq!(code, 2, "{v}");
    assert!(v["error"]["message"].as_str().unwrap().contains("10000000"), "{v}");
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn a_script_makes_a_payload_set_but_not_through_mcp() {
    let (dir, project) = setup("script");
    let (port, hits) = serve(Duration::ZERO, |_| "ok".into());
    let script = dir.join("ids.js");
    std::fs::write(
        &script,
        "function payloads(ctx) { return [1, 2, 3].map(n => ctx.default + '-' + n + '-' + ctx.set); }",
    )
    .unwrap();
    let spec = format!("script:{}", script.display());
    let url = format!("http://127.0.0.1:{port}/?id=§u§");
    let (code, v) = run_mcp(&["fuzz", "run", "--url", &url, "-p", &spec], &project);
    assert_eq!(code, 2, "{v}");
    assert!(v["error"]["message"].as_str().unwrap().contains("isn't offered through MCP"), "{v}");
    assert_eq!(hits.load(Ordering::SeqCst), 0);
    let (code, v) = run(&["fuzz", "run", "--url", &url, "-p", &spec], &project);
    assert_eq!(code, 0, "{v}");
    let rows = results(&project, &v["data"]["run"]["id"].to_string());
    let sent: Vec<&str> = rows.iter().map(|r| r[1].as_str().unwrap()).collect();
    assert_eq!(sent, [r#"["u-1-1"]"#, r#"["u-2-1"]"#, r#"["u-3-1"]"#]);
    assert_eq!(v["data"]["run"]["config"]["payload_scripts"][0]["sha256"].as_str().unwrap().len(), 64, "{v}");
    let _ = std::fs::remove_dir_all(dir);
}

/// What an SSRF does with `?u=URL`: fetches it.
fn fetch(line: &str) {
    let Some(url) = line.split("u=").nth(1).and_then(|r| r.split(' ').next()) else { return };
    let url = url.replace("%3A", ":").replace("%2F", "/");
    let Some(rest) = url.strip_prefix("http://") else { return };
    let (hostport, path) = rest.split_once('/').map_or((rest, String::from("/")), |(h, p)| (h, format!("/{p}")));
    let Ok(mut s) = std::net::TcpStream::connect(hostport) else { return };
    let _ = s.write_all(format!("GET {path} HTTP/1.1\r\nHost: {hostport}\r\nConnection: close\r\n\r\n").as_bytes());
    let mut sink = Vec::new();
    let _ = s.read_to_end(&mut sink);
}

#[test]
fn oob_tokens_are_payloads_tied_to_the_run() {
    let (dir, project) = setup("oob");
    let (port, _) = serve(Duration::ZERO, |line| {
        fetch(line);
        "fetched".into()
    });
    let url = format!("http://127.0.0.1:{port}/?u=§x§");
    let (code, v) = run(&["fuzz", "run", "--url", &url, "-p", "oob:3"], &project);
    assert_eq!(code, 4, "no listener: {v}");
    assert!(v["error"]["message"].as_str().unwrap().contains("oob start"), "{v}");
    let (code, v) = run(&["oob", "start", "--listen", "127.0.0.1:0"], &project);
    assert_eq!(code, 0, "{v}");

    // Through MCP too: the tokens are the project's own.
    let (code, v) = run_mcp(&["fuzz", "run", "--url", &url, "-p", "oob:3"], &project);
    assert_eq!(code, 0, "{v}");
    let run_id = v["data"]["run"]["id"].to_string();
    assert_eq!(v["data"]["run"]["done"], 3, "{v}");
    let (code, v) = run(&["oob", "poll", "--wait", "5"], &project);
    assert_eq!(code, 0, "{v}");
    let hits = v["data"]["interactions"].as_array().unwrap();
    assert_eq!(hits.len(), 3, "{v}");
    for h in hits {
        assert_eq!(h["payload"]["source"], "fuzz", "{h}");
        let note = h["payload"]["note"].as_str().unwrap();
        assert!(note.starts_with(&format!("fuzz run {run_id}, set 1 payload")), "{h}");
    }
    // Each payload is one of the run's, and each token went out once.
    let sent: Vec<String> = results(&project, &run_id).iter().map(|r| r[1].as_str().unwrap().to_string()).collect();
    for h in hits {
        let token = h["token"].as_str().unwrap();
        assert_eq!(sent.iter().filter(|p| p.contains(token)).count(), 1, "{token} in {sent:?}");
    }
    let (code, v) = run(&["oob", "stop"], &project);
    assert_eq!(code, 0, "{v}");
    let _ = std::fs::remove_dir_all(dir);
}

/// Every index from 0 to `total` once, and nothing else.
fn assert_each_index_once(project: &Path, run_id: &str, total: u64) {
    let sql =
        format!("SELECT COUNT(*), COUNT(DISTINCT idx), MIN(idx), MAX(idx) FROM fuzz_results WHERE run_id = {run_id}");
    let (code, v) = run(&["query", &sql], project);
    assert_eq!(code, 0, "{v}");
    assert_eq!(v["data"]["rows"][0], serde_json::json!([total, total, 0, total - 1]), "{v}");
}

#[test]
fn a_paused_run_holds_until_it_is_resumed() {
    let (dir, project) = setup("pause");
    let (port, hits) = serve(Duration::from_millis(40), |_| "ok".into());
    let url = format!("http://127.0.0.1:{port}/?n=§0§");
    let (code, v) = run(&["fuzz", "run", "--url", &url, "-p", "range:1-120", "-c", "2", "--background"], &project);
    assert_eq!(code, 0, "{v}");
    let id = v["data"]["run"]["id"].to_string();
    wait_for(&project, &id, |s| s["done"].as_u64().unwrap() >= 6);
    let (code, v) = run(&["fuzz", "pause", &id], &project);
    assert_eq!(code, 0, "{v}");
    assert_eq!(v["data"], serde_json::json!({"run": id.parse::<i64>().unwrap(), "state": "paused"}));
    let (code, v) = run(&["fuzz", "pause", &id], &project);
    assert_eq!(v["error"]["kind"], "conflict", "{code} {v}");
    // The engine sees it within half a second; what was in flight then finishes.
    std::thread::sleep(Duration::from_millis(1200));
    let (held, sent) = (status(&project, &id), hits.load(Ordering::SeqCst));
    std::thread::sleep(Duration::from_millis(1500));
    let still = status(&project, &id);
    assert_eq!(still["state"], "paused", "{still}");
    assert_eq!(still["done"], held["done"], "nothing finishes while paused: {held} {still}");
    assert_eq!(hits.load(Ordering::SeqCst), sent, "nothing is sent while paused");
    assert!(held["done"].as_u64().unwrap() < 120, "{held}");

    let (code, v) = run(&["fuzz", "resume", &id], &project);
    assert_eq!(code, 0, "{v}");
    assert_eq!(v["data"]["state"], "running", "{v}");
    let s = wait_for(&project, &id, |s| s["state"] == "completed");
    assert_eq!(s["done"], 120, "{s}");
    assert_each_index_once(&project, &id, 120);
    assert_eq!(hits.load(Ordering::SeqCst), 120);

    // A paused run can be stopped, and a stopped one isn't paused.
    let (code, v) = run(&["fuzz", "run", "--url", &url, "-p", "range:1-500", "-c", "2", "--background"], &project);
    assert_eq!(code, 0, "{v}");
    let id = v["data"]["run"]["id"].to_string();
    wait_for(&project, &id, |s| s["done"].as_u64().unwrap() >= 2);
    assert_eq!(run(&["fuzz", "pause", &id], &project).0, 0);
    let (code, v) = run(&["fuzz", "stop", &id], &project);
    assert_eq!(code, 0, "{v}");
    wait_for(&project, &id, |s| s["state"] == "stopped");
    let (_, v) = run(&["fuzz", "pause", &id], &project);
    assert_eq!(v["error"]["kind"], "conflict", "{v}");
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn a_stopped_run_resumes_with_what_it_has_not_sent() {
    let (dir, project) = setup("resume");
    let (port, hits) = serve(Duration::from_millis(20), |_| "ok".into());
    let words = dir.join("words.txt");
    std::fs::write(&words, (0..150).map(|i| format!("w{i}\n")).collect::<String>()).unwrap();
    let url = format!("http://127.0.0.1:{port}/?a=§0§&b=§0§");
    let spec = format!("file:{}", words.display());
    let args = ["fuzz", "run", "--url", &url, "--mode", "pitchfork", "-p", &spec, "-p", "brute:xyz:1-5", "-c", "3"];
    let (code, v) = run(&[&args[..], &["--background", "--timeout", "7"]].concat(), &project);
    assert_eq!(code, 0, "{v}");
    let id = v["data"]["run"]["id"].to_string();
    wait_for(&project, &id, |s| s["done"].as_u64().unwrap() >= 20);
    assert_eq!(run(&["fuzz", "stop", &id], &project).0, 0);
    let stopped = wait_for(&project, &id, |s| s["state"] == "stopped");
    let done = stopped["done"].as_u64().unwrap();
    assert!(done < 150, "{stopped}");
    assert_eq!(stopped["config"]["send"]["timeout"], 7.0, "{stopped}");

    let (code, v) = run(&["fuzz", "resume", &id], &project);
    assert_eq!(code, 0, "{v}");
    assert_eq!(v["data"]["resumed_from"], done, "{v}");
    assert_eq!(v["data"]["remaining"], 150 - done, "{v}");
    let s = wait_for(&project, &id, |s| s["state"] == "completed");
    assert_eq!(s["done"], 150, "{s}");
    assert_each_index_once(&project, &id, 150);
    assert_eq!(hits.load(Ordering::SeqCst), 150, "each request went out once");
    // The payloads are the ones the plan gives each index, before and after the resume.
    let rows = results(&project, &id);
    assert_eq!(rows[0][1], r#"["w0","x"]"#);
    assert_eq!(rows[149][1], r#"["w149","xyxxz"]"#, "{:?}", rows[149]);
    let (_, v) = run(&["fuzz", "resume", &id], &project);
    assert_eq!(v["error"]["kind"], "conflict", "a completed run doesn't resume: {v}");

    // A payload file that changed since the start would make other payloads of the same indexes.
    let (code, v) = run(&[&args[..], &["--background"]].concat(), &project);
    assert_eq!(code, 0, "{v}");
    let id = v["data"]["run"]["id"].to_string();
    wait_for(&project, &id, |s| s["done"].as_u64().unwrap() >= 3);
    assert_eq!(run(&["fuzz", "stop", &id], &project).0, 0);
    wait_for(&project, &id, |s| s["state"] == "stopped");
    std::fs::write(&words, "other\n").unwrap();
    let (_, v) = run(&["fuzz", "resume", &id], &project);
    assert_eq!(v["error"]["kind"], "conflict", "{v}");
    assert!(v["error"]["message"].as_str().unwrap().contains("payload set 1 changed"), "{v}");
    assert_eq!(status(&project, &id)["state"], "stopped");

    // Nor is a set read from stdin, which can't be read again.
    let mut child = bin()
        .args(["--format", "json", "--project"])
        .arg(&project)
        .args(["fuzz", "run", "--url", &url.replace("&b=§0§", ""), "-p", "file:-", "-c", "1"])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    let lines: String = (0..500).map(|i| format!("s{i}\n")).collect();
    child.stdin.take().unwrap().write_all(lines.as_bytes()).unwrap();
    let (code, v) = run(&["fuzz", "list", "--limit", "1"], &project);
    assert_eq!(code, 0, "{v}");
    let deadline = Instant::now() + Duration::from_secs(30);
    let id = loop {
        let (_, v) = run(&["fuzz", "list", "--limit", "1"], &project);
        let row = &v["data"]["rows"][0];
        if row[2] == "running" {
            break row[0].to_string();
        }
        assert!(Instant::now() < deadline, "{v}");
        std::thread::sleep(Duration::from_millis(50));
    };
    assert_eq!(run(&["fuzz", "stop", &id], &project).0, 0);
    let out = child.wait_with_output().unwrap();
    assert_eq!(parse(&out).1["data"]["outcome"], "stopped");
    let (_, v) = run(&["fuzz", "resume", &id], &project);
    assert_eq!(v["error"]["kind"], "conflict", "{v}");
    assert!(v["error"]["message"].as_str().unwrap().contains("stdin"), "{v}");
    let _ = std::fs::remove_dir_all(dir);
}
