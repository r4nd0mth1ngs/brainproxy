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
