//! End-to-end tests: run the real binary against a local HTTP server.

use std::io::{Read, Write};
use std::net::TcpListener;
use std::process::{Command, Stdio};

use serde_json::Value;

fn bin() -> Command {
    Command::new(env!("CARGO_BIN_EXE_brainproxy"))
}

/// Serves `n` connections, echoing back the request line and body in a fixed response.
fn serve(n: usize) -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for stream in listener.incoming().take(n) {
            let mut s = stream.unwrap();
            let mut buf = vec![0u8; 65536];
            let mut len = 0;
            // Read the head, then Content-Length bytes of body.
            loop {
                len += s.read(&mut buf[len..]).unwrap();
                let text = String::from_utf8_lossy(&buf[..len]).to_string();
                if let Some(i) = text.find("\r\n\r\n") {
                    let cl = text
                        .lines()
                        .find_map(|l| {
                            l.to_ascii_lowercase()
                                .strip_prefix("content-length:")
                                .map(|v| v.trim().parse::<usize>().unwrap())
                        })
                        .unwrap_or(0);
                    if len >= i + 4 + cl {
                        break;
                    }
                }
            }
            let req = String::from_utf8_lossy(&buf[..len]).to_string();
            let line = req.lines().next().unwrap().to_string();
            let body = req.split("\r\n\r\n").nth(1).unwrap_or("").to_string();
            let payload = format!("{line}|{body}");
            let resp = format!(
                "HTTP/1.1 201 Created\r\nX-Test: yes\r\nTransfer-Encoding: chunked\r\n\r\n{:x}\r\n{payload}\r\n0\r\n\r\n",
                payload.len()
            );
            s.write_all(resp.as_bytes()).unwrap();
        }
    });
    port
}

fn run(args: &[&str], project: &std::path::Path, stdin: Option<&[u8]>) -> (i32, Value) {
    let mut child = bin()
        .args(["--format", "json", "--project"])
        .arg(project)
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    {
        let mut stdin_pipe = child.stdin.take().unwrap();
        if let Some(data) = stdin {
            // A command that fails on its arguments exits without reading stdin, and may be
            // gone before this write: that is its answer to check, not a failure here.
            let _ = stdin_pipe.write_all(data);
        }
    }
    let out = child.wait_with_output().unwrap();
    let v: Value = serde_json::from_slice(&out.stdout)
        .unwrap_or_else(|e| panic!("bad JSON ({e}): {}", String::from_utf8_lossy(&out.stdout)));
    (out.status.code().unwrap(), v)
}

fn tmp_project(name: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!("bp-test-{}-{name}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let p = dir.join("p.bpdb");
    let _ = std::fs::remove_file(&p);
    let status = bin()
        .args(["--format", "json", "--project"])
        .arg(&p)
        .args(["engagement", "start", "--target", "127.0.0.1", "--target", "localhost"])
        .output()
        .unwrap();
    assert!(status.status.success(), "{}", String::from_utf8_lossy(&status.stdout));
    p
}

#[test]
fn send_raw_from_stdin_then_history() {
    let port = serve(1);
    let project = tmp_project("raw");
    // Unix line endings and a wrong Content-Length: both get fixed.
    let req = format!("POST /echo?a=1 HTTP/1.1\nHost: 127.0.0.1:{port}\nContent-Length: 99\n\nhi=there");
    let (code, v) = run(&["send", "--scheme", "http"], &project, Some(req.as_bytes()));
    assert_eq!(code, 0, "{v}");
    assert_eq!(v["ok"], true);
    let resp = &v["data"]["response"];
    assert_eq!(resp["status"], 201);
    assert_eq!(resp["body"]["content"], "POST /echo?a=1 HTTP/1.1|hi=there");
    let id = v["data"]["id"].as_i64().unwrap();

    let (code, v) = run(&["history", "list", "--status", "201"], &project, None);
    assert_eq!(code, 0);
    assert_eq!(v["data"]["count"], 1);
    assert_eq!(v["data"]["items"][0]["url"], format!("http://127.0.0.1:{port}/echo?a=1"));

    let (code, v) = run(&["history", "show", &id.to_string()], &project, None);
    assert_eq!(code, 0);
    assert!(v["data"]["request"]["content"].as_str().unwrap().contains("Content-Length: 8\r\n"));
}

#[test]
fn send_url_mode() {
    let port = serve(1);
    let project = tmp_project("url");
    let url = format!("http://127.0.0.1:{port}/x");
    let (code, v) = run(&["send", "--url", &url, "-X", "PUT", "-d", "abc", "-H", "X-A: 1"], &project, None);
    assert_eq!(code, 0, "{v}");
    assert_eq!(v["data"]["response"]["body"]["content"], "PUT /x HTTP/1.1|abc");
}

#[test]
fn connection_errors_are_structured() {
    // Bind and drop to get a port with nothing listening.
    let port = TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port();
    let project = tmp_project("err");
    let url = format!("http://127.0.0.1:{port}/");
    let (code, v) = run(&["send", "--url", &url], &project, None);
    assert_eq!(code, 3);
    assert_eq!(v["ok"], false);
    assert_eq!(v["error"]["kind"], "connect");
    // Failures are recorded too.
    let (_, v) = run(&["history", "list"], &project, None);
    assert_eq!(v["data"]["count"], 1);
    // With no response recorded, `response` is null (not a parsed empty head).
    let id = v["data"]["items"][0]["id"].to_string();
    let (_, v) = run(&["history", "show", &id], &project, None);
    assert!(v["data"]["response"].is_null(), "{v}");
    assert!(v["data"]["entry"]["error"].is_string(), "{v}");
}

#[test]
fn usage_and_not_found_errors() {
    let project = tmp_project("usage");
    let (code, v) = run(&["send", "--bogus"], &project, None);
    assert_eq!((code, v["error"]["kind"].as_str()), (2, Some("usage")));
    let (code, v) = run(&["history", "show", "42"], &project, None);
    assert_eq!((code, v["error"]["kind"].as_str()), (4, Some("not_found")));
}

#[test]
fn codecs_chain() {
    let project = tmp_project("codec");
    let (code, v) = run(&["encode", "url,base64", "a b"], &project, None);
    assert_eq!(code, 0);
    assert_eq!(v["data"]["output"]["content"], "YSUyMGI=");
    let (_, v) = run(&["decode", "base64,url", "-"], &project, Some(b"YSUyMGI="));
    assert_eq!(v["data"]["output"]["content"], "a b");
    let (_, v) = run(&["hash", "sha1", "abc"], &project, None);
    assert_eq!(v["data"]["output"]["content"], "a9993e364706816aba3e25717850c26c9cd0d89d");

    // Compression output is binary, so it comes back as base64.
    let (code, v) = run(&["encode", "gzip,base64,url", "-"], &project, Some(b"{\"role\":\"admin\"}"));
    assert_eq!(code, 0);
    let layered = v["data"]["output"]["content"].as_str().unwrap().to_string();
    let (code, v) = run(&["decode", "auto", &layered], &project, None);
    assert_eq!(code, 0);
    assert_eq!(v["data"]["steps"], serde_json::json!(["url", "base64", "gzip"]));
    assert_eq!(v["data"]["output"]["content"], "{\"role\":\"admin\"}");
    let (_, v) = run(&["decode", "url,auto", &layered], &project, None);
    assert_eq!(v["data"]["steps"], serde_json::json!(["url", "base64", "gzip"]));
    // Nothing to undo: no steps, the input unchanged.
    let (code, v) = run(&["decode", "auto", "password"], &project, None);
    assert_eq!(code, 0);
    assert_eq!(
        (v["data"]["steps"].clone(), v["data"]["output"]["content"].clone()),
        (serde_json::json!([]), serde_json::json!("password"))
    );
    let (code, v) = run(&["decode", "gzip", "not gzip"], &project, None);
    assert_eq!((code, v["error"]["kind"].as_str()), (2, Some("invalid_input")));
}

#[test]
fn decode_auto_steps_and_limits() {
    let project = tmp_project("codec-auto");
    let (_, v) = run(&["encode", "gzip,base64,url", "-"], &project, Some(b"{\"role\":\"admin\"}"));
    let layered = v["data"]["output"]["content"].as_str().unwrap().to_string();
    // The steps replay as an ordinary chain, and a second `auto` finds nothing more.
    let (_, auto) = run(&["decode", "auto", &layered], &project, None);
    let steps: Vec<&str> = auto["data"]["steps"].as_array().unwrap().iter().map(|s| s.as_str().unwrap()).collect();
    let (code, v) = run(&["decode", &steps.join(","), &layered], &project, None);
    assert_eq!(code, 0);
    assert_eq!((&v["data"]["steps"], &v["data"]["output"]), (&auto["data"]["steps"], &auto["data"]["output"]));
    let (_, v) = run(&["decode", "auto,auto", &layered], &project, None);
    assert_eq!((&v["data"]["steps"], v["data"]["chain"].as_str()), (&auto["data"]["steps"], Some("auto,auto")));
    // `stopped` says why the last `auto` stopped: here the JSON it reached.
    assert_eq!(auto["data"]["stopped"], "json");
    let (_, v) = run(&["decode", "auto", "plain"], &project, None);
    assert_eq!((&v["data"]["steps"], &v["data"]["stopped"]), (&serde_json::json!([]), &serde_json::json!("nothing")));
    let (_, v) = run(&["encode", &["base64"; 10].join(","), "deep"], &project, None);
    let (_, v) = run(&["decode", "auto", v["data"]["output"]["content"].as_str().unwrap()], &project, None);
    assert_eq!((v["data"]["steps"].as_array().unwrap().len(), &v["data"]["stopped"]), (8, &serde_json::json!("depth")));
    // Without `auto`, steps are the chain as given and there is no `stopped`.
    let (_, v) = run(&["decode", "base64,url", "YSUyMGI="], &project, None);
    assert_eq!(v["data"]["steps"], serde_json::json!(["base64", "url"]));
    assert!(v["data"].get("stopped").is_none(), "{v}");
    // --raw prints the bytes alone.
    let out = bin().arg("--project").arg(&project).args(["decode", "auto", "--raw", &layered]).output().unwrap();
    assert!(out.status.success());
    assert_eq!(out.stdout, b"{\"role\":\"admin\"}");
    // Piped input with a trailing line break.
    let (_, v) = run(&["decode", "auto", "-"], &project, Some(b"SGVsbG8sIHdvcmxkIQ==\n"));
    assert_eq!(
        (&v["data"]["steps"], v["data"]["output"]["content"].as_str()),
        (&serde_json::json!(["base64"]), Some("Hello, world!"))
    );
    // Binary output comes back as base64.
    let (_, v) = run(&["encode", "gzip,base64", "-"], &project, Some(&[0xff, 0x00, 0xfe]));
    let (_, v) = run(&["decode", "auto", v["data"]["output"]["content"].as_str().unwrap()], &project, None);
    assert_eq!(v["data"]["steps"], serde_json::json!(["base64", "gzip"]));
    assert_eq!(
        (v["data"]["output"]["encoding"].as_str(), v["data"]["output"]["content"].as_str()),
        (Some("base64"), Some("/wD+"))
    );
    // brotli and auto only decode.
    for kind in ["brotli", "auto"] {
        let (code, v) = run(&["encode", kind, "x"], &project, None);
        assert_eq!((code, v["error"]["kind"].as_str()), (2, Some("invalid_input")), "{kind}");
    }
    let (_, v) = run(&["capabilities"], &project, None);
    let codecs = &v["data"]["codecs"];
    for (op, kind, listed) in
        [("decode", "auto", true), ("decode", "brotli", true), ("encode", "brotli", false), ("encode", "gzip", true)]
    {
        assert_eq!(codecs[op].as_array().unwrap().contains(&serde_json::json!(kind)), listed, "{op} {kind}");
    }
}

#[test]
fn decode_refuses_decompression_bombs() {
    let project = tmp_project("codec-bomb");
    let (code, v) = run(&["encode", "gzip,base64", "-"], &project, Some(&vec![0u8; 16 * 1024 * 1024 + 1]));
    assert_eq!(code, 0);
    let bomb = v["data"]["output"]["content"].as_str().unwrap().to_string();
    assert!(bomb.len() < 64 * 1024);
    let (code, v) = run(&["decode", "base64,gzip", &bomb], &project, None);
    assert_eq!((code, v["error"]["kind"].as_str()), (2, Some("invalid_input")));
    assert!(v["error"]["message"].as_str().unwrap().contains("16 MB limit"), "{v}");
    // `auto` stops before the bomb and hands back the compressed bytes.
    let (code, v) = run(&["decode", "auto", &bomb], &project, None);
    assert_eq!((code, &v["data"]["steps"]), (0, &serde_json::json!(["base64"])));
    // It says so, rather than looking like there was nothing more to undo.
    assert_eq!(v["data"]["stopped"]["refused"], "gzip", "{v}");
    assert!(v["data"]["stopped"]["error"].as_str().unwrap().contains("16 MB limit"), "{v}");
    assert_eq!(v["data"]["output"]["encoding"], "base64");
    assert!(v["data"]["output"]["length"].as_u64().unwrap() < 64 * 1024);
}

#[test]
fn capabilities_lists_all_commands() {
    let project = tmp_project("caps");
    let (code, v) = run(&["capabilities"], &project, None);
    assert_eq!(code, 0);
    let names: Vec<&str> =
        v["data"]["commands"].as_array().unwrap().iter().map(|c| c["command"].as_str().unwrap()).collect();
    for want in [
        "send",
        "history",
        "query",
        "schema",
        "proxy",
        "ca",
        "scope",
        "rules",
        "intercept",
        "encode",
        "decode",
        "hash",
        "project",
        "findings",
        "report",
    ] {
        assert!(names.contains(&want), "{want} missing from {names:?}");
    }
    assert_eq!(v["data"]["conventions"]["interactive_prompts"], false);
    assert!(!names.contains(&"engage"), "hidden commands stay out of capabilities");
}

#[test]
fn engage() {
    let project = tmp_project("engage");
    let (code, v) = run(&["engage"], &project, None);
    assert_eq!((code, v["data"]["order"].as_str()), (0, Some("Make it so.")));
    let help = bin().arg("--help").output().unwrap();
    let help = String::from_utf8_lossy(&help.stdout).into_owned();
    assert!(help.contains("  engagement") && !help.lines().any(|l| l.trim_start().starts_with("engage ")), "{help}");
}

#[test]
fn query_schema_and_tags() {
    let port = serve(2);
    let project = tmp_project("query");
    for path in ["/a?x=1", "/b"] {
        let url = format!("http://127.0.0.1:{port}{path}");
        assert_eq!(run(&["send", "--url", &url], &project, None).0, 0);
    }

    let (code, v) = run(
        &["query", "SELECT id, path, header(resp_headers, 'x-test') AS h FROM history WHERE query = ?1", "-p", "x=1"],
        &project,
        None,
    );
    assert_eq!(code, 0, "{v}");
    assert_eq!(v["data"]["columns"], serde_json::json!(["id", "path", "h"]));
    assert_eq!(v["data"]["rows"], serde_json::json!([[1, "/a", "yes"]]));

    // FTS over the decoded (dechunked) body, objects shape, row limit.
    let (_, v) = run(
        &[
            "query",
            "--shape",
            "objects",
            "--limit",
            "1",
            "SELECT rowid AS id FROM history_fts WHERE history_fts MATCH 'GET'",
        ],
        &project,
        None,
    );
    assert_eq!(v["data"]["truncated"], true);
    assert_eq!(v["data"]["rows"][0]["id"], 1);

    // Read-only: writes are rejected as invalid input.
    let (code, v) = run(&["query", "DELETE FROM history"], &project, None);
    assert_eq!((code, v["error"]["kind"].as_str()), (2, Some("invalid_input")));

    let (_, v) = run(&["history", "tag", "2", "--add", "idor", "--add", "todo"], &project, None);
    assert_eq!(v["data"]["tags"], serde_json::json!(["idor", "todo"]));
    let (_, v) = run(&["history", "list", "--tag", "idor"], &project, None);
    assert_eq!(v["data"]["count"], 1);

    let (_, v) = run(&["schema"], &project, None);
    let cols = v["data"]["tables"][0]["columns"].as_array().unwrap();
    assert!(cols.iter().any(|c| c["name"] == "resp_body_text"));
    assert!(!v["data"]["examples"].as_array().unwrap().is_empty());
}

#[test]
fn capabilities_for_one_command() {
    let project = tmp_project("caps-one");
    let (code, v) = run(&["capabilities", "history", "list"], &project, None);
    assert_eq!(code, 0);
    assert_eq!(v["data"]["command"], "history list");
    let (code, _) = run(&["capabilities", "nope"], &project, None);
    assert_eq!(code, 4);
}

#[test]
fn scan_sources_without_arguments_only_shows() {
    let project = tmp_project("sources");
    let (_, v) = run(&["scan", "sources", "proxy,crawl"], &project, None);
    assert_eq!(v["data"]["sources"], serde_json::json!(["proxy", "crawl"]));
    let (code, v) = run(&["scan", "sources"], &project, None);
    assert_eq!(code, 0);
    assert_eq!(v["data"]["sources"], serde_json::json!(["proxy", "crawl"]), "{v}");
}

#[test]
fn background_start_errors_are_the_childs_own() {
    let project = tmp_project("bgerr");
    run(&["engagement", "start", "--target", "127.0.0.1"], &project, None);
    let (code, v) = run(&["scan", "active", "127.0.0.1:9", "--background"], &project, None);
    assert_eq!(code, 2);
    assert_eq!(v["error"]["kind"], "invalid_input");
    let msg = v["error"]["message"].as_str().unwrap();
    // Not "active-scan exited (...): {json envelope}", and the prefix isn't doubled.
    assert!(!msg.contains("exited (") && !msg.contains("{\"ok\""), "{msg}");
    assert_eq!(msg.matches("invalid input:").count(), 1, "{msg}");
}

#[test]
fn background_jobs_keep_job_id_before_a_separator() {
    // MCP writes `--` before positionals; the child's --job-id must not land after it.
    let port = serve_site();
    let project = tmp_project("bgsep");
    let site = format!("http://127.0.0.1:{port}/");
    let (code, v) = run(&["crawl", "--background", "--no-robots", "--no-sitemap", "--", &site], &project, None);
    assert_eq!(code, 0, "{v}");
    let id = v["data"]["job"].as_i64().unwrap().to_string();
    let (_, v) = run(&["job", "wait", &id, "--timeout", "30"], &project, None);
    assert_eq!(v["data"]["state"], "completed", "{v}");
}

#[test]
fn queued_jobs_are_reaped_and_keep_a_stop_request() {
    use brainproxy_core::store::Store;
    let project = tmp_project("queued");
    let store = Store::open(&project).unwrap();
    // A child that died before it marked the job running: failed, with the error from its log.
    let id = store.job_create("active-scan", "queued", &[]).unwrap();
    let mut gone = bin().arg("--version").stdout(Stdio::null()).spawn().unwrap();
    gone.wait().unwrap();
    store.job_set_pid(id, gone.id()).unwrap();
    let log = std::fs::canonicalize(&project).unwrap().with_extension(format!("job-{id}.log"));
    std::fs::write(&log, "{\"ok\":false,\"error\":{\"kind\":\"timeout\",\"message\":\"timed out: login\"}}\n").unwrap();
    let (_, v) = run(&["job", "status", &id.to_string()], &project, None);
    assert_eq!(v["data"]["state"], "failed", "{v}");
    assert_eq!(v["data"]["error"], "timed out: login", "{v}");
    // A stop requested while queued isn't overwritten when the job's process starts.
    let id = store.job_create("active-scan", "queued", &[]).unwrap();
    let (_, v) = run(&["job", "stop", &id.to_string()], &project, None);
    assert_eq!(v["data"]["state"], "stopping", "{v}");
    assert!(!store.job_start(id, std::process::id()).unwrap());
    assert_eq!(store.job_state(id).unwrap(), "stopping");
    let id = store.job_create("active-scan", "queued", &[]).unwrap();
    assert!(store.job_start(id, std::process::id()).unwrap());
    assert_eq!(store.job_state(id).unwrap(), "running");
}

/// A two-page site: `/` links to `/item?id=1`. Serves until the test process ends.
fn serve_site() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut s) = stream else { continue };
            std::thread::spawn(move || {
                let mut buf = vec![0u8; 16384];
                let mut len = 0;
                while !buf[..len].windows(4).any(|w| w == b"\r\n\r\n") {
                    match s.read(&mut buf[len..]) {
                        Ok(0) | Err(_) => return,
                        Ok(n) => len += n,
                    }
                }
                let line = String::from_utf8_lossy(&buf[..len]).lines().next().unwrap_or("").to_string();
                let body = if line.starts_with("GET / ") {
                    "<html><body><a href=\"/item?id=1\">item</a></body></html>"
                } else if line.contains("/users/1%27") {
                    "You have an error in your SQL syntax"
                } else {
                    "<html><body>item</body></html>"
                };
                let status = if line.contains("/users/999") { "404 Not Found" } else { "200 OK" };
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

/// `/allowed/` answers with a 103 Early Hints, then a page linking `/allowed/next`;
/// everything else is a plain page. Records the request lines.
fn serve_early_hints() -> (u16, std::sync::Arc<std::sync::Mutex<Vec<String>>>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let seen = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    let log = seen.clone();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut s) = stream else { continue };
            let log = log.clone();
            std::thread::spawn(move || {
                let mut buf = vec![0u8; 16384];
                let mut len = 0;
                while !buf[..len].windows(4).any(|w| w == b"\r\n\r\n") {
                    match s.read(&mut buf[len..]) {
                        Ok(0) | Err(_) => return,
                        Ok(n) => len += n,
                    }
                }
                let line = String::from_utf8_lossy(&buf[..len]).lines().next().unwrap_or("").to_string();
                log.lock().unwrap().push(line.clone());
                let body = if line.starts_with("GET /allowed/ ") { "<a href=\"/allowed/next\">next</a>" } else { "ok" };
                let hints = if line.starts_with("GET /allowed/ ") {
                    "HTTP/1.1 103 Early Hints\r\nLink: </x.css>; rel=preload\r\n\r\n"
                } else {
                    ""
                };
                let resp = format!(
                    "{hints}HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = s.write_all(resp.as_bytes());
            });
        }
    });
    (port, seen)
}

#[test]
fn crawl_filters_its_first_requests_and_reads_past_early_hints() {
    let (port, seen) = serve_early_hints();
    let project = tmp_project("crawlfilters");
    let site = format!("http://127.0.0.1:{port}/allowed/");
    let (code, v) = run(&["crawl", &site, "--path-prefix", "/allowed", "--exclude", "robots|sitemap"], &project, None);
    assert_eq!(code, 0, "{v}");
    let seen = seen.lock().unwrap().clone();
    assert!(!seen.iter().any(|l| l.contains("robots.txt") || l.contains("sitemap.xml")), "{seen:?}");
    // The page after the 103 is the one read: its link is followed.
    assert!(seen.iter().any(|l| l.starts_with("GET /allowed/next ")), "{seen:?}");
    assert_eq!(v["data"]["by_status"]["200"], 2, "{v}");
}

/// Like the Supportdesk lab: `/` links to `/login` (sets a device cookie) and to
/// `/docs`, a 401 page that names `/api/doc.html?publickey=…` only in its text.
fn serve_cookie_site() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut s) = stream else { continue };
            std::thread::spawn(move || {
                let mut buf = vec![0u8; 16384];
                let mut len = 0;
                while !buf[..len].windows(4).any(|w| w == b"\r\n\r\n") {
                    match s.read(&mut buf[len..]) {
                        Ok(0) | Err(_) => return,
                        Ok(n) => len += n,
                    }
                }
                let line = String::from_utf8_lossy(&buf[..len]).lines().next().unwrap_or("").to_string();
                let (status, extra, body) = if line.starts_with("GET / ") {
                    ("200 OK", "", "<a href=\"/login\">sign in</a> <a href=\"/docs\">API</a>")
                } else if line.starts_with("GET /login") {
                    (
                        "200 OK",
                        "Set-Cookie: DEVICE=abc123; Max-Age=3600; Path=/\r\n",
                        "<form method=post action=/login><input name=user></form>",
                    )
                } else if line.starts_with("GET /docs") {
                    (
                        "401 UNAUTHORIZED",
                        "",
                        "<p>Open it from your email (<code>/api/doc.html?publickey=&hellip;</code>).</p>",
                    )
                } else {
                    ("200 OK", "", "ok")
                };
                let resp = format!(
                    "HTTP/1.1 {status}\r\nContent-Type: text/html\r\n{extra}Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = s.write_all(resp.as_bytes());
            });
        }
    });
    port
}

#[test]
fn crawl_keeps_cookies_and_follows_urls_in_page_text() {
    let port = serve_cookie_site();
    let project = tmp_project("crawlcookies");
    run(&["engagement", "start", "--target", "127.0.0.1"], &project, None);
    let site = format!("http://127.0.0.1:{port}/");
    let (code, v) = run(&["crawl", &site, "--no-robots", "--no-sitemap"], &project, None);
    assert_eq!(code, 0, "{v}");
    let sql = "SELECT method, path, query, header(req_headers, 'cookie') AS cookie FROM history \
               WHERE source = 'crawl' ORDER BY id";
    let (_, v) = run(&["query", "--shape", "objects", sql], &project, None);
    let rows = v["data"]["rows"].as_array().unwrap();
    let doc = rows.iter().find(|r| r["path"] == "/api/doc.html").unwrap_or_else(|| panic!("{v}"));
    assert_eq!(doc["query"], "publickey=brainproxy", "{v}");
    // The cookie set by GET /login comes back on later requests, e.g. the form POST.
    let post = rows.iter().find(|r| r["method"] == "POST" && r["path"] == "/login").unwrap_or_else(|| panic!("{v}"));
    assert_eq!(post["cookie"], "DEVICE=abc123", "{v}");
    // So scan active --cookies has a cookie insertion point.
    let (code, v) = run(
        &["scan", "active", "--where", "method = 'POST'", "--cookies", "--rules", "40018", "--no-oob"],
        &project,
        None,
    );
    assert_eq!(code, 0, "{v}");
    assert!(v["data"]["insertion_points"].as_u64().unwrap() >= 2, "{v}");
}

#[test]
fn scan_active_crawl_attacks_what_the_crawl_finds() {
    let port = serve_site();
    let project = tmp_project("crawlscan");
    run(&["engagement", "start", "--target", "127.0.0.1"], &project, None);
    let site = format!("http://127.0.0.1:{port}");
    // Without --crawl a site URL is one request with no parameters.
    let (_, v) = run(&["scan", "active", &site, "--rules", "40018", "--no-oob"], &project, None);
    assert_eq!(v["data"]["insertion_points"], 0, "{v}");
    // With --crawl the linked page and its parameter are found and attacked.
    let (code, v) = run(&["scan", "active", &site, "--crawl", "--rules", "40018", "--no-oob"], &project, None);
    assert_eq!(code, 0, "{v}");
    assert!(v["data"]["crawl"]["requests"].as_u64().unwrap() >= 2, "{v}");
    assert!(v["data"]["insertion_points"].as_u64().unwrap() >= 1, "{v}");
    let (code, v) = run(&["scan", "active", "--crawl"], &project, None);
    assert_eq!(code, 2, "{v}");
}

#[test]
fn auth_secrets_stay_out_of_show_and_query() {
    let project = tmp_project("secrets");
    let (code, v) = run(&["auth", "add", "p1", "-H", "Authorization: Bearer APIKEY123"], &project, None);
    assert_eq!(code, 0, "{v}");
    let (_, v) = run(&["auth", "show", "p1"], &project, None);
    assert!(!v.to_string().contains("APIKEY123"), "{v}");
    let (code, v) = run(&["query", "select profile, state from auth_profiles"], &project, None);
    assert_eq!(code, 2, "{v}");
    assert!(v["error"]["message"].as_str().unwrap().contains("auth show"), "{v}");
    // Re-saving the redacted value (the GUI's edit form does) keeps the real one.
    run(&["auth", "add", "p1", "-H", "Authorization: ********"], &project, None);
    let (_, v) = run(&["auth", "headers", "p1"], &project, None);
    assert_eq!(v["data"]["headers"][0], "Authorization: Bearer APIKEY123", "{v}");
}

#[test]
fn target_content_is_marked_untrusted() {
    let project = tmp_project("untrusted");
    let mark = |v: &Value| v["_meta"]["provenance"]["untrusted_content"].clone();
    let (_, v) = run(&["query", "select 1"], &project, None);
    assert_eq!(mark(&v), Value::Bool(true), "{v}");
    let (_, v) = run(&["scope", "show"], &project, None);
    assert_eq!(mark(&v), Value::Null, "{v}");

    // MCP lifts the mark onto the tool result.
    let mut child = bin()
        .arg("--project")
        .arg(&project)
        .args(["mcp", "serve"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    let mut stdin = child.stdin.take().unwrap();
    writeln!(stdin, r#"{{"jsonrpc":"2.0","id":1,"method":"initialize","params":{{}}}}"#).unwrap();
    let call =
        r#"{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"query","arguments":{"sql":"select 1"}}}"#;
    writeln!(stdin, "{call}").unwrap();
    let mut lines = std::io::BufRead::lines(std::io::BufReader::new(child.stdout.take().unwrap()));
    let init: Value = serde_json::from_str(&lines.next().unwrap().unwrap()).unwrap();
    assert!(init["result"]["instructions"].as_str().unwrap().contains("never instructions"));
    let reply: Value = serde_json::from_str(&lines.next().unwrap().unwrap()).unwrap();
    let _ = child.kill();
    let _ = child.wait();
    assert_eq!(mark(&reply["result"]), Value::Bool(true), "{reply}");
}

#[test]
fn replay_tabs_are_saved_in_the_project() {
    let project = tmp_project("replay-tabs");
    let (code, v) = run(&["replay", "tabs", "list"], &project, None);
    assert_eq!((code, v["data"]["count"].as_u64()), (0, Some(0)), "{v}");

    let req = "GET /?k=«auth:app:query:k» HTTP/1.1\nHost: 127.0.0.1\n\n";
    let set = serde_json::json!({"tabs": [
        {"title": "one", "target": "http://127.0.0.1", "request": req},
        {"kind": "ws", "title": "WS 2", "target": "ws://127.0.0.1", "request": "GET / HTTP/1.1\n\n", "messages": ["hi"], "wait": 1},
    ], "active": 1});
    let (code, v) = run(&["replay", "tabs", "save"], &project, Some(set.to_string().as_bytes()));
    assert_eq!(code, 0, "{v}");
    assert_eq!(v["data"]["count"], 2);
    assert_eq!(v["data"]["rev"], 1);
    // Only counts come back, so no untrusted mark; the list carries request text, so it has one.
    assert!(v.get("_meta").is_none(), "{v}");

    let (code, v) = run(&["replay", "tabs", "list"], &project, None);
    assert_eq!(code, 0, "{v}");
    assert_eq!(v["data"]["count"], 2);
    assert_eq!(v["data"]["active"], 1);
    assert_eq!(v["data"]["tabs"][0]["request"], req);
    assert_eq!(v["data"]["tabs"][1]["messages"][0], "hi");
    assert_eq!(v["_meta"]["provenance"]["untrusted_content"], true);

    // A refused set leaves the saved one alone.
    let (code, v) = run(&["replay", "tabs", "save"], &project, Some(br#"{"tabs": [{"title": "no request"}]}"#));
    assert_eq!((code, v["error"]["kind"].as_str()), (2, Some("invalid_input")), "{v}");
    // It stops reading at the cap, so the rest of the write fails (the app ignores that too).
    let big = serde_json::json!({"tabs": [{"request": "a".repeat(17 * 1024 * 1024)}]}).to_string();
    let mut child = bin()
        .args(["--format", "json", "--project"])
        .arg(&project)
        .args(["replay", "tabs", "save"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    let _ = child.stdin.take().unwrap().write_all(big.as_bytes());
    let out = child.wait_with_output().unwrap();
    let v: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(out.status.code(), Some(2), "{v}");
    assert!(v["error"]["message"].as_str().unwrap().contains("over 16 MB"), "{v}");
    assert_eq!(run(&["replay", "tabs", "list"], &project, None).1["data"]["count"], 2);

    // A summary leaves the requests out, and one tab can be read on its own, so a large set
    // can be paged through under an output cap.
    let (code, v) = run(&["replay", "tabs", "list", "--summary"], &project, None);
    assert_eq!(code, 0, "{v}");
    assert_eq!((&v["data"]["rev"], &v["data"]["v"]), (&1.into(), &1.into()));
    assert_eq!(
        v["data"]["tabs"][0],
        serde_json::json!({"index": 0, "kind": "http", "title": "one",
        "target": "http://127.0.0.1", "request_bytes": req.len()})
    );
    assert_eq!(v["data"]["tabs"][1]["messages"], 1);
    assert_eq!(v["_meta"]["provenance"]["untrusted_content"], true);
    let (code, v) = run(&["replay", "tabs", "list", "--index", "1"], &project, None);
    assert_eq!(code, 0, "{v}");
    assert_eq!((&v["data"]["index"], &v["data"]["tab"]["title"]), (&serde_json::json!(1), &set["tabs"][1]["title"]));
    assert_eq!(v["data"]["tab"]["messages"], set["tabs"][1]["messages"]);
    let (code, v) = run(&["replay", "tabs", "list", "--index", "2"], &project, None);
    assert_eq!(v["error"]["kind"], "not_found", "{v}");
    assert_ne!(code, 0);

    // A save checked against an old revision changes nothing; appending keeps the saved tabs.
    let one = br#"{"tabs": [{"title": "agent", "request": "GET / HTTP/1.1\n\n"}], "active": 0}"#;
    let (code, v) = run(&["replay", "tabs", "save", "--if-revision", "0"], &project, Some(one));
    assert_eq!(v["error"]["kind"], "conflict", "{v}");
    assert!(v["error"]["message"].as_str().unwrap().contains("revision 1, not 0"), "{v}");
    assert_ne!(code, 0);
    let (code, v) = run(&["replay", "tabs", "save", "--append", "--if-revision", "1"], &project, Some(one));
    assert_eq!(code, 0, "{v}");
    assert_eq!((&v["data"]["count"], &v["data"]["added"], &v["data"]["rev"]), (&3.into(), &1.into(), &2.into()));
    let (_, v) = run(&["replay", "tabs", "list"], &project, None);
    assert_eq!(v["data"]["tabs"][0]["title"], "one");
    assert_eq!(v["data"]["tabs"][2]["title"], "agent");
    assert_eq!(v["data"]["active"], 2);

    // The tabs travel with a saved copy; an empty set leaves none but keeps the revision going.
    let copy = project.with_file_name("copy.bpdb");
    let _ = std::fs::remove_file(&copy);
    let (code, v) = run(&["project", "save", "--output", copy.to_str().unwrap()], &project, None);
    assert_eq!(code, 0, "{v}");
    assert_eq!(run(&["replay", "tabs", "list"], &copy, None).1["data"]["tabs"][0]["title"], "one");
    let (code, v) = run(&["replay", "tabs", "save", "--if-revision", "2"], &project, Some(br#"{"tabs": []}"#));
    assert_eq!((code, &v["data"]["rev"]), (0, &3.into()), "{v}");
    let (_, v) = run(&["replay", "tabs", "list"], &project, None);
    assert_eq!((&v["data"]["count"], &v["data"]["rev"]), (&0.into(), &3.into()), "{v}");

    // A set saved by a newer version isn't saved over (its new fields would be lost), but lists.
    let newer = r#"{"v":2,"rev":7,"tabs":[{"kind":"grpc","request":""}]}"#;
    brainproxy_core::store::Store::open(&project).unwrap().meta_set("replay.tabs", Some(newer)).unwrap();
    let (code, v) = run(&["replay", "tabs", "save"], &project, Some(br#"{"tabs": []}"#));
    assert_eq!(v["error"]["kind"], "conflict", "{v}");
    assert_ne!(code, 0);
    // The listing says which format, so the app can tell and not try to save over it.
    let (_, v) = run(&["replay", "tabs", "list"], &project, None);
    assert_eq!(
        (&v["data"]["tabs"][0]["kind"], &v["data"]["v"], &v["data"]["rev"]),
        (&"grpc".into(), &2.into(), &7.into())
    );
    assert_eq!(run(&["replay", "tabs", "list", "--summary"], &project, None).1["data"]["v"], 2);
}

#[test]
fn replay_tabs_keep_bytes_and_placeholders_and_send_nothing() {
    let project = tmp_project("replay-tabs-text");
    let (code, v) = run(&["auth", "add", "p1", "-H", "Authorization: Bearer APIKEY123"], &project, None);
    assert_eq!(code, 0, "{v}");
    // A binary request holds one character per byte, every byte value included.
    let binary: String = "POST / HTTP/1.1\r\n\r\n".chars().chain((0u8..=255).map(char::from)).collect();
    let typed =
        "GET /é?q=«auth:p1:header:Authorization» HTTP/1.1\r\nAuthorization: «auth:p1:header:Authorization»\r\n\r\n";
    // Out of scope: kept, since saving sends nothing (a person sends from Replay, through scope).
    let set = serde_json::json!({"tabs": [
        {"title": "bin", "target": "http://10.255.255.1", "request": binary, "binary": true},
        {"title": "auth", "target": "http://127.0.0.1", "request": typed},
    ]});
    let (code, v) = run(&["replay", "tabs", "save"], &project, Some(set.to_string().as_bytes()));
    assert_eq!(code, 0, "{v}");
    let (_, v) = run(&["replay", "tabs", "list"], &project, None);
    assert_eq!(v["data"]["tabs"][0]["request"], binary.as_str());
    assert_eq!(v["data"]["tabs"][0]["binary"], true);
    assert_eq!(v["data"]["tabs"][1]["request"], typed);
    assert!(!v.to_string().contains("APIKEY123"), "{v}");
    assert_eq!(v["data"]["active"], Value::Null);
    let (_, v) = run(&["history", "list"], &project, None);
    assert_eq!(v["data"]["count"], 0, "{v}");

    // Text output: one line per tab; none left says so.
    let text = |args: &[&str]| {
        let out = bin().args(["--format", "text", "--project"]).arg(&project).args(args).output().unwrap();
        assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
        String::from_utf8(out.stdout).unwrap()
    };
    let list = text(&["replay", "tabs", "list"]);
    assert_eq!(
        list.lines().collect::<Vec<_>>(),
        ["  0  http  bin  http://10.255.255.1", "  1  http  auth  http://127.0.0.1"]
    );
    let mut child = bin()
        .args(["--format", "text", "--project"])
        .arg(&project)
        .args(["replay", "tabs", "save"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    let _ = child.stdin.take().unwrap().write_all(br#"{"tabs": [{"kind": "ws", "request": ""}]}"#);
    let out = child.wait_with_output().unwrap();
    assert_eq!(String::from_utf8_lossy(&out.stdout), "saved 1 Replay tab\n");
    assert_eq!(text(&["replay", "tabs", "list"]), "  0  ws      \n");
    // Control characters in a title or target can't clear the screen or add a row in text
    // mode; JSON and the project keep them as saved.
    let sly = serde_json::json!({"tabs": [
        {"title": "\u{1b}[2J\u{1b}]0;x\u{7}", "target": "http://a.test\r\n  2  http  forged  http://b.test", "request": ""},
    ]});
    let (code, v) = run(&["replay", "tabs", "save"], &project, Some(sly.to_string().as_bytes()));
    assert_eq!(code, 0, "{v}");
    assert_eq!(
        text(&["replay", "tabs", "list"]),
        "  0  http  \\u{1b}[2J\\u{1b}]0;x\\u{7}  http://a.test\\r\\n  2  http  forged  http://b.test\n"
    );
    let (_, v) = run(&["replay", "tabs", "list"], &project, None);
    assert_eq!(v["data"]["tabs"][0]["title"], sly["tabs"][0]["title"]);
    assert_eq!(v["data"]["tabs"][0]["target"], sly["tabs"][0]["target"]);
    run(&["replay", "tabs", "save"], &project, Some(br#"{"tabs": []}"#));
    assert_eq!(text(&["replay", "tabs", "list"]), "no saved Replay tabs\n");
}

#[test]
fn ws_send_refuses_a_wait_over_a_day() {
    // A saved Replay tab carries its wait to Send: too large a value would hold the connection
    // for years, or panic making the duration.
    let project = tmp_project("ws-wait");
    for wait in ["1e300", "86400.5", "inf"] {
        let (code, v) = run(&["ws", "send", "--url", "ws://127.0.0.1:9/", "--wait", wait], &project, None);
        assert_eq!(v["error"]["kind"], "invalid_input", "{wait}: {v}");
        assert!(v["error"]["message"].as_str().unwrap().contains("--wait: at most 86400"), "{v}");
        assert_eq!(code, 2);
    }
}

#[test]
fn output_files_are_not_overwritten_without_force() {
    let project = tmp_project("overwrite");
    let dir = project.parent().unwrap();
    let (home, file) = (dir.join("home"), dir.join("existing.txt"));
    let (home, path) = (home.to_str().unwrap(), file.to_str().unwrap());
    for args in [vec!["report", "-o", path], vec!["--home", home, "ca", "export", "--out", path]] {
        std::fs::write(&file, "keep me").unwrap();
        let (code, v) = run(&args, &project, None);
        assert_eq!(code, 2, "{v}");
        assert_eq!(v["error"]["kind"], "conflict", "{v}");
        assert_eq!(std::fs::read_to_string(&file).unwrap(), "keep me");
        let (code, v) = run(&[&args[..], &["--force"]].concat(), &project, None);
        assert_eq!(code, 0, "{v}");
        assert_ne!(std::fs::read_to_string(&file).unwrap(), "keep me");
    }
}

/// `/` links to five pages; every other path is a plain page. Serves until the test process ends.
fn serve_links() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut s) = stream else { continue };
            std::thread::spawn(move || {
                let mut buf = vec![0u8; 16384];
                let mut len = 0;
                while !buf[..len].windows(4).any(|w| w == b"\r\n\r\n") {
                    match s.read(&mut buf[len..]) {
                        Ok(0) | Err(_) => return,
                        Ok(n) => len += n,
                    }
                }
                let line = String::from_utf8_lossy(&buf[..len]).lines().next().unwrap_or("").to_string();
                let body = if line.starts_with("GET / ") {
                    "<a href=/a>a</a><a href=/b>b</a><a href=/c>c</a><a href=/d>d</a><a href=/e>e</a>"
                } else {
                    "page"
                };
                let resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = s.write_all(resp.as_bytes());
            });
        }
    });
    port
}

#[test]
fn crawl_rate_holds_across_concurrency() {
    let port = serve_links();
    let project = tmp_project("crawlrate");
    let site = format!("http://127.0.0.1:{port}/");
    // 6 requests at 4/s take at least 1.25 s; the old per-batch delay sent the 5 links at once.
    let (code, v) = run(&["crawl", &site, "--rate", "4", "-c", "10", "--no-robots", "--no-sitemap"], &project, None);
    assert_eq!(code, 0, "{v}");
    assert_eq!(v["data"]["requests"], 6, "{v}");
    assert!(v["data"]["elapsed_ms"].as_u64().unwrap() >= 1200, "{v}");
}

#[test]
fn scan_active_skips_methods_outside_the_defaults() {
    let port = serve_site();
    let project = tmp_project("methods");
    let req = format!("DELETE /item?id=1 HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n\r\n");
    let (code, v) = run(&["send", "--scheme", "http"], &project, Some(req.as_bytes()));
    assert_eq!(code, 0, "{v}");
    let (code, v) = run(&["scan", "active", "--rules", "40018", "--no-oob"], &project, None);
    assert_eq!(code, 2, "{v}");
    let (code, v) =
        run(&["scan", "active", "--rules", "40018", "--no-oob", "--include-methods", "delete"], &project, None);
    assert_eq!(code, 0, "{v}");
    assert_eq!(v["data"]["targets"], 1, "{v}");
    assert!(v["data"].get("post_hint").is_none(), "{v}");
    // Naming it by id still needs its method.
    let id = run(&["query", "SELECT id FROM history WHERE method = 'DELETE' LIMIT 1"], &project, None).1["data"]
        ["rows"][0][0]
        .to_string();
    let named = ["scan", "active", "--rules", "40018", "--no-oob", "--history-id", &id];
    let (code, v) = run(&named, &project, None);
    assert_eq!(code, 2, "{v}");
    assert!(v["error"]["message"].as_str().unwrap().contains("--include-methods DELETE"), "{v}");
    let (code, v) = run(&[&named[..], &["--include-methods", "DELETE"]].concat(), &project, None);
    assert_eq!(code, 0, "{v}");
}

#[test]
fn scan_active_attacks_post_by_default_and_warns() {
    let port = serve_site();
    let project = tmp_project("post-warning");
    for req in [
        format!("POST /contact HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 5\r\n\r\nmsg=1"),
        format!("GET /item?id=1 HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n\r\n"),
    ] {
        let (code, v) = run(&["send", "--scheme", "http"], &project, Some(req.as_bytes()));
        assert_eq!(code, 0, "{v}");
    }
    let (code, v) = run(&["scan", "active", "--rules", "40018", "--no-oob"], &project, None);
    assert_eq!(code, 0, "{v}");
    assert_eq!(v["data"]["targets"], 2, "{v}");
    assert_eq!(v["data"]["post_targets"], 1, "{v}");
    let hint = v["data"]["post_hint"].as_str().unwrap();
    assert!(hint.contains("side effects such as email"), "{v}");
    assert!(v["data"].get("skipped_methods").is_none(), "{v}");
    // No POST target, nothing to warn about.
    let (code, v) =
        run(&["scan", "active", "--rules", "40018", "--no-oob", "--where", "method <> 'POST'"], &project, None);
    assert_eq!(code, 0, "{v}");
    assert_eq!(v["data"]["targets"], 1, "{v}");
    assert!(v["data"].get("post_targets").is_none(), "{v}");
    assert!(v["data"].get("post_hint").is_none(), "{v}");
    // Text mode warns on stderr, before the attack; stdout stays the summary.
    let o = bin()
        .args(["--format", "text", "--project"])
        .arg(&project)
        .args(["scan", "active", "--rules", "40018", "--no-oob"])
        .output()
        .unwrap();
    assert!(o.status.success());
    assert!(String::from_utf8_lossy(&o.stderr).contains("warning: 1 POST target(s). POST requests are replayed"));
    assert!(!String::from_utf8_lossy(&o.stdout).contains("POST"));
}

#[test]
fn scan_active_help_warns_about_post() {
    let o = bin().args(["scan", "active", "--help"]).output().unwrap();
    let help = String::from_utf8_lossy(&o.stdout);
    assert!(help.contains("side effects such as email"), "{help}");
}

#[test]
fn scan_active_url_path_attacks_each_route_once() {
    let port = serve_site();
    let project = tmp_project("routes");
    // No passive scan of what's sent: it takes seconds per request in a debug build.
    run(&["scan", "sources", "proxy"], &project, None);
    let mut ids = vec![];
    for path in ["/users/999", "/users/1", "/users/2", "/assets/js/a.js", "/assets/js/b.js", "/files/a.pdf"] {
        let req = format!("GET {path} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n\r\n");
        let (code, v) = run(&["send", "--scheme", "http"], &project, Some(req.as_bytes()));
        assert_eq!(code, 0, "{v}");
        ids.push(v["data"]["id"].as_i64().unwrap_or_else(|| panic!("{v}")).to_string());
    }
    let scan = ["scan", "active", "--rules", "40018", "--no-oob"];
    let (_, v) = run(&scan, &project, None);
    assert_eq!(v["data"]["targets"], 6, "only with --url-path: {v}");
    let (code, v) = run(&[&scan[..], &["--url-path"]].concat(), &project, None);
    assert_eq!(code, 0, "{v}");
    // /users/{id}, /assets/js/{asset} and /files/a.pdf, with 2 + 3 + 2 segments.
    assert_eq!(v["data"]["targets"], 3, "{v}");
    assert_eq!(v["data"]["insertion_points"], 7, "{v}");
    // The route's request that worked is the one attacked, not the 404 seen first.
    assert!(v["data"]["raised"].as_object().is_some_and(|r| !r.is_empty()), "{v}");
    // Requests asked for by id are all attacked.
    let named = ["--url-path", "--history-id", &ids[0], "--history-id", &ids[1], "--history-id", &ids[2]];
    let (code, v) = run(&[&scan[..], &named].concat(), &project, None);
    assert_eq!(code, 0, "{v}");
    assert_eq!(v["data"]["targets"], 3, "{v}");
}

#[test]
fn scan_active_url_path_keeps_the_history_order_under_the_target_cap() {
    let port = serve_site();
    let project = tmp_project("routecap");
    run(&["scan", "sources", "proxy"], &project, None);
    // A route that only ever answered 404 comes first, and isn't cut for it.
    for path in ["/old/users/999", "/users/1"] {
        let req = format!("GET {path} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n\r\n");
        let (code, v) = run(&["send", "--scheme", "http"], &project, Some(req.as_bytes()));
        assert_eq!(code, 0, "{v}");
    }
    let scan = ["scan", "active", "--rules", "40018", "--no-oob", "--url-path", "--max-targets", "1"];
    let (code, v) = run(&scan, &project, None);
    assert_eq!(code, 0, "{v}");
    assert_eq!(v["data"]["insertion_points"], 3, "{v}");
}

#[test]
fn stop_never_signals_a_process_it_cannot_verify() {
    use brainproxy_core::store::Store;
    use serde_json::json;
    let project = tmp_project("pids");
    let set = |key: &str, v: &Value| Store::open(&project).unwrap().meta_set(key, Some(&v.to_string())).unwrap();
    let proxy = |pid: u64, start: Option<u64>| json!({"pid": pid, "listen": "127.0.0.1:1", "started": "0", "ca_cert": "/x", "log": null, "start_time": start});
    let oob = |pid: u64| {
        json!({"pid": pid, "started": "0", "tcp_listen": "127.0.0.1:1", "dns_listen": null, "public_ip": null,
               "endpoint": {"domain": null, "public_host": "127.0.0.1", "public_port": 1}, "log": null})
    };
    // kill(-1) / kill(0) / init that can't be verified or is another process, and a reused
    // pid (this test, with another start time): none is taken for a running proxy or
    // listener, so nothing gets signalled.
    let me = std::process::id() as u64;
    for (pid, start) in [(4294967295, None), (0, None), (1, None), (1, Some(1)), (me, Some(1))] {
        set("proxy.state", &proxy(pid, start));
        let (_, v) = run(&["proxy", "status"], &project, None);
        assert_eq!(v["data"]["running"], false, "{pid}: {v}");
        set("proxy.state", &proxy(pid, start));
        let (code, v) = run(&["proxy", "stop"], &project, None);
        assert_eq!((code, v["error"]["kind"].as_str()), (4, Some("not_found")), "{pid}: {v}");
        let mut o = oob(pid);
        o["start_time"] = json!(start);
        set("oob.state", &o);
        let (code, v) = run(&["oob", "stop"], &project, None);
        assert_eq!((code, v["error"]["kind"].as_str()), (4, Some("not_found")), "{pid}: {v}");
    }
    // State from an older version (no start time) for a live process that ignores
    // SIGTERM: it gets SIGTERM, never SIGKILL, and the user is told.
    #[cfg(unix)]
    {
        // `exec`, so the pid is the sleep itself (an ignored signal stays ignored across
        // exec). A shell that forks it instead leaves it running when the shell is killed
        // below, still holding this test's stderr.
        let mut child = Command::new("sh").args(["-c", "trap '' TERM; exec sleep 30"]).spawn().unwrap();
        std::thread::sleep(std::time::Duration::from_millis(200));
        set("oob.state", &oob(child.id() as u64));
        let (_, v) = run(&["oob", "status"], &project, None);
        assert_eq!(v["data"]["running"], true, "old state is still read: {v}");
        set("proxy.state", &proxy(child.id() as u64, None));
        let (_, v) = run(&["proxy", "stop"], &project, None);
        assert_eq!(v["error"]["kind"], "conflict", "{v}");
        assert!(v["error"]["message"].as_str().unwrap().contains("not sending SIGKILL"), "{v}");
        assert!(child.try_wait().unwrap().is_none(), "the unverified process was killed");
        child.kill().unwrap();
        child.wait().unwrap();
    }
}

/// Answers every request with 200 and a session cookie, keeping the raw requests it got.
fn serve_recording() -> (u16, std::sync::Arc<std::sync::Mutex<Vec<String>>>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let seen = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    let log = seen.clone();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let mut s = stream.unwrap();
            let mut buf = vec![0u8; 65536];
            let mut len = 0;
            loop {
                let n = s.read(&mut buf[len..]).unwrap();
                len += n;
                let text = String::from_utf8_lossy(&buf[..len]).to_string();
                let Some(i) = text.find("\r\n\r\n") else { continue };
                let cl = text
                    .lines()
                    .find_map(|l| l.to_ascii_lowercase().strip_prefix("content-length:").map(|v| v.trim().to_string()))
                    .map_or(0, |v| v.parse::<usize>().unwrap());
                if n == 0 || len >= i + 4 + cl {
                    break;
                }
            }
            log.lock().unwrap().push(String::from_utf8_lossy(&buf[..len]).to_string());
            let _ = s.write_all(
                b"HTTP/1.1 200 OK\r\nSet-Cookie: sid=SESSIONVAL77\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok",
            );
        }
    });
    (port, seen)
}

#[test]
fn auth_secrets_stay_out_of_history_and_replay_fills_them_in() {
    let (port, seen) = serve_recording();
    let project = tmp_project("auth-history");
    let base = format!("http://127.0.0.1:{port}");
    let login_url = format!("{base}/login");
    let args = [
        "auth",
        "add",
        "p",
        "--login-url",
        &login_url,
        "--login-body",
        "u={{username}}&pw={{password}}",
        "--username",
        "alice",
        "--password",
        "S3cretPW",
        "--header",
        "X-Api-Key: APIKEY123",
    ];
    let (code, v) = run(&args, &project, None);
    assert_eq!(code, 0, "{v}");
    let (code, v) = run(&["send", "--url", &format!("{base}/data"), "--auth", "p"], &project, None);
    assert_eq!(code, 0, "{v}");
    let send_id = v["data"]["id"].as_i64().unwrap();

    // The server got the real values: password in the login, key and session cookie after.
    {
        let got = seen.lock().unwrap();
        assert!(got.iter().any(|r| r.starts_with("POST /login") && r.ends_with("pw=S3cretPW")), "{got:?}");
        let data = got.iter().find(|r| r.starts_with("GET /data")).unwrap();
        assert!(data.contains("X-Api-Key: APIKEY123\r\n") && data.contains("sid=SESSIONVAL77"), "{data}");
    }

    // History holds placeholders, whichever way it is read.
    let secrets = ["S3cretPW", "APIKEY123", "SESSIONVAL77"];
    let sql = "SELECT url, req_headers, req_body_text, CAST(request AS TEXT) FROM history";
    let (code, v) = run(&["query", sql], &project, None);
    assert_eq!(code, 0, "{v}");
    let rows = v["data"].to_string();
    assert!(rows.contains("«auth:p:header:X-Api-Key»") && rows.contains("«auth:p:password:form»"), "{rows}");
    for s in secrets {
        assert!(!rows.contains(s), "{s} in history: {rows}");
    }
    let (_, v) = run(&["history", "show", &send_id.to_string()], &project, None);
    let shown = v["data"]["request"].to_string();
    assert!(shown.contains("sid=«auth:p:cookie:sid»"), "{shown}");
    for s in secrets {
        assert!(!shown.contains(s), "{s} in history show: {shown}");
    }

    // Re-sending stored requests (as Replay does) puts the current values back.
    let (_, v) = run(&["query", "SELECT id FROM history WHERE path = '/login'"], &project, None);
    let login_id = v["data"]["rows"][0][0].as_i64().unwrap();
    for id in [send_id, login_id] {
        let raw = bin()
            .args(["--project"])
            .arg(&project)
            .args(["history", "show", &id.to_string(), "--part", "request", "--raw"])
            .output()
            .unwrap()
            .stdout;
        let (code, v) = run(&["send", "--scheme", "http", "-"], &project, Some(&raw));
        assert_eq!(code, 0, "{v}");
    }
    {
        let got = seen.lock().unwrap();
        let data: Vec<_> = got.iter().filter(|r| r.starts_with("GET /data")).collect();
        assert_eq!(data.len(), 2);
        assert!(data[1].contains("X-Api-Key: APIKEY123\r\n") && data[1].contains("sid=SESSIONVAL77"), "{}", data[1]);
        let logins: Vec<_> = got.iter().filter(|r| r.starts_with("POST /login")).collect();
        assert!(logins.len() == 2 && logins[1].ends_with("pw=S3cretPW"), "{logins:?}");
    }
    let (_, v) = run(&["query", sql], &project, None);
    assert!(secrets.iter().all(|s| !v["data"].to_string().contains(s)), "{v}");

    // With the profile gone, a re-send fails clearly instead of sending the placeholder.
    run(&["auth", "remove", "p"], &project, None);
    let raw = format!("GET /data HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nX-Api-Key: «auth:p:header:X-Api-Key»\r\n\r\n");
    let (code, v) = run(&["send", "--scheme", "http", "-"], &project, Some(raw.as_bytes()));
    assert_ne!(code, 0, "{v}");
    assert!(v["error"]["message"].as_str().unwrap().contains("«auth:p:header:X-Api-Key»"), "{v}");
}

#[test]
fn history_contains_takes_the_gui_arguments_and_finds_no_secrets() {
    let (port, _) = serve_recording();
    let project = tmp_project("contains");
    let base = format!("http://127.0.0.1:{port}");
    let login_url = format!("{base}/login");
    let args = [
        "auth",
        "add",
        "p",
        "--login-url",
        &login_url,
        "--login-body",
        "u={{username}}&pw={{password}}",
        "--username",
        "alice",
        "--password",
        "S3cretPW",
        "--header",
        "X-Api-Key: APIKEY123",
    ];
    let (code, v) = run(&args, &project, None);
    assert_eq!(code, 0, "{v}");
    let (code, v) = run(&["send", "--url", &format!("{base}/data"), "--auth", "p"], &project, None);
    assert_eq!(code, 0, "{v}");
    let mut sent = Vec::new();
    for body in ["q=-tok=1&a", "q=other", "q=-tok=3&b"] {
        let req = format!("POST /f HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nContent-Length: {}\r\n\r\n{body}", body.len());
        let (code, v) = run(&["send", "--scheme", "http"], &project, Some(req.as_bytes()));
        assert_eq!(code, 0, "{v}");
        sent.push(v["data"]["id"].as_i64().unwrap());
    }
    let ids = |args: &[&str]| {
        let (code, v) = run(&[&["history", "list"], args].concat(), &project, None);
        assert_eq!(code, 0, "{v}");
        v["data"]["items"].as_array().unwrap().iter().map(|i| i["id"].as_i64().unwrap()).collect::<Vec<_>>()
    };

    // The GUI passes the text as --contains=TEXT, so a leading dash or an = sign is part of it.
    let first = sent[0].to_string();
    assert_eq!(ids(&["--contains=-tok=", "--source=send", "--after=0", "--limit=2000"]), [sent[0], sent[2]]);
    assert_eq!(ids(&["--contains=-tok=", "--source=send", "--after=0", "--limit=1"]), [sent[0]]);
    assert_eq!(ids(&["--contains=-tok=", "--source=send", &format!("--after={first}"), "--limit=2000"]), [sent[2]]);
    assert!(ids(&["--contains=-tok=", "--source=proxy", "--after=0", "--limit=2000"]).is_empty());
    assert!(ids(&["--contains=-TOK=", "--after=0"]).is_empty(), "case-sensitive");

    // Auth secrets are stored as placeholders, so searching for them finds nothing.
    for secret in ["S3cretPW", "APIKEY123"] {
        assert!(ids(&[&format!("--contains={secret}")]).is_empty(), "{secret}");
    }
    assert!(!ids(&["--contains=«auth:p:password:form»"]).is_empty());
    assert!(!ids(&["--contains=«auth:p:header:X-Api-Key»"]).is_empty());

    // The flag's help (and the history_list MCP tool, built from it) says how it matches.
    let (code, v) = run(&["capabilities", "history", "list"], &project, None);
    assert_eq!(code, 0, "{v}");
    let arg = v["data"]["args"].as_array().unwrap().iter().find(|a| a["flag"] == "--contains").unwrap();
    let help = arg["help"].as_str().unwrap();
    for words in ["decoded bodies", "Case-sensitive and literal", "URL-encoded", "JSON-escaped"] {
        assert!(help.contains(words), "{help}");
    }
}

#[test]
fn history_filter_takes_the_gui_arguments() {
    let (port, _) = serve_recording();
    let project = tmp_project("filter");
    let mut sent = Vec::new();
    for (method, path, body) in
        [("POST", "/api/login", "user=alice"), ("GET", "/health", ""), ("PUT", "/api/items/7", "{\"n\":1}")]
    {
        let req = format!(
            "{method} {path} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nX-Trace: t-{path}\r\nContent-Length: {}\r\n\r\n{body}",
            body.len()
        );
        let (code, v) = run(&["send", "--scheme", "http"], &project, Some(req.as_bytes()));
        assert_eq!(code, 0, "{v}");
        sent.push(v["data"]["id"].as_i64().unwrap());
    }
    let ids = |args: &[&str]| {
        let (code, v) = run(&[&["history", "list"], args].concat(), &project, None);
        assert_eq!(code, 0, "{v}");
        v["data"]["items"].as_array().unwrap().iter().map(|i| i["id"].as_i64().unwrap()).collect::<Vec<_>>()
    };

    // The GUI passes the query as --filter=QUERY with --after and --limit, as it does --contains.
    assert_eq!(ids(&["--filter=path:/api/ NOT method=put", "--after=0", "--limit=2000"]), [sent[0]]);
    assert_eq!(ids(&["--filter=req.body:ALICE OR req.header.x-trace~\"items\"", "--after=0"]), [sent[0], sent[2]]);
    assert_eq!(
        ids(&["--filter=status:2xx resp.header.set-cookie:*", &format!("--after={}", sent[0])]),
        [sent[1], sent[2]]
    );
    assert_eq!(ids(&["--filter=-x", "--source=send"]), Vec::<i64>::new(), "a leading dash is part of the query");
    assert_eq!(ids(&["--filter=health", "--source=send", "--limit=1"]), [sent[1]]);

    // A query that doesn't parse is invalid input, and says where.
    let (code, v) = run(&["history", "list", "--filter=stauts:200"], &project, None);
    assert_eq!(code, 2, "{v}");
    assert_eq!(v["error"]["kind"], "invalid_input");
    assert!(v["error"]["message"].as_str().unwrap().contains("unknown field \"stauts\" at position 1"), "{v}");

    // Saved Traffic filters live in the project, guarded by a revision.
    let save = |args: &[&str], body: &str| {
        run(&[&["history", "filters", "save"], args].concat(), &project, Some(body.as_bytes()))
    };
    let (code, v) = save(
        &["--if-revision", "0"],
        r#"{"filters": [{"name": "api", "filter": {"text": "path:/api/", "query": true}}]}"#,
    );
    assert_eq!(code, 0, "{v}");
    assert_eq!((v["data"]["count"].as_u64(), v["data"]["rev"].as_u64()), (Some(1), Some(1)));
    let (code, v) = save(&["--if-revision", "0"], r#"{"filters": []}"#);
    assert_eq!((code, v["error"]["kind"].as_str()), (2, Some("conflict")), "{v}");
    let (code, v) = save(&["--append"], r#"{"filters": [{"name": "api", "filter": {}}]}"#);
    assert_eq!((code, v["error"]["kind"].as_str()), (2, Some("conflict")), "{v}");
    let (code, v) =
        save(&["--append"], r#"{"filters": [{"name": "bad", "filter": {"query": true, "text": "stauts:1"}}]}"#);
    assert_eq!((code, v["error"]["kind"].as_str()), (2, Some("invalid_input")), "{v}");
    let (code, v) = save(&["--append"], r#"{"filters": [{"name": "health", "filter": {"text": "health"}}]}"#);
    assert_eq!(code, 0, "{v}");
    let (code, v) = run(&["history", "filters", "list"], &project, None);
    assert_eq!(code, 0, "{v}");
    assert_eq!(v["data"]["rev"], 2);
    let listed: Vec<(&str, &str)> = v["data"]["filters"]
        .as_array()
        .unwrap()
        .iter()
        .map(|f| (f["name"].as_str().unwrap(), f["mode"].as_str().unwrap()))
        .collect();
    assert_eq!(listed, [("api", "query"), ("health", "url")]);
    // A saved query is the text --filter takes.
    let query = v["data"]["filters"][0]["filter"]["text"].as_str().unwrap().to_string();
    assert_eq!(ids(&[&format!("--filter={query}")]), [sent[0], sent[2]]);

    // The notes (and the history_list MCP tool, built from them) list the fields.
    let (code, v) = run(&["capabilities", "history", "list"], &project, None);
    assert_eq!(code, 0, "{v}");
    let notes = v["data"]["notes"].as_str().unwrap();
    for words in ["resp.header.NAME", "status:5xx", "(?i)", "NOT status:500 keeps requests"] {
        assert!(notes.contains(words), "{notes}");
    }
}

#[test]
fn auth_add_reads_a_literal_password_from_the_environment() {
    let project = tmp_project("pwenv");
    let out = bin()
        .args(["--format", "json", "--project"])
        .arg(&project)
        .args(["auth", "add", "--login-url", "http://127.0.0.1:1/login", "--username", "u", "p"])
        .env("BRAINPROXY_SECRET_PASSWORD", "-Pa55")
        .output()
        .unwrap();
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stdout));
    let (_, v) = run(&["auth", "show", "p"], &project, None);
    assert!(v["data"]["profile"]["password"]["literal"].is_string(), "{v}");
    assert!(!v.to_string().contains("-Pa55"), "{v}");
}

/// Replay's Race: `send --target=T --race=N -` with the tab's request on stdin.
#[test]
fn race_from_stdin_as_replay_runs_it() {
    let (port, seen) = serve_recording();
    let project = tmp_project("race-replay");
    let target = format!("--target=http://127.0.0.1:{port}");
    let (code, v) = run(&["auth", "add", "k", "--header", "X-Api-Key: APIKEY123"], &project, None);
    assert_eq!(code, 0, "{v}");

    // A stored request with a placeholder (Unix line endings, as the editor has them):
    // every racing request carries the real value, history keeps the placeholder.
    let raw = format!("GET /race HTTP/1.1\nHost: 127.0.0.1:{port}\nX-Api-Key: «auth:k:header:X-Api-Key»\n\n");
    let (code, v) = run(&["send", &target, "--race=3", "-"], &project, Some(raw.as_bytes()));
    assert_eq!(code, 0, "{v}");
    let d = &v["data"];
    assert_eq!((d["race"].as_u64(), d["sync"].as_str()), (Some(3), Some("last-byte")), "{d}");
    assert_eq!(d["distinct_responses"], serde_json::json!({"200 2B": 3}), "{d}");
    for r in d["results"].as_array().unwrap() {
        assert!(r["id"].is_i64() && r["status"] == 200 && r["length"] == 2 && r["duration_ms"].is_u64(), "{r}");
    }
    {
        let got = seen.lock().unwrap();
        assert_eq!(got.len(), 3, "{got:?}");
        assert!(got.iter().all(|r| r.starts_with("GET /race ") && r.contains("X-Api-Key: APIKEY123\r\n")), "{got:?}");
    }
    let (_, v) =
        run(&["query", "SELECT CAST(request AS TEXT), req_headers FROM history WHERE source = 'race'"], &project, None);
    assert_eq!(v["data"]["rows"].as_array().unwrap().len(), 3, "{v}");
    let rows = v["data"].to_string();
    assert!(rows.contains("«auth:k:header:X-Api-Key»") && !rows.contains("APIKEY123"), "{rows}");
    // The app opens each raced response by its id.
    let id = d["results"][0]["id"].to_string();
    let (code, v) = run(&["history", "show", &id, "--max-body=2000000"], &project, None);
    assert_eq!((code, v["data"]["response"]["status"].as_u64()), (0, Some(200)), "{v}");

    // Each row says which race it was in, how it was run, and its place in it.
    let race_id = d["race_id"].as_str().unwrap().to_string();
    let (_, v) = run(&["query", "SELECT tags FROM history WHERE source = 'race' ORDER BY id"], &project, None);
    let tags: Vec<Vec<String>> = v["data"]["rows"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| serde_json::from_str(r[0].as_str().unwrap()).unwrap())
        .collect();
    for (i, t) in tags.iter().enumerate() {
        let want = [format!("race:{race_id}"), "race-sync:last-byte".into(), format!("race-pos:{}/3", i + 1)];
        assert_eq!(t, &want, "{tags:?}");
    }
    let (_, v) = run(&["history", "list", "--tag", &format!("race:{race_id}")], &project, None);
    assert_eq!(v["data"]["count"], 3, "{v}");

    // With the profile gone, no racing request goes out with the placeholder.
    run(&["auth", "remove", "k"], &project, None);
    let (code, v) = run(&["send", &target, "--race=3", "-"], &project, Some(raw.as_bytes()));
    assert_eq!(code, 0, "{v}");
    for r in v["data"]["results"].as_array().unwrap() {
        let named = r["error"].as_str().is_some_and(|e| e.contains("«auth:k:header:X-Api-Key»"));
        assert!(named && r["kind"] == "invalid_input" && r["id"].is_i64(), "{r}");
    }
    assert_eq!(seen.lock().unwrap().len(), 3);
    // A second race of the same request has an id of its own.
    assert_ne!(v["data"]["race_id"].as_str(), Some(race_id.as_str()), "{v}");

    // The counts the app allows: 1000 at most, and 100 for a request line in HTTP/2.
    // Both are refused before anything is sent.
    let (code, v) = run(&["send", &target, "--race=1001", "-"], &project, Some(raw.as_bytes()));
    assert_eq!((code, v["error"]["kind"].as_str()), (2, Some("invalid_input")), "{v}");
    let h2 = format!("GET /race HTTP/2\nHost: 127.0.0.1:{port}\n\n");
    let (code, v) = run(&["send", &target, "--race=101", "-"], &project, Some(h2.as_bytes()));
    assert_eq!((code, v["error"]["kind"].as_str()), (2, Some("invalid_input")), "{v}");
    assert!(v["error"]["message"].as_str().unwrap().contains("1 to 100"), "{v}");
    assert_eq!(seen.lock().unwrap().len(), 3);
}

/// A race whose requests all fail still answers, one error per request, and records each.
#[test]
fn race_failures_come_back_per_request() {
    // Bind and drop to get a port with nothing listening.
    let port = TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port();
    let project = tmp_project("race-fail");
    let raw = format!("GET / HTTP/1.1\nHost: 127.0.0.1:{port}\n\n");
    let (code, v) =
        run(&["send", &format!("--target=http://127.0.0.1:{port}"), "--race=2", "-"], &project, Some(raw.as_bytes()));
    assert_eq!(code, 0, "{v}");
    let d = &v["data"];
    // Each failure comes back with the id of the row that records it.
    for r in d["results"].as_array().unwrap() {
        assert!(r["error"].is_string() && r["kind"] == "connect" && r["id"].is_i64(), "{r}");
        let (code, v) = run(&["history", "show", &r["id"].to_string()], &project, None);
        assert_eq!((code, v["data"]["entry"]["error"].as_str()), (0, r["error"].as_str()), "{v}");
    }
    assert_eq!(d["distinct_responses"], serde_json::json!({"error: connect": 2}), "{d}");
    let (_, v) = run(
        &[
            "query",
            "SELECT count(*) FROM history WHERE source = 'race' AND error IS NOT NULL AND tags LIKE '%race-pos:%/2%'",
        ],
        &project,
        None,
    );
    assert_eq!(v["data"]["rows"][0][0], 2, "{v}");

    // Unstored, each still has a row (no content) with the race's tags.
    let (code, v) = run(
        &["send", &format!("--target=http://127.0.0.1:{port}"), "--race=2", "--no-store", "-"],
        &project,
        Some(raw.as_bytes()),
    );
    assert_eq!(code, 0, "{v}");
    assert!(v["data"]["results"].as_array().unwrap().iter().all(|r| r["id"].is_i64()), "{v}");
    let tag = format!("race:{}", v["data"]["race_id"].as_str().unwrap());
    let (_, v) = run(&["history", "list", "--tag", &tag], &project, None);
    assert_eq!(v["data"]["count"], 2, "{v}");
}

/// A last-byte race opens a connection per request: a count the open-file limit has no room
/// for is refused before anything is sent, instead of failing locally request by request.
#[cfg(unix)]
#[test]
fn race_beyond_the_open_file_limit_is_refused() {
    use std::os::unix::process::CommandExt;
    let (port, seen) = serve_recording();
    let project = tmp_project("race-nofile");
    let raw = format!("GET / HTTP/1.1\nHost: 127.0.0.1:{port}\n\n");
    let race = |n: &str| {
        let mut cmd = bin();
        cmd.args(["--format", "json", "--project"]).arg(&project);
        cmd.args(["send", &format!("--target=http://127.0.0.1:{port}"), n, "-"]);
        // Soft and hard limit 128, as `ulimit -n 128` sets them: nothing to raise it to.
        // SAFETY: setrlimit is async-signal-safe.
        unsafe {
            cmd.pre_exec(|| {
                let lim = libc::rlimit { rlim_cur: 128, rlim_max: 128 };
                if libc::setrlimit(libc::RLIMIT_NOFILE, &lim) != 0 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
        let mut child = cmd.stdin(Stdio::piped()).stdout(Stdio::piped()).spawn().unwrap();
        // A command that fails on its arguments may exit before reading its stdin.
        let _ = child.stdin.take().unwrap().write_all(raw.as_bytes());
        let out = child.wait_with_output().unwrap();
        let v: Value = serde_json::from_slice(&out.stdout).unwrap();
        (out.status.code().unwrap(), v)
    };
    let (code, v) = race("--race=100");
    assert_eq!((code, v["error"]["kind"].as_str()), (2, Some("invalid_input")), "{v}");
    assert!(v["error"]["message"].as_str().unwrap().contains("open-file limit (128)"), "{v}");
    assert!(seen.lock().unwrap().is_empty());
    let (code, v) = race("--race=10");
    assert_eq!(code, 0, "{v}");
    assert!(v["data"]["results"].as_array().unwrap().iter().all(|r| r["status"] == 200), "{v}");
}

/// `findings add` records and never sends: a URL outside the engagement scope is kept with a
/// warning, and nothing reaches history.
#[test]
fn findings_added_by_hand_warn_outside_scope_and_send_nothing() {
    let project = tmp_project("manual-scope");
    let add = |project: &std::path::Path, title: &str, url: &str| {
        let (code, v) = run(&["findings", "add", "--title", title, "--risk", "low", "--url", url], project, None);
        assert_eq!(code, 0, "{v}");
        v["data"]["warnings"].as_array().unwrap().iter().map(|w| w.as_str().unwrap().to_string()).collect::<Vec<_>>()
    };
    // The scope lists 127.0.0.1 and localhost.
    assert!(add(&project, "In scope", "http://127.0.0.1:9/x").is_empty());
    assert!(add(&project, "Socket in scope", "ws://localhost/live").is_empty());
    let w = add(&project, "Elsewhere", "http://10.9.9.9/a");
    assert!(w.len() == 1 && w[0].contains("10.9.9.9:80") && w[0].contains("outside"), "{w:?}");
    let (_, v) = run(&["history", "list"], &project, None);
    assert_eq!(v["data"]["count"], 0, "{v}");
    let (_, v) = run(&["findings", "list", "--source", "manual", "--all"], &project, None);
    let items = v["data"]["items"].as_array().unwrap();
    assert!(items.len() == 3 && items.iter().all(|i| i["source"] == "manual"), "{v}");

    // A scope of names: another name can't be in it, ws(s) URLs count as http(s).
    let named = project.with_file_name("named.bpdb");
    let _ = std::fs::remove_file(&named);
    let (code, v) = run(&["engagement", "start", "--target", "app.test"], &named, None);
    assert_eq!(code, 0, "{v}");
    assert!(add(&named, "On the site", "https://app.test/a").is_empty());
    assert!(add(&named, "Socket on the site", "wss://app.test/live").is_empty());
    let w = add(&named, "Socket elsewhere", "wss://elsewhere.test/live");
    assert!(w.len() == 1 && w[0].contains("elsewhere.test:443"), "{w:?}");
    // In text, the warning comes before the result.
    let out = bin()
        .args(["--format", "text", "--project"])
        .arg(&named)
        .args(["findings", "add", "--title", "Elsewhere", "--risk", "low", "--url", "http://other.test/"])
        .output()
        .unwrap();
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(text.starts_with("warning: other.test:80 is outside") && text.contains("added finding"), "{text}");
}

/// Long texts come from a flag, a file, or stdin (only one of them), with clear errors.
#[test]
fn findings_add_reads_texts_from_files_and_stdin() {
    let project = tmp_project("manual-texts");
    let dir = project.parent().unwrap();
    let file = dir.join("solution.md");
    std::fs::write(&file, "Check the owner.\n").unwrap();
    let base = ["findings", "add", "--title", "Order IDOR", "--risk", "high", "--url", "http://127.0.0.1/orders/7"];
    fn args(v: &[String]) -> Vec<&str> {
        v.iter().map(String::as_str).collect()
    }
    let sol = file.to_str().unwrap();
    let with = |more: &[&str]| base.iter().chain(more).map(|a| a.to_string()).collect::<Vec<String>>();

    let (code, v) = run(
        &args(&with(&["--description-file", "-", "--solution-file", sol, "--cwe", "639", "--history-id", ""])),
        &project,
        Some("Any user\nreads any order.".as_bytes()),
    );
    // An empty --history-id is not an id.
    assert_eq!(code, 2, "{v}");
    let (code, v) = run(
        &args(&with(&["--description-file", "-", "--solution-file", sol, "--cwe", "639"])),
        &project,
        Some("Any user\nreads any order.".as_bytes()),
    );
    assert_eq!(code, 0, "{v}");
    let f = &v["data"]["finding"];
    assert_eq!(f["description"], "Any user\nreads any order.");
    assert_eq!(f["solution"], "Check the owner.");
    assert_eq!(
        (f["cwe"].as_i64(), f["confidence"].as_str(), f["state"].as_str()),
        (Some(639), Some("medium"), Some("open"))
    );
    let id = v["data"]["id"].as_i64().unwrap().to_string();
    let (_, v) = run(&["findings", "show", &id], &project, None);
    assert_eq!(v["data"]["history_ids"], serde_json::json!([]), "{v}");

    let fail = |more: &[&str], stdin: Option<&[u8]>| {
        let (code, v) = run(&args(&with(more)), &project, stdin);
        (code, v["error"]["kind"].as_str().unwrap_or_default().to_string(), v["error"]["message"].to_string())
    };
    // Two flags can't both read stdin.
    let (code, _, msg) = fail(&["--param", "a", "--description-file", "-", "--evidence-file", "-"], Some(b"x"));
    assert!(code == 2 && msg.contains("stdin"), "{msg}");
    // A text and its file flag together are a usage error.
    let (code, kind, _) = fail(&["--param", "b", "--solution", "x", "--solution-file", sol], None);
    assert_eq!((code, kind.as_str()), (2, "usage"));
    let missing = dir.join("missing.txt");
    let (code, kind, _) = fail(&["--param", "c", "--evidence-file", missing.to_str().unwrap()], None);
    assert_eq!((code, kind.as_str()), (4, "not_found"));
    let binary = dir.join("binary.bin");
    std::fs::write(&binary, [0xff, 0xfe, 0x00]).unwrap();
    let (code, _, msg) = fail(&["--param", "d", "--description-file", binary.to_str().unwrap()], None);
    assert!(code == 2 && msg.contains("UTF-8"), "{msg}");
    let (code, _, msg) = fail(&["--param", "e", "--description-file", "-"], Some(&[0xff, 0xfe]));
    assert!(code == 2 && msg.contains("UTF-8"), "{msg}");
    // A history entry that doesn't exist, a bad risk, and a URL that isn't one.
    assert_eq!(fail(&["--param", "f", "--history-id", "99"], None).0, 4);
    let (code, v) =
        run(&["findings", "add", "--title", "X", "--risk", "severe", "--url", "http://a.test/"], &project, None);
    assert_eq!((code, v["error"]["kind"].as_str()), (2, Some("usage")));
    let (code, v) =
        run(&["findings", "add", "--title", "X", "--risk", "low", "--url", "javascript:alert(1)"], &project, None);
    assert_eq!((code, v["error"]["kind"].as_str()), (2, Some("invalid_input")), "{v}");
    // None of these was stored.
    let (_, v) = run(&["findings", "list", "--source", "manual", "--all"], &project, None);
    assert_eq!(v["data"]["items"].as_array().unwrap().len(), 1, "{v}");
    // --input-json takes the texts from stdin as JSON, and not with a text flag too. Another
    // solution than the one findings of this title share is refused unless --replace-text.
    let json = br#"{"solution": "Check the owner, always.", "evidence": "token=abc"}"#;
    let (code, kind, msg) = fail(&["--param", "g", "--input-json"], Some(json));
    assert!(code == 2 && kind == "conflict" && msg.contains("--replace-text"), "{kind} {msg}");
    let (code, v) = run(&args(&with(&["--param", "g", "--input-json", "--replace-text"])), &project, Some(json));
    assert_eq!(code, 0, "{v}");
    let f = &v["data"]["finding"];
    assert_eq!((f["evidence"].as_str(), f["solution"].as_str()), (Some("token=abc"), Some("Check the owner, always.")));
    assert_eq!(f["replaced_texts"][0]["solution"], "Check the owner.", "{v}");
    let w = v["data"]["warnings"].as_array().unwrap();
    assert!(w.len() == 1 && w[0].as_str().unwrap().contains("replaced the solution"), "{v}");
    let (code, kind, _) = fail(&["--param", "h", "--input-json", "--evidence", "x"], Some(b"{}"));
    assert_eq!((code, kind.as_str()), (2, "usage"));
    let (code, _, msg) = fail(&["--param", "h", "--input-json"], Some(br#"{"notes": "x"}"#));
    assert!(code == 2 && msg.contains("--input-json"), "{msg}");
    let g = v["data"]["id"].to_string();
    let (_, v) = run(&["findings", "remove", &g], &project, None);
    assert_eq!(v["data"]["removed"], 1, "{v}");
    // Removing one that isn't there removes nothing.
    let (code, v) = run(&["findings", "remove", &id, "99"], &project, None);
    assert_eq!((code, v["error"]["kind"].as_str()), (4, Some("not_found")));
    let (code, v) = run(&["findings", "remove", &id], &project, None);
    assert_eq!((code, v["data"]["removed"].as_i64()), (0, Some(1)));
    // Removed findings stay, hidden unless asked for; removing one again is refused.
    let (code, v) = run(&["findings", "remove", &id], &project, None);
    assert_eq!((code, v["error"]["kind"].as_str()), (2, Some("conflict")), "{v}");
    let (_, v) = run(&["findings", "list", "--source", "manual", "--all"], &project, None);
    assert_eq!(v["data"]["items"].as_array().unwrap().len(), 0, "{v}");
    let (_, v) = run(&["findings", "list", "--source", "manual", "--all", "--state", "all"], &project, None);
    let items = v["data"]["items"].as_array().unwrap();
    assert!(items.len() == 2 && items.iter().all(|i| i["state"] == "removed"), "{v}");
    let (_, v) = run(&["findings", "show", &g], &project, None);
    assert_eq!((v["data"]["state"].as_str(), v["data"]["removed"]["state"].as_str()), (Some("removed"), Some("open")));
    let (code, v) = run(&["findings", "mark", &g, "--state", "confirmed"], &project, None);
    assert_eq!((code, v["error"]["kind"].as_str()), (2, Some("conflict")), "{v}");
    // A tool call can't remove findings, even when run outside the server.
    let out = bin()
        .env("BRAINPROXY_MCP_CALL", "1")
        .args(["--format", "json", "--project"])
        .arg(&project)
        .args(["findings", "remove", "99"])
        .output()
        .unwrap();
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert!(v["error"]["message"].as_str().unwrap().contains("false_positive"), "{v}");
}

/// The URL can come on stdin with the texts, out of the process list, and a linked entry on
/// another site is warned about, with every linked entry's method and URL in the result.
#[test]
fn findings_add_takes_the_url_on_stdin_and_checks_its_links() {
    let project = tmp_project("manual-links");
    let (here, there) = (serve(1), serve(1));
    let sent: Vec<String> = [here, there]
        .iter()
        .map(|port| {
            let (code, v) = run(&["send", "--url", &format!("http://127.0.0.1:{port}/orders/7")], &project, None);
            assert_eq!(code, 0, "{v}");
            v["data"]["id"].to_string()
        })
        .collect();
    let add = |more: &[&str], stdin: Option<&[u8]>| {
        let mut a = vec!["findings", "add", "--title", "Token in URL", "--risk", "medium"];
        a.extend_from_slice(more);
        run(&a, &project, stdin)
    };
    let json = format!(r#"{{"url": "http://127.0.0.1:{here}/reset?token=FAKE-TOKEN", "method": "post"}}"#);
    let (code, v) = add(&["--input-json", "--history-id", &sent.join(",")], Some(json.as_bytes()));
    assert_eq!(code, 0, "{v}");
    let f = &v["data"]["finding"];
    let url = format!("http://127.0.0.1:{here}/reset?token=FAKE-TOKEN");
    assert_eq!((f["url"].as_str(), f["method"].as_str()), (Some(url.as_str()), Some("POST")));
    let links = v["data"]["history"].as_array().unwrap();
    assert_eq!(links.len(), 2, "{v}");
    assert_eq!(links[1]["url"], format!("http://127.0.0.1:{there}/orders/7"));
    assert_eq!((links[0]["other_site"].as_bool(), links[1]["other_site"].as_bool()), (Some(false), Some(true)));
    let w = v["data"]["warnings"].as_array().unwrap();
    assert!(w.len() == 1 && w[0].as_str().unwrap().contains(&format!("GET http://127.0.0.1:{there}/orders/7")), "{v}");
    // Not both ways.
    let (code, v) = add(&["--url", "http://127.0.0.1/a", "--input-json"], Some(br#"{"url": "http://127.0.0.1/b"}"#));
    assert!(code == 2 && v["error"]["message"].as_str().unwrap().contains("--url"), "{v}");
}

#[test]
fn a_server_name_outside_the_scope_is_refused() {
    // Accepts connections, counts them and says nothing: the check comes before the connection.
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let accepted = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let counted = accepted.clone();
    std::thread::spawn(move || {
        let mut held = vec![];
        for s in listener.incoming().flatten() {
            counted.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            held.push(s);
        }
    });
    let project = tmp_project("sni");
    let url = format!("https://127.0.0.1:{port}/");
    for http2 in [false, true] {
        let mut args = vec!["send", "--url", &url, "--sni", "other-tenant.test", "--timeout", "2"];
        args.extend(http2.then_some("--http2"));
        let (code, v) = run(&args, &project, None);
        assert_ne!(code, 0, "{v}");
        assert!(v["error"]["message"].as_str().unwrap().contains("--sni other-tenant.test"), "{v}");
        assert_eq!(accepted.load(std::sync::atomic::Ordering::SeqCst), 0, "no connection is opened");
    }
    // A name the scope lists gets as far as the handshake.
    let (code, v) = run(&["send", "--url", &url, "--sni", "localhost", "--timeout", "2"], &project, None);
    assert_ne!(code, 0, "{v}");
    assert!(!v["error"]["message"].as_str().unwrap().contains("--sni"), "{v}");
    assert!(accepted.load(std::sync::atomic::Ordering::SeqCst) > 0);
}
