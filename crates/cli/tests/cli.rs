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
            stdin_pipe.write_all(data).unwrap();
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
                } else {
                    "<html><body>item</body></html>"
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
fn scan_active_skips_state_changing_methods_by_default() {
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
        let mut child = Command::new("sh").args(["-c", "trap '' TERM; sleep 30"]).spawn().unwrap();
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
