//! Through MCP, a command reads a caller-given local file only from the project's folder (#112):
//! `send FILE`, `fuzz run FILE` and `file:` payloads, `ws send FILE`, `auth macro add --step`,
//! `auth add --login-request`, `intercept forward --file`, `findings compare
//! --baseline/--current`, and template files for `checks validate` and `scan active --checks`.
//! Commands that read a folder the caller names are refused. A file elsewhere, a link out of the folder and a `..` path are refused
//! without quoting the file, and nothing is sent; a person may name any file.

use std::io::{Read, Write};
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};

use serde_json::Value;

const SECRET: &str = "PRIVATE-FILE-CONTENT";

/// Answers every request with 200 and records its request line.
struct Server {
    port: u16,
    lines: Arc<Mutex<Vec<String>>>,
}

impl Server {
    fn start() -> Server {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let lines: Arc<Mutex<Vec<String>>> = Arc::default();
        let shared = lines.clone();
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut s) = stream else { continue };
                let lines = shared.clone();
                std::thread::spawn(move || {
                    let mut buf = Vec::new();
                    let mut chunk = [0u8; 4096];
                    while !buf.windows(4).any(|w| w == b"\r\n\r\n") {
                        match s.read(&mut chunk) {
                            Ok(0) | Err(_) => return,
                            Ok(n) => buf.extend_from_slice(&chunk[..n]),
                        }
                    }
                    let text = String::from_utf8_lossy(&buf);
                    lines.lock().unwrap().push(text.lines().next().unwrap_or_default().to_string());
                    let _ = s.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok");
                });
            }
        });
        Server { port, lines }
    }

    fn sent(&self, what: &str) -> bool {
        self.lines.lock().unwrap().iter().any(|l| l.contains(what))
    }
}

struct Output {
    code: i32,
    json: Value,
    /// stdout and stderr together.
    all: String,
}

fn run(project: &Path, args: &[&str], agent: bool) -> Output {
    run_in(project, args, agent, None)
}

/// [`run`] in `cwd`, where the server may have been started.
fn run_in(project: &Path, args: &[&str], agent: bool, cwd: Option<&Path>) -> Output {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_brainproxy"));
    if let Some(dir) = cwd {
        cmd.current_dir(dir);
    }
    if agent {
        cmd.env("BRAINPROXY_MCP_CALL", "1");
    } else {
        cmd.env_remove("BRAINPROXY_MCP_CALL");
    }
    let out = cmd
        .args(["--format", "json", "--project"])
        .arg(project)
        // The test's own home, beside the project's folder.
        .arg("--home")
        .arg(project.parent().unwrap().parent().unwrap().join("home"))
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
    Output {
        code: out.status.code().unwrap_or(-1),
        json: serde_json::from_str(&stdout).unwrap_or(Value::Null),
        all: format!("{stdout}\n{stderr}"),
    }
}

fn person(project: &Path, args: &[&str]) -> Value {
    let o = run(project, args, false);
    assert_eq!(o.code, 0, "{args:?}: {}", o.all);
    o.json["data"].clone()
}

/// A project in a folder of its own (`proj`), with a file elsewhere beside it.
struct Setup {
    dir: PathBuf,
    proj: PathBuf,
    project: PathBuf,
    server: Server,
}

impl Setup {
    fn new(name: &str) -> Setup {
        let dir = std::env::temp_dir().join(format!("bp-mcpfiles-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let proj = dir.join("proj");
        std::fs::create_dir_all(proj.join("sub")).unwrap();
        std::fs::create_dir_all(dir.join("elsewhere")).unwrap();
        let project = proj.join("p.bpdb");
        person(&project, &["engagement", "start", "--target", "127.0.0.1"]);
        Setup { dir, proj, project, server: Server::start() }
    }

    /// Writes `text` (its PORT the server's) to `rel` under the test's folder; returns the path.
    fn write(&self, rel: &str, text: &str) -> String {
        let path = self.dir.join(rel);
        std::fs::write(&path, text.replace("PORT", &self.server.port.to_string())).unwrap();
        path.to_str().unwrap().to_string()
    }

    /// The same file outside the folder as `outside`, reached three ways an agent might try:
    /// as it is, through a link inside the folder, and through `..` from inside.
    fn escapes(&self, outside: &str, name: &str) -> Vec<String> {
        let mut paths = vec![outside.to_string()];
        #[cfg(unix)]
        {
            let link = self.proj.join(format!("link-{name}"));
            std::os::unix::fs::symlink(outside, &link).unwrap();
            paths.push(link.to_str().unwrap().to_string());
        }
        paths.push(format!("{}/sub/../../elsewhere/{name}", self.proj.display()));
        paths
    }

    fn refused(&self, args: &[&str]) {
        self.refused_in(args, None)
    }

    fn refused_in(&self, args: &[&str], cwd: Option<&Path>) {
        let o = run_in(&self.project, args, true, cwd);
        assert_eq!(o.code, 2, "{args:?}: {}", o.all);
        let msg = o.json["error"]["message"].as_str().unwrap_or_default();
        assert!(msg.contains("project's folder"), "{args:?}: {}", o.all);
        assert!(!o.all.contains(SECRET), "{args:?}: {}", o.all);
        assert!(!self.server.sent(SECRET), "{args:?} sent the file");
    }
}

impl Drop for Setup {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

const REQUEST: &str = "GET /SECRET HTTP/1.1\r\nHost: 127.0.0.1:PORT\r\n\r\n";

#[test]
fn an_agent_sends_a_request_file_only_from_the_projects_folder() {
    let s = Setup::new("send");
    let inside = s.write("proj/req.txt", &REQUEST.replace("SECRET", "inside"));
    let outside = s.write("elsewhere/req.txt", &REQUEST.replace("SECRET", SECRET));
    for path in s.escapes(&outside, "req.txt") {
        s.refused(&["send", "--scheme", "http", &path]);
        s.refused(&["fuzz", "run", "--scheme", "http", &path, "-p", "list:a"]);
        s.refused(&["ws", "send", &path, "--message", "hi"]);
    }
    // A file in the folder is read, by its own path or through `..` that stays inside.
    let o = run(&s.project, &["send", "--scheme", "http", &inside], true);
    assert_eq!(o.code, 0, "{}", o.all);
    let dotted = format!("{}/sub/../req.txt", s.proj.display());
    assert_eq!(run(&s.project, &["send", "--scheme", "http", &dotted], true).code, 0);
    assert!(s.server.sent("GET /inside"));
    // A handshake file in the folder is sent too (the server is no WebSocket one, so it fails there).
    let o = run(&s.project, &["ws", "send", "--scheme", "http", &inside, "--message", "hi"], true);
    assert!(!o.all.contains("project's folder"), "{}", o.all);
    assert_eq!(s.server.lines.lock().unwrap().iter().filter(|l| l.starts_with("GET /inside")).count(), 3);
    // A person may send any file.
    person(&s.project, &["send", "--scheme", "http", &outside]);
    assert!(s.server.sent(SECRET));
}

#[test]
fn an_agent_s_payload_files_come_only_from_the_projects_folder() {
    let s = Setup::new("fuzz");
    let url = format!("http://127.0.0.1:{}/§x§", s.server.port);
    let inside = s.write("proj/words.txt", "inside-word\n");
    let outside = s.write("elsewhere/words.txt", &format!("{SECRET}\n"));
    for path in s.escapes(&outside, "words.txt") {
        s.refused(&["fuzz", "run", "--url", &url, "-p", &format!("file:{path}")]);
    }
    let o = run(&s.project, &["fuzz", "run", "--url", &url, "-p", &format!("file:{inside}")], true);
    assert_eq!(o.code, 0, "{}", o.all);
    assert!(s.server.sent("/inside-word"));
    // The run records the source as the caller gave it.
    assert_eq!(o.json["data"]["run"]["config"]["payloads"][0], format!("file:{inside}"), "{}", o.all);
    person(&s.project, &["fuzz", "run", "--url", &url, "-p", &format!("file:{outside}")]);
    assert!(s.server.sent(SECRET));
}

#[test]
fn an_agent_s_macro_steps_and_login_requests_come_only_from_the_projects_folder() {
    let s = Setup::new("auth");
    let inside = s.write("proj/step.txt", &REQUEST.replace("SECRET", "inside"));
    let outside = s.write("elsewhere/step.txt", &REQUEST.replace("SECRET", SECRET));
    let login_url = format!("http://127.0.0.1:{}/login", s.server.port);
    for path in s.escapes(&outside, "step.txt") {
        s.refused(&["auth", "macro", "add", "app", "m", "--scheme", "http", "--step", &path]);
        let origin_step = format!("http://127.0.0.1:{}={path}", s.server.port);
        s.refused(&["auth", "macro", "add", "app", "m", "--step", &origin_step]);
        s.refused(&["auth", "add", "app", "--login-url", &login_url, "--login-request", &path]);
    }
    // Nothing of the refused files was stored.
    let list = person(&s.project, &["auth", "list"]);
    assert!(!list.to_string().contains("app"), "{list}");

    let o = run(&s.project, &["auth", "macro", "add", "app", "m", "--scheme", "http", "--step", &inside], true);
    assert_eq!(o.code, 0, "{}", o.all);
    let o = run(&s.project, &["auth", "add", "app2", "--login-url", &login_url, "--login-request", &inside], true);
    assert_eq!(o.code, 0, "{}", o.all);
    person(&s.project, &["auth", "macro", "add", "app", "theirs", "--scheme", "http", "--step", &outside]);
    person(&s.project, &["auth", "add", "app3", "--login-url", &login_url, "--login-request", &outside]);
}

#[test]
fn an_agent_s_intercept_edit_comes_only_from_the_projects_folder() {
    let s = Setup::new("intercept");
    let outside = s.write("elsewhere/edit.txt", &REQUEST.replace("SECRET", SECRET));
    // Refused before the held message is even looked up.
    for path in s.escapes(&outside, "edit.txt") {
        s.refused(&["intercept", "forward", "1", "--file", &path]);
    }
    let inside = s.write("proj/edit.txt", "GET / HTTP/1.1\r\n\r\n");
    let o = run(&s.project, &["intercept", "forward", "1", "--file", &inside], true);
    assert_ne!(o.code, 0, "{}", o.all);
    assert!(!o.all.contains("project's folder"), "{}", o.all);
}

#[test]
fn an_agent_compares_only_report_files_in_the_projects_folder() {
    let s = Setup::new("compare");
    let inside = s.proj.join("report.json");
    person(&s.project, &["report", "json", "--output", inside.to_str().unwrap()]);
    let inside = inside.to_str().unwrap().to_string();
    let text = std::fs::read_to_string(&inside).unwrap();
    let outside = s.write("elsewhere/report.json", &text);
    for path in s.escapes(&outside, "report.json") {
        s.refused(&["findings", "compare", "--baseline", &path]);
        s.refused(&["findings", "compare", "--baseline", &inside, "--current", &path]);
    }
    let o = run(&s.project, &["findings", "compare", "--baseline", &inside], true);
    assert_eq!(o.code, 0, "{}", o.all);
    // A missing baseline is refused too, and the refusal says what a first run does instead.
    let missing = format!("{}/none.json", s.proj.display());
    let o = run(&s.project, &["findings", "compare", "--baseline", &missing, "--allow-missing-baseline"], true);
    assert_eq!(o.code, 2, "{}", o.all);
    assert!(o.all.contains("leave out --baseline"), "{}", o.all);
    person(&s.project, &["findings", "compare", "--baseline", &outside]);
}

const TEMPLATE: &str = r#"
id: SECRET
info: {name: Probe, severity: info}
http:
  - raw:
      - |
        GET /probe HTTP/1.1
        Host: {{Hostname}}

    matchers:
      - type: word
        words: ["never in a response"]
"#;

#[test]
fn an_agent_names_template_files_only_in_the_projects_folder_and_no_folders() {
    let s = Setup::new("checks");
    let url = format!("http://127.0.0.1:{}/", s.server.port);
    let inside = s.write("proj/probe.yaml", &TEMPLATE.replace("SECRET", "inside-probe"));
    let outside = s.write("elsewhere/probe.yaml", &TEMPLATE.replace("SECRET", SECRET));
    for path in s.escapes(&outside, "probe.yaml") {
        s.refused(&["checks", "validate", &path]);
        s.refused(&["checks", "list", "--skipped", &path]);
        s.refused(&["scan", "active", &url, "--no-rules", "--checks", &path]);
    }
    // A folder, even the project's own, is refused: a link in it could lead out.
    let folder = s.proj.to_str().unwrap();
    for args in [
        vec!["checks", "validate", folder],
        vec!["checks", "list", "--skipped", folder],
        vec!["scan", "active", &url, "--no-rules", "--checks", folder],
        vec!["checks", "update", "--from", folder],
        vec!["checks", "feed", "verify", folder],
        vec!["scan", "data", "update", "--from", folder],
    ] {
        let o = run(&s.project, &args, true);
        assert_eq!(o.code, 2, "{args:?}: {}", o.all);
        assert!(
            o.json["error"]["message"].as_str().unwrap_or_default().contains("app or a terminal"),
            "{args:?}: {}",
            o.all
        );
    }
    let o = run(&s.project, &["checks", "validate", &inside], true);
    assert_eq!((o.code, o.json["data"]["ok"].as_u64()), (0, Some(1)), "{}", o.all);
    let o = run(&s.project, &["scan", "active", &url, "--no-rules", "--checks", &inside], true);
    assert_eq!(o.code, 0, "{}", o.all);
    assert!(s.server.sent("GET /probe"));
    // A person may validate a template anywhere, and a folder.
    let v = person(&s.project, &["checks", "validate", &outside]);
    assert_eq!(v["files"][0]["id"], SECRET, "{v}");
    person(&s.project, &["checks", "validate", folder]);
}

/// Where `-` is a file name, not stdin (a macro step, a login request, a report, a template), a
/// file named `-` in the server's folder is checked like any other.
#[test]
fn an_agent_s_dash_is_a_file_where_a_command_reads_no_stdin() {
    let s = Setup::new("dash");
    let elsewhere = s.dir.join("elsewhere");
    s.write("elsewhere/-", &REQUEST.replace("SECRET", SECRET));
    let login_url = format!("http://127.0.0.1:{}/login", s.server.port);
    for args in [
        vec!["auth", "macro", "add", "app", "m", "--scheme", "http", "--step", "-"],
        vec!["auth", "add", "app", "--login-url", &login_url, "--login-request", "-"],
        vec!["findings", "compare", "--baseline", "-"],
        vec!["checks", "validate", "-"],
        vec!["checks", "list", "--skipped", "-"],
    ] {
        s.refused_in(&args, Some(&elsewhere));
    }
    // A person's `-` is the file it names, as before.
    let o = run_in(
        &s.project,
        &["auth", "macro", "add", "app", "m", "--scheme", "http", "--step", "-"],
        false,
        Some(&elsewhere),
    );
    assert_eq!(o.code, 0, "{}", o.all);
}

/// A person may name a store's folder that isn't there yet, as before: it is an empty store,
/// not a missing file.
#[test]
fn a_person_s_missing_store_folder_is_an_empty_store() {
    let s = Setup::new("store");
    let url = format!("http://127.0.0.1:{}/", s.server.port);
    let store = s.dir.join("home/checks/local");
    let store = store.to_str().unwrap();
    let v = person(&s.project, &["checks", "list", store]);
    assert_eq!(v["loaded"], 0, "{v}");
    let o = run(&s.project, &["scan", "active", &url, "--no-rules", "--checks", store], false);
    assert!(o.all.contains("no checks selected"), "{}", o.all);
}
