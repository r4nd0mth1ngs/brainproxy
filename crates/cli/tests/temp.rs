//! Temporary projects: create, use, save, discard, sweep, and `mcp serve --temp`.

use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use serde_json::{json, Value};

/// A private BRAINPROXY_TEMP_DIR and CA home per test.
struct Env {
    dir: PathBuf,
}

impl Env {
    fn new(name: &str) -> Self {
        let dir = std::env::temp_dir().join(format!("bp-temp-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("base")).unwrap();
        Self { dir }
    }

    fn cmd(&self, project: &Path) -> Command {
        let mut c = Command::new(env!("CARGO_BIN_EXE_brainproxy"));
        c.env("BRAINPROXY_TEMP_DIR", self.dir.join("base"))
            .env_remove("BRAINPROXY_PROJECT")
            .args(["--format", "json", "--home"])
            .arg(self.dir.join("home"))
            .arg("--project")
            .arg(project);
        c
    }

    fn run(&self, project: &Path, args: &[&str]) -> (i32, Value) {
        let out = self.cmd(project).args(args).output().unwrap();
        let v = serde_json::from_slice(&out.stdout)
            .unwrap_or_else(|e| panic!("bad JSON ({e}): {}", String::from_utf8_lossy(&out.stdout)));
        (out.status.code().unwrap(), v)
    }

    fn ok(&self, project: &Path, args: &[&str]) -> Value {
        let (code, v) = self.run(project, args);
        assert_eq!(code, 0, "{args:?} -> {v}");
        v["data"].clone()
    }

    /// A new temp project with an engagement scope.
    fn temp(&self, extra: &[&str]) -> PathBuf {
        let mut args = vec!["project", "temp"];
        args.extend(extra);
        let d = self.ok(Path::new("unused.bpdb"), &args);
        assert_eq!(d["temp"], true);
        let p = PathBuf::from(d["path"].as_str().unwrap());
        assert!(p.starts_with(self.dir.join("base")), "{p:?}");
        self.ok(&p, &["engagement", "start", "--target", "127.0.0.1"]);
        p
    }
}

impl Drop for Env {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

#[test]
fn create_use_save_and_discard() {
    let env = Env::new("cycle");
    let p = env.temp(&[]);
    let info = env.ok(&p, &["project", "info"]);
    assert_eq!(info["temp"], true, "{info}");
    assert!(info["ram_backed"].is_boolean());

    // Save: a normal project with the same data, and never over an existing file.
    let saved = env.dir.join("kept/acme.bpdb");
    env.ok(&p, &["project", "save", "--output", saved.to_str().unwrap()]);
    let shown = env.ok(&saved, &["engagement", "show"]);
    assert_eq!(shown["engagement"]["include"], json!(["127.0.0.1"]));
    assert_eq!(env.ok(&saved, &["project", "info"])["temp"], false);
    let (code, v) = env.run(&p, &["project", "save", "--output", saved.to_str().unwrap()]);
    assert_ne!(code, 0, "{v}");
    assert_eq!(v["error"]["kind"], "conflict");

    // Nor into the temp project's own folder, which discard wipes.
    let inside = p.parent().unwrap().join("keep.bpdb");
    let (code, v) = env.run(&p, &["project", "save", "--output", inside.to_str().unwrap()]);
    assert_eq!(v["error"]["kind"], "invalid_input", "{v}");
    assert_ne!(code, 0);

    // A normal project is never discarded.
    let (code, v) = env.run(&saved, &["project", "discard"]);
    assert_ne!(code, 0);
    assert_eq!(v["error"]["kind"], "invalid_input", "{v}");
    assert!(saved.exists());

    env.ok(&p, &["project", "discard"]);
    assert!(!p.parent().unwrap().exists());
}

#[test]
fn discard_stops_the_proxy() {
    let env = Env::new("proxy");
    let p = env.temp(&[]);
    let started = env.ok(&p, &["proxy", "start", "--listen", "127.0.0.1:0"]);
    let pid = started["pid"].as_u64().unwrap() as u32;
    // A copy saved meanwhile doesn't take the running proxy for its own.
    let copy = env.dir.join("copy.bpdb");
    env.ok(&p, &["project", "save", "--output", copy.to_str().unwrap()]);
    assert_eq!(env.ok(&copy, &["proxy", "status"])["running"], false);
    let (code, _) = env.run(&copy, &["proxy", "stop"]);
    assert_ne!(code, 0);
    let d = env.ok(&p, &["project", "discard"]);
    assert_eq!(d["stopped"]["proxy"], pid, "{d}");
    assert!(!p.parent().unwrap().exists());
    #[cfg(unix)]
    assert_ne!(unsafe { libc::kill(pid as i32, 0) }, 0, "proxy {pid} still running");
}

#[test]
fn sweep_wipes_projects_whose_owner_exited() {
    let env = Env::new("sweep");
    let mut owner = sleeper();
    let owned = env.temp(&["--owner", &owner.id().to_string()]);
    let unowned = env.temp(&[]);

    // Owner alive: kept.
    assert_eq!(env.ok(Path::new("x.bpdb"), &["project", "sweep"])["removed"], json!([]));
    assert!(owned.exists());

    owner.kill().unwrap();
    owner.wait().unwrap();
    let removed = env.ok(Path::new("x.bpdb"), &["project", "sweep"])["removed"].clone();
    assert_eq!(removed.as_array().unwrap().len(), 1, "{removed}");
    assert!(!owned.parent().unwrap().exists());
    // Without an owner it stays until discarded.
    assert!(unowned.exists());

    // An owner that isn't running is refused rather than swept straight away.
    let (code, v) = env.run(Path::new("x.bpdb"), &["project", "temp", "--owner", "999999999"]);
    assert_ne!(code, 0, "{v}");
}

/// Answers every request after `delay`, so work against it stays busy.
fn slow_server(delay: Duration) -> u16 {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for stream in listener.incoming().flatten() {
            std::thread::spawn(move || {
                let mut s = stream;
                let mut buf = [0u8; 4096];
                while let Ok(n) = std::io::Read::read(&mut s, &mut buf) {
                    if n == 0 {
                        break;
                    }
                    std::thread::sleep(delay);
                    let _ = s.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok");
                }
            });
        }
    });
    port
}

#[test]
fn discard_stops_background_fuzzing() {
    let env = Env::new("fuzz");
    let p = env.temp(&[]);
    let port = slow_server(Duration::from_millis(200));
    let url = format!("http://127.0.0.1:{port}/§x§");
    let started = env.ok(&p, &["fuzz", "run", "--url", &url, "-p", "range:1-5000", "-c", "2", "--background"]);
    let run = started["run"]["id"].as_i64().or_else(|| started["id"].as_i64()).unwrap_or(1);
    let d = env.ok(&p, &["project", "discard"]);
    let work = d["stopped"]["work"].as_array().unwrap();
    assert!(work.iter().any(|w| w["kind"] == "fuzz run" && w["id"] == run), "{d}");
    assert!(!p.parent().unwrap().exists());
}

#[cfg(unix)]
fn sleeper() -> std::process::Child {
    Command::new("sleep").arg("60").spawn().unwrap()
}

#[cfg(windows)]
fn sleeper() -> std::process::Child {
    Command::new("powershell").args(["-NoProfile", "-Command", "Start-Sleep 60"]).spawn().unwrap()
}

#[test]
fn mcp_serve_temp_wipes_its_project_on_exit() {
    let env = Env::new("mcp");
    let mut child = Command::new(env!("CARGO_BIN_EXE_brainproxy"))
        .env("BRAINPROXY_TEMP_DIR", env.dir.join("base"))
        .env_remove("BRAINPROXY_PROJECT")
        .arg("--home")
        .arg(env.dir.join("home"))
        .args(["mcp", "serve", "--temp"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    let mut stdin = child.stdin.take().unwrap();
    let mut stdout = BufReader::new(child.stdout.take().unwrap());
    let path = {
        let mut ask = |id: i64, method: &str, params: Value| -> Value {
            writeln!(stdin, "{}", json!({"jsonrpc": "2.0", "id": id, "method": method, "params": params})).unwrap();
            stdin.flush().unwrap();
            let mut line = String::new();
            stdout.read_line(&mut line).unwrap();
            serde_json::from_str(&line).unwrap()
        };
        let init = ask(1, "initialize", json!({"protocolVersion": "2025-06-18"}));
        assert!(init["result"]["instructions"].as_str().unwrap().contains("temporary"), "{init}");
        let tools = ask(2, "tools/list", json!({}));
        let names: Vec<&str> =
            tools["result"]["tools"].as_array().unwrap().iter().map(|t| t["name"].as_str().unwrap()).collect();
        assert!(names.contains(&"project_save") && !names.contains(&"project_discard"), "{names:?}");
        let r = ask(3, "tools/call", json!({"name": "project_info", "arguments": {}}));
        let info: Value = serde_json::from_str(r["result"]["content"][0]["text"].as_str().unwrap()).unwrap();
        assert_eq!(info["data"]["temp"], true, "{info}");
        PathBuf::from(info["data"]["path"].as_str().unwrap())
    };
    assert!(path.exists());

    // The client hangs up: the server exits and wipes its project.
    drop(stdin);
    let deadline = Instant::now() + Duration::from_secs(20);
    while child.try_wait().unwrap().is_none() && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(50));
    }
    assert!(child.try_wait().unwrap().is_some(), "server didn't exit");
    assert!(!path.parent().unwrap().exists(), "{path:?} left behind");
}

#[test]
fn mcp_serve_temp_refuses_an_explicit_project() {
    let env = Env::new("mcp-both");
    let out = env.cmd(&env.dir.join("p.bpdb")).args(["mcp", "serve", "--temp"]).stdin(Stdio::null()).output().unwrap();
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stdout).contains("--temp"), "{}", String::from_utf8_lossy(&out.stdout));
}
