//! The CLI side of temporary engagements, which are a desktop-app feature: the app's shell
//! creates and deletes their folders itself. Here: `project save` and `project stop` (which
//! delete nothing), and the guard that neither the CLI nor `mcp serve` can make or wipe a
//! self-deleting project, so whatever a script or agent starts keeps its project file.

use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::Duration;

use serde_json::{json, Value};

/// A private folder and CA home per test, with a project scoped to 127.0.0.1.
struct Env {
    dir: PathBuf,
    project: PathBuf,
}

impl Env {
    fn new(name: &str) -> Self {
        let dir = std::env::temp_dir().join(format!("bp-temp-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let env = Self { project: dir.join("p.bpdb"), dir };
        env.ok(&env.project, &["engagement", "start", "--target", "127.0.0.1"]);
        env
    }

    fn cmd(&self, project: &Path) -> Command {
        let mut c = Command::new(env!("CARGO_BIN_EXE_brainproxy"));
        c.env_remove("BRAINPROXY_PROJECT")
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
}

impl Drop for Env {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

#[test]
fn save_copies_and_never_overwrites() {
    let env = Env::new("save");
    let saved = env.dir.join("kept/acme.bpdb");
    env.ok(&env.project, &["project", "save", "--output", saved.to_str().unwrap()]);
    let shown = env.ok(&saved, &["engagement", "show"]);
    assert_eq!(shown["engagement"]["include"], json!(["127.0.0.1"]));

    let (code, v) = env.run(&env.project, &["project", "save", "--output", saved.to_str().unwrap()]);
    assert_ne!(code, 0, "{v}");
    assert_eq!(v["error"]["kind"], "conflict");
}

#[test]
fn stop_stops_the_proxy_and_deletes_nothing() {
    let env = Env::new("stop");
    let started = env.ok(&env.project, &["proxy", "start", "--listen", "127.0.0.1:0"]);
    let pid = started["pid"].as_u64().unwrap() as u32;

    // A copy saved meanwhile doesn't take the running proxy for its own.
    let copy = env.dir.join("copy.bpdb");
    env.ok(&env.project, &["project", "save", "--output", copy.to_str().unwrap()]);
    assert_eq!(env.ok(&copy, &["proxy", "status"])["running"], false);
    let (code, _) = env.run(&copy, &["proxy", "stop"]);
    assert_ne!(code, 0);

    let d = env.ok(&env.project, &["project", "stop"]);
    assert_eq!(d["proxy"], pid, "{d}");
    assert_eq!(env.ok(&env.project, &["proxy", "status"])["running"], false);
    #[cfg(unix)]
    assert_ne!(unsafe { libc::kill(pid as i32, 0) }, 0, "proxy {pid} still running");
    assert!(env.project.exists());
    // Nothing running: stopping again is fine.
    env.ok(&env.project, &["project", "stop"]);
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
fn stop_stops_background_fuzzing() {
    let env = Env::new("fuzz");
    let port = slow_server(Duration::from_millis(200));
    let url = format!("http://127.0.0.1:{port}/§x§");
    let started =
        env.ok(&env.project, &["fuzz", "run", "--url", &url, "-p", "range:1-5000", "-c", "2", "--background"]);
    let run = started["run"]["id"].as_i64().unwrap();
    let d = env.ok(&env.project, &["project", "stop"]);
    let work = d["work"].as_array().unwrap();
    assert!(work.iter().any(|w| w["kind"] == "fuzz run" && w["id"] == run), "{d}");
    let state = env.ok(&env.project, &["fuzz", "status", &run.to_string()]);
    assert_eq!(state["run"]["state"], "stopped", "{state}");
    assert!(env.project.exists());
}

#[test]
fn cli_cannot_make_or_wipe_temporary_projects() {
    let env = Env::new("cli");
    for cmd in [&["project", "temp"][..], &["project", "discard"], &["project", "sweep"]] {
        let (code, v) = env.run(&env.project, cmd);
        assert_eq!(code, 2, "{cmd:?} -> {v}");
        assert_eq!(v["error"]["kind"], "usage", "{cmd:?} -> {v}");
    }
    assert!(env.project.exists());
}

#[test]
fn mcp_serve_cannot_make_or_wipe_temporary_projects() {
    let env = Env::new("mcp");
    let out = env.cmd(&env.project).args(["mcp", "serve", "--temp"]).stdin(Stdio::null()).output().unwrap();
    assert_eq!(out.status.code(), Some(2), "{}", String::from_utf8_lossy(&out.stdout));

    let mut child =
        env.cmd(&env.project).args(["mcp", "serve"]).stdin(Stdio::piped()).stdout(Stdio::piped()).spawn().unwrap();
    let mut stdin = child.stdin.take().unwrap();
    let mut stdout = BufReader::new(child.stdout.take().unwrap());
    writeln!(stdin, "{}", json!({"jsonrpc": "2.0", "id": 1, "method": "tools/list"})).unwrap();
    stdin.flush().unwrap();
    let mut line = String::new();
    stdout.read_line(&mut line).unwrap();
    drop(stdin);
    let _ = child.wait();
    let reply: Value = serde_json::from_str(&line).unwrap();
    let names: Vec<&str> =
        reply["result"]["tools"].as_array().unwrap().iter().map(|t| t["name"].as_str().unwrap()).collect();
    assert!(names.contains(&"project_stop"), "{names:?}");
    for name in &names {
        assert!(!["temp", "discard", "sweep", "delete", "wipe"].iter().any(|w| name.contains(w)), "{name}");
    }
    // Copying the project elsewhere is for the person running the server.
    assert!(!names.contains(&"project_save"), "{names:?}");
    assert!(env.project.exists());
}

/// What another container on the same volume would see: the lock file naming another PID
/// namespace, and the saved pid not there.
#[cfg(target_os = "linux")]
fn pretend_other_namespace(env: &Env, lock: &str, set_pid: impl FnOnce(&brainproxy_core::store::Store, u32)) {
    let path = env.dir.join(format!("p.bpdb-{lock}.lock"));
    assert!(std::fs::read_to_string(&path).unwrap().starts_with("pid:["), "{path:?}");
    std::fs::write(&path, "pid:[1]").unwrap();
    set_pid(&brainproxy_core::store::Store::open(&env.project).unwrap(), i32::MAX as u32);
}

/// Accepts connections and never answers, for a job that runs until it is killed.
#[cfg(target_os = "linux")]
fn silent_server() -> u16 {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    std::thread::spawn(move || {
        let mut held = Vec::new();
        for stream in listener.incoming() {
            held.push(stream);
        }
    });
    port
}

#[cfg(target_os = "linux")]
fn kill(pid: u64) {
    assert!(Command::new("kill").args(["-9", &pid.to_string()]).status().unwrap().success());
}

#[cfg(target_os = "linux")]
#[test]
fn fuzz_run_in_another_namespace_is_not_taken_for_dead() {
    let env = Env::new("fuzz-ns");
    let port = slow_server(Duration::from_millis(200));
    let url = format!("http://127.0.0.1:{port}/§x§");
    let start = || {
        let args = ["fuzz", "run", "--url", &url, "-p", "range:1-5000", "-c", "2", "--background"];
        let run = env.ok(&env.project, &args)["run"].clone();
        let id = run["id"].as_i64().unwrap();
        pretend_other_namespace(&env, &format!("fuzz-{id}"), |store, pid| {
            store.fuzz_set_state(id, "running", Some(pid), None, false).unwrap();
        });
        (id, run["pid"].as_u64().unwrap())
    };
    let state = |id: i64| env.ok(&env.project, &["fuzz", "status", &id.to_string()])["run"]["state"].clone();

    // Being looked at, however many times, changes nothing, and it can still be stopped.
    let (run, _) = start();
    for _ in 0..2 {
        assert_eq!(state(run), "running");
    }
    let status = env.ok(&env.project, &["fuzz", "status", &run.to_string()]);
    assert_eq!(status["run"]["other_pid_namespace"], true, "{status}");
    let d = env.ok(&env.project, &["project", "stop"]);
    assert!(d["work"].as_array().unwrap().iter().any(|w| w["id"] == run), "{d}");
    // `project stop` waited for it, so it is done by now, and has cleaned up after itself.
    assert_eq!(state(run), "stopped");
    assert!(!env.dir.join(format!("p.bpdb-fuzz-{run}.lock")).exists());

    // Once it is killed outright, it is told from a running one right away.
    let (run, pid) = start();
    assert_eq!(state(run), "running");
    kill(pid);
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    while state(run) == "running" {
        assert!(std::time::Instant::now() < deadline, "the dead run still looks like it runs");
        std::thread::sleep(Duration::from_millis(50));
    }
    assert_eq!(state(run), "failed");
    assert!(!env.dir.join(format!("p.bpdb-fuzz-{run}.lock")).exists());
}

#[cfg(target_os = "linux")]
#[test]
fn job_in_another_namespace_is_not_taken_for_dead() {
    let env = Env::new("job-ns");
    let site = format!("http://127.0.0.1:{}/", silent_server());
    let args = ["crawl", &site, "--no-robots", "--no-sitemap", "--timeout", "600", "--background"];
    let id = env.ok(&env.project, &args)["job"].as_i64().unwrap();
    let id_text = id.to_string();
    let status = || env.ok(&env.project, &["job", "status", &id_text]);
    let pid = status()["pid"].as_u64().unwrap();
    assert_eq!(status()["other_pid_namespace"], false);
    assert_stdin_is_not_the_lock(pid, &env.dir.join(format!("p.bpdb-job-{id}.lock")));
    pretend_other_namespace(&env, &format!("job-{id}"), |store, pid| {
        store.job_set_state(id, "running", Some(pid), None, false).unwrap();
    });

    for _ in 0..2 {
        assert_eq!(status()["state"], "running");
    }
    assert_eq!(status()["other_pid_namespace"], true);
    let waited = env.ok(&env.project, &["job", "wait", &id_text, "--timeout", "0.5"]);
    assert_eq!((&waited["state"], &waited["timed_out"]), (&"running".into(), &true.into()), "{waited}");

    kill(pid);
    let waited = env.ok(&env.project, &["job", "wait", &id_text, "--timeout", "5"]);
    assert_eq!(waited["state"], "failed", "{waited}");
    assert_eq!(waited["error"], "job process exited unexpectedly");
    assert!(!env.dir.join(format!("p.bpdb-job-{id}.lock")).exists());
}

/// Whatever a job starts doesn't inherit its lock, which would keep it held after the job died.
#[cfg(target_os = "linux")]
fn assert_stdin_is_not_the_lock(pid: u64, lock: &Path) {
    let fds = PathBuf::from(format!("/proc/{pid}/fd"));
    assert_eq!(std::fs::read_link(fds.join("0")).unwrap(), PathBuf::from("/dev/null"));
    let lock = std::fs::canonicalize(lock).unwrap();
    let held = std::fs::read_dir(&fds)
        .unwrap()
        .flatten()
        .find(|fd| std::fs::read_link(fd.path()).is_ok_and(|p| p == lock))
        .expect("the job holds its lock");
    let info = std::fs::read_to_string(format!("/proc/{pid}/fdinfo/{}", held.file_name().display())).unwrap();
    let flags = info.lines().find_map(|l| l.strip_prefix("flags:")).unwrap().trim();
    assert_ne!(u32::from_str_radix(flags, 8).unwrap() & 0o2000000, 0, "not close-on-exec: {info}");
}

/// Its pid can be reused, or its namespace's number: a free lock still says it is gone.
#[cfg(target_os = "linux")]
#[test]
fn a_free_lock_beats_a_live_pid() {
    let env = Env::new("job-reuse");
    let site = format!("http://127.0.0.1:{}/", silent_server());
    let args = ["crawl", &site, "--no-robots", "--no-sitemap", "--timeout", "600", "--background"];
    let id = env.ok(&env.project, &args)["job"].as_i64().unwrap();
    let id_text = id.to_string();
    let pid = env.ok(&env.project, &["job", "status", &id_text])["pid"].as_u64().unwrap();
    let store = brainproxy_core::store::Store::open(&env.project).unwrap();
    store.job_set_state(id, "running", Some(std::process::id()), None, false).unwrap();
    kill(pid);
    let waited = env.ok(&env.project, &["job", "wait", &id_text, "--timeout", "5"]);
    assert_eq!(waited["state"], "failed", "{waited}");
}

#[cfg(target_os = "linux")]
#[test]
fn background_work_cleans_up_its_lock_when_it_finishes() {
    let env = Env::new("job-done");
    let site = format!("http://127.0.0.1:{}/", slow_server(Duration::ZERO));
    let args = ["crawl", &site, "--no-robots", "--no-sitemap", "--background"];
    let id = env.ok(&env.project, &args)["job"].as_i64().unwrap();
    let done = env.ok(&env.project, &["job", "wait", &id.to_string(), "--timeout", "30"]);
    assert_eq!(done["state"], "completed", "{done}");
    assert!(!env.dir.join(format!("p.bpdb-job-{id}.lock")).exists());

    let url = format!("{site}§x§");
    let args = ["fuzz", "run", "--url", &url, "-p", "range:1-3", "--background"];
    let run = env.ok(&env.project, &args)["run"]["id"].as_i64().unwrap();
    let deadline = std::time::Instant::now() + Duration::from_secs(30);
    let finished = loop {
        let status = env.ok(&env.project, &["fuzz", "status", &run.to_string()]);
        if !matches!(status["run"]["state"].as_str(), Some("queued" | "running")) {
            break status;
        }
        assert!(std::time::Instant::now() < deadline, "{status}");
        std::thread::sleep(Duration::from_millis(50));
    };
    assert_eq!(finished["run"]["state"], "completed", "{finished}");
    assert!(!env.dir.join(format!("p.bpdb-fuzz-{run}.lock")).exists());
}
