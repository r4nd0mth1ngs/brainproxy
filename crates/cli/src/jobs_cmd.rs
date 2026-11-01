//! Background jobs: running a long command detached, and polling, waiting for,
//! or stopping it.

use std::path::Path;
use std::process::Stdio;
use std::time::{Duration, Instant};

use brainproxy_core::jobs::{is_finished, JobControl};
use brainproxy_core::store::Store;
use brainproxy_core::Error;
use clap::Subcommand;
use serde_json::{json, Value};

use crate::output::Out;
use crate::process;

#[derive(Subcommand)]
pub enum JobCmd {
    /// Recent jobs.
    List {
        #[arg(long, default_value_t = 20)]
        limit: usize,
    },
    /// State, progress, and (when finished) result of a job.
    Status { id: i64 },
    /// Block until a job finishes (or the timeout passes), then print its status.
    Wait {
        id: i64,
        /// Seconds to wait at most.
        #[arg(long, default_value_t = 300.0)]
        timeout: f64,
    },
    /// Ask a running job to stop.
    Stop { id: i64 },
}

pub fn job(project: &Path, cmd: JobCmd, out: &Out) -> Result<(), Error> {
    let store = Store::open(project)?;
    match cmd {
        JobCmd::List { limit } => {
            let jobs = store.job_list(limit)?;
            out.ok(json!({"jobs": jobs}), || {
                jobs.iter()
                    .map(|j| {
                        format!(
                            "{:>4}  {:<12} {:<10} {}",
                            j["id"],
                            j["kind"].as_str().unwrap_or(""),
                            j["state"].as_str().unwrap_or(""),
                            j["time"].as_str().unwrap_or("")
                        )
                    })
                    .collect::<Vec<_>>()
                    .join("\n")
            });
        }
        JobCmd::Status { id } => {
            reap(project, &store, id)?;
            let j = shown(&store, id)?;
            out.ok(j.clone(), || text(&j));
        }
        JobCmd::Wait { id, timeout } => {
            let deadline = Instant::now() + Duration::from_secs_f64(timeout.max(0.0));
            loop {
                reap(project, &store, id)?;
                let state = store.job_state(id)?;
                if is_finished(&state) || Instant::now() >= deadline {
                    break;
                }
                std::thread::sleep(Duration::from_millis(250));
            }
            let mut j = shown(&store, id)?;
            j["timed_out"] = json!(!is_finished(j["state"].as_str().unwrap_or("")));
            out.ok(j.clone(), || text(&j));
        }
        JobCmd::Stop { id } => {
            let state = store.job_state(id)?;
            if is_finished(&state) {
                return Err(Error::Conflict(format!("job {id} is {state}")));
            }
            store.job_set_state(id, "stopping", None, None, false)?;
            out.ok(json!({"id": id, "state": "stopping"}), || format!("stopping job {id}"));
        }
    }
    Ok(())
}

/// A job, and whether its pid means anything here.
fn shown(store: &Store, id: i64) -> Result<Value, Error> {
    let mut j = store.job_get(id)?;
    j["other_pid_namespace"] = json!(process::work_elsewhere(store, &lock_name(id)));
    Ok(j)
}

fn text(j: &Value) -> String {
    format!(
        "job {} [{}] {}\nprogress: {}\nresult: {}",
        j["id"],
        j["state"].as_str().unwrap_or(""),
        j["kind"].as_str().unwrap_or(""),
        j["progress"],
        j.get("result").cloned().unwrap_or(Value::Null)
    )
}

/// A job's lock file (see `process::work_lock`).
pub(crate) fn lock_name(id: i64) -> String {
    format!("job-{id}")
}

/// Marks a job whose process died as failed. One that died while still queued (before
/// it marked itself running) failed setting up: its error is the last one in its log.
pub(crate) fn reap(project: &Path, store: &Store, id: i64) -> Result<(), Error> {
    let j = store.job_get(id)?;
    if !matches!(j["state"].as_str().unwrap_or(""), "queued" | "running" | "stopping") {
        return Ok(());
    }
    let Some(pid) = j["pid"].as_u64() else { return Ok(()) };
    let name = lock_name(id);
    if !process::work_gone(store, &name, pid as u32) {
        return Ok(());
    }
    // It may have finished, and exited, since the state above was read.
    let state = store.job_state(id)?;
    if is_finished(&state) {
        return Ok(());
    }
    let logged = || {
        let project = std::fs::canonicalize(project).unwrap_or_else(|_| project.to_path_buf());
        let log = std::fs::read_to_string(project.with_extension(format!("job-{id}.log"))).ok()?;
        logged_error(&log).map(|(_, message)| message)
    };
    let error = match state.as_str() {
        "queued" => logged().unwrap_or_else(|| "job process exited before it started".into()),
        _ => "job process exited unexpectedly".into(),
    };
    store.job_set_state(id, "failed", None, Some(&error), true)?;
    process::forget_work_lock(store, &name);
    Ok(())
}

/// The kind and message of the last error envelope in a child's log.
fn logged_error(log: &str) -> Option<(String, String)> {
    log.lines().rev().find_map(|l| {
        let v: Value = serde_json::from_str(l).ok()?;
        let e = v.get("error")?;
        Some((e["kind"].as_str()?.to_string(), e["message"].as_str()?.to_string()))
    })
}

/// Re-runs the current command detached (without --background, with --job-id)
/// and returns once the child has picked the job up.
/// The error for a background child that exited before it started: the child's own error
/// envelope (last JSON line of its log) with its kind and message, or the raw log text.
pub fn child_failure(what: &str, status: std::process::ExitStatus, log: &str) -> Error {
    let Some((kind, message)) = logged_error(log) else {
        return Error::InvalidInput(format!("{what} exited ({status}): {}", log.trim()));
    };
    // The message is the child's Display text; drop its "<kind>: " prefix before re-wrapping.
    let strip = |prefix: &str| message.strip_prefix(prefix).unwrap_or(&message).to_string();
    match kind.as_str() {
        "not_found" => Error::NotFound(strip("not found: ")),
        "conflict" => Error::Conflict(strip("conflict: ")),
        "out_of_scope" => Error::OutOfScope(strip("out of scope: ")),
        "connect" => Error::Connect(strip("connection failed: ")),
        "tls" => Error::Tls(strip("TLS error: ")),
        "protocol" => Error::Protocol(strip("protocol error: ")),
        _ => Error::InvalidInput(strip("invalid input: ")),
    }
}

pub fn spawn_background(kind: &str, project: &Path, home: &Path, out: &Out) -> Result<(), Error> {
    let store = Store::open(project)?;
    let argv = child_args();
    let id = store.job_create(kind, "queued", &argv)?;
    let child_argv = with_options(argv, ["--job-id".into(), id.to_string()]);
    let project = std::fs::canonicalize(project)?;
    let log = project.with_extension(format!("job-{id}.log"));
    let log_file = std::fs::OpenOptions::new().create(true).append(true).open(&log)?;
    let mut cmd = std::process::Command::new(std::env::current_exe()?);
    cmd.arg("--project").arg(&project).arg("--home").arg(home).args(["--format", "json"]).args(&child_argv);
    process::detach(&mut cmd);
    let stdin = process::work_lock_stdin(&store, &lock_name(id));
    let mut child =
        cmd.stdin(stdin).stdout(Stdio::from(log_file.try_clone()?)).stderr(Stdio::from(log_file)).spawn()?;
    // Our copy of the lock goes with it: the child's is the one that counts.
    drop(cmd);
    // Set up work (loading checks, logging in) can outlast the wait below; with the pid
    // recorded, a child that then fails before starting the job is reaped as failed.
    store.job_set_pid(id, child.id())?;
    let deadline = Instant::now() + Duration::from_secs(10);
    while store.job_state(id)? == "queued" && Instant::now() < deadline {
        if let Some(status) = child.try_wait()? {
            let msg = std::fs::read_to_string(&log).unwrap_or_default();
            store.job_set_state(id, "failed", None, Some(msg.trim()), true)?;
            process::forget_work_lock(&store, &lock_name(id));
            return Err(child_failure(kind, status, &msg));
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    let data = json!({
        "job": id,
        "kind": kind,
        "state": store.job_state(id)?,
        "log": log,
        "next": format!("brainproxy job wait {id} --timeout 300   (or: job status {id}, job stop {id})"),
    });
    out.ok(data, || format!("{kind} running in the background as job {id}"));
    Ok(())
}

/// `argv` with `options` added before a `--` separator, where they are still options.
pub fn with_options(mut argv: Vec<String>, options: impl IntoIterator<Item = String>) -> Vec<String> {
    let at = argv.iter().position(|a| a == "--").unwrap_or(argv.len());
    argv.splice(at..at, options);
    argv
}

/// This process's arguments minus `--background` and the global options the
/// child gets explicitly (`--project`, `--home`, `--format`).
pub fn child_args() -> Vec<String> {
    let mut out = Vec::new();
    let mut args = std::env::args().skip(1);
    while let Some(a) = args.next() {
        if a == "--background" {
            continue;
        }
        if ["--project", "--home", "--format"].contains(&a.as_str()) {
            args.next();
            continue;
        }
        if ["--project=", "--home=", "--format="].iter().any(|p| a.starts_with(p)) {
            continue;
        }
        out.push(a);
    }
    out
}

/// Runs a job body in this process: marks the job running, watches for stop
/// requests and persists progress, then stores the result and final state.
/// Without a job id (a foreground run) it just runs the body.
pub fn run_job(
    project: &Path,
    job_id: Option<i64>,
    body: impl FnOnce(JobControl) -> Result<Value, Error>,
) -> Result<Value, Error> {
    let store = Store::open(project)?;
    let ctl = JobControl::default();
    // A job run by this process rather than a `--background` child (an authz run).
    let _lock = job_id.and_then(|id| process::work_lock(&store, &lock_name(id)));
    if let Some(id) = job_id {
        // A stop requested while the job was queued stands: the job starts stopped.
        if !store.job_start(id, std::process::id())? && store.job_state(id)? == "stopping" {
            ctl.request_stop();
        }
    }
    let watcher = ctl.watch(project, job_id);
    let result = body(ctl.clone());
    drop(watcher);
    if let Some(id) = job_id {
        match &result {
            Ok(v) => {
                store.job_result(id, v)?;
                store.job_set_state(id, if ctl.stopped() { "stopped" } else { "completed" }, None, None, true)?;
            }
            Err(e) => store.job_set_state(id, "failed", None, Some(&e.to_string()), true)?,
        }
        process::forget_work_lock(&store, &lock_name(id));
    }
    result
}
