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
            reap(&store, id)?;
            let j = store.job_get(id)?;
            out.ok(j.clone(), || text(&j));
        }
        JobCmd::Wait { id, timeout } => {
            let deadline = Instant::now() + Duration::from_secs_f64(timeout.max(0.0));
            loop {
                reap(&store, id)?;
                let state = store.job_state(id)?;
                if is_finished(&state) || Instant::now() >= deadline {
                    break;
                }
                std::thread::sleep(Duration::from_millis(250));
            }
            let mut j = store.job_get(id)?;
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

/// Marks a job whose process died as failed.
fn reap(store: &Store, id: i64) -> Result<(), Error> {
    let j = store.job_get(id)?;
    if matches!(j["state"].as_str(), Some("running" | "stopping")) {
        if let Some(pid) = j["pid"].as_u64() {
            if !crate::proxy_cmd::alive(pid as u32) {
                store.job_set_state(id, "failed", None, Some("job process exited unexpectedly"), true)?;
            }
        }
    }
    Ok(())
}

/// Re-runs the current command detached (without --background, with --job-id)
/// and returns once the child has picked the job up.
pub fn spawn_background(kind: &str, project: &Path, home: &Path, out: &Out) -> Result<(), Error> {
    let store = Store::open(project)?;
    let argv = child_args();
    let id = store.job_create(kind, "queued", &argv)?;
    let project = std::fs::canonicalize(project)?;
    let log = project.with_extension(format!("job-{id}.log"));
    let log_file = std::fs::OpenOptions::new().create(true).append(true).open(&log)?;
    let mut cmd = std::process::Command::new(std::env::current_exe()?);
    cmd.arg("--project").arg(&project).arg("--home").arg(home).args(["--format", "json"]).args(&argv);
    cmd.arg("--job-id").arg(id.to_string());
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        cmd.process_group(0);
    }
    let mut child =
        cmd.stdin(Stdio::null()).stdout(Stdio::from(log_file.try_clone()?)).stderr(Stdio::from(log_file)).spawn()?;
    let deadline = Instant::now() + Duration::from_secs(10);
    while store.job_state(id)? == "queued" && Instant::now() < deadline {
        if let Some(status) = child.try_wait()? {
            let msg = std::fs::read_to_string(&log).unwrap_or_default();
            store.job_set_state(id, "failed", None, Some(msg.trim()), true)?;
            return Err(Error::InvalidInput(format!("{kind} exited ({status}): {}", msg.trim())));
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
    if let Some(id) = job_id {
        store.job_set_state(id, "running", Some(std::process::id()), None, false)?;
    }
    let ctl = JobControl::default();
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
    }
    result
}
