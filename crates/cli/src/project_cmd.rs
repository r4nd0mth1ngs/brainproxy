//! `project`: the project file itself. Nothing here deletes a project: a project started
//! from the CLI or by an agent stays as proof of the work until a person removes it.

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use brainproxy_core::store::Store;
use brainproxy_core::Error;
use clap::Subcommand;
use serde_json::{json, Value};

use crate::output::Out;
use crate::process::{self, Liveness};

#[derive(Subcommand)]
pub enum ProjectCmd {
    /// Create the project file if missing and report its location.
    Init,
    /// Show project statistics.
    Info,
    /// Copy the project to a new file (a consistent snapshot, safe while it is in use).
    #[command(after_help = "Missing folders are created; an existing file is never overwritten. The copy \
        doesn't take over the original's running proxy, OOB listener or background work.")]
    Save {
        /// File to write, e.g. /home/you/engagements/acme.bpdb.
        #[arg(long, value_name = "FILE")]
        output: PathBuf,
    },
    /// Stop everything running for this project: its proxy, OOB listener, jobs and fuzz runs.
    #[command(after_help = "Jobs and fuzz runs are asked to stop and given 10 s to finish; it fails, naming \
        them, if any are still running. Nothing is deleted.")]
    Stop,
}

pub fn project(path: &Path, cmd: ProjectCmd, out: &Out) -> Result<(), Error> {
    match cmd {
        ProjectCmd::Init | ProjectCmd::Info => {
            let store = Store::open(path)?;
            let shown = std::fs::canonicalize(path).unwrap_or(path.to_path_buf());
            let count = store.count()?;
            let data = json!({"path": shown, "history_count": count});
            match cmd {
                ProjectCmd::Init => out.ok(data, || format!("project ready: {}", shown.display())),
                _ => out.ok(data, || format!("{}\nhistory entries: {count}", shown.display())),
            }
        }
        ProjectCmd::Save { output } => {
            let store = Store::open(path)?;
            store.save_as(&output)?;
            let saved = std::fs::canonicalize(&output).unwrap_or(output);
            out.ok(json!({"path": saved, "from": path}), || format!("saved to {}", saved.display()));
        }
        ProjectCmd::Stop => {
            let stopped = stop_all(path)?;
            out.ok(stopped.clone(), || format!("stopped: {stopped}"));
        }
    }
    Ok(())
}

/// Stops the project's proxy, OOB listener, jobs and fuzz runs. Returns what was stopped;
/// fails if some work is still running after being asked to stop.
fn stop_all(path: &Path) -> Result<Value, Error> {
    let store = Store::open(path)?;
    let proxy = crate::proxy_cmd::stop(&store)?.map(|(pid, _)| pid);
    let oob = crate::oob_cmd::stop(&store)?.map(|(pid, _)| pid);
    let work = store.unfinished_work()?;

    // Jobs and fuzz runs poll for the stop request and exit. It is repeated while waiting: one
    // still queued has no process yet and marks itself running once its process starts. They
    // are never signalled: no start time is recorded for them, so a pid reused by another
    // process can't be told apart, and one in another container can't be reached anyway.
    let lock = |what: &str, id: i64| {
        if what == "job" {
            crate::jobs_cmd::lock_name(id)
        } else {
            crate::fuzz_cmd::lock_name(id)
        }
    };
    let busy = || -> Result<Vec<(String, i64, Option<u32>)>, Error> {
        store.stop_all_work()?;
        let work = store.unfinished_work()?;
        Ok(work
            .into_iter()
            .filter(|(what, id, pid)| pid.is_none_or(|pid| !process::work_gone(&store, &lock(what, *id), pid)))
            .collect())
    };
    let deadline = Instant::now() + Duration::from_secs(10);
    let mut left = busy()?;
    while !left.is_empty() && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(100));
        left = busy()?;
    }
    // Work that never got a process has nothing to stop. Work that can't be verified may well be
    // gone, and its pid may be another process here: point to `stop --forget`, not to the pid.
    let stuck: Vec<String> = left
        .iter()
        .filter_map(|(what, id, pid)| {
            let pid = (*pid)?;
            let name = lock(what, *id);
            Some(match process::work_liveness(&store, &name, pid) {
                Liveness::Unverified => {
                    process::work_unverified_text(if what == "job" { "job" } else { "fuzz" }, *id, pid)
                }
                _ => format!("{what} {id} ({})", process::work_pid_text(&store, &name, pid)),
            })
        })
        .collect();
    if left.iter().any(|(what, id, pid)| {
        pid.is_some_and(|pid| process::work_liveness(&store, &lock(what, *id), pid) == Liveness::Unverified)
    }) {
        return Err(Error::Conflict(format!("still not known to have stopped: {}", stuck.join("; "))));
    }
    if !stuck.is_empty() {
        return Err(Error::Conflict(format!(
            "still running after being asked to stop: {}; wait for them to finish (or stop those processes)",
            stuck.join(", ")
        )));
    }
    let work: Vec<Value> = work.iter().map(|(what, id, _)| json!({"kind": what, "id": id})).collect();
    Ok(json!({"proxy": proxy, "oob": oob, "work": work}))
}
