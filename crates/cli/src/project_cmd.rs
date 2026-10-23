//! `project`: the project file itself, and temporary projects (one engagement, kept in RAM
//! where the OS allows it and wiped when closed; see `brainproxy_core::temp`).

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use brainproxy_core::store::Store;
use brainproxy_core::temp::{self, Owner};
use brainproxy_core::Error;
use clap::Subcommand;
use serde_json::{json, Value};

use crate::output::Out;
use crate::process;

#[derive(Subcommand)]
pub enum ProjectCmd {
    /// Create the project file if missing and report its location.
    Init,
    /// Show project statistics.
    Info,
    /// Create a temporary project and print its path; pass it as --project to later commands.
    #[command(after_help = "The project lives in a RAM-backed folder where there is one ($XDG_RUNTIME_DIR or \
        /dev/shm on Linux, whichever has more room; `ram_backed` says which), otherwise in the OS temp folder on disk; \
        $BRAINPROXY_TEMP_DIR picks another place. It still needs `engagement start`. Wipe it with `project \
        discard`, or keep it with `project save`. With --owner it is also wiped once that process has exited \
        (by `project sweep`, which `project temp` and `mcp serve --temp` run first).")]
    Temp {
        /// Process that owns the project: once it exits, the project is wiped by the next sweep.
        #[arg(long, value_name = "PID")]
        owner: Option<u32>,
    },
    /// Stop the temporary project's proxy, OOB listener, jobs and fuzz runs, then wipe it.
    #[command(after_help = "Refused for a project that isn't temporary. Close browsers opened for the project \
        first: their profiles are wiped with it.")]
    Discard,
    /// Copy the project to a new file (a consistent snapshot, safe while it is in use).
    #[command(after_help = "Use it to keep a temporary project: save it, then open the saved file. Missing \
        folders are created; an existing file is never overwritten, and a file inside a temporary project's \
        folder is refused (it would be wiped with it).")]
    Save {
        /// File to write, e.g. /home/you/engagements/acme.bpdb.
        #[arg(long, value_name = "FILE")]
        output: PathBuf,
    },
    /// Wipe temporary projects whose owner process has exited; also says where temp projects go.
    Sweep,
}

pub fn project(path: &Path, cmd: ProjectCmd, out: &Out) -> Result<(), Error> {
    match cmd {
        ProjectCmd::Init | ProjectCmd::Info => {
            let store = Store::open(path)?;
            let shown = std::fs::canonicalize(path).unwrap_or(path.to_path_buf());
            let count = store.count()?;
            let mut data = json!({"path": shown, "history_count": count, "temp": false});
            if temp::marker(path).is_some() {
                data["temp"] = json!(true);
                data["ram_backed"] = json!(temp::ram_backed(path));
            }
            match cmd {
                ProjectCmd::Init => out.ok(data, || format!("project ready: {}", shown.display())),
                _ => out.ok(data, || format!("{}\nhistory entries: {count}", shown.display())),
            }
        }
        ProjectCmd::Temp { owner } => {
            let owner = owner.map(owner_of).transpose()?;
            sweep();
            let path = create_temp(owner)?;
            let location = temp::location();
            let data = json!({
                "path": path,
                "temp": true,
                "ram_backed": location.ram_backed,
                "owner": owner.map(|o| o.pid),
                "next": format!("brainproxy --project {} engagement start --target HOST", path.display()),
            });
            out.ok(data, || {
                let place = if location.ram_backed { "in RAM" } else { "in the temp folder, on disk" };
                format!("temporary project {place}: {}", path.display())
            });
        }
        ProjectCmd::Discard => {
            if temp::marker(path).is_none() {
                return Err(Error::InvalidInput(format!(
                    "{} is not a temporary project; delete a normal project's files yourself",
                    path.display()
                )));
            }
            let stopped = discard(path)?;
            out.ok(json!({"discarded": path, "stopped": stopped}), || format!("discarded {}", path.display()));
        }
        ProjectCmd::Save { output } => {
            if temp::is_inside(&output) {
                return Err(Error::InvalidInput(format!(
                    "{} is inside a temporary project's folder, which is wiped with it; choose another folder",
                    output.display()
                )));
            }
            let store = Store::open(path)?;
            store.save_as(&output)?;
            let saved = std::fs::canonicalize(&output).unwrap_or(output);
            out.ok(json!({"path": saved, "from": path}), || format!("saved to {}", saved.display()));
        }
        ProjectCmd::Sweep => {
            let (removed, kept) = sweep();
            let location = temp::location();
            let data = json!({
                "removed": removed,
                "kept": kept.iter().map(|(p, e)| json!({"path": p, "error": e})).collect::<Vec<_>>(),
                "root": location.root,
                "ram_backed": location.ram_backed,
            });
            out.ok(data, || {
                let mut text = format!("removed {} abandoned temporary projects", removed.len());
                for (p, e) in &kept {
                    text.push_str(&format!("\nkept {}: {e}", p.display()));
                }
                text
            });
        }
    }
    Ok(())
}

/// `pid` as an owner, refusing one that isn't running (it would be swept at once).
fn owner_of(pid: u32) -> Result<Owner, Error> {
    if !process::alive(pid) {
        return Err(Error::InvalidInput(format!("owner pid {pid} isn't a running process of yours")));
    }
    Ok(Owner { pid, start_time: process::start_time(pid) })
}

/// Makes a temp project and its database.
pub(crate) fn create_temp(owner: Option<Owner>) -> Result<PathBuf, Error> {
    let path = temp::create(owner)?;
    if let Err(e) = Store::open(&path) {
        let _ = temp::remove(&path);
        return Err(e);
    }
    Ok(path)
}

/// Stops everything still using the temp project at `path`, then wipes it. Returns what was
/// stopped. Fails, leaving the project in place, if a process won't stop.
pub(crate) fn discard(path: &Path) -> Result<Value, Error> {
    let store = Store::open(path)?;
    let proxy = crate::proxy_cmd::stop(&store)?.map(|(pid, _)| pid);
    let oob = crate::oob_cmd::stop(&store)?.map(|(pid, _)| pid);
    let work = store.unfinished_work()?;

    // Jobs and fuzz runs poll for the stop request and exit. It is repeated while waiting: one
    // still queued has no process yet and marks itself running once its process starts. They
    // are never signalled: no start time is recorded for them, so a pid reused by another
    // process can't be told apart.
    let busy = || -> Result<Vec<(String, i64, Option<u32>)>, Error> {
        store.stop_all_work()?;
        let work = store.unfinished_work()?;
        Ok(work.into_iter().filter(|(_, _, pid)| pid.is_none_or(process::alive)).collect())
    };
    let deadline = Instant::now() + Duration::from_secs(10);
    let mut left = busy()?;
    while !left.is_empty() && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(100));
        left = busy()?;
    }
    drop(store);
    // Work that never got a process has nothing to stop; once the folder is gone it can't start.
    let stuck: Vec<String> =
        left.iter().filter_map(|(what, id, pid)| pid.map(|pid| format!("{what} {id} (pid {pid})"))).collect();
    if !stuck.is_empty() {
        return Err(Error::Conflict(format!(
            "still running after being asked to stop, so the project was kept: {}; wait for them to finish (or \
             stop those processes), then discard again",
            stuck.join(", ")
        )));
    }
    temp::remove(path)?;
    let work: Vec<Value> = work.iter().map(|(what, id, _)| json!({"kind": what, "id": id})).collect();
    Ok(json!({"proxy": proxy, "oob": oob, "work": work}))
}

/// Wipes temp projects whose owner has exited (and finishes interrupted wipes). Projects
/// without an owner are left for `project discard`. Returns the paths removed, and those kept
/// because wiping failed, with why.
pub(crate) fn sweep() -> (Vec<PathBuf>, Vec<(PathBuf, String)>) {
    temp::remove_leftovers();
    let (mut removed, mut kept) = (Vec::new(), Vec::new());
    let orphans = temp::list()
        .into_iter()
        .filter(|(_, m)| m.owner.is_some_and(|o| process::still_running(o.pid, o.start_time) == Some(false)));
    for (path, _) in orphans {
        match discard(&path) {
            Ok(_) => removed.push(path),
            Err(e) => kept.push((path, e.to_string())),
        }
    }
    (removed, kept)
}
