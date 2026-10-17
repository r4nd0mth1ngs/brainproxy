//! Background jobs (crawls, active scans): a row per job in the project
//! database holding its state, progress, and result, so any process can poll,
//! wait for, or stop a job.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use rusqlite::{params, OptionalExtension};
use serde_json::{json, Value};

use crate::error::{Error, Result};
use crate::store::Store;

pub(crate) const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS jobs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    time TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    kind TEXT NOT NULL,
    state TEXT NOT NULL,
    pid INTEGER,
    args TEXT NOT NULL DEFAULT '[]',
    progress TEXT,
    result TEXT,
    error TEXT,
    finished_time TEXT
);
";

pub const JOB_COLUMNS: &[(&str, &str, &str)] = &[
    ("id", "INTEGER", "Job id"),
    ("time", "TEXT", "UTC start time"),
    ("kind", "TEXT", "crawl, active-scan, or import"),
    ("state", "TEXT", "queued, running, stopping, completed, stopped, failed"),
    ("pid", "INTEGER", "Process running the job"),
    ("args", "TEXT", "Command-line arguments as a JSON array"),
    ("progress", "TEXT", "Latest progress as JSON"),
    ("result", "TEXT", "Final summary as JSON"),
    ("error", "TEXT", "Error message if the job failed"),
];

/// Terminal states.
pub fn is_finished(state: &str) -> bool {
    matches!(state, "completed" | "stopped" | "failed")
}

impl Store {
    pub fn job_create(&self, kind: &str, state: &str, args: &[String]) -> Result<i64> {
        self.conn.execute(
            "INSERT INTO jobs (kind, state, args) VALUES (?1, ?2, ?3)",
            params![kind, state, serde_json::to_string(args).unwrap_or_default()],
        )?;
        Ok(self.conn.last_insert_rowid())
    }

    pub fn job_state(&self, id: i64) -> Result<String> {
        self.conn
            .query_row("SELECT state FROM jobs WHERE id = ?1", [id], |r| r.get(0))
            .optional()?
            .ok_or_else(|| Error::NotFound(format!("job {id}")))
    }

    /// Updates state; `finished` stamps the finish time. pid/error are kept when None.
    pub fn job_set_state(
        &self,
        id: i64,
        state: &str,
        pid: Option<u32>,
        error: Option<&str>,
        finished: bool,
    ) -> Result<()> {
        let n = self.conn.execute(
            "UPDATE jobs SET state = ?1, pid = COALESCE(?2, pid), error = COALESCE(?3, error),
                finished_time = CASE WHEN ?4 THEN strftime('%Y-%m-%dT%H:%M:%fZ','now') ELSE finished_time END
             WHERE id = ?5",
            params![state, pid, error, finished, id],
        )?;
        if n == 0 {
            return Err(Error::NotFound(format!("job {id}")));
        }
        Ok(())
    }

    pub fn job_progress(&self, id: i64, progress: &Value) -> Result<()> {
        self.conn.execute("UPDATE jobs SET progress = ?1 WHERE id = ?2", params![progress.to_string(), id])?;
        Ok(())
    }

    pub fn job_result(&self, id: i64, result: &Value) -> Result<()> {
        self.conn.execute("UPDATE jobs SET result = ?1 WHERE id = ?2", params![result.to_string(), id])?;
        Ok(())
    }

    pub fn job_get(&self, id: i64) -> Result<Value> {
        self.conn
            .query_row(
                "SELECT id, time, kind, state, pid, args, progress, result, error, finished_time FROM jobs WHERE id = ?1",
                [id],
                job_row,
            )
            .optional()?
            .ok_or_else(|| Error::NotFound(format!("job {id}")))
    }

    pub fn job_list(&self, limit: usize) -> Result<Vec<Value>> {
        let mut stmt = self.conn.prepare(
            "SELECT id, time, kind, state, pid, args, progress, NULL, error, finished_time FROM jobs
             ORDER BY id DESC LIMIT ?1",
        )?;
        let rows = stmt.query_map([limit as i64], job_row)?;
        Ok(rows.collect::<std::result::Result<_, _>>()?)
    }
}

fn job_row(r: &rusqlite::Row) -> rusqlite::Result<Value> {
    let parse = |s: Option<String>| s.and_then(|s| serde_json::from_str::<Value>(&s).ok()).unwrap_or(Value::Null);
    let mut v = json!({
        "id": r.get::<_, i64>(0)?,
        "time": r.get::<_, String>(1)?,
        "kind": r.get::<_, String>(2)?,
        "state": r.get::<_, String>(3)?,
        "pid": r.get::<_, Option<i64>>(4)?,
        "args": parse(r.get(5)?),
        "progress": parse(r.get(6)?),
        "error": r.get::<_, Option<String>>(8)?,
        "finished_time": r.get::<_, Option<String>>(9)?,
    });
    let result = parse(r.get(7)?);
    if !result.is_null() {
        v["result"] = result;
    }
    Ok(v)
}

/// Shared by a running job and its watcher thread: a stop flag set when the job
/// is asked to stop, and the latest progress to persist.
#[derive(Clone, Default)]
pub struct JobControl {
    stop: Arc<AtomicBool>,
    progress: Arc<std::sync::Mutex<Option<Value>>>,
}

impl JobControl {
    pub fn stopped(&self) -> bool {
        self.stop.load(Ordering::Relaxed)
    }

    pub fn request_stop(&self) {
        self.stop.store(true, Ordering::Relaxed);
    }

    pub fn set_progress(&self, v: Value) {
        *self.progress.lock().unwrap() = Some(v);
    }

    /// Starts a thread that writes progress and watches for a stop request
    /// every half second. Returns a handle; drop it (or call `finish`) to end it.
    pub fn watch(&self, project: &std::path::Path, job_id: Option<i64>) -> Watcher {
        let done = Arc::new(AtomicBool::new(false));
        let (ctl, flag, project) = (self.clone(), done.clone(), project.to_path_buf());
        let handle = std::thread::spawn(move || {
            let Ok(store) = Store::open(&project) else { return };
            while !flag.load(Ordering::Relaxed) {
                // Parked rather than slept, so dropping the watcher wakes it at once.
                std::thread::park_timeout(Duration::from_millis(500));
                let Some(id) = job_id else { continue };
                if let Some(p) = ctl.progress.lock().unwrap().take() {
                    let _ = store.job_progress(id, &p);
                }
                if store.job_state(id).is_ok_and(|s| s == "stopping") {
                    ctl.request_stop();
                }
            }
        });
        Watcher { done, handle: Some(handle) }
    }
}

pub struct Watcher {
    done: Arc<AtomicBool>,
    handle: Option<std::thread::JoinHandle<()>>,
}

impl Drop for Watcher {
    fn drop(&mut self) {
        self.done.store(true, Ordering::Relaxed);
        if let Some(h) = self.handle.take() {
            h.thread().unpark();
            let _ = h.join();
        }
    }
}
