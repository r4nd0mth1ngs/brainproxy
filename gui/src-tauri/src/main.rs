//! Desktop shell for brainproxy. The window runs the React UI in `../src`; every engine call
//! goes through the `brainproxy` CLI with `--format json`, the same way `mcp serve` runs
//! tools, so scope enforcement, output, and errors are exactly the CLI's. The one thing the
//! shell does itself is temporary engagements (`temp.rs`): creating and deleting their
//! folders, which nothing reachable from the CLI or MCP may do.

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod temp;

use std::collections::HashMap;
use std::fs::File;
use std::path::PathBuf;
use std::process::Stdio;
use std::sync::Mutex;

use serde_json::{json, Value};
use tauri::Manager;
use tokio::io::AsyncWriteExt;
use tokio::process::Command;
use tokio::sync::oneshot;

/// The CLI to run: $BRAINPROXY_BIN, else the bundled sidecar next to this executable,
/// else `brainproxy` on PATH.
fn binary() -> PathBuf {
    if let Some(bin) = std::env::var_os("BRAINPROXY_BIN") {
        return bin.into();
    }
    let name = if cfg!(windows) { "brainproxy.exe" } else { "brainproxy" };
    std::env::current_exe()
        .ok()
        .and_then(|exe| Some(exe.parent()?.join(name)))
        .filter(|p| p.is_file())
        .unwrap_or_else(|| name.into())
}

fn failure(message: String) -> Value {
    json!({"ok": false, "command": "gui", "error": {"kind": "gui", "message": message}})
}

/// Prefix of the only variables the frontend may set on the child (`env`): secrets the CLI
/// reads through options like `--password-env`, so they never appear in argv.
const SECRET_ENV_PREFIX: &str = "BRAINPROXY_SECRET_";

/// Calls started with a `call` id, which `cli_cancel` can stop.
#[derive(Default)]
struct Cancellable(Mutex<HashMap<String, oneshot::Sender<()>>>);

impl Cancellable {
    fn held(&self) -> std::sync::MutexGuard<'_, HashMap<String, oneshot::Sender<()>>> {
        self.0.lock().unwrap_or_else(|e| e.into_inner())
    }
}

/// How long a cancelled call may take to finish after SIGTERM (recording what it sent)
/// before it is killed.
const CANCEL_GRACE: std::time::Duration = std::time::Duration::from_secs(3);

/// Runs `brainproxy --format json --project PROJECT ARGS...` and returns its JSON envelope.
/// `stdin` is written byte for byte; `env` adds BRAINPROXY_SECRET_* variables to the child.
/// With a `call` id, `cli_cancel` with that id stops the child (a browser sign-in waiting
/// for the user, say), and the envelope says it was cancelled. On unix the child gets
/// SIGTERM first, so a request it already sent is recorded as cancelled, and is killed if
/// it is still running after `CANCEL_GRACE`. Windows has no SIGTERM: the child is killed at
/// once, and a sent request keeps the row it was given before it went out.
#[tauri::command]
async fn cli(
    app: tauri::AppHandle,
    project: String,
    args: Vec<String>,
    stdin: Option<Vec<u8>>,
    env: Option<HashMap<String, String>>,
    call: Option<String>,
) -> Value {
    let env = env.unwrap_or_default();
    if let Some(bad) = env.keys().find(|k| !k.starts_with(SECRET_ENV_PREFIX)) {
        return failure(format!("env {bad:?} is not allowed (only {SECRET_ENV_PREFIX}*)"));
    }
    let Some(call) = call else { return run(&project, &args, stdin, &env).await };
    let child = match spawn(&project, &args, stdin, &env) {
        Ok(c) => c,
        Err(e) => return e,
    };
    let (tx, rx) = oneshot::channel();
    app.state::<Cancellable>().held().insert(call.clone(), tx);
    let pid = child.id();
    let output = output(child);
    tokio::pin!(output);
    let out = tokio::select! {
        out = &mut output => out,
        _ = rx => {
            terminate(pid);
            // Dropping the output drops the child, which kills it (kill_on_drop).
            let _ = tokio::time::timeout(CANCEL_GRACE, &mut output).await;
            json!({"ok": false, "command": "gui", "error": {"kind": "cancelled", "message": "cancelled"}})
        }
    };
    app.state::<Cancellable>().held().remove(&call);
    out
}

/// Asks the child to exit (SIGTERM). Elsewhere there is no such request; the child is killed
/// when it is dropped.
fn terminate(pid: Option<u32>) {
    #[cfg(unix)]
    if let Some(pid) = pid.and_then(|p| libc::pid_t::try_from(p).ok()).filter(|&p| p > 1) {
        // SAFETY: kill() only sends a signal; the pid is our own child's, still unreaped.
        unsafe {
            libc::kill(pid, libc::SIGTERM);
        }
    }
    #[cfg(not(unix))]
    let _ = pid;
}

/// Stops the `cli` call started with this id, if it is still running.
#[tauri::command]
fn cli_cancel(call: String, running: tauri::State<'_, Cancellable>) {
    if let Some(tx) = running.held().remove(&call) {
        let _ = tx.send(());
    }
}

async fn run(project: &str, args: &[String], stdin: Option<Vec<u8>>, env: &HashMap<String, String>) -> Value {
    match spawn(project, args, stdin, env) {
        Ok(child) => output(child).await,
        Err(e) => e,
    }
}

/// Starts the CLI and feeds it `stdin`; an error comes back as the envelope to return.
fn spawn(
    project: &str,
    args: &[String],
    stdin: Option<Vec<u8>>,
    env: &HashMap<String, String>,
) -> Result<tokio::process::Child, Value> {
    let mut cmd = Command::new(binary());
    cmd.args(["--format", "json", "--project"]).arg(project).args(args).envs(env);
    cmd.stdin(if stdin.is_some() { Stdio::piped() } else { Stdio::null() })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    // CREATE_NO_WINDOW: the CLI is a console program; without it each call flashes a console window.
    #[cfg(windows)]
    cmd.creation_flags(0x0800_0000);
    let mut child = cmd.spawn().map_err(|e| failure(format!("can't run {}: {e}", binary().display())))?;
    if let (Some(data), Some(mut pipe)) = (stdin, child.stdin.take()) {
        tokio::spawn(async move {
            let _ = pipe.write_all(&data).await;
        });
    }
    Ok(child)
}

/// The child's JSON envelope, once it exits.
async fn output(child: tokio::process::Child) -> Value {
    match child.wait_with_output().await {
        Ok(out) => serde_json::from_slice(&out.stdout).unwrap_or_else(|_| {
            let text = String::from_utf8_lossy(if out.stdout.is_empty() { &out.stderr } else { &out.stdout });
            failure(text.trim().to_string())
        }),
        Err(e) => failure(e.to_string()),
    }
}

/// The locks on the temp projects this app has, with whether each is a leftover it is asking
/// about (rather than one it created). Dropping a lock (or the app exiting) makes the project
/// a leftover again.
#[derive(Default)]
struct TempLocks(Mutex<HashMap<PathBuf, (File, bool)>>);

impl TempLocks {
    fn held(&self) -> std::sync::MutexGuard<'_, HashMap<PathBuf, (File, bool)>> {
        self.0.lock().unwrap_or_else(|e| e.into_inner())
    }
}

/// Where new temp projects go: `{ram_backed}`.
#[tauri::command]
fn temp_location() -> Value {
    json!({"ram_backed": temp::location().ram_backed})
}

/// Makes a temp project folder and returns `{path, ram_backed}`; the UI then opens `path` like
/// any project (`project init`, `engagement start`).
#[tauri::command]
fn temp_create(locks: tauri::State<'_, TempLocks>) -> Result<Value, String> {
    let (path, lock) = temp::create().map_err(|e| e.to_string())?;
    let ram_backed = temp::ram_backed(&path);
    locks.held().insert(path.clone(), (lock, false));
    Ok(json!({"path": path, "ram_backed": ram_backed}))
}

/// Temp projects left by an app that exited without discarding them, newest first:
/// `[{path, created, ram_backed}]`. Each stays locked by this app until it is discarded, so
/// a second window doesn't ask too.
#[tauri::command]
fn temp_leftovers(locks: tauri::State<'_, TempLocks>) -> Vec<Value> {
    let mut held = locks.held();
    for (path, _, lock) in temp::leftovers() {
        held.insert(path, (lock, true));
    }
    let mut found: Vec<Value> = held
        .iter()
        .filter(|(_, (_, leftover))| *leftover)
        .filter_map(|(p, _)| {
            let marker = temp::marker(p)?;
            Some(json!({"path": p, "created": marker["created"], "ram_backed": temp::ram_backed(p)}))
        })
        .collect();
    found.sort_by_key(|v| std::cmp::Reverse(v["created"].as_u64()));
    found
}

/// Whether `path` is inside a temp project's folder (saving there would be deleted with it).
#[tauri::command]
fn temp_is_inside(path: String) -> bool {
    temp::is_inside(std::path::Path::new(&path))
}

/// Stops everything still running for the temp project (`project stop`, which deletes
/// nothing), then deletes its folder. Fails, keeping it, if something won't stop.
#[tauri::command]
async fn temp_discard(project: String, locks: tauri::State<'_, TempLocks>) -> Result<(), String> {
    let path = PathBuf::from(&project);
    // Only one this app holds the lock for (made here, or a leftover it is offering), so an
    // engagement another app window has open is never deleted from this one.
    if !locks.held().contains_key(&path) {
        return Err(format!("{project} is not a temporary engagement this window has open"));
    }
    if temp::marker(&path).is_none() {
        return Err(format!("{project} is not a temporary project"));
    }
    let stopped = run(&project, &["project".into(), "stop".into()], None, &HashMap::new()).await;
    if stopped["ok"] != true {
        return Err(stopped["error"]["message"].as_str().unwrap_or("its processes didn't stop").to_string());
    }
    locks.held().remove(&path);
    temp::remove(&path).map_err(|e| e.to_string())
}

fn main() {
    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_opener::init())
        .manage(TempLocks::default())
        .manage(Cancellable::default())
        .invoke_handler(tauri::generate_handler![
            cli,
            cli_cancel,
            temp_location,
            temp_create,
            temp_leftovers,
            temp_is_inside,
            temp_discard
        ])
        .run(tauri::generate_context!())
        .expect("error while running brainproxy");
}
