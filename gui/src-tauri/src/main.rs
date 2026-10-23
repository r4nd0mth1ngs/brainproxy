//! Desktop shell for brainproxy. The window runs the React UI in `../src`; every engine call
//! goes through the `brainproxy` CLI with `--format json`, the same way `mcp serve` runs
//! tools, so scope enforcement, output, and errors are exactly the CLI's.

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use std::collections::HashMap;
use std::path::PathBuf;
use std::process::Stdio;

use serde_json::{json, Value};
use tokio::io::AsyncWriteExt;
use tokio::process::Command;

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

/// The only commands that may run while no project is open (the welcome screen's). Anything
/// else would fall back to `brainproxy.bpdb` in the app's working directory.
const WITHOUT_PROJECT: &[&[&str]] = &[&["project", "temp"], &["project", "sweep"]];

/// Prefix of the only variables the frontend may set on the child (`env`): secrets the CLI
/// reads through options like `--password-env`, so they never appear in argv.
const SECRET_ENV_PREFIX: &str = "BRAINPROXY_SECRET_";

/// Runs `brainproxy --format json --project PROJECT ARGS...` and returns its JSON envelope
/// (no `--project` while none is open, e.g. `project temp` from the welcome screen).
/// `stdin` is written byte for byte; `env` adds BRAINPROXY_SECRET_* variables to the child.
#[tauri::command]
async fn cli(
    project: String,
    args: Vec<String>,
    stdin: Option<Vec<u8>>,
    env: Option<HashMap<String, String>>,
) -> Value {
    let env = env.unwrap_or_default();
    if let Some(bad) = env.keys().find(|k| !k.starts_with(SECRET_ENV_PREFIX)) {
        return failure(format!("env {bad:?} is not allowed (only {SECRET_ENV_PREFIX}*)"));
    }
    let head: Vec<&str> = args.iter().take(2).map(String::as_str).collect();
    if project.is_empty() && !WITHOUT_PROJECT.iter().any(|c| *c == head.as_slice()) {
        return failure("no project is open".into());
    }
    let mut cmd = Command::new(binary());
    cmd.args(["--format", "json"]);
    if !project.is_empty() {
        cmd.arg("--project").arg(&project);
    }
    cmd.args(&args).envs(&env);
    cmd.stdin(if stdin.is_some() { Stdio::piped() } else { Stdio::null() })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    // CREATE_NO_WINDOW: the CLI is a console program; without it each call flashes a console window.
    #[cfg(windows)]
    cmd.creation_flags(0x0800_0000);
    let mut child = match cmd.spawn() {
        Ok(c) => c,
        Err(e) => return failure(format!("can't run {}: {e}", binary().display())),
    };
    if let (Some(data), Some(mut pipe)) = (stdin, child.stdin.take()) {
        tokio::spawn(async move {
            let _ = pipe.write_all(&data).await;
        });
    }
    match child.wait_with_output().await {
        Ok(out) => serde_json::from_slice(&out.stdout).unwrap_or_else(|_| {
            let text = String::from_utf8_lossy(if out.stdout.is_empty() { &out.stderr } else { &out.stdout });
            failure(text.trim().to_string())
        }),
        Err(e) => failure(e.to_string()),
    }
}

/// This process's pid: the owner of the app's temporary projects, so one left behind by a
/// crash is wiped by the next `project sweep`.
#[tauri::command]
fn app_pid() -> u32 {
    std::process::id()
}

fn main() {
    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_opener::init())
        .invoke_handler(tauri::generate_handler![cli, app_pid])
        .run(tauri::generate_context!())
        .expect("error while running brainproxy");
}
