//! MCP server (`mcp serve`): exposes the CLI as tools over stdio, newline-delimited
//! JSON-RPC 2.0 (initialize, ping, tools/list, tools/call).
//!
//! The tool list is derived from the same clap definitions as `capabilities`, one tool
//! per leaf command. A call runs this binary as a child process with the command's
//! arguments, `--format json`, and the server's `--project`/`--home`, so it goes through
//! exactly the same code, scope checks, and JSON envelope as a shell invocation. The
//! child's stdin is the call's `stdin` argument or empty, never the server's stdin.

use std::any::TypeId;
use std::io::{BufRead, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command as Process, Stdio};
use std::time::{Duration, Instant};

use brainproxy_core::Error;
use clap::{Arg, ArgAction, Command};
use serde_json::{json, Map, Value};

/// Protocol versions we can speak; the first is offered when the client asks for another.
const PROTOCOL_VERSIONS: &[&str] = &["2025-06-18", "2025-03-26", "2024-11-05"];

/// Commands not offered as tools: the server itself, and foreground servers that never
/// return (their `start` variants run them in the background).
const EXCLUDED: &[&str] = &["mcp serve", "proxy run", "oob run"];

#[derive(clap::Subcommand)]
pub enum McpCmd {
    /// Serve the CLI as MCP tools over stdio (JSON-RPC 2.0, one message per line).
    #[command(after_help = "One tool per command (`history list` -> history_list); tool arguments are the \
        command's flags and positionals by name, plus `stdin` where the command reads it. Each call runs \
        `brainproxy --format json --project P ...` as a child process and returns its JSON envelope; isError \
        is set when the exit code is not 0. Calls run one at a time; use --background and job_wait for long \
        work. See docs/MCP.md.")]
    Serve(ServeArgs),
}

#[derive(clap::Args)]
pub struct ServeArgs {
    /// Seconds a tool call may run before it is killed (use --background for long work).
    #[arg(long, default_value_t = 600)]
    timeout: u64,
    /// Maximum bytes of command output returned per call; the rest is cut off.
    #[arg(long, default_value_t = 1_000_000)]
    max_output: usize,
}

struct Server {
    root: Command,
    project: PathBuf,
    home: Option<PathBuf>,
    timeout: Duration,
    max_output: usize,
}

pub fn serve(root: Command, project: &Path, home: Option<&Path>, args: ServeArgs) -> Result<(), Error> {
    let server = Server {
        root,
        project: project.to_path_buf(),
        home: home.map(Path::to_path_buf),
        timeout: Duration::from_secs(args.timeout),
        max_output: args.max_output,
    };
    let stdin = std::io::stdin();
    let mut stdout = std::io::stdout();
    for line in stdin.lock().lines() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        if let Some(reply) = server.handle(&line) {
            writeln!(stdout, "{reply}")?;
            stdout.flush()?;
        }
    }
    Ok(())
}

impl Server {
    /// Handles one message; returns the response, or None for notifications.
    fn handle(&self, line: &str) -> Option<Value> {
        let msg: Value = match serde_json::from_str(line) {
            Ok(v) => v,
            Err(e) => return Some(rpc_error(Value::Null, -32700, &format!("parse error: {e}"))),
        };
        let Some(obj) = msg.as_object() else {
            return Some(rpc_error(Value::Null, -32600, "expected a JSON-RPC request object"));
        };
        let id = obj.get("id").cloned();
        let Some(method) = obj.get("method").and_then(Value::as_str) else {
            // A response from the client (we send no requests) or garbage.
            return id.map(|id| rpc_error(id, -32600, "missing method"));
        };
        let id = id?; // notifications (initialized, cancelled, ...) need no reply
        let params = obj.get("params").cloned().unwrap_or(Value::Null);
        let result = match method {
            "initialize" => Ok(self.initialize(&params)),
            "ping" => Ok(json!({})),
            "tools/list" => Ok(json!({"tools": self.tools()})),
            "tools/call" => self.call(&params),
            _ => Err((-32601, format!("method not found: {method}"))),
        };
        Some(match result {
            Ok(r) => json!({"jsonrpc": "2.0", "id": id, "result": r}),
            Err((code, msg)) => rpc_error(id, code, &msg),
        })
    }

    fn initialize(&self, params: &Value) -> Value {
        let asked = params["protocolVersion"].as_str().unwrap_or_default();
        let version = PROTOCOL_VERSIONS.iter().find(|v| **v == asked).unwrap_or(&PROTOCOL_VERSIONS[0]);
        json!({
            "protocolVersion": version,
            "capabilities": {"tools": {"listChanged": false}},
            "serverInfo": {"name": "brainproxy", "version": env!("CARGO_PKG_VERSION")},
            "instructions": "brainproxy web security testing tools. Nothing is sent until a scope exists: call \
                engagement_start once per project with the targets you may test (it can never be changed). \
                Each tool returns the CLI's JSON envelope {ok, command, data} or {ok:false, error:{kind, message}}. \
                Use the `capabilities` tool for conventions and exit codes, `schema` + `query` to read recorded \
                traffic with SQL, and --background with job_wait for crawls, scans, and fuzzing.",
        })
    }

    fn tools(&self) -> Vec<Value> {
        let mut tools = Vec::new();
        leaves(&self.root, &mut Vec::new(), &mut |path, cmd| {
            if !EXCLUDED.contains(&path.join(" ").as_str()) {
                tools.push(tool(path, cmd));
            }
        });
        tools
    }

    fn call(&self, params: &Value) -> Result<Value, (i64, String)> {
        let name = params["name"].as_str().ok_or((-32602, "missing tool name".to_string()))?;
        let empty = Map::new();
        let args = match &params["arguments"] {
            Value::Null => &empty,
            Value::Object(m) => m,
            _ => return Err((-32602, "arguments must be an object".into())),
        };
        let mut found = None;
        leaves(&self.root, &mut Vec::new(), &mut |path, cmd| {
            if tool_name(path) == name && !EXCLUDED.contains(&path.join(" ").as_str()) {
                found = Some((path.to_vec(), cmd.clone()));
            }
        });
        let (path, cmd) = found.ok_or_else(|| (-32602, format!("unknown tool: {name}")))?;
        let argv = argv(&path, &cmd, args).map_err(|e| (-32602, e))?;
        let stdin = match args.get("stdin") {
            None | Some(Value::Null) => None,
            Some(Value::String(s)) if reads_stdin(&cmd) => Some(s.clone().into_bytes()),
            Some(Value::String(_)) => return Err((-32602, format!("{name} does not read stdin"))),
            Some(_) => return Err((-32602, "stdin must be a string".into())),
        };
        Ok(self.run(&path.join(" "), &argv, stdin))
    }

    /// Runs `brainproxy <argv>` with the server's globals and returns an MCP tool result.
    fn run(&self, command: &str, argv: &[String], stdin: Option<Vec<u8>>) -> Value {
        let exe = match std::env::current_exe() {
            Ok(e) => e,
            Err(e) => return failure(command, "io", &format!("can't find own executable: {e}")),
        };
        let mut p = Process::new(exe);
        p.args(["--format", "json", "--project"]).arg(&self.project);
        if let Some(home) = &self.home {
            p.arg("--home").arg(home);
        }
        p.args(argv).stdin(if stdin.is_some() { Stdio::piped() } else { Stdio::null() });
        let mut child = match p.stdout(Stdio::piped()).stderr(Stdio::piped()).spawn() {
            Ok(c) => c,
            Err(e) => return failure(command, "io", &format!("can't start command: {e}")),
        };
        if let (Some(data), Some(mut pipe)) = (stdin, child.stdin.take()) {
            std::thread::spawn(move || {
                let _ = pipe.write_all(&data);
            });
        }
        let out = drain(child.stdout.take(), self.max_output);
        let err = drain(child.stderr.take(), 4096);
        let deadline = Instant::now() + self.timeout;
        let status = loop {
            match child.try_wait() {
                Ok(Some(s)) => break Some(s),
                Ok(None) if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(20)),
                _ => {
                    let _ = child.kill();
                    let _ = child.wait();
                    break None;
                }
            }
        };
        let (stdout, truncated) = out.join().unwrap_or_default();
        let (stderr, _) = err.join().unwrap_or_default();
        let Some(status) = status else {
            let secs = self.timeout.as_secs();
            return failure(command, "timeout", &format!("killed after {secs} s; use --background and job_wait"));
        };
        let mut text = String::from_utf8_lossy(&stdout).into_owned();
        if truncated {
            text.push_str(&format!("\n[output cut off at {} bytes]", self.max_output));
        }
        let mut content = vec![json!({"type": "text", "text": text})];
        let stderr = String::from_utf8_lossy(&stderr);
        if !status.success() && !stderr.trim().is_empty() {
            content.push(json!({"type": "text", "text": format!("stderr: {}", stderr.trim())}));
        }
        let mut result = json!({"content": content, "isError": !status.success()});
        if let Ok(v @ Value::Object(_)) = serde_json::from_slice::<Value>(&stdout) {
            result["structuredContent"] = v;
        }
        result
    }
}

/// Reads a pipe to the end on a thread, keeping the first `max` bytes.
fn drain(pipe: Option<impl Read + Send + 'static>, max: usize) -> std::thread::JoinHandle<(Vec<u8>, bool)> {
    std::thread::spawn(move || {
        let (mut kept, mut truncated) = (Vec::new(), false);
        if let Some(mut pipe) = pipe {
            let mut buf = [0u8; 8192];
            while let Ok(n @ 1..) = pipe.read(&mut buf) {
                let room = max.saturating_sub(kept.len());
                kept.extend_from_slice(&buf[..n.min(room)]);
                truncated |= n > room;
            }
        }
        (kept, truncated)
    })
}

/// A tool result for a failure that happened outside the command (start, timeout).
fn failure(command: &str, kind: &str, message: &str) -> Value {
    let env = json!({"ok": false, "command": command, "error": {"kind": kind, "message": message}});
    json!({"content": [{"type": "text", "text": env.to_string()}], "isError": true, "structuredContent": env})
}

fn rpc_error(id: Value, code: i64, message: &str) -> Value {
    json!({"jsonrpc": "2.0", "id": id, "error": {"code": code, "message": message}})
}

/// Calls `f` for every visible leaf command with its path (e.g. ["history", "list"]).
fn leaves(cmd: &Command, path: &mut Vec<String>, f: &mut impl FnMut(&[String], &Command)) {
    for sub in cmd.get_subcommands().filter(|c| !c.is_hide_set()) {
        path.push(sub.get_name().to_string());
        if sub.has_subcommands() {
            leaves(sub, path, f);
        } else {
            f(path, sub);
        }
        path.pop();
    }
}

fn tool_name(path: &[String]) -> String {
    path.join("_").replace('-', "_")
}

/// The arguments a tool accepts: visible, non-global clap args (globals come from the server).
fn tool_args(cmd: &Command) -> impl Iterator<Item = &Arg> {
    cmd.get_arguments()
        .filter(|a| !a.is_hide_set() && !a.is_global_set() && !matches!(a.get_id().as_str(), "help" | "version"))
}

fn reads_stdin(cmd: &Command) -> bool {
    let mentions = |s: Option<String>| s.is_some_and(|s| s.contains("stdin"));
    mentions(cmd.get_after_help().map(|s| s.to_string()))
        || tool_args(cmd).any(|a| mentions(a.get_help().map(|s| s.to_string())))
}

fn tool(path: &[String], cmd: &Command) -> Value {
    let mut properties = Map::new();
    let mut required = Vec::new();
    for a in tool_args(cmd) {
        let id = a.get_id().to_string();
        let mut help = a.get_help().map(|s| s.to_string()).unwrap_or_default();
        let defaults: Vec<String> = a.get_default_values().iter().map(|d| d.to_string_lossy().into_owned()).collect();
        if !defaults.is_empty() {
            let sep = if help.is_empty() || help.ends_with('.') { "" } else { "." };
            help.push_str(&format!("{sep} Default: {}.", defaults.join(",")));
        }
        let mut schema = match a.get_action() {
            ArgAction::SetTrue | ArgAction::SetFalse => json!({"type": "boolean"}),
            ArgAction::Count => json!({"type": "integer", "minimum": 0}),
            _ => {
                let mut s = json!({"type": value_type(a)});
                let possible: Vec<String> = a.get_possible_values().iter().map(|p| p.get_name().to_string()).collect();
                if !possible.is_empty() {
                    s["enum"] = json!(possible);
                }
                if repeatable(a) {
                    s = json!({"type": "array", "items": s});
                }
                s
            }
        };
        schema["description"] = json!(help.trim());
        properties.insert(id.clone(), schema);
        if a.is_required_set() {
            required.push(id);
        }
    }
    if reads_stdin(cmd) {
        properties.insert(
            "stdin".into(),
            json!({"type": "string", "description": "Text for the command's standard input, read when its FILE/INPUT argument is '-' or omitted."}),
        );
    }
    let mut description = cmd.get_about().map(|s| s.to_string()).unwrap_or_default();
    if let Some(notes) = cmd.get_after_help() {
        description.push_str(&format!("\n\n{notes}"));
    }
    json!({
        "name": tool_name(path),
        "title": format!("brainproxy {}", path.join(" ")),
        "description": description,
        "inputSchema": {"type": "object", "properties": properties, "required": required, "additionalProperties": false},
    })
}

fn repeatable(a: &Arg) -> bool {
    matches!(a.get_action(), ArgAction::Append) || a.get_num_args().is_some_and(|n| n.max_values() > 1)
}

fn value_type(a: &Arg) -> &'static str {
    let t = a.get_value_parser().type_id();
    let ints = [
        TypeId::of::<u8>(),
        TypeId::of::<u16>(),
        TypeId::of::<u32>(),
        TypeId::of::<u64>(),
        TypeId::of::<usize>(),
        TypeId::of::<i32>(),
        TypeId::of::<i64>(),
    ];
    if ints.iter().any(|i| t == *i) {
        "integer"
    } else if t == TypeId::of::<f64>() || t == TypeId::of::<f32>() {
        "number"
    } else if t == TypeId::of::<bool>() {
        "boolean"
    } else {
        "string"
    }
}

/// Builds the command line for a tool call: `path... --flag=value ... -- positionals...`.
/// `--flag=value` and the `--` separator keep values that start with '-' as values.
fn argv(path: &[String], cmd: &Command, args: &Map<String, Value>) -> Result<Vec<String>, String> {
    let mut flags = Vec::new();
    let mut positionals: Vec<(usize, Vec<String>)> = Vec::new();
    for (key, value) in args {
        if key == "stdin" {
            continue;
        }
        let a = tool_args(cmd).find(|a| a.get_id() == key).ok_or_else(|| format!("unknown argument: {key}"))?;
        let flag = match (a.get_long(), a.get_short()) {
            (Some(l), _) => Some(format!("--{l}")),
            (None, Some(s)) => Some(format!("-{s}")),
            (None, None) => None,
        };
        match (a.get_action(), &flag) {
            (ArgAction::SetTrue | ArgAction::SetFalse, Some(f)) => match value {
                Value::Bool(true) => flags.push(f.clone()),
                Value::Bool(false) | Value::Null => {}
                _ => return Err(format!("{key} must be a boolean")),
            },
            (ArgAction::Count, Some(f)) => {
                let n = value.as_u64().ok_or_else(|| format!("{key} must be a non-negative integer"))?;
                flags.extend(std::iter::repeat_n(f.clone(), n.min(16) as usize));
            }
            _ => {
                let values = match value {
                    Value::Null => continue,
                    Value::Array(items) if repeatable(a) => {
                        items.iter().map(|v| scalar(key, v)).collect::<Result<Vec<_>, _>>()?
                    }
                    Value::Array(_) => return Err(format!("{key} takes one value, not an array")),
                    v => vec![scalar(key, v)?],
                };
                match &flag {
                    Some(f) => flags.extend(values.iter().map(|v| format!("{f}={v}"))),
                    None => positionals.push((a.get_index().unwrap_or(0), values)),
                }
            }
        }
    }
    let mut out = path.to_vec();
    out.extend(flags);
    if !positionals.is_empty() {
        positionals.sort_by_key(|(i, _)| *i);
        out.push("--".into());
        out.extend(positionals.into_iter().flat_map(|(_, v)| v));
    }
    Ok(out)
}

fn scalar(key: &str, v: &Value) -> Result<String, String> {
    match v {
        Value::String(s) => Ok(s.clone()),
        Value::Number(n) => Ok(n.to_string()),
        Value::Bool(b) => Ok(b.to_string()),
        _ => Err(format!("{key}: expected a string, number, or boolean")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cmd() -> Command {
        Command::new("t")
            .arg(Arg::new("verbose").long("verbose").action(ArgAction::SetTrue))
            .arg(Arg::new("limit").long("limit").value_parser(clap::value_parser!(u32)))
            .arg(Arg::new("tag").long("tag").action(ArgAction::Append))
            .arg(Arg::new("first").index(1))
            .arg(Arg::new("rest").index(2).num_args(1..))
    }

    #[test]
    fn builds_argv_with_separator() {
        let args = json!({"verbose": true, "limit": 5, "tag": ["a", "-b"], "rest": ["-x", "y"], "first": "-"});
        let v = argv(&["t".into()], &cmd(), args.as_object().unwrap()).unwrap();
        assert_eq!(v, ["t", "--verbose", "--limit=5", "--tag=a", "--tag=-b", "--", "-", "-x", "y"]);
    }

    #[test]
    fn rejects_unknown_and_mistyped() {
        let c = cmd();
        assert!(argv(&[], &c, json!({"nope": 1}).as_object().unwrap()).unwrap_err().contains("unknown"));
        assert!(argv(&[], &c, json!({"verbose": "yes"}).as_object().unwrap()).is_err());
        assert!(argv(&[], &c, json!({"limit": [1, 2]}).as_object().unwrap()).is_err());
    }

    #[test]
    fn schema_types() {
        let t = tool(&["t".into()], &cmd());
        let p = &t["inputSchema"]["properties"];
        assert_eq!(p["verbose"]["type"], "boolean");
        assert_eq!(p["limit"]["type"], "integer");
        assert_eq!(p["tag"]["type"], "array");
        assert_eq!(p["rest"]["type"], "array");
        assert_eq!(p["first"]["type"], "string");
    }
}
