//! Machine-readable description of every command, so an agent can discover the
//! whole CLI in one call instead of scraping `--help`.

use brainproxy_core::codec;
use clap::{ArgAction, Command};
use serde_json::{json, Value};

pub fn describe(cmd: &Command) -> Value {
    json!({
        "name": "brainproxy",
        "version": env!("CARGO_PKG_VERSION"),
        "conventions": {
            "interactive_prompts": false,
            "output": "With --format json (the default when stdout is not a terminal) every command prints one JSON envelope: {ok, command, data} or {ok:false, command, error:{kind, message}}.",
            "stdin": "Commands that take a FILE or INPUT read stdin when it is '-' or omitted.",
            "project": "History is stored in the SQLite project file from --project or BRAINPROXY_PROJECT, created on first use.",
        },
        "exit_codes": {
            "0": "success",
            "1": "internal, I/O, or storage error",
            "2": "invalid input or usage",
            "3": "network error (connect, TLS, timeout, protocol)",
            "4": "not found",
        },
        "env": {
            "BRAINPROXY_PROJECT": "project file path",
            "BRAINPROXY_FORMAT": "auto | json | text",
        },
        "codecs": {
            "encode": codec::ENCODINGS,
            "decode": codec::DECODINGS,
            "hash": codec::HASHES,
        },
        "commands": cmd.get_subcommands().filter(|c| !c.is_hide_set()).map(|c| command(c, "")).collect::<Vec<_>>(),
        "global_args": args(cmd),
    })
}

fn command(cmd: &Command, prefix: &str) -> Value {
    let path = if prefix.is_empty() { cmd.get_name().to_string() } else { format!("{prefix} {}", cmd.get_name()) };
    let subs: Vec<Value> = cmd.get_subcommands().filter(|c| !c.is_hide_set()).map(|c| command(c, &path)).collect();
    let mut v = json!({
        "command": path,
        "about": cmd.get_about().map(|s| s.to_string()),
        "args": args(cmd),
    });
    if let Some(long) = cmd.get_after_help() {
        v["notes"] = json!(long.to_string());
    }
    if !subs.is_empty() {
        v["subcommands"] = json!(subs);
    }
    v
}

fn args(cmd: &Command) -> Vec<Value> {
    cmd.get_arguments()
        .filter(|a| !a.is_hide_set() && !matches!(a.get_id().as_str(), "help" | "version"))
        .filter(|a| !a.is_global_set() || cmd.get_name() == "brainproxy")
        .map(|a| {
            let takes_value = !matches!(
                a.get_action(),
                ArgAction::SetTrue | ArgAction::SetFalse | ArgAction::Count | ArgAction::Help | ArgAction::Version
            );
            let mut v = json!({
                "name": a.get_id().as_str(),
                "help": a.get_help().map(|s| s.to_string()),
                "required": a.is_required_set(),
                "takes_value": takes_value,
                "repeatable": matches!(a.get_action(), ArgAction::Append | ArgAction::Count),
            });
            match a.get_long() {
                Some(l) => v["flag"] = json!(format!("--{l}")),
                None => v["positional"] = json!(true),
            }
            if let Some(s) = a.get_short() {
                v["short"] = json!(format!("-{s}"));
            }
            let defaults: Vec<String> =
                a.get_default_values().iter().map(|d| d.to_string_lossy().into_owned()).collect();
            if !defaults.is_empty() {
                v["default"] = json!(defaults.join(","));
            }
            let possible: Vec<String> = a.get_possible_values().iter().map(|p| p.get_name().to_string()).collect();
            if !possible.is_empty() {
                v["values"] = json!(possible);
            }
            if let Some(env) = a.get_env() {
                v["env"] = json!(env.to_string_lossy());
            }
            v
        })
        .collect()
}

/// Describes a single command by its space-separated path, e.g. "history list".
pub fn describe_one(root: &Command, path: &str) -> Option<Value> {
    let mut cmd = root;
    let mut walked = Vec::new();
    for part in path.split_whitespace() {
        cmd = cmd.get_subcommands().find(|c| c.get_name() == part)?;
        walked.push(part);
    }
    if walked.is_empty() {
        return None;
    }
    let prefix = walked[..walked.len() - 1].join(" ");
    Some(command(cmd, &prefix))
}
