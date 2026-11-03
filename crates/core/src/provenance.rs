//! Who or what produced a record, and how it went on the wire beyond the bytes.
//!
//! The origin is a property of the process: `mcp` when an MCP tool call ran the command,
//! `gui` when the desktop app did, `cli` otherwise. Background jobs, fuzz runs and the proxy
//! are processes of their own; they inherit the environment of the command that started them
//! (and [`pass_on`] sets it explicitly), so a proxy an agent started records `mcp`.
//!
//! An agent can't pass for the app: the MCP server sets [`MCP_ENV`] on every command a tool
//! call runs and gives the agent no way to set or clear environment variables, and that
//! variable wins over [`CLIENT_ENV`].

use std::sync::RwLock;

/// Set on every command an MCP tool call runs.
pub const MCP_ENV: &str = "BRAINPROXY_MCP_CALL";

/// Set to `gui` by the desktop app (and its development bridge) on the commands it runs.
pub const CLIENT_ENV: &str = "BRAINPROXY_CLIENT";

/// The origins a record can have; rows from before schema v13 have none ("unknown").
pub const ORIGINS: &[&str] = &["gui", "cli", "mcp"];

/// This process's origin: `mcp`, `gui` or `cli`.
pub fn origin() -> &'static str {
    if std::env::var_os(MCP_ENV).is_some() {
        "mcp"
    } else if std::env::var(CLIENT_ENV).is_ok_and(|v| v == "gui") {
        "gui"
    } else {
        "cli"
    }
}

/// Makes a child process record the same origin as this one. Children inherit the
/// environment anyway; this keeps it true if that ever changes.
pub fn pass_on(cmd: &mut std::process::Command) {
    match origin() {
        "mcp" => {
            cmd.env(MCP_ENV, "1");
        }
        "gui" => {
            cmd.env(CLIENT_ENV, "gui");
        }
        _ => {
            cmd.env_remove(CLIENT_ENV);
        }
    }
}

/// An origin in words, for people reading a report or a listing.
pub fn describe(origin: Option<&str>) -> &'static str {
    match origin {
        Some("mcp") => "via MCP (an agent)",
        Some("gui") => "from the desktop app",
        Some("cli") => "from the command line",
        _ => "from an unknown origin (recorded before brainproxy kept it)",
    }
}

/// The TLS server name (SNI) override the clients of this process send, if any. A command
/// sends with one set of options, so it is a process value like the origin.
static SNI: RwLock<Option<String>> = RwLock::new(None);

/// Notes the SNI override a client was created with, to record it with every https capture.
pub(crate) fn note_sni(sni: Option<&str>) {
    if let Some(name) = sni {
        *SNI.write().unwrap() = Some(name.to_string());
    }
}

/// The SNI override in effect, for a capture of `scheme`: TLS only.
pub(crate) fn sni_for(scheme: &str) -> Option<String> {
    if scheme.eq_ignore_ascii_case("https") || scheme.eq_ignore_ascii_case("wss") {
        SNI.read().unwrap().clone()
    } else {
        None
    }
}
