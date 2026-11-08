//! Who or what produced a record, and who changed it before it went out.
//!
//! The origin is a property of the process: `mcp` when an MCP tool call ran the command,
//! `gui` when the desktop app did, `cli` otherwise. Background jobs, fuzz runs and the proxy
//! are processes of their own; they inherit the environment of the command that started them
//! (and [`pass_on`] sets it explicitly), so a proxy an agent started records `mcp`.
//!
//! An agent can't pass for the app: the MCP server sets [`MCP_ENV`] on every command a tool
//! call runs and gives the agent no way to set or clear environment variables, and that
//! variable wins over [`CLIENT_ENV`].

use serde::{Deserialize, Serialize};

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

/// A change made to a proxied request before it went out, by someone other than the process
/// that recorded it: an edit forwarded from the intercept queue, a match-and-replace rule, or
/// the proxy's auth profile (its session, and the session rules and macros that applied). The
/// history row keeps the list as `edited_by`, so an agent's edit to a person's request (or the
/// reverse) is on the record even though the row's origin is the proxy's.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Edit {
    /// gui, cli or mcp: who made the edit, or added (or last changed) the rule, macro or
    /// profile that made it; None for one from before brainproxy kept it.
    pub by: Option<String>,
    /// The intercept it was edited in.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub intercept: Option<i64>,
    /// The match-and-replace rule that changed it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rule: Option<u32>,
    /// The auth profile whose session went on it; alone, the profile itself (its cookies,
    /// headers and token), else one of its session rules or macros.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auth: Option<String>,
    /// The profile's session rule that applied to it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_rule: Option<u32>,
    /// The profile's macro whose values a session rule put into it.
    #[serde(default, rename = "macro", skip_serializing_if = "Option::is_none")]
    pub macro_name: Option<String>,
}

impl Edit {
    /// "edited in intercept 4 via MCP (an agent)", for people.
    pub fn describe(&self) -> String {
        let profile = self.auth.as_deref().unwrap_or_default();
        let how = match (self.intercept, self.rule, self.session_rule, &self.macro_name) {
            (Some(i), ..) => format!("edited in intercept {i}"),
            (_, Some(r), ..) => format!("changed by rule {r}"),
            (_, _, Some(r), _) => format!("changed by session rule {r} of auth profile {profile}"),
            (.., Some(m)) => format!("given values by macro {m} of auth profile {profile}"),
            _ if self.auth.is_some() => format!("given the session of auth profile {profile}"),
            _ => "edited".to_string(),
        };
        let added = self.rule.is_some() || self.auth.is_some();
        let by = match self.by.as_deref() {
            None => "added by an unknown origin".to_string(),
            Some(o) if added => format!("added {}", describe(Some(o))),
            Some(o) => describe(Some(o)).to_string(),
        };
        format!("{how} {by}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn edits_by_a_profile_say_which_part_of_it() {
        let auth = Some("admin".to_string());
        let by = Some("mcp".to_string());
        let profile = Edit { by: by.clone(), auth: auth.clone(), ..Default::default() };
        assert_eq!(profile.describe(), "given the session of auth profile admin added via MCP (an agent)");
        let rule = Edit { session_rule: Some(3), ..profile.clone() };
        assert_eq!(rule.describe(), "changed by session rule 3 of auth profile admin added via MCP (an agent)");
        let m = Edit { macro_name: Some("csrf".into()), by: None, ..profile };
        assert_eq!(m.describe(), "given values by macro csrf of auth profile admin added by an unknown origin");
        let json = serde_json::to_value(&m).unwrap();
        assert_eq!(json, serde_json::json!({"by": null, "auth": "admin", "macro": "csrf"}));
        assert_eq!(serde_json::from_value::<Edit>(json).unwrap(), m);
    }
}
