//! Proxy settings: scope, match-and-replace rules, and interception. They live in
//! the project database so the CLI can change them while a proxy is running; the
//! proxy picks up changes within a fraction of a second.

use regex::Regex;
use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};

/// Match-and-replace rules: they began as the proxy's and are still named from here.
pub use crate::rules::{
    apply_request_rules, breaks_head, compile_rules, validate_rule, CompiledRule, Rule, RuleLocation, RULES_KEY,
    RULE_IDS,
};

pub const SCOPE_KEY: &str = "scope";
pub const INTERCEPT_KEY: &str = "intercept";
pub const AUTHZ_KEY: &str = "authz";

/// Live access-control testing (`proxy start --authz`): each in-scope request the proxy
/// records that carries credentials, uses a safe method and isn't excluded is also sent
/// as these identities. Read when the proxy starts, which writes what it uses.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct LiveAuthz {
    #[serde(default)]
    pub enabled: bool,
    /// Auth profiles to send each request as.
    #[serde(default)]
    pub identities: Vec<String>,
    /// Also send without credentials.
    #[serde(default)]
    pub anonymous: bool,
    /// Requests per second the tester sends at most.
    #[serde(default)]
    pub rate: Option<f64>,
    /// Requests waiting to be tested at most; more are dropped and counted.
    #[serde(default = "default_queue")]
    pub queue: usize,
    /// Regex on paths not to test.
    #[serde(default = "default_exclude")]
    pub exclude: String,
    /// Cookies that aren't credentials and stay on the request.
    #[serde(default)]
    pub keep_cookies: Vec<String>,
    /// Test static assets too.
    #[serde(default)]
    pub include_static: bool,
    /// Skip paths of this run, on top of the project's saved ones (`authz skip`).
    #[serde(default)]
    pub skip_paths: Vec<String>,
    /// The authz run (job id) of the proxy that last started with live testing.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub run_id: Option<i64>,
}

fn default_queue() -> usize {
    100
}

fn default_exclude() -> String {
    crate::authz::DEFAULT_EXCLUDE.to_string()
}

impl Default for LiveAuthz {
    fn default() -> Self {
        LiveAuthz {
            enabled: false,
            identities: vec![],
            anonymous: false,
            rate: None,
            queue: default_queue(),
            exclude: default_exclude(),
            keep_cookies: vec![],
            include_static: false,
            skip_paths: vec![],
            run_id: None,
        }
    }
}

/// Host-based scope. Patterns are regexes matched against the host name.
/// An empty include list means every host is in scope.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct Scope {
    #[serde(default)]
    pub include: Vec<String>,
    #[serde(default)]
    pub exclude: Vec<String>,
    /// Record out-of-scope traffic in full too; without it each request keeps only its
    /// request line. Out-of-scope HTTPS is always tunneled without interception (a row per
    /// tunnel either way).
    #[serde(default)]
    pub record_out_of_scope: bool,
}

#[derive(Debug, Clone, Default)]
pub struct CompiledScope {
    include: Vec<Regex>,
    exclude: Vec<Regex>,
    pub record_out_of_scope: bool,
}

impl Scope {
    pub fn compile(&self) -> Result<CompiledScope> {
        Ok(CompiledScope {
            include: compile_all(&self.include)?,
            exclude: compile_all(&self.exclude)?,
            record_out_of_scope: self.record_out_of_scope,
        })
    }
}

impl CompiledScope {
    pub fn allows(&self, host: &str) -> bool {
        let host = host.to_ascii_lowercase();
        (self.include.is_empty() || self.include.iter().any(|r| r.is_match(&host)))
            && !self.exclude.iter().any(|r| r.is_match(&host))
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "kebab-case")]
pub enum TimeoutAction {
    #[default]
    Forward,
    Drop,
}

/// Which messages are held for review. Patterns are regexes; unset means "any".
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct InterceptSettings {
    pub enabled: bool,
    pub requests: bool,
    pub responses: bool,
    /// Hold WebSocket messages from the client.
    #[serde(default)]
    pub ws_to_server: bool,
    /// Hold WebSocket messages from the server.
    #[serde(default)]
    pub ws_to_client: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub method: Option<String>,
    /// Seconds a message waits for a decision before `timeout_action` applies.
    pub timeout_secs: u64,
    pub timeout_action: TimeoutAction,
}

impl Default for InterceptSettings {
    fn default() -> Self {
        Self {
            enabled: false,
            requests: true,
            responses: false,
            ws_to_server: false,
            ws_to_client: false,
            host: None,
            path: None,
            method: None,
            timeout_secs: 120,
            timeout_action: TimeoutAction::Forward,
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct CompiledIntercept {
    pub settings: InterceptSettings,
    host: Option<Regex>,
    path: Option<Regex>,
    method: Option<Regex>,
}

impl InterceptSettings {
    pub fn compile(&self) -> Result<CompiledIntercept> {
        let re = |p: &Option<String>, what: &str| -> Result<Option<Regex>> {
            p.as_deref()
                .map(|p| Regex::new(p).map_err(|e| Error::InvalidInput(format!("intercept {what} pattern: {e}"))))
                .transpose()
        };
        Ok(CompiledIntercept {
            host: re(&self.host, "host")?,
            path: re(&self.path, "path")?,
            method: re(&self.method.as_ref().map(|m| format!("(?i)^(?:{m})$")), "method")?,
            settings: self.clone(),
        })
    }
}

impl CompiledIntercept {
    /// Whether a message for this request should be held.
    pub fn matches(&self, response: bool, method: &str, host: &str, path: &str) -> bool {
        let s = &self.settings;
        s.enabled
            && (if response { s.responses } else { s.requests })
            && self.host.as_ref().is_none_or(|r| r.is_match(host))
            && self.path.as_ref().is_none_or(|r| r.is_match(path))
            && self.method.as_ref().is_none_or(|r| r.is_match(method))
    }

    /// Whether a WebSocket data message going `direction` on a connection upgraded from a
    /// request to `host` and `path` should be held. The method filter doesn't apply.
    pub fn matches_ws(&self, direction: crate::ws::Direction, host: &str, path: &str) -> bool {
        let s = &self.settings;
        s.enabled
            && match direction {
                crate::ws::Direction::ToServer => s.ws_to_server,
                crate::ws::Direction::ToClient => s.ws_to_client,
            }
            && self.host.as_ref().is_none_or(|r| r.is_match(host))
            && self.path.as_ref().is_none_or(|r| r.is_match(path))
    }
}

fn compile_all(patterns: &[String]) -> Result<Vec<Regex>> {
    patterns
        .iter()
        .map(|p| Regex::new(&format!("(?i){p}")).map_err(|e| Error::InvalidInput(format!("scope pattern {p:?}: {e}"))))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scope_matching() {
        let s = Scope {
            include: vec![r"(^|\.)target\.test$".into()],
            exclude: vec!["^cdn\\.".into()],
            ..Default::default()
        }
        .compile()
        .unwrap();
        assert!(s.allows("target.test") && s.allows("API.target.test"));
        assert!(!s.allows("cdn.target.test") && !s.allows("other.test"));
        assert!(Scope::default().compile().unwrap().allows("anything"));
    }

    #[test]
    fn intercept_matching() {
        let i = InterceptSettings { enabled: true, method: Some("post|put".into()), ..Default::default() }
            .compile()
            .unwrap();
        assert!(i.matches(false, "POST", "h", "/"));
        assert!(!i.matches(false, "GET", "h", "/"));
        assert!(!i.matches(true, "POST", "h", "/"));
    }
}
