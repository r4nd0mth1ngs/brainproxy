//! Proxy settings: scope, match-and-replace rules, and interception. They live in
//! the project database so the CLI can change them while a proxy is running; the
//! proxy picks up changes within a fraction of a second.

use std::borrow::Cow;
use std::sync::Arc;

use regex::Regex;
use serde::{Deserialize, Serialize};

use crate::capture::Capture;
use crate::error::{Error, Result};
use crate::filter::{Matcher, Query, Stage};

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

/// Which messages are held for review. Patterns are regexes; unset means "any". A message is
/// held when every one that is set matches.
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
    /// A query in the history filter language (`history list --filter`) the message's exchange
    /// must match: the request for a held request, the request sent and the response for a held
    /// response, the handshake request for a WebSocket message. Fields not known yet when the
    /// message is held are refused when the settings are compiled.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub filter: Option<String>,
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
            filter: None,
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
    filter: Option<Arc<Matcher>>,
}

impl InterceptSettings {
    pub fn compile(&self) -> Result<CompiledIntercept> {
        let re = |p: &Option<String>, what: &str| -> Result<Option<Regex>> {
            p.as_deref()
                .map(|p| Regex::new(p).map_err(|e| Error::InvalidInput(format!("intercept {what} pattern: {e}"))))
                .transpose()
        };
        let filter = match self.filter.as_deref().filter(|f| !f.trim().is_empty()) {
            Some(text) => {
                let query = Query::parse(text)?;
                query.check_known(self.filter_stage())?;
                Some(Arc::new(Matcher::new(&query)?))
            }
            None => None,
        };
        Ok(CompiledIntercept {
            filter,
            host: re(&self.host, "host")?,
            path: re(&self.path, "path")?,
            method: re(&self.method.as_ref().map(|m| format!("(?i)^(?:{m})$")), "method")?,
            settings: self.clone(),
        })
    }

    /// What the filter may ask about: only what a request carries when requests or WebSocket
    /// messages are held (those are matched by their handshake request), the response too when
    /// only responses are.
    fn filter_stage(&self) -> Stage {
        match self.requests || self.ws_to_server || self.ws_to_client {
            true => Stage::Request,
            false => Stage::Response,
        }
    }
}

impl CompiledIntercept {
    /// Whether a message for this request should be held. `exchange` is the request (and, for a
    /// response, the response) as the filter sees it; it is made only when a filter is set and
    /// everything else matches.
    pub fn matches<'c>(
        &self,
        response: bool,
        method: &str,
        host: &str,
        path: &str,
        exchange: impl FnOnce() -> Cow<'c, Capture>,
    ) -> bool {
        let s = &self.settings;
        s.enabled
            && (if response { s.responses } else { s.requests })
            && self.host.as_ref().is_none_or(|r| r.is_match(host))
            && self.path.as_ref().is_none_or(|r| r.is_match(path))
            && self.method.as_ref().is_none_or(|r| r.is_match(method))
            && self.filter.as_ref().is_none_or(|m| filter_matches(m, &exchange()))
    }

    /// Whether a WebSocket data message going `direction` on a connection upgraded from a
    /// request to `host` and `path` should be held. The method filter doesn't apply. The filter
    /// is asked about the handshake request through `handshake`, which may keep the answer for
    /// the connection while the filter is the same one.
    pub fn matches_ws(
        &self,
        direction: crate::ws::Direction,
        host: &str,
        path: &str,
        handshake: impl FnOnce(&Arc<Matcher>) -> bool,
    ) -> bool {
        let s = &self.settings;
        s.enabled
            && match direction {
                crate::ws::Direction::ToServer => s.ws_to_server,
                crate::ws::Direction::ToClient => s.ws_to_client,
            }
            && self.host.as_ref().is_none_or(|r| r.is_match(host))
            && self.path.as_ref().is_none_or(|r| r.is_match(path))
            && self.filter.as_ref().is_none_or(handshake)
    }
}

/// Whether `exchange` matches the intercept's filter. A filter that can't be evaluated (it
/// parsed and was checked, so this isn't expected) holds the message: the person asked to see
/// what they might want to change, and a held message is forwarded on its timeout anyway.
pub fn filter_matches(m: &Matcher, exchange: &Capture) -> bool {
    m.matches(exchange).unwrap_or_else(|e| {
        eprintln!("brainproxy: intercept filter not evaluated, message held: {e}");
        true
    })
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
        let none = || unreachable!("no filter, no exchange made");
        assert!(i.matches(false, "POST", "h", "/", none));
        assert!(!i.matches(false, "GET", "h", "/", none));
        assert!(!i.matches(true, "POST", "h", "/", none));
    }

    fn exchange(request: &str, response: Option<&str>) -> Capture {
        let target = crate::http::Target { scheme: "https".into(), host: "app.test".into(), port: 443 };
        Capture::new("proxy", &target, request.as_bytes(), response.map(str::as_bytes), Some(5), None)
    }

    fn owned(request: &str, response: Option<&str>) -> Cow<'static, Capture> {
        Cow::Owned(exchange(request, response))
    }

    #[test]
    fn intercept_filter() {
        let post = "POST /api/login HTTP/1.1\r\nHost: app.test\r\nContent-Length: 6\r\n\r\nuser=a";
        let get = "GET /static/app.js HTTP/1.1\r\nHost: app.test\r\n\r\n";
        let i = InterceptSettings {
            enabled: true,
            filter: Some("req.body:user NOT path:/static".into()),
            ..Default::default()
        }
        .compile()
        .unwrap();
        assert!(i.matches(false, "POST", "app.test", "/api/login", || owned(post, None)));
        assert!(!i.matches(false, "GET", "app.test", "/static/app.js", || owned(get, None)));
        // The other settings still apply, and the exchange isn't made when they don't match.
        let i = InterceptSettings { method: Some("PUT".into()), ..i.settings.clone() }.compile().unwrap();
        assert!(!i.matches(false, "POST", "app.test", "/api/login", || unreachable!()));

        // Response fields: only when only responses are held.
        let held = |requests, responses, ws_to_server, ws_to_client| {
            InterceptSettings {
                enabled: true,
                requests,
                responses,
                ws_to_server,
                ws_to_client,
                filter: Some("status:5xx".into()),
                ..Default::default()
            }
            .compile()
        };
        for refused in [
            held(true, false, false, false),
            held(true, true, false, false),
            held(false, true, true, false),
            held(false, true, false, true),
        ] {
            let e = refused.unwrap_err().to_string();
            assert!(e.contains("status isn't known when a request or a WebSocket message is held"), "{e}");
        }
        let i = held(false, true, false, false).unwrap();
        let boom = "HTTP/1.1 503 Busy\r\nContent-Length: 0\r\n\r\n";
        let ok = "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n";
        assert!(i.matches(true, "GET", "app.test", "/", || owned(get, Some(boom))));
        assert!(!i.matches(true, "GET", "app.test", "/", || owned(get, Some(ok))));

        // Never known in flight, at any stage; an empty filter is none.
        let e = InterceptSettings { filter: Some("id>3".into()), ..Default::default() }.compile().unwrap_err();
        assert!(e.to_string().contains("history id"), "{e}");
        let e = InterceptSettings { filter: Some("status:".into()), ..Default::default() }.compile().unwrap_err();
        assert!(e.to_string().contains("needs a value"), "{e}");
        let i = InterceptSettings { enabled: true, filter: Some("  ".into()), ..Default::default() }.compile().unwrap();
        assert!(i.matches(false, "GET", "h", "/", || unreachable!()));
    }

    #[test]
    fn intercept_filter_on_websocket_messages() {
        use crate::ws::Direction;
        let i = InterceptSettings {
            enabled: true,
            requests: false,
            ws_to_server: true,
            filter: Some("path:/chat".into()),
            ..Default::default()
        }
        .compile()
        .unwrap();
        let chat = "GET /chat HTTP/1.1\r\nHost: app.test\r\nUpgrade: websocket\r\n\r\n";
        let ask = |request: &'static str| move |m: &Arc<Matcher>| filter_matches(m, &exchange(request, None));
        assert!(i.matches_ws(Direction::ToServer, "app.test", "/chat", ask(chat)));
        assert!(!i.matches_ws(
            Direction::ToServer,
            "app.test",
            "/feed",
            ask("GET /feed HTTP/1.1\r\nHost: app.test\r\n\r\n")
        ));
        assert!(!i.matches_ws(Direction::ToClient, "app.test", "/chat", |_| unreachable!()));
    }
}
