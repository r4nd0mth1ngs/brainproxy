//! Proxy settings: scope, match-and-replace rules, and interception. They live in
//! the project database so the CLI can change them while a proxy is running; the
//! proxy picks up changes within a fraction of a second.

use regex::bytes::Regex as BytesRegex;
use regex::Regex;
use serde::{Deserialize, Serialize};

use crate::capture::decode_body;
use crate::error::{Error, Result};
use crate::http::request::split_head_body;
use crate::http::{parse_response_head, RawRequest};

pub const SCOPE_KEY: &str = "scope";
pub const RULES_KEY: &str = "rules";
pub const INTERCEPT_KEY: &str = "intercept";

/// Host-based scope. Patterns are regexes matched against the host name.
/// An empty include list means every host is in scope.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct Scope {
    #[serde(default)]
    pub include: Vec<String>,
    #[serde(default)]
    pub exclude: Vec<String>,
    /// Record out-of-scope traffic too. Out-of-scope HTTPS is always tunneled
    /// without interception.
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

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum RuleLocation {
    RequestLine,
    RequestHeader,
    RequestBody,
    ResponseHeader,
    ResponseBody,
}

impl RuleLocation {
    pub const ALL: &'static [&'static str] =
        &["request-line", "request-header", "request-body", "response-header", "response-body"];

    pub fn parse(s: &str) -> Result<Self> {
        serde_json::from_value(serde_json::Value::String(s.to_string()))
            .map_err(|_| Error::InvalidInput(format!("unknown rule location {s:?}; valid: {}", Self::ALL.join(", "))))
    }

    fn is_request(self) -> bool {
        matches!(self, Self::RequestLine | Self::RequestHeader | Self::RequestBody)
    }
}

/// A match-and-replace rule. `pattern` is a regex; `replace` may use `$1`-style
/// group references. For header locations each header line is matched on its
/// own; an empty pattern adds `replace` as a new header, and a line replaced
/// with nothing is removed.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Rule {
    pub id: u32,
    pub location: RuleLocation,
    pub pattern: String,
    #[serde(default)]
    pub replace: String,
    #[serde(default = "yes")]
    pub enabled: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub comment: Option<String>,
}

fn yes() -> bool {
    true
}

#[derive(Debug, Clone)]
pub struct CompiledRule {
    location: RuleLocation,
    text: Option<Regex>,
    bytes: Option<BytesRegex>,
    replace: String,
}

pub fn compile_rules(rules: &[Rule]) -> Result<Vec<CompiledRule>> {
    rules
        .iter()
        .filter(|r| r.enabled)
        .map(|r| {
            let body = matches!(r.location, RuleLocation::RequestBody | RuleLocation::ResponseBody);
            let bad = |e: regex::Error| Error::InvalidInput(format!("rule {} pattern: {e}", r.id));
            Ok(CompiledRule {
                location: r.location,
                text: if body || r.pattern.is_empty() { None } else { Some(Regex::new(&r.pattern).map_err(bad)?) },
                bytes: if body && !r.pattern.is_empty() {
                    Some(BytesRegex::new(&r.pattern).map_err(bad)?)
                } else {
                    None
                },
                replace: r.replace.clone(),
            })
        })
        .collect()
}

/// Applies request rules. Returns the request unchanged when nothing matched.
pub fn apply_request_rules(rules: &[CompiledRule], req: Vec<u8>) -> Vec<u8> {
    let active: Vec<&CompiledRule> = rules.iter().filter(|r| r.location.is_request()).collect();
    if active.is_empty() {
        return req;
    }
    let (head, body) = split_head_body(&req);
    let (mut first, mut headers) = split_lines(head);
    let mut body = body.to_vec();
    let mut body_changed = false;
    for rule in active {
        match rule.location {
            RuleLocation::RequestLine => {
                if let Some(re) = &rule.text {
                    first = re.replace_all(&first, rule.replace.as_str()).into_owned();
                }
            }
            RuleLocation::RequestHeader => apply_header_rule(rule, &mut headers),
            RuleLocation::RequestBody => {
                if let Some(re) = &rule.bytes {
                    let new = re.replace_all(&body, rule.replace.as_bytes()).into_owned();
                    body_changed |= new != body;
                    body = new;
                }
            }
            _ => {}
        }
    }
    let out = join(&first, &headers, &body);
    if body_changed {
        RawRequest::from_bytes(out).update_content_length().into_bytes()
    } else {
        out
    }
}

/// Applies response rules to the final response (after any 1xx interim
/// responses). Body rules decode the body first and re-frame it with a
/// Content-Length.
pub fn apply_response_rules(rules: &[CompiledRule], resp: Vec<u8>) -> Vec<u8> {
    let active: Vec<&CompiledRule> = rules.iter().filter(|r| !r.location.is_request()).collect();
    if active.is_empty() {
        return resp;
    }
    let final_start = final_response_offset(&resp);
    let (prefix, rest) = resp.split_at(final_start);
    let Ok(parsed) = parse_response_head(rest) else { return resp };
    let (head, raw_body) = split_head_body(rest);
    let (first, mut headers) = split_lines(head);
    let mut body: Option<Vec<u8>> = None;
    for rule in active {
        match rule.location {
            RuleLocation::ResponseHeader => apply_header_rule(rule, &mut headers),
            RuleLocation::ResponseBody => {
                if let Some(re) = &rule.bytes {
                    let current = body.take().unwrap_or_else(|| decode_body(&parsed.headers, raw_body));
                    body = Some(re.replace_all(&current, rule.replace.as_bytes()).into_owned());
                }
            }
            _ => {}
        }
    }
    let body = match body {
        Some(b) => {
            headers.retain(|h| {
                let name = h.split(':').next().unwrap_or("").trim();
                !["content-length", "transfer-encoding", "content-encoding"]
                    .iter()
                    .any(|n| name.eq_ignore_ascii_case(n))
            });
            headers.push(format!("Content-Length: {}", b.len()));
            b
        }
        None => raw_body.to_vec(),
    };
    let mut out = prefix.to_vec();
    out.extend(join(&first, &headers, &body));
    out
}

fn apply_header_rule(rule: &CompiledRule, headers: &mut Vec<String>) {
    match &rule.text {
        None => {
            if !rule.replace.is_empty() {
                headers.push(rule.replace.clone());
            }
        }
        Some(re) => {
            *headers = headers
                .iter()
                .map(|h| re.replace_all(h, rule.replace.as_str()).into_owned())
                .filter(|h| !h.is_empty())
                .collect();
        }
    }
}

fn final_response_offset(resp: &[u8]) -> usize {
    let mut start = 0;
    while let Ok(h) = parse_response_head(&resp[start..]) {
        if (100..200).contains(&h.status) && h.status != 101 {
            let (head, _) = split_head_body(&resp[start..]);
            start += head.len();
        } else {
            break;
        }
    }
    start
}

fn split_lines(head: &[u8]) -> (String, Vec<String>) {
    let text = String::from_utf8_lossy(head);
    let mut lines = text.trim_end_matches("\r\n").split("\r\n").map(str::to_string);
    let first = lines.next().unwrap_or_default();
    (first, lines.filter(|l| !l.is_empty()).collect())
}

fn join(first: &str, headers: &[String], body: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(first.len() + body.len() + 64 * (headers.len() + 1));
    out.extend_from_slice(first.as_bytes());
    out.extend_from_slice(b"\r\n");
    for h in headers {
        out.extend_from_slice(h.as_bytes());
        out.extend_from_slice(b"\r\n");
    }
    out.extend_from_slice(b"\r\n");
    out.extend_from_slice(body);
    out
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

    fn rule(id: u32, loc: RuleLocation, pattern: &str, replace: &str) -> Rule {
        Rule { id, location: loc, pattern: pattern.into(), replace: replace.into(), enabled: true, comment: None }
    }

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
    fn request_rules() {
        let rules = compile_rules(&[
            rule(1, RuleLocation::RequestHeader, "", "X-Added: 1"),
            rule(2, RuleLocation::RequestHeader, "(?i)^user-agent:.*$", ""),
            rule(3, RuleLocation::RequestLine, "^GET ", "POST "),
            rule(4, RuleLocation::RequestBody, "role=user", "role=admin"),
        ])
        .unwrap();
        let out = apply_request_rules(
            &rules,
            b"GET /p HTTP/1.1\r\nHost: h\r\nUser-Agent: x\r\nContent-Length: 9\r\n\r\nrole=user".to_vec(),
        );
        assert_eq!(
            String::from_utf8(out).unwrap(),
            "POST /p HTTP/1.1\r\nHost: h\r\nContent-Length: 10\r\nX-Added: 1\r\n\r\nrole=admin"
        );
    }

    #[test]
    fn response_body_rule_reframes() {
        let rules = compile_rules(&[rule(1, RuleLocation::ResponseBody, "false", "true")]).unwrap();
        let out = apply_response_rules(
            &rules,
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n10\r\n{\"admin\": false}\r\n0\r\n\r\n".to_vec(),
        );
        assert_eq!(String::from_utf8(out).unwrap(), "HTTP/1.1 200 OK\r\nContent-Length: 15\r\n\r\n{\"admin\": true}");
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
