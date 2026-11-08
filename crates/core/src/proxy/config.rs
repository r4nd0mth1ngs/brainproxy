//! Proxy settings: scope, match-and-replace rules, and interception. They live in
//! the project database so the CLI can change them while a proxy is running; the
//! proxy picks up changes within a fraction of a second.

use regex::bytes::Regex as BytesRegex;
use regex::Regex;
use serde::{Deserialize, Serialize};

use crate::capture::decode_body_fully;
use crate::error::{Error, Result};
use crate::http::request::split_head_body;
use crate::http::response::dechunk;
use crate::http::{parse_response_head, RawRequest};

pub const SCOPE_KEY: &str = "scope";
pub const RULES_KEY: &str = "rules";
/// The meta key of the last match-and-replace rule id handed out: an id is never used twice,
/// so the `edited_by` of an old history row can't come to name another rule.
pub const RULE_IDS: &str = "rule_ids";
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
    /// Who added it or last enabled it: gui, cli or mcp (None: before brainproxy kept it). A
    /// request it changes records this in its history row's `edited_by`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub origin: Option<String>,
    /// Added (or last enabled) with `--host-header-test`: a Host it puts in a request is meant,
    /// so the proxy sends it even when an agent added the rule.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub host_header_test: bool,
}

fn yes() -> bool {
    true
}

#[derive(Debug, Clone)]
pub struct CompiledRule {
    pub id: u32,
    pub origin: Option<String>,
    /// See [`Rule::host_header_test`].
    pub host_header_test: bool,
    location: RuleLocation,
    text: Option<Regex>,
    bytes: Option<BytesRegex>,
    replace: String,
}

/// Checks a rule's pattern whether or not it is enabled: a bad one saved disabled would
/// stop the proxy loading any settings once enabled.
pub fn validate_rule(rule: &Rule) -> Result<()> {
    // A line break in a request line or header would start another header (a Host, say).
    let head = matches!(rule.location, RuleLocation::RequestLine | RuleLocation::RequestHeader);
    if head && rule.replace.contains(['\r', '\n', '\0']) {
        return Err(Error::InvalidInput(
            "a request-line or request-header replacement can't hold a line break or NUL".into(),
        ));
    }
    compile_rules(std::slice::from_ref(&Rule { enabled: true, ..rule.clone() })).map(|_| ())
}

pub fn compile_rules(rules: &[Rule]) -> Result<Vec<CompiledRule>> {
    rules
        .iter()
        .filter(|r| r.enabled)
        .map(|r| {
            let body = matches!(r.location, RuleLocation::RequestBody | RuleLocation::ResponseBody);
            let bad = |e: regex::Error| Error::InvalidInput(format!("rule {} pattern: {e}", r.id));
            Ok(CompiledRule {
                id: r.id,
                origin: r.origin.clone(),
                host_header_test: r.host_header_test,
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
    apply_request_rules_traced(rules, req).0
}

/// Applies request rules, and says which of them changed the request, so its record can say
/// who edited it.
pub fn apply_request_rules_traced(rules: &[CompiledRule], req: Vec<u8>) -> (Vec<u8>, Vec<&CompiledRule>) {
    let active: Vec<&CompiledRule> = rules.iter().filter(|r| r.location.is_request()).collect();
    if active.is_empty() {
        return (req, Vec::new());
    }
    let (head, raw_body) = split_head_body(&req);
    let (mut first, mut headers) = split_lines(head);
    // Body rules see the data, not the chunk framing (which they would break).
    let chunked = headers.iter().any(|h| {
        h.split_once(':').is_some_and(|(k, v)| {
            k.trim().eq_ignore_ascii_case("transfer-encoding") && v.to_ascii_lowercase().contains("chunked")
        })
    });
    let has_body_rule = active.iter().any(|r| r.location == RuleLocation::RequestBody && r.bytes.is_some());
    let mut body = if chunked && has_body_rule { dechunk(raw_body) } else { raw_body.to_vec() };
    let mut body_changed = false;
    let mut changed_by = Vec::new();
    for rule in active {
        let changed = match rule.location {
            RuleLocation::RequestLine => rule.text.as_ref().is_some_and(|re| {
                let new = re.replace_all(&first, rule.replace.as_str()).into_owned();
                std::mem::replace(&mut first, new) != first
            }),
            RuleLocation::RequestHeader => {
                let before = headers.clone();
                apply_header_rule(rule, &mut headers);
                before != headers
            }
            RuleLocation::RequestBody => rule.bytes.as_ref().is_some_and(|re| {
                let new = re.replace_all(&body, rule.replace.as_bytes()).into_owned();
                std::mem::replace(&mut body, new) != body
            }),
            _ => false,
        };
        if changed {
            body_changed |= rule.location == RuleLocation::RequestBody;
            changed_by.push(rule);
        }
    }
    if !body_changed {
        return (join(&first, &headers, if chunked && has_body_rule { raw_body } else { &body }), changed_by);
    }
    if chunked {
        // Only the chunks were taken off: a Content-Encoding still applies to the body.
        reframe(&mut headers, body.len(), false);
        return (join(&first, &headers, &body), changed_by);
    }
    (RawRequest::from_bytes(join(&first, &headers, &body)).update_content_length().into_bytes(), changed_by)
}

/// Drops the framing headers of a de-chunked body (and with `decoded`, its coding header)
/// and gives its length.
fn reframe(headers: &mut Vec<String>, len: usize, decoded: bool) {
    let drop: &[&str] = if decoded {
        &["content-length", "transfer-encoding", "content-encoding"]
    } else {
        &["content-length", "transfer-encoding"]
    };
    headers.retain(|h| {
        let name = h.split(':').next().unwrap_or("").trim();
        !drop.iter().any(|n| name.eq_ignore_ascii_case(n))
    });
    headers.push(format!("Content-Length: {len}"));
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
    // Decoded once, when a body rule needs it; None if it can't be decoded (then body rules
    // leave it alone: without its Content-Encoding the client couldn't read it).
    let mut decoded: Option<Option<Vec<u8>>> = None;
    let mut body_changed = false;
    for rule in active {
        match rule.location {
            RuleLocation::ResponseHeader => apply_header_rule(rule, &mut headers),
            RuleLocation::ResponseBody => {
                if let Some(re) = &rule.bytes {
                    let current = decoded.get_or_insert_with(|| decode_body_fully(&parsed.headers, raw_body));
                    if let Some(current) = current {
                        let new = re.replace_all(current, rule.replace.as_bytes()).into_owned();
                        body_changed |= new != *current;
                        *current = new;
                    }
                }
            }
            _ => {}
        }
    }
    let body = match decoded.flatten().filter(|_| body_changed) {
        Some(b) => {
            reframe(&mut headers, b.len(), true);
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

    fn rule(id: u32, loc: RuleLocation, pattern: &str, replace: &str) -> Rule {
        Rule {
            id,
            location: loc,
            pattern: pattern.into(),
            replace: replace.into(),
            enabled: true,
            comment: None,
            origin: None,
            host_header_test: false,
        }
    }

    #[test]
    fn a_head_replacement_cant_hold_a_line_break() {
        for loc in [RuleLocation::RequestLine, RuleLocation::RequestHeader] {
            for bad in ["X-A: a\r\nHost: e.test", "a\nb", "a\0b"] {
                assert!(validate_rule(&rule(1, loc, "^X", bad)).is_err(), "{bad:?}");
            }
        }
        // A body can hold one.
        validate_rule(&rule(1, RuleLocation::RequestBody, "x", "a\r\nb")).unwrap();
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
    fn request_rules_say_which_of_them_changed_the_request() {
        let mut agents = rule(2, RuleLocation::RequestHeader, "^X-Role: user$", "X-Role: admin");
        agents.origin = Some("mcp".into());
        let rules = compile_rules(&[
            rule(1, RuleLocation::RequestBody, "never-there", "x"),
            agents,
            rule(3, RuleLocation::RequestLine, "^GET ", "GET "),
        ])
        .unwrap();
        let (out, changed) = apply_request_rules_traced(&rules, b"GET /p HTTP/1.1\r\nX-Role: user\r\n\r\n".to_vec());
        assert_eq!(String::from_utf8(out).unwrap(), "GET /p HTTP/1.1\r\nX-Role: admin\r\n\r\n");
        // A rule that matched but left the bytes as they were didn't change it.
        let changed: Vec<_> = changed.iter().map(|r| (r.id, r.origin.as_deref())).collect();
        assert_eq!(changed, [(2, Some("mcp"))]);
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
    fn request_body_rule_on_a_chunked_body_reframes_it() {
        let rules = compile_rules(&[rule(1, RuleLocation::RequestBody, "role=user", "role=admin")]).unwrap();
        let req = b"POST /p HTTP/1.1\r\nHost: h\r\nTransfer-Encoding: chunked\r\n\r\n9\r\nrole=user\r\n0\r\n\r\n";
        let out = apply_request_rules(&rules, req.to_vec());
        assert_eq!(
            String::from_utf8(out).unwrap(),
            "POST /p HTTP/1.1\r\nHost: h\r\nContent-Length: 10\r\n\r\nrole=admin"
        );
        // A coded body is only de-chunked, so it keeps its Content-Encoding.
        let coded = b"POST /p HTTP/1.1\r\nContent-Encoding: x-test\r\nTransfer-Encoding: chunked\r\n\r\n9\r\nrole=user\r\n0\r\n\r\n";
        assert_eq!(
            String::from_utf8(apply_request_rules(&rules, coded.to_vec())).unwrap(),
            "POST /p HTTP/1.1\r\nContent-Encoding: x-test\r\nContent-Length: 10\r\n\r\nrole=admin"
        );
        // No match: sent as it came, chunks and all.
        let rules = compile_rules(&[rule(1, RuleLocation::RequestBody, "nothing", "x")]).unwrap();
        assert_eq!(apply_request_rules(&rules, req.to_vec()), req.to_vec());
    }

    #[test]
    fn response_body_rules_leave_bodies_they_cannot_decode_or_do_not_change() {
        let rules = compile_rules(&[rule(1, RuleLocation::ResponseBody, "a", "b")]).unwrap();
        let zstd = b"HTTP/1.1 200 OK\r\nContent-Encoding: zstd\r\nContent-Length: 4\r\n\r\n(\xb5/\xfd".to_vec();
        assert_eq!(apply_response_rules(&rules, zstd.clone()), zstd);
        let head = b"HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\nContent-Length: 120\r\n\r\n".to_vec();
        assert_eq!(apply_response_rules(&rules, head.clone()), head);
    }

    #[test]
    fn disabled_rules_are_validated_too() {
        let mut r = rule(1, RuleLocation::RequestHeader, "(", "x");
        r.enabled = false;
        assert!(compile_rules(std::slice::from_ref(&r)).is_ok());
        assert!(validate_rule(&r).is_err());
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
