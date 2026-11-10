//! Match-and-replace rules. A rule names a place in a message (its location, and for a header
//! or query parameter a name), what to match there (a regex, literal text, or the whole value),
//! and what to write instead. It applies to the traffic of the engines it lists (the proxy
//! unless it says otherwise) and, with a host condition, only to targets whose host matches.
//!
//! Rules live in the project's settings ([`RULES_KEY`]). The proxy reloads them as they change;
//! `send`, the fuzzer and the active scanner read them when a run starts ([`RuleSet::load`]).
//! Nothing here opens a connection: [`RuleSet::request`] and [`RuleSet::response`] only rewrite
//! bytes, which is also all `rules test` does.

use std::sync::Arc;

use regex::bytes::Regex as BytesRegex;
use regex::Regex;
use serde::{Deserialize, Serialize};

use crate::capture::decode_body_fully;
use crate::error::{Error, Result};
use crate::http::client::SendOptions;
use crate::http::request::split_head_body;
use crate::http::response::dechunk;
use crate::http::{parse_response_head, RawRequest, Target};
use crate::provenance::Edit;
use crate::store::Store;

pub const RULES_KEY: &str = "rules";
/// The meta key of the last match-and-replace rule id handed out: an id is never used twice,
/// so the `edited_by` of an old history row can't come to name another rule.
pub const RULE_IDS: &str = "rule_ids";

/// The place in a message a rule works on.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum RuleLocation {
    /// The request line as one string.
    RequestLine,
    /// Each request header line (`Name: value`), or with a name the value of that header.
    RequestHeader,
    RequestBody,
    /// Each response header line, or with a name the value of that header.
    ResponseHeader,
    ResponseBody,
    /// The request method.
    Method,
    /// The request target's path (without the query string).
    Path,
    /// The value of the query parameter the rule names, as written in the request line.
    QueryParam,
    /// The response's status code.
    Status,
    /// The payload of a WebSocket data message the proxy relays.
    WsMessage,
}

impl RuleLocation {
    pub const ALL: &'static [&'static str] = &[
        "request-line",
        "request-header",
        "request-body",
        "response-header",
        "response-body",
        "method",
        "path",
        "query-param",
        "status",
        "ws-message",
    ];

    pub fn parse(s: &str) -> Result<Self> {
        serde_json::from_value(serde_json::Value::String(s.to_string()))
            .map_err(|_| Error::InvalidInput(format!("unknown rule location {s:?}; valid: {}", Self::ALL.join(", "))))
    }

    pub fn name(self) -> &'static str {
        Self::ALL[self as usize]
    }

    fn is_request(self) -> bool {
        matches!(
            self,
            Self::RequestLine | Self::RequestHeader | Self::RequestBody | Self::Method | Self::Path | Self::QueryParam
        )
    }

    fn is_response(self) -> bool {
        matches!(self, Self::ResponseHeader | Self::ResponseBody | Self::Status)
    }

    /// In the request's head, where a line break would start another header.
    fn request_head(self) -> bool {
        self.is_request() && self != Self::RequestBody
    }

    fn is_header(self) -> bool {
        matches!(self, Self::RequestHeader | Self::ResponseHeader)
    }
}

/// Whose traffic a rule applies to.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum Engine {
    /// Requests and responses the proxy relays.
    Proxy,
    /// `send` (the app's Replay), a race included.
    Send,
    /// Fuzz runs.
    Fuzz,
    /// Active scans and declarative checks.
    Scan,
    /// WebSocket messages the proxy relays from the client.
    WsToServer,
    /// WebSocket messages the proxy relays from the server.
    WsToClient,
}

impl Engine {
    pub const ALL: &'static [&'static str] = &["proxy", "send", "fuzz", "scan", "ws-to-server", "ws-to-client"];

    pub fn parse(s: &str) -> Result<Self> {
        serde_json::from_value(serde_json::Value::String(s.trim().to_string()))
            .map_err(|_| Error::InvalidInput(format!("unknown engine {s:?}; valid: {}", Self::ALL.join(", "))))
    }

    pub fn name(self) -> &'static str {
        Self::ALL[self as usize]
    }

    pub fn is_ws(self) -> bool {
        matches!(self, Self::WsToServer | Self::WsToClient)
    }
}

/// How a rule's `pattern` is read.
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum MatchKind {
    /// A regex; the replacement may use `$1`-style group references.
    #[default]
    Regex,
    /// Plain text; each occurrence is replaced with the replacement as written.
    Literal,
    /// The whole value, when it equals the pattern, is replaced with the replacement as written.
    Whole,
}

impl MatchKind {
    pub const ALL: &'static [&'static str] = &["regex", "literal", "whole"];

    pub fn parse(s: &str) -> Result<Self> {
        serde_json::from_value(serde_json::Value::String(s.to_string()))
            .map_err(|_| Error::InvalidInput(format!("unknown match kind {s:?}; valid: {}", Self::ALL.join(", "))))
    }

    fn is_regex(&self) -> bool {
        *self == Self::Regex
    }
}

/// What a rule does to the header or query parameter it names.
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum RuleAction {
    /// Rewrite its value where the pattern matches; with no pattern, set the value, adding the
    /// header or parameter if the message has none.
    #[default]
    Set,
    /// Add another one, whatever the message holds.
    Add,
    /// Remove it (with a pattern: only where the value matches).
    Remove,
}

impl RuleAction {
    pub const ALL: &'static [&'static str] = &["set", "add", "remove"];

    pub fn parse(s: &str) -> Result<Self> {
        serde_json::from_value(serde_json::Value::String(s.to_string()))
            .map_err(|_| Error::InvalidInput(format!("unknown rule action {s:?}; valid: {}", Self::ALL.join(", "))))
    }
}

/// What makes a rule's replacement. One kind so far; another (a script, say) is a variant here,
/// a field of its own on [`Rule`] if it needs more than `replace`, and an arm in [`Replacer`].
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum ReplaceKind {
    /// `replace` as text (with a regex, `$1`-style group references).
    #[default]
    Text,
}

impl ReplaceKind {
    fn is_text(&self) -> bool {
        *self == Self::Text
    }
}

/// A match-and-replace rule. `pattern` is read as `matcher` says (a regex unless it says
/// otherwise); `replace` may use `$1`-style group references with a regex.
///
/// Without a `name`, a header location matches each header line on its own; an empty pattern
/// adds `replace` as a new header, and a line replaced with nothing is removed. With a `name`
/// (a header's, or a query parameter's) the rule works on that header's or parameter's value
/// and does what `action` says. Elsewhere an empty pattern stands for the whole value, except
/// with a regex on the request line or a body, where it matches nothing (as it always did).
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
    /// so it is sent even when an agent added the rule.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub host_header_test: bool,
    /// How `pattern` is read.
    #[serde(default, skip_serializing_if = "MatchKind::is_regex")]
    pub matcher: MatchKind,
    /// The header or query parameter the rule works on.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// What to do with the named header or parameter (set, unless it says otherwise).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub action: Option<RuleAction>,
    /// The engines whose traffic it applies to. Empty: the proxy (for `ws-message`, messages
    /// both ways), as every rule did before a rule could say.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub applies_to: Vec<Engine>,
    /// Regex on the target's host (case-insensitive): the rule applies only where it matches.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host: Option<String>,
    /// What makes the replacement.
    #[serde(default, skip_serializing_if = "ReplaceKind::is_text")]
    pub replacer: ReplaceKind,
}

fn yes() -> bool {
    true
}

impl Rule {
    /// An enabled regex rule for the proxy, as `rules add --location --match --replace` makes.
    pub fn new(id: u32, location: RuleLocation, pattern: &str, replace: &str) -> Self {
        Rule {
            id,
            location,
            pattern: pattern.into(),
            replace: replace.into(),
            enabled: true,
            comment: None,
            origin: None,
            host_header_test: false,
            matcher: MatchKind::Regex,
            name: None,
            action: None,
            applies_to: Vec::new(),
            host: None,
            replacer: ReplaceKind::Text,
        }
    }

    /// The engines it applies to: the ones it lists, else its location's default.
    pub fn engines(&self) -> Vec<Engine> {
        match (self.applies_to.is_empty(), self.location) {
            (false, _) => self.applies_to.clone(),
            (true, RuleLocation::WsMessage) => vec![Engine::WsToServer, Engine::WsToClient],
            (true, _) => vec![Engine::Proxy],
        }
    }
}

/// What a rule's pattern matches in the value its location picks.
#[derive(Debug, Clone)]
enum Matcher {
    /// The whole value, whatever it is.
    Any,
    Regex(BytesRegex),
    /// Each occurrence of a text (the regex is that text, escaped).
    Literal(BytesRegex),
    /// The whole value, when it is exactly this.
    Whole(Vec<u8>),
}

/// One match, as a replacer sees it.
struct Matched<'a> {
    /// The bytes matched.
    #[allow(dead_code)] // A replacer that computes its text reads what was matched.
    found: &'a [u8],
    /// The regex's groups, for a regex match.
    groups: Option<&'a regex::bytes::Captures<'a>>,
}

/// What a rule writes in place of a match: see [`ReplaceKind`].
#[derive(Debug, Clone)]
enum Replacer {
    Text(String),
}

impl Replacer {
    fn of(rule: &Rule) -> Self {
        match rule.replacer {
            ReplaceKind::Text => Self::Text(rule.replace.clone()),
        }
    }

    /// Appends the replacement for `m` to `out`.
    fn write(&self, m: &Matched<'_>, out: &mut Vec<u8>) {
        match self {
            Self::Text(text) => match m.groups {
                Some(groups) => groups.expand(text.as_bytes(), out),
                None => out.extend_from_slice(text.as_bytes()),
            },
        }
    }

    /// The value of a header or parameter the rule adds, where there is nothing to match.
    fn fresh(&self) -> String {
        let mut out = Vec::new();
        self.write(&Matched { found: b"", groups: None }, &mut out);
        String::from_utf8_lossy(&out).into_owned()
    }
}

impl Matcher {
    fn matches(&self, value: &[u8]) -> bool {
        match self {
            Self::Any => true,
            Self::Regex(re) | Self::Literal(re) => re.is_match(value),
            Self::Whole(whole) => value == whole.as_slice(),
        }
    }

    /// `value` with each match replaced by what `replacer` writes; None when nothing matched.
    fn rewrite(&self, replacer: &Replacer, value: &[u8]) -> Option<Vec<u8>> {
        let mut out = Vec::new();
        match self {
            Self::Any => replacer.write(&Matched { found: value, groups: None }, &mut out),
            Self::Whole(whole) => {
                if value != whole.as_slice() {
                    return None;
                }
                replacer.write(&Matched { found: value, groups: None }, &mut out);
            }
            Self::Regex(re) | Self::Literal(re) => {
                let expand = matches!(self, Self::Regex(_));
                let mut last = 0;
                let mut any = false;
                for groups in re.captures_iter(value) {
                    let m = groups.get(0).expect("group 0 is the match");
                    any = true;
                    out.extend_from_slice(&value[last..m.start()]);
                    replacer.write(&Matched { found: m.as_bytes(), groups: expand.then_some(&groups) }, &mut out);
                    last = m.end();
                }
                if !any {
                    return None;
                }
                out.extend_from_slice(&value[last..]);
            }
        }
        Some(out)
    }
}

#[derive(Debug, Clone)]
pub struct CompiledRule {
    pub id: u32,
    pub origin: Option<String>,
    /// See [`Rule::host_header_test`].
    pub host_header_test: bool,
    location: RuleLocation,
    name: Option<String>,
    action: RuleAction,
    /// None: nothing to match (a header rule then adds a line; others do nothing).
    matcher: Option<Matcher>,
    replacer: Replacer,
    host: Option<Regex>,
    engines: Vec<Engine>,
}

impl CompiledRule {
    fn applies(&self, engine: Engine, host: &str) -> bool {
        self.engines.contains(&engine) && self.host.as_ref().is_none_or(|re| re.is_match(host))
    }

    /// `value` rewritten, or None when the rule doesn't match it.
    fn rewrite(&self, value: &[u8]) -> Option<Vec<u8>> {
        self.matcher.as_ref()?.rewrite(&self.replacer, value)
    }

    /// As [`CompiledRule::rewrite`], for a part of the head.
    fn rewrite_str(&self, value: &str) -> Option<String> {
        self.rewrite(value.as_bytes()).map(|b| String::from_utf8_lossy(&b).into_owned())
    }

    fn matches(&self, value: &str) -> bool {
        self.matcher.as_ref().is_some_and(|m| m.matches(value.as_bytes()))
    }

    fn sets_any(&self) -> bool {
        matches!(self.matcher, Some(Matcher::Any))
    }
}

/// Characters of a header name (RFC 9110 token).
fn is_token(s: &str) -> bool {
    !s.is_empty() && s.bytes().all(|b| b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b))
}

/// Checks a rule whether or not it is enabled: a bad one saved disabled would stop the proxy
/// loading any settings once enabled.
pub fn validate_rule(rule: &Rule) -> Result<()> {
    let bad = |m: String| Err(Error::InvalidInput(m));
    let loc = rule.location;
    match (&rule.name, loc) {
        (None, RuleLocation::QueryParam) => return bad("a query-param rule needs the parameter's --name".into()),
        // The name as it reads decoded: it is written encoded where the rule adds the parameter.
        (Some(n), RuleLocation::QueryParam) => {
            if n.is_empty() || n.chars().any(char::is_control) {
                return bad(format!("{n:?} can't be a query parameter's name"));
            }
        }
        (Some(n), l) if l.is_header() => {
            if !is_token(n) {
                return bad(format!("{n:?} can't be a header's name"));
            }
        }
        (Some(_), _) => return bad(format!("--name goes with a header location or query-param, not {}", loc.name())),
        (None, _) => {}
    }
    match (rule.action, rule.name.is_some()) {
        (Some(_), false) => return bad("--action goes with --name (a header's or a query parameter's)".into()),
        (Some(RuleAction::Add), _) if !rule.pattern.is_empty() => {
            return bad("--action add takes no --match: it adds the header or parameter whatever is there".into())
        }
        (Some(RuleAction::Remove), _) if !rule.replace.is_empty() => {
            return bad("--action remove takes no --replace".into())
        }
        _ => {}
    }
    if breaks_head(rule) {
        return bad("a replacement written into a request's line or headers can't hold a line break or NUL".into());
    }
    if loc == RuleLocation::Status {
        // A group reference is only known once it has matched; the result is checked then too.
        let computed = rule.matcher == MatchKind::Regex && rule.replace.contains('$');
        if !computed && status_parts(&rule.replace).is_none() {
            return bad(format!(
                "a status replacement is a code from 200 to 999, with a reason if you like (\"404\" or \"404 Not Found\"), not {:?}",
                rule.replace
            ));
        }
    }
    let ws = loc == RuleLocation::WsMessage;
    if let Some(e) = rule.applies_to.iter().find(|e| e.is_ws() != ws) {
        return bad(if ws {
            format!("a ws-message rule applies to ws-to-server and ws-to-client, not {}", e.name())
        } else {
            format!("{} takes a ws-message rule: a {} rule applies to proxy, send, fuzz and scan", e.name(), loc.name())
        });
    }
    compile_rules(std::slice::from_ref(&Rule { enabled: true, ..rule.clone() })).map(|_| ())
}

/// Whether `rule` would write a line break or NUL into a request's head, which would start
/// another header (a Host, say). Saving one is refused; one saved before that was checked is
/// skipped when rules load (see [`compile_rules`]) and listed as skipped.
pub fn breaks_head(rule: &Rule) -> bool {
    let breaks = |s: &str| s.contains(['\r', '\n', '\0']);
    rule.location.request_head() && (breaks(&rule.replace) || rule.name.as_deref().is_some_and(breaks))
}

fn compile(r: &Rule) -> Result<CompiledRule> {
    let bad = |e: regex::Error| Error::InvalidInput(format!("rule {} pattern: {e}", r.id));
    let matcher = if r.pattern.is_empty() {
        match (r.location, r.name.is_some(), r.matcher) {
            // Adds a header line.
            (RuleLocation::RequestHeader | RuleLocation::ResponseHeader, false, _) => None,
            (
                RuleLocation::RequestLine | RuleLocation::RequestBody | RuleLocation::ResponseBody,
                _,
                MatchKind::Regex,
            ) => None,
            _ => Some(Matcher::Any),
        }
    } else {
        Some(match r.matcher {
            MatchKind::Regex => Matcher::Regex(BytesRegex::new(&r.pattern).map_err(bad)?),
            MatchKind::Literal => Matcher::Literal(BytesRegex::new(&regex::escape(&r.pattern)).map_err(bad)?),
            MatchKind::Whole => Matcher::Whole(r.pattern.clone().into_bytes()),
        })
    };
    let host = r
        .host
        .as_deref()
        .filter(|h| !h.is_empty())
        .map(|h| {
            Regex::new(&format!("(?i){h}")).map_err(|e| Error::InvalidInput(format!("rule {} host pattern: {e}", r.id)))
        })
        .transpose()?;
    Ok(CompiledRule {
        id: r.id,
        origin: r.origin.clone(),
        host_header_test: r.host_header_test,
        location: r.location,
        name: r.name.clone().filter(|_| r.location.is_header() || r.location == RuleLocation::QueryParam),
        action: r.action.unwrap_or_default(),
        matcher,
        replacer: Replacer::of(r),
        host,
        engines: r.engines(),
    })
}

/// The enabled rules, compiled. One that [`breaks_head`] is left out rather than failing the
/// load, so the proxy keeps the rest.
pub fn compile_rules(rules: &[Rule]) -> Result<Vec<CompiledRule>> {
    rules.iter().filter(|r| r.enabled && !breaks_head(r)).map(compile).collect()
}

/// A rule that changed a message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Fired {
    pub id: u32,
    pub origin: Option<String>,
    pub host_header_test: bool,
}

/// A message after an engine's rules.
#[derive(Debug, Clone, Default)]
pub struct Ruled {
    /// The message to use.
    pub bytes: Vec<u8>,
    /// The message as it was, when a rule changed it.
    pub original: Option<Vec<u8>>,
    /// The rules that changed it, in the order they applied.
    pub fired: Vec<Fired>,
}

impl Ruled {
    fn unchanged(bytes: Vec<u8>) -> Self {
        Ruled { bytes, original: None, fired: Vec::new() }
    }

    fn of(original: Vec<u8>, bytes: Vec<u8>, by: Vec<&CompiledRule>) -> Self {
        // A rule may undo another: then nothing changed, whatever fired on the way.
        if by.is_empty() || bytes == original {
            return Self::unchanged(original);
        }
        let fired = by
            .iter()
            .map(|r| Fired { id: r.id, origin: r.origin.clone(), host_header_test: r.host_header_test })
            .collect();
        Ruled { bytes, original: Some(original), fired }
    }

    pub fn changed(&self) -> bool {
        self.original.is_some()
    }

    /// The rules that changed it, for a history row's `edited_by`.
    pub fn edits(&self) -> Vec<Edit> {
        self.fired.iter().map(|r| Edit { by: r.origin.clone(), rule: Some(r.id), ..Default::default() }).collect()
    }

    pub fn ids(&self) -> Vec<u32> {
        self.fired.iter().map(|r| r.id).collect()
    }

    /// The host an agent's rule brought into this request that the scope doesn't list: a rule
    /// added through MCP and not saved as a Host-header test. Such a request isn't sent, as a
    /// shared front end may route it to another site. A person's rule was warned about when it
    /// was saved.
    pub fn agent_host(&self, opts: &SendOptions, target: &Target) -> Option<String> {
        let before = self.original.as_deref()?;
        if !self.fired.iter().any(|r| r.origin.as_deref() == Some("mcp") && !r.host_header_test) {
            return None;
        }
        let had = opts.foreign_hosts(before, target);
        opts.foreign_hosts(&self.bytes, target).into_iter().find(|h| !had.contains(h))
    }

    /// Refuses the request [`Ruled::agent_host`] finds a host in.
    pub fn check_host(&self, opts: &SendOptions, target: &Target) -> Result<()> {
        match self.agent_host(opts, target) {
            Some(host) => Err(Error::OutOfScope(agent_host_refusal(&host))),
            None => Ok(()),
        }
    }
}

/// Why a request an agent's rule put `host` in isn't sent.
pub fn agent_host_refusal(host: &str) -> String {
    format!(
        "Host {host}: an agent's rule put a host the scope doesn't list in the request; \
         add the rule with --host-header-test for a Host-header test"
    )
}

/// The enabled rules of a project, or the ones of them an engine applies.
#[derive(Debug, Clone, Default)]
pub struct RuleSet {
    rules: Vec<CompiledRule>,
}

impl RuleSet {
    /// Every enabled rule (see [`compile_rules`]).
    pub fn compile(rules: &[Rule]) -> Result<Self> {
        Ok(RuleSet { rules: compile_rules(rules)? })
    }

    /// The rules `engine` applies, read from the project now; None when it has none, which is
    /// every project whose rules don't say otherwise for an engine other than the proxy. Only
    /// the engine's own rules are read: one that is another engine's, or that this build can't
    /// read (a newer build wrote it), can't stop this one's run. An unreadable rule is said so.
    pub fn load(store: &Store, engine: Engine) -> Result<Option<Arc<Self>>> {
        let stored: Vec<serde_json::Value> = store.setting(RULES_KEY)?;
        let mut rules = Vec::new();
        for value in stored {
            let id = value["id"].clone();
            match serde_json::from_value::<Rule>(value) {
                Ok(rule) if rule.engines().contains(&engine) => rules.push(rule),
                Ok(_) => {}
                Err(e) => {
                    eprintln!("brainproxy: match-and-replace rule {id} not applied: this build can't read it ({e})")
                }
            }
        }
        let set = Self::compile(&rules)?;
        Ok((!set.rules.is_empty()).then(|| Arc::new(set)))
    }

    pub fn is_empty(&self) -> bool {
        self.rules.is_empty()
    }

    fn active<'a>(
        &'a self,
        engine: Engine,
        host: &'a str,
        part: impl Fn(RuleLocation) -> bool + 'a,
    ) -> impl Iterator<Item = &'a CompiledRule> {
        self.rules.iter().filter(move |r| part(r.location) && r.applies(engine, host))
    }

    /// `request` to `host` after the rules `engine` applies there.
    pub fn request(&self, engine: Engine, host: &str, request: Vec<u8>) -> Ruled {
        let active: Vec<&CompiledRule> = self.active(engine, host, RuleLocation::is_request).collect();
        if active.is_empty() {
            return Ruled::unchanged(request);
        }
        let (bytes, by) = request_rules(&active, &request);
        Ruled::of(request, bytes, by)
    }

    /// `response` from `host` after the rules `engine` applies there.
    pub fn response(&self, engine: Engine, host: &str, response: Vec<u8>) -> Ruled {
        let active: Vec<&CompiledRule> = self.active(engine, host, RuleLocation::is_response).collect();
        if active.is_empty() {
            return Ruled::unchanged(response);
        }
        let (bytes, by) = response_rules(&active, &response);
        Ruled::of(response, bytes, by)
    }

    /// Whether `engine` has a rule for responses from `host`: a sender that only holds a
    /// response by reference copies it for the rules only then.
    pub fn rewrites_responses(&self, engine: Engine, host: &str) -> bool {
        self.active(engine, host, RuleLocation::is_response).next().is_some()
    }

    /// Whether a WebSocket message going `engine`'s way on a connection to `host` may be
    /// rewritten, so the relay only takes a message apart when a rule is waiting for it.
    pub fn rewrites_ws(&self, engine: Engine, host: &str) -> bool {
        self.active(engine, host, |l| l == RuleLocation::WsMessage).next().is_some()
    }

    /// A WebSocket message's payload after the rules for its direction (`engine`).
    pub fn ws_message(&self, engine: Engine, host: &str, payload: &[u8]) -> Ruled {
        let mut current = payload.to_vec();
        let mut by = Vec::new();
        for rule in self.active(engine, host, |l| l == RuleLocation::WsMessage) {
            if let Some(new) = rule.rewrite(&current).filter(|new| *new != current) {
                current = new;
                by.push(rule);
            }
        }
        Ruled::of(payload.to_vec(), current, by)
    }
}

/// The rules one engine other than the proxy applies to each exchange it sends, read when its
/// run starts. Cheap to clone.
#[derive(Debug, Clone)]
pub struct EngineRules {
    engine: Engine,
    set: Arc<RuleSet>,
}

impl EngineRules {
    /// `engine`'s rules in the project; None when no enabled rule lists it.
    pub fn load(store: &Store, engine: Engine) -> Result<Option<Self>> {
        Ok(RuleSet::load(store, engine)?.map(|set| EngineRules { engine, set }))
    }

    /// `request` to `target` after the rules, before a session is applied to it (the proxy's
    /// order). Refused when an agent's rule put a host the scope doesn't list in it (see
    /// [`Ruled::agent_host`]); the client's own Host check still sees whatever goes out.
    pub fn request(&self, opts: &SendOptions, target: &Target, request: Vec<u8>) -> Result<Ruled> {
        let ruled = self.set.request(self.engine, &target.host, request);
        ruled.check_host(opts, target)?;
        Ok(ruled)
    }

    /// Whether a response from `target` has rules to go through (see
    /// [`RuleSet::rewrites_responses`]).
    pub fn rewrites_responses(&self, target: &Target) -> bool {
        self.set.rewrites_responses(self.engine, &target.host)
    }

    /// `response` from `target` after the rules: what the engine then reads.
    pub fn response(&self, target: &Target, response: Vec<u8>) -> Ruled {
        self.set.response(self.engine, &target.host, response)
    }
}

/// Applies request rules, whatever engines and hosts they name: for checking what a rule would
/// make of a request before it is saved. Returns the request unchanged when nothing matched.
pub fn apply_request_rules(rules: &[CompiledRule], req: Vec<u8>) -> Vec<u8> {
    let active: Vec<&CompiledRule> = rules.iter().filter(|r| r.location.is_request()).collect();
    if active.is_empty() {
        return req;
    }
    request_rules(&active, &req).0
}

/// The request line's method, target and version, when it is those three with single spaces.
fn line_parts(first: &str) -> Option<(&str, &str, &str)> {
    let mut parts = first.split(' ');
    let (method, target, version) = (parts.next()?, parts.next()?, parts.next()?);
    (parts.next().is_none() && !method.is_empty() && !target.is_empty() && !version.is_empty())
        .then_some((method, target, version))
}

/// A request target as what comes before its path (the scheme and authority of an absolute
/// one), the path, and the query string after `?` if it has one.
fn target_parts(target: &str) -> (&str, &str, Option<&str>) {
    let start = match target.find("://") {
        Some(at) if !target.starts_with('/') => target[at + 3..].find(['/', '?']).map_or(target.len(), |i| at + 3 + i),
        _ => 0,
    };
    let (before, rest) = target.split_at(start);
    match rest.split_once('?') {
        Some((path, query)) => (before, path, Some(query)),
        None => (before, rest, None),
    }
}

/// A query parameter's name decoded (`%XX`, and `+` as a space), for comparing it.
fn decode_name(raw: &str) -> String {
    match crate::codec::decode("url", raw.as_bytes()) {
        Ok(decoded) => String::from_utf8_lossy(&decoded).into_owned(),
        Err(_) => raw.to_string(),
    }
}

/// A query parameter's name as a rule writes it into a query string.
fn encode_name(name: &str) -> String {
    match crate::codec::encode("url", name.as_bytes()) {
        Ok(encoded) => String::from_utf8_lossy(&encoded).into_owned(),
        Err(_) => name.to_string(),
    }
}

/// What a named-parameter rule makes of a query string; None when it changes nothing. The
/// rule's name is the parameter's decoded name; values are read and written as they are.
fn edit_query(rule: &CompiledRule, query: Option<&str>) -> Option<Option<String>> {
    let name = rule.name.as_deref()?;
    let mut pairs: Vec<String> =
        query.map(|q| q.split('&').filter(|p| !p.is_empty()).map(str::to_string).collect()).unwrap_or_default();
    let before = pairs.clone();
    let split = |pair: &str| -> (String, Option<String>) {
        match pair.split_once('=') {
            Some((k, v)) => (k.to_string(), Some(v.to_string())),
            None => (pair.to_string(), None),
        }
    };
    let is = |pair: &str| {
        let key = split(pair).0;
        key == name || decode_name(&key) == name
    };
    match rule.action {
        RuleAction::Add => pairs.push(format!("{}={}", encode_name(name), rule.replacer.fresh())),
        RuleAction::Remove => pairs.retain(|p| !(is(p) && rule.matches(split(p).1.as_deref().unwrap_or("")))),
        RuleAction::Set => {
            let mut found = false;
            for pair in pairs.iter_mut().filter(|p| is(p)) {
                found = true;
                let (key, value) = split(pair);
                let value = value.unwrap_or_default();
                // A value left as it is leaves the parameter as written (`?debug` stays so).
                if let Some(new) = rule.rewrite_str(&value).filter(|new| *new != value) {
                    *pair = format!("{key}={new}");
                }
            }
            if !found && rule.sets_any() {
                pairs.push(format!("{}={}", encode_name(name), rule.replacer.fresh()));
            }
        }
    }
    if pairs == before {
        return None;
    }
    Some((!pairs.is_empty()).then(|| pairs.join("&")))
}

/// Applies a rule on a part of the request line to it. Leaves a line that isn't `METHOD
/// TARGET VERSION` alone, and a result that would break the line in two.
fn edit_request_line(rule: &CompiledRule, first: &mut String) -> bool {
    let Some((method, target, version)) = line_parts(first) else { return false };
    let (before, path, query) = target_parts(target);
    let with_query = |q: Option<&str>| match q {
        Some(q) => format!("{before}{path}?{q}"),
        None => format!("{before}{path}"),
    };
    let new = match rule.location {
        RuleLocation::Method => rule.rewrite_str(method).map(|m| format!("{m} {target} {version}")),
        RuleLocation::Path => rule.rewrite_str(path).map(|p| match query {
            Some(q) => format!("{method} {before}{p}?{q} {version}"),
            None => format!("{method} {before}{p} {version}"),
        }),
        RuleLocation::QueryParam => {
            edit_query(rule, query).map(|q| format!("{method} {} {version}", with_query(q.as_deref())))
        }
        _ => None,
    };
    match new {
        Some(new) if new != *first && !new.contains(['\r', '\n', '\0']) => {
            *first = new;
            true
        }
        _ => false,
    }
}

fn request_rules<'a>(active: &[&'a CompiledRule], req: &[u8]) -> (Vec<u8>, Vec<&'a CompiledRule>) {
    let (head, raw_body) = split_head_body(req);
    let (mut first, mut headers) = split_lines(head);
    // Body rules see the data, not the chunk framing (which they would break).
    let chunked = headers.iter().any(|h| {
        h.split_once(':').is_some_and(|(k, v)| {
            k.trim().eq_ignore_ascii_case("transfer-encoding") && v.to_ascii_lowercase().contains("chunked")
        })
    });
    let has_body_rule = active.iter().any(|r| r.location == RuleLocation::RequestBody && r.matcher.is_some());
    let mut body = if chunked && has_body_rule { dechunk(raw_body) } else { raw_body.to_vec() };
    let mut body_changed = false;
    let mut changed_by = Vec::new();
    for &rule in active {
        let changed = match rule.location {
            RuleLocation::RequestLine => rule.rewrite_str(&first).is_some_and(|new| {
                let changed = new != first;
                first = new;
                changed
            }),
            RuleLocation::Method | RuleLocation::Path | RuleLocation::QueryParam => edit_request_line(rule, &mut first),
            RuleLocation::RequestHeader => {
                let before = headers.clone();
                apply_header_rule(rule, &mut headers);
                before != headers
            }
            RuleLocation::RequestBody => rule.rewrite(&body).is_some_and(|new| {
                let changed = new != body;
                body = new;
                changed
            }),
            _ => false,
        };
        if changed {
            body_changed |= rule.location == RuleLocation::RequestBody;
            changed_by.push(rule);
        }
    }
    if changed_by.is_empty() {
        // Sent as it came, chunks and all.
        return (req.to_vec(), changed_by);
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

/// A status replacement's code and reason: `404`, or `404 Not Found`.
fn status_parts(replacement: &str) -> Option<(u16, Option<&str>)> {
    let (code, reason) = match replacement.split_once(' ') {
        Some((code, reason)) => (code, Some(reason)),
        None => (replacement, None),
    };
    // Not 1xx: a client would go on waiting for the final response.
    let ok = code.len() == 3 && code.bytes().all(|b| b.is_ascii_digit()) && !code.starts_with(['0', '1']);
    if !ok || reason.is_some_and(|r| r.contains(['\r', '\n', '\0'])) {
        return None;
    }
    Some((code.parse().ok()?, reason))
}

/// The usual reason for a status code a rule sets without giving one.
fn reason(code: u16) -> &'static str {
    match code {
        200 => "OK",
        201 => "Created",
        202 => "Accepted",
        204 => "No Content",
        206 => "Partial Content",
        301 => "Moved Permanently",
        302 => "Found",
        303 => "See Other",
        304 => "Not Modified",
        307 => "Temporary Redirect",
        308 => "Permanent Redirect",
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        409 => "Conflict",
        410 => "Gone",
        418 => "I'm a teapot",
        422 => "Unprocessable Content",
        429 => "Too Many Requests",
        500 => "Internal Server Error",
        501 => "Not Implemented",
        502 => "Bad Gateway",
        503 => "Service Unavailable",
        504 => "Gateway Timeout",
        _ => "",
    }
}

/// Applies a status rule to a status line (`HTTP/1.1 200 OK`).
fn edit_status(rule: &CompiledRule, first: &mut String) -> bool {
    let mut parts = first.splitn(3, ' ');
    let (Some(version), Some(code)) = (parts.next(), parts.next()) else { return false };
    let had_reason = parts.next().is_some();
    let Some(replacement) = rule.rewrite_str(code) else { return false };
    let Some((new_code, new_reason)) = status_parts(&replacement) else { return false };
    // The same code and no reason given: the line stays as the server wrote it.
    if new_reason.is_none() && new_code.to_string() == code {
        return false;
    }
    let new_reason = new_reason.unwrap_or_else(|| reason(new_code));
    let new = if new_reason.is_empty() && !had_reason {
        format!("{version} {new_code}")
    } else {
        format!("{version} {new_code} {new_reason}")
    };
    let changed = new != *first;
    *first = new;
    changed
}

/// Applies response rules to the final response (after any 1xx interim responses). Body rules
/// decode the body first and re-frame it with a Content-Length.
fn response_rules<'a>(active: &[&'a CompiledRule], resp: &[u8]) -> (Vec<u8>, Vec<&'a CompiledRule>) {
    let final_start = final_response_offset(resp);
    let (prefix, rest) = resp.split_at(final_start);
    let Ok(parsed) = parse_response_head(rest) else { return (resp.to_vec(), Vec::new()) };
    let (head, raw_body) = split_head_body(rest);
    let (mut first, mut headers) = split_lines(head);
    // Decoded once, when a body rule needs it; None if it can't be decoded (then body rules
    // leave it alone: without its Content-Encoding the client couldn't read it).
    let mut decoded: Option<Option<Vec<u8>>> = None;
    let mut body_changed = false;
    let mut changed_by = Vec::new();
    for &rule in active {
        let changed = match rule.location {
            RuleLocation::Status => edit_status(rule, &mut first),
            RuleLocation::ResponseHeader => {
                let before = headers.clone();
                apply_header_rule(rule, &mut headers);
                before != headers
            }
            RuleLocation::ResponseBody if rule.matcher.is_some() => {
                let current = decoded.get_or_insert_with(|| decode_body_fully(&parsed.headers, raw_body));
                match current.as_mut().and_then(|current| {
                    let new = rule.rewrite(current).filter(|new| new != current)?;
                    *current = new;
                    Some(())
                }) {
                    Some(()) => {
                        body_changed = true;
                        true
                    }
                    None => false,
                }
            }
            _ => false,
        };
        if changed {
            changed_by.push(rule);
        }
    }
    if changed_by.is_empty() {
        return (resp.to_vec(), changed_by);
    }
    let mut body = match decoded.flatten().filter(|_| body_changed) {
        Some(b) => {
            reframe(&mut headers, b.len(), true);
            b
        }
        None => raw_body.to_vec(),
    };
    // A status rule may move the response between the statuses that have no body and the ones
    // that do. The framing follows: a body left after a 204 would be read as the start of the
    // next response, and a 200 with no length would never end on a kept-alive connection.
    let bodyless = |code: u16| matches!(code, 204 | 304);
    let status = first.split(' ').nth(1).and_then(|code| code.parse::<u16>().ok()).unwrap_or(parsed.status);
    if bodyless(status) && !bodyless(parsed.status) {
        body.clear();
        headers.retain(|h| {
            let name = h.split(':').next().unwrap_or("").trim();
            !["content-length", "transfer-encoding"].iter().any(|n| name.eq_ignore_ascii_case(n))
        });
    } else if bodyless(parsed.status) && !bodyless(status) {
        reframe(&mut headers, body.len(), false);
    }
    let mut out = prefix.to_vec();
    out.extend(join(&first, &headers, &body));
    (out, changed_by)
}

/// A header line's name and its value.
fn header_parts(line: &str) -> Option<(&str, &str)> {
    line.split_once(':').map(|(name, value)| (name, value.trim()))
}

fn apply_header_rule(rule: &CompiledRule, headers: &mut Vec<String>) {
    let Some(name) = rule.name.as_deref() else {
        match &rule.matcher {
            None => {
                let line = rule.replacer.fresh();
                if !line.is_empty() {
                    headers.push(line);
                }
            }
            Some(_) => {
                *headers = headers
                    .iter()
                    .map(|h| rule.rewrite_str(h).unwrap_or_else(|| h.clone()))
                    .filter(|h| !h.is_empty())
                    .collect();
            }
        }
        return;
    };
    let is = |line: &str| header_parts(line).is_some_and(|(k, _)| k.trim().eq_ignore_ascii_case(name));
    match rule.action {
        RuleAction::Add => headers.push(format!("{name}: {}", rule.replacer.fresh())),
        RuleAction::Remove => headers.retain(|h| !(is(h) && rule.matches(header_parts(h).map_or("", |(_, v)| v)))),
        RuleAction::Set => {
            let mut found = false;
            for line in headers.iter_mut().filter(|h| is(h)) {
                found = true;
                let Some((key, value)) = header_parts(line) else { continue };
                // A value left as it is leaves the line as written, spacing and all.
                if let Some(new) = rule.rewrite_str(value).filter(|new| new != value) {
                    *line = format!("{key}: {new}");
                }
            }
            if !found && rule.sets_any() {
                headers.push(format!("{name}: {}", rule.replacer.fresh()));
            }
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

#[cfg(test)]
mod tests {
    use super::*;

    fn rule(id: u32, loc: RuleLocation, pattern: &str, replace: &str) -> Rule {
        Rule::new(id, loc, pattern, replace)
    }

    fn named(id: u32, loc: RuleLocation, name: &str, action: RuleAction, pattern: &str, replace: &str) -> Rule {
        Rule { name: Some(name.into()), action: Some(action), ..rule(id, loc, pattern, replace) }
    }

    fn request(rules: &[Rule], req: &str) -> (String, Vec<u32>) {
        let out = RuleSet::compile(rules).unwrap().request(Engine::Proxy, "h.test", req.as_bytes().to_vec());
        (String::from_utf8(out.bytes.clone()).unwrap(), out.ids())
    }

    fn response(rules: &[Rule], resp: &str) -> (String, Vec<u32>) {
        let out = RuleSet::compile(rules).unwrap().response(Engine::Proxy, "h.test", resp.as_bytes().to_vec());
        (String::from_utf8(out.bytes.clone()).unwrap(), out.ids())
    }

    #[test]
    fn names_are_the_ones_parsed_and_stored() {
        for name in RuleLocation::ALL {
            let location = RuleLocation::parse(name).unwrap();
            assert_eq!((location.name(), serde_json::to_value(location).unwrap()), (*name, serde_json::json!(name)));
        }
        for name in Engine::ALL {
            let engine = Engine::parse(name).unwrap();
            assert_eq!((engine.name(), serde_json::to_value(engine).unwrap()), (*name, serde_json::json!(name)));
        }
        for name in MatchKind::ALL {
            assert_eq!(serde_json::to_value(MatchKind::parse(name).unwrap()).unwrap(), serde_json::json!(name));
        }
        for name in RuleAction::ALL {
            assert_eq!(serde_json::to_value(RuleAction::parse(name).unwrap()).unwrap(), serde_json::json!(name));
        }
        assert!(RuleLocation::parse("cookie").is_err() && Engine::parse("crawl").is_err());
    }

    #[test]
    fn a_head_replacement_cant_hold_a_line_break() {
        for loc in [RuleLocation::RequestLine, RuleLocation::RequestHeader, RuleLocation::Method, RuleLocation::Path] {
            for bad in ["X-A: a\r\nHost: e.test", "a\nb", "a\0b"] {
                assert!(validate_rule(&rule(1, loc, "^X", bad)).is_err(), "{bad:?}");
            }
        }
        let host = named(1, RuleLocation::RequestHeader, "X-A", RuleAction::Set, "", "a\r\nHost: e.test");
        assert!(validate_rule(&host).is_err());
        // A body can hold one.
        validate_rule(&rule(1, RuleLocation::RequestBody, "x", "a\r\nb")).unwrap();
        // One saved before this was checked is left out when rules load; the others stay.
        let saved = [
            rule(1, RuleLocation::RequestHeader, "^X", "X-A: a\r\nHost: e"),
            rule(2, RuleLocation::RequestHeader, "^X", "Y"),
        ];
        let compiled = compile_rules(&saved).unwrap();
        assert_eq!(compiled.iter().map(|r| r.id).collect::<Vec<_>>(), [2]);
    }

    #[test]
    fn request_rules() {
        let rules = [
            rule(1, RuleLocation::RequestHeader, "", "X-Added: 1"),
            rule(2, RuleLocation::RequestHeader, "(?i)^user-agent:.*$", ""),
            rule(3, RuleLocation::RequestLine, "^GET ", "POST "),
            rule(4, RuleLocation::RequestBody, "role=user", "role=admin"),
        ];
        let req = "GET /p HTTP/1.1\r\nHost: h\r\nUser-Agent: x\r\nContent-Length: 9\r\n\r\nrole=user";
        let ruled = "POST /p HTTP/1.1\r\nHost: h\r\nContent-Length: 10\r\nX-Added: 1\r\n\r\nrole=admin";
        assert_eq!(request(&rules, req).0, ruled);
        // The same whatever engines the rules name, for checking a rule before it is saved.
        let compiled = compile_rules(&rules).unwrap();
        assert_eq!(String::from_utf8(apply_request_rules(&compiled, req.as_bytes().to_vec())).unwrap(), ruled);
    }

    #[test]
    fn request_rules_say_which_of_them_changed_the_request() {
        let mut agents = rule(2, RuleLocation::RequestHeader, "^X-Role: user$", "X-Role: admin");
        agents.origin = Some("mcp".into());
        let rules = [
            rule(1, RuleLocation::RequestBody, "never-there", "x"),
            agents,
            rule(3, RuleLocation::RequestLine, "^GET ", "GET "),
        ];
        let set = RuleSet::compile(&rules).unwrap();
        let out = set.request(Engine::Proxy, "h", b"GET /p HTTP/1.1\r\nX-Role: user\r\n\r\n".to_vec());
        assert_eq!(String::from_utf8(out.bytes.clone()).unwrap(), "GET /p HTTP/1.1\r\nX-Role: admin\r\n\r\n");
        // A rule that matched but left the bytes as they were didn't change it.
        let changed: Vec<_> = out.fired.iter().map(|r| (r.id, r.origin.as_deref())).collect();
        assert_eq!(changed, [(2, Some("mcp"))]);
        assert_eq!(out.edits(), [Edit { by: Some("mcp".into()), rule: Some(2), ..Default::default() }]);
    }

    #[test]
    fn response_body_rule_reframes() {
        let rules = [rule(1, RuleLocation::ResponseBody, "false", "true")];
        let resp = "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n10\r\n{\"admin\": false}\r\n0\r\n\r\n";
        assert_eq!(response(&rules, resp).0, "HTTP/1.1 200 OK\r\nContent-Length: 15\r\n\r\n{\"admin\": true}");
    }

    #[test]
    fn request_body_rule_on_a_chunked_body_reframes_it() {
        let rules = [rule(1, RuleLocation::RequestBody, "role=user", "role=admin")];
        let req = "POST /p HTTP/1.1\r\nHost: h\r\nTransfer-Encoding: chunked\r\n\r\n9\r\nrole=user\r\n0\r\n\r\n";
        assert_eq!(request(&rules, req).0, "POST /p HTTP/1.1\r\nHost: h\r\nContent-Length: 10\r\n\r\nrole=admin");
        // A coded body is only de-chunked, so it keeps its Content-Encoding.
        let coded = "POST /p HTTP/1.1\r\nContent-Encoding: x-test\r\nTransfer-Encoding: chunked\r\n\r\n9\r\nrole=user\r\n0\r\n\r\n";
        assert_eq!(
            request(&rules, coded).0,
            "POST /p HTTP/1.1\r\nContent-Encoding: x-test\r\nContent-Length: 10\r\n\r\nrole=admin"
        );
        // No match: sent as it came, chunks and all.
        let rules = [rule(1, RuleLocation::RequestBody, "nothing", "x")];
        assert_eq!(request(&rules, req), (req.to_string(), vec![]));
    }

    #[test]
    fn response_body_rules_leave_bodies_they_cannot_decode_or_do_not_change() {
        let set = RuleSet::compile(&[rule(1, RuleLocation::ResponseBody, "a", "b")]).unwrap();
        let zstd = b"HTTP/1.1 200 OK\r\nContent-Encoding: zstd\r\nContent-Length: 4\r\n\r\n(\xb5/\xfd".to_vec();
        assert_eq!(set.response(Engine::Proxy, "h", zstd.clone()).bytes, zstd);
        let head = b"HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\nContent-Length: 120\r\n\r\n".to_vec();
        let out = set.response(Engine::Proxy, "h", head.clone());
        assert_eq!((out.bytes, out.original), (head, None));
    }

    #[test]
    fn disabled_rules_are_validated_too() {
        let mut r = rule(1, RuleLocation::RequestHeader, "(", "x");
        r.enabled = false;
        assert!(compile_rules(std::slice::from_ref(&r)).is_ok());
        assert!(validate_rule(&r).is_err());
    }

    #[test]
    fn a_rule_stored_before_structured_rules_reads_as_it_did() {
        let stored = r#"[{"id":3,"location":"request-header","pattern":"^X: (.*)$","replace":"X: $1!","enabled":true,"origin":"gui"}]"#;
        let rules: Vec<Rule> = serde_json::from_str(stored).unwrap();
        assert_eq!(rules[0].engines(), [Engine::Proxy]);
        assert_eq!(
            (rules[0].matcher, rules[0].name.as_deref(), rules[0].host.as_deref()),
            (MatchKind::Regex, None, None)
        );
        // And is written back with nothing added.
        assert_eq!(serde_json::to_string(&rules).unwrap(), stored);
        let (out, fired) = request(&rules, "GET / HTTP/1.1\r\nX: a\r\n\r\n");
        assert_eq!((out.as_str(), fired), ("GET / HTTP/1.1\r\nX: a!\r\n\r\n", vec![3]));
    }

    #[test]
    fn method_and_path_rules_work_on_their_part_of_the_request_line() {
        let rules = [
            rule(1, RuleLocation::Method, "", "POST"),
            Rule { matcher: MatchKind::Literal, ..rule(2, RuleLocation::Path, "/v1/", "/v2/") },
            rule(3, RuleLocation::Path, "^/api/(\\w+)/(\\d+)$", "/api/$2/$1"),
        ];
        let (out, fired) = request(&rules, "GET /api/v1/7?next=/v1/ HTTP/1.1\r\nHost: h\r\n\r\n");
        // The query string is not the path's, and a literal is not a regex.
        assert_eq!(out, "POST /api/7/v2?next=/v1/ HTTP/1.1\r\nHost: h\r\n\r\n");
        assert_eq!(fired, [1, 2, 3]);
        // An absolute target keeps its scheme and authority.
        let (out, _) = request(&rules[1..2], "GET http://h.test/v1/x HTTP/1.1\r\n\r\n");
        assert_eq!(out, "GET http://h.test/v2/x HTTP/1.1\r\n\r\n");
        // One with no path has its query string where the authority ends.
        let bare = "GET http://h.test?x=1 HTTP/1.1\r\n\r\n";
        let path = [rule(5, RuleLocation::Path, "", "/new")];
        assert_eq!(request(&path, bare).0, "GET http://h.test/new?x=1 HTTP/1.1\r\n\r\n");
        let param = [named(6, RuleLocation::QueryParam, "x", RuleAction::Set, "", "2")];
        assert_eq!(request(&param, bare).0, "GET http://h.test?x=2 HTTP/1.1\r\n\r\n");
        // A line that isn't METHOD TARGET VERSION is left alone.
        let odd = "GET /a b HTTP/1.1\r\n\r\n";
        assert_eq!(request(&rules, odd), (odd.to_string(), vec![]));
        // A whole-value match is the whole value or nothing.
        let whole = [Rule { matcher: MatchKind::Whole, ..rule(4, RuleLocation::Method, "GET", "HEAD") }];
        assert_eq!(request(&whole, "GET / HTTP/1.1\r\n\r\n").0, "HEAD / HTTP/1.1\r\n\r\n");
        assert_eq!(request(&whole, "GETS / HTTP/1.1\r\n\r\n").1, Vec::<u32>::new());
    }

    #[test]
    fn query_parameter_rules_set_add_and_remove() {
        let q = RuleLocation::QueryParam;
        let set = [named(1, q, "role", RuleAction::Set, "", "admin")];
        assert_eq!(request(&set, "GET /p?a=1&role=user HTTP/1.1\r\n\r\n").0, "GET /p?a=1&role=admin HTTP/1.1\r\n\r\n");
        // Set adds the parameter when the request has none, a query string too.
        assert_eq!(request(&set, "GET /p HTTP/1.1\r\n\r\n").0, "GET /p?role=admin HTTP/1.1\r\n\r\n");
        // With a pattern it only rewrites a value that matches, and adds nothing.
        let matched = [named(1, q, "id", RuleAction::Set, "^(\\d+)$", "${1}0")];
        assert_eq!(request(&matched, "GET /p?id=7&id=x HTTP/1.1\r\n\r\n").0, "GET /p?id=70&id=x HTTP/1.1\r\n\r\n");
        assert_eq!(request(&matched, "GET /p HTTP/1.1\r\n\r\n").1, Vec::<u32>::new());
        let add = [named(2, q, "debug", RuleAction::Add, "", "1")];
        assert_eq!(request(&add, "GET /p?debug=0 HTTP/1.1\r\n\r\n").0, "GET /p?debug=0&debug=1 HTTP/1.1\r\n\r\n");
        // The name is the decoded one: it matches however the request wrote it, and the last
        // parameter gone takes the `?` with it.
        let remove = [named(3, q, "csrf token", RuleAction::Remove, "", "")];
        validate_rule(&remove[0]).unwrap();
        assert_eq!(request(&remove, "GET /p?csrf+token=x&a=1 HTTP/1.1\r\n\r\n").0, "GET /p?a=1 HTTP/1.1\r\n\r\n");
        assert_eq!(request(&remove, "GET /p?csrf%20token=x HTTP/1.1\r\n\r\n").0, "GET /p HTTP/1.1\r\n\r\n");
        // A rule that adds the parameter writes its name encoded: it stays one parameter.
        let odd = [named(4, q, "a b&c=d", RuleAction::Set, "", "1")];
        validate_rule(&odd[0]).unwrap();
        assert_eq!(request(&odd, "GET /p HTTP/1.1\r\n\r\n").0, "GET /p?a%20b%26c%3Dd=1 HTTP/1.1\r\n\r\n");
        assert_eq!(request(&odd, "GET /p?a+b%26c%3Dd=0 HTTP/1.1\r\n\r\n").0, "GET /p?a+b%26c%3Dd=1 HTTP/1.1\r\n\r\n");
    }

    #[test]
    fn named_header_rules_set_add_and_remove() {
        let h = RuleLocation::RequestHeader;
        let set = [named(1, h, "X-Role", RuleAction::Set, "", "admin")];
        // The name is matched without regard to case and kept as the request wrote it.
        assert_eq!(
            request(&set, "GET / HTTP/1.1\r\nx-role: user\r\n\r\n").0,
            "GET / HTTP/1.1\r\nx-role: admin\r\n\r\n"
        );
        assert_eq!(request(&set, "GET / HTTP/1.1\r\n\r\n").0, "GET / HTTP/1.1\r\nX-Role: admin\r\n\r\n");
        // A header whose name only starts like it is another header.
        assert_eq!(
            request(&set, "GET / HTTP/1.1\r\nX-Role-Id: 4\r\n\r\n").0,
            "GET / HTTP/1.1\r\nX-Role-Id: 4\r\nX-Role: admin\r\n\r\n"
        );
        let value =
            [Rule { matcher: MatchKind::Literal, ..named(2, h, "Cookie", RuleAction::Set, "tier=free", "tier=pro") }];
        let (out, fired) = request(&value, "GET / HTTP/1.1\r\nCookie: a=1; tier=free\r\nX: tier=free\r\n\r\n");
        assert_eq!((out.as_str(), fired), ("GET / HTTP/1.1\r\nCookie: a=1; tier=pro\r\nX: tier=free\r\n\r\n", vec![2]));
        let add = [named(3, h, "X-Forwarded-For", RuleAction::Add, "", "127.0.0.1")];
        assert_eq!(request(&add, "GET / HTTP/1.1\r\n\r\n").0, "GET / HTTP/1.1\r\nX-Forwarded-For: 127.0.0.1\r\n\r\n");
        let remove = [named(4, RuleLocation::ResponseHeader, "Content-Security-Policy", RuleAction::Remove, "", "")];
        let (out, fired) = response(&remove, "HTTP/1.1 200 OK\r\ncontent-security-policy: x\r\nA: b\r\n\r\nhi");
        assert_eq!((out.as_str(), fired), ("HTTP/1.1 200 OK\r\nA: b\r\n\r\nhi", vec![4]));
        // Remove with a pattern keeps the ones whose value doesn't match.
        let some = [named(5, h, "Cookie", RuleAction::Remove, "^track", "")];
        assert_eq!(
            request(&some, "GET / HTTP/1.1\r\nCookie: track=1\r\nCookie: s=2\r\n\r\n").0,
            "GET / HTTP/1.1\r\nCookie: s=2\r\n\r\n"
        );
    }

    #[test]
    fn a_set_that_changes_no_value_changes_nothing() {
        // The header and the parameter are there with the value already: not a byte moves.
        let header = [named(1, RuleLocation::RequestHeader, "X-Role", RuleAction::Set, "", "admin")];
        let same = "GET /p?debug HTTP/1.1\r\nX-Role:admin\r\n\r\n";
        assert_eq!(request(&header, same), (same.to_string(), vec![]));
        let param = [named(2, RuleLocation::QueryParam, "debug", RuleAction::Set, "", "")];
        assert_eq!(request(&param, same), (same.to_string(), vec![]));
        let nothing = [named(3, RuleLocation::QueryParam, "debug", RuleAction::Set, "x", "y")];
        assert_eq!(request(&nothing, same), (same.to_string(), vec![]));
    }

    #[test]
    fn an_engine_loads_only_its_own_rules_and_skips_ones_it_cannot_read() {
        let store = Store::open_in_memory().unwrap();
        let stored = serde_json::json!([
            // The proxy's, with a pattern that doesn't compile: none of send's business.
            {"id": 1, "location": "request-header", "pattern": "(", "replace": "x", "enabled": true},
            // From a build that knows more locations and replacers than this one.
            {"id": 2, "location": "trailer", "pattern": "", "replace": "x", "applies_to": ["send"]},
            {"id": 3, "location": "path", "pattern": "", "replace": "/x", "applies_to": ["send"], "replacer": "script"},
            {"id": 4, "location": "method", "pattern": "", "replace": "PUT", "applies_to": ["send", "fuzz"]},
            {"id": 5, "location": "method", "pattern": "", "replace": "HEAD", "applies_to": ["send"], "enabled": false},
        ]);
        store.set_setting(RULES_KEY, &stored).unwrap();
        let target = Target { scheme: "http".into(), host: "h.test".into(), port: 80 };
        let send = EngineRules::load(&store, Engine::Send).unwrap().unwrap();
        let out = send.request(&SendOptions::default(), &target, b"GET / HTTP/1.1\r\n\r\n".to_vec()).unwrap();
        assert_eq!((out.bytes.as_slice(), out.ids()), (&b"PUT / HTTP/1.1\r\n\r\n"[..], vec![4]));
        assert!(!send.rewrites_responses(&target));
        assert!(EngineRules::load(&store, Engine::Scan).unwrap().is_none());
        // The proxy reads them all, and says what is wrong with them.
        assert!(store.setting::<Vec<Rule>>(RULES_KEY).is_err());
    }

    #[test]
    fn status_rules_set_the_code_and_its_reason() {
        let s = RuleLocation::Status;
        let (out, fired) = response(&[rule(1, s, "403", "200")], "HTTP/1.1 403 Forbidden\r\nA: b\r\n\r\nno");
        assert_eq!((out.as_str(), fired), ("HTTP/1.1 200 OK\r\nA: b\r\n\r\nno", vec![1]));
        assert_eq!(response(&[rule(1, s, "", "418 Nope")], "HTTP/1.1 200 OK\r\n\r\n").0, "HTTP/1.1 418 Nope\r\n\r\n");
        // The same code leaves the server's reason; a code that doesn't match is left alone.
        let same = "HTTP/1.1 200 Fine\r\n\r\n";
        assert_eq!(response(&[rule(1, s, "", "200")], same), (same.to_string(), vec![]));
        assert_eq!(response(&[rule(1, s, "^5", "200")], same).1, Vec::<u32>::new());
        // An interim response is passed over: the final one is what is ruled.
        let early = "HTTP/1.1 103 Early Hints\r\nLink: </a>\r\n\r\nHTTP/1.1 500 Oops\r\n\r\n";
        assert_eq!(
            response(&[rule(1, s, "500", "200")], early).0,
            "HTTP/1.1 103 Early Hints\r\nLink: </a>\r\n\r\nHTTP/1.1 200 OK\r\n\r\n"
        );
        for bad in ["20", "abc", "099", "103", "200\r\nX: y"] {
            assert!(validate_rule(&rule(1, s, "", bad)).is_err(), "{bad:?}");
        }
        // A computed code that isn't one changes nothing, and neither does an informational one.
        assert_eq!(response(&[rule(1, s, "^(2)00$", "${1}")], same).1, Vec::<u32>::new());
        assert_eq!(response(&[rule(1, s, "^(2)00$", "103")], same).1, Vec::<u32>::new());
    }

    #[test]
    fn a_status_rule_keeps_the_framing_right_for_statuses_without_a_body() {
        let s = RuleLocation::Status;
        // To 204: the body goes, with its framing, or it would be read as the next response.
        let with_body = "HTTP/1.1 200 OK\r\nContent-Length: 5\r\nX: y\r\n\r\nhello";
        assert_eq!(response(&[rule(1, s, "", "204")], with_body).0, "HTTP/1.1 204 No Content\r\nX: y\r\n\r\n");
        let chunked = "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n";
        assert_eq!(response(&[rule(1, s, "", "304")], chunked).0, "HTTP/1.1 304 Not Modified\r\n\r\n");
        // From 204: the response says it has no body, or it would never end.
        let none = "HTTP/1.1 204 No Content\r\nX: y\r\n\r\n";
        assert_eq!(response(&[rule(1, s, "", "200")], none).0, "HTTP/1.1 200 OK\r\nX: y\r\nContent-Length: 0\r\n\r\n");
        // Between statuses that both have one, the body and its framing stay as they came.
        assert_eq!(
            response(&[rule(1, s, "", "404")], with_body).0,
            "HTTP/1.1 404 Not Found\r\nContent-Length: 5\r\nX: y\r\n\r\nhello"
        );
    }

    #[test]
    fn literal_and_whole_matching_take_the_replacement_as_written() {
        let literal = [Rule { matcher: MatchKind::Literal, ..rule(1, RuleLocation::RequestBody, "a.b", "$1") }];
        let (out, _) = request(&literal, "POST / HTTP/1.1\r\nContent-Length: 7\r\n\r\na.b axb");
        assert_eq!(out, "POST / HTTP/1.1\r\nContent-Length: 6\r\n\r\n$1 axb");
        let whole = [Rule { matcher: MatchKind::Whole, ..rule(2, RuleLocation::ResponseBody, "", "{}") }];
        assert_eq!(
            response(&whole, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nhi").0,
            "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}"
        );
        // A regex with nothing to match still matches nothing on a body, as it always did.
        let empty = [rule(3, RuleLocation::RequestBody, "", "x")];
        assert_eq!(request(&empty, "POST / HTTP/1.1\r\nContent-Length: 1\r\n\r\na").1, Vec::<u32>::new());
    }

    #[test]
    fn a_rule_applies_to_the_engines_and_hosts_it_names() {
        let fuzz = Rule { applies_to: vec![Engine::Fuzz, Engine::Send], ..rule(1, RuleLocation::Method, "", "PUT") };
        let host = Rule { host: Some(r"(^|\.)api\.test$".into()), ..rule(2, RuleLocation::Path, "", "/x") };
        let set = RuleSet::compile(&[fuzz, host]).unwrap();
        let req = b"GET / HTTP/1.1\r\n\r\n".to_vec();
        let ids = |engine, host| set.request(engine, host, req.clone()).ids();
        assert_eq!(ids(Engine::Proxy, "h.test"), Vec::<u32>::new());
        assert_eq!(ids(Engine::Proxy, "V2.API.test"), [2]);
        assert_eq!(ids(Engine::Fuzz, "api.test"), [1]);
        assert_eq!(ids(Engine::Scan, "api.test"), Vec::<u32>::new());
        // The original is kept only when a rule changed the message.
        let out = set.request(Engine::Send, "h.test", req.clone());
        assert_eq!((out.original.as_deref(), out.bytes.as_slice()), (Some(&req[..]), &b"PUT / HTTP/1.1\r\n\r\n"[..]));
        assert!(set.request(Engine::Scan, "h.test", req.clone()).original.is_none());
    }

    #[test]
    fn websocket_rules_rewrite_messages_one_way() {
        let both = rule(1, RuleLocation::WsMessage, "\"admin\":false", "\"admin\":true");
        assert_eq!(both.engines(), [Engine::WsToServer, Engine::WsToClient]);
        let down = Rule { applies_to: vec![Engine::WsToClient], ..rule(2, RuleLocation::WsMessage, "true", "1") };
        let set = RuleSet::compile(&[both, down]).unwrap();
        let msg = br#"{"admin":false}"#;
        assert_eq!(set.ws_message(Engine::WsToServer, "h", msg).bytes, br#"{"admin":true}"#);
        let out = set.ws_message(Engine::WsToClient, "h", msg);
        assert_eq!((out.bytes.as_slice(), out.ids()), (&br#"{"admin":1}"#[..], vec![1, 2]));
        assert!(set.rewrites_ws(Engine::WsToServer, "h") && !set.ws_message(Engine::WsToServer, "h", b"x").changed());
        // They don't touch HTTP, and HTTP rules don't touch messages.
        assert!(!set.request(Engine::Proxy, "h", b"GET /true HTTP/1.1\r\n\r\n".to_vec()).changed());
        // A WebSocket rule lists WebSocket directions, another rule the HTTP engines.
        let mixed = Rule { applies_to: vec![Engine::Proxy], ..rule(3, RuleLocation::WsMessage, "a", "b") };
        assert!(validate_rule(&mixed).is_err());
        let mixed = Rule { applies_to: vec![Engine::WsToServer], ..rule(3, RuleLocation::RequestBody, "a", "b") };
        assert!(validate_rule(&mixed).is_err());
    }

    #[test]
    fn rules_that_do_not_fit_their_location_are_refused() {
        let q = RuleLocation::QueryParam;
        assert!(validate_rule(&rule(1, q, "", "x")).is_err(), "no name");
        assert!(validate_rule(&named(1, q, "", RuleAction::Set, "", "x")).is_err());
        assert!(validate_rule(&named(1, q, "a\tb", RuleAction::Set, "", "x")).is_err());
        assert!(validate_rule(&named(1, RuleLocation::RequestHeader, "Bad Name", RuleAction::Set, "", "x")).is_err());
        assert!(validate_rule(&named(1, RuleLocation::Path, "n", RuleAction::Set, "", "x")).is_err());
        assert!(validate_rule(&Rule { action: Some(RuleAction::Add), ..rule(1, RuleLocation::Path, "", "x") }).is_err());
        assert!(validate_rule(&named(1, q, "n", RuleAction::Add, "pat", "x")).is_err());
        assert!(validate_rule(&named(1, q, "n", RuleAction::Remove, "", "x")).is_err());
        assert!(validate_rule(&Rule { host: Some("(".into()), ..rule(1, RuleLocation::Path, "", "/") }).is_err());
        validate_rule(&named(1, q, "n", RuleAction::Remove, "^a", "")).unwrap();
    }

    #[test]
    fn an_agents_rule_that_brings_in_a_foreign_host_is_found() {
        let target = Target { scheme: "https".into(), host: "h.test".into(), port: 443 };
        let opts = SendOptions::default();
        let req = b"GET / HTTP/1.1\r\nHost: h.test\r\n\r\n".to_vec();
        let mut host = named(1, RuleLocation::RequestHeader, "Host", RuleAction::Set, "", "evil.test");
        let ruled =
            |r: &Rule| RuleSet::compile(std::slice::from_ref(r)).unwrap().request(Engine::Proxy, "h.test", req.clone());
        // A person's rule was warned about when it was saved.
        assert_eq!(ruled(&host).agent_host(&opts, &target), None);
        host.origin = Some("mcp".into());
        assert_eq!(ruled(&host).agent_host(&opts, &target).as_deref(), Some("evil.test"));
        assert!(matches!(ruled(&host).check_host(&opts, &target), Err(Error::OutOfScope(_))));
        host.host_header_test = true;
        assert_eq!(ruled(&host).agent_host(&opts, &target), None);
        // An agent's rule that changes something else is no concern.
        let mut other = named(2, RuleLocation::RequestHeader, "X-A", RuleAction::Set, "", "b");
        other.origin = Some("mcp".into());
        assert_eq!(ruled(&other).agent_host(&opts, &target), None);
    }
}
