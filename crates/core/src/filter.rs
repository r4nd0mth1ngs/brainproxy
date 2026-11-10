//! The history filter language: a small query a person types in Traffic, or passes to
//! `history list --filter`, compiled to a parameterized SQL condition on the `history` table.
//!
//! ```text
//! status:5xx AND resp.body:"stack trace"
//! host:api.example.com method=POST NOT path:/health
//! resp.header.server~"(?i)nginx|apache" OR req.header.authorization:*
//! (source=proxy OR source=send) length>10000 duration>=2000
//! ```
//!
//! A term is `FIELD OP VALUE`, or a bare word that searches the URL and title (and matches a
//! method exactly), as the plain Traffic filter does. Terms next to each other must all match;
//! `AND`, `OR`, `NOT` (in any case) and parentheses combine them (`NOT` binds tightest, then `AND`, then
//! `OR`). Values with spaces or special characters go in double quotes, with `\"` and `\\`.
//!
//! Every value is bound as a parameter, and field names map to fixed column expressions, so
//! nothing typed becomes SQL. Each term is coalesced to 0 or 1, so `NOT status:500` keeps the
//! requests that got no response at all.
//!
//! The proxy's intercept uses the same language to pick the messages it holds
//! (`intercept enable --filter`): [`Matcher`] runs the same SQL against a one-row table made
//! from the message in flight, and [`Query::check_known`] refuses fields that aren't known yet
//! when the message is held (a response's status, for a request).

use std::sync::Mutex;

use regex::RegexBuilder;
use rusqlite::types::Value;
use rusqlite::{Connection, ToSql};

use crate::capture::Capture;
use crate::error::{Error, Result};

/// Longest query accepted, in bytes.
pub const MAX_LEN: usize = 4096;
/// Most terms in one query.
const MAX_TERMS: usize = 64;
/// Deepest nesting of parentheses and `NOT`.
const MAX_DEPTH: usize = 32;
/// Compiled size limit for a regex value.
const REGEX_SIZE: usize = 1 << 20;

/// What a field holds, which decides the operators it takes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Kind {
    /// Text, searched case-insensitively (`:` contains, `=` equals, `~` regex).
    Text,
    /// Raw or decoded bytes (`:` contains, `~` regex; no `=`).
    Bytes,
    /// A number (`=`, `!=`, `<`, `<=`, `>`, `>=`; `:` means `=`).
    Number,
    /// An ISO-8601 time, compared as text (`:` is a prefix, such as a day).
    Time,
    /// The JSON array of tags (`:` contains, `=` is one tag exactly).
    Tags,
}

/// The fields, their column expressions, and a description for `capabilities` and the docs.
/// `{h}` in an expression is replaced by the bound header name.
pub const FIELDS: &[(&str, &str)] = &[
    ("id", "History id"),
    ("method", "HTTP method"),
    ("scheme", "http or https"),
    ("host", "Target host"),
    ("port", "Target port"),
    ("path", "URL path, without the query"),
    ("query", "Raw query string, without '?'"),
    ("url", "Full URL"),
    ("status", "Response status; also 2xx, 3xx, 4xx, 5xx"),
    ("length", "Decoded response body length in bytes"),
    ("duration", "Round-trip time in milliseconds"),
    ("time", "When it was recorded (UTC ISO-8601); time:2026-11-08 is that day"),
    ("source", "Tool that recorded it: proxy, send, race, fuzz, scan, crawl, crawl-browser, import, ws"),
    ("origin", "Who started the recording process: gui, cli, mcp, or unknown"),
    ("title", "HTML <title>"),
    ("type", "Response Content-Type"),
    ("error", "Why no response came back"),
    ("note", "The entry's note"),
    ("tag", "One of the entry's tags (tag=race:ID is exact)"),
    ("sni", "TLS server name, when overridden"),
    ("client", "Proxy client address"),
    ("req", "Raw request bytes as sent"),
    ("resp", "Raw response bytes as received"),
    ("req.body", "Request body (chunking and compression removed)"),
    ("resp.body", "Response body (chunking and compression removed)"),
    ("body", "Request or response body"),
    ("req.type", "Request Content-Type"),
    ("req.length", "Request body length in bytes"),
    ("req.headers", "Every request header, as JSON text"),
    ("resp.headers", "Every response header, as JSON text"),
    ("req.header.NAME", "One request header by name, e.g. req.header.authorization"),
    ("resp.header.NAME", "One response header by name, e.g. resp.header.server"),
];

/// The column expression and kind of a field. For `*.header.NAME` it is the headers column,
/// with the header name (lower-case) to look for in it.
fn field(name: &str) -> Option<(Kind, &'static str, Option<String>)> {
    let lower = name.to_ascii_lowercase();
    for (prefix, cols) in [("req.header.", "req_headers"), ("resp.header.", "resp_headers")] {
        if let Some(h) = lower.strip_prefix(prefix) {
            if h.is_empty() || !h.bytes().all(is_token_byte) {
                return None;
            }
            return Some((Kind::Text, cols, Some(h.to_string())));
        }
    }
    let (kind, expr) = match lower.as_str() {
        "id" => (Kind::Number, "id"),
        "method" => (Kind::Text, "method"),
        "scheme" => (Kind::Text, "scheme"),
        "host" => (Kind::Text, "host"),
        "port" => (Kind::Number, "port"),
        "path" => (Kind::Text, "path"),
        "query" => (Kind::Text, "query"),
        "url" => (Kind::Text, "url"),
        "status" => (Kind::Number, "status"),
        "length" => (Kind::Number, "resp_body_length"),
        "duration" => (Kind::Number, "duration_ms"),
        "time" => (Kind::Time, "time"),
        "source" => (Kind::Text, "source"),
        "origin" => (Kind::Text, "coalesce(origin, 'unknown')"),
        "title" => (Kind::Text, "title"),
        "type" => (Kind::Text, "resp_content_type"),
        "error" => (Kind::Text, "error"),
        "note" => (Kind::Text, "note"),
        "tag" => (Kind::Tags, "tags"),
        "sni" => (Kind::Text, "sni"),
        "client" => (Kind::Text, "client_addr"),
        "req" => (Kind::Bytes, "request"),
        "resp" => (Kind::Bytes, "response"),
        "req.body" => (Kind::Bytes, "req_body"),
        "resp.body" => (Kind::Bytes, "resp_body"),
        "body" => (Kind::Bytes, "body"),
        "req.type" => (Kind::Text, "req_content_type"),
        "req.length" => (Kind::Number, "length(req_body)"),
        "req.headers" => (Kind::Text, "req_headers"),
        "resp.headers" => (Kind::Text, "resp_headers"),
        _ => return None,
    };
    Some((kind, expr, None))
}

/// What is known of an exchange when the proxy's intercept holds one of its messages.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Stage {
    /// A request on its way out, before any response. WebSocket messages are matched by their
    /// connection's handshake request, so they are at this stage too.
    Request,
    /// A response on its way back, with the request that was sent.
    Response,
}

/// When a field's value is known for a message in flight.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Known {
    /// From the request on.
    Request,
    /// Once the response is in.
    Response,
    /// Never while a message is held, for this reason.
    Never(&'static str),
}

/// When `name`'s value is known in flight. Every field in [`FIELDS`] is listed here (a test
/// checks it), so a field added later isn't quietly matched against nothing.
fn known(name: &str) -> Known {
    let lower = name.to_ascii_lowercase();
    if lower.starts_with("req.header.") {
        return Known::Request;
    }
    if lower.starts_with("resp.header.") {
        return Known::Response;
    }
    match lower.as_str() {
        "method" | "scheme" | "host" | "port" | "path" | "query" | "url" | "time" | "source" | "origin" | "sni"
        | "client" | "req" | "req.body" | "req.type" | "req.length" | "req.headers" => Known::Request,
        "status" | "length" | "duration" | "title" | "type" | "resp" | "resp.body" | "body" | "resp.headers" => {
            Known::Response
        }
        "id" => Known::Never("a history id is given when the exchange is recorded"),
        "error" => Known::Never("a held message has no error: one is recorded when no response came back"),
        "note" | "tag" => Known::Never("notes and tags are added to an entry once it is recorded"),
        _ => Known::Never("it isn't known while a message is held"),
    }
}

/// A header-name character (RFC 9110 token).
fn is_token_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b)
}

/// A comparison.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Op {
    /// `:` contains (text and bytes), equals (numbers), prefix (time), or one tag containing.
    Has,
    Eq,
    Ne,
    Regex,
    NotRegex,
    Lt,
    Le,
    Gt,
    Ge,
}

impl Op {
    fn text(self) -> &'static str {
        match self {
            Op::Has => ":",
            Op::Eq => "=",
            Op::Ne => "!=",
            Op::Regex => "~",
            Op::NotRegex => "!~",
            Op::Lt => "<",
            Op::Le => "<=",
            Op::Gt => ">",
            Op::Ge => ">=",
        }
    }
}

/// The operators, longest first so `>=` isn't read as `>`.
const OPS: &[(&str, Op)] = &[
    ("!=", Op::Ne),
    ("!~", Op::NotRegex),
    (">=", Op::Ge),
    ("<=", Op::Le),
    (":", Op::Has),
    ("=", Op::Eq),
    ("~", Op::Regex),
    (">", Op::Gt),
    ("<", Op::Lt),
];

#[derive(Debug, Clone, PartialEq)]
enum Token {
    Open,
    Close,
    And,
    Or,
    Not,
    /// A field comparison: field name as typed, operator, value, whether the value was quoted.
    Term {
        field: String,
        op: Op,
        value: String,
        quoted: bool,
        at: usize,
    },
    /// A bare word or quoted phrase.
    Word {
        text: String,
        at: usize,
    },
}

/// A parsed query.
#[derive(Debug, Clone, PartialEq)]
pub struct Query(Node);

#[derive(Debug, Clone, PartialEq)]
enum Node {
    And(Vec<Node>),
    Or(Vec<Node>),
    Not(Box<Node>),
    Word(String),
    Term { field: String, op: Op, value: String, quoted: bool },
}

fn invalid(msg: String) -> Error {
    Error::InvalidInput(format!("filter: {msg}"))
}

/// Characters a bare word or an unquoted value stops at.
fn ends_word(c: char) -> bool {
    c.is_whitespace() || c == '(' || c == ')'
}

/// A field name as typed: a letter, then letters, digits, `.`, `-` and `_`.
fn field_like(s: &str) -> bool {
    let mut cs = s.chars();
    matches!(cs.next(), Some(c) if c.is_ascii_alphabetic())
        && cs.all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_'))
}

/// Reads a double-quoted string starting at byte `start` (the opening quote). Returns the text
/// and the byte after the closing quote.
fn quoted(s: &str, start: usize) -> Result<(String, usize)> {
    let mut out = String::new();
    let mut it = s[start + 1..].char_indices();
    while let Some((i, c)) = it.next() {
        match c {
            '"' => return Ok((out, start + 1 + i + 1)),
            '\\' => match it.next() {
                Some((_, e @ ('"' | '\\'))) => out.push(e),
                Some((_, e)) => {
                    out.push('\\');
                    out.push(e);
                }
                None => break,
            },
            c => out.push(c),
        }
    }
    Err(invalid(format!("the quote at position {} isn't closed", pos(s, start))))
}

/// Where byte `i` of `s` is, for messages: its character count from 1.
fn pos(s: &str, i: usize) -> usize {
    s[..i].chars().count() + 1
}

/// The end (exclusive) of an unquoted run starting at `start`.
fn run_end(s: &str, start: usize) -> usize {
    s[start..].char_indices().find(|&(_, c)| ends_word(c)).map(|(i, _)| start + i).unwrap_or(s.len())
}

fn tokenize(s: &str) -> Result<Vec<Token>> {
    let mut out = Vec::new();
    let mut i = 0;
    while i < s.len() {
        let c = s[i..].chars().next().unwrap();
        if c.is_whitespace() {
            i += c.len_utf8();
            continue;
        }
        match c {
            '(' => {
                out.push(Token::Open);
                i += 1;
                continue;
            }
            ')' => {
                out.push(Token::Close);
                i += 1;
                continue;
            }
            '"' => {
                let (text, next) = quoted(s, i)?;
                out.push(Token::Word { text, at: pos(s, i) });
                i = next;
                continue;
            }
            _ => {}
        }
        // A field comparison: a field-like name followed by an operator.
        let name_end = s[i..]
            .char_indices()
            .find(|&(_, c)| !(c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_')))
            .map(|(k, _)| i + k)
            .unwrap_or(s.len());
        let name = &s[i..name_end];
        let op = OPS.iter().find(|(t, _)| s[name_end..].starts_with(t));
        let lower_name = name.to_ascii_lowercase();
        let header_like = lower_name.starts_with("req.header.") || lower_name.starts_with("resp.header.");
        if header_like && op.is_none() && s[name_end..].chars().next().is_some_and(|c| !ends_word(c)) {
            return Err(invalid(format!(
                "the header name at position {} may only use letters, digits, '-', '_' and '.' here; use \
                 req.headers or resp.headers to search for others",
                pos(s, i)
            )));
        }
        if let (true, Some(&(op_text, op))) = (field_like(name), op) {
            let after = name_end + op_text.len();
            // `https://…` and `app.test:8443` are text to search, not fields. A dotted name is a
            // field only under req. or resp., where a typo is still refused.
            let lower = name.to_ascii_lowercase();
            let url_like = (op == Op::Has && s[after..].starts_with("//"))
                || (field(name).is_none()
                    && lower.contains('.')
                    && !lower.starts_with("req.")
                    && !lower.starts_with("resp."));
            if !url_like {
                if field(name).is_none() {
                    return Err(invalid(format!(
                        "unknown field {name:?} at position {} (fields: {}); put text in quotes to search for it",
                        pos(s, i),
                        FIELDS.iter().map(|(f, _)| *f).collect::<Vec<_>>().join(", ")
                    )));
                }
                let (value, quoted_value, next) = if s[after..].starts_with('"') {
                    let (v, n) = quoted(s, after)?;
                    (v, true, n)
                } else {
                    let end = run_end(s, after);
                    (s[after..end].to_string(), false, end)
                };
                if value.is_empty() && !quoted_value {
                    return Err(invalid(format!("{name}{op_text} at position {} needs a value", pos(s, i))));
                }
                out.push(Token::Term { field: name.to_string(), op, value, quoted: quoted_value, at: pos(s, i) });
                i = next;
                continue;
            }
        }
        let end = run_end(s, i);
        let word = &s[i..end];
        // Keywords in any case: `a or b` must not quietly search for the word "or". Quote one to
        // search for it.
        out.push(match word.to_ascii_uppercase().as_str() {
            "AND" => Token::And,
            "OR" => Token::Or,
            "NOT" => Token::Not,
            _ => Token::Word { text: word.to_string(), at: pos(s, i) },
        });
        i = end;
    }
    Ok(out)
}

struct Parser {
    tokens: Vec<Token>,
    pos: usize,
    terms: usize,
}

impl Parser {
    fn peek(&self) -> Option<&Token> {
        self.tokens.get(self.pos)
    }

    fn or(&mut self, depth: usize) -> Result<Node> {
        let mut parts = vec![self.and(depth)?];
        while self.peek() == Some(&Token::Or) {
            self.pos += 1;
            parts.push(self.and(depth)?);
        }
        Ok(if parts.len() == 1 { parts.pop().unwrap() } else { Node::Or(parts) })
    }

    fn and(&mut self, depth: usize) -> Result<Node> {
        let mut parts = vec![self.unary(depth)?];
        loop {
            match self.peek() {
                Some(Token::And) => {
                    self.pos += 1;
                    parts.push(self.unary(depth)?);
                }
                Some(Token::Or | Token::Close) | None => break,
                Some(_) => parts.push(self.unary(depth)?),
            }
        }
        Ok(if parts.len() == 1 { parts.pop().unwrap() } else { Node::And(parts) })
    }

    fn unary(&mut self, depth: usize) -> Result<Node> {
        if depth > MAX_DEPTH {
            return Err(invalid(format!("nested more than {MAX_DEPTH} deep")));
        }
        match self.tokens.get(self.pos).cloned() {
            Some(Token::Not) => {
                self.pos += 1;
                Ok(Node::Not(Box::new(self.unary(depth + 1)?)))
            }
            Some(Token::Open) => {
                self.pos += 1;
                let inner = self.or(depth + 1)?;
                if self.peek() != Some(&Token::Close) {
                    return Err(invalid("a '(' isn't closed".into()));
                }
                self.pos += 1;
                Ok(inner)
            }
            Some(Token::Word { text, .. }) => {
                self.pos += 1;
                self.count()?;
                Ok(Node::Word(text))
            }
            Some(Token::Term { field, op, value, quoted, at }) => {
                self.pos += 1;
                self.count()?;
                check_term(&field, op, &value, quoted, at)?;
                Ok(Node::Term { field, op, value, quoted })
            }
            Some(Token::Close) => Err(invalid("a ')' has no '(' before it".into())),
            Some(Token::And) => Err(invalid("AND needs a term on each side".into())),
            Some(Token::Or) => Err(invalid("OR needs a term on each side".into())),
            None => Err(invalid("the query ends where a term was expected".into())),
        }
    }

    fn count(&mut self) -> Result<()> {
        self.terms += 1;
        if self.terms > MAX_TERMS {
            return Err(invalid(format!("more than {MAX_TERMS} terms")));
        }
        Ok(())
    }
}

/// Whether `v` is an ISO-8601 date or date and time SQLite's date functions read: a day,
/// optionally a time with seconds and up to milliseconds (what is stored, and what julianday
/// keeps), optionally `Z` or an offset.
fn is_time(v: &str) -> bool {
    static RE: std::sync::OnceLock<regex::Regex> = std::sync::OnceLock::new();
    let re = RE.get_or_init(|| {
        regex::Regex::new(
            r"^(\d{4})-(\d{2})-(\d{2})(?:[T ](\d{2}):(\d{2})(?::(\d{2})(?:\.\d{1,3})?)?)?(?:Z|[+-](\d{2}):(\d{2}))?$",
        )
        .expect("valid regex")
    });
    let Some(c) = re.captures(v) else { return false };
    let n = |i: usize| c.get(i).map_or(0, |m| m.as_str().parse::<u32>().unwrap_or(u32::MAX));
    let (year, month, day) = (n(1), n(2), n(3));
    let leap = year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
    let days = match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if leap => 29,
        2 => 28,
        _ => return false,
    };
    // A day that exists, and a time and offset that do (SQLite would read anything else as NULL).
    (1..=days).contains(&day) && n(4) < 24 && n(5) < 60 && n(6) < 60 && n(7) < 24 && n(8) < 60
}

/// Whether `v` is a status class such as `5xx`.
fn status_class(v: &str) -> Option<i64> {
    let b = v.as_bytes();
    (b.len() == 3 && (b'1'..=b'5').contains(&b[0]) && b[1..].eq_ignore_ascii_case(b"xx")).then(|| (b[0] - b'0') as i64)
}

/// `field:*`, unquoted: the field is present.
fn is_present(op: Op, value: &str, quoted: bool) -> bool {
    op == Op::Has && value == "*" && !quoted
}

/// Refuses operators a field can't take and values that can't be used, with the term's position.
fn check_term(name: &str, op: Op, value: &str, quoted: bool, at: usize) -> Result<()> {
    let (kind, _, _) = field(name).expect("tokenize accepts known fields only");
    let bad = |why: &str| invalid(format!("{name}{}{value} at position {at}: {why}", op.text()));
    if is_present(op, value, quoted) {
        return Ok(());
    }
    match kind {
        Kind::Number => {
            if matches!(op, Op::Regex | Op::NotRegex) {
                return Err(bad("a number takes =, !=, <, <=, > or >=, not a regex"));
            }
            let class = name.eq_ignore_ascii_case("status") && status_class(value).is_some();
            if class && !matches!(op, Op::Has | Op::Eq | Op::Ne) {
                return Err(bad("a status class takes :, = or !="));
            }
            if !class && value.parse::<i64>().is_err() {
                return Err(bad("expected a whole number"));
            }
        }
        Kind::Bytes => {
            if matches!(op, Op::Eq | Op::Ne | Op::Lt | Op::Le | Op::Gt | Op::Ge) {
                return Err(bad("bytes take : (contains), ~ or !~ (regex)"));
            }
        }
        Kind::Text | Kind::Tags => {
            if matches!(op, Op::Lt | Op::Le | Op::Gt | Op::Ge) {
                return Err(bad("text takes :, =, !=, ~ or !~"));
            }
            if kind == Kind::Tags && matches!(op, Op::Regex | Op::NotRegex) {
                return Err(bad("tags take : or ="));
            }
        }
        Kind::Time => {
            if matches!(op, Op::Regex | Op::NotRegex) {
                return Err(bad("a time takes :, =, !=, <, <=, > or >="));
            }
            if op != Op::Has && !is_time(value) {
                return Err(bad(
                    "expected a time such as 2026-11-08, 2026-11-08T12:00:00Z or 2026-11-08T12:00:00+01:00",
                ));
            }
        }
    }
    if matches!(op, Op::Regex | Op::NotRegex) && kind == Kind::Bytes {
        regex::bytes::RegexBuilder::new(value)
            .size_limit(REGEX_SIZE)
            .build()
            .map_err(|e| bad(&format!("not a valid regex ({e})")))?;
    } else if matches!(op, Op::Regex | Op::NotRegex) {
        RegexBuilder::new(value)
            .size_limit(REGEX_SIZE)
            .build()
            .map_err(|e| bad(&format!("not a valid regex ({e})")))?;
    }
    Ok(())
}

impl Query {
    /// Parses a query. A query that is empty or only whitespace is refused: the caller leaves
    /// the filter out instead.
    pub fn parse(s: &str) -> Result<Query> {
        if s.len() > MAX_LEN {
            return Err(invalid(format!("longer than {MAX_LEN} bytes")));
        }
        let tokens = tokenize(s)?;
        if tokens.is_empty() {
            return Err(invalid("the query is empty".into()));
        }
        let mut p = Parser { tokens, pos: 0, terms: 0 };
        let node = p.or(0)?;
        match p.peek() {
            None => Ok(Query(node)),
            Some(Token::Close) => Err(invalid("a ')' has no '(' before it".into())),
            Some(_) => Err(invalid("unexpected text after the query".into())),
        }
    }

    /// The query as a SQL condition on `history`. Its values are pushed onto `params`, and its
    /// placeholders are numbered after `first` others the statement binds before them (`?N`
    /// with N from `first + 1`).
    pub fn to_sql(&self, params: &mut Vec<Value>, first: usize) -> String {
        let start = params.len();
        node_sql(&self.0, &mut Binder { params, first, start })
    }
}

impl Query {
    /// Refuses a field whose value isn't known yet when a message is held at `stage` (a
    /// response's status, for a request), or is never known in flight (a history id), so a
    /// filter doesn't quietly never match. Bare words are fine at either stage: they search the
    /// URL and match the method, and the title too once there is a response.
    pub fn check_known(&self, stage: Stage) -> Result<()> {
        fn walk(n: &Node, stage: Stage) -> Result<()> {
            match n {
                Node::And(parts) | Node::Or(parts) => parts.iter().try_for_each(|p| walk(p, stage)),
                Node::Not(inner) => walk(inner, stage),
                Node::Word(_) => Ok(()),
                Node::Term { field, .. } => match (known(field), stage) {
                    (Known::Request, _) | (Known::Response, Stage::Response) => Ok(()),
                    (Known::Never(why), _) => {
                        Err(invalid(format!("{field} can't pick which messages are held: {why}")))
                    }
                    (Known::Response, Stage::Request) => {
                        let instead = if field.eq_ignore_ascii_case("body") { " (req.body is)" } else { "" };
                        Err(invalid(format!(
                            "{field} isn't known when a request or a WebSocket message is held: it comes with \
                             the response{instead}. Hold only responses (--responses, without --requests, \
                             --ws-to-server or --ws-to-client) to filter on it"
                        )))
                    }
                },
            }
        }
        walk(&self.0, stage)
    }
}

/// Values a [`Capture`] doesn't hold as such but its history row does, as
/// [`crate::store`]'s insert works them out.
struct Derived<'a> {
    resp_body_length: Option<i64>,
    tags: String,
    origin: &'a str,
    none: Option<i64>,
}

impl<'a> Derived<'a> {
    fn of(c: &'a Capture) -> Self {
        Derived {
            resp_body_length: c.resp_body.as_ref().map(|b| b.len() as i64),
            tags: serde_json::to_string(&c.tags).unwrap_or_else(|_| "[]".into()),
            origin: c.origin.as_deref().unwrap_or(crate::provenance::origin()),
            none: None,
        }
    }
}

/// The one-row `history` [`Matcher`] asks about: each column the filter language reads, with
/// its value from `c` as the history row would have it. `time` is the time of the match.
fn in_flight_row<'a>(c: &'a Capture, d: &'a Derived<'a>) -> [(&'static str, &'a dyn ToSql); 27] {
    [
        ("id", &d.none),
        ("source", &c.source),
        ("scheme", &c.scheme),
        ("host", &c.host),
        ("port", &c.port),
        ("method", &c.method),
        ("url", &c.url),
        ("path", &c.path),
        ("query", &c.query),
        ("req_headers", &c.req_headers),
        ("req_content_type", &c.req_content_type),
        ("req_body", &c.req_body),
        ("status", &c.status),
        ("resp_headers", &c.resp_headers),
        ("resp_content_type", &c.resp_content_type),
        ("resp_body", &c.resp_body),
        ("resp_body_length", &d.resp_body_length),
        ("title", &c.title),
        ("duration_ms", &c.duration_ms),
        ("error", &c.error),
        ("note", &d.none),
        ("tags", &d.tags),
        ("request", &c.request),
        ("response", &c.response),
        ("origin", &d.origin),
        ("client_addr", &c.client_addr),
        ("sni", &c.sni),
    ]
}

/// A query matched against messages in flight (the proxy's intercept), with the same SQL
/// [`Query::to_sql`] gives `history list --filter`, run on an in-memory connection over a
/// one-row `history` made from the exchange. The same SQL means the same answers: case, NUL
/// bytes, missing values and regexes behave as they do on recorded rows.
pub struct Matcher {
    sql: String,
    params: Vec<Value>,
    /// Connections not in use. Each match takes one (or opens one) and puts it back, so matches
    /// on different connections of the proxy don't wait for each other.
    idle: Mutex<Vec<Connection>>,
}

/// The most idle connections kept; more are opened while matches run side by side.
const IDLE_CONNECTIONS: usize = 8;

impl std::fmt::Debug for Matcher {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Matcher").field("sql", &self.sql).finish_non_exhaustive()
    }
}

impl Matcher {
    pub fn new(query: &Query) -> Result<Matcher> {
        let names = in_flight_row(&Capture::default(), &Derived::of(&Capture::default())).map(|(name, _)| name);
        let mut params = Vec::new();
        let cond = query.to_sql(&mut params, names.len());
        let cols: Vec<String> = names.iter().enumerate().map(|(i, c)| format!("?{} AS {c}", i + 1)).collect();
        let sql = format!(
            "SELECT coalesce(({cond}), 0) FROM (SELECT strftime('%Y-%m-%dT%H:%M:%fZ', 'now') AS time, {}) AS history",
            cols.join(", ")
        );
        let conn = Self::open()?;
        conn.prepare_cached(&sql)?;
        Ok(Matcher { sql, params, idle: Mutex::new(vec![conn]) })
    }

    fn open() -> Result<Connection> {
        let conn = Connection::open_in_memory()?;
        crate::store::register_functions(&conn)?;
        Ok(conn)
    }

    /// Whether the exchange `c` matches. A request on its way out has no response yet: its
    /// response fields are NULL, which [`Query::check_known`] keeps a filter from asking about.
    pub fn matches(&self, c: &Capture) -> Result<bool> {
        let derived = Derived::of(c);
        let row = in_flight_row(c, &derived).map(|(_, v)| v);
        let params = row.into_iter().chain(self.params.iter().map(|v| v as &dyn ToSql));
        let idle = || self.idle.lock().unwrap_or_else(|e| e.into_inner());
        let taken = idle().pop();
        let conn = match taken {
            Some(conn) => conn,
            None => Self::open()?,
        };
        let hit = conn
            .prepare_cached(&self.sql)
            .and_then(|mut stmt| stmt.query_row(rusqlite::params_from_iter(params), |r| r.get::<_, i64>(0)));
        let mut pool = idle();
        if pool.len() < IDLE_CONNECTIONS {
            pool.push(conn);
        }
        Ok(hit? != 0)
    }
}

/// Collects a statement's values and numbers their placeholders.
struct Binder<'a> {
    params: &'a mut Vec<Value>,
    first: usize,
    /// How many values `params` held before this query's.
    start: usize,
}

impl Binder<'_> {
    /// A placeholder for `v`, bound as the next parameter.
    fn bind(&mut self, v: Value) -> String {
        self.params.push(v);
        format!("?{}", self.first + self.params.len() - self.start)
    }

    fn text(&mut self, v: &str) -> String {
        self.bind(Value::Text(v.to_string()))
    }
}

/// `expr` contains `p`, ASCII letters in any case. instr reads every byte, where LIKE would stop
/// at a NUL in a binary body.
fn contains(expr: &str, p: &str) -> String {
    format!("instr(lower({expr}), lower({p})) > 0")
}

fn node_sql(n: &Node, b: &mut Binder) -> String {
    match n {
        Node::And(parts) => {
            format!("({})", parts.iter().map(|p| node_sql(p, b)).collect::<Vec<_>>().join(" AND "))
        }
        Node::Or(parts) => format!("({})", parts.iter().map(|p| node_sql(p, b)).collect::<Vec<_>>().join(" OR ")),
        Node::Not(inner) => format!("(NOT {})", node_sql(inner, b)),
        Node::Word(w) => {
            let p = b.text(w);
            format!("coalesce(({} OR {} OR method = upper({p})), 0)", contains("url", &p), contains("title", &p))
        }
        Node::Term { field: name, op, value, quoted } => {
            let (kind, expr, header) = field(name).expect("parse accepts known fields only");
            let cond = match header {
                Some(h) => header_sql(expr, &h, *op, value, *quoted, name, b),
                None => term_sql(kind, expr, *op, value, *quoted, name, b),
            };
            format!("coalesce(({cond}), 0)")
        }
    }
}

/// A header term over every header of that name in `cols` (a JSON array of [name, value]):
/// a repeated header such as Set-Cookie matches when any of its values does, a negation when
/// none does, and `:*` when the header is there, even empty.
fn header_sql(cols: &str, h: &str, op: Op, value: &str, quoted: bool, name: &str, b: &mut Binder) -> String {
    let wanted = b.text(h);
    let named = format!("lower(json_extract(value, '$[0]')) = {wanted}");
    if is_present(op, value, quoted) {
        return format!("EXISTS (SELECT 1 FROM json_each({cols}) WHERE {named})");
    }
    let v = "json_extract(value, '$[1]')";
    let (negate, positive) = match op {
        Op::Ne => (true, Op::Eq),
        Op::NotRegex => (true, Op::Regex),
        other => (false, other),
    };
    let cond = term_sql(Kind::Text, v, positive, value, quoted, name, b);
    let exists = format!("EXISTS (SELECT 1 FROM json_each({cols}) WHERE {named} AND coalesce(({cond}), 0))");
    if negate {
        format!("NOT {exists}")
    } else {
        exists
    }
}

fn term_sql(kind: Kind, expr: &str, op: Op, value: &str, quoted: bool, name: &str, b: &mut Binder) -> String {
    // `body` is either body: each comparison is made on both and either may match.
    if expr == "body" {
        let req = term_sql(kind, "req_body", op, value, quoted, name, b);
        let resp = term_sql(kind, "resp_body", op, value, quoted, name, b);
        let either = format!("coalesce(({req}), 0) OR coalesce(({resp}), 0)");
        // A negation means neither matches.
        return if matches!(op, Op::NotRegex) {
            format!("coalesce(({req}), 0) AND coalesce(({resp}), 0)")
        } else {
            either
        };
    }
    if is_present(op, value, quoted) {
        return match kind {
            Kind::Number | Kind::Time => format!("{expr} IS NOT NULL"),
            Kind::Tags => format!("json_array_length({expr}) > 0"),
            Kind::Text | Kind::Bytes => format!("length({expr}) > 0"),
        };
    }
    match kind {
        Kind::Number => {
            if let Some(class) = status_class(value) {
                let lo = b.bind(Value::Integer(class * 100));
                let hi = b.bind(Value::Integer(class * 100 + 99));
                let within = format!("{expr} BETWEEN {lo} AND {hi}");
                return if op == Op::Ne { format!("NOT coalesce(({within}), 0)") } else { within };
            }
            let n = b.bind(Value::Integer(value.parse().expect("checked when parsed")));
            match op {
                Op::Has | Op::Eq => format!("{expr} = {n}"),
                Op::Ne => format!("NOT coalesce(({expr} = {n}), 0)"),
                Op::Lt => format!("{expr} < {n}"),
                Op::Le => format!("{expr} <= {n}"),
                Op::Gt => format!("{expr} > {n}"),
                Op::Ge => format!("{expr} >= {n}"),
                Op::Regex | Op::NotRegex => unreachable!("refused when parsed"),
            }
        }
        Kind::Time => {
            let v = b.text(value);
            match op {
                // A prefix, such as a day; the rest compare as instants, so a stored fraction of a
                // second or a given offset doesn't throw the order off.
                Op::Has => format!("substr({expr}, 1, length({v})) = replace({v}, ' ', 'T')"),
                Op::Eq => format!("julianday({expr}) = julianday({v})"),
                Op::Ne => format!("NOT coalesce((julianday({expr}) = julianday({v})), 0)"),
                Op::Lt => format!("julianday({expr}) < julianday({v})"),
                Op::Le => format!("julianday({expr}) <= julianday({v})"),
                Op::Gt => format!("julianday({expr}) > julianday({v})"),
                Op::Ge => format!("julianday({expr}) >= julianday({v})"),
                Op::Regex | Op::NotRegex => unreachable!("refused when parsed"),
            }
        }
        Kind::Tags => {
            let each = match op {
                Op::Has => contains("value", &b.text(value)),
                _ => format!("value = {}", b.text(value)),
            };
            let exists = format!("EXISTS (SELECT 1 FROM json_each({expr}) WHERE {each})");
            if op == Op::Ne {
                format!("NOT {exists}")
            } else {
                exists
            }
        }
        Kind::Bytes if matches!(op, Op::Regex | Op::NotRegex) => {
            // Over the bytes, so a body that isn't UTF-8 is still searched.
            let m = format!("regexp_bytes({}, {expr})", b.text(value));
            if op == Op::NotRegex {
                format!("NOT {m}")
            } else {
                m
            }
        }
        Kind::Text | Kind::Bytes => match op {
            Op::Has => contains(expr, &b.text(value)),
            Op::Eq => format!("lower({expr}) = lower({})", b.text(value)),
            Op::Ne => format!("NOT coalesce((lower({expr}) = lower({})), 0)", b.text(value)),
            Op::Regex => format!("regexp({}, {expr})", b.text(value)),
            Op::NotRegex => format!("NOT regexp({}, {expr})", b.text(value)),
            Op::Lt | Op::Le | Op::Gt | Op::Ge => {
                unreachable!("{name}: refused when parsed")
            }
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::http::Target;

    fn sql(q: &str) -> (String, Vec<Value>) {
        let mut params = Vec::new();
        let s = Query::parse(q).unwrap().to_sql(&mut params, 0);
        (s, params)
    }

    fn err(q: &str) -> String {
        Query::parse(q).unwrap_err().to_string()
    }

    #[test]
    fn terms_and_words() {
        let (s, p) = sql("status:5xx resp.body:\"stack trace\"");
        assert!(s.starts_with("(coalesce((status BETWEEN ?1 AND ?2), 0) AND "), "{s}");
        assert!(s.contains("instr(lower(resp_body), lower(?3)) > 0"), "{s}");
        assert_eq!(p, vec![Value::Integer(500), Value::Integer(599), Value::Text("stack trace".into())]);

        let (s, p) = sql("login");
        assert!(s.contains("instr(lower(url), lower(?1))") && s.contains("method = upper(?1)"), "{s}");
        assert_eq!(p, vec![Value::Text("login".into())]);
    }

    #[test]
    fn keywords_in_any_case() {
        let q = Query::parse("a or b and not c").unwrap();
        assert_eq!(
            q.0,
            Node::Or(vec![
                Node::Word("a".into()),
                Node::And(vec![Node::Word("b".into()), Node::Not(Box::new(Node::Word("c".into())))])
            ])
        );
        assert_eq!(Query::parse("\"or\"").unwrap().0, Node::Word("or".into()));
    }

    #[test]
    fn placeholders_follow_the_statements_own() {
        let mut params = vec![Value::Integer(1)];
        let s = Query::parse("host:a status:2xx").unwrap().to_sql(&mut params, 3);
        assert!(s.contains("lower(?4)") && s.contains("BETWEEN ?5 AND ?6"), "{s}");
        assert_eq!(params.len(), 4, "pushed after what was there");
    }

    #[test]
    fn precedence() {
        // NOT binds tightest, then AND, then OR.
        let q = Query::parse("a OR b c NOT d").unwrap();
        assert_eq!(
            q.0,
            Node::Or(vec![
                Node::Word("a".into()),
                Node::And(vec![
                    Node::Word("b".into()),
                    Node::Word("c".into()),
                    Node::Not(Box::new(Node::Word("d".into())))
                ])
            ])
        );
        let q = Query::parse("(a OR b) AND c").unwrap();
        assert_eq!(
            q.0,
            Node::And(vec![Node::Or(vec![Node::Word("a".into()), Node::Word("b".into())]), Node::Word("c".into())])
        );
    }

    #[test]
    fn values_are_parameters_never_sql() {
        let (s, p) = sql("host:\"x' OR 1=1 --\" resp.header.server=\"a)b\"");
        assert!(!s.contains("1=1") && !s.contains("a)b"), "{s}");
        assert!(p.contains(&Value::Text("x' OR 1=1 --".into())));
        assert!(s.contains("json_each(resp_headers)") && s.contains("= ?2"), "{s}");
        assert_eq!(p[1], Value::Text("server".into()));
    }

    #[test]
    fn wildcards_are_plain_text() {
        let (s, p) = sql("path:\"100%_\\\\x\"");
        assert!(!s.contains("LIKE"), "{s}");
        assert_eq!(p[0], Value::Text("100%_\\x".into()));
    }

    #[test]
    fn urls_are_words_and_unknown_fields_are_refused() {
        assert_eq!(Query::parse("https://app.test/a").unwrap().0, Node::Word("https://app.test/a".into()));
        assert_eq!(Query::parse("app.test:8443").unwrap().0, Node::Word("app.test:8443".into()));
        assert!(err("resp.bdy:x").contains("unknown field \"resp.bdy\""));
        assert!(err("stauts:500").contains("unknown field \"stauts\""));
        assert_eq!(Query::parse("\"stauts:500\"").unwrap().0, Node::Word("stauts:500".into()));
    }

    #[test]
    fn operators_per_kind() {
        assert!(err("status~5").contains("not a regex"));
        assert!(err("status:abc").contains("whole number"));
        assert!(err("status>5xx").contains("status class"));
        assert!(err("body=x").contains("bytes take"));
        assert!(err("host>a").contains("text takes"));
        assert!(err("tag~a").contains("tags take"));
        assert!(err("url~\"(\"").contains("not a valid regex"));
        assert!(err("host:").contains("needs a value"));
        let (s, _) = sql("length>=1000 duration<5 id!=3");
        assert!(
            s.contains("resp_body_length >= ?1")
                && s.contains("duration_ms < ?2")
                && s.contains("NOT coalesce((id = ?3), 0)"),
            "{s}"
        );
        let (s, _) = sql("host:\"\"");
        assert!(s.contains("instr(lower(host), lower(?1))"), "{s}");
    }

    #[test]
    fn presence_and_headers() {
        let (s, p) = sql("req.header.authorization:*");
        assert!(
            s.contains("EXISTS (SELECT 1 FROM json_each(req_headers) WHERE lower(json_extract(value, '$[0]')) = ?1)"),
            "{s}"
        );
        assert_eq!(p, vec![Value::Text("authorization".into())]);
        let (s, p) = sql("url:\"*\"");
        assert!(s.contains("instr(lower(url), lower(?1))"), "{s}");
        assert_eq!(p[0], Value::Text("*".into()));
        assert!(err("req.header.:x").contains("unknown field"));
        // A header name the tokenizer can't read is refused, not searched as a word.
        assert!(err("req.header.a@b:x").contains("may only use letters"));
        assert!(err("req.header.x!foo:bar").contains("may only use letters"));
        assert_eq!(
            Query::parse("req.header.x-a_b.c:*").unwrap().0,
            Node::Term { field: "req.header.x-a_b.c".into(), op: Op::Has, value: "*".into(), quoted: false }
        );
    }

    #[test]
    fn times_are_checked_and_compared_as_instants() {
        for ok in ["2026-11-08", "2026-11-08T12:00", "2026-11-08T12:00:00Z", "2026-11-08 12:00:00.5+01:00"] {
            let (s, _) = sql(&format!("time>=\"{ok}\""));
            assert!(s.contains("julianday(time) >= julianday(?1)"), "{s}");
        }
        assert!(err("time>yesterday").contains("expected a time"));
        assert!(err("time<2026-11").contains("expected a time"));
        // A day or time that doesn't exist is refused, not matched as NULL.
        for bad in [
            "2026-11-31",
            "2026-02-29",
            "2026-13-01",
            "2026-11-08T24:00",
            "2026-11-08T12:60",
            "2026-11-08T12:00:00+25:00",
        ] {
            assert!(err(&format!("time>=\"{bad}\"")).contains("expected a time"), "{bad}");
        }
        assert!(Query::parse("time>=2024-02-29").is_ok(), "a leap day");
        assert!(err("time<2026-11-08T12:00:00.1234Z").contains("expected a time"), "finer than milliseconds");
        assert!(Query::parse("time<2026-11-08T12:00:00.123Z").is_ok());
        // A prefix takes any text, a space standing for the stored T.
        assert!(sql("time:2026-11").0.contains("substr(time, 1, length(?1)) = replace(?1, ' ', 'T')"));
    }

    #[test]
    fn byte_fields_take_byte_regexes() {
        assert!(sql("resp.body~\"(?-u:\\xff)\"").0.contains("regexp_bytes(?1, resp_body)"));
        assert!(err("url~\"(?-u:\\xff)\"").contains("not a valid regex"), "text fields are text");
    }

    #[test]
    fn positions_count_characters() {
        assert!(err("title:\"über\" stauts:1").contains("at position 14"), "{}", err("title:\"über\" stauts:1"));
    }

    #[test]
    fn every_field_has_a_stage() {
        for (name, _) in FIELDS {
            let name = name.replace("NAME", "x");
            assert_ne!(
                known(&name),
                Known::Never("it isn't known while a message is held"),
                "{name} isn't listed in known()"
            );
        }
        assert_eq!(known("REQ.HEADER.Cookie"), Known::Request);
        assert_eq!(known("resp.header.server"), Known::Response);
    }

    #[test]
    fn fields_unknown_at_hold_time_are_refused() {
        let check = |q: &str, stage| Query::parse(q).unwrap().check_known(stage);
        for q in ["host:a method=POST req.body:x req.header.cookie:* NOT path:/health", "login", "time:2026 client:127"]
        {
            check(q, Stage::Request).unwrap();
            check(q, Stage::Response).unwrap();
        }
        for q in
            ["status:5xx", "host:a OR (NOT resp.header.server:nginx)", "title:x", "length>1", "duration>1", "type:json"]
        {
            let e = check(q, Stage::Request).unwrap_err().to_string();
            assert!(e.contains("isn't known when a request") && e.contains("Hold only responses"), "{q}: {e}");
            check(q, Stage::Response).unwrap();
        }
        assert!(check("body:x", Stage::Request).unwrap_err().to_string().contains("(req.body is)"));
        for (q, why) in
            [("id>3", "history id"), ("note:x", "notes and tags"), ("tag=a", "notes and tags"), ("error:*", "no error")]
        {
            for stage in [Stage::Request, Stage::Response] {
                let e = check(q, stage).unwrap_err().to_string();
                assert!(e.contains("can't pick which messages are held") && e.contains(why), "{q}: {e}");
            }
        }
    }

    fn exchange(request: &str, response: Option<&str>) -> Capture {
        let target = Target { scheme: "https".into(), host: "app.test".into(), port: 443 };
        Capture::new("proxy", &target, request.as_bytes(), response.map(str::as_bytes), Some(12), None)
    }

    #[test]
    fn in_flight_matches_as_history_list_does() {
        let get = "GET /login?next=%2F HTTP/1.1\r\nHost: app.test\r\nCookie: a=1\r\nX-Dup: one\r\nX-Dup: two\r\n\r\n";
        let post = "POST /api/items HTTP/1.1\r\nHost: app.test\r\nContent-Type: application/json\r\nContent-Length: 10\r\n\r\n{\"n\":\"\u{0}x\"}";
        let ok = "HTTP/1.1 200 OK\r\nServer: nginx\r\nContent-Type: text/html\r\nContent-Length: 34\r\n\r\n<html><title>Sign in</title></html>";
        let boom = "HTTP/1.1 500 Internal Server Error\r\nContent-Length: 11\r\n\r\nstack trace";
        let exchanges =
            [exchange(get, None), exchange(post, None), exchange(get, Some(ok)), exchange(post, Some(boom))];
        let store = crate::store::Store::open_in_memory().unwrap();
        let ids: Vec<i64> = exchanges.iter().map(|c| store.record(c).unwrap()).collect();
        let queries = [
            "login",
            "LOGIN",
            "post",
            "\"sign in\"",
            "host:app.test method=post",
            "path:/api NOT method=GET",
            "query:next url~\"^https://app\\\\.test/login\"",
            "port=443 scheme=https source=proxy",
            "req.header.cookie:*",
            "req.header.x-dup=two",
            "req.header.x-dup!=one",
            "NOT req.header.cookie:*",
            "req.body:x req.type:json req.length=10",
            "req~\"\\\\x00\"",
            "req.headers:cookie",
            "status:5xx",
            "status!=200",
            "NOT status:200",
            "resp.body:\"stack trace\" OR title:sign",
            "resp.header.server~\"(?i)NGINX\"",
            "type:html length>10 duration<100",
            "body:x",
            "resp:nginx",
            "time:2",
            "origin:*",
            "client:*",
            "sni:*",
        ];
        let mut seen = std::collections::HashMap::new();
        for q in queries {
            let query = Query::parse(q).unwrap();
            let listed: Vec<i64> = store
                .list(&crate::store::HistoryFilter { filter: Some(q.into()), ..Default::default() })
                .unwrap()
                .iter()
                .map(|e| e.id)
                .collect();
            let m = Matcher::new(&query).unwrap();
            let matched: Vec<i64> =
                ids.iter().zip(&exchanges).filter(|(_, c)| m.matches(c).unwrap()).map(|(id, _)| *id).collect();
            assert_eq!(matched, listed, "{q}");
            seen.insert(q, matched);
        }
        // The cases above pick different rows, not all or none.
        assert_eq!(seen["status:5xx"], [ids[3]]);
        assert_eq!(seen["login"], [ids[0], ids[2]]);
        assert_eq!(seen["\"sign in\""], [ids[2]]);
        assert_eq!(seen["req.body:x req.type:json req.length=10"], [ids[1], ids[3]]);
        assert_eq!(seen["NOT status:200"], [ids[0], ids[1], ids[3]], "no response is no status");
        assert_eq!(seen["req.header.x-dup=two"], [ids[0], ids[2]]);
    }

    #[test]
    fn in_flight_matcher_is_shared_across_threads() {
        let m = std::sync::Arc::new(Matcher::new(&Query::parse("method=POST").unwrap()).unwrap());
        let post = exchange("POST / HTTP/1.1\r\nHost: app.test\r\n\r\n", None);
        let get = exchange("GET / HTTP/1.1\r\nHost: app.test\r\n\r\n", None);
        std::thread::scope(|s| {
            for _ in 0..4 {
                s.spawn(|| {
                    for _ in 0..50 {
                        assert!(m.matches(&post).unwrap() && !m.matches(&get).unwrap());
                    }
                });
            }
        });
    }

    #[test]
    fn structure_errors() {
        assert!(err("").contains("empty"));
        assert!(err("(a").contains("isn't closed"));
        assert!(err("a)").contains("no '('"));
        assert!(err("a AND").contains("ends where a term"));
        assert!(err("OR a").contains("OR needs"));
        assert!(err("\"open").contains("isn't closed"));
        assert!(err(&"(".repeat(40)).contains("nested"));
        assert!(err(&"a ".repeat(70)).contains("terms"));
        assert!(err(&"a".repeat(MAX_LEN + 1)).contains("longer"));
    }
}
