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
//! `AND`, `OR`, `NOT` and parentheses combine them (`NOT` binds tightest, then `AND`, then
//! `OR`). Values with spaces or special characters go in double quotes, with `\"` and `\\`.
//!
//! Every value is bound as a parameter, and field names map to fixed column expressions, so
//! nothing typed becomes SQL. Each term is coalesced to 0 or 1, so `NOT status:500` keeps the
//! requests that got no response at all.

use regex::RegexBuilder;
use rusqlite::types::Value;

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

/// The column expression and kind of a field, with the header name for `*.header.NAME`.
fn field(name: &str) -> Option<(Kind, &'static str, Option<String>)> {
    let lower = name.to_ascii_lowercase();
    for (prefix, cols) in [("req.header.", "req_headers"), ("resp.header.", "resp_headers")] {
        if let Some(h) = lower.strip_prefix(prefix) {
            if h.is_empty() || !h.bytes().all(is_token_byte) {
                return None;
            }
            let expr = if cols == "req_headers" { "header(req_headers, {h})" } else { "header(resp_headers, {h})" };
            return Some((Kind::Text, expr, Some(h.to_string())));
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
    Err(invalid(format!("the quote at position {} isn't closed", start + 1)))
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
                out.push(Token::Word { text, at: i + 1 });
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
                        i + 1,
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
                    return Err(invalid(format!("{name}{op_text} at position {} needs a value", i + 1)));
                }
                out.push(Token::Term { field: name.to_string(), op, value, quoted: quoted_value, at: i + 1 });
                i = next;
                continue;
            }
        }
        let end = run_end(s, i);
        let word = &s[i..end];
        out.push(match word {
            "AND" => Token::And,
            "OR" => Token::Or,
            "NOT" => Token::Not,
            _ => Token::Word { text: word.to_string(), at: i + 1 },
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
        }
    }
    if matches!(op, Op::Regex | Op::NotRegex) {
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

    /// The query as a SQL condition on `history`, with `?N` placeholders numbered from
    /// `params.len() + 1`; the values are pushed onto `params`.
    pub fn to_sql(&self, params: &mut Vec<Value>) -> String {
        node_sql(&self.0, params)
    }
}

/// A placeholder for `v`, bound as the next parameter.
fn bind(params: &mut Vec<Value>, v: Value) -> String {
    params.push(v);
    format!("?{}", params.len())
}

/// `%v%` for LIKE, with the LIKE wildcards in `v` escaped by `\`.
fn like_pattern(v: &str) -> String {
    let mut out = String::with_capacity(v.len() + 2);
    out.push('%');
    for c in v.chars() {
        if matches!(c, '%' | '_' | '\\') {
            out.push('\\');
        }
        out.push(c);
    }
    out.push('%');
    out
}

fn node_sql(n: &Node, params: &mut Vec<Value>) -> String {
    match n {
        Node::And(parts) => {
            format!("({})", parts.iter().map(|p| node_sql(p, params)).collect::<Vec<_>>().join(" AND "))
        }
        Node::Or(parts) => format!("({})", parts.iter().map(|p| node_sql(p, params)).collect::<Vec<_>>().join(" OR ")),
        Node::Not(inner) => format!("(NOT {})", node_sql(inner, params)),
        Node::Word(w) => {
            let p = bind(params, Value::Text(like_pattern(w)));
            let m = bind(params, Value::Text(w.clone()));
            format!("coalesce((url LIKE {p} ESCAPE '\\' OR title LIKE {p} ESCAPE '\\' OR method = upper({m})), 0)")
        }
        Node::Term { field: name, op, value, quoted } => {
            let (kind, expr, header) = field(name).expect("parse accepts known fields only");
            let expr = match header {
                Some(h) => expr.replace("{h}", &bind(params, Value::Text(h))),
                None => expr.to_string(),
            };
            format!("coalesce(({}), 0)", term_sql(kind, &expr, *op, value, *quoted, name, params))
        }
    }
}

fn term_sql(kind: Kind, expr: &str, op: Op, value: &str, quoted: bool, name: &str, params: &mut Vec<Value>) -> String {
    // `body` is either body: each comparison is made on both and either may match.
    if expr == "body" {
        let req = term_sql(kind, "req_body", op, value, quoted, name, params);
        let resp = term_sql(kind, "resp_body", op, value, quoted, name, params);
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
                let lo = bind(params, Value::Integer(class * 100));
                let hi = bind(params, Value::Integer(class * 100 + 99));
                let within = format!("{expr} BETWEEN {lo} AND {hi}");
                return if op == Op::Ne { format!("NOT coalesce(({within}), 0)") } else { within };
            }
            let n = bind(params, Value::Integer(value.parse().expect("checked when parsed")));
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
            let v = bind(params, Value::Text(value.to_string()));
            match op {
                Op::Has => format!("substr({expr}, 1, length({v})) = {v}"),
                Op::Eq => format!("{expr} = {v}"),
                Op::Ne => format!("NOT coalesce(({expr} = {v}), 0)"),
                Op::Lt => format!("{expr} < {v}"),
                Op::Le => format!("{expr} <= {v}"),
                Op::Gt => format!("{expr} > {v}"),
                Op::Ge => format!("{expr} >= {v}"),
                Op::Regex | Op::NotRegex => unreachable!("refused when parsed"),
            }
        }
        Kind::Tags => {
            let each = match op {
                Op::Has => format!("value LIKE {} ESCAPE '\\'", bind(params, Value::Text(like_pattern(value)))),
                _ => format!("value = {}", bind(params, Value::Text(value.to_string()))),
            };
            let exists = format!("EXISTS (SELECT 1 FROM json_each({expr}) WHERE {each})");
            if op == Op::Ne {
                format!("NOT {exists}")
            } else {
                exists
            }
        }
        Kind::Text | Kind::Bytes => match op {
            Op::Has => format!("{expr} LIKE {} ESCAPE '\\'", bind(params, Value::Text(like_pattern(value)))),
            Op::Eq => format!("lower({expr}) = lower({})", bind(params, Value::Text(value.to_string()))),
            Op::Ne => {
                format!("NOT coalesce((lower({expr}) = lower({})), 0)", bind(params, Value::Text(value.to_string())))
            }
            Op::Regex => format!("regexp({}, {expr})", bind(params, Value::Text(value.to_string()))),
            Op::NotRegex => format!("NOT regexp({}, {expr})", bind(params, Value::Text(value.to_string()))),
            Op::Lt | Op::Le | Op::Gt | Op::Ge => {
                unreachable!("{name}: refused when parsed")
            }
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sql(q: &str) -> (String, Vec<Value>) {
        let mut params = Vec::new();
        let s = Query::parse(q).unwrap().to_sql(&mut params);
        (s, params)
    }

    fn err(q: &str) -> String {
        Query::parse(q).unwrap_err().to_string()
    }

    #[test]
    fn terms_and_words() {
        let (s, p) = sql("status:5xx resp.body:\"stack trace\"");
        assert!(s.starts_with("(coalesce((status BETWEEN ?1 AND ?2), 0) AND "), "{s}");
        assert!(s.contains("resp_body LIKE ?3 ESCAPE"), "{s}");
        assert_eq!(p, vec![Value::Integer(500), Value::Integer(599), Value::Text("%stack trace%".into())]);

        let (s, p) = sql("login");
        assert!(s.contains("url LIKE ?1") && s.contains("method = upper(?2)"), "{s}");
        assert_eq!(p[0], Value::Text("%login%".into()));
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
        assert!(p.contains(&Value::Text("%x' OR 1=1 --%".into())));
        assert!(s.contains("header(resp_headers, ?2)"), "{s}");
        assert_eq!(p[1], Value::Text("server".into()));
    }

    #[test]
    fn like_wildcards_are_escaped() {
        let (_, p) = sql("path:\"100%_\\\\x\"");
        assert_eq!(p[0], Value::Text("%100\\%\\_\\\\x%".into()));
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
        assert!(s.contains("host LIKE ?1"), "{s}");
    }

    #[test]
    fn presence_and_headers() {
        let (s, p) = sql("req.header.authorization:*");
        assert!(s.contains("length(header(req_headers, ?1)) > 0"), "{s}");
        assert_eq!(p, vec![Value::Text("authorization".into())]);
        let (s, p) = sql("url:\"*\"");
        assert!(s.contains("url LIKE ?1"), "{s}");
        assert_eq!(p[0], Value::Text("%*%".into()));
        assert!(err("req.header.:x").contains("unknown field"));
        // A name with a character no field has is a bare word.
        assert_eq!(Query::parse("req.header.a@b:x").unwrap().0, Node::Word("req.header.a@b:x".into()));
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
