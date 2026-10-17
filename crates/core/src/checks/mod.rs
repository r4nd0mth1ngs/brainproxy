//! Declarative checks (docs/CHECKS.md; docs/RULE_UPDATES.md layer 3).
//!
//! One format: the HTTP subset of Nuclei templates, plus a few brainproxy
//! extensions (`scope`, `inject`, `info.confidence`, matcher part `baseline_body`),
//! so community templates and checks an agent writes load through the same parser.
//! A template using anything outside the subset is skipped with a reason, never
//! half-run. Checks run as active rules (`rule.rs`): every request goes through
//! `Cx`, so through the engagement scope guard, auth session, and rate limit.

mod dsl;
mod rule;
mod store;

use std::collections::{BTreeMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::LazyLock;

use regex::Regex;
use serde::Serialize;
use serde_json::Value;

use crate::error::{Error, Result};
use crate::scan::active::RuleScope;
use crate::scan::{Confidence, Risk};
pub use rule::into_rules;
pub use store::{local_dir, nuclei_dir, nuclei_status, update, Source, StoreStatus, UpdateResult};

/// Templates bigger than this are skipped.
const MAX_TEMPLATE: u64 = 512 << 10;
/// Payload combinations per request block (clusterbomb grows fast).
const MAX_COMBOS: usize = 1000;

#[derive(Debug, Clone, Serialize)]
pub struct Check {
    pub id: String,
    pub name: String,
    pub severity: String,
    #[serde(skip)]
    pub risk: Risk,
    #[serde(skip)]
    pub confidence: Confidence,
    #[serde(skip)]
    pub description: String,
    #[serde(skip)]
    pub remediation: String,
    #[serde(skip)]
    pub references: Vec<String>,
    #[serde(skip)]
    pub cwe: u32,
    pub tags: Vec<String>,
    pub scope: &'static str,
    pub requests: usize,
    pub file: PathBuf,
    #[serde(skip)]
    pub(crate) rule_scope: RuleScope,
    #[serde(skip)]
    pub(crate) variables: Vec<(String, String)>,
    #[serde(skip)]
    pub(crate) blocks: Vec<Block>,
    /// `flow:` as a boolean expression over `http(N)` (variables `__http_N`).
    #[serde(skip)]
    pub(crate) flow: Option<dsl::Expr>,
}

/// One entry of `http:` (a request block).
#[derive(Debug, Clone)]
pub(crate) struct Block {
    pub method: String,
    pub paths: Vec<String>,
    pub raws: Vec<String>,
    pub headers: Vec<(String, String)>,
    pub body: String,
    /// brainproxy extension: values for the attacked insertion point (scope: param).
    pub inject: Vec<String>,
    pub inject_raw: bool,
    pub payloads: Vec<(String, Vec<String>)>,
    pub attack: Attack,
    pub unsafe_raw: bool,
    pub redirects: bool,
    pub stop_at_first_match: bool,
    /// Matchers run once after all requests of a payload combination, seeing
    /// each response as numbered parts (`body_2`, `status_code_1`), like
    /// Nuclei's `req-condition` (set when numbered parts are used).
    pub req_condition: bool,
    pub matchers_and: bool,
    pub matchers: Vec<Matcher>,
    pub extractors: Vec<Extractor>,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub(crate) enum Attack {
    BatteringRam,
    Pitchfork,
    ClusterBomb,
}

#[derive(Debug, Clone, PartialEq)]
pub(crate) enum Part {
    Body,
    Header,
    All,
    /// One response header (Nuclei exposes `content_type` etc. as parts).
    Named(String),
    /// brainproxy extension: the baseline response body of the attacked request.
    BaselineBody,
    /// A part of the nth (1-based) response of the block (`body_2`).
    Nth(usize, Box<Part>),
}

#[derive(Debug, Clone)]
pub(crate) enum MatchKind {
    Word(Vec<String>),
    Regex(Regexes),
    Status(Vec<u16>),
    Size(Vec<usize>),
    Binary(Vec<Vec<u8>>),
    Dsl(Vec<dsl::Expr>),
}

#[derive(Debug, Clone)]
pub(crate) struct Matcher {
    pub kind: MatchKind,
    pub part: Part,
    pub and: bool,
    pub negative: bool,
    pub case_insensitive: bool,
    /// Counts for the block's result (and `flow`) but doesn't report a finding alone.
    pub internal: bool,
    pub name: Option<String>,
}

#[derive(Debug, Clone)]
pub(crate) enum ExtractKind {
    Regex(Regexes, usize),
    Kval(Vec<String>),
    Dsl(Vec<dsl::Expr>),
    Json(Vec<Vec<JsonStep>>),
}

/// A step of the jq path subset `json` extractors support.
#[derive(Debug, Clone, PartialEq)]
pub(crate) enum JsonStep {
    Key(String),
    Index(usize),
    /// `[]`: every element (or object value).
    Each,
}

/// Parses `.a.b`, `.a[0]`, `.["k"]`, `.[]`, and pipes of these (`.[] | .slug`).
fn compile_json_path(q: &str) -> Option<Vec<JsonStep>> {
    let mut steps = Vec::new();
    for part in q.split('|') {
        let b = part.trim().as_bytes();
        if b.first() != Some(&b'.') {
            return None;
        }
        let mut i = 0;
        while i < b.len() {
            match b[i] {
                b'.' if b.get(i + 1).is_some_and(|c| c.is_ascii_alphabetic() || *c == b'_') => {
                    let start = i + 1;
                    i = start;
                    while i < b.len() && (b[i].is_ascii_alphanumeric() || b[i] == b'_') {
                        i += 1;
                    }
                    steps.push(JsonStep::Key(String::from_utf8_lossy(&b[start..i]).into_owned()));
                }
                b'.' if i + 1 == b.len() || b[i + 1] == b'[' => i += 1,
                b'[' => {
                    let end = i + b[i..].iter().position(|c| *c == b']')?;
                    let inner = std::str::from_utf8(&b[i + 1..end]).ok()?.trim();
                    steps.push(if inner.is_empty() {
                        JsonStep::Each
                    } else if let Ok(n) = inner.parse() {
                        JsonStep::Index(n)
                    } else if inner.len() >= 2
                        && inner.starts_with('"')
                        && inner.ends_with('"')
                        && !inner[1..inner.len() - 1].contains(['"', '\\'])
                    {
                        JsonStep::Key(inner[1..inner.len() - 1].to_string())
                    } else {
                        return None;
                    });
                    i = end + 1;
                }
                _ => return None,
            }
        }
    }
    Some(steps)
}

/// Applies a json path; strings come out raw, other values as JSON (like `jq -r`).
pub(crate) fn json_path(root: &Value, steps: &[JsonStep]) -> Vec<String> {
    let mut cur = vec![root];
    for step in steps {
        cur = cur
            .into_iter()
            .flat_map(|v| -> Vec<&Value> {
                match (step, v) {
                    (JsonStep::Key(k), Value::Object(m)) => m.get(k).into_iter().collect(),
                    (JsonStep::Index(n), Value::Array(a)) => a.get(*n).into_iter().collect(),
                    (JsonStep::Each, Value::Array(a)) => a.iter().collect(),
                    (JsonStep::Each, Value::Object(m)) => m.values().collect(),
                    _ => vec![],
                }
            })
            .collect();
    }
    cur.into_iter()
        .filter(|v| !v.is_null())
        .map(|v| match v {
            Value::String(s) => s.clone(),
            v => v.to_string(),
        })
        .collect()
}

#[derive(Debug, Clone)]
pub(crate) struct Extractor {
    pub kind: ExtractKind,
    pub part: Part,
    pub name: Option<String>,
    pub internal: bool,
}

/// A template that was not loaded.
#[derive(Debug, Clone, Serialize)]
pub struct Skipped {
    pub file: PathBuf,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    /// "invalid" (not a usable template) or "unsupported" (outside the subset).
    pub kind: &'static str,
    pub reason: String,
}

#[derive(Debug, Default, Serialize)]
pub struct Loaded {
    pub checks: Vec<Check>,
    pub skipped: Vec<Skipped>,
}

impl Loaded {
    /// Skip reasons with counts, most common first (for bounded output).
    pub fn reasons(&self) -> Vec<(String, usize)> {
        let mut m: BTreeMap<&str, usize> = BTreeMap::new();
        for s in &self.skipped {
            *m.entry(s.reason.as_str()).or_default() += 1;
        }
        let mut v: Vec<(String, usize)> = m.into_iter().map(|(k, n)| (k.to_string(), n)).collect();
        v.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
        v
    }
}

enum Problem {
    Invalid(String),
    Unsupported(String),
}

fn invalid<T>(m: impl Into<String>) -> std::result::Result<T, Problem> {
    Err(Problem::Invalid(m.into()))
}

fn unsupported<T>(m: impl Into<String>) -> std::result::Result<T, Problem> {
    Err(Problem::Unsupported(m.into()))
}

/// Loads every `.yaml`/`.yml` under `paths` (files or directories, recursively).
/// Later templates with an id already loaded are skipped.
pub fn load(paths: &[PathBuf]) -> Result<Loaded> {
    let mut files = Vec::new();
    for p in paths {
        if p.is_dir() {
            walk(p, &mut files)?;
        } else if p.is_file() {
            files.push(p.clone());
        } else {
            return Err(Error::NotFound(format!("check file or directory {}", p.display())));
        }
    }
    // Parsing (YAML + regex compilation) dominates; spread it over the cores.
    let threads = std::thread::available_parallelism().map_or(4, |n| n.get()).min(16);
    let chunk = files.len().div_ceil(threads).max(1);
    let parsed: Vec<(PathBuf, Parsed)> = std::thread::scope(|sc| {
        let handles: Vec<_> = files
            .chunks(chunk)
            .map(|c| sc.spawn(move || c.iter().map(|f| (f.clone(), parse_file(f))).collect::<Vec<_>>()))
            .collect();
        handles.into_iter().flat_map(|h| h.join().unwrap_or_default()).collect()
    });
    let mut out = Loaded::default();
    let mut ids = HashSet::new();
    for (file, result) in parsed {
        let skip = |id: Option<String>, p: Problem| {
            let (kind, reason) = match p {
                Problem::Invalid(r) => ("invalid", r),
                Problem::Unsupported(r) => ("unsupported", r),
            };
            Skipped { file: file.clone(), id, kind, reason }
        };
        match result {
            Ok(c) if !ids.insert(c.id.clone()) => {
                out.skipped.push(skip(Some(c.id), Problem::Invalid("duplicate id".into())));
            }
            Ok(c) => out.checks.push(c),
            Err((id, p)) => out.skipped.push(skip(id, p)),
        }
    }
    Ok(out)
}

type Parsed = std::result::Result<Check, (Option<String>, Problem)>;

fn parse_file(file: &Path) -> Parsed {
    let bytes = match std::fs::metadata(file) {
        Ok(m) if m.len() > MAX_TEMPLATE => return Err((None, Problem::Invalid("file too large".into()))),
        Ok(_) => std::fs::read(file),
        Err(e) => Err(e),
    };
    match bytes {
        Ok(b) => parse(&String::from_utf8_lossy(&b), file),
        Err(e) => Err((None, Problem::Invalid(e.to_string()))),
    }
}

fn walk(dir: &Path, out: &mut Vec<PathBuf>) -> Result<()> {
    let mut entries: Vec<_> = std::fs::read_dir(dir)?.filter_map(|e| e.ok()).map(|e| e.path()).collect();
    entries.sort();
    for p in entries {
        let name = p.file_name().and_then(|n| n.to_str()).unwrap_or("");
        if name.starts_with('.') {
            continue;
        }
        if p.is_dir() {
            walk(&p, out)?;
        } else if name.ends_with(".yaml") || name.ends_with(".yml") {
            out.push(p);
        }
    }
    Ok(())
}

/// Parses one template.
pub fn parse_str(text: &str) -> Result<Check> {
    parse(text, Path::new("<inline>")).map_err(|(_, p)| match p {
        Problem::Invalid(r) => Error::InvalidInput(r),
        Problem::Unsupported(r) => Error::InvalidInput(format!("unsupported: {r}")),
    })
}

fn parse(text: &str, file: &Path) -> std::result::Result<Check, (Option<String>, Problem)> {
    let doc = crate::apiimport::parse_document(text).map_err(|e| (None, Problem::Invalid(e.to_string())))?;
    let id = doc.get("id").and_then(Value::as_str).map(str::to_string);
    compile(&doc, file).map_err(|p| (id, p))
}

const TOP_KEYS: &[&str] = &["id", "info", "http", "requests", "variables", "scope", "flow"];
const BLOCK_KEYS: &[&str] = &[
    "method",
    "path",
    "raw",
    "headers",
    "body",
    "payloads",
    "attack",
    "matchers",
    "matchers-condition",
    "extractors",
    "stop-at-first-match",
    "redirects",
    "host-redirects",
    "max-redirects",
    "unsafe",
    "cookie-reuse",
    "disable-cookie",
    "max-size",
    "read-all",
    "id",
    "name",
    "threads",
    "skip-variables-check",
    "inject",
    "inject-raw",
    "req-condition",
];

fn s(v: &Value) -> Option<String> {
    match v {
        Value::String(s) => Some(s.clone()),
        Value::Number(n) => Some(n.to_string()),
        Value::Bool(b) => Some(b.to_string()),
        _ => None,
    }
}

/// A string or a list of strings.
fn list(v: Option<&Value>) -> Vec<String> {
    match v {
        Some(Value::Array(a)) => a.iter().filter_map(s).collect(),
        Some(v) => s(v).into_iter().collect(),
        None => vec![],
    }
}

fn flag(v: &Value, key: &str) -> bool {
    match v.get(key) {
        Some(Value::Bool(b)) => *b,
        Some(Value::String(s)) => s == "true",
        _ => false,
    }
}

fn compile(doc: &Value, file: &Path) -> std::result::Result<Check, Problem> {
    let Some(obj) = doc.as_object() else { return invalid("not a mapping") };
    let Some(id) = obj.get("id").and_then(Value::as_str).map(str::to_string) else {
        return invalid("missing id");
    };
    if id.is_empty() || id.len() > 200 || id.chars().any(|c| c.is_control() || c.is_whitespace()) {
        return invalid("bad id");
    }
    for k in obj.keys() {
        if !TOP_KEYS.contains(&k.as_str()) {
            return unsupported(format!("top-level `{k}`"));
        }
    }
    let info = obj.get("info").cloned().unwrap_or(Value::Null);
    let name = info.get("name").and_then(s).unwrap_or_else(|| id.clone());
    let severity = info.get("severity").and_then(s).unwrap_or_else(|| "info".into()).to_ascii_lowercase();
    let risk = match severity.as_str() {
        "critical" | "high" => Risk::High,
        "medium" => Risk::Medium,
        "low" => Risk::Low,
        "info" | "unknown" => Risk::Info,
        other => return invalid(format!("unknown severity {other:?}")),
    };
    let confidence = match info.get("confidence").and_then(s).as_deref() {
        Some("low") => Confidence::Low,
        Some("high") | Some("confirmed") => Confidence::High,
        _ => Confidence::Medium,
    };
    let mut tags: Vec<String> =
        list(info.get("tags")).iter().flat_map(|t| t.split(',')).map(|t| t.trim().to_string()).collect();
    tags.retain(|t| !t.is_empty());
    let cwe = list(info.get("classification").and_then(|c| c.get("cwe-id")))
        .first()
        .and_then(|c| c.trim_start_matches(|ch: char| !ch.is_ascii_digit()).parse().ok())
        .unwrap_or(0);
    let (rule_scope, scope) = match obj.get("scope").and_then(Value::as_str).unwrap_or("host") {
        "host" => (RuleScope::Host, "host"),
        "request" => (RuleScope::Page, "request"),
        "param" => (RuleScope::Param, "param"),
        other => return invalid(format!("unknown scope {other:?} (host, request, param)")),
    };

    let mut variables = Vec::new();
    match obj.get("variables") {
        None => {}
        Some(Value::Object(m)) => {
            for (k, v) in m {
                let Some(v) = s(v) else { return unsupported("non-string variable") };
                variables.push((k.clone(), v));
            }
        }
        Some(_) => return invalid("variables must be a mapping"),
    }

    let blocks_v = match (obj.get("http"), obj.get("requests")) {
        (Some(Value::Array(a)), None) | (None, Some(Value::Array(a))) => a,
        (None, None) => return unsupported("no http requests"),
        _ => return invalid("http must be a list"),
    };
    let mut blocks = Vec::new();
    for b in blocks_v {
        blocks.push(compile_block(b, rule_scope)?);
    }
    if blocks.is_empty() {
        return invalid("no requests");
    }
    check_placeholders(&variables, &mut blocks)?;
    let flow = match obj.get("flow") {
        None => None,
        Some(f) => Some(compile_flow(&s(f).unwrap_or_default(), blocks.len())?),
    };

    let references = list(info.get("reference"));
    Ok(Check {
        id,
        name,
        severity,
        risk,
        confidence,
        description: info.get("description").and_then(s).unwrap_or_default().trim().to_string(),
        remediation: info.get("remediation").and_then(s).unwrap_or_default().trim().to_string(),
        references,
        cwe,
        tags,
        scope,
        requests: blocks.iter().map(|b| b.paths.len() + b.raws.len() + b.inject.len()).sum(),
        file: file.to_path_buf(),
        rule_scope,
        variables,
        blocks,
        flow,
    })
}

/// `flow: http(1) && (http(2) || http(3))`: `&&`, `||`, `!`, and parentheses
/// over request blocks; JavaScript flows are unsupported.
fn compile_flow(flow: &str, blocks: usize) -> std::result::Result<dsl::Expr, Problem> {
    static CALL: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\bhttp\s*\(\s*(\d+)\s*\)").unwrap());
    let js = || unsupported("flow (JavaScript)");
    let Ok(expr) = dsl::parse(&CALL.replace_all(flow, "__http_$1")) else { return js() };
    fn shape(e: &dsl::Expr, blocks: usize) -> bool {
        match e {
            dsl::Expr::Var(v) => v
                .strip_prefix("__http_")
                .and_then(|n| n.parse::<usize>().ok())
                .is_some_and(|n| (1..=blocks).contains(&n)),
            dsl::Expr::Not(e) => shape(e, blocks),
            dsl::Expr::Bin(dsl::Op::And | dsl::Op::Or, a, b) => shape(a, blocks) && shape(b, blocks),
            _ => false,
        }
    }
    if shape(&expr, blocks) {
        Ok(expr)
    } else {
        js()
    }
}

fn compile_block(b: &Value, scope: RuleScope) -> std::result::Result<Block, Problem> {
    let Some(obj) = b.as_object() else { return invalid("request block is not a mapping") };
    for k in obj.keys() {
        if !BLOCK_KEYS.contains(&k.as_str()) {
            return unsupported(format!("request `{k}`"));
        }
    }
    let method = b.get("method").and_then(s).unwrap_or_else(|| "GET".into()).to_ascii_uppercase();
    if method.is_empty() || !method.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'-' || c == b'_') {
        return invalid("bad method");
    }
    let paths = list(b.get("path"));
    let raws = list(b.get("raw"));
    let inject = list(b.get("inject"));
    match scope {
        RuleScope::Param if inject.is_empty() || !paths.is_empty() || !raws.is_empty() => {
            return invalid("scope: param blocks take `inject` values (no path/raw)")
        }
        RuleScope::Param => {}
        _ if !inject.is_empty() => return invalid("`inject` needs scope: param"),
        _ if paths.is_empty() && raws.is_empty() => return invalid("request block without path or raw"),
        _ => {}
    }
    if raws.iter().chain(&paths).any(|r| r.contains('§')) {
        return unsupported("§ payload markers");
    }
    let mut headers = Vec::new();
    if let Some(h) = b.get("headers") {
        let Some(m) = h.as_object() else { return invalid("headers must be a mapping") };
        for (k, v) in m {
            let v = s(v).unwrap_or_default();
            if k.is_empty() || k.contains([':', '\r', '\n']) || v.contains(['\r', '\n']) {
                return invalid("bad header");
            }
            headers.push((k.clone(), v));
        }
    }
    let mut payloads = Vec::new();
    if let Some(p) = b.get("payloads") {
        let Some(m) = p.as_object() else { return invalid("payloads must be a mapping") };
        for (k, v) in m {
            match v {
                Value::Array(a) => payloads.push((k.clone(), a.iter().filter_map(s).collect())),
                _ => return unsupported("payload files"),
            }
        }
    }
    let attack = match b.get("attack").and_then(Value::as_str).unwrap_or("batteringram") {
        "batteringram" => Attack::BatteringRam,
        "pitchfork" => Attack::Pitchfork,
        "clusterbomb" => Attack::ClusterBomb,
        other => return invalid(format!("unknown attack {other:?}")),
    };
    let block_combos = combos(&payloads, attack, MAX_COMBOS + 1).len();
    if block_combos > MAX_COMBOS {
        return unsupported(format!("more than {MAX_COMBOS} payload combinations"));
    }
    let matchers_and = match b.get("matchers-condition").and_then(Value::as_str).unwrap_or("or") {
        "and" => true,
        "or" => false,
        other => return invalid(format!("unknown matchers-condition {other:?}")),
    };
    let mut matchers = Vec::new();
    for m in b.get("matchers").and_then(Value::as_array).into_iter().flatten() {
        matchers.push(compile_matcher(m)?);
    }
    let mut extractors = Vec::new();
    for e in b.get("extractors").and_then(Value::as_array).into_iter().flatten() {
        extractors.push(compile_extractor(e)?);
    }
    if matchers.is_empty() && extractors.is_empty() {
        return invalid("request block without matchers or extractors");
    }
    Ok(Block {
        method,
        paths,
        raws,
        headers,
        body: b.get("body").and_then(s).unwrap_or_default(),
        inject,
        inject_raw: flag(b, "inject-raw"),
        payloads,
        attack,
        unsafe_raw: flag(b, "unsafe"),
        redirects: flag(b, "redirects") || flag(b, "host-redirects"),
        stop_at_first_match: flag(b, "stop-at-first-match"),
        req_condition: flag(b, "req-condition")
            || matchers
                .iter()
                .map(|m| &m.part)
                .chain(extractors.iter().map(|e| &e.part))
                .any(|p| matches!(p, Part::Nth(..))),
        matchers_and,
        matchers,
        extractors,
    })
}

const MATCHER_KEYS: &[&str] = &[
    "type",
    "part",
    "words",
    "regex",
    "status",
    "size",
    "binary",
    "condition",
    "negative",
    "case-insensitive",
    "name",
    "internal",
    "encoding",
    "match-all",
    "dsl",
];

static NUMBERED: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"_(\d+)$").unwrap());

/// Splits `body_2` into (`body`, 2).
pub(crate) fn numbered(name: &str) -> Option<(&str, usize)> {
    let c = NUMBERED.captures(name)?;
    let n = c[1].parse().ok().filter(|n| *n > 0)?;
    Some((&name[..name.len() - c[0].len()], n))
}

fn compile_part(v: &Value) -> std::result::Result<Part, Problem> {
    let p = v.get("part").and_then(Value::as_str).unwrap_or("body").to_ascii_lowercase();
    part_named(&p)
}

fn part_named(p: &str) -> std::result::Result<Part, Problem> {
    if let Some((base, n)) = numbered(p) {
        return match part_named(base)? {
            part @ (Part::Body | Part::Header | Part::All | Part::Named(_)) => Ok(Part::Nth(n, Box::new(part))),
            _ => unsupported(format!("part `{p}`")),
        };
    }
    Ok(match p {
        "body" => Part::Body,
        "header" | "headers" | "all_headers" => Part::Header,
        "all" | "response" | "raw" => Part::All,
        "baseline_body" => Part::BaselineBody,
        p if p.starts_with("interactsh") => return unsupported("interactsh (out-of-band) matchers"),
        p if matches!(p, "request" | "host" | "status_code" | "content_length" | "duration") => {
            return unsupported(format!("part `{p}`"))
        }
        p if p.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'_' || c == b'-') => Part::Named(p.replace('_', "-")),
        p => return invalid(format!("bad part {p:?}")),
    })
}

/// Template regexes, syntax-checked at load and compiled on first use: some
/// templates carry hundreds of Unicode-heavy patterns that take seconds to build.
#[derive(Debug, Clone)]
pub(crate) struct Regexes {
    src: Vec<String>,
    compiled: std::sync::Arc<std::sync::OnceLock<Vec<Regex>>>,
}

impl Regexes {
    pub fn get(&self) -> &[Regex] {
        self.compiled.get_or_init(|| {
            self.src.iter().filter_map(|r| regex::RegexBuilder::new(r).size_limit(1 << 22).build().ok()).collect()
        })
    }

    pub fn len(&self) -> usize {
        self.src.len()
    }
}

fn compile_regexes(v: &Value) -> std::result::Result<Regexes, Problem> {
    let src = list(v.get("regex"));
    for r in &src {
        // Lookaround and backreferences (RE2 lacks them too) fail here.
        if regex_syntax::ast::parse::Parser::new().parse(r).is_err() {
            return unsupported("regex syntax (lookaround/backreference)");
        }
    }
    Ok(Regexes { src, compiled: Default::default() })
}

fn compile_matcher(m: &Value) -> std::result::Result<Matcher, Problem> {
    let Some(obj) = m.as_object() else { return invalid("matcher is not a mapping") };
    for k in obj.keys() {
        if !MATCHER_KEYS.contains(&k.as_str()) {
            return unsupported(format!("matcher `{k}`"));
        }
    }
    let hex = match m.get("encoding").and_then(Value::as_str) {
        None => false,
        Some("hex") => true,
        Some(other) => return unsupported(format!("matcher encoding {other}")),
    };
    let case_insensitive = flag(m, "case-insensitive");
    let kind = match m.get("type").and_then(Value::as_str).unwrap_or("") {
        "word" => {
            let mut words = list(m.get("words"));
            if hex {
                words = words
                    .iter()
                    .map(|w| hex::decode(w).map(|b| String::from_utf8_lossy(&b).into_owned()))
                    .collect::<std::result::Result<_, _>>()
                    .or_else(|_| invalid("bad hex word"))?;
            }
            MatchKind::Word(words)
        }
        "regex" => MatchKind::Regex(compile_regexes(m)?),
        "status" => MatchKind::Status(
            list(m.get("status"))
                .iter()
                .map(|x| x.parse())
                .collect::<std::result::Result<_, _>>()
                .or_else(|_| invalid("bad status"))?,
        ),
        "size" => MatchKind::Size(
            list(m.get("size"))
                .iter()
                .map(|x| x.parse())
                .collect::<std::result::Result<_, _>>()
                .or_else(|_| invalid("bad size"))?,
        ),
        "binary" => MatchKind::Binary(
            list(m.get("binary"))
                .iter()
                .map(hex::decode)
                .collect::<std::result::Result<_, _>>()
                .or_else(|_| invalid("bad binary"))?,
        ),
        "dsl" => MatchKind::Dsl(compile_dsl(m)?),
        "" => return invalid("matcher without type"),
        other => return unsupported(format!("{other} matchers")),
    };
    let empty = match &kind {
        MatchKind::Word(v) => v.is_empty(),
        MatchKind::Regex(v) => v.len() == 0,
        MatchKind::Status(v) => v.is_empty(),
        MatchKind::Size(v) => v.is_empty(),
        MatchKind::Binary(v) => v.is_empty(),
        MatchKind::Dsl(v) => v.is_empty(),
    };
    if empty {
        return invalid("matcher without values");
    }
    let and = match m.get("condition").and_then(Value::as_str).unwrap_or("or") {
        "and" => true,
        "or" => false,
        other => return invalid(format!("unknown condition {other:?}")),
    };
    // DSL expressions name their parts themselves.
    let part = if matches!(kind, MatchKind::Dsl(_)) { Part::Body } else { compile_part(m)? };
    Ok(Matcher {
        kind,
        part,
        and,
        negative: flag(m, "negative"),
        case_insensitive,
        internal: flag(m, "internal"),
        name: m.get("name").and_then(s),
    })
}

fn compile_extractor(e: &Value) -> std::result::Result<Extractor, Problem> {
    let kind = match e.get("type").and_then(Value::as_str).unwrap_or("") {
        "regex" => {
            let group = e.get("group").and_then(Value::as_u64).unwrap_or(0) as usize;
            let res = compile_regexes(e)?;
            if res.len() == 0 {
                return invalid("regex extractor without regex");
            }
            ExtractKind::Regex(res, group)
        }
        "kval" => ExtractKind::Kval(list(e.get("kval")).iter().map(|k| k.replace('_', "-")).collect()),
        "dsl" => {
            let exprs = compile_dsl(e)?;
            if exprs.is_empty() {
                return invalid("dsl extractor without expressions");
            }
            ExtractKind::Dsl(exprs)
        }
        "json" => {
            let paths = list(e.get("json"))
                .iter()
                .map(|q| compile_json_path(q))
                .collect::<Option<Vec<_>>>()
                .map_or_else(|| unsupported("json extractor query (beyond .a.b[0][] paths)"), Ok)?;
            if paths.is_empty() {
                return invalid("json extractor without queries");
            }
            ExtractKind::Json(paths)
        }
        other => return unsupported(format!("{other} extractors")),
    };
    let part = if matches!(kind, ExtractKind::Dsl(_)) { Part::Body } else { compile_part(e)? };
    Ok(Extractor {
        kind,
        part,
        name: e.get("name").and_then(Value::as_str).map(str::to_string),
        internal: flag(e, "internal"),
    })
}

fn compile_dsl(v: &Value) -> std::result::Result<Vec<dsl::Expr>, Problem> {
    list(v.get("dsl"))
        .iter()
        .map(|src| {
            dsl::parse(src).map_err(|e| match e {
                dsl::ParseError::Unsupported(r) => Problem::Unsupported(r),
                dsl::ParseError::Invalid(r) => Problem::Invalid(format!("dsl: {r}")),
            })
        })
        .collect()
}

/// Names the runtime fills in (see `rule::builtins`).
pub(crate) const BUILTINS: &[&str] =
    &["BaseURL", "RootURL", "Hostname", "Host", "Port", "Path", "File", "Scheme", "randstr"];

pub(crate) static PLACEHOLDER: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\{\{\s*([^{}]*?)\s*\}\}").unwrap());

/// Every `{{name}}` must be something the runtime can fill in; Nuclei DSL
/// expressions (function calls, interactsh-url, ...) make the template unsupported.
pub(crate) static RANDSTR: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\brandstr(_\d+)?\b").unwrap());

fn check_placeholders(vars: &[(String, String)], blocks: &mut [Block]) -> std::result::Result<(), Problem> {
    let is_randstr = |n: &str| RANDSTR.find(n).is_some_and(|m| m.len() == n.len());
    let mut known: HashSet<String> = BUILTINS.iter().map(|b| b.to_string()).collect();
    known.extend(vars.iter().map(|(k, _)| k.clone()));
    for b in blocks.iter() {
        known.extend(b.payloads.iter().map(|(k, _)| k.clone()));
        known.extend(b.extractors.iter().filter_map(|e| e.name.clone()));
    }
    // DSL variables: response parts, the names above, or a response header
    // (`content_type`, `set_cookie`); numbered parts (`body_2`) turn on req-condition.
    for b in blocks.iter_mut() {
        let mut dsl_vars = Vec::new();
        for m in &b.matchers {
            if let MatchKind::Dsl(exprs) = &m.kind {
                exprs.iter().for_each(|e| e.vars(&mut dsl_vars));
            }
        }
        for e in &b.extractors {
            if let ExtractKind::Dsl(exprs) = &e.kind {
                exprs.iter().for_each(|e| e.vars(&mut dsl_vars));
            }
        }
        let mut nth = false;
        for v in dsl_vars {
            if v.starts_with("interactsh") {
                return unsupported("interactsh (out-of-band) matchers");
            }
            nth |= !known.contains(v) && numbered(v).is_some();
        }
        b.req_condition |= nth;
    }
    let mut texts: Vec<&str> = vars.iter().map(|(_, v)| v.as_str()).collect();
    for b in blocks.iter() {
        texts.extend(b.paths.iter().chain(&b.raws).map(String::as_str));
        texts.extend(b.headers.iter().map(|(_, v)| v.as_str()));
        texts.push(&b.body);
        for m in &b.matchers {
            if let MatchKind::Word(w) = &m.kind {
                texts.extend(w.iter().map(String::as_str));
            }
        }
    }
    for t in texts {
        for c in PLACEHOLDER.captures_iter(t) {
            let name = &c[1];
            if name == "interactsh-url" {
                return unsupported("interactsh (out-of-band) payloads");
            }
            if known.contains(name) || is_randstr(name) {
                continue;
            }
            // A DSL expression over known values, e.g. `{{base64(username)}}`.
            let expr = match dsl::parse(name) {
                Ok(e) => e,
                Err(dsl::ParseError::Unsupported(r)) => return unsupported(r),
                Err(dsl::ParseError::Invalid(_)) => return unsupported("placeholder syntax"),
            };
            let mut used = Vec::new();
            expr.vars(&mut used);
            if used.iter().any(|v| !known.contains(*v) && !is_randstr(v)) {
                return unsupported("placeholders without a value (template inputs)");
            }
        }
    }
    Ok(())
}

/// Payload value combinations for a block: name -> value per combination.
pub(crate) fn combos(payloads: &[(String, Vec<String>)], attack: Attack, cap: usize) -> Vec<Vec<(String, String)>> {
    if payloads.is_empty() {
        return vec![vec![]];
    }
    match attack {
        Attack::BatteringRam | Attack::Pitchfork => {
            let n = payloads.iter().map(|(_, v)| v.len()).min().unwrap_or(0);
            (0..n.min(cap)).map(|i| payloads.iter().map(|(k, v)| (k.clone(), v[i].clone())).collect()).collect()
        }
        Attack::ClusterBomb => {
            let mut out: Vec<Vec<(String, String)>> = vec![vec![]];
            for (k, vals) in payloads {
                let mut next = Vec::new();
                'outer: for prefix in &out {
                    for v in vals {
                        if next.len() >= cap {
                            break 'outer;
                        }
                        let mut c = prefix.clone();
                        c.push((k.clone(), v.clone()));
                        next.push(c);
                    }
                }
                out = next;
            }
            out
        }
    }
}

/// Which loaded checks to run.
#[derive(Debug, Clone, Default)]
pub struct Filter {
    pub ids: Vec<String>,
    /// Any of these tags.
    pub tags: Vec<String>,
    pub exclude_tags: Vec<String>,
    pub min_risk: Option<Risk>,
}

impl Filter {
    pub fn keep(&self, c: &Check) -> bool {
        let has = |t: &String| c.tags.iter().any(|x| x.eq_ignore_ascii_case(t));
        (self.ids.is_empty() || self.ids.contains(&c.id))
            && (self.tags.is_empty() || self.tags.iter().any(has))
            && !self.exclude_tags.iter().any(has)
            && self.min_risk.is_none_or(|r| c.risk >= r)
    }
}

/// Resolves `--checks` selectors: `nuclei`, `local`, `all`, or a path.
pub fn resolve_selectors(home: &Path, selectors: &[String]) -> Vec<PathBuf> {
    let mut out = Vec::new();
    for s in selectors {
        match s.as_str() {
            "nuclei" => out.push(nuclei_dir(home)),
            "local" => out.push(local_dir(home)),
            "all" => out.extend([nuclei_dir(home), local_dir(home)]),
            p => out.push(PathBuf::from(p)),
        }
    }
    // A store that doesn't exist yet is empty, not an error.
    let (nuclei, local) = (nuclei_dir(home), local_dir(home));
    out.retain(|p| p.exists() || (*p != nuclei && *p != local));
    out.dedup();
    out
}

#[cfg(test)]
mod tests;
