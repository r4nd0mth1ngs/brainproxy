//! Runs a declarative check as an active rule. Every request is sent through
//! `Cx` (scope guard, auth session, rate limit, stop/deadline).

use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::Duration;

use super::dsl::Value;
use super::{combos, Block, Check, ExtractKind, Extractor, MatchKind, Matcher, Part, MAX_COMBOS, PLACEHOLDER, RANDSTR};
use crate::http::RawRequest;
use crate::oob::Payload;
use crate::scan::active::{ActiveRule, BoxFuture, Cx, Response, RuleScope};
use crate::scan::{AlertDef, Confidence, Risk};
use crate::{Error, Result};

pub struct CheckRule {
    check: Check,
    /// Per-request timeout unless a request block sets its own (`@timeout`).
    timeout: Duration,
    /// Request templates (`template_key`) that other selected checks send too.
    shared: Arc<HashSet<String>>,
    name: &'static str,
    alerts: &'static [&'static AlertDef],
}

/// A request template as written, for spotting checks that send the same one.
/// None when its responses can't be shared: payloads, an OOB URL, a request
/// sequence, its own timeout, or deliberately malformed (`unsafe`).
fn template_key(check: &Check, block: &Block, template: &str, raw: bool) -> Option<String> {
    let plain = block.payloads.is_empty()
        && !block.req_condition
        && !check.oob_url
        && block.timeout.is_none()
        && !block.unsafe_raw
        && block.inject.is_empty();
    plain.then(|| {
        if raw {
            template.trim().to_string()
        } else {
            format!(
                "{} {template}\n{:?}\n{}\n{:?}\n{}",
                block.method, block.headers, block.body, block.body_bytes, block.redirects
            )
        }
    })
}

fn leak(s: String) -> &'static str {
    Box::leak(s.into_boxed_str())
}

/// The check's alert definition, leaked to be `'static` like the ported rules' ones.
fn alert_def(c: &Check) -> &'static AlertDef {
    let description = if c.description.is_empty() { c.name.clone() } else { c.description.clone() };
    Box::leak(Box::new(AlertDef {
        alert_ref: leak(format!("check:{}", c.id)),
        name: leak(c.name.clone()),
        risk: c.risk,
        confidence: c.confidence,
        cwe: c.cwe,
        wasc: 0,
        description: leak(description),
        solution: leak(c.remediation.clone()),
        references: Box::leak(c.references.iter().map(|r| leak(r.clone())).collect::<Vec<_>>().into_boxed_slice()),
        tags: Box::leak(c.tags.iter().map(|t| leak(t.clone())).collect::<Vec<_>>().into_boxed_slice()),
    }))
}

/// A `scope: passive` check: matchers over recorded responses, nothing is sent.
pub struct PassiveCheck {
    check: Check,
    def: &'static AlertDef,
}

impl PassiveCheck {
    pub fn id(&self) -> &str {
        &self.check.id
    }

    pub fn def(&self) -> &'static AlertDef {
        self.def
    }

    /// `request` is the recorded request's line and headers.
    pub fn scan(&self, host: &str, request: &str, resp: &Response, out: &mut Vec<crate::scan::Finding>) {
        out.extend(passive_findings(&self.check, self.def, host, request, resp));
    }
}

/// The passive checks among `checks` (their definitions are leaked: load once per process).
pub fn into_passive(checks: Vec<Check>) -> Vec<PassiveCheck> {
    checks.into_iter().filter(|c| c.scope == "passive").map(|c| PassiveCheck { def: alert_def(&c), check: c }).collect()
}

/// Turns loaded checks into active rules. Their alert definitions must be
/// `'static` like the ported rules' ones, so they are leaked: load once per process.
/// `timeout` is the per-request timeout (Nuclei's default is 10 s), capped by the
/// scan's own.
pub fn into_rules(checks: Vec<Check>, timeout: Duration) -> Vec<&'static dyn ActiveRule> {
    let mut seen: HashMap<String, usize> = HashMap::new();
    for c in &checks {
        for b in &c.blocks {
            let templates = b.paths.iter().map(|p| (p, false)).chain(b.raws.iter().map(|r| (r, true)));
            for (t, raw) in templates {
                if let Some(k) = template_key(c, b, t, raw) {
                    *seen.entry(k).or_default() += 1;
                }
            }
        }
    }
    let shared: Arc<HashSet<String>> = Arc::new(seen.into_iter().filter(|(_, n)| *n > 1).map(|(k, _)| k).collect());
    checks
        .into_iter()
        .filter(|c| c.scope != "passive")
        .map(|c| {
            let def = alert_def(&c);
            let rule = CheckRule {
                name: def.name,
                alerts: Box::leak(Box::new([def])),
                check: c,
                timeout,
                shared: shared.clone(),
            };
            &*Box::leak(Box::new(rule)) as &'static dyn ActiveRule
        })
        .collect()
}

impl ActiveRule for CheckRule {
    fn id(&self) -> u32 {
        0
    }

    fn name(&self) -> &'static str {
        self.name
    }

    fn alerts(&self) -> &'static [&'static AlertDef] {
        self.alerts
    }

    fn scope(&self) -> RuleScope {
        self.check.rule_scope
    }

    fn scan<'a>(&'a self, cx: &'a Cx) -> BoxFuture<'a> {
        Box::pin(run(self, cx))
    }

    /// Checks that wait longer on purpose (`@timeout`) or send malformed requests
    /// (`unsafe`), which can hang until the timeout, start first; the rest are a
    /// request or two each and fill the gaps at the end.
    fn order(&self) -> u8 {
        if self.check.blocks.iter().any(|b| b.timeout.is_some() || b.unsafe_raw) {
            0
        } else {
            3
        }
    }
}

/// `send` with the block's timeout (the check's default unless `@timeout` set one).
async fn timed(
    rule: &CheckRule,
    block: &Block,
    send: impl std::future::Future<Output = Result<Response>>,
) -> Result<Response> {
    let t = block.timeout.unwrap_or(rule.timeout);
    tokio::time::timeout(t, send).await.unwrap_or(Err(Error::Timeout(t)))
}

fn rand_alnum(n: usize) -> String {
    use std::hash::{BuildHasher, Hasher};
    let mut out = String::new();
    while out.len() < n {
        let mut h = std::collections::hash_map::RandomState::new().build_hasher();
        h.write_usize(out.len());
        let v = h.finish();
        out.extend(v.to_le_bytes().iter().map(|b| (b'a' + b % 26) as char));
    }
    out.truncate(n);
    out
}

/// Nuclei's input-derived variables for the attacked request.
fn builtins(cx: &Cx, scope: RuleScope) -> HashMap<String, String> {
    let t = cx.target();
    let origin = t.origin();
    let path = cx.base().path.clone();
    let (base_url, path) =
        if scope == RuleScope::Host { (origin.clone(), String::new()) } else { (format!("{origin}{path}"), path) };
    let file = path.rsplit('/').next().unwrap_or("").to_string();
    HashMap::from([
        ("BaseURL".into(), base_url),
        ("RootURL".into(), origin),
        ("Hostname".into(), t.host_header()),
        ("Host".into(), t.host.clone()),
        ("Port".into(), t.port.to_string()),
        ("Path".into(), path),
        ("File".into(), file),
        ("Scheme".into(), t.scheme.clone()),
    ])
}

/// Fills `{{name}}` and `{{expression}}` placeholders. Returns None when one
/// needs a value that isn't available (e.g. an extractor that matched nothing),
/// like Nuclei, which skips such requests.
fn subst(text: &str, vars: &HashMap<String, String>) -> Option<String> {
    let mut missing = false;
    let out = PLACEHOLDER.replace_all(text, |c: &regex::Captures| {
        placeholder(&c[1], vars).unwrap_or_else(|| {
            missing = true;
            String::new()
        })
    });
    (!missing).then(|| out.into_owned())
}

/// The value of one placeholder: a variable, or a DSL expression over them.
fn placeholder(name: &str, vars: &HashMap<String, String>) -> Option<String> {
    vars.get(name).cloned().or_else(|| {
        let env = |name: &str| vars.get(name).map(|v| Value::Str(v.clone()));
        super::dsl::parse(name).ok()?.eval(&env).map(Value::into_string)
    })
}

/// A DSL expression with the placeholders in its strings filled, as Nuclei does before
/// evaluating (`contains(body, '{{randstr}}')`). One without a value stays as written.
fn fill_dsl<'e>(e: &'e super::dsl::Expr, vars: &HashMap<String, String>) -> std::borrow::Cow<'e, super::dsl::Expr> {
    let mut strings = Vec::new();
    e.strings(&mut strings);
    if !strings.iter().any(|s| PLACEHOLDER.is_match(s)) {
        return std::borrow::Cow::Borrowed(e);
    }
    let fill = |s: &str| {
        PLACEHOLDER
            .replace_all(s, |c: &regex::Captures| placeholder(&c[1], vars).unwrap_or_else(|| c[0].to_string()))
            .into_owned()
    };
    std::borrow::Cow::Owned(e.filled(&fill))
}

/// The string literals of a block's DSL matchers (immediate ones) and extractors.
pub(crate) fn dsl_strings(b: &Block) -> Vec<&str> {
    let mut out = Vec::new();
    for m in b.matchers.iter().filter(|m| !m.oob) {
        if let MatchKind::Dsl(exprs) = &m.kind {
            exprs.iter().for_each(|e| e.strings(&mut out));
        }
    }
    for e in &b.extractors {
        if let ExtractKind::Dsl(exprs) = &e.kind {
            exprs.iter().for_each(|e| e.strings(&mut out));
        }
    }
    out
}

/// Adds a `randstr*` value for every such placeholder in the check.
fn add_randstr(check: &Check, vars: &mut HashMap<String, String>) {
    let mut texts: Vec<&str> = check.variables.iter().map(|(_, v)| v.as_str()).collect();
    for b in &check.blocks {
        texts.extend(b.paths.iter().chain(&b.raws).map(String::as_str));
        texts.extend(b.headers.iter().map(|(_, v)| v.as_str()));
        texts.push(&b.body);
        for m in &b.matchers {
            if let MatchKind::Word(w) = &m.kind {
                texts.extend(w.iter().map(String::as_str));
            }
        }
        texts.extend(dsl_strings(b));
    }
    for t in texts {
        for c in PLACEHOLDER.captures_iter(t) {
            for r in RANDSTR.find_iter(&c[1]) {
                vars.entry(r.as_str().to_string()).or_insert_with(|| rand_alnum(25));
            }
        }
    }
}

async fn run(rule: &CheckRule, cx: &Cx) {
    let check = &rule.check;
    let mut vars = builtins(cx, check.rule_scope);
    add_randstr(check, &mut vars);
    vars.extend(check.inputs.iter().cloned());
    // Variables may refer to builtins, inputs, and earlier variables; an input
    // with the same name wins (like Nuclei's `-var`).
    for (k, v) in &check.variables {
        if check.inputs.iter().any(|(i, _)| i == k) {
            continue;
        }
        if let Some(v) = subst(v, &vars) {
            vars.insert(k.clone(), v);
        }
    }
    match &check.flow {
        Some(flow) => {
            run_flow(rule, cx, flow, &mut vars).await;
        }
        None => {
            for block in &check.blocks {
                // Boxed: a block's future is about 100 KB, too much to hold on the stack.
                if Box::pin(run_block(rule, cx, block, &mut vars)).await.stop {
                    return;
                }
            }
        }
    }
}

/// Evaluates a `flow` expression, running each `http(N)` block when it is
/// reached (`&&`/`||` short-circuit like Nuclei's JavaScript).
fn run_flow<'a>(
    rule: &'a CheckRule,
    cx: &'a Cx,
    e: &'a super::dsl::Expr,
    vars: &'a mut HashMap<String, String>,
) -> std::pin::Pin<Box<dyn std::future::Future<Output = bool> + Send + 'a>> {
    use super::dsl::{Expr, Op};
    Box::pin(async move {
        if cx.stopped() {
            return false;
        }
        match e {
            Expr::Var(v) => {
                let n: usize = v.trim_start_matches("__http_").parse().unwrap_or(0);
                match rule.check.blocks.get(n.wrapping_sub(1)) {
                    Some(block) => Box::pin(run_block(rule, cx, block, vars)).await.matched,
                    None => false,
                }
            }
            Expr::Not(e) => !run_flow(rule, cx, e, vars).await,
            Expr::Bin(Op::And, a, b) => run_flow(rule, cx, a, vars).await && run_flow(rule, cx, b, vars).await,
            Expr::Bin(Op::Or, a, b) => run_flow(rule, cx, a, vars).await || run_flow(rule, cx, b, vars).await,
            _ => false,
        }
    })
}

#[derive(Default)]
struct Outcome {
    /// Some response of the block matched.
    matched: bool,
    /// The check should stop (scan stopped, or stop-at-first-match).
    stop: bool,
}

/// Runs one request block.
async fn run_block(rule: &CheckRule, cx: &Cx, block: &Block, vars: &mut HashMap<String, String>) -> Outcome {
    let mut out = Outcome::default();
    if !block.inject.is_empty() {
        for value in &block.inject {
            if cx.stopped() {
                out.stop = true;
                return out;
            }
            let sent = if block.inject_raw {
                timed(rule, block, cx.send_payload_raw(value)).await
            } else {
                timed(rule, block, cx.send_payload(value)).await
            };
            let Ok(resp) = sent else { continue };
            if evaluate(rule, cx, block, std::slice::from_ref(&resp), vars, value, None) {
                out.matched = true;
                if block.stop_at_first_match {
                    out.stop = true;
                    return out;
                }
            }
        }
        return out;
    }
    for combo in combos(&block.payloads, block.attack, MAX_COMBOS) {
        let mut v = vars.clone();
        v.extend(combo.iter().cloned());
        let attack = combo.iter().map(|(k, x)| format!("{k}={x}")).collect::<Vec<_>>().join(", ");
        let requests = block.paths.iter().map(|p| (p, false)).chain(block.raws.iter().map(|r| (r, true)));
        let count = block.paths.len() + block.raws.len();
        let mut history: Vec<Response> = Vec::new();
        // One OOB payload per request (per sequence with req-condition).
        let mut oob: Option<Payload> = None;
        for (template, raw) in requests {
            if cx.stopped() {
                out.stop = true;
                return out;
            }
            if rule.check.oob_url && (oob.is_none() || !block.req_condition) {
                // Without a listener (`--no-oob`, or it stopped) the request tests nothing.
                let Some(p) = cx.oob_payload() else { continue };
                set_oob(&rule.check, &mut v, &p);
                oob = Some(p);
            }
            let req = if raw { build_raw(cx, block, template, &v) } else { build_path(cx, block, template, &v) };
            let Some(req) = req else { continue };
            let sent_req = oob.as_ref().map(|_| req.clone());
            // Requests other checks send alike go out once (GET/HEAD only: no side effects).
            let once = (req.starts_with(b"GET ") || req.starts_with(b"HEAD "))
                && template_key(&rule.check, block, template, raw).is_some_and(|k| rule.shared.contains(&k));
            let key = once.then(|| [&[block.redirects as u8][..], &req].concat());
            let send = async {
                if block.redirects {
                    timed(rule, block, cx.send_following(req)).await
                } else {
                    timed(rule, block, cx.send(req)).await
                }
            };
            let sent = match key {
                Some(k) => Box::pin(cx.send_once(&k, send)).await,
                None => send.await,
            };
            let oob_sent = oob.as_ref().zip(sent_req.as_deref());
            let resp = match sent {
                Ok(r) => r,
                Err(_) => {
                    // A callback can still arrive (the target may hang while making it).
                    if let Some(sent) = oob_sent.filter(|_| block.oob && !block.req_condition) {
                        let immediate = vec![false; block.matchers.iter().filter(|m| !m.oob).count()];
                        defer_oob(rule, cx, block, &[], &v, &attack, sent, &immediate);
                    }
                    continue;
                }
            };
            let matched = if block.req_condition {
                // Internal extractors feed the next request; the matchers wait
                // for the whole sequence (a missing response means no match).
                history.push(resp);
                for e in block.extractors.iter().filter(|e| e.internal) {
                    if let (Some(name), Some(first)) =
                        (&e.name, extract(&Env::of(cx), &history, e, &v).into_iter().next())
                    {
                        v.insert(name.clone(), first);
                    }
                }
                history.len() == count && evaluate(rule, cx, block, &history, &mut v, &attack, oob_sent)
            } else {
                evaluate(rule, cx, block, std::slice::from_ref(&resp), &mut v, &attack, oob_sent)
            };
            // Internal extractor values carry over to later requests.
            for e in block.extractors.iter().filter(|e| e.internal) {
                if let Some(name) = &e.name {
                    if let Some(x) = v.get(name) {
                        vars.insert(name.clone(), x.clone());
                    }
                }
            }
            out.matched |= matched;
            if matched && block.stop_at_first_match {
                out.stop = true;
                return out;
            }
        }
    }
    out
}

/// The value of `{{interactsh-url}}`: a host name carrying the token in DNS
/// mode, `host:port/token` in host mode (so `http://{{interactsh-url}}/x`
/// still works). Variables that use it are evaluated again.
fn set_oob(check: &Check, vars: &mut HashMap<String, String>, p: &Payload) {
    let host =
        if p.dns { p.host.clone() } else { p.url.trim_start_matches("http://").trim_end_matches('/').to_string() };
    vars.insert("interactsh-url".into(), host);
    // Also variables that use it through another one (`jndi: ldap://{{callback}}/x`).
    let mut changed = vec!["interactsh-url"];
    for (k, v) in &check.variables {
        if changed.iter().any(|c| v.contains(c)) && !check.inputs.iter().any(|(i, _)| i == k) {
            if let Some(x) = subst(v, vars) {
                vars.insert(k.clone(), x);
                changed.push(k.as_str());
            }
        }
    }
}

/// Registers a request that carried an OOB payload when its interactsh
/// matchers can still decide the result: `immediate` holds the other
/// matchers' results (all must hold with matchers-condition and; with or, none
/// held or the finding was already reported). An interaction with the token
/// raises the finding at correlation if it passes the interactsh matchers
/// (`interaction_matches`); DSL values from the response are kept with them.
#[allow(clippy::too_many_arguments)]
fn defer_oob(
    rule: &CheckRule,
    cx: &Cx,
    block: &Block,
    seen: &[Response],
    vars: &HashMap<String, String>,
    attack: &str,
    (payload, request): (&Payload, &[u8]),
    immediate: &[bool],
) {
    if block.matchers_and && !immediate.iter().all(|x| *x) {
        return;
    }
    let mut snapshot: serde_json::Map<String, serde_json::Value> =
        vars.iter().map(|(k, v)| (k.clone(), v.clone().into())).collect();
    let mut names = Vec::new();
    for m in block.matchers.iter().filter(|m| m.oob) {
        if let MatchKind::Dsl(exprs) = &m.kind {
            exprs.iter().for_each(|e| e.vars(&mut names));
        }
    }
    for n in names.into_iter().filter(|n| !n.starts_with("interactsh")) {
        if let Some(v) = dsl_value(&Env::of(cx), seen, vars, n) {
            snapshot.insert(n.to_string(), dsl_to_json(v));
        }
    }
    let def = rule.alerts[0];
    let check = serde_json::json!({
        "alert": {
            "alert_ref": def.alert_ref, "name": def.name, "risk": def.risk.as_str(),
            "confidence": def.confidence.as_str(), "cwe": def.cwe, "description": def.description,
            "solution": def.solution, "references": def.references, "tags": def.tags,
        },
        "and": block.matchers_and,
        "matchers": block.matchers.iter().filter_map(|m| m.src.clone()).collect::<Vec<_>>(),
        "vars": snapshot,
    });
    let c = &rule.check;
    let param = if c.rule_scope == RuleScope::Param { cx.point().name.clone() } else { String::new() };
    let attack =
        if attack.is_empty() { vars.get("interactsh-url").cloned().unwrap_or_default() } else { attack.into() };
    let finding = def.raise(param, "").attack(attack).other_info(format!("Check {} ({})", c.id, c.file.display()));
    cx.oob_register_check(payload, finding, request, seen.last(), Some(check.to_string()));
}

fn dsl_to_json(v: Value) -> serde_json::Value {
    match v {
        Value::Str(s) => s.into(),
        Value::Num(n) => serde_json::Number::from_f64(n).map_or(serde_json::Value::Null, Into::into),
        Value::Bool(b) => b.into(),
    }
}

/// Whether an out-of-band interaction passes a check's interactsh matchers
/// (`check_json` of its payload, see `defer_oob`). Matchers see
/// `interactsh_protocol` (dns, http, ldap, tcp; a TLS ClientHello counts as
/// http, as HTTPS does for interactsh), `interactsh_request` (what was
/// received), `interactsh_ip`, and an empty `interactsh_response`; DSL
/// expressions also see the values kept from the attack's response.
pub fn interaction_matches(check: &serde_json::Value, protocol: &str, remote: &str, raw: &[u8]) -> bool {
    let Some(srcs) = check["matchers"].as_array() else { return true };
    let mut vars = HashMap::new();
    let mut values = HashMap::new();
    for (k, v) in check["vars"].as_object().into_iter().flatten() {
        let v = match v {
            serde_json::Value::String(s) => {
                vars.insert(k.clone(), s.clone());
                Value::Str(s.clone())
            }
            serde_json::Value::Number(n) => Value::Num(n.as_f64().unwrap_or(0.0)),
            serde_json::Value::Bool(b) => Value::Bool(*b),
            _ => continue,
        };
        values.insert(k.clone(), v);
    }
    let protocol = if protocol == "tls" { "http" } else { protocol };
    let request = String::from_utf8_lossy(raw).into_owned();
    let ip = remote.rsplit_once(':').map_or(remote, |(h, _)| h).trim_matches(['[', ']']);
    let field = |name: &str| -> Option<String> {
        Some(match name {
            "interactsh_protocol" => protocol.into(),
            "interactsh_request" => request.clone(),
            "interactsh_response" => String::new(),
            "interactsh_ip" => ip.into(),
            _ => return None,
        })
    };
    let hit = |src: &serde_json::Value| -> bool {
        let Ok(m) = super::compile_matcher(src) else { return false };
        let hit = match &m.kind {
            MatchKind::Dsl(exprs) => {
                let env = |n: &str| field(n).map(Value::Str).or_else(|| values.get(n).cloned());
                let h = |e: &super::dsl::Expr| e.matches(&env);
                if m.and {
                    exprs.iter().all(h)
                } else {
                    exprs.iter().any(h)
                }
            }
            _ => {
                let text = match &m.part {
                    Part::Oob(n) => field(n).unwrap_or_default(),
                    _ => String::new(),
                };
                text_match(&m, &text, &vars).0
            }
        };
        hit != m.negative
    };
    if check["and"].as_bool().unwrap_or(false) {
        srcs.iter().all(hit)
    } else {
        srcs.iter().any(hit)
    }
}

/// The alert of a check's OOB payload (`check_json`), for correlation in a
/// later process (`oob poll`) that hasn't loaded the check. Leaked like
/// `into_rules`' definitions: once per correlated interaction.
pub fn alert_from_json(check: &serde_json::Value) -> Option<&'static AlertDef> {
    let a = &check["alert"];
    let s = |k: &str| a[k].as_str().unwrap_or("").to_string();
    let list = |k: &str| -> &'static [&'static str] {
        Box::leak(
            a[k].as_array()
                .into_iter()
                .flatten()
                .filter_map(|x| x.as_str())
                .map(|x| leak(x.into()))
                .collect::<Vec<_>>()
                .into_boxed_slice(),
        )
    };
    let alert_ref = s("alert_ref");
    if !alert_ref.starts_with("check:") {
        return None;
    }
    Some(Box::leak(Box::new(AlertDef {
        alert_ref: leak(alert_ref),
        name: leak(s("name")),
        risk: Risk::parse(&s("risk"))?,
        confidence: Confidence::parse(&s("confidence"))?,
        cwe: a["cwe"].as_u64().unwrap_or(0) as u32,
        wasc: 0,
        description: leak(s("description")),
        solution: leak(s("solution")),
        references: list("references"),
        tags: list("tags"),
    })))
}

/// `path:` requests: the base request's headers (cookies, auth) with the
/// template's method, path, headers, and body. Other origins are skipped.
fn build_path(cx: &Cx, block: &Block, template: &str, vars: &HashMap<String, String>) -> Option<Vec<u8>> {
    let filled = subst(template, vars)?;
    let url = url::Url::parse(&filled).ok()?;
    let target = crate::http::Target::from_url(url.as_str()).ok()?;
    if target != *cx.target() {
        return None;
    }
    let mut req = RawRequest::from_bytes(cx.request_for(&block.method, &request_target(&filled)));
    for (k, v) in &block.headers {
        req = req.set_header(k, &subst(v, vars)?);
    }
    let mut bytes = req.into_bytes();
    match &block.body_bytes {
        Some(b) => bytes.extend_from_slice(b),
        None => bytes.extend_from_slice(subst(&block.body, vars)?.as_bytes()),
    }
    Some(RawRequest::from_bytes(bytes).update_content_length().into_bytes())
}

/// The path and query of a filled-in `path:` URL as written, like Nuclei: `..`, `%2e` and
/// `\` segments are sent, not resolved (path-traversal checks depend on them). Only bytes
/// that can't appear in a request line are escaped; the fragment is dropped.
fn request_target(url: &str) -> String {
    let rest = url.split_once("://").map_or(url, |(_, r)| r);
    let tail = &rest[rest.find(['/', '\\', '?', '#']).unwrap_or(rest.len())..];
    let tail = tail.split('#').next().unwrap_or("");
    let mut out = String::new();
    if !tail.starts_with(['/', '\\']) {
        out.push('/');
    }
    for b in tail.bytes() {
        if b.is_ascii_graphic() {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

/// `raw:` requests: line endings normalized and Content-Length fixed unless
/// `unsafe: true`. An absolute-form request target is cut to its path.
fn build_raw(cx: &Cx, block: &Block, template: &str, vars: &HashMap<String, String>) -> Option<Vec<u8>> {
    let text = subst(template.trim_start(), vars)?;
    let (head, body) = match text.find("\n\n").or_else(|| text.find("\r\n\r\n")) {
        Some(i) => (&text[..i], text[i..].trim_start_matches(['\r', '\n'])),
        None => (text.trim_end(), ""),
    };
    let body = if block.unsafe_raw { body } else { body.trim_end_matches(['\r', '\n']) };
    let mut lines: Vec<String> = head.lines().map(|l| l.trim_end_matches('\r').to_string()).collect();
    let first = lines.first_mut()?;
    let mut parts: Vec<&str> = first.splitn(3, ' ').collect();
    if parts.len() < 2 {
        return None;
    }
    let path;
    if parts[1].starts_with("http://") || parts[1].starts_with("https://") {
        let u = url::Url::parse(parts[1]).ok()?;
        if crate::http::Target::from_url(u.as_str()).ok()? != *cx.target() {
            return None;
        }
        path = format!("{}{}", u.path(), u.query().map(|q| format!("?{q}")).unwrap_or_default());
        parts[1] = &path;
    }
    *first = parts.join(" ");
    let mut bytes = format!("{}\r\n\r\n", lines.join("\r\n")).into_bytes();
    bytes.extend_from_slice(body.as_bytes());
    let req = RawRequest::from_bytes(bytes);
    Some(if block.unsafe_raw { req } else { req.update_content_length() }.into_bytes())
}

/// The text of a part. `seen` holds the responses of the block so far (just
/// the current one unless req-condition); the last one is the current one.
fn part_text(env: &Env, seen: &[Response], part: &Part) -> String {
    let Some(resp) = seen.last() else { return String::new() };
    match part {
        Part::Nth(n, p) => match seen.get(n - 1) {
            Some(r) => part_text(env, std::slice::from_ref(r), p),
            None => String::new(),
        },
        Part::Body => resp.body_str().to_string(),
        Part::Header => resp.head_text(),
        Part::All => format!("{}{}", resp.head_text(), resp.body_str()),
        Part::Named(h) => resp.headers_named(h).collect::<Vec<_>>().join("\n"),
        Part::BaselineBody => env.baseline.map(|b| b.body_str().to_string()).unwrap_or_default(),
        Part::RequestHeader => env.request.unwrap_or_default().to_string(),
        // Interactions are matched at correlation (`interaction_matches`).
        Part::Oob(_) => String::new(),
    }
}

/// A DSL variable: template values (variables, payloads, extractors) first,
/// then the response's parts, then a response header (`set_cookie` is `Set-Cookie`).
fn dsl_value(env: &Env, seen: &[Response], vars: &HashMap<String, String>, name: &str) -> Option<Value> {
    if let Some(v) = vars.get(name) {
        return Some(Value::Str(v.clone()));
    }
    if let Some((base, n)) = super::numbered(name) {
        if let Some(r) = seen.get(n - 1) {
            return dsl_value(env, std::slice::from_ref(r), vars, base);
        }
    }
    let resp = seen.last()?;
    Some(match name {
        "status_code" => Value::Num(resp.status as f64),
        "body" => Value::Str(resp.body_str().to_string()),
        "header" | "all_headers" => Value::Str(resp.head_text()),
        "response" | "raw" => Value::Str(format!("{}{}", resp.head_text(), resp.body_str())),
        "content_length" => Value::Num(
            resp.header("content-length").and_then(|v| v.trim().parse().ok()).unwrap_or(resp.body.len() as f64),
        ),
        "duration" => Value::Num(resp.duration.as_secs_f64()),
        "host" => Value::Str(env.host.to_string()),
        "request_header" if env.request.is_some() => Value::Str(env.request.unwrap_or_default().to_string()),
        _ => {
            let h = name.replace('_', "-");
            let values: Vec<&str> = resp.headers_named(&h).collect();
            if values.is_empty() {
                return None;
            }
            Value::Str(values.join(", "))
        }
    })
}

/// Whether the matcher matches, with evidence when it does.
fn matches(env: &Env, seen: &[Response], m: &Matcher, vars: &HashMap<String, String>) -> (bool, Option<String>) {
    let Some(resp) = seen.last() else { return (false, None) };
    let (hit, evidence) = match &m.kind {
        MatchKind::Dsl(exprs) => {
            let lookup = |name: &str| dsl_value(env, seen, vars, name);
            let hit = |e: &super::dsl::Expr| fill_dsl(e, vars).matches(&lookup);
            (if m.and { exprs.iter().all(hit) } else { exprs.iter().any(hit) }, None)
        }
        MatchKind::Status(codes) => (codes.contains(&resp.status), Some(resp.status_line.clone())),
        MatchKind::Size(sizes) => (sizes.contains(&resp.body.len()), None),
        MatchKind::Binary(_) if m.part == Part::Body => text_match_bytes(m, &resp.body),
        _ => text_match(m, &part_text(env, seen, &m.part), vars),
    };
    if m.negative {
        (!hit, None)
    } else {
        (hit, evidence.filter(|_| hit))
    }
}

/// A word, regex, or binary matcher over `text` (before `negative`), with evidence.
fn text_match(m: &Matcher, text: &str, vars: &HashMap<String, String>) -> (bool, Option<String>) {
    match &m.kind {
        MatchKind::Word(words) => {
            let hay = if m.case_insensitive { text.to_lowercase() } else { text.to_string() };
            let mut found = None;
            let mut all = true;
            for w in words {
                let w = subst(w, vars).unwrap_or_else(|| w.clone());
                let w = if m.case_insensitive { w.to_lowercase() } else { w };
                if hay.contains(&w) {
                    found.get_or_insert(w);
                } else {
                    all = false;
                }
            }
            (if m.and { all } else { found.is_some() }, found)
        }
        MatchKind::Regex(res) => {
            let res = res.get();
            let found: Vec<String> = res.iter().filter_map(|r| r.find(text).map(|x| x.as_str().to_string())).collect();
            (if m.and { found.len() == res.len() } else { !found.is_empty() }, found.into_iter().next())
        }
        MatchKind::Binary(_) => text_match_bytes(m, text.as_bytes()),
        _ => (false, None),
    }
}

fn text_match_bytes(m: &Matcher, bytes: &[u8]) -> (bool, Option<String>) {
    let MatchKind::Binary(bins) = &m.kind else { return (false, None) };
    let has = |b: &Vec<u8>| bytes.windows(b.len().max(1)).any(|w| w == b.as_slice());
    (if m.and { bins.iter().all(has) } else { bins.iter().any(has) }, None)
}

fn extract(env: &Env, seen: &[Response], e: &Extractor, vars: &HashMap<String, String>) -> Vec<String> {
    let mut out = Vec::new();
    let Some(resp) = seen.last() else { return out };
    match &e.kind {
        ExtractKind::Dsl(exprs) => {
            let lookup = |name: &str| dsl_value(env, seen, vars, name);
            out.extend(
                exprs
                    .iter()
                    .filter_map(|x| fill_dsl(x, vars).eval(&lookup))
                    .map(Value::into_string)
                    .filter(|v| !v.is_empty()),
            );
        }
        ExtractKind::Json(paths) => {
            if let Ok(doc) = serde_json::from_str::<serde_json::Value>(&part_text(env, seen, &e.part)) {
                for p in paths {
                    out.extend(super::json_path(&doc, p).into_iter().take(20));
                }
            }
        }
        ExtractKind::Regex(res, group) => {
            let text = part_text(env, seen, &e.part);
            for r in res.get() {
                for c in r.captures_iter(&text).take(20) {
                    if let Some(g) = c.get(*group) {
                        out.push(g.as_str().to_string());
                    }
                }
            }
        }
        ExtractKind::Kval(keys) => {
            for k in keys {
                out.extend(resp.headers_named(k).map(str::to_string));
            }
        }
    }
    out.dedup();
    out
}

/// What matchers see besides the responses: the target's host and, for an attack,
/// the baseline response of the attacked request (passive checks have none).
struct Env<'a> {
    host: &'a str,
    baseline: Option<&'a Response>,
    /// Passive checks: the recorded request's line and headers (`request_header`).
    request: Option<&'a str>,
}

impl<'a> Env<'a> {
    fn of(cx: &'a Cx) -> Self {
        Env { host: &cx.target().host, baseline: Some(cx.base_response()), request: None }
    }
}

/// A block's matcher results and extracted values for one response.
struct Assessed {
    results: Vec<(bool, Option<String>)>,
    extracted: Vec<String>,
    /// The variables the matchers saw: `vars` plus this response's named extractor values.
    mvars: HashMap<String, String>,
}

/// Runs the block's extractors and matchers over a response. Internal extractor
/// values are stored in `vars`; named ones are visible to this response's DSL matchers.
fn assess(block: &Block, env: &Env, seen: &[Response], vars: &mut HashMap<String, String>) -> Assessed {
    let mut extracted = Vec::new();
    let mut named = HashMap::new();
    for e in &block.extractors {
        let values = extract(env, seen, e, vars);
        if e.internal {
            if let (Some(name), Some(first)) = (&e.name, values.first()) {
                vars.insert(name.clone(), first.clone());
            }
        } else {
            if let (Some(name), Some(first)) = (&e.name, values.first()) {
                named.insert(name.clone(), first.clone());
            }
            extracted.extend(values);
        }
    }
    let mut mvars = vars.clone();
    mvars.extend(named);
    let results = block.matchers.iter().map(|m| matches(env, seen, m, &mvars)).collect();
    Assessed { results, extracted, mvars }
}

/// Whether the block matched: None if not, Some(None) if only internal matchers
/// held (a flow precondition, nothing to report), else the finding's evidence and
/// other info.
fn verdict(check: &Check, block: &Block, a: Assessed) -> Option<Option<(String, String)>> {
    let matched = if a.results.is_empty() {
        !a.extracted.is_empty()
    } else if block.matchers_and {
        a.results.iter().all(|r| r.0)
    } else {
        a.results.iter().any(|r| r.0)
    };
    if !matched {
        return None;
    }
    if !block.matchers.is_empty() && block.matchers.iter().all(|m| m.internal) {
        return Some(None);
    }
    let names: Vec<&str> = a
        .results
        .iter()
        .zip(&block.matchers)
        .filter(|((hit, _), m)| *hit && !m.internal)
        .filter_map(|(_, m)| m.name.as_deref())
        .collect();
    let names = names.join(", ");
    let evidence =
        a.results.into_iter().zip(&block.matchers).find_map(|((hit, ev), m)| ev.filter(|_| hit && !m.internal));
    let evidence = evidence.or_else(|| a.extracted.first().cloned()).unwrap_or_default();
    let mut info = format!("Check {} ({})", check.id, check.file.display());
    if !names.is_empty() {
        info.push_str(&format!("\nMatched: {names}"));
    }
    if !a.extracted.is_empty() {
        let shown: Vec<&str> = a.extracted.iter().take(10).map(String::as_str).collect();
        info.push_str(&format!("\nExtracted: {}", shown.join(", ")));
    }
    Some(Some((evidence, info)))
}

/// A passive check's findings on one recorded response: one per block that matches.
fn passive_findings(
    check: &Check,
    def: &'static AlertDef,
    host: &str,
    request: &str,
    resp: &Response,
) -> Vec<crate::scan::Finding> {
    let env = Env { host, baseline: None, request: Some(request) };
    let seen = std::slice::from_ref(resp);
    let mut vars: HashMap<String, String> = check.variables.iter().chain(&check.inputs).cloned().collect();
    let mut out = Vec::new();
    for block in &check.blocks {
        let a = assess(block, &env, seen, &mut vars);
        if let Some(Some((evidence, info))) = verdict(check, block, a) {
            out.push(def.raise("", evidence).other_info(info));
        }
    }
    out
}

/// Applies the block's matchers and extractors to a response and reports a
/// finding when they match. Internal extractor values are stored in `vars`.
fn evaluate(
    rule: &CheckRule,
    cx: &Cx,
    block: &Block,
    seen: &[Response],
    vars: &mut HashMap<String, String>,
    attack: &str,
    oob: Option<(&Payload, &[u8])>,
) -> bool {
    let Some(resp) = seen.last() else { return false };
    let a = assess(block, &Env::of(cx), seen, vars);
    if block.oob {
        // Interactsh matchers decide later, unless (or) another matcher already holds.
        let immediate: Vec<bool> =
            a.results.iter().zip(&block.matchers).filter(|(_, m)| !m.oob).map(|(r, _)| r.0).collect();
        if block.matchers_and || !immediate.iter().any(|x| *x) {
            if let Some(sent) = oob {
                defer_oob(rule, cx, block, seen, &a.mvars, attack, sent, &immediate);
            }
            return false;
        }
    }
    let check = &rule.check;
    let Some(report) = verdict(check, block, a) else { return false };
    // Internal matchers (flow preconditions) count, but don't report alone.
    if let Some((evidence, info)) = report {
        let param = if check.rule_scope == RuleScope::Param { cx.point().name.clone() } else { String::new() };
        cx.report(rule.alerts[0].raise(param, evidence).attack(attack).other_info(info), resp);
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    #[test]
    fn variables_using_the_oob_url_through_another_get_it() {
        let yaml = "id: x\ninfo: {severity: low}\nvariables:\n  callback: '{{interactsh-url}}'\n  jndi: 'ldap%3a//{{callback}}/zz'\n  plain: 'p'\nhttp:\n  - path: ['{{BaseURL}}/?a={{jndi}}']\n    matchers:\n      - type: status\n        status: [200]\n";
        let opts = super::super::LoadOptions { oob: true, ..Default::default() };
        let check = super::super::parse(yaml, Path::new("t.yaml"), None, &opts).unwrap_or_else(|_| panic!("loads"));
        let mut vars = HashMap::new();
        let p = Payload { token: "t".into(), host: "t.oob.test".into(), url: "http://t.oob.test/".into(), dns: true };
        set_oob(&check, &mut vars, &p);
        assert_eq!(vars["callback"], "t.oob.test");
        assert_eq!(vars["jndi"], "ldap%3a//t.oob.test/zz");
        assert!(!vars.contains_key("plain"));
    }

    #[test]
    fn path_requests_keep_the_path_as_written() {
        assert_eq!(request_target("http://a.test/js/../.htpasswd"), "/js/../.htpasswd");
        assert_eq!(request_target("http://a.test:8080/.%2e/%2e%2e/etc"), "/.%2e/%2e%2e/etc");
        assert_eq!(request_target(r"http://a.test/static\..\web.config"), r"/static\..\web.config");
        assert_eq!(request_target("http://a.test?x=1 2#frag"), "/?x=1%202");
        assert_eq!(request_target("http://a.test"), "/");
        assert_eq!(request_target("http://a.test/é"), "/%C3%A9");
    }
}
