//! Runs a declarative check as an active rule. Every request is sent through
//! `Cx` (scope guard, auth session, rate limit, stop/deadline).

use std::collections::HashMap;

use super::dsl::Value;
use super::{combos, Block, Check, ExtractKind, Extractor, MatchKind, Matcher, Part, MAX_COMBOS, PLACEHOLDER, RANDSTR};
use crate::http::RawRequest;
use crate::scan::active::{ActiveRule, BoxFuture, Cx, Response, RuleScope};
use crate::scan::AlertDef;

pub struct CheckRule {
    check: Check,
    name: &'static str,
    alerts: &'static [&'static AlertDef],
}

fn leak(s: String) -> &'static str {
    Box::leak(s.into_boxed_str())
}

/// Turns loaded checks into active rules. Their alert definitions must be
/// `'static` like the ported rules' ones, so they are leaked: load once per process.
pub fn into_rules(checks: Vec<Check>) -> Vec<&'static dyn ActiveRule> {
    checks
        .into_iter()
        .map(|c| {
            let mut description = c.description.clone();
            if description.is_empty() {
                description = c.name.clone();
            }
            let def: &'static AlertDef = Box::leak(Box::new(AlertDef {
                alert_ref: leak(format!("check:{}", c.id)),
                name: leak(c.name.clone()),
                risk: c.risk,
                confidence: c.confidence,
                cwe: c.cwe,
                wasc: 0,
                description: leak(description),
                solution: leak(c.remediation.clone()),
                references: Box::leak(
                    c.references.iter().map(|r| leak(r.clone())).collect::<Vec<_>>().into_boxed_slice(),
                ),
                tags: Box::leak(c.tags.iter().map(|t| leak(t.clone())).collect::<Vec<_>>().into_boxed_slice()),
            }));
            let rule = CheckRule { name: def.name, alerts: Box::leak(Box::new([def])), check: c };
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
        let value = vars.get(&c[1]).cloned().or_else(|| {
            let env = |name: &str| vars.get(name).map(|v| Value::Str(v.clone()));
            super::dsl::parse(&c[1]).ok()?.eval(&env).map(Value::into_string)
        });
        value.unwrap_or_else(|| {
            missing = true;
            String::new()
        })
    });
    (!missing).then(|| out.into_owned())
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
                if run_block(rule, cx, block, &mut vars).await.stop {
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
                    Some(block) => run_block(rule, cx, block, vars).await.matched,
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
            let sent = if block.inject_raw { cx.send_payload_raw(value).await } else { cx.send_payload(value).await };
            let Ok(resp) = sent else { continue };
            if evaluate(rule, cx, block, std::slice::from_ref(&resp), vars, value) {
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
        for (template, raw) in requests {
            if cx.stopped() {
                out.stop = true;
                return out;
            }
            let req = if raw { build_raw(cx, block, template, &v) } else { build_path(cx, block, template, &v) };
            let Some(req) = req else { continue };
            let sent = if block.redirects { cx.send_following(req).await } else { cx.send(req).await };
            let Ok(resp) = sent else { continue };
            let matched = if block.req_condition {
                // Internal extractors feed the next request; the matchers wait
                // for the whole sequence (a missing response means no match).
                history.push(resp);
                for e in block.extractors.iter().filter(|e| e.internal) {
                    if let (Some(name), Some(first)) = (&e.name, extract(cx, &history, e, &v).into_iter().next()) {
                        v.insert(name.clone(), first);
                    }
                }
                history.len() == count && evaluate(rule, cx, block, &history, &mut v, &attack)
            } else {
                evaluate(rule, cx, block, std::slice::from_ref(&resp), &mut v, &attack)
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

/// `path:` requests: the base request's headers (cookies, auth) with the
/// template's method, path, headers, and body. Other origins are skipped.
fn build_path(cx: &Cx, block: &Block, template: &str, vars: &HashMap<String, String>) -> Option<Vec<u8>> {
    let url = url::Url::parse(&subst(template, vars)?).ok()?;
    let target = crate::http::Target::from_url(url.as_str()).ok()?;
    if target != *cx.target() {
        return None;
    }
    let mut pq = url.path().to_string();
    if let Some(q) = url.query() {
        pq.push('?');
        pq.push_str(q);
    }
    let mut req = RawRequest::from_bytes(cx.request_for(&block.method, &pq));
    for (k, v) in &block.headers {
        req = req.set_header(k, &subst(v, vars)?);
    }
    let body = subst(&block.body, vars)?;
    let mut bytes = req.into_bytes();
    bytes.extend_from_slice(body.as_bytes());
    Some(RawRequest::from_bytes(bytes).update_content_length().into_bytes())
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
fn part_text(cx: &Cx, seen: &[Response], part: &Part) -> String {
    let Some(resp) = seen.last() else { return String::new() };
    match part {
        Part::Nth(n, p) => match seen.get(n - 1) {
            Some(r) => part_text(cx, std::slice::from_ref(r), p),
            None => String::new(),
        },
        Part::Body => resp.body_str().to_string(),
        Part::Header => resp.head_text(),
        Part::All => format!("{}{}", resp.head_text(), resp.body_str()),
        Part::Named(h) => resp.headers_named(h).collect::<Vec<_>>().join("\n"),
        Part::BaselineBody => cx.base_response().body_str().to_string(),
    }
}

/// A DSL variable: template values (variables, payloads, extractors) first,
/// then the response's parts, then a response header (`set_cookie` is `Set-Cookie`).
fn dsl_value(cx: &Cx, seen: &[Response], vars: &HashMap<String, String>, name: &str) -> Option<Value> {
    if let Some(v) = vars.get(name) {
        return Some(Value::Str(v.clone()));
    }
    if let Some((base, n)) = super::numbered(name) {
        if let Some(r) = seen.get(n - 1) {
            return dsl_value(cx, std::slice::from_ref(r), vars, base);
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
        "host" => Value::Str(cx.target().host.clone()),
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
fn matches(cx: &Cx, seen: &[Response], m: &Matcher, vars: &HashMap<String, String>) -> (bool, Option<String>) {
    let Some(resp) = seen.last() else { return (false, None) };
    let (hit, evidence) = match &m.kind {
        MatchKind::Dsl(exprs) => {
            let env = |name: &str| dsl_value(cx, seen, vars, name);
            let hit = |e: &super::dsl::Expr| e.matches(&env);
            (if m.and { exprs.iter().all(hit) } else { exprs.iter().any(hit) }, None)
        }
        MatchKind::Status(codes) => (codes.contains(&resp.status), Some(resp.status_line.clone())),
        MatchKind::Size(sizes) => (sizes.contains(&resp.body.len()), None),
        MatchKind::Word(words) => {
            let text = part_text(cx, seen, &m.part);
            let hay = if m.case_insensitive { text.to_lowercase() } else { text };
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
            let text = part_text(cx, seen, &m.part);
            let res = res.get();
            let found: Vec<String> = res.iter().filter_map(|r| r.find(&text).map(|x| x.as_str().to_string())).collect();
            (if m.and { found.len() == res.len() } else { !found.is_empty() }, found.into_iter().next())
        }
        MatchKind::Binary(bins) => {
            let bytes: Vec<u8> = match m.part {
                Part::Body => resp.body.clone(),
                _ => part_text(cx, seen, &m.part).into_bytes(),
            };
            let has = |b: &Vec<u8>| bytes.windows(b.len().max(1)).any(|w| w == b.as_slice());
            (if m.and { bins.iter().all(has) } else { bins.iter().any(has) }, None)
        }
    };
    if m.negative {
        (!hit, None)
    } else {
        (hit, evidence.filter(|_| hit))
    }
}

fn extract(cx: &Cx, seen: &[Response], e: &Extractor, vars: &HashMap<String, String>) -> Vec<String> {
    let mut out = Vec::new();
    let Some(resp) = seen.last() else { return out };
    match &e.kind {
        ExtractKind::Dsl(exprs) => {
            let env = |name: &str| dsl_value(cx, seen, vars, name);
            out.extend(exprs.iter().filter_map(|x| x.eval(&env)).map(Value::into_string).filter(|v| !v.is_empty()));
        }
        ExtractKind::Json(paths) => {
            if let Ok(doc) = serde_json::from_str::<serde_json::Value>(&part_text(cx, seen, &e.part)) {
                for p in paths {
                    out.extend(super::json_path(&doc, p).into_iter().take(20));
                }
            }
        }
        ExtractKind::Regex(res, group) => {
            let text = part_text(cx, seen, &e.part);
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

/// Applies the block's matchers and extractors to a response and reports a
/// finding when they match. Internal extractor values are stored in `vars`.
fn evaluate(
    rule: &CheckRule,
    cx: &Cx,
    block: &Block,
    seen: &[Response],
    vars: &mut HashMap<String, String>,
    attack: &str,
) -> bool {
    let Some(resp) = seen.last() else { return false };
    let mut extracted = Vec::new();
    // Named extractor values are visible to this response's DSL matchers.
    let mut named = HashMap::new();
    for e in &block.extractors {
        let values = extract(cx, seen, e, vars);
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
    let mvars;
    let mvars = if named.is_empty() {
        &*vars
    } else {
        mvars = vars.iter().map(|(k, v)| (k.clone(), v.clone())).chain(named).collect::<HashMap<_, _>>();
        &mvars
    };
    let results: Vec<(bool, Option<String>)> = block.matchers.iter().map(|m| matches(cx, seen, m, mvars)).collect();
    let matched = if results.is_empty() {
        !extracted.is_empty()
    } else if block.matchers_and {
        results.iter().all(|r| r.0)
    } else {
        results.iter().any(|r| r.0)
    };
    let names: Vec<&str> = results
        .iter()
        .zip(&block.matchers)
        .filter(|((hit, _), m)| *hit && !m.internal)
        .filter_map(|(_, m)| m.name.as_deref())
        .collect();
    let names = names.join(", ");
    let evidence =
        results.into_iter().zip(&block.matchers).find_map(|((hit, ev), m)| ev.filter(|_| hit && !m.internal));
    if !matched {
        return false;
    }
    // Internal matchers (flow preconditions) count, but don't report alone.
    if !block.matchers.is_empty() && block.matchers.iter().all(|m| m.internal) {
        return true;
    }
    let check = &rule.check;
    let evidence = evidence.or_else(|| extracted.first().cloned()).unwrap_or_default();
    let mut info = format!("Check {} ({})", check.id, check.file.display());
    if !names.is_empty() {
        info.push_str(&format!("\nMatched: {names}"));
    }
    if !extracted.is_empty() {
        let shown: Vec<&str> = extracted.iter().take(10).map(String::as_str).collect();
        info.push_str(&format!("\nExtracted: {}", shown.join(", ")));
    }
    let param = if check.rule_scope == RuleScope::Param { cx.point().name.clone() } else { String::new() };
    cx.report(rule.alerts[0].raise(param, evidence).attack(attack).other_info(info), resp);
    true
}
