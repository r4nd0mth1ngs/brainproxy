//! Runs a declarative check as an active rule. Every request is sent through
//! `Cx` (scope guard, auth session, rate limit, stop/deadline).

use std::collections::HashMap;

use super::{combos, Block, Check, ExtractKind, Extractor, MatchKind, Matcher, Part, MAX_COMBOS, PLACEHOLDER};
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

/// Fills `{{name}}` placeholders. Returns None when one names a value that
/// isn't available (e.g. an extractor that matched nothing), like Nuclei,
/// which skips such requests.
fn subst(text: &str, vars: &HashMap<String, String>) -> Option<String> {
    let mut missing = false;
    let out = PLACEHOLDER.replace_all(text, |c: &regex::Captures| match vars.get(&c[1]) {
        Some(v) => v.clone(),
        None => {
            missing = true;
            String::new()
        }
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
            if c[1].starts_with("randstr") {
                vars.entry(c[1].to_string()).or_insert_with(|| rand_alnum(25));
            }
        }
    }
}

async fn run(rule: &CheckRule, cx: &Cx) {
    let check = &rule.check;
    let mut vars = builtins(cx, check.rule_scope);
    add_randstr(check, &mut vars);
    // Variables may refer to builtins and to earlier variables.
    for (k, v) in &check.variables {
        if let Some(v) = subst(v, &vars) {
            vars.insert(k.clone(), v);
        }
    }
    for block in &check.blocks {
        if run_block(rule, cx, block, &mut vars).await {
            return;
        }
    }
}

/// Runs one request block; true when the check should stop (stop-at-first-match).
async fn run_block(rule: &CheckRule, cx: &Cx, block: &Block, vars: &mut HashMap<String, String>) -> bool {
    if !block.inject.is_empty() {
        for value in &block.inject {
            if cx.stopped() {
                return true;
            }
            let sent = if block.inject_raw { cx.send_payload_raw(value).await } else { cx.send_payload(value).await };
            let Ok(resp) = sent else { continue };
            if evaluate(rule, cx, block, &resp, vars, value) && block.stop_at_first_match {
                return true;
            }
        }
        return false;
    }
    for combo in combos(&block.payloads, block.attack, MAX_COMBOS) {
        let mut v = vars.clone();
        v.extend(combo.iter().cloned());
        let attack = combo.iter().map(|(k, x)| format!("{k}={x}")).collect::<Vec<_>>().join(", ");
        let requests = block.paths.iter().map(|p| (p, false)).chain(block.raws.iter().map(|r| (r, true)));
        for (template, raw) in requests {
            if cx.stopped() {
                return true;
            }
            let req = if raw { build_raw(cx, block, template, &v) } else { build_path(cx, block, template, &v) };
            let Some(req) = req else { continue };
            let sent = if block.redirects { cx.send_following(req).await } else { cx.send(req).await };
            let Ok(resp) = sent else { continue };
            let matched = evaluate(rule, cx, block, &resp, &mut v, &attack);
            // Internal extractor values carry over to later requests.
            for e in block.extractors.iter().filter(|e| e.internal) {
                if let Some(name) = &e.name {
                    if let Some(x) = v.get(name) {
                        vars.insert(name.clone(), x.clone());
                    }
                }
            }
            if matched && block.stop_at_first_match {
                return true;
            }
        }
    }
    false
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

fn part_text(cx: &Cx, resp: &Response, part: &Part) -> String {
    match part {
        Part::Body => resp.body_str().to_string(),
        Part::Header => resp.head_text(),
        Part::All => format!("{}{}", resp.head_text(), resp.body_str()),
        Part::Named(h) => resp.headers_named(h).collect::<Vec<_>>().join("\n"),
        Part::BaselineBody => cx.base_response().body_str().to_string(),
    }
}

/// Whether the matcher matches, with evidence when it does.
fn matches(cx: &Cx, resp: &Response, m: &Matcher, vars: &HashMap<String, String>) -> (bool, Option<String>) {
    let (hit, evidence) = match &m.kind {
        MatchKind::Status(codes) => (codes.contains(&resp.status), Some(resp.status_line.clone())),
        MatchKind::Size(sizes) => (sizes.contains(&resp.body.len()), None),
        MatchKind::Word(words) => {
            let text = part_text(cx, resp, &m.part);
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
            let text = part_text(cx, resp, &m.part);
            let res = res.get();
            let found: Vec<String> = res.iter().filter_map(|r| r.find(&text).map(|x| x.as_str().to_string())).collect();
            (if m.and { found.len() == res.len() } else { !found.is_empty() }, found.into_iter().next())
        }
        MatchKind::Binary(bins) => {
            let bytes: Vec<u8> = match m.part {
                Part::Body => resp.body.clone(),
                _ => part_text(cx, resp, &m.part).into_bytes(),
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

fn extract(cx: &Cx, resp: &Response, e: &Extractor) -> Vec<String> {
    let mut out = Vec::new();
    match &e.kind {
        ExtractKind::Regex(res, group) => {
            let text = part_text(cx, resp, &e.part);
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
    resp: &Response,
    vars: &mut HashMap<String, String>,
    attack: &str,
) -> bool {
    let mut extracted = Vec::new();
    for e in &block.extractors {
        let values = extract(cx, resp, e);
        if e.internal {
            if let (Some(name), Some(first)) = (&e.name, values.first()) {
                vars.insert(name.clone(), first.clone());
            }
        } else {
            extracted.extend(values);
        }
    }
    let results: Vec<(bool, Option<String>)> = block.matchers.iter().map(|m| matches(cx, resp, m, vars)).collect();
    let matched = if results.is_empty() {
        !extracted.is_empty()
    } else if block.matchers_and {
        results.iter().all(|r| r.0)
    } else {
        results.iter().any(|r| r.0)
    };
    let evidence = results.into_iter().find_map(|(hit, ev)| ev.filter(|_| hit));
    if !matched {
        return false;
    }
    let check = &rule.check;
    let evidence = evidence.or_else(|| extracted.first().cloned()).unwrap_or_default();
    let mut info = format!("Check {} ({})", check.id, check.file.display());
    if !extracted.is_empty() {
        let shown: Vec<&str> = extracted.iter().take(10).map(String::as_str).collect();
        info.push_str(&format!("\nExtracted: {}", shown.join(", ")));
    }
    let param = if check.rule_scope == RuleScope::Param { cx.point().name.clone() } else { String::new() };
    cx.report(rule.alerts[0].raise(param, evidence).attack(attack).other_info(info), resp);
    true
}
