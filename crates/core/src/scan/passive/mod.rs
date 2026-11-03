//! Passive scanner: runs every enabled rule over captured exchanges. Scanning is
//! incremental: a watermark records the last history row scanned, so callers
//! (proxy, send, findings queries) can cheaply "catch up" at any time.

pub mod rules;
pub mod util;

use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use serde::{Deserialize, Serialize};

use crate::error::Result;
use crate::scan::{Finding, Message, PassiveRule};
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
}

fn default_sources() -> Vec<String> {
    ["proxy", "send", "crawl", "crawl-browser"].map(String::from).to_vec()
}

impl Default for PassiveSettings {
    fn default() -> Self {
        Self { disabled: Vec::new(), disabled_checks: Vec::new(), sources: default_sources() }
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

/// Runs enabled rules, then the enabled passive checks, over one message.
pub fn scan_message(msg: &Message, settings: &PassiveSettings) -> Vec<Finding> {
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
}

/// Scans every capture recorded since the last call.
pub fn scan_pending(store: &mut Store) -> Result<ScanStats> {
    let settings: PassiveSettings = store.setting(SETTINGS_KEY)?;
    let mut last: i64 = store.meta_get(WATERMARK_KEY)?.and_then(|v| v.parse().ok()).unwrap_or(0);
    let mut stats = ScanStats { last_id: last, ..Default::default() };
    // Rows recorded while we scan are left for the next call.
    let max_at_start = store.max_history_id()?;
    if max_at_start <= last {
        return Ok(stats);
    }
    loop {
        let batch = store.scan_messages_after(last, &settings.sources, BATCH)?;
        // Rows from unscanned sources are skipped by the query; jump the watermark past them.
        let Some(batch_last) = batch.last().map(|m| m.history_id) else { break };
        for msg in &batch {
            let findings = scan_message(msg, &settings);
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
    for msg in store.scan_messages_after(id - 1, &settings.sources, 1)?.iter().filter(|m| m.history_id == id) {
        new += store.record_findings("passive", msg, &scan_message(msg, &settings))?;
    }
    Ok(new)
}

/// Clears passive findings and rescans all history from the start.
pub fn rescan(store: &mut Store) -> Result<ScanStats> {
    store.findings_reset("passive")?;
    store.meta_set(WATERMARK_KEY, None)?;
    scan_pending(store)
}
