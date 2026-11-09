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
    /// Rescan: findings it didn't find again and removed (none of them triaged).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub removed: Option<usize>,
    /// Rescan: triaged findings it didn't find again, kept with 0 hits.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kept_not_found: Option<usize>,
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
    loop {
        let batch = store.scan_messages_after(last, &sources, BATCH)?;
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
    let before = store.findings_rescan_start("passive")?;
    store.meta_set(WATERMARK_KEY, None)?;
    let mut stats = scan_pending(store)?;
    let (removed, kept) = store.findings_rescan_finish("passive")?;
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
