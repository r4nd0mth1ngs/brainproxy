//! Passive scanner: runs every enabled rule over captured exchanges. Scanning is
//! incremental: a watermark records the last history row scanned, so callers
//! (proxy, send, findings queries) can cheaply "catch up" at any time.

pub mod rules;
pub mod util;

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
    /// History sources that get scanned.
    #[serde(default = "default_sources")]
    pub sources: Vec<String>,
}

fn default_sources() -> Vec<String> {
    ["proxy", "send", "crawl"].map(String::from).to_vec()
}

impl Default for PassiveSettings {
    fn default() -> Self {
        Self { disabled: Vec::new(), sources: default_sources() }
    }
}

pub fn all_rules() -> &'static [Box<dyn PassiveRule>] {
    static RULES: OnceLock<Vec<Box<dyn PassiveRule>>> = OnceLock::new();
    RULES.get_or_init(rules::all)
}

/// Runs enabled rules over one message.
pub fn scan_message(msg: &Message, disabled: &[u32]) -> Vec<Finding> {
    let mut out = Vec::new();
    for rule in all_rules() {
        if !disabled.contains(&rule.id()) {
            rule.scan(msg, &mut out);
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
            let findings = scan_message(msg, &settings.disabled);
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

/// Clears passive findings and rescans all history from the start.
pub fn rescan(store: &mut Store) -> Result<ScanStats> {
    store.findings_reset("passive")?;
    store.meta_set(WATERMARK_KEY, None)?;
    scan_pending(store)
}
