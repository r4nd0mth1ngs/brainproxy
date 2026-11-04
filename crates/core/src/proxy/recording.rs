//! Every change to what the proxy records: the recording scope and the TLS pass-through list.
//! Agents change both legitimately, but narrowing either hides traffic (the proxy then keeps
//! only a request line, or a tunnel's row), so each change is kept with who made it and when.
//! One an agent made that narrowed recording stays flagged until a person changes that
//! setting again (from the app or a terminal, even saving it unchanged), or the agent puts it
//! back as it was: later changes by the agent, or more of them than the log keeps, don't hide it.
//!
//! The log is one JSON value in `meta` ([`CHANGES_KEY`]), so it needs no schema change.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::error::{Error, Result};
use crate::proxy::config::Scope;
use crate::store::Store;

/// Key in the project `meta` table holding the [`Changes`].
pub const CHANGES_KEY: &str = "proxy.recording_changes";
/// Changes kept, the oldest dropped first.
const KEEP: usize = 100;

/// One change to the recording scope or the pass-through list.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Change {
    pub time: String,
    /// gui, cli or mcp.
    pub by: String,
    /// `scope` or `passthrough`.
    pub setting: String,
    /// Whether it left less traffic recorded in full than before. See [`scope_change`] and
    /// [`passthrough_change`].
    pub narrowed: bool,
    /// What changed, for people: "include: added ^a\.test$".
    pub summary: String,
    pub before: Value,
    pub after: Value,
}

impl Change {
    /// "recording scope changed via MCP (an agent) at 2026-01-31T12:00:00.000Z, narrowing
    /// recording: include: added ^a\.test$", for people.
    pub fn describe(&self) -> String {
        let what = if self.setting == "passthrough" { "TLS pass-through list" } else { "recording scope" };
        let narrowing = if self.narrowed { ", narrowing recording" } else { "" };
        format!(
            "{what} changed {} at {}{narrowing}: {}",
            crate::provenance::describe(Some(&self.by)),
            self.time,
            self.summary
        )
    }
}

/// An agent's narrowing nobody has looked at since, and the setting as it was before it.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct Flag {
    change: Change,
    baseline: Value,
}

/// The log of changes, and the agents' narrowing changes not changed by a person since.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Changes {
    /// Oldest first, at most [`KEEP`].
    #[serde(default)]
    changes: Vec<Change>,
    /// By setting.
    #[serde(default)]
    flagged: BTreeMap<String, Flag>,
}

impl Changes {
    /// The latest `n` changes, newest first.
    pub fn recent(&self, n: usize) -> Vec<&Change> {
        self.changes.iter().rev().take(n).collect()
    }

    /// Per setting, the latest change through MCP that narrowed recording, while no person
    /// has changed that setting since and the agent hasn't put it back.
    pub fn narrowed_by_agent(&self) -> Vec<&Change> {
        self.flagged.values().map(|f| &f.change).collect()
    }

    /// Adds a change of `setting` by `by` (`summary` None: saved unchanged).
    fn note(&mut self, by: &str, setting: &str, before: Value, after: Value, summary: Option<(bool, String)>) {
        let Some((narrowed, summary)) = summary else {
            // A person saving it as it is has seen it; an agent doing so changes nothing.
            if by != "mcp" {
                self.flagged.remove(setting);
            }
            return;
        };
        let change = Change {
            time: crate::ws::now_iso(),
            by: by.to_string(),
            setting: setting.to_string(),
            narrowed,
            summary,
            before: before.clone(),
            after: after.clone(),
        };
        if by != "mcp" {
            self.flagged.remove(setting);
        } else if narrowed {
            let baseline = self.flagged.get(setting).map_or(before, |f| f.baseline.clone());
            self.flagged.insert(setting.to_string(), Flag { change: change.clone(), baseline });
        } else if self.flagged.get(setting).is_some_and(|f| f.baseline == after) {
            self.flagged.remove(setting);
        }
        self.changes.push(change);
        let extra = self.changes.len().saturating_sub(KEEP);
        self.changes.drain(..extra);
    }
}

/// Whether out-of-scope traffic is recorded in full: it is recorded too, or nothing is out of scope.
fn records_everything(s: &Scope) -> bool {
    s.record_out_of_scope || (s.include.is_empty() && s.exclude.is_empty())
}

/// Whether `list` holds pattern `p`, compared as the commands that edit the lists do.
fn has(list: &[String], p: &str) -> bool {
    list.iter().any(|q| q.trim().eq_ignore_ascii_case(p.trim()))
}

/// "added a, b, removed c" between two pattern lists, or None if they hold the same patterns.
fn list_diff(before: &[String], after: &[String]) -> Option<String> {
    let added: Vec<&str> = after.iter().filter(|p| !has(before, p)).map(String::as_str).collect();
    let removed: Vec<&str> = before.iter().filter(|p| !has(after, p)).map(String::as_str).collect();
    let mut parts = Vec::new();
    if !added.is_empty() {
        parts.push(format!("added {}", added.join(", ")));
    }
    if !removed.is_empty() {
        parts.push(format!("removed {}", removed.join(", ")));
    }
    (!parts.is_empty()).then(|| parts.join(", "))
}

/// Whether going from `before` to `after` narrowed recording, and what changed; None if
/// nothing did. It narrowed when traffic is now left out that wasn't before: an include list
/// that went from empty (everything) to some hosts, or lost a pattern; a new exclude pattern;
/// or out-of-scope recording turned off. None of that narrows anything while out-of-scope
/// traffic is recorded in full anyway.
pub fn scope_change(before: &Scope, after: &Scope) -> Option<(bool, String)> {
    let include = list_diff(&before.include, &after.include);
    let exclude = list_diff(&before.exclude, &after.exclude);
    let include_narrowed = !after.include.is_empty()
        && (before.include.is_empty() || before.include.iter().any(|p| !has(&after.include, p)));
    let exclude_grew = after.exclude.iter().any(|p| !has(&before.exclude, p));
    let narrowed = !records_everything(after) && (records_everything(before) || include_narrowed || exclude_grew);
    let mut parts = Vec::new();
    if let Some(d) = include {
        parts.push(format!("include: {d}"));
    }
    if let Some(d) = exclude {
        parts.push(format!("exclude: {d}"));
    }
    if before.record_out_of_scope != after.record_out_of_scope {
        let state = if after.record_out_of_scope { "on" } else { "off" };
        parts.push(format!("out-of-scope recording turned {state}"));
    }
    (!parts.is_empty()).then(|| (narrowed, parts.join("; ")))
}

/// Whether the pass-through list narrowed recording (a pattern was added: its hosts' TLS is
/// no longer decrypted, so only the connection is recorded), and what changed; None if nothing did.
pub fn passthrough_change(before: &[String], after: &[String]) -> Option<(bool, String)> {
    let added = after.iter().any(|p| !has(before, p));
    list_diff(before, after).map(|d| (added, d))
}

impl Store {
    /// The log of changes to what the proxy records.
    pub fn recording_changes(&self) -> Result<Changes> {
        match self.meta_get(CHANGES_KEY)? {
            Some(v) => serde_json::from_str(&v).map_err(|e| Error::InvalidInput(format!("{CHANGES_KEY}: {e}"))),
            None => Ok(Changes::default()),
        }
    }

    /// Notes that this process saved the recording scope, `before` as it was.
    pub fn note_scope_change(&mut self, before: &Scope, after: &Scope) -> Result<()> {
        let to_json = |s: &Scope| serde_json::to_value(s).unwrap_or_default();
        self.note_recording_change("scope", to_json(before), to_json(after), scope_change(before, after))
    }

    /// Notes that this process saved the TLS pass-through list, `before` as it was.
    pub fn note_passthrough_change(&mut self, before: &[String], after: &[String]) -> Result<()> {
        let summary = passthrough_change(before, after);
        self.note_recording_change("passthrough", Value::from(before), Value::from(after), summary)
    }

    fn note_recording_change(
        &mut self,
        setting: &str,
        before: Value,
        after: Value,
        summary: Option<(bool, String)>,
    ) -> Result<()> {
        let by = crate::provenance::origin();
        self.meta_update(CHANGES_KEY, |old| {
            let mut changes: Changes = match old {
                Some(v) => serde_json::from_str(&v).map_err(|e| Error::InvalidInput(format!("{CHANGES_KEY}: {e}")))?,
                None => Changes::default(),
            };
            changes.note(by, setting, before, after, summary);
            let json = serde_json::to_string(&changes).map_err(|e| Error::InvalidInput(e.to_string()))?;
            Ok((Some(json), ()))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scope(include: &[&str], exclude: &[&str], record: bool) -> Scope {
        let v = |l: &[&str]| l.iter().map(|s| s.to_string()).collect();
        Scope { include: v(include), exclude: v(exclude), record_out_of_scope: record }
    }

    #[test]
    fn narrowing_the_scope_is_told_from_widening_it() {
        let all = scope(&[], &[], false);
        let a = scope(&["a"], &[], false);
        let ab = scope(&["a", "b"], &[], false);
        assert_eq!(scope_change(&all, &a), Some((true, "include: added a".into())));
        assert_eq!(scope_change(&a, &ab), Some((false, "include: added b".into())));
        assert_eq!(scope_change(&ab, &a), Some((true, "include: removed b".into())));
        assert_eq!(scope_change(&a, &all), Some((false, "include: removed a".into())));
        assert_eq!(scope_change(&a, &scope(&["c"], &[], false)), Some((true, "include: added c, removed a".into())));
        assert_eq!(scope_change(&all, &scope(&[], &["x"], false)), Some((true, "exclude: added x".into())));
        assert_eq!(scope_change(&scope(&[], &["x"], false), &all), Some((false, "exclude: removed x".into())));
        assert_eq!(scope_change(&a, &a), None);
        // Out-of-scope traffic recorded in full: the scope narrows interception, not recording.
        let a_rec = scope(&["a"], &[], true);
        assert_eq!(
            scope_change(&all, &a_rec),
            Some((false, "include: added a; out-of-scope recording turned on".into()))
        );
        assert_eq!(scope_change(&a_rec, &a), Some((true, "out-of-scope recording turned off".into())));
        assert_eq!(
            scope_change(&scope(&[], &[], true), &all),
            Some((false, "out-of-scope recording turned off".into()))
        );
    }

    #[test]
    fn a_new_pass_through_pattern_narrows_recording() {
        let v = |l: &[&str]| l.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        assert_eq!(passthrough_change(&[], &v(&["a.test"])), Some((true, "added a.test".into())));
        assert_eq!(passthrough_change(&v(&["a.test"]), &[]), Some((false, "removed a.test".into())));
        assert_eq!(passthrough_change(&v(&["a.test"]), &v(&["A.test"])), None);
    }

    #[test]
    fn an_agents_narrowing_stays_flagged_until_a_person_changes_the_setting() {
        let (all, a, ab) = (scope(&[], &[], false), scope(&["a"], &[], false), scope(&["a", "b"], &[], false));
        let j = |s: &Scope| serde_json::to_value(s).unwrap();
        let mut c = Changes::default();
        c.note("mcp", "scope", j(&all), j(&a), scope_change(&all, &a));
        assert_eq!(c.narrowed_by_agent().len(), 1);
        // The agent widening it a little, or saving it unchanged, doesn't hide it.
        c.note("mcp", "scope", j(&a), j(&ab), scope_change(&a, &ab));
        c.note("mcp", "scope", j(&ab), j(&ab), None);
        assert_eq!(c.narrowed_by_agent()[0].summary, "include: added a");
        // Nor does pushing it out of the log.
        for _ in 0..KEEP {
            c.note(
                "mcp",
                "passthrough",
                Value::from(Vec::<String>::new()),
                Value::from(vec!["x"]),
                Some((false, "x".into())),
            );
        }
        assert_eq!(c.recent(usize::MAX).len(), KEEP);
        assert_eq!(c.narrowed_by_agent().iter().filter(|c| c.setting == "scope").count(), 1);
        // A person saving it, even unchanged, has seen it.
        c.note("gui", "scope", j(&ab), j(&ab), None);
        assert!(c.narrowed_by_agent().iter().all(|c| c.setting != "scope"));
        // An agent putting it back as it was clears it too.
        c.note("mcp", "scope", j(&ab), j(&a), scope_change(&ab, &a));
        assert_eq!(c.narrowed_by_agent().len(), 1);
        c.note("mcp", "scope", j(&a), j(&ab), scope_change(&a, &ab));
        assert!(c.narrowed_by_agent().is_empty());
    }
}
