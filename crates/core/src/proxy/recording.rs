//! Every change to what the proxy records: the recording scope and the TLS pass-through list.
//! Agents change both legitimately, but narrowing either hides traffic (the proxy then keeps
//! only a request line, or a tunnel's row), so each change is kept with who made it and when.
//! One an agent made that narrowed recording stays flagged until a person changes that
//! setting again (from the app or a terminal, even saving it unchanged), or the agent puts it
//! back as it was: later changes by the agent, or any number of other changes, don't hide it.
//! The log keeps every change made through MCP or that narrowed recording; only a person's
//! routine ones are dropped, the oldest first, past [`KEEP`].
//!
//! The log is one JSON value in `meta` ([`CHANGES_KEY`]), so it needs no schema change.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use rusqlite::{params, OptionalExtension};

use crate::connection::{ConnectionSettings, CONNECTION_KEY};
use crate::error::{Error, Result};
use crate::proxy::config::{Scope, SCOPE_KEY};
use crate::store::Store;

/// Key in the project `meta` table holding the [`Changes`].
pub const CHANGES_KEY: &str = "proxy.recording_changes";
/// A person's changes that didn't narrow recording kept, the oldest dropped first. Changes
/// through MCP and narrowing ones are never dropped.
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
    /// Whether the log keeps it for good: it came through MCP or narrowed recording.
    pub fn kept(&self) -> bool {
        self.narrowed || self.by == "mcp"
    }

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
    /// Oldest first: every [kept](Change::kept) one and at most [`KEEP`] others.
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

    /// The latest `n` changes and every [kept](Change::kept) one before them, newest first:
    /// any number of later changes can't push an agent's or a narrowing change out of view.
    pub fn shown(&self, n: usize) -> Vec<&Change> {
        self.changes.iter().rev().enumerate().filter(|(i, c)| *i < n || c.kept()).map(|(_, c)| c).collect()
    }

    /// Every [kept](Change::kept) change, newest first.
    pub fn kept(&self) -> Vec<&Change> {
        self.shown(0)
    }

    /// Per setting, the latest change through MCP that narrowed recording, while no person
    /// has changed that setting since and the agent hasn't put it back.
    pub fn narrowed_by_agent(&self) -> Vec<&Change> {
        self.flagged.values().map(|f| &f.change).collect()
    }

    /// Adds a change of `setting` by `by` (`summary` None: saved unchanged). `reviewed`: the
    /// command saved that setting itself, so saving it unchanged shows a person has seen it;
    /// another command saving the settings it is kept with doesn't.
    fn note(
        &mut self,
        by: &str,
        setting: &str,
        before: Value,
        after: Value,
        summary: Option<(bool, String)>,
        reviewed: bool,
    ) {
        let Some((narrowed, summary)) = summary else {
            // A person saving it as it is has seen it; an agent doing so changes nothing.
            if by != "mcp" && reviewed {
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
        // Put back as it was before the agent's first narrowing, it is as a person left it,
        // whatever this last change did on its own.
        if by != "mcp" || self.flagged.get(setting).is_some_and(|f| f.baseline == after) {
            self.flagged.remove(setting);
        } else if narrowed {
            let baseline = self.flagged.get(setting).map_or(before, |f| f.baseline.clone());
            self.flagged.insert(setting.to_string(), Flag { change: change.clone(), baseline });
        }
        self.changes.push(change);
        // Past KEEP routine changes, drop the oldest of them; the kept ones stay wherever they are.
        let mut extra = self.changes.iter().filter(|c| !c.kept()).count().saturating_sub(KEEP);
        self.changes.retain(|c| {
            let drop = extra > 0 && !c.kept();
            extra -= usize::from(drop);
            !drop
        });
    }
}

/// Whether nothing is out of scope.
fn everything_in_scope(s: &Scope) -> bool {
    s.include.is_empty() && s.exclude.is_empty()
}

/// How two patterns of a list compare: the scope's regexes exactly (`\d` isn't `\D`), the
/// pass-through list's host patterns as the commands that edit it do.
type Same = fn(&str, &str) -> bool;
const EXACT: Same = |a, b| a == b;
const HOST: Same = |a, b| a.trim().eq_ignore_ascii_case(b.trim());

/// Whether `list` holds pattern `p`.
fn has(same: Same, list: &[String], p: &str) -> bool {
    list.iter().any(|q| same(q, p))
}

/// "added a, b, removed c" between two pattern lists, or None if they hold the same patterns.
fn list_diff(same: Same, before: &[String], after: &[String]) -> Option<String> {
    let added: Vec<&str> = after.iter().filter(|p| !has(same, before, p)).map(String::as_str).collect();
    let removed: Vec<&str> = before.iter().filter(|p| !has(same, after, p)).map(String::as_str).collect();
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
/// or out-of-scope recording turned off while something is out of scope. Out-of-scope
/// recording doesn't make a smaller scope harmless: HTTPS to a host outside it is tunnelled,
/// never decrypted, so only the connection is recorded.
pub fn scope_change(before: &Scope, after: &Scope) -> Option<(bool, String)> {
    let include = list_diff(EXACT, &before.include, &after.include);
    let exclude = list_diff(EXACT, &before.exclude, &after.exclude);
    let include_narrowed = !after.include.is_empty()
        && (before.include.is_empty() || before.include.iter().any(|p| !has(EXACT, &after.include, p)));
    let exclude_grew = after.exclude.iter().any(|p| !has(EXACT, &before.exclude, p));
    let smaller = everything_in_scope(before) || include_narrowed || exclude_grew;
    let recording_off = before.record_out_of_scope && !after.record_out_of_scope;
    let narrowed = !everything_in_scope(after) && (smaller || recording_off);
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
    let added = after.iter().any(|p| !has(HOST, before, p));
    list_diff(HOST, before, after).map(|d| (added, d))
}

impl Store {
    /// The log of changes to what the proxy records.
    pub fn recording_changes(&self) -> Result<Changes> {
        match self.meta_get(CHANGES_KEY)? {
            Some(v) => serde_json::from_str(&v).map_err(|e| Error::InvalidInput(format!("{CHANGES_KEY}: {e}"))),
            None => Ok(Changes::default()),
        }
    }

    /// Saves the recording scope and logs the change (see [`Store::save_logged`]).
    pub fn save_scope(&mut self, scope: &Scope) -> Result<()> {
        let to_json = |s: &Scope| serde_json::to_value(s).unwrap_or_default();
        self.save_logged(SCOPE_KEY, scope, true, |before: Scope| {
            ("scope", to_json(&before), to_json(scope), scope_change(&before, scope))
        })
    }

    /// Saves the connection settings, validated, and logs a change to their TLS pass-through
    /// list (see [`Store::save_logged`]). `reviewed`: the command was one that edits that list.
    pub fn save_connection_settings(&mut self, s: &ConnectionSettings, reviewed: bool) -> Result<()> {
        s.validate()?;
        self.save_logged(CONNECTION_KEY, s, reviewed, |before: ConnectionSettings| {
            let summary = passthrough_change(&before.passthrough, &s.passthrough);
            ("passthrough", Value::from(before.passthrough), Value::from(s.passthrough.clone()), summary)
        })
    }

    /// Writes setting `key`, bumps the settings version so running proxies reload, and logs
    /// what `change` makes of the setting as it was, in one write transaction: a save by another
    /// process can't land between them, unlogged, or have its flag cleared by this one.
    fn save_logged<T: Serialize + serde::de::DeserializeOwned + Default>(
        &mut self,
        key: &str,
        value: &T,
        reviewed: bool,
        change: impl FnOnce(T) -> (&'static str, Value, Value, Option<(bool, String)>),
    ) -> Result<()> {
        let by = crate::provenance::origin();
        let json = serde_json::to_string(value).map_err(|e| Error::InvalidInput(e.to_string()))?;
        let key = format!("setting.{key}");
        let tx = self.write_tx()?;
        let get = |k: &str| tx.query_row("SELECT value FROM meta WHERE key = ?1", [k], |r| r.get::<_, String>(0));
        let before: T = match get(&key).optional()? {
            Some(v) => serde_json::from_str(&v).map_err(|e| Error::InvalidInput(format!("{key}: {e}")))?,
            None => T::default(),
        };
        let mut changes: Changes = match get(CHANGES_KEY).optional()? {
            Some(v) => serde_json::from_str(&v).map_err(|e| Error::InvalidInput(format!("{CHANGES_KEY}: {e}")))?,
            None => Changes::default(),
        };
        let (setting, before, after, summary) = change(before);
        changes.note(by, setting, before, after, summary, reviewed);
        let log = serde_json::to_string(&changes).map_err(|e| Error::InvalidInput(e.to_string()))?;
        let set = "INSERT INTO meta (key, value) VALUES (?1, ?2) ON CONFLICT(key) DO UPDATE SET value = excluded.value";
        tx.execute(set, params![key, json])?;
        tx.execute(set, params![CHANGES_KEY, log])?;
        tx.execute(
            "INSERT INTO meta (key, value) VALUES ('settings_version', '1')
             ON CONFLICT(key) DO UPDATE SET value = CAST(value AS INTEGER) + 1",
            [],
        )?;
        tx.commit()?;
        Ok(())
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
        // Regexes are compared exactly: `\d` isn't `\D`.
        assert_eq!(
            scope_change(&scope(&[r"^\D+$"], &[], false), &scope(&[r"^\d+$"], &[], false)),
            Some((true, r"include: added ^\d+$, removed ^\D+$".into()))
        );
        // Out-of-scope traffic recorded too doesn't make a smaller scope harmless: HTTPS outside
        // it is tunnelled, never decrypted.
        let a_rec = scope(&["a"], &[], true);
        assert_eq!(
            scope_change(&all, &a_rec),
            Some((true, "include: added a; out-of-scope recording turned on".into()))
        );
        assert_eq!(
            scope_change(&a_rec, &ab),
            Some((true, "include: added b; out-of-scope recording turned off".into()))
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
        c.note("mcp", "scope", j(&all), j(&a), scope_change(&all, &a), true);
        assert_eq!(c.narrowed_by_agent().len(), 1);
        // The agent widening it a little, or saving it unchanged, doesn't hide it.
        c.note("mcp", "scope", j(&a), j(&ab), scope_change(&a, &ab), true);
        c.note("mcp", "scope", j(&ab), j(&ab), None, true);
        assert_eq!(c.narrowed_by_agent()[0].summary, "include: added a");
        // Nor do more changes than the log keeps: those through MCP are never dropped.
        for _ in 0..KEEP {
            c.note(
                "gui",
                "passthrough",
                Value::from(Vec::<String>::new()),
                Value::from(vec!["x"]),
                Some((false, "x".into())),
                true,
            );
        }
        assert_eq!(c.recent(usize::MAX).len(), KEEP + 2);
        assert_eq!(c.kept().len(), 2);
        assert_eq!(c.narrowed_by_agent().iter().filter(|c| c.setting == "scope").count(), 1);
        // A person saving it, even unchanged, has seen it.
        c.note("gui", "scope", j(&ab), j(&ab), None, true);
        assert!(c.narrowed_by_agent().iter().all(|c| c.setting != "scope"));
        // An agent putting it back as it was clears it too.
        c.note("mcp", "scope", j(&ab), j(&a), scope_change(&ab, &a), true);
        assert_eq!(c.narrowed_by_agent().len(), 1);
        c.note("mcp", "scope", j(&a), j(&ab), scope_change(&a, &ab), true);
        assert!(c.narrowed_by_agent().is_empty());
        // Put back by a change that narrows on its own (b replaced by a): cleared all the same.
        let b = scope(&["b"], &[], false);
        c.note("mcp", "scope", j(&a), j(&b), scope_change(&a, &b), true);
        assert_eq!(c.narrowed_by_agent().len(), 1);
        c.note("mcp", "scope", j(&b), j(&a), scope_change(&b, &a), true);
        assert!(c.narrowed_by_agent().is_empty());
        // Saved unchanged by a command that doesn't edit the setting: not a person's review.
        c.note("mcp", "scope", j(&a), j(&b), scope_change(&a, &b), true);
        c.note("gui", "scope", j(&b), j(&b), None, false);
        assert_eq!(c.narrowed_by_agent().len(), 1);
    }

    #[test]
    fn an_agents_narrowing_stays_in_the_log_however_many_changes_follow() {
        let (all, none) = (scope(&[], &[], false), scope(&["^nothing$"], &[], false));
        let j = |s: &Scope| serde_json::to_value(s).unwrap();
        let list = |l: &[&str]| Value::from(l.iter().map(|s| s.to_string()).collect::<Vec<_>>());
        let mut c = Changes::default();
        // The agent narrows the scope to nothing, sends its traffic, and puts it back: no flag.
        c.note("mcp", "scope", j(&all), j(&none), scope_change(&all, &none), true);
        c.note("mcp", "scope", j(&none), j(&all), scope_change(&none, &all), true);
        assert!(c.narrowed_by_agent().is_empty());
        // Then adds and removes a pass-through pattern again and again, and a person makes a
        // lot of routine changes.
        for _ in 0..2 * KEEP {
            c.note("mcp", "passthrough", list(&[]), list(&["z.test"]), Some((true, "added z.test".into())), true);
            c.note("mcp", "passthrough", list(&["z.test"]), list(&[]), Some((false, "removed z.test".into())), true);
            c.note("gui", "scope", j(&all), j(&all), Some((false, "include: removed b".into())), true);
        }
        assert!(c.narrowed_by_agent().is_empty());
        // The narrowing is still in the log and in what `scope show` lists; the routine changes
        // are capped.
        let narrowing = |l: &[&Change]| l.iter().any(|c| c.setting == "scope" && c.by == "mcp" && c.narrowed);
        assert!(narrowing(&c.recent(usize::MAX)));
        assert!(narrowing(&c.shown(20)));
        assert!(narrowing(&c.kept()));
        assert_eq!(c.recent(usize::MAX).iter().filter(|c| !c.kept()).count(), KEEP);
        assert_eq!(c.kept().len(), 2 + 4 * KEEP);
        // The latest changes come first, whatever they are.
        assert_eq!(c.shown(1)[0].by, "gui");
        assert_eq!(c.shown(1).len(), 1 + c.kept().len());
        // It survives being saved and read back.
        let back: Changes = serde_json::from_str(&serde_json::to_string(&c).unwrap()).unwrap();
        assert!(narrowing(&back.shown(20)));
    }
}
