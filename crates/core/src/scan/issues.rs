//! Findings as records: issues above instances, a timeline of what happened to each finding,
//! and what each scan saw.
//!
//! - An **issue** is one root cause: one alert type on one host. Its findings (instances) are
//!   the URLs and parameters it was seen at, so a header missing on 500 pages is one issue
//!   with 500 locations. Testers can split an issue (two bugs that share a rule) and merge
//!   issues (one bug seen on two hosts).
//! - A **finding event** is one change, with who made it and when: created, a state or note
//!   change, a retest and its outcome, a move between issues, a fixed finding seen again
//!   (regressed), a removal. The `findings` row keeps only the current state and note.
//! - A **scan observation** is what one active scan saw of one finding (new, still there,
//!   gone), stored when the scan ends, so trends are read rather than worked out again.

use rusqlite::{params, Connection, OptionalExtension};
use serde_json::{json, Map, Value};

use crate::error::{Error, Result};
use crate::scan::compare::Comparison;
use crate::scan::findings_db::{FindingFilter, REMOVED};
use crate::store::Store;

/// Schema v15.
pub(crate) const SCHEMA_V15: &str = "
CREATE TABLE IF NOT EXISTS issues (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    time TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    alert_ref TEXT NOT NULL,
    host TEXT NOT NULL,
    title TEXT
);
CREATE INDEX IF NOT EXISTS issues_key ON issues(alert_ref, host);
CREATE TABLE IF NOT EXISTS finding_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    time TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    finding_id INTEGER,
    issue_id INTEGER,
    origin TEXT,
    kind TEXT NOT NULL,
    old TEXT,
    new TEXT,
    text TEXT,
    history_id INTEGER,
    job_id INTEGER
);
CREATE INDEX IF NOT EXISTS finding_events_finding ON finding_events(finding_id);
CREATE INDEX IF NOT EXISTS finding_events_issue ON finding_events(issue_id);
CREATE TABLE IF NOT EXISTS scan_observations (
    job_id INTEGER NOT NULL,
    finding_id INTEGER NOT NULL,
    seen TEXT NOT NULL,
    time TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    PRIMARY KEY (job_id, finding_id)
);
CREATE INDEX IF NOT EXISTS scan_observations_finding ON scan_observations(finding_id);
";

pub const ISSUE_COLUMNS: &[(&str, &str, &str)] = &[
    ("id", "INTEGER", "Issue id"),
    ("time", "TEXT", "When the issue was first recorded"),
    ("alert_ref", "TEXT", "Alert type of its findings"),
    ("host", "TEXT", "Host of its findings"),
    ("title", "TEXT", "Title a tester gave it (NULL: the alert's name)"),
    ("cvss_vector", "TEXT", "CVSS 4.0 vector a tester gave it (`findings issue cvss`)"),
    ("cvss_score", "REAL", "Its score, 0.0 to 10.0"),
    ("narrative", "TEXT", "Write-up for reports (`findings issue narrative`); printed once reviewed"),
    ("narrative_origin", "TEXT", "Who wrote it: gui, cli or mcp"),
    ("narrative_at", "TEXT", "When it was written"),
    ("reviewed_origin", "TEXT", "Who reviewed it (a person: gui or cli); NULL while a draft"),
    ("reviewed_at", "TEXT", "When it was reviewed"),
];

pub const EVENT_COLUMNS: &[(&str, &str, &str)] = &[
    ("id", "INTEGER", "Event id"),
    ("time", "TEXT", "UTC time"),
    ("finding_id", "INTEGER", "The finding it happened to (NULL for an issue's own events)"),
    ("issue_id", "INTEGER", "The finding's issue at the time, or the issue it happened to"),
    ("origin", "TEXT", "Who: gui, cli, mcp; NULL when unknown (events backfilled from older projects)"),
    ("kind", "TEXT", "created, state, note, retest, regressed, risk (a sighting rated it otherwise), moved (to another issue), title, cvss, narrative, reviewed, ticket, removed; summary and summary_reviewed (the executive summary: no finding or issue)"),
    ("old", "TEXT", "Value before (a state, a note, an issue id)"),
    ("new", "TEXT", "Value after; for retest: still_present or not_reproduced"),
    ("text", "TEXT", "Free text: the note, or what a retest sent"),
    ("history_id", "INTEGER", "history.id involved (a retest's request, a regression's sighting)"),
    ("job_id", "INTEGER", "jobs.id involved"),
];

pub const OBSERVATION_COLUMNS: &[(&str, &str, &str)] = &[
    ("job_id", "INTEGER", "The active-scan job (jobs.id)"),
    ("finding_id", "INTEGER", "The finding"),
    ("seen", "TEXT", "new (first found by the scan), still (found before and again), gone (covered, not found)"),
    ("time", "TEXT", "When the scan ended"),
];

/// Builds the v15 records for an existing project: an issue per alert type and host, and a
/// timeline from what each finding row already says (when it was added and by whom, the
/// last state and note change).
pub(crate) fn migrate_v15(conn: &Connection) -> Result<()> {
    conn.execute_batch(SCHEMA_V15)?;
    if !crate::store::has_column(conn, "findings", "issue_id")? {
        conn.execute_batch(
            "ALTER TABLE findings ADD COLUMN issue_id INTEGER;
             CREATE INDEX IF NOT EXISTS findings_issue ON findings(issue_id);",
        )?;
    }
    conn.execute_batch(
        "INSERT INTO issues (time, alert_ref, host)
            SELECT min(time), alert_ref, host FROM findings WHERE issue_id IS NULL
            GROUP BY alert_ref, host ORDER BY min(id);
         UPDATE findings SET issue_id = (SELECT i.id FROM issues i
            WHERE i.alert_ref = findings.alert_ref AND i.host = findings.host ORDER BY i.id LIMIT 1)
            WHERE issue_id IS NULL;
         INSERT INTO finding_events (time, finding_id, issue_id, origin, kind, new, history_id)
            SELECT time, id, issue_id, origin, 'created', 'open', history_id FROM findings ORDER BY id;
         INSERT INTO finding_events (time, finding_id, issue_id, origin, kind, new)
            SELECT state_changed_at, id, issue_id, state_origin, 'state', state FROM findings
            WHERE state_changed_at IS NOT NULL AND state != 'removed' ORDER BY state_changed_at;
         INSERT INTO finding_events (time, finding_id, issue_id, origin, kind, new)
            SELECT state_changed_at, id, issue_id, state_origin, 'removed', 'removed' FROM findings
            WHERE state_changed_at IS NOT NULL AND state = 'removed' ORDER BY state_changed_at;
         INSERT INTO finding_events (time, finding_id, issue_id, origin, kind, text)
            SELECT note_changed_at, id, issue_id, note_origin, 'note', note FROM findings
            WHERE note_changed_at IS NOT NULL ORDER BY note_changed_at;",
    )?;
    Ok(())
}

/// One event in a finding's or issue's timeline.
#[derive(Debug, Default)]
pub(crate) struct Event<'a> {
    pub finding: Option<i64>,
    pub issue: Option<i64>,
    pub kind: &'a str,
    pub old: Option<&'a str>,
    pub new: Option<&'a str>,
    pub text: Option<&'a str>,
    pub history_id: Option<i64>,
    pub job_id: Option<i64>,
}

/// Records an event by this process's origin. A finding's event takes the finding's issue.
pub(crate) fn record(conn: &Connection, e: &Event) -> Result<()> {
    conn.prepare_cached(
        "INSERT INTO finding_events (finding_id, issue_id, origin, kind, old, new, text, history_id, job_id)
         VALUES (?1, COALESCE(?2, (SELECT issue_id FROM findings WHERE id = ?1)), ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
    )?
    .execute(params![
        e.finding,
        e.issue,
        crate::provenance::origin(),
        e.kind,
        e.old,
        e.new,
        e.text,
        e.history_id,
        e.job_id
    ])?;
    Ok(())
}

/// The issue a new finding of `alert_ref` on `host` belongs to: the first issue that holds
/// findings of that pair, so a merge keeps them together (the issue merged away still has
/// the pair but no findings); else the first issue made for the pair; else a new one. (After
/// a split there may be several; new findings join the first.)
pub(crate) fn issue_for(conn: &Connection, alert_ref: &str, host: &str) -> Result<i64> {
    let found: Option<i64> = conn
        .prepare_cached(
            "SELECT coalesce(
                (SELECT min(issue_id) FROM findings WHERE alert_ref = ?1 AND host = ?2 AND issue_id IS NOT NULL),
                (SELECT min(id) FROM issues WHERE alert_ref = ?1 AND host = ?2))",
        )?
        .query_row(params![alert_ref, host], |r| r.get(0))?;
    match found {
        Some(id) => Ok(id),
        None => {
            conn.prepare_cached("INSERT INTO issues (alert_ref, host) VALUES (?1, ?2)")?
                .execute(params![alert_ref, host])?;
            Ok(conn.last_insert_rowid())
        }
    }
}

/// Puts a new finding in its issue and records that it was created.
pub(crate) fn created(
    conn: &Connection,
    finding: i64,
    alert_ref: &str,
    host: &str,
    history_id: Option<i64>,
) -> Result<()> {
    let issue = issue_for(conn, alert_ref, host)?;
    conn.prepare_cached("UPDATE findings SET issue_id = ?1 WHERE id = ?2")?.execute(params![issue, finding])?;
    record(
        conn,
        &Event {
            finding: Some(finding),
            issue: Some(issue),
            kind: "created",
            new: Some("open"),
            history_id,
            ..Default::default()
        },
    )
}

/// What a retest found.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Retest {
    StillPresent,
    NotReproduced,
}

impl Retest {
    pub fn as_str(self) -> &'static str {
        match self {
            Retest::StillPresent => "still_present",
            Retest::NotReproduced => "not_reproduced",
        }
    }
}

/// Triage states a retest outcome moves: a fixed finding still there is open again, and one
/// no longer reproduced is fixed. False positives and accepted risks keep their state.
fn after_retest(state: &str, outcome: Retest) -> Option<&'static str> {
    match (state, outcome) {
        ("fixed" | "retest_pending", Retest::StillPresent) => Some("open"),
        ("open" | "confirmed" | "retest_pending", Retest::NotReproduced) => Some("fixed"),
        _ => None,
    }
}

/// What an issue's row says, counted over its findings (removed ones left out).
const ISSUE_SELECT: &str = "SELECT i.id, i.alert_ref, i.host, COALESCE(i.title, max(f.name)) AS title,
        i.title IS NOT NULL AS titled, max(f.risk_level) AS risk_level, count(f.id) AS instances,
        sum(f.hits) AS hits, min(f.time) AS first_seen,
        max(COALESCE((SELECT h.time FROM history h WHERE h.id = f.last_history_id), f.time)) AS last_seen,
        json_group_object(f.state, 1) AS states, group_concat(DISTINCT f.source) AS sources,
        json_group_object(f.host, 1) AS hosts, i.cvss_vector, i.cvss_score
    FROM issues i JOIN findings f ON f.issue_id = i.id";

fn risk_name(level: i64) -> &'static str {
    ["info", "low", "medium", "high", "critical"].get(level.clamp(0, 4) as usize).copied().unwrap_or("info")
}

fn issue_row(r: &rusqlite::Row) -> rusqlite::Result<Value> {
    let level: i64 = r.get("risk_level")?;
    let states: String = r.get("states")?;
    let mut states: Vec<String> =
        serde_json::from_str::<Map<String, Value>>(&states).map(|m| m.keys().cloned().collect()).unwrap_or_default();
    states.sort();
    let sources: Option<String> = r.get("sources")?;
    // Its findings' hosts, not the issue's own: a merge can bring findings of other hosts, and
    // labelling them all with the first host would be wrong. One host is the usual case.
    let hosts: String = r.get("hosts")?;
    let mut hosts: Vec<String> =
        serde_json::from_str::<Map<String, Value>>(&hosts).map(|m| m.keys().cloned().collect()).unwrap_or_default();
    hosts.sort();
    if hosts.is_empty() {
        hosts.push(r.get("host")?);
    }
    Ok(json!({
        "id": r.get::<_, i64>("id")?,
        "alert_ref": r.get::<_, String>("alert_ref")?,
        "host": hosts.join(", "),
        "hosts": hosts,
        "title": r.get::<_, String>("title")?,
        "titled": r.get::<_, bool>("titled")?,
        "risk": risk_name(level),
        "instances": r.get::<_, i64>("instances")?,
        "hits": r.get::<_, i64>("hits")?,
        "first_seen": r.get::<_, String>("first_seen")?,
        "last_seen": r.get::<_, String>("last_seen")?,
        "states": states,
        "sources": sources.map(|s| s.split(',').map(str::to_string).collect::<Vec<_>>()).unwrap_or_default(),
        "cvss": r.get::<_, Option<String>>("cvss_vector")?.map(|v| {
            let score: f64 = r.get("cvss_score").unwrap_or(0.0);
            json!({"vector": v, "score": score, "severity": crate::scan::cvss::severity(score)})
        }),
    }))
}

fn event_row(r: &rusqlite::Row) -> rusqlite::Result<Value> {
    let origin: Option<String> = r.get("origin")?;
    Ok(json!({
        "id": r.get::<_, i64>("id")?,
        "time": r.get::<_, String>("time")?,
        "finding_id": r.get::<_, Option<i64>>("finding_id")?,
        "issue_id": r.get::<_, Option<i64>>("issue_id")?,
        "by": crate::provenance::describe(origin.as_deref()),
        "origin": origin,
        "kind": r.get::<_, String>("kind")?,
        "old": r.get::<_, Option<String>>("old")?,
        "new": r.get::<_, Option<String>>("new")?,
        "text": r.get::<_, Option<String>>("text")?,
        "history_id": r.get::<_, Option<i64>>("history_id")?,
        "job_id": r.get::<_, Option<i64>>("job_id")?,
    }))
}

impl Store {
    /// Issues whose findings match `filter`, riskiest first, with how many instances each has.
    pub fn issues_list(&self, filter: &FindingFilter, limit: usize) -> Result<Vec<Value>> {
        let (where_sql, args) = filter.sql();
        let sql = format!(
            "{ISSUE_SELECT} WHERE f.id IN (SELECT id FROM findings WHERE {where_sql})
             GROUP BY i.id ORDER BY risk_level DESC, instances DESC, i.id LIMIT {limit}"
        );
        let mut stmt = self.conn.prepare(&sql)?;
        let rows = stmt.query_map(rusqlite::params_from_iter(args.iter()), issue_row)?;
        Ok(rows.collect::<std::result::Result<_, _>>()?)
    }

    /// One issue with its findings (removed ones left out) and its own events.
    pub fn issue_get(&self, id: i64) -> Result<Value> {
        let mut issue = self
            .conn
            .query_row(
                &format!("{ISSUE_SELECT} WHERE i.id = ?1 AND f.state != '{REMOVED}' GROUP BY i.id"),
                [id],
                issue_row,
            )
            .optional()?
            .ok_or_else(|| Error::NotFound(format!("issue {id} (or it has no findings)")))?;
        let filter = FindingFilter { state: Some("all".into()), issue: Some(id), ..Default::default() };
        let mut findings = self.findings_list(&filter, i64::MAX as usize)?;
        findings.retain(|f| f["state"] != REMOVED);
        issue["findings"] = json!(findings);
        let mut stmt = self
            .conn
            .prepare("SELECT * FROM finding_events WHERE issue_id = ?1 AND finding_id IS NULL ORDER BY time, id")?;
        let events: Vec<Value> = stmt.query_map([id], event_row)?.collect::<std::result::Result<_, _>>()?;
        issue["events"] = json!(events);
        issue["narrative"] = json!(self.issue_narrative(id)?);
        Ok(issue)
    }

    /// The findings of an issue, for triage of the whole issue at once.
    pub fn issue_finding_ids(&self, id: i64) -> Result<Vec<i64>> {
        let mut stmt = self.conn.prepare("SELECT id FROM findings WHERE issue_id = ?1 AND state != ?2 ORDER BY id")?;
        let ids: Vec<i64> =
            stmt.query_map(params![id, REMOVED], |r| r.get(0))?.collect::<std::result::Result<_, _>>()?;
        if ids.is_empty() {
            return Err(Error::NotFound(format!("issue {id} (or it has no findings)")));
        }
        Ok(ids)
    }

    /// A finding's timeline, oldest first.
    pub fn finding_events(&self, id: i64) -> Result<Vec<Value>> {
        self.conn
            .query_row("SELECT 1 FROM findings WHERE id = ?1", [id], |_| Ok(()))
            .optional()?
            .ok_or_else(|| Error::NotFound(format!("finding {id}")))?;
        let mut stmt = self.conn.prepare("SELECT * FROM finding_events WHERE finding_id = ?1 ORDER BY time, id")?;
        let rows = stmt.query_map([id], event_row)?;
        Ok(rows.collect::<std::result::Result<_, _>>()?)
    }

    /// Moves the findings of the `from` issues into `into`; the emptied issues stay, with no
    /// findings, so their ids still name something in old events. Returns findings moved.
    pub fn issues_merge(&mut self, into: i64, from: &[i64]) -> Result<usize> {
        let tx = self.write_tx()?;
        exists(&tx, into)?;
        let mut moved = 0;
        for &issue in from.iter().filter(|&&i| i != into) {
            exists(&tx, issue)?;
            let ids: Vec<i64> = {
                let mut stmt = tx.prepare("SELECT id FROM findings WHERE issue_id = ?1")?;
                let ids = stmt.query_map([issue], |r| r.get(0))?.collect::<std::result::Result<_, _>>()?;
                ids
            };
            moved += move_findings(&tx, &ids, issue, into)?;
        }
        tx.commit()?;
        Ok(moved)
    }

    /// Moves findings out of their issue into a new one (two bugs that share a rule and host);
    /// all of them must be in the same issue. Returns the new issue's id.
    pub fn issue_split(&mut self, findings: &[i64], title: Option<&str>) -> Result<i64> {
        if findings.is_empty() {
            return Err(Error::InvalidInput("name the findings to split off".into()));
        }
        let tx = self.write_tx()?;
        let mut from: Option<(i64, String, String)> = None;
        for &id in findings {
            let row: (Option<i64>, String, String) = tx
                .query_row(
                    "SELECT issue_id, alert_ref, host FROM findings WHERE id = ?1 AND state != ?2",
                    params![id, REMOVED],
                    |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
                )
                .optional()?
                .ok_or_else(|| Error::NotFound(format!("finding {id}")))?;
            let issue = row.0.ok_or_else(|| Error::Conflict(format!("finding {id} has no issue")))?;
            match &from {
                None => from = Some((issue, row.1, row.2)),
                Some((i, ..)) if *i != issue => {
                    return Err(Error::InvalidInput(format!(
                        "finding {id} is in issue {issue}, not {i}: split findings of one issue at a time"
                    )))
                }
                Some(_) => {}
            }
        }
        let (old, alert_ref, host) = from.expect("at least one finding");
        let title = title.map(str::trim).filter(|t| !t.is_empty());
        tx.execute("INSERT INTO issues (alert_ref, host, title) VALUES (?1, ?2, ?3)", params![alert_ref, host, title])?;
        let new = tx.last_insert_rowid();
        move_findings(&tx, findings, old, new)?;
        tx.commit()?;
        Ok(new)
    }

    /// Gives an issue a title of its own; an empty one goes back to the alert's name.
    pub fn issue_set_title(&mut self, id: i64, title: &str) -> Result<()> {
        let tx = self.write_tx()?;
        let old: Option<String> = tx
            .query_row("SELECT title FROM issues WHERE id = ?1", [id], |r| r.get(0))
            .optional()?
            .ok_or_else(|| Error::NotFound(format!("issue {id}")))?;
        let title = Some(title.trim()).filter(|t| !t.is_empty());
        tx.execute("UPDATE issues SET title = ?1 WHERE id = ?2", params![title, id])?;
        record(&tx, &Event { issue: Some(id), kind: "title", old: old.as_deref(), new: title, ..Default::default() })?;
        tx.commit()?;
        Ok(())
    }

    /// Records a retest of a finding: an event with its outcome and the request it sent and,
    /// with `mark`, a sighting when it is still there (hits and last seen) and the state that
    /// follows: fixed when not reproduced, open again when a fixed finding is still there.
    /// Without `mark` only the event is recorded, so the finding is left as it was. Returns the
    /// finding's state after.
    pub fn finding_retested(
        &mut self,
        id: i64,
        outcome: Retest,
        history_id: Option<i64>,
        detail: &str,
        mark: bool,
    ) -> Result<String> {
        let tx = self.write_tx()?;
        let (state, last): (String, Option<i64>) = tx
            .query_row("SELECT state, last_history_id FROM findings WHERE id = ?1", [id], |r| {
                Ok((r.get(0)?, r.get(1)?))
            })
            .optional()?
            .ok_or_else(|| Error::NotFound(format!("finding {id}")))?;
        // A sighting recorded after the retest's request (history ids grow) is newer proof
        // that it is there: a "not reproduced" from before it doesn't mark it fixed.
        let outdated = outcome == Retest::NotReproduced && matches!((last, history_id), (Some(l), Some(h)) if l > h);
        record(
            &tx,
            &Event {
                finding: Some(id),
                kind: "retest",
                old: Some(&state),
                new: Some(outcome.as_str()),
                text: Some(detail),
                history_id,
                ..Default::default()
            },
        )?;
        // The retest's reply is read only here (the passive scan never reads retest traffic),
        // so it is counted once.
        if let (Retest::StillPresent, Some(h), true) = (outcome, history_id, mark) {
            tx.execute("UPDATE findings SET hits = hits + 1, last_history_id = ?1 WHERE id = ?2", params![h, id])?;
        }
        let after = match after_retest(&state, outcome).filter(|_| mark && !outdated) {
            Some(next) => {
                let cause = format!("retest: {}", outcome.as_str().replace('_', " "));
                crate::scan::findings_db::mark_with(&tx, id, Some(next), None, Some((&cause, history_id)))?;
                next.to_string()
            }
            None => state,
        };
        tx.commit()?;
        Ok(after)
    }

    /// Stores what a finished active scan saw of each finding it covered. A scan run again
    /// replaces its observations.
    pub fn scan_observations_record(&mut self, job: i64, seen: &Comparison) -> Result<usize> {
        let tx = self.write_tx()?;
        tx.execute("DELETE FROM scan_observations WHERE job_id = ?1", [job])?;
        let mut n = 0;
        {
            let mut insert = tx.prepare_cached(
                "INSERT OR REPLACE INTO scan_observations (job_id, finding_id, seen,
                    time) VALUES (?1, ?2, ?3, COALESCE((SELECT finished_time FROM jobs WHERE id = ?1),
                    strftime('%Y-%m-%dT%H:%M:%fZ','now')))",
            )?;
            for (kind, list) in [("new", &seen.new), ("still", &seen.unchanged), ("gone", &seen.fixed)] {
                for id in list.iter().filter_map(|f| f.id) {
                    n += insert.execute(params![job, id, kind])?;
                }
            }
        }
        tx.commit()?;
        Ok(n)
    }

    /// The project's security posture: open issues and instances by risk, findings by state,
    /// a risk × confidence grid, the hosts with the most open findings, what each active scan
    /// found new and no longer found, and retest outcomes. "Open" is open, confirmed and
    /// awaiting retest.
    pub fn posture(&self) -> Result<Value> {
        self.posture_of(None)
    }

    /// [`Store::posture`] over the findings `scope` selects (its state ignored), or all.
    pub fn posture_of(&self, scope: Option<&FindingFilter>) -> Result<Value> {
        let (within, args) = match scope {
            Some(f) => {
                let f = FindingFilter { state: Some("all".into()), ..f.clone() };
                let (w, a) = f.sql();
                (format!("SELECT id FROM findings WHERE {w}"), a)
            }
            None => ("SELECT id FROM findings".to_string(), Vec::new()),
        };
        let p = || rusqlite::params_from_iter(args.iter());
        let open = format!("state IN ('open', 'confirmed', 'retest_pending') AND id IN ({within})");
        let by_risk = |sql: &str| -> Result<Map<String, Value>> {
            let mut stmt = self.conn.prepare(sql)?;
            let mut m = Map::new();
            for level in (0..=4).rev() {
                m.insert(risk_name(level).into(), json!(0));
            }
            for row in stmt.query_map(p(), |r| Ok((r.get::<_, i64>(0)?, r.get::<_, i64>(1)?)))? {
                let (level, n) = row?;
                m.insert(risk_name(level).into(), json!(n));
            }
            Ok(m)
        };
        let instances =
            by_risk(&format!("SELECT risk_level, count(*) FROM findings WHERE {open} GROUP BY risk_level"))?;
        let issues = by_risk(&format!(
            "SELECT lvl, count(*) FROM (SELECT max(risk_level) AS lvl FROM findings WHERE {open} AND issue_id IS NOT NULL
             GROUP BY issue_id) GROUP BY lvl"
        ))?;
        let mut stmt = self.conn.prepare(&format!(
            "SELECT state, count(*) FROM findings WHERE state != 'removed' AND id IN ({within}) GROUP BY state"
        ))?;
        let mut by_state = Map::new();
        for row in stmt.query_map(p(), |r| Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?)))? {
            let (s, n) = row?;
            by_state.insert(s, json!(n));
        }
        let mut stmt = self.conn.prepare(&format!(
            "SELECT risk_level, confidence, count(*) FROM findings WHERE {open} GROUP BY risk_level, confidence"
        ))?;
        let mut grid: Vec<Value> = Vec::new();
        for row in stmt.query_map(p(), |r| Ok((r.get::<_, i64>(0)?, r.get::<_, String>(1)?, r.get::<_, i64>(2)?)))? {
            let (level, conf, n) = row?;
            grid.push(json!({"risk": risk_name(level), "confidence": conf, "count": n}));
        }
        let mut stmt = self.conn.prepare(&format!(
            "SELECT host, max(risk_level), count(*), sum(risk_level = 4), sum(risk_level = 3), sum(risk_level = 2),
                sum(risk_level = 1), sum(risk_level = 0)
             FROM findings WHERE {open} GROUP BY host ORDER BY max(risk_level) DESC, count(*) DESC, host LIMIT 20"
        ))?;
        let hosts: Vec<Value> = stmt
            .query_map(p(), |r| {
                Ok(json!({
                    "host": r.get::<_, String>(0)?,
                    "risk": risk_name(r.get(1)?),
                    "open": r.get::<_, i64>(2)?,
                    "by_risk": {"critical": r.get::<_, i64>(3)?, "high": r.get::<_, i64>(4)?, "medium": r.get::<_, i64>(5)?,
                        "low": r.get::<_, i64>(6)?, "info": r.get::<_, i64>(7)?},
                }))
            })?
            .collect::<std::result::Result<_, _>>()?;
        let mut stmt = self.conn.prepare(&format!(
            "SELECT o.job_id, j.time, j.finished_time, j.state, sum(o.seen = 'new'), sum(o.seen = 'still'), sum(o.seen = 'gone')
             FROM scan_observations o LEFT JOIN jobs j ON j.id = o.job_id WHERE o.finding_id IN ({within})
             GROUP BY o.job_id ORDER BY COALESCE(j.time, o.time) DESC, o.job_id DESC LIMIT 50"
        ))?;
        let mut scans: Vec<Value> = stmt
            .query_map(p(), |r| {
                Ok(json!({
                    "job": r.get::<_, i64>(0)?,
                    "started": r.get::<_, Option<String>>(1)?,
                    "finished": r.get::<_, Option<String>>(2)?,
                    "state": r.get::<_, Option<String>>(3)?,
                    "new": r.get::<_, i64>(4)?,
                    "still": r.get::<_, i64>(5)?,
                    "gone": r.get::<_, i64>(6)?,
                }))
            })?
            .collect::<std::result::Result<_, _>>()?;
        scans.reverse();
        let mut stmt = self.conn.prepare(&format!(
            "SELECT new, count(*) FROM finding_events WHERE kind = 'retest' AND finding_id IN ({within}) GROUP BY new"
        ))?;
        let mut retests = Map::new();
        for row in stmt.query_map(p(), |r| Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?)))? {
            let (outcome, n) = row?;
            retests.insert(outcome, json!(n));
        }
        let regressed: i64 = self.conn.query_row(
            &format!("SELECT count(*) FROM finding_events WHERE kind = 'regressed' AND finding_id IN ({within})"),
            p(),
            |r| r.get(0),
        )?;
        Ok(json!({
            "open": {"issues": issues, "instances": instances},
            "by_state": by_state,
            "risk_confidence": grid,
            "hosts": hosts,
            "scans": scans,
            "retests": retests,
            "regressed": regressed,
        }))
    }
}

fn exists(conn: &Connection, issue: i64) -> Result<()> {
    conn.query_row("SELECT 1 FROM issues WHERE id = ?1", [issue], |_| Ok(()))
        .optional()?
        .ok_or_else(|| Error::NotFound(format!("issue {issue}")))
}

/// Moves findings between issues, recording a `moved` event for each.
fn move_findings(conn: &Connection, ids: &[i64], from: i64, to: i64) -> Result<usize> {
    let (old, new) = (from.to_string(), to.to_string());
    let mut n = 0;
    for &id in ids {
        n += conn.execute("UPDATE findings SET issue_id = ?1 WHERE id = ?2", params![to, id])?;
        record(
            conn,
            &Event {
                finding: Some(id),
                issue: Some(to),
                kind: "moved",
                old: Some(&old),
                new: Some(&new),
                ..Default::default()
            },
        )?;
    }
    Ok(n)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capture::Capture;
    use crate::http::Target;
    use crate::scan::passive;

    fn store() -> Store {
        let mut s = Store::open_in_memory().unwrap();
        let resp = b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nX-Powered-By: PHP/5.1\r\nContent-Length: 0\r\n\r\n";
        for (host, path) in [("a.test", "/x"), ("a.test", "/y"), ("b.test", "/x")] {
            let target = Target { scheme: "http".into(), host: host.into(), port: 80 };
            let req = format!("GET {path} HTTP/1.1\r\nHost: {host}\r\n\r\n");
            s.record(&Capture::new("send", &target, req.as_bytes(), Some(resp), None, None)).unwrap();
        }
        passive::scan_pending(&mut s).unwrap();
        s
    }

    fn xpb(s: &Store) -> Vec<Value> {
        let all = s.issues_list(&FindingFilter::default(), 100).unwrap();
        all.into_iter().filter(|i| i["alert_ref"] == "10037").collect()
    }

    #[test]
    fn one_issue_per_alert_and_host_with_its_instances() {
        let s = store();
        let issues = xpb(&s);
        assert_eq!(issues.len(), 2, "{issues:?}");
        let a = issues.iter().find(|i| i["host"] == "a.test").unwrap();
        assert_eq!(a["instances"], 2);
        assert_eq!(a["title"], "Server Leaks Information via \"X-Powered-By\" HTTP Response Header Field(s)");
        let got = s.issue_get(a["id"].as_i64().unwrap()).unwrap();
        assert_eq!(got["findings"].as_array().unwrap().len(), 2);
        // Every finding has its "created" event.
        let f = got["findings"][0]["id"].as_i64().unwrap();
        let events = s.finding_events(f).unwrap();
        assert_eq!(events[0]["kind"], "created");
        assert_eq!(events[0]["issue_id"], a["id"]);
    }

    #[test]
    fn split_merge_and_titles_are_on_the_timeline() {
        let mut s = store();
        let issues = xpb(&s);
        let a = issues.iter().find(|i| i["host"] == "a.test").unwrap()["id"].as_i64().unwrap();
        let b = issues.iter().find(|i| i["host"] == "b.test").unwrap()["id"].as_i64().unwrap();
        let ids = s.issue_finding_ids(a).unwrap();
        // Findings of two issues can't be split together.
        let other = s.issue_finding_ids(b).unwrap()[0];
        assert!(matches!(s.issue_split(&[ids[0], other], None), Err(Error::InvalidInput(_))));
        let new = s.issue_split(&[ids[1]], Some("Second bug")).unwrap();
        assert_eq!(s.issue_finding_ids(a).unwrap(), [ids[0]]);
        assert_eq!(s.issue_get(new).unwrap()["title"], "Second bug");
        let moved = s.finding_events(ids[1]).unwrap();
        let last = moved.last().unwrap();
        assert_eq!((last["kind"].as_str(), last["old"].as_str()), (Some("moved"), Some(a.to_string().as_str())));
        // Merging brings both back, and the emptied issue lists no findings.
        assert_eq!(s.issues_merge(a, &[new, b]).unwrap(), 2);
        assert_eq!(s.issue_finding_ids(a).unwrap().len(), 3);
        assert!(matches!(s.issue_get(b), Err(Error::NotFound(_))));
        assert!(matches!(s.issues_merge(a, &[999]), Err(Error::NotFound(_))));
        // A new finding on the merged host joins the merged issue, not the emptied one.
        let target = Target { scheme: "http".into(), host: "b.test".into(), port: 80 };
        let resp = b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nX-Powered-By: PHP/5.1\r\nContent-Length: 0\r\n\r\n";
        s.record(&Capture::new("send", &target, b"GET /z HTTP/1.1\r\nHost: b.test\r\n\r\n", Some(resp), None, None))
            .unwrap();
        passive::scan_pending(&mut s).unwrap();
        assert_eq!(s.issue_finding_ids(a).unwrap().len(), 4);
        // A rescan finds every finding again: it keeps the split, and adds no "created".
        let back = s.issue_split(&[ids[1]], None).unwrap();
        passive::rescan(&mut s).unwrap();
        assert_eq!(s.issue_finding_ids(back).unwrap(), [ids[1]]);
        assert_eq!(s.finding_events(ids[1]).unwrap().iter().filter(|e| e["kind"] == "created").count(), 1);
        s.issues_merge(a, &[back]).unwrap();
        s.issue_set_title(a, "PHP version shown").unwrap();
        let got = s.issue_get(a).unwrap();
        assert_eq!((got["title"].as_str(), got["titled"].as_bool()), (Some("PHP version shown"), Some(true)));
        assert_eq!(got["events"][0]["kind"], "title");
        s.issue_set_title(a, " ").unwrap();
        assert_eq!(s.issue_get(a).unwrap()["titled"], false);
    }

    #[test]
    fn retests_move_the_state_and_regressions_reopen() {
        let mut s = store();
        let list =
            s.findings_list(&FindingFilter { alert_ref: Some("10037".into()), ..Default::default() }, 10).unwrap();
        let f = list.iter().find(|f| f["host"] == "a.test" && f["url"] == "http://a.test/x").unwrap()["id"]
            .as_i64()
            .unwrap();
        // A "not reproduced" older than the latest sighting is recorded, but marks nothing.
        let last = s.finding_get(f).unwrap()["last_history_id"].as_i64().unwrap();
        assert_eq!(s.finding_retested(f, Retest::NotReproduced, Some(last - 1), "GET /x", true).unwrap(), "open");
        assert_eq!(s.finding_retested(f, Retest::NotReproduced, Some(last + 1), "GET /x", true).unwrap(), "fixed");
        // Still there after all: open again. Without `mark`, only the event.
        assert_eq!(s.finding_retested(f, Retest::StillPresent, None, "GET /x", true).unwrap(), "open");
        assert_eq!(s.finding_retested(f, Retest::NotReproduced, None, "", false).unwrap(), "open");
        s.finding_mark(f, Some("false_positive"), None).unwrap();
        assert_eq!(s.finding_retested(f, Retest::StillPresent, None, "", true).unwrap(), "false_positive");
        let kinds: Vec<String> =
            s.finding_events(f).unwrap().iter().map(|e| e["kind"].as_str().unwrap().to_string()).collect();
        assert_eq!(kinds, ["created", "retest", "retest", "state", "retest", "state", "retest", "state", "retest"]);

        // A fixed finding seen again by a scanner is open again, and says it regressed.
        s.finding_mark(f, Some("fixed"), None).unwrap();
        let target = Target { scheme: "http".into(), host: "a.test".into(), port: 80 };
        let resp = b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nX-Powered-By: PHP/5.1\r\nContent-Length: 0\r\n\r\n";
        let h = s
            .record(&Capture::new("send", &target, b"GET /x HTTP/1.1\r\nHost: a.test\r\n\r\n", Some(resp), None, None))
            .unwrap();
        passive::scan_pending(&mut s).unwrap();
        assert_eq!(s.finding_get(f).unwrap()["state"], "open");
        let events = s.finding_events(f).unwrap();
        let last = events.last().unwrap();
        assert_eq!((last["kind"].as_str(), last["history_id"].as_i64()), (Some("regressed"), Some(h)));
        let posture = s.posture().unwrap();
        assert_eq!(posture["regressed"], 1);
        // A rescan reads the old traffic again: that doesn't reopen a finding marked fixed since.
        std::thread::sleep(std::time::Duration::from_millis(5));
        s.finding_mark(f, Some("fixed"), None).unwrap();
        passive::rescan(&mut s).unwrap();
        assert_eq!(s.finding_get(f).unwrap()["state"], "fixed");
        assert_eq!(s.posture().unwrap()["regressed"], 1);
        assert_eq!(posture["retests"]["still_present"], 2);
    }

    #[test]
    fn a_rescan_keeps_findings_with_records() {
        let mut s = store();
        let issues = xpb(&s);
        let a = issues.iter().find(|i| i["host"] == "a.test").unwrap()["id"].as_i64().unwrap();
        let b = issues.iter().find(|i| i["host"] == "b.test").unwrap()["id"].as_i64().unwrap();
        let split = s.issue_finding_ids(a).unwrap()[1];
        s.issue_split(&[split], None).unwrap();
        s.issue_set_title(b, "Shown on b").unwrap();
        // The rule is switched off, so the rescan finds none of them again: the split finding
        // and the renamed issue's keep their records; the others go.
        let settings = passive::PassiveSettings { disabled: vec![10037], ..Default::default() };
        s.set_setting(passive::SETTINGS_KEY, &settings).unwrap();
        passive::rescan(&mut s).unwrap();
        let left: Vec<i64> = s
            .findings_list(&FindingFilter { alert_ref: Some("10037".into()), ..Default::default() }, 10)
            .unwrap()
            .iter()
            .map(|f| f["issue_id"].as_i64().unwrap())
            .collect();
        assert_eq!(left.len(), 2, "{left:?}");
        assert!(left.contains(&b) && !left.contains(&a));
        assert_eq!(s.finding_events(split).unwrap().last().unwrap()["kind"], "moved");
    }

    #[test]
    fn posture_counts_open_work() {
        let mut s = store();
        let p = s.posture().unwrap();
        assert_eq!(p["open"]["issues"]["low"], 2);
        assert!(p["open"]["instances"]["low"].as_i64().unwrap() >= 3);
        assert_eq!(p["hosts"][0]["host"], "a.test");
        let ids = s.issue_finding_ids(xpb(&s)[0]["id"].as_i64().unwrap()).unwrap();
        s.findings_mark(&ids, Some("accepted_risk"), None).unwrap();
        let p = s.posture().unwrap();
        assert_eq!(p["open"]["issues"]["low"], 1);
        assert_eq!(p["by_state"]["accepted_risk"], ids.len());
        // Observations of a scan: new, still and gone counted per job.
        let items = crate::scan::compare::project_items(&s).unwrap();
        let seen = Comparison { new: items[..1].to_vec(), fixed: items[1..2].to_vec(), ..Default::default() };
        assert_eq!(s.scan_observations_record(7, &seen).unwrap(), 2);
        assert_eq!(s.scan_observations_record(7, &seen).unwrap(), 2);
        let p = s.posture().unwrap();
        assert_eq!(
            p["scans"],
            json!([{"job": 7, "started": null, "finished": null, "state": null, "new": 1, "still": 0, "gone": 1}])
        );
    }

    #[test]
    fn a_retest_without_mark_records_only_its_outcome_and_counts_once() {
        let mut s = store();
        let list = s
            .findings_list(
                &FindingFilter { alert_ref: Some("10037".into()), host: Some("a.test".into()), ..Default::default() },
                10,
            )
            .unwrap();
        let f = list.iter().find(|f| f["url"] == "http://a.test/x").unwrap()["id"].as_i64().unwrap();
        let before = s.finding_get(f).unwrap();
        let target = Target { scheme: "http".into(), host: "a.test".into(), port: 80 };
        let resp = b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nX-Powered-By: PHP/5.1\r\nContent-Length: 0\r\n\r\n";
        let h = s
            .record(&Capture::new(
                "retest",
                &target,
                b"GET /x HTTP/1.1\r\nHost: a.test\r\n\r\n",
                Some(resp),
                None,
                None,
            ))
            .unwrap();
        assert_eq!(s.finding_retested(f, Retest::StillPresent, Some(h), "GET /x", false).unwrap(), "open");
        let after = s.finding_get(f).unwrap();
        assert_eq!((&after["hits"], &after["last_history_id"]), (&before["hits"], &before["last_history_id"]));
        assert_eq!(s.finding_events(f).unwrap().last().unwrap()["kind"], "retest");
        // A source list saved before `scan sources` refused retest: the background scan still
        // leaves the retest's reply alone, so a marking retest is the one sighting of it.
        let settings = passive::PassiveSettings { sources: vec!["send".into(), "retest".into()], ..Default::default() };
        s.set_setting(passive::SETTINGS_KEY, &settings).unwrap();
        passive::scan_pending(&mut s).unwrap();
        assert_eq!(s.finding_get(f).unwrap()["hits"], before["hits"]);
        s.finding_retested(f, Retest::StillPresent, Some(h), "GET /x", true).unwrap();
        let after = s.finding_get(f).unwrap();
        assert_eq!(after["hits"].as_i64(), before["hits"].as_i64().map(|n| n + 1));
        assert_eq!(after["last_history_id"], h);
    }

    #[test]
    fn a_merged_issue_names_every_host_it_holds() {
        let mut s = store();
        let issues = xpb(&s);
        let a = issues.iter().find(|i| i["host"] == "a.test").unwrap()["id"].as_i64().unwrap();
        let b = issues.iter().find(|i| i["host"] == "b.test").unwrap()["id"].as_i64().unwrap();
        assert_eq!(issues[0]["hosts"].as_array().unwrap().len(), 1);
        s.issues_merge(a, &[b]).unwrap();
        let merged = xpb(&s);
        assert_eq!(merged.len(), 1, "{merged:?}");
        assert_eq!(
            (merged[0]["host"].as_str(), &merged[0]["hosts"]),
            (Some("a.test, b.test"), &json!(["a.test", "b.test"]))
        );
        assert_eq!(s.issue_get(a).unwrap()["host"], "a.test, b.test");
        // Listed for one host, it names the host its matching findings are on.
        let on_b = FindingFilter { host: Some("b.test".into()), alert_ref: Some("10037".into()), ..Default::default() };
        let listed = s.issues_list(&on_b, 10).unwrap();
        assert_eq!((listed[0]["id"].as_i64(), listed[0]["host"].as_str()), (Some(a), Some("b.test")));
    }
}
