//! Proof and agent work: write-ups an agent drafts and a person reviews, the trail of what
//! an agent sent for a finding, and tickets that name a finding the same way every export does.
//!
//! - A **narrative** is prose for a report: one per issue, and an executive summary for the
//!   project. Whoever writes it (an agent through MCP, often) is recorded, and a report prints
//!   it only once a person has reviewed it, saying who drafted it and who reviewed it.
//!   Reviewing is refused through MCP.
//! - An **agent trail** is what an agent did for a finding: the requests it sent to that host
//!   around the finding, its changes to the finding, and whether a person looked after it.
//! - A **ticket** is a finding written up for an issue tracker, carrying its fingerprint (the
//!   identity reports and SARIF use), with the tracker's link recorded on the timeline.

use rusqlite::{params, OptionalExtension};
use serde::Serialize;
use serde_json::{json, Value};

use crate::error::{Error, Result};
use crate::scan::findings_db::{identity_url, MANUAL_SOURCE};
use crate::scan::issues::{record, Event};
use crate::store::Store;

/// Schema v17: an issue's narrative and its review.
pub(crate) fn migrate_v17(conn: &rusqlite::Connection) -> Result<()> {
    for (column, kind) in [
        ("narrative", "TEXT"),
        ("narrative_origin", "TEXT"),
        ("narrative_at", "TEXT"),
        ("reviewed_origin", "TEXT"),
        ("reviewed_at", "TEXT"),
    ] {
        if !crate::store::has_column(conn, "issues", column)? {
            conn.execute_batch(&format!("ALTER TABLE issues ADD COLUMN {column} {kind};"))?;
        }
    }
    // An agent trail looks up the agent's requests to one host in a time window.
    conn.execute_batch("CREATE INDEX IF NOT EXISTS history_origin_host_time ON history(origin, host, time);")?;
    Ok(())
}

/// Longest narrative, in bytes.
pub const MAX_NARRATIVE: usize = 50_000;

/// The meta key of the project's executive summary.
const SUMMARY_KEY: &str = "report.summary";

/// Prose for a report, with who wrote it and who reviewed it.
#[derive(Debug, Clone, Default, PartialEq, serde::Deserialize)]
pub struct Narrative {
    pub text: String,
    /// gui, cli or mcp.
    pub origin: Option<String>,
    pub at: Option<String>,
    /// Who reviewed it (gui or cli: a person), and when; None while it is a draft.
    pub reviewed_origin: Option<String>,
    pub reviewed_at: Option<String>,
}

/// What a person names when they review a text: a hash of exactly what they read, so a text
/// changed after they read it isn't approved in its place.
pub fn text_hash(text: &str) -> String {
    use sha2::{Digest, Sha256};
    hex::encode(Sha256::digest(text.as_bytes()))
}

impl Narrative {
    pub fn reviewed(&self) -> bool {
        self.reviewed_at.is_some()
    }

    pub fn hash(&self) -> String {
        text_hash(&self.text)
    }

    /// "drafted via MCP (an agent) on 2026-11-06, reviewed in the desktop app on 2026-11-07".
    pub fn credit(&self) -> String {
        let day = |t: &Option<String>| t.as_deref().and_then(|t| t.get(..10)).unwrap_or("").to_string();
        let mut s = format!("written {} on {}", crate::provenance::describe(self.origin.as_deref()), day(&self.at));
        if self.origin.as_deref() == Some("mcp") {
            s = format!("drafted {} on {}", crate::provenance::describe(self.origin.as_deref()), day(&self.at));
        }
        match &self.reviewed_origin {
            Some(_) => s.push_str(&format!(
                ", reviewed {} on {}",
                crate::provenance::describe(self.reviewed_origin.as_deref()),
                day(&self.reviewed_at)
            )),
            None => s.push_str(", not reviewed"),
        }
        s
    }
}

impl Serialize for Narrative {
    /// With its hash, which a review names.
    fn serialize<S: serde::Serializer>(&self, s: S) -> std::result::Result<S::Ok, S::Error> {
        use serde::ser::SerializeStruct;
        let mut st = s.serialize_struct("Narrative", 6)?;
        st.serialize_field("text", &self.text)?;
        st.serialize_field("hash", &self.hash())?;
        st.serialize_field("origin", &self.origin)?;
        st.serialize_field("at", &self.at)?;
        st.serialize_field("reviewed_origin", &self.reviewed_origin)?;
        st.serialize_field("reviewed_at", &self.reviewed_at)?;
        st.end()
    }
}

/// A review must name the text it read.
fn same_text(current: &str, hash: &str) -> Result<()> {
    if !text_hash(current).eq_ignore_ascii_case(hash.trim()) {
        return Err(Error::Conflict(
            "the text changed since it was read (its hash differs): read it again, then review that".into(),
        ));
    }
    Ok(())
}

fn check_text(text: &str) -> Result<()> {
    if text.len() > MAX_NARRATIVE {
        return Err(Error::InvalidInput(format!("a narrative has at most {MAX_NARRATIVE} bytes")));
    }
    Ok(())
}

/// Only a person reviews: an agent's review would vouch for itself.
fn person_only(what: &str) -> Result<()> {
    if crate::provenance::origin() == "mcp" {
        return Err(Error::InvalidInput(format!(
            "{what} is reviewed by a person, in the desktop app or a terminal, not through MCP"
        )));
    }
    Ok(())
}

/// A request in an agent trail.
#[derive(Debug, Clone, Serialize)]
pub struct TrailRequest {
    pub history_id: i64,
    pub time: String,
    pub method: String,
    pub url: String,
    pub status: Option<i64>,
}

/// What an agent did for a finding.
#[derive(Debug, Clone, Serialize)]
pub struct AgentTrail {
    pub finding_id: i64,
    /// Whether an agent added the finding or changed it.
    pub agent_involved: bool,
    /// The agent's requests to the finding's host, from half an hour before it first touched
    /// the finding until its last change (at most [`TRAIL_MAX`], latest kept).
    pub requests: Vec<TrailRequest>,
    pub requests_total: usize,
    /// The agent's events on the finding (created, state, note, retest, ...).
    pub events: Vec<Value>,
    /// The first change a person made after the agent's last one.
    pub reviewed_by: Option<String>,
    pub reviewed_at: Option<String>,
}

/// Most requests a trail lists.
pub const TRAIL_MAX: usize = 200;

impl Store {
    /// Sets an issue's narrative ("" clears it). A new text is a draft until reviewed.
    pub fn issue_set_narrative(&mut self, id: i64, text: &str) -> Result<()> {
        check_text(text)?;
        let text = Some(text.trim()).filter(|t| !t.is_empty());
        let tx = self.write_tx()?;
        let n = tx.execute(
            "UPDATE issues SET narrative = ?1, narrative_origin = ?2,
                narrative_at = strftime('%Y-%m-%dT%H:%M:%fZ','now'), reviewed_origin = NULL, reviewed_at = NULL
             WHERE id = ?3",
            params![text, crate::provenance::origin(), id],
        )?;
        if n == 0 {
            return Err(Error::NotFound(format!("issue {id}")));
        }
        record(&tx, &Event { issue: Some(id), kind: "narrative", text, ..Default::default() })?;
        tx.commit()?;
        Ok(())
    }

    /// Marks an issue's narrative reviewed by this person, who names the text they read by its
    /// hash (`findings issue show` gives it).
    pub fn issue_review_narrative(&mut self, id: i64, hash: &str) -> Result<()> {
        person_only("a narrative")?;
        let tx = self.write_tx()?;
        let has: Option<Option<String>> =
            tx.query_row("SELECT narrative FROM issues WHERE id = ?1", [id], |r| r.get(0)).optional()?;
        match has {
            None => return Err(Error::NotFound(format!("issue {id}"))),
            Some(None) => return Err(Error::Conflict(format!("issue {id} has no narrative to review"))),
            Some(Some(text)) => same_text(&text, hash)?,
        }
        tx.execute(
            "UPDATE issues SET reviewed_origin = ?1, reviewed_at = strftime('%Y-%m-%dT%H:%M:%fZ','now') WHERE id = ?2",
            params![crate::provenance::origin(), id],
        )?;
        record(&tx, &Event { issue: Some(id), kind: "reviewed", ..Default::default() })?;
        tx.commit()?;
        Ok(())
    }

    pub fn issue_narrative(&self, id: i64) -> Result<Option<Narrative>> {
        let row = self
            .conn
            .query_row(
                "SELECT narrative, narrative_origin, narrative_at, reviewed_origin, reviewed_at FROM issues WHERE id = ?1",
                [id],
                |r| {
                    Ok(r.get::<_, Option<String>>(0)?.map(|text| Narrative {
                        text,
                        origin: r.get(1).unwrap_or(None),
                        at: r.get(2).unwrap_or(None),
                        reviewed_origin: r.get(3).unwrap_or(None),
                        reviewed_at: r.get(4).unwrap_or(None),
                    }))
                },
            )
            .optional()?
            .ok_or_else(|| Error::NotFound(format!("issue {id}")))?;
        Ok(row)
    }

    /// Sets the executive summary ("" clears it); a new text is a draft until reviewed. Each
    /// change is an event with no finding or issue (kind `summary`), so it has a timeline too.
    pub fn summary_set(&self, text: &str) -> Result<()> {
        check_text(text)?;
        let text = Some(text.trim()).filter(|t| !t.is_empty());
        record(&self.conn, &Event { kind: "summary", text, ..Default::default() })?;
        match text {
            None => self.meta_set(SUMMARY_KEY, None),
            Some(t) => {
                let at: String =
                    self.conn.query_row("SELECT strftime('%Y-%m-%dT%H:%M:%fZ','now')", [], |r| r.get(0))?;
                let n = Narrative {
                    text: t.to_string(),
                    origin: Some(crate::provenance::origin().to_string()),
                    at: Some(at),
                    ..Default::default()
                };
                self.meta_set(SUMMARY_KEY, Some(&serde_json::to_string(&n).unwrap_or_default()))
            }
        }
    }

    pub fn summary(&self) -> Result<Option<Narrative>> {
        Ok(self.meta_get(SUMMARY_KEY)?.and_then(|v| serde_json::from_str(&v).ok()))
    }

    /// Marks the executive summary reviewed by this person, who names the text they read.
    pub fn summary_review(&mut self, hash: &str) -> Result<()> {
        person_only("the summary")?;
        let tx = self.write_tx()?;
        let stored: Option<String> =
            tx.query_row("SELECT value FROM meta WHERE key = ?1", [SUMMARY_KEY], |r| r.get(0)).optional()?;
        let mut n: Narrative = stored
            .and_then(|v| serde_json::from_str(&v).ok())
            .ok_or_else(|| Error::Conflict("there is no summary to review".into()))?;
        same_text(&n.text, hash)?;
        let at: String = tx.query_row("SELECT strftime('%Y-%m-%dT%H:%M:%fZ','now')", [], |r| r.get(0))?;
        n.reviewed_origin = Some(crate::provenance::origin().to_string());
        n.reviewed_at = Some(at);
        tx.execute(
            "UPDATE meta SET value = ?1 WHERE key = ?2",
            params![serde_json::to_string(&n).unwrap_or_default(), SUMMARY_KEY],
        )?;
        record(&tx, &Event { kind: "summary_reviewed", ..Default::default() })?;
        tx.commit()?;
        Ok(())
    }

    /// Whether an agent added, changed or sent a request to any of `ids`: those it did. A
    /// request counts when it went to the finding's own method and address (its URL as the
    /// finding's identity sees it: any query, any session id in the path): history keeps every
    /// one, where the finding keeps only its latest sighting.
    pub fn agent_touched(&self, ids: &[i64]) -> Result<std::collections::HashSet<i64>> {
        use std::collections::HashSet;
        let list = serde_json::to_string(ids).unwrap_or_default();
        let mut stmt = self.conn.prepare(
            "SELECT f.id, f.host, f.method, f.url, (f.origin = 'mcp' AND f.source = 'manual')
                OR EXISTS (SELECT 1 FROM finding_events e WHERE e.origin = 'mcp' AND e.kind NOT IN ('created', 'regressed')
                    AND (e.finding_id = f.id OR (e.finding_id IS NULL AND e.issue_id = f.issue_id)))
             FROM findings f WHERE f.id IN (SELECT value FROM json_each(?1))",
        )?;
        type Row = (i64, String, String, String, bool);
        let found: Vec<Row> = stmt
            .query_map([list], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)))?
            .collect::<std::result::Result<_, _>>()?;
        let mut touched: HashSet<i64> = found.iter().filter(|f| f.4).map(|f| f.0).collect();
        if found.iter().all(|f| f.4) {
            return Ok(touched);
        }
        // The addresses the agent sent requests to, read once rather than once per finding.
        let mut stmt = self.conn.prepare("SELECT DISTINCT host, method, url FROM history WHERE origin = 'mcp'")?;
        let mut sent: HashSet<(String, String, String)> = HashSet::new();
        for row in
            stmt.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?, r.get::<_, String>(2)?)))?
        {
            let (host, method, url) = row?;
            sent.insert((host, method, identity_url(&url).into_owned()));
        }
        touched.extend(
            found
                .into_iter()
                .filter(|f| sent.contains(&(f.1.clone(), f.2.clone(), identity_url(&f.3).into_owned())))
                .map(|f| f.0),
        );
        Ok(touched)
    }

    /// What an agent did for finding `id` (see [`AgentTrail`]): its changes to the finding and
    /// to the finding's issue (write-up, title, CVSS), its requests to the finding's address,
    /// and the agent's requests to that host from half an hour before its first such act
    /// until its last.
    pub fn agent_trail(&self, id: i64) -> Result<AgentTrail> {
        type Row = (String, String, Option<String>, Option<i64>, String, String, String);
        let (host, time, origin, issue, method, url, source): Row = self
            .conn
            .query_row(
                "SELECT host, time, origin, issue_id, method, url, source FROM findings WHERE id = ?1",
                [id],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?, r.get(5)?, r.get(6)?)),
            )
            .optional()?
            .ok_or_else(|| Error::NotFound(format!("finding {id}")))?;
        // The agent's first and latest requests to the finding's own method and address (any
        // query, any session id in the path), in id order.
        let address = identity_url(&url).into_owned();
        let (mut first_seen, mut last_seen): (Option<String>, Option<String>) = (None, None);
        {
            let mut stmt = self.conn.prepare(
                "SELECT time, url FROM history WHERE origin = 'mcp' AND host = ?1 AND method = ?2 ORDER BY id",
            )?;
            for row in
                stmt.query_map(params![host, method], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))?
            {
                let (time, sent) = row?;
                if identity_url(&sent) == address {
                    first_seen.get_or_insert_with(|| time.clone());
                    last_seen = Some(time);
                }
            }
        }
        let mut stmt = self.conn.prepare(
            "SELECT id, time, kind, old, new, text, history_id, finding_id IS NULL FROM finding_events
             WHERE origin = 'mcp' AND kind NOT IN ('created', 'regressed')
               AND (finding_id = ?1 OR (finding_id IS NULL AND issue_id = ?2)) ORDER BY time, id",
        )?;
        let events: Vec<Value> = stmt
            .query_map(params![id, issue], |r| {
                Ok(json!({
                    "id": r.get::<_, i64>(0)?,
                    "time": r.get::<_, String>(1)?,
                    "kind": r.get::<_, String>(2)?,
                    "old": r.get::<_, Option<String>>(3)?,
                    "new": r.get::<_, Option<String>>(4)?,
                    "text": r.get::<_, Option<String>>(5)?,
                    "history_id": r.get::<_, Option<i64>>(6)?,
                    "on_issue": r.get::<_, bool>(7)?,
                }))
            })?
            .collect::<std::result::Result<_, _>>()?;
        // The agent's acts, as (time, event id): its events, its creating the finding, and its
        // first and latest requests to the finding (which have no event; they sort after events
        // at their time).
        let mut acts: Vec<(String, i64)> = events
            .iter()
            .map(|e| (e["time"].as_str().unwrap_or("").to_string(), e["id"].as_i64().unwrap_or(0)))
            .collect();
        // A scanner's finding and its regressions are the process's that ran the scan, not
        // necessarily the agent's: those count through the agent's requests above, if it sent
        // them. A finding added by hand is the agent's own.
        if origin.as_deref() == Some("mcp") && source == MANUAL_SOURCE {
            acts.push((time.clone(), 0));
        }
        for t in first_seen.iter().chain(&last_seen) {
            acts.push((t.clone(), i64::MAX));
        }
        acts.sort();
        let agent_involved = !acts.is_empty();
        let (mut requests, mut requests_total) = (Vec::new(), 0);
        let mut reviewed: Option<(String, String)> = None;
        if let (Some(first), Some(last)) = (acts.first().cloned(), acts.last().cloned()) {
            let window = "origin = 'mcp' AND host = ?1
                 AND time >= strftime('%Y-%m-%dT%H:%M:%fZ', ?2, '-30 minutes') AND time <= ?3";
            requests_total = self.conn.query_row(
                &format!("SELECT count(*) FROM history WHERE {window}"),
                params![host, first.0, last.0],
                |r| r.get::<_, i64>(0),
            )? as usize;
            let mut stmt = self.conn.prepare(&format!(
                "SELECT id, time, method, url, status FROM history WHERE {window} ORDER BY id DESC LIMIT {TRAIL_MAX}"
            ))?;
            requests = stmt
                .query_map(params![host, first.0, last.0], |r| {
                    Ok(TrailRequest {
                        history_id: r.get(0)?,
                        time: r.get(1)?,
                        method: r.get(2)?,
                        url: r.get(3)?,
                        status: r.get(4)?,
                    })
                })?
                .collect::<std::result::Result<_, _>>()?;
            requests.reverse();
            // A person's own triage of the finding after the agent's last act: a state, a note, a
            // retest, or reviewing the issue's write-up. Changes made in bulk on the issue (its
            // title or rating) and automatic events (a regression, a move) don't count.
            reviewed = self
                .conn
                .query_row(
                    "SELECT origin, time FROM finding_events
                     WHERE origin IN ('gui', 'cli')
                       AND ((finding_id = ?1 AND kind IN ('state', 'note', 'retest'))
                         OR (finding_id IS NULL AND issue_id = ?2 AND kind = 'reviewed'))
                       AND (time > ?3 OR (time = ?3 AND id > ?4))
                     ORDER BY time, id LIMIT 1",
                    params![id, issue, last.0, last.1],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )
                .optional()?;
        }
        Ok(AgentTrail {
            finding_id: id,
            agent_involved,
            requests,
            requests_total,
            events,
            reviewed_by: reviewed.as_ref().map(|r| crate::provenance::describe(Some(&r.0)).to_string()),
            reviewed_at: reviewed.map(|r| r.1),
        })
    }

    /// Records a ticket filed for a finding: its link on the timeline.
    pub fn finding_ticket_recorded(&mut self, id: i64, tracker: &str, url: &str) -> Result<()> {
        let url = url.trim();
        let parsed = url::Url::parse(url).ok().filter(|u| matches!(u.scheme(), "http" | "https"));
        if parsed.is_none() || url.len() > 2000 || url.chars().any(|c| c.is_control() || c.is_whitespace()) {
            return Err(Error::InvalidInput("give the ticket's http(s) link".into()));
        }
        let tx = self.write_tx()?;
        tx.query_row("SELECT 1 FROM findings WHERE id = ?1", [id], |_| Ok(()))
            .optional()?
            .ok_or_else(|| Error::NotFound(format!("finding {id}")))?;
        record(
            &tx,
            &Event { finding: Some(id), kind: "ticket", new: Some(tracker), text: Some(url), ..Default::default() },
        )?;
        tx.commit()?;
        Ok(())
    }

    /// The tickets recorded for a finding: (tracker, link), latest last.
    pub fn finding_tickets(&self, id: i64) -> Result<Vec<(String, String)>> {
        Ok(self.findings_tickets(&[id])?.remove(&id).unwrap_or_default())
    }

    /// [`Store::finding_tickets`] of many findings in one query, by finding.
    pub fn findings_tickets(&self, ids: &[i64]) -> Result<std::collections::HashMap<i64, Vec<(String, String)>>> {
        let list = serde_json::to_string(ids).unwrap_or_default();
        let mut stmt = self.conn.prepare(
            "SELECT finding_id, coalesce(new, ''), coalesce(text, '') FROM finding_events
             WHERE kind = 'ticket' AND finding_id IN (SELECT value FROM json_each(?1)) ORDER BY id",
        )?;
        let mut out: std::collections::HashMap<i64, Vec<(String, String)>> = Default::default();
        for row in stmt.query_map([list], |r| Ok((r.get::<_, i64>(0)?, r.get(1)?, r.get(2)?)))? {
            let (id, tracker, url) = row?;
            out.entry(id).or_default().push((tracker, url));
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capture::Capture;
    use crate::http::Target;
    use crate::scan::passive;

    fn store() -> (Store, i64, i64) {
        let mut s = Store::open_in_memory().unwrap();
        let target = Target { scheme: "http".into(), host: "a.test".into(), port: 80 };
        let resp = b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nX-Powered-By: PHP/5.1\r\nContent-Length: 0\r\n\r\n";
        s.record(&Capture::new("send", &target, b"GET /x HTTP/1.1\r\nHost: a.test\r\n\r\n", Some(resp), None, None))
            .unwrap();
        passive::scan_pending(&mut s).unwrap();
        let f = s.findings_list(&Default::default(), 1).unwrap()[0].clone();
        (s, f["id"].as_i64().unwrap(), f["issue_id"].as_i64().unwrap())
    }

    #[test]
    fn narratives_are_drafts_until_a_person_reviews_them() {
        let (mut s, _, issue) = store();
        s.issue_set_narrative(issue, "An attacker learns the PHP version.").unwrap();
        // The whole SHA-256, so two texts with the same hash can't be made to order.
        let hash = text_hash("An attacker learns the PHP version.");
        assert_eq!(hash.len(), 64);
        let n = s.issue_narrative(issue).unwrap().unwrap();
        assert!(!n.reviewed() && n.credit().ends_with("not reviewed"), "{}", n.credit());
        // A review names the text it read; a stale hash is refused.
        assert!(matches!(s.issue_review_narrative(issue, &text_hash("something else")), Err(Error::Conflict(_))));
        s.issue_review_narrative(issue, &text_hash("An attacker learns the PHP version.")).unwrap();
        let n = s.issue_narrative(issue).unwrap().unwrap();
        assert!(n.reviewed() && n.credit().contains("reviewed from the command line"), "{}", n.credit());
        // A new text is a draft again; "" clears it, and there's nothing to review.
        s.issue_set_narrative(issue, "Second take").unwrap();
        assert!(!s.issue_narrative(issue).unwrap().unwrap().reviewed());
        s.issue_set_narrative(issue, " ").unwrap();
        assert!(s.issue_narrative(issue).unwrap().is_none());
        assert!(matches!(s.issue_review_narrative(issue, ""), Err(Error::Conflict(_))));
        assert!(s.issue_set_narrative(issue, &"x".repeat(MAX_NARRATIVE + 1)).is_err());
        // The project's summary works the same way.
        s.summary_set("Three serious issues.").unwrap();
        assert!(!s.summary().unwrap().unwrap().reviewed());
        assert!(s.summary_review("0000").is_err());
        s.summary_review(&text_hash("Three serious issues.")).unwrap();
        assert!(s.summary().unwrap().unwrap().reviewed());
        s.summary_set("").unwrap();
        assert!(s.summary().unwrap().is_none());
        // Each change and the review are on record.
        let kinds: Vec<String> = s
            .conn
            .prepare("SELECT kind FROM finding_events WHERE kind LIKE 'summary%' ORDER BY id")
            .unwrap()
            .query_map([], |r| r.get(0))
            .unwrap()
            .collect::<std::result::Result<_, _>>()
            .unwrap();
        assert_eq!(kinds.last().map(String::as_str), Some("summary"));
        assert!(kinds.iter().any(|k| k == "summary_reviewed"), "{kinds:?}");
    }

    #[test]
    fn an_agents_request_stays_on_the_trail_after_later_sightings() {
        let (mut s, f, _) = store();
        let target = Target { scheme: "http".into(), host: "a.test".into(), port: 80 };
        let resp = b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nX-Powered-By: PHP/5.1\r\nContent-Length: 0\r\n\r\n";
        let send = |s: &mut Store| {
            s.record(&Capture::new(
                "send",
                &target,
                b"GET /x?a=1 HTTP/1.1\r\nHost: a.test\r\n\r\n",
                Some(resp),
                None,
                None,
            ))
            .unwrap()
        };
        // The agent's request sees it again; then a person's, which becomes the latest sighting.
        let agent = send(&mut s);
        s.conn.execute("UPDATE history SET origin = 'mcp' WHERE id = ?1", [agent]).unwrap();
        passive::scan_pending(&mut s).unwrap();
        send(&mut s);
        passive::scan_pending(&mut s).unwrap();
        assert_ne!(s.finding_get(f).unwrap()["last_history_id"].as_i64(), Some(agent));
        assert!(s.agent_touched(&[f]).unwrap().contains(&f));
        let t = s.agent_trail(f).unwrap();
        assert!(t.agent_involved && t.requests.iter().any(|r| r.history_id == agent), "{t:?}");
    }

    #[test]
    fn an_agents_request_with_another_session_id_is_on_the_trail() {
        let (mut s, _, _) = store();
        let target = Target { scheme: "http".into(), host: "a.test".into(), port: 80 };
        let resp = b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nX-Powered-By: PHP/5.1\r\nContent-Length: 0\r\n\r\n";
        let send = |s: &mut Store, path: &str| {
            let req = format!("GET {path} HTTP/1.1\r\nHost: a.test\r\n\r\n");
            let id = s.record(&Capture::new("send", &target, req.as_bytes(), Some(resp), None, None)).unwrap();
            passive::scan_pending(s).unwrap();
            id
        };
        // A person's request finds it; the agent's, in another session, is the same finding.
        send(&mut s, "/login;jsessionid=A");
        let agent = send(&mut s, "/login;jsessionid=B?next=1");
        s.conn.execute("UPDATE history SET origin = 'mcp' WHERE id = ?1", [agent]).unwrap();
        let filter = crate::scan::findings_db::FindingFilter { alert_ref: Some("10037".into()), ..Default::default() };
        let f = s
            .findings_list(&filter, 100)
            .unwrap()
            .into_iter()
            .find(|f| f["url"] == "http://a.test/login;jsessionid=A")
            .unwrap()["id"]
            .as_i64()
            .unwrap();
        assert_eq!(s.finding_get(f).unwrap()["hits"], 2);
        assert!(s.agent_touched(&[f]).unwrap().contains(&f));
        let t = s.agent_trail(f).unwrap();
        assert!(t.agent_involved && t.requests.iter().any(|r| r.history_id == agent), "{t:?}");
    }

    #[test]
    fn an_agents_trail_and_who_looked_after_it() {
        let (mut s, f, _) = store();
        // Nothing an agent did: no trail.
        let t = s.agent_trail(f).unwrap();
        assert!(!t.agent_involved && t.requests.is_empty());
        // An agent's requests and its confirmation, then a person's note.
        s.conn.execute("UPDATE history SET origin = 'mcp'", []).unwrap();
        s.conn
            .execute(
                "INSERT INTO finding_events (finding_id, origin, kind, old, new) VALUES (?1, 'mcp', 'state', 'open', 'confirmed')",
                [f],
            )
            .unwrap();
        let t = s.agent_trail(f).unwrap();
        assert!(t.agent_involved && t.requests_total == 1 && t.reviewed_by.is_none(), "{t:?}");
        std::thread::sleep(std::time::Duration::from_millis(5));
        s.finding_mark(f, None, Some("Checked by hand")).unwrap();
        let t = s.agent_trail(f).unwrap();
        assert_eq!(t.reviewed_by.as_deref(), Some("from the command line"));
        // The agent changing the issue afterwards undoes that review.
        let issue = s.finding_get(f).unwrap()["issue_id"].as_i64().unwrap();
        std::thread::sleep(std::time::Duration::from_millis(5));
        s.conn
            .execute(
                "INSERT INTO finding_events (issue_id, origin, kind, new) VALUES (?1, 'mcp', 'cvss', 'x')",
                [issue],
            )
            .unwrap();
        assert!(s.agent_trail(f).unwrap().reviewed_by.is_none());
        assert_eq!(s.agent_touched(&[f, 999]).unwrap().into_iter().collect::<Vec<_>>(), [f]);
        // Tickets go on the timeline.
        assert!(s.finding_ticket_recorded(f, "github", "javascript:alert(1)").is_err());
        assert!(s.finding_ticket_recorded(f, "github", "https://x.test/a\n![x](https://evil)").is_err());
        s.finding_ticket_recorded(f, "github", "https://github.com/o/r/issues/3").unwrap();
        assert_eq!(
            s.finding_tickets(f).unwrap(),
            [("github".to_string(), "https://github.com/o/r/issues/3".to_string())]
        );
    }
}
