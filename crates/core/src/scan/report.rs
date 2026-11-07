//! Reports: findings joined with their alert type texts and the HTTP evidence
//! from history, rendered as JSON, Markdown, self-contained HTML, or SARIF 2.1.0.
//!
//! Everything taken from the target (URLs, evidence, attack payloads, bodies) is
//! untrusted: Markdown puts it in code spans/blocks, HTML escapes it and ships a
//! CSP that blocks scripts, SARIF/JSON carry it as plain strings.

use std::fmt::Write as _;

use rusqlite::OptionalExtension;
use serde::Serialize;
use serde_json::{json, Value};

use crate::error::{Error, Result};
use crate::guard::ScopeSpec;
use crate::provenance;
use crate::scan::cvss;
use crate::scan::findings_db::{fingerprint, FindingFilter, MANUAL_SOURCE};
use crate::scan::layout::{Layout, Section};
use crate::scan::proof::Narrative;
use crate::scan::redact::Redactor;
use crate::store::Store;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReportKind {
    Json,
    Markdown,
    Html,
    Sarif,
    Csv,
    Junit,
    DefectDojo,
}

impl ReportKind {
    pub fn as_str(self) -> &'static str {
        match self {
            ReportKind::Json => "json",
            ReportKind::Markdown => "markdown",
            ReportKind::Html => "html",
            ReportKind::Sarif => "sarif",
            ReportKind::Csv => "csv",
            ReportKind::Junit => "junit",
            ReportKind::DefectDojo => "defectdojo",
        }
    }
}

#[derive(Debug, Clone)]
pub struct ReportOptions {
    pub filter: FindingFilter,
    pub title: Option<String>,
    /// Maximum findings (instances) to include; `summary.truncated` says if more matched.
    pub limit: usize,
    /// Include the request/response from history for each finding.
    pub evidence: bool,
    /// Maximum bytes of each request/response body in the evidence.
    pub max_evidence: usize,
    /// The scan job whose findings `filter.ids` are, to say so in the report.
    pub scan: Option<i64>,
    /// With `scan`: whether each finding is new in that scan or was found before and again
    /// (finding id, true when new), for SARIF's `baselineState`.
    pub baseline: Option<std::collections::HashMap<i64, bool>>,
    /// Mask session secrets (cookies, credentials, tokens) in everything taken from traffic.
    pub redact: bool,
    /// Which sections the report has, and its branding.
    pub layout: Layout,
    /// Print narratives nobody has reviewed yet, marked as drafts.
    pub drafts: bool,
}

impl Default for ReportOptions {
    fn default() -> Self {
        Self {
            filter: FindingFilter::default(),
            title: None,
            limit: 500,
            evidence: true,
            max_evidence: 4096,
            scan: None,
            baseline: None,
            redact: true,
            layout: Layout::default(),
            drafts: false,
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct Report {
    pub title: String,
    pub generated: String,
    pub tool: Tool,
    pub scope: Option<ScopeSpec>,
    pub filters: Value,
    pub summary: Summary,
    pub alerts: Vec<AlertGroup>,
    /// Findings an agent marked false positive that the state filter leaves out (at most
    /// [`MAX_AGENT_FALSE_POSITIVES`]), so a reader sees what an agent hid.
    pub agent_false_positives: Vec<HiddenFinding>,
    /// With a posture section: `findings posture`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub posture: Option<Value>,
    /// With a retest section: what changed since a day.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub retest: Option<RetestLetter>,
    /// The executive summary, once reviewed (or a draft, when drafts are asked for).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub summary_narrative: Option<Narrative>,
    #[serde(skip)]
    pub layout: Layout,
}

/// What changed since a day: findings fixed (by a person or a retest), still there after a
/// retest, back after a fix, and waiting for a retest.
#[derive(Debug, Clone, Default, Serialize)]
pub struct RetestLetter {
    pub since: String,
    pub fixed: Vec<RetestRow>,
    pub still_present: Vec<RetestRow>,
    /// Retested and not reproduced, but not marked fixed (`retest --no-mark`).
    pub not_reproduced: Vec<RetestRow>,
    pub regressed: Vec<RetestRow>,
    pub pending: Vec<RetestRow>,
}

#[derive(Debug, Clone, Serialize)]
pub struct RetestRow {
    pub id: i64,
    pub name: String,
    pub risk: String,
    pub method: String,
    pub url: String,
    pub param: String,
    pub state: String,
    /// The event that put it here, and when; None for one only waiting.
    pub event: Option<String>,
    pub time: Option<String>,
    /// The retest's request, or the sighting it came back in.
    pub history_id: Option<i64>,
}

/// An issue's CVSS 4.0 rating.
#[derive(Debug, Clone, Serialize)]
pub struct CvssRating {
    pub vector: String,
    pub score: f64,
    pub severity: &'static str,
}

/// A finding left out of the report because it was marked false positive.
#[derive(Debug, Clone, Serialize)]
pub struct HiddenFinding {
    pub id: i64,
    pub name: String,
    pub risk: String,
    pub method: String,
    pub url: String,
    pub param: String,
    pub state_changed_at: Option<String>,
    pub note: Option<String>,
}

/// How many findings an agent marked false positive a report lists by name.
pub const MAX_AGENT_FALSE_POSITIVES: usize = 100;

#[derive(Debug, Clone, Serialize)]
pub struct Tool {
    pub name: &'static str,
    pub version: &'static str,
}

#[derive(Debug, Clone, Serialize)]
pub struct Summary {
    /// Findings matching the filters.
    pub total: usize,
    /// Findings included in this report (at most `limit`).
    pub included: usize,
    pub truncated: bool,
    pub alert_types: usize,
    /// Matching findings per risk, high to info.
    pub by_risk: Vec<RiskCount>,
    /// Findings matching the other filters that are left out because they were marked false
    /// positive, by who marked them (none when the state filter includes false positives).
    pub false_positives_left_out: Vec<OriginCount>,
    /// How many places a secret was masked in; None when the report isn't redacted.
    pub redacted: Option<usize>,
}

#[derive(Debug, Clone, Serialize)]
pub struct OriginCount {
    /// gui, cli or mcp; None when unknown (marked before brainproxy kept it).
    pub origin: Option<String>,
    pub count: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct RiskCount {
    pub risk: String,
    pub count: usize,
}

/// One alert type with its texts and the findings (instances) of it.
#[derive(Debug, Clone, Serialize)]
pub struct AlertGroup {
    pub alert_ref: String,
    pub rule_id: i64,
    pub name: String,
    /// Highest risk among the instances.
    pub risk: String,
    pub cwe: Option<i64>,
    pub wasc: Option<i64>,
    pub description: String,
    pub solution: String,
    pub references: Vec<String>,
    pub tags: Vec<String>,
    /// The highest CVSS 4.0 score among its instances' issues.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cvss: Option<CvssRating>,
    /// Write-ups of its issues (usually one per host), reviewed or, when asked for, drafts.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub narratives: Vec<IssueNarrative>,
    pub instances: Vec<Instance>,
}

/// An issue's write-up in a report.
#[derive(Debug, Clone, Serialize)]
pub struct IssueNarrative {
    pub issue_id: i64,
    /// The hosts of the issue's findings in the report, joined by ", " (several after issues
    /// from two hosts were merged).
    pub host: String,
    #[serde(flatten)]
    pub narrative: Narrative,
}

/// What an agent did for a finding, in short.
#[derive(Debug, Clone, Serialize)]
pub struct TrailSummary {
    pub requests: usize,
    pub first_history_id: Option<i64>,
    pub last_history_id: Option<i64>,
    pub agent_changes: usize,
    pub reviewed_by: Option<String>,
    pub reviewed_at: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct Ticket {
    pub tracker: String,
    pub url: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct Instance {
    pub id: i64,
    pub time: String,
    pub source: String,
    pub risk: String,
    pub confidence: String,
    pub host: String,
    pub method: String,
    pub url: String,
    pub param: String,
    pub evidence: String,
    pub attack: String,
    pub other_info: String,
    pub hits: i64,
    pub state: String,
    pub note: Option<String>,
    pub history_id: Option<i64>,
    /// The latest sighting: the history entry the finding was last found in, and when.
    pub last_history_id: Option<i64>,
    pub last_seen: Option<String>,
    /// For a finding added by hand: every history entry it links to (the first is the evidence).
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub history_ids: Vec<i64>,
    /// For a finding added by hand: its own CWE, when it isn't its alert type's.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cwe: Option<i64>,
    /// Who or what added it: gui, cli, mcp; None from before brainproxy kept it.
    pub origin: Option<String>,
    /// Who last changed its state with `findings mark` (gui, cli, mcp), and when; None if
    /// nobody has.
    pub state_origin: Option<String>,
    pub state_changed_at: Option<String>,
    /// The state and who set it, in words: "confirmed via MCP (an agent) at ...".
    pub state_text: String,
    /// Who last set the note, and when.
    pub note_origin: Option<String>,
    pub note_changed_at: Option<String>,
    pub request: Option<HttpRequest>,
    pub response: Option<HttpResponse>,
    /// `request` and `response` are from the first sighting; this is the latest one, when the
    /// finding was seen again in another history entry.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub latest: Option<Exchange>,
    /// With a `--scan`: new (first found by that scan) or unchanged (found before and again).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub baseline_state: Option<&'static str>,
    /// What makes it the same finding in the project (alert, method, URL without its query or
    /// path parameters, parameter), hashed before redaction: SARIF's fingerprint, and what `findings compare`
    /// matches a saved report by, since redaction may change the URL.
    pub fingerprint: String,
    /// The issue (alert type and host, or hosts once merged) it is an instance of, and that
    /// issue's CVSS rating.
    pub issue_id: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cvss: Option<CvssRating>,
    /// When an agent added or changed it: what it sent and whether a person looked after.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub agent_trail: Option<TrailSummary>,
    /// Tickets filed for it (`findings ticket --record`).
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub tickets: Vec<Ticket>,
}

impl Instance {
    /// The history entry of a later sighting than the first, if any. A finding added by hand
    /// links its entries instead, and lists them all.
    fn latest_id(&self) -> Option<i64> {
        self.last_history_id.filter(|&l| Some(l) != self.history_id && self.source != MANUAL_SOURCE)
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct Exchange {
    pub request: HttpRequest,
    pub response: Option<HttpResponse>,
}

#[derive(Debug, Clone, Serialize)]
pub struct HttpRequest {
    pub method: String,
    pub url: String,
    pub headers: Vec<(String, String)>,
    pub body: Body,
}

#[derive(Debug, Clone, Serialize)]
pub struct HttpResponse {
    pub status: Option<i64>,
    pub reason: Option<String>,
    pub headers: Vec<(String, String)>,
    pub body: Body,
}

/// A body as text (UTF-8, lossy), cut to `max_evidence` bytes.
#[derive(Debug, Clone, Serialize)]
pub struct Body {
    pub text: String,
    pub length: usize,
    pub truncated: bool,
    /// The body isn't valid UTF-8; `text` is a placeholder.
    pub binary: bool,
}

impl Body {
    fn new(bytes: &[u8], max: usize) -> Self {
        let length = bytes.len();
        let slice = &bytes[..length.min(max)];
        let truncated = length > max;
        let text = match std::str::from_utf8(slice) {
            Ok(s) => Some(s.to_string()),
            // The cut may split a multi-byte character; keep the valid prefix.
            Err(e) if truncated && e.error_len().is_none() => {
                Some(String::from_utf8_lossy(&slice[..e.valid_up_to()]).into())
            }
            Err(_) => None,
        };
        match text {
            Some(text) => Body { text, length, truncated, binary: false },
            None => Body { text: format!("[{length} bytes of binary data]"), length, truncated: false, binary: true },
        }
    }
}

const RISKS: [&str; 5] = ["critical", "high", "medium", "low", "info"];

/// A finding's state and who set it, in words.
fn state_text(state: &str, by: Option<&str>, at: Option<&str>) -> String {
    let state = state.replace('_', " ");
    match (by, at) {
        (None, None) if state == "open" => state,
        (None, None) => format!("{state} (by whom is unknown)"),
        (by, at) => {
            let at = at.map(|t| format!(" at {t}")).unwrap_or_default();
            format!("{state} {}{at}", provenance::describe(by))
        }
    }
}

/// A person (the desktop app or the command line) set this state, as opposed to an agent or
/// someone unknown.
fn by_a_person(origin: Option<&str>) -> bool {
    matches!(origin, Some("gui" | "cli"))
}

/// Builds a report from the project's findings.
pub fn build(store: &Store, opts: &ReportOptions) -> Result<Report> {
    if opts.limit == 0 {
        return Err(Error::InvalidInput("--limit must be at least 1".into()));
    }
    let (where_sql, args) = opts.filter.sql();
    let conn = &store.conn;

    let mut by_risk = Vec::new();
    let mut total = 0;
    {
        let mut stmt = conn.prepare(&format!("SELECT risk, count(*) FROM findings WHERE {where_sql} GROUP BY risk"))?;
        let counts: Vec<(String, i64)> = stmt
            .query_map(rusqlite::params_from_iter(args.iter()), |r| Ok((r.get(0)?, r.get(1)?)))?
            .collect::<std::result::Result<_, _>>()?;
        for risk in RISKS {
            let count = counts.iter().find(|(r, _)| r == risk).map_or(0, |(_, c)| *c as usize);
            total += count;
            by_risk.push(RiskCount { risk: risk.into(), count });
        }
    }

    let sql = format!(
        "SELECT f.id, f.time, f.source, f.risk, f.confidence, f.host, f.method, f.url, f.param, f.evidence,
            coalesce(f.attack, ''), f.other_info, f.hits, f.state, f.note, f.history_id,
            f.alert_ref, f.rule_id, f.name, f.cwe, f.wasc,
            coalesce(t.description, ''), coalesce(t.solution, ''), coalesce(t.refs, '[]'), coalesce(t.tags, '[]'),
            f.origin, f.state_origin, f.state_changed_at, f.note_origin, f.note_changed_at,
            f.last_history_id, h.time, f.issue_id, i.cvss_vector, i.cvss_score
         FROM (SELECT * FROM findings WHERE {where_sql}) f LEFT JOIN finding_types t ON t.alert_ref = f.alert_ref
            LEFT JOIN history h ON h.id = coalesce(f.last_history_id, f.history_id)
            LEFT JOIN issues i ON i.id = f.issue_id
         ORDER BY f.risk_level DESC, f.alert_ref, f.id LIMIT {}",
        opts.limit
    );
    let mut groups: Vec<AlertGroup> = Vec::new();
    let mut stmt = conn.prepare(&sql)?;
    let mut rows = stmt.query(rusqlite::params_from_iter(args.iter()))?;
    let mut included = 0;
    while let Some(r) = rows.next()? {
        included += 1;
        let (state, state_origin, state_changed_at): (String, Option<String>, Option<String>) =
            (r.get(13)?, r.get(26)?, r.get(27)?);
        let mut inst = Instance {
            id: r.get(0)?,
            time: r.get(1)?,
            source: r.get(2)?,
            risk: r.get(3)?,
            confidence: r.get(4)?,
            host: r.get(5)?,
            method: r.get(6)?,
            url: r.get(7)?,
            param: r.get(8)?,
            evidence: r.get(9)?,
            attack: r.get(10)?,
            other_info: r.get(11)?,
            hits: r.get(12)?,
            state_text: state_text(&state, state_origin.as_deref(), state_changed_at.as_deref()),
            state,
            note: r.get(14)?,
            history_id: r.get(15)?,
            history_ids: Vec::new(),
            cwe: r.get::<_, Option<i64>>(19)?.filter(|&c| c > 0),
            origin: r.get(25)?,
            state_origin,
            state_changed_at,
            note_origin: r.get(28)?,
            note_changed_at: r.get(29)?,
            last_history_id: r.get::<_, Option<i64>>(30)?.or(r.get(15)?),
            last_seen: r.get(31)?,
            request: None,
            response: None,
            latest: None,
            fingerprint: String::new(),
            baseline_state: None,
            agent_trail: None,
            tickets: Vec::new(),
            issue_id: r.get(32)?,
            cvss: match (r.get::<_, Option<String>>(33)?, r.get::<_, Option<f64>>(34)?) {
                (Some(vector), Some(score)) => Some(CvssRating { vector, score, severity: cvss::severity(score) }),
                _ => None,
            },
        };
        let alert_ref: String = r.get(16)?;
        inst.baseline_state =
            opts.baseline.as_ref().and_then(|b| b.get(&inst.id)).map(|&new| if new { "new" } else { "unchanged" });
        inst.fingerprint = fingerprint(&alert_ref, &inst.method, &inst.url, &inst.param);
        // Rows are sorted by risk, so the first instance of a type carries its highest risk.
        match groups.iter_mut().find(|g| g.alert_ref == alert_ref) {
            Some(g) => {
                // Each finding added by hand has its own CWE; the type takes the first one given.
                g.cwe = g.cwe.or(inst.cwe);
                if inst.cvss.as_ref().is_some_and(|c| g.cvss.as_ref().is_none_or(|h| c.score > h.score)) {
                    g.cvss = inst.cvss.clone();
                }
                g.instances.push(inst)
            }
            None => {
                let list = |s: String| serde_json::from_str::<Vec<String>>(&s).unwrap_or_default();
                groups.push(AlertGroup {
                    alert_ref,
                    rule_id: r.get(17)?,
                    name: r.get(18)?,
                    risk: inst.risk.clone(),
                    cwe: inst.cwe,
                    wasc: r.get::<_, Option<i64>>(20)?.filter(|&w| w > 0),
                    description: r.get(21)?,
                    solution: r.get(22)?,
                    references: list(r.get(23)?),
                    tags: list(r.get(24)?),
                    cvss: inst.cvss.clone(),
                    narratives: Vec::new(),
                    instances: vec![inst],
                })
            }
        }
    }
    drop(rows);
    drop(stmt);

    for g in &mut groups {
        let group_cwe = g.cwe;
        for inst in &mut g.instances {
            // An instance's CWE is shown only when it isn't the type's.
            if inst.source != MANUAL_SOURCE || inst.cwe == group_cwe {
                inst.cwe = None;
            }
            if inst.source == MANUAL_SOURCE {
                inst.history_ids = store.finding_history_ids(inst.id)?;
            }
        }
    }

    // Write-ups (reviewed, or drafts when asked for), agent trails and tickets. A trail is
    // worked out only for the findings an agent touched, found in one query.
    let ids: Vec<i64> = groups.iter().flat_map(|g| g.instances.iter().map(|i| i.id)).collect();
    let touched = store.agent_touched(&ids)?;
    let mut tickets = store.findings_tickets(&ids)?;
    for g in &mut groups {
        // An issue merged from several hosts holds findings of each: its write-up names them
        // all, not the host of whichever finding comes first.
        let mut hosts: std::collections::BTreeMap<i64, std::collections::BTreeSet<String>> = Default::default();
        for inst in &g.instances {
            if let Some(issue) = inst.issue_id {
                hosts.entry(issue).or_default().insert(inst.host.clone());
            }
        }
        let mut seen = std::collections::BTreeSet::new();
        for inst in &mut g.instances {
            if let Some(issue) = inst.issue_id.filter(|i| seen.insert(*i)) {
                if let Some(n) = store.issue_narrative(issue)?.filter(|n| n.reviewed() || opts.drafts) {
                    let host = hosts.get(&issue).map(|h| h.iter().cloned().collect::<Vec<_>>().join(", "));
                    g.narratives.push(IssueNarrative {
                        issue_id: issue,
                        host: host.unwrap_or_else(|| inst.host.clone()),
                        narrative: n,
                    });
                }
            }
            let trail = if touched.contains(&inst.id) { Some(store.agent_trail(inst.id)?) } else { None };
            if let Some(trail) = trail.filter(|t| t.agent_involved) {
                inst.agent_trail = Some(TrailSummary {
                    requests: trail.requests_total,
                    first_history_id: trail.requests.first().map(|r| r.history_id),
                    last_history_id: trail.requests.last().map(|r| r.history_id),
                    agent_changes: trail.events.len(),
                    reviewed_by: trail.reviewed_by,
                    reviewed_at: trail.reviewed_at,
                });
            }
            inst.tickets = tickets
                .remove(&inst.id)
                .unwrap_or_default()
                .into_iter()
                .map(|(tracker, url)| Ticket { tracker, url })
                .collect();
        }
    }
    let summary_narrative = store.summary()?.filter(|n| n.reviewed() || opts.drafts);

    // The exchanges, first and latest sighting, with their secrets masked; the values masked
    // there are then masked wherever else the report quotes them. Without evidence (a CI
    // baseline of many findings) nothing is read, and secrets are masked by their place only.
    let mut redactor = opts.redact.then(Redactor::default);
    if let Some(red) = redactor.as_mut() {
        // The project's own session secrets, wherever the report quotes them, in any format.
        for (profile, state) in store.auth_list()? {
            red.know(profile.secret_values(&state));
        }
    }
    if opts.evidence {
        for inst in groups.iter_mut().flat_map(|g| g.instances.iter_mut()) {
            if let Some((mut req, mut resp)) =
                inst.history_id.map(|h| evidence(store, h, opts.max_evidence)).transpose()?.flatten()
            {
                if let Some(red) = redactor.as_mut() {
                    red.exchange(&mut req, resp.as_mut());
                }
                inst.request = Some(req);
                inst.response = resp;
            }
            if let Some((mut request, mut response)) =
                inst.latest_id().map(|h| evidence(store, h, opts.max_evidence)).transpose()?.flatten()
            {
                if let Some(red) = redactor.as_mut() {
                    red.exchange(&mut request, response.as_mut());
                }
                inst.latest = Some(Exchange { request, response });
            }
        }
    }

    // False positives the state filter leaves out: counted by who marked them, and the ones an
    // agent marked listed, so they don't vanish from the report unseen.
    let mut false_positives_left_out = Vec::new();
    let mut agent_false_positives = Vec::new();
    let fp_included =
        matches!(opts.filter.state.as_deref().map(|s| s.replace('-', "_")).as_deref(), Some("all" | "false_positive"));
    if !fp_included {
        let fp = FindingFilter { state: Some("false_positive".into()), ..opts.filter.clone() };
        let (fp_where, fp_args) = fp.sql();
        let mut stmt = conn.prepare(&format!(
            "SELECT state_origin, count(*) FROM findings WHERE {fp_where} GROUP BY state_origin ORDER BY 2 DESC"
        ))?;
        false_positives_left_out = stmt
            .query_map(rusqlite::params_from_iter(fp_args.iter()), |r| {
                Ok(OriginCount { origin: r.get(0)?, count: r.get::<_, i64>(1)? as usize })
            })?
            .collect::<std::result::Result<_, _>>()?;
        let mut stmt = conn.prepare(&format!(
            "SELECT id, name, risk, method, url, param, state_changed_at, note FROM findings
             WHERE {fp_where} AND state_origin = 'mcp' ORDER BY risk_level DESC, id LIMIT {MAX_AGENT_FALSE_POSITIVES}"
        ))?;
        agent_false_positives = stmt
            .query_map(rusqlite::params_from_iter(fp_args.iter()), |r| {
                Ok(HiddenFinding {
                    id: r.get(0)?,
                    name: r.get(1)?,
                    risk: r.get(2)?,
                    method: r.get(3)?,
                    url: r.get(4)?,
                    param: r.get(5)?,
                    state_changed_at: r.get(6)?,
                    note: r.get(7)?,
                })
            })?
            .collect::<std::result::Result<_, _>>()?;
    }

    // The extra sections cover the same findings as the report: its filters, any state.
    let scope = FindingFilter { state: Some("all".into()), ..opts.filter.clone() };
    let posture = if opts.layout.has(Section::Posture) { Some(store.posture_of(Some(&scope))?) } else { None };
    let mut retest =
        if opts.layout.has(Section::Retest) { Some(retest_letter(store, &opts.layout, &scope)?) } else { None };

    let mut summary_narrative = summary_narrative;
    if let Some(red) = redactor.as_mut() {
        // Findings the report names outside its list (the retest letter's, those an agent
        // hid): their exchanges are read only to learn their secrets, so the scrub masks
        // those wherever the report quotes them.
        let mut ids: Vec<i64> = agent_false_positives.iter().map(|h| h.id).collect();
        let mut sightings = Vec::new();
        if let Some(l) = &retest {
            for row in [&l.fixed, &l.still_present, &l.not_reproduced, &l.regressed, &l.pending].into_iter().flatten() {
                ids.push(row.id);
                sightings.extend(row.history_id);
            }
        }
        learn_secrets(store, red, &ids, sightings)?;
        redact_findings(red, &mut groups, &mut agent_false_positives, retest.as_mut(), summary_narrative.as_mut());
    }

    let generated: String = conn.query_row("SELECT strftime('%Y-%m-%dT%H:%M:%SZ','now')", [], |r| r.get(0))?;
    let f = &opts.filter;
    let mut filters = json!({
        "min_risk": f.min_risk.map(|r| r.as_str()),
        "min_confidence": f.min_confidence.map(|c| c.as_str()),
        "host": f.host,
        "alert": f.alert_ref,
        "state": f.state.clone().unwrap_or_else(|| "open,confirmed,retest_pending".into()),
        "source": f.source,
    });
    if let Some(job) = opts.scan {
        filters["scan"] = json!(job);
    }
    Ok(Report {
        title: opts.title.clone().unwrap_or_else(|| "brainproxy security report".into()),
        generated,
        tool: Tool { name: "brainproxy", version: env!("CARGO_PKG_VERSION") },
        scope: store.engagement().ok().flatten(),
        filters,
        summary: Summary {
            total,
            included,
            truncated: included < total,
            alert_types: groups.len(),
            by_risk,
            false_positives_left_out,
            redacted: redactor.map(|r| r.masked),
        },
        alerts: groups,
        agent_false_positives,
        posture,
        retest,
        summary_narrative,
        layout: opts.layout.clone(),
    })
}

/// The retest section: the latest retest, regression or fix of each finding `scope` selects
/// since the layout's day (default: the last 30 days), and those waiting for a retest.
fn retest_letter(store: &Store, layout: &Layout, scope: &FindingFilter) -> Result<RetestLetter> {
    let (within, mut args) = scope.sql();
    let conn = &store.conn;
    let since: String = match &layout.since {
        Some(d) => d.clone(),
        None => conn.query_row("SELECT strftime('%Y-%m-%d', 'now', '-30 days')", [], |r| r.get(0))?,
    };
    let row = |r: &rusqlite::Row, event: bool| -> rusqlite::Result<RetestRow> {
        Ok(RetestRow {
            id: r.get("id")?,
            name: r.get("name")?,
            risk: r.get("risk")?,
            method: r.get("method")?,
            url: r.get("url")?,
            param: r.get("param")?,
            state: r.get("state")?,
            event: if event { r.get("event")? } else { None },
            time: if event { r.get("etime")? } else { None },
            history_id: if event { r.get("ehistory")? } else { None },
        })
    };
    // A fix a retest made carries the retest's outcome and request on its own event.
    args.push(since.clone());
    let since_at = args.len();
    let mut stmt = conn.prepare(&format!(
        "SELECT f.id, f.name, f.risk, f.method, f.url, f.param, f.state,
            CASE WHEN e.kind = 'retest' THEN 'retest: ' || replace(e.new, '_', ' ')
                WHEN e.kind = 'regressed' THEN 'seen again after a fix'
                ELSE coalesce(e.text, 'marked fixed') END AS event,
            e.time AS etime, e.history_id AS ehistory, e.kind AS kind, e.new AS outcome
         FROM finding_events e JOIN findings f ON f.id = e.finding_id
         WHERE e.id IN (SELECT max(id) FROM finding_events
                        WHERE time >= ?{since_at}
                          AND (kind IN ('retest', 'regressed') OR (kind = 'state' AND new = 'fixed'))
                        GROUP BY finding_id)
           AND f.state != 'removed' AND f.id IN (SELECT id FROM findings WHERE {within})
         ORDER BY f.risk_level DESC, e.time"
    ))?;
    let mut letter = RetestLetter { since: since.clone(), ..Default::default() };
    let mut rows = stmt.query(rusqlite::params_from_iter(args.iter()))?;
    while let Some(r) = rows.next()? {
        let item = row(r, true)?;
        let kind: String = r.get("kind")?;
        let outcome: Option<String> = r.get("outcome")?;
        // A retest that still saw it says so, even of one marked fixed (--no-mark).
        let still = kind == "retest" && outcome.as_deref() == Some("still_present");
        if still {
            letter.still_present.push(item);
        } else if item.state == "fixed" {
            letter.fixed.push(item);
        } else if kind == "regressed" {
            letter.regressed.push(item);
        } else if kind == "retest" {
            letter.not_reproduced.push(item);
        }
    }
    drop(rows);
    args.pop();
    let mut stmt = conn.prepare(&format!(
        "SELECT id, name, risk, method, url, param, state FROM findings
         WHERE state = 'retest_pending' AND id IN (SELECT id FROM findings WHERE {within})
         ORDER BY risk_level DESC, id"
    ))?;
    letter.pending = stmt
        .query_map(rusqlite::params_from_iter(args.iter()), |r| row(r, false))?
        .collect::<std::result::Result<_, _>>()?;
    Ok(letter)
}

/// Masks secrets in everything a report quotes from the target, and in the words people and
/// agents wrote about it (notes, write-ups, ticket links), which may quote a live token.
fn redact_findings(
    red: &mut Redactor,
    groups: &mut [AlertGroup],
    hidden: &mut [HiddenFinding],
    mut letter: Option<&mut RetestLetter>,
    mut summary: Option<&mut Narrative>,
) {
    // Notes, write-ups and tickets: someone's words and links, but they may quote a token.
    let words = |red: &mut Redactor,
                 groups: &mut [AlertGroup],
                 hidden: &mut [HiddenFinding],
                 summary: Option<&mut Narrative>,
                 pass: fn(&mut Redactor, &mut String)| {
        for g in groups.iter_mut() {
            // A tester's title and texts are their words too; a rule's are fixed.
            if is_manual(g) {
                for t in [&mut g.name, &mut g.description, &mut g.solution] {
                    pass(red, t);
                }
            }
            for n in g.narratives.iter_mut() {
                pass(red, &mut n.narrative.text);
            }
            for i in g.instances.iter_mut() {
                if let Some(n) = i.note.as_mut() {
                    pass(red, n);
                }
                for t in i.tickets.iter_mut() {
                    pass(red, &mut t.url);
                }
            }
        }
        for n in hidden.iter_mut().filter_map(|h| h.note.as_mut()) {
            pass(red, n);
        }
        if let Some(n) = summary {
            pass(red, &mut n.text);
        }
    };
    let mut letter_fields = |red: &mut Redactor, pass: fn(&mut Redactor, &mut String)| {
        if let Some(l) = letter.as_deref_mut() {
            for list in [&mut l.fixed, &mut l.still_present, &mut l.not_reproduced, &mut l.regressed, &mut l.pending] {
                for row in list.iter_mut() {
                    pass(red, &mut row.url);
                    pass(red, &mut row.param);
                    // A title, which may be a tester's: only values known elsewhere go.
                    red.scrub(&mut row.name);
                }
            }
        }
    };
    // First by place, so every secret is known; then each known value wherever it appears.
    for inst in groups.iter_mut().flat_map(|g| g.instances.iter_mut()) {
        for s in [&mut inst.url, &mut inst.param, &mut inst.evidence, &mut inst.attack, &mut inst.other_info] {
            red.text(s);
        }
    }
    for h in hidden.iter_mut() {
        red.text(&mut h.url);
        red.text(&mut h.param);
    }
    letter_fields(red, Redactor::text);
    words(red, groups, hidden, summary.as_deref_mut(), Redactor::text);
    for inst in groups.iter_mut().flat_map(|g| g.instances.iter_mut()) {
        for s in [&mut inst.url, &mut inst.param, &mut inst.evidence, &mut inst.attack, &mut inst.other_info] {
            red.scrub(s);
        }
        if let Some(req) = inst.request.as_mut() {
            red.scrub_exchange(req, inst.response.as_mut());
        }
        if let Some(ex) = inst.latest.as_mut() {
            red.scrub_exchange(&mut ex.request, ex.response.as_mut());
        }
    }
    for h in hidden.iter_mut() {
        red.scrub(&mut h.url);
        red.scrub(&mut h.param);
        red.scrub(&mut h.name);
    }
    letter_fields(red, Redactor::scrub);
    words(red, groups, hidden, summary, Redactor::scrub);
}

/// Reads the first and latest exchanges of findings `ids`, and the history entries
/// `sightings`, only so the redactor learns the secrets in them.
fn learn_secrets(store: &Store, red: &mut Redactor, ids: &[i64], sightings: Vec<i64>) -> Result<()> {
    let mut history: std::collections::BTreeSet<i64> = sightings.into_iter().collect();
    if !ids.is_empty() {
        let list = serde_json::to_string(ids).unwrap_or_default();
        let mut stmt = store.conn.prepare(
            "SELECT history_id, last_history_id FROM findings WHERE id IN (SELECT value FROM json_each(?1))",
        )?;
        for row in stmt.query_map([list], |r| Ok((r.get::<_, Option<i64>>(0)?, r.get::<_, Option<i64>>(1)?)))? {
            let (first, last) = row?;
            history.extend(first.into_iter().chain(last));
        }
    }
    for h in history {
        if let Some((mut req, mut resp)) = evidence(store, h, 64 * 1024)? {
            red.exchange(&mut req, resp.as_mut());
        }
    }
    Ok(())
}

fn evidence(store: &Store, id: i64, max: usize) -> Result<Option<(HttpRequest, Option<HttpResponse>)>> {
    let row = store
        .conn
        .query_row(
            "SELECT method, url, req_headers, req_body, status, reason, resp_headers, resp_body FROM history WHERE id = ?1",
            [id],
            |r| {
                let headers = |s: Option<String>| -> Vec<(String, String)> {
                    s.and_then(|s| serde_json::from_str(&s).ok()).unwrap_or_default()
                };
                let req = HttpRequest {
                    method: r.get(0)?,
                    url: r.get(1)?,
                    headers: headers(r.get(2)?),
                    body: Body::new(&r.get::<_, Vec<u8>>(3)?, max),
                };
                let status: Option<i64> = r.get(4)?;
                let resp = status.map(|_| -> rusqlite::Result<HttpResponse> {
                    Ok(HttpResponse {
                        status,
                        reason: r.get(5)?,
                        headers: headers(r.get(6)?),
                        body: Body::new(&r.get::<_, Option<Vec<u8>>>(7)?.unwrap_or_default(), max),
                    })
                });
                Ok((req, resp.transpose()?))
            },
        )
        .optional()?;
    Ok(row)
}

/// Renders a report in the given format.
#[path = "report_docx.rs"]
mod docx;
#[path = "report_exports.rs"]
mod exports;

/// The report as a Word document (DOCX).
pub fn render_docx(report: &Report) -> Vec<u8> {
    docx::render(report)
}

/// The HTML report for printing (PDF): its folded evidence open, and shown in print. Folded
/// sections are the report's own markup (everything quoted from traffic is escaped), so
/// opening them by text is safe.
pub fn render_print_html(report: &Report) -> String {
    let html = render(report, ReportKind::Html);
    if !report.layout.has(Section::Evidence) {
        return html;
    }
    html.replace("<details class=\"tech\">", "<details class=\"tech\" open>")
        .replace("<details><summary>", "<details open><summary>")
        .replacen("</head>", "<style>@media print{.tech{display:block}}</style></head>", 1)
}

pub fn render(report: &Report, kind: ReportKind) -> String {
    match kind {
        ReportKind::Json => serde_json::to_string_pretty(report).unwrap_or_default() + "\n",
        ReportKind::Markdown => markdown(report),
        ReportKind::Html => html(report),
        ReportKind::Sarif => serde_json::to_string_pretty(&sarif(report)).unwrap_or_default() + "\n",
        ReportKind::Csv => exports::csv(report),
        ReportKind::Junit => exports::junit(report),
        ReportKind::DefectDojo => exports::defectdojo(report),
    }
}

/// "3 findings marked false positive are left out: 2 via MCP (an agent), 1 from the desktop app."
fn left_out_text(r: &Report) -> Option<String> {
    let total: usize = r.summary.false_positives_left_out.iter().map(|c| c.count).sum();
    if total == 0 {
        return None;
    }
    let by: Vec<String> = r
        .summary
        .false_positives_left_out
        .iter()
        .map(|c| match c.origin.as_deref() {
            None => format!("{} by whom is unknown", c.count),
            by => format!("{} {}", c.count, provenance::describe(by)),
        })
        .collect();
    Some(format!(
        "{total} finding{} marked false positive {} left out of this report: {}.",
        if total == 1 { "" } else { "s" },
        if total == 1 { "is" } else { "are" },
        by.join(", ")
    ))
}

/// Whether the traffic quoted in the report had its secrets masked, in words.
fn redaction_text(r: &Report) -> String {
    match r.summary.redacted {
        Some(0) => {
            "Session secrets (cookie values, credentials, tokens) would be shown as [redacted]; none were found.".into()
        }
        Some(n) => format!(
            "Session secrets (cookie values, credentials, tokens) are shown as [redacted], in {n} place{}.",
            if n == 1 { "" } else { "s" }
        ),
        None => "This report is not redacted: it quotes session cookies, credentials and tokens as recorded. \
                 Share it only with people who may use them."
            .into(),
    }
}

fn risk_title(risk: &str) -> &'static str {
    match risk {
        "critical" => "Critical",
        "high" => "High",
        "medium" => "Medium",
        "low" => "Low",
        _ => "Informational",
    }
}

/// Raw HTTP-like text for a request/response pair, for Markdown and HTML.
fn http_text(req: &HttpRequest, resp: Option<&HttpResponse>) -> String {
    let mut s = format!("{} {}\n", req.method, req.url);
    for (k, v) in &req.headers {
        let _ = writeln!(s, "{k}: {v}");
    }
    push_body(&mut s, &req.body);
    if let Some(resp) = resp {
        let _ = writeln!(s, "\n--- response ---\n");
        let _ = writeln!(s, "HTTP {} {}", resp.status.unwrap_or(0), resp.reason.as_deref().unwrap_or(""));
        for (k, v) in &resp.headers {
            let _ = writeln!(s, "{k}: {v}");
        }
        push_body(&mut s, &resp.body);
    }
    s
}

fn push_body(s: &mut String, b: &Body) {
    if b.length == 0 {
        return;
    }
    s.push('\n');
    s.push_str(&b.text);
    if b.truncated {
        let _ = write!(s, "\n[... truncated, {} bytes total]", b.length);
    }
    s.push('\n');
}

fn cwe_url(cwe: i64) -> String {
    format!("https://cwe.mitre.org/data/definitions/{cwe}.html")
}

// ---------- Markdown ----------

/// A code span that can't be broken out of: the fence is longer than any backtick run inside.
fn md_code(s: &str) -> String {
    let s = s.replace(['\r', '\n'], " ");
    let fence = "`".repeat(longest_run(&s, '`') + 1);
    let pad = if s.starts_with('`') || s.ends_with('`') || s.is_empty() { " " } else { "" };
    format!("{fence}{pad}{s}{pad}{fence}")
}

fn md_block(s: &str, lang: &str) -> String {
    let fence = "`".repeat((longest_run(s, '`') + 1).max(3));
    let nl = if s.ends_with('\n') { "" } else { "\n" };
    format!("{fence}{lang}\n{s}{nl}{fence}\n")
}

fn longest_run(s: &str, c: char) -> usize {
    let (mut best, mut cur) = (0, 0);
    for ch in s.chars() {
        cur = if ch == c { cur + 1 } else { 0 };
        best = best.max(cur);
    }
    best
}

/// Whether an alert type is one a person added by hand (`findings add`).
fn is_manual(g: &AlertGroup) -> bool {
    g.alert_ref.starts_with("manual:")
}

/// "#3, #7": the history entries a finding links to.
fn history_list(ids: &[i64]) -> String {
    ids.iter().map(|id| format!("#{id}")).collect::<Vec<_>>().join(", ")
}

/// Markdown from a tester's text that renders nothing it holds. Fenced code blocks keep their
/// text as written (often a request to copy), each in a fence of our own that nothing inside can
/// close; every other line is plain text through [`md_escape`], so no HTML, link, image, code
/// span, emphasis or table survives outside a fence. A fence indented four or more spaces, as in
/// a list item, isn't one here: its lines are text like the rest.
fn md_no_html(s: &str) -> String {
    let s = s.replace("\r\n", "\n").replace('\r', "\n");
    let lines: Vec<&str> = s.lines().collect();
    let mut out = String::new();
    let mut i = 0;
    while i < lines.len() {
        let Some((indent, mark, run, lang)) = md_fence_open(lines[i]) else {
            // Leading blanks come off, so no line starts an indented code block.
            out.push_str(&md_escape(lines[i].trim_start_matches([' ', '\t'])));
            out.push('\n');
            i += 1;
            continue;
        };
        let mut body = String::new();
        i += 1;
        while i < lines.len() {
            let l = lines[i];
            i += 1;
            if md_fence_close(l, mark, run) {
                break;
            }
            // The fence's own indent comes off its lines, as in CommonMark.
            let cut = l.len() - l.trim_start_matches(' ').len();
            body.push_str(&l[cut.min(indent)..]);
            body.push('\n');
        }
        // Our own fence closes the block, so a closer misread either way leaves only literal
        // code or escaped text, and an unclosed one ends with the text, not the report.
        out.push_str(&md_block(&body, &lang));
    }
    if !s.ends_with('\n') {
        out.pop();
    }
    out
}

/// A line that opens a fenced code block: its indent, fence character, fence length and language.
fn md_fence_open(line: &str) -> Option<(usize, char, usize, String)> {
    let rest = line.trim_start_matches(' ');
    let indent = line.len() - rest.len();
    let mark = rest.chars().next().filter(|c| matches!(c, '`' | '~'))?;
    let run = rest.len() - rest.trim_start_matches(mark).len();
    let info = rest[run..].trim();
    if indent > 3 || run < 3 || (mark == '`' && info.contains('`')) {
        return None;
    }
    // Only a plain language name is kept from the info string.
    let lang = info.split_whitespace().next().unwrap_or("");
    let ok = lang.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '_' | '-'));
    Some((indent, mark, run, if ok { lang.to_string() } else { String::new() }))
}

/// A line that closes a fence of `run` `mark`s: up to three spaces, at least as long a run of
/// the same character, then only spaces or tabs.
fn md_fence_close(line: &str, mark: char, run: usize) -> bool {
    let rest = line.trim_start_matches(' ');
    let n = rest.len() - rest.trim_start_matches(mark).len();
    line.len() - rest.len() <= 3 && n >= run && rest[n..].chars().all(|c| matches!(c, ' ' | '\t'))
}

/// Text that Markdown shows as written: every ASCII punctuation character backslash-escaped,
/// except `&`, `<` and `>`, which become entities, so even a renderer that ignores backslash
/// escapes reads no HTML in it.
fn md_escape(s: &str) -> String {
    let mut o = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => o.push_str("&amp;"),
            '<' => o.push_str("&lt;"),
            '>' => o.push_str("&gt;"),
            c if c.is_ascii_punctuation() => {
                o.push('\\');
                o.push(c);
            }
            _ => o.push(c),
        }
    }
    o
}

/// Text from our own rule definitions; only table pipes and line breaks need care.
/// Text someone typed, for one line or a table cell: escaped, its line breaks made spaces.
fn md_line(s: &str) -> String {
    md_escape(&s.replace(['\r', '\n'], " "))
}

fn md_text(s: &str) -> String {
    s.replace('|', "\\|").replace(['\r', '\n'], " ")
}

/// An alert type's name for a heading or table cell; a tester's title is plain text.
fn md_name(g: &AlertGroup) -> String {
    if is_manual(g) {
        md_escape(&g.name.replace(['\r', '\n'], " "))
    } else {
        md_text(&g.name)
    }
}

fn markdown(r: &Report) -> String {
    let mut s = String::new();
    let layout = &r.layout;
    let _ = writeln!(s, "# {}\n", md_text(&r.title));
    if let Some(c) = &layout.company {
        let _ = writeln!(s, "Security assessment by {}.\n", md_line(c));
    }
    let _ = writeln!(s, "Generated {} by {} {}.\n", r.generated, r.tool.name, r.tool.version);
    if let Some(scope) = &r.scope {
        let inc: Vec<String> = scope.include.iter().map(|x| md_code(x)).collect();
        let _ = write!(s, "**Scope:** {}", inc.join(", "));
        if !scope.exclude.is_empty() {
            let exc: Vec<String> = scope.exclude.iter().map(|x| md_code(x)).collect();
            let _ = write!(s, " (excluding {})", exc.join(", "));
        }
        s.push_str("\n\n");
    }
    if let Some(job) = r.filters["scan"].as_i64() {
        let _ = writeln!(s, "Only the findings scan job {job} found, for the first time or again.\n");
    }
    if layout.has(Section::Summary) {
        s.push_str("## Summary\n\n| Risk | Findings |\n|---|---:|\n");
        for rc in r.summary.by_risk.iter().filter(|rc| rc.risk != "critical" || rc.count > 0) {
            let _ = writeln!(s, "| {} | {} |", risk_title(&rc.risk), rc.count);
        }
        let _ = writeln!(s, "| **Total** | **{}** |\n", r.summary.total);
    }
    if r.summary.truncated {
        let _ = writeln!(
            s,
            "> Showing {} of {} findings (raise `--limit` to include more).\n",
            r.summary.included, r.summary.total
        );
    }
    if let Some(t) = left_out_text(r) {
        let _ = writeln!(s, "> {t}\n");
    }
    let _ = writeln!(s, "> {}\n", redaction_text(r));
    if let Some(n) = r.summary_narrative.as_ref().filter(|_| layout.has(Section::Summary)) {
        let _ = writeln!(
            s,
            "## Executive summary{}\n\n{}\n\n_{}_\n",
            if n.reviewed() { "" } else { " (draft, not reviewed)" },
            md_no_html(n.text.trim()),
            md_escape(&n.credit())
        );
    }
    if layout.has(Section::FixFirst) {
        let urgent: Vec<_> =
            r.alerts.iter().filter(|g| matches!(g.risk.as_str(), "critical" | "high" | "medium")).take(10).collect();
        if !urgent.is_empty() {
            s.push_str("## Fix these first\n\n");
            for (i, g) in urgent.iter().enumerate() {
                let _ = writeln!(
                    s,
                    "{}. **{}** ({}, {} place{}): {}",
                    i + 1,
                    md_name(g),
                    risk_title(&g.risk),
                    g.instances.len(),
                    if g.instances.len() == 1 { "" } else { "s" },
                    md_escape(first_sentence(&g.solution))
                );
            }
            s.push('\n');
        }
    }
    if let Some(p) = r.posture.as_ref().filter(|_| layout.has(Section::Posture)) {
        md_posture(&mut s, p);
    }
    if let Some(l) = r.retest.as_ref().filter(|_| layout.has(Section::Retest)) {
        md_retest(&mut s, l);
    }
    if r.alerts.is_empty() {
        s.push_str("No findings match the filters.\n");
        md_agent_false_positives(&mut s, r);
        return s;
    }
    if layout.has(Section::List) {
        // A CVSS column only when a tester rated something.
        let rated = r.alerts.iter().any(|g| g.cvss.is_some());
        s.push_str(if rated {
            "| # | Risk | Alert | CVSS | Instances |\n|---:|---|---|---:|---:|\n"
        } else {
            "| # | Risk | Alert | Instances |\n|---:|---|---|---:|\n"
        });
        for (i, g) in r.alerts.iter().enumerate() {
            let cvss = match (&g.cvss, rated) {
                (Some(c), _) => format!(" {:.1} |", c.score),
                (None, true) => " – |".into(),
                (None, false) => String::new(),
            };
            let _ =
                writeln!(s, "| {} | {} | {} |{cvss} {} |", i + 1, risk_title(&g.risk), md_name(g), g.instances.len());
        }
        s.push('\n');
    }
    for (i, g) in r.alerts.iter().enumerate().filter(|_| layout.has(Section::Issues)) {
        let _ = writeln!(s, "## {}. {} ({})\n", i + 1, md_name(g), risk_title(&g.risk));
        let mut meta = vec![format!("**Alert:** `{}`", g.alert_ref)];
        if let Some(c) = &g.cvss {
            meta.push(format!("**CVSS 4.0:** {:.1} ({}) `{}`", c.score, c.severity, c.vector));
        }
        if let Some(c) = g.cwe {
            meta.push(format!("**CWE:** [{c}]({})", cwe_url(c)));
        }
        if let Some(w) = g.wasc {
            meta.push(format!("**WASC:** {w}"));
        }
        let _ = writeln!(s, "{}\n", meta.join(" · "));
        for n in &g.narratives {
            let _ = writeln!(
                s,
                "### {}\n\n{}\n\n_{}_\n",
                md_escape(&narrative_title(g, n)),
                md_no_html(n.narrative.text.trim()),
                md_escape(&n.narrative.credit())
            );
        }
        // A tester's own text is plain text, fenced code apart: it may quote the target.
        let prose = |t: &str| if is_manual(g) { md_no_html(t.trim()) } else { t.trim().to_string() };
        if !g.description.is_empty() {
            let _ = writeln!(s, "### Description\n\n{}\n", prose(&g.description));
        }
        if !g.solution.is_empty() {
            let _ = writeln!(s, "### Solution\n\n{}\n", prose(&g.solution));
        }
        if !g.references.is_empty() {
            s.push_str("### References\n\n");
            for u in &g.references {
                let _ = writeln!(s, "- <{}>", u.replace(['<', '>', ' '], ""));
            }
            s.push('\n');
        }
        if layout.has(Section::Reproduce) {
            let lines: Vec<String> = g.instances.iter().filter_map(|i| i.request.as_ref().map(curl)).collect();
            if !lines.is_empty() {
                let _ = writeln!(s, "### How to reproduce\n\n{}", md_block(&lines.join("\n\n"), "sh"));
            }
        }
        let _ = writeln!(s, "### Instances ({})\n", g.instances.len());
        for inst in &g.instances {
            let _ = writeln!(s, "#### {} {}\n", inst.method, md_code(&inst.url));
            if !layout.has(Section::Evidence) {
                continue;
            }
            let _ = writeln!(
                s,
                "- Finding #{} · {} · confidence {} · {} · seen {}× · added {}",
                inst.id,
                inst.source,
                inst.confidence,
                inst.state_text,
                inst.hits,
                provenance::describe(inst.origin.as_deref())
            );
            if !inst.param.is_empty() {
                let _ = writeln!(s, "- Parameter: {}", md_code(&inst.param));
            }
            if !inst.evidence.is_empty() {
                let _ = writeln!(s, "- Evidence: {}", md_code(&inst.evidence));
            }
            if !inst.attack.is_empty() {
                let _ = writeln!(s, "- Attack: {}", md_code(&inst.attack));
            }
            if let Some(n) = inst.note.as_deref().filter(|n| !n.is_empty()) {
                let _ = writeln!(s, "- Note ({}): {}", note_by(inst), md_code(n));
            }
            if let Some(c) = inst.cwe {
                let _ = writeln!(s, "- CWE: [{c}]({})", cwe_url(c));
            }
            if inst.history_ids.len() > 1 {
                let _ = writeln!(s, "- History: {}", history_list(&inst.history_ids));
            }
            if let Some(t) = latest_text(inst) {
                let _ = writeln!(s, "- {t}");
            }
            if let Some(t) = &inst.agent_trail {
                let _ = writeln!(s, "- Agent trail: {}", trail_text(t));
            }
            for t in &inst.tickets {
                let _ = writeln!(s, "- Ticket ({}): <{}>", t.tracker, t.url.replace(['<', '>', ' '], ""));
            }
            s.push('\n');
            if !inst.other_info.is_empty() {
                let _ = writeln!(s, "Other info:\n\n{}", md_block(&inst.other_info, "text"));
            }
            if let Some(req) = &inst.request {
                let _ = writeln!(
                    s,
                    "<details><summary>Request and response (history #{})</summary>\n\n{}\n</details>\n",
                    inst.history_id.unwrap_or(0),
                    md_block(&http_text(req, inst.response.as_ref()), "http")
                );
            }
            if let Some(ex) = &inst.latest {
                let _ = writeln!(
                    s,
                    "<details><summary>Latest sighting (history #{})</summary>\n\n{}\n</details>\n",
                    inst.last_history_id.unwrap_or(0),
                    md_block(&http_text(&ex.request, ex.response.as_ref()), "http")
                );
            }
        }
    }
    md_agent_false_positives(&mut s, r);
    s
}

/// The posture section in Markdown.
fn md_posture(s: &mut String, p: &Value) {
    s.push_str("## Posture\n\n| Risk | Open issues | Places |\n|---|---:|---:|\n");
    for risk in RISKS {
        let issues = p["open"]["issues"][risk].as_i64().unwrap_or(0);
        if risk == "critical" && issues == 0 {
            continue;
        }
        let _ =
            writeln!(s, "| {} | {issues} | {} |", risk_title(risk), p["open"]["instances"][risk].as_i64().unwrap_or(0));
    }
    let state = |k: &str| p["by_state"][k].as_i64().unwrap_or(0);
    let retests = |k: &str| p["retests"][k].as_i64().unwrap_or(0);
    let _ = writeln!(
        s,
        "\n{} fixed, {} accepted as a risk, {} awaiting a retest. Retests: {} not reproduced, {} still there. \
         {} came back after a fix.\n",
        state("fixed"),
        state("accepted_risk"),
        state("retest_pending"),
        retests("not_reproduced"),
        retests("still_present"),
        p["regressed"].as_i64().unwrap_or(0)
    );
    let scans = p["scans"].as_array().map(Vec::as_slice).unwrap_or_default();
    if !scans.is_empty() {
        s.push_str("| Scan | Finished | New | Still there | No longer found |\n|---|---|---:|---:|---:|\n");
        for scan in scans.iter().rev().take(10) {
            let _ = writeln!(
                s,
                "| #{} | {} | {} | {} | {} |",
                scan["job"],
                day(scan["finished"].as_str().unwrap_or("")),
                scan["new"],
                scan["still"],
                scan["gone"]
            );
        }
        s.push('\n');
    }
}

/// The retest section in Markdown.
fn md_retest(s: &mut String, l: &RetestLetter) {
    let _ = writeln!(
        s,
        "## Retest since {}\n\n**{} fixed**, {} still there, {} came back after a fix, {} awaiting a retest.\n",
        md_escape(&l.since),
        l.fixed.len(),
        l.still_present.len(),
        l.regressed.len(),
        l.pending.len()
    );
    for (title, rows) in [
        ("Fixed", &l.fixed),
        ("Still there", &l.still_present),
        ("Not reproduced, not marked fixed", &l.not_reproduced),
        ("Came back after a fix", &l.regressed),
        ("Awaiting a retest", &l.pending),
    ] {
        if rows.is_empty() {
            continue;
        }
        let _ = writeln!(
            s,
            "### {title}\n\n| # | Issue | Risk | Address | What happened | Proof |\n|---:|---|---|---|---|---|"
        );
        for row in rows {
            let what = match (&row.event, &row.time) {
                (Some(e), Some(t)) => format!("{e} on {}", day(t)),
                _ => row.state.replace('_', " "),
            };
            let _ = writeln!(
                s,
                "| {} | {} | {} | {} | {} | {} |",
                row.id,
                md_line(&row.name),
                risk_title(&row.risk),
                md_code(&format!("{} {}", row.method, row.url)),
                md_line(&what),
                row.history_id.map(|h| format!("history #{h}")).unwrap_or_default()
            );
        }
        s.push('\n');
    }
}

/// When a finding was first and last seen, when it was seen in more than one history entry.
fn latest_text(inst: &Instance) -> Option<String> {
    let last = inst.latest_id()?;
    let when = inst.last_seen.as_deref().map(|t| format!(" on {}", day(t))).unwrap_or_default();
    Some(format!("First seen {}; last seen in history #{last}{when}", day(&inst.time)))
}

/// Who wrote a finding's note, in words.
fn note_by(inst: &Instance) -> String {
    match (&inst.note_origin, &inst.note_changed_at) {
        (None, _) => "by whom is unknown".into(),
        (by, at) => {
            let at = at.as_deref().map(|t| format!(" at {t}")).unwrap_or_default();
            format!("written {}{at}", provenance::describe(by.as_deref()))
        }
    }
}

fn md_agent_false_positives(s: &mut String, r: &Report) {
    if r.agent_false_positives.is_empty() {
        return;
    }
    let _ = writeln!(
        s,
        "## Marked false positive by an agent\n\nThese findings were marked false positive via MCP (an agent), \
         not by a person, and are left out above.\n"
    );
    for h in &r.agent_false_positives {
        let _ =
            write!(s, "- #{} {} ({}) · {} {}", h.id, md_text(&h.name), risk_title(&h.risk), h.method, md_code(&h.url));
        if !h.param.is_empty() {
            let _ = write!(s, " · parameter {}", md_code(&h.param));
        }
        if let Some(t) = &h.state_changed_at {
            let _ = write!(s, " · at {t}");
        }
        if let Some(n) = h.note.as_deref().filter(|n| !n.is_empty()) {
            let _ = write!(s, " · note {}", md_code(n));
        }
        s.push('\n');
    }
    s.push('\n');
}

// ---------- HTML ----------

fn esc(s: &str) -> String {
    let mut o = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => o.push_str("&amp;"),
            '<' => o.push_str("&lt;"),
            '>' => o.push_str("&gt;"),
            '"' => o.push_str("&quot;"),
            '\'' => o.push_str("&#39;"),
            _ => o.push(c),
        }
    }
    o
}

/// A link only for http(s) URLs; anything else is shown as text.
fn link(url: &str, text: &str) -> String {
    if url.starts_with("https://") || url.starts_with("http://") {
        format!("<a href=\"{}\" rel=\"noreferrer\">{}</a>", esc(url), esc(text))
    } else {
        esc(text)
    }
}

const CSS: &str = r#"
:root{--bg:#fff;--fg:#1d1f23;--muted:#5d6370;--line:#dfe2e7;--card:#f6f7f9;--code:#eef0f3;
--critical:#7b1fa2;--high:#c62828;--medium:#d9730d;--low:#b59a00;--info:#3d6fb6}
@media (prefers-color-scheme:dark){:root{--bg:#16181c;--fg:#e4e6ea;--muted:#9aa0aa;--line:#2e323a;
--card:#1e2126;--code:#262a31;--critical:#ce93d8;--high:#ef5350;--medium:#f0953e;--low:#d8c13c;--info:#6c9be0}}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--fg);font:15px/1.55 system-ui,-apple-system,"Segoe UI",sans-serif}
main{max-width:980px;margin:0 auto;padding:24px 16px 64px}
h1{font-size:1.7em;margin:0 0 4px}h2{margin-top:2em;border-bottom:1px solid var(--line);padding-bottom:4px}
h3{margin:1.4em 0 .4em;font-size:1.05em}
.muted{color:var(--muted)}
table{border-collapse:collapse;width:100%;margin:12px 0}
th,td{text-align:left;padding:6px 10px;border-bottom:1px solid var(--line);vertical-align:top}
td.n,th.n{text-align:right}
.badge{display:inline-block;padding:1px 8px;border-radius:10px;color:#fff;font-size:.8em;font-weight:600}
.critical{background:var(--critical)}.high{background:var(--high)}.medium{background:var(--medium)}.low{background:var(--low)}.info{background:var(--info)}
.inst{background:var(--card);border:1px solid var(--line);border-radius:8px;padding:10px 14px;margin:10px 0}
.inst dl{display:grid;grid-template-columns:max-content 1fr;gap:2px 12px;margin:6px 0}
.inst dt{color:var(--muted)}.inst dd{margin:0;min-width:0}
code,pre{font:13px/1.45 ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;background:var(--code);border-radius:4px}
code{padding:1px 4px;overflow-wrap:anywhere}
pre{padding:10px;overflow:auto;white-space:pre-wrap;overflow-wrap:anywhere;max-height:480px}
summary{cursor:pointer;color:var(--muted)}
a{color:var(--info)}
.note{border-left:3px solid var(--medium);padding:4px 10px}
.cover{border-bottom:2px solid var(--fg);padding-bottom:8px}.kicker{text-transform:uppercase;letter-spacing:.08em;font-size:.8em;color:var(--muted)}
.verdict{font-size:1.15em}
.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(210px,1fr));gap:10px;margin:14px 0}
.card{display:flex;gap:12px;align-items:flex-start;background:var(--card);border:1px solid var(--line);border-left-width:5px;border-radius:8px;padding:10px 12px}
.card .num{font-size:2em;font-weight:700;line-height:1;min-width:1.4em}.card p{margin:4px 0 0;font-size:.9em;color:var(--muted)}
.critical-edge{border-left-color:var(--critical)}.high-edge{border-left-color:var(--high)}.medium-edge{border-left-color:var(--medium)}.low-edge{border-left-color:var(--low)}.info-edge{border-left-color:var(--info)}
.fixfirst li{margin:6px 0}
.tag{display:inline-block;padding:0 6px;border:1px solid var(--line);border-radius:4px;font-size:.8em}
.tech{margin:12px 0;border:1px solid var(--line);border-radius:8px;padding:6px 12px}
.narrative{border-left:3px solid var(--line);padding-left:12px}.cover{border-top:6px solid var(--brand,transparent);padding-top:12px}.cover .logo{max-height:56px;max-width:240px;display:block;margin-bottom:12px}
h1,h2{color:var(--brand-ink,inherit)}.cvss{font-size:.9em}.letter td.n{white-space:nowrap}
@media print{body{font-size:11pt;background:#fff;color:#000}main{max-width:none;padding:0}a{color:inherit;text-decoration:none}
.card,.inst,tr{break-inside:avoid}h2,h3{break-after:avoid}.tech{display:none}}
"#;

/// What a risk level means, in plain words, for the report's readers.
fn risk_meaning(risk: &str) -> &'static str {
    match risk {
        "critical" => "Severe: an attacker could take over the system or its data with little effort. Fix now.",
        "high" => "Serious: could let an attacker steal data or take over accounts. Fix these first.",
        "medium" => "Important weaknesses that make attacks easier. Plan fixes soon.",
        "low" => "Minor issues and missing hardening. Fix when convenient.",
        _ => "Observations, not problems on their own.",
    }
}

/// The first sentence of a rule text, for the overview. ZAP texts often put one sentence per
/// line, and CWE-style ones start with a "Phase: ..." line.
fn first_sentence(s: &str) -> &str {
    let line = s.lines().map(str::trim).find(|l| !l.is_empty() && !l.starts_with("Phase:")).unwrap_or("");
    let end = line
        .match_indices(". ")
        .map(|(i, _)| i)
        .find(|&i| !["etc", "e.g", "i.e"].iter().any(|a| line[..i].ends_with(a)))
        .map_or(line.len(), |i| i + 1);
    match line[..end].char_indices().nth(240) {
        Some((i, _)) => &line[..i],
        None => &line[..end],
    }
}

fn paragraphs(s: &str) -> String {
    esc(s.trim()).replace("\n\n", "</p><p>").replace('\n', "<br>")
}

fn html(r: &Report) -> String {
    let mut s = String::new();
    let _ = write!(
        s,
        "<!doctype html>\n<html lang=\"en\"><head><meta charset=\"utf-8\">\
         <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\
         <meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'none'; style-src 'unsafe-inline'; img-src data:\">\
         <meta name=\"referrer\" content=\"no-referrer\">\
         <title>{}</title><style>{CSS}</style>{}</head><body><main>\n",
        esc(&r.title),
        // Only #rrggbb, checked here too, so it can't leave the declaration.
        r.layout
            .accent
            .as_deref()
            .filter(|a| a.len() == 7 && a.starts_with('#') && a[1..].chars().all(|c| c.is_ascii_hexdigit()))
            .map(|a| format!("<style>:root{{--brand:{a};--brand-ink:{a}}}</style>"))
            .unwrap_or_default()
    );
    let layout = &r.layout;
    let count = |risk: &str| r.summary.by_risk.iter().find(|c| c.risk == risk).map_or(0, |c| c.count);
    let instances = || r.alerts.iter().flat_map(|g| &g.instances);
    let mut hosts: Vec<&str> = instances().map(|i| i.host.as_str()).collect();
    hosts.sort_unstable();
    hosts.dedup();
    let first = instances().map(|i| i.time.as_str()).min();
    let last = instances().map(|i| i.time.as_str()).max();

    let logo =
        layout.logo.as_deref().map(|l| format!("<img class=\"logo\" alt=\"\" src=\"{}\">", esc(l))).unwrap_or_default();
    let kicker = match &layout.company {
        Some(c) => format!("Security assessment by {}", esc(c)),
        None => "Security assessment".to_string(),
    };
    let _ = writeln!(s, "<header class=\"cover\">{logo}<div class=\"kicker\">{kicker}</div><h1>{}</h1>", esc(&r.title));
    let mut facts = vec![format!("Report generated {}", esc(day(&r.generated)))];
    if let (Some(a), Some(b)) = (first, last) {
        facts.push(if day(a) == day(b) {
            format!("issues found on {}", esc(day(a)))
        } else {
            format!("issues found {} to {}", esc(day(a)), esc(day(b)))
        });
    }
    if let Some(job) = r.filters["scan"].as_i64() {
        facts.push(format!("only the findings of scan job {job}"));
    }
    let _ = writeln!(s, "<p class=\"muted\">{} · {} {}</p></header>", facts.join(" · "), r.tool.name, r.tool.version);

    // ---- At a glance: for readers who stop after the first page.
    if layout.has(Section::Summary) {
        s.push_str("<h2>At a glance</h2>\n");
        // Critical and high are both "serious" here; the cards tell them apart.
        let (high, medium) = (count("critical") + count("high"), count("medium"));
        let verdict = if r.summary.total == 0 {
            "The automated tests found no issues that match this report's filters.".to_string()
        } else if high > 0 {
            format!(
                "The tests found <strong>{high} serious issue{}</strong> that should be fixed as soon as possible, \
             because they could let an attacker steal data or take over accounts.",
                if high == 1 { "" } else { "s" }
            )
        } else if medium > 0 {
            format!(
                "No serious issues were found, but <strong>{medium} important weakness{}</strong> make attacks easier \
             and should be fixed soon.",
                if medium == 1 { "" } else { "es" }
            )
        } else {
            "No serious or important issues were found; what remains is minor hardening and observations.".to_string()
        };
        let _ = writeln!(s, "<p class=\"verdict\">{verdict}</p>");
        if let Some(n) = &r.summary_narrative {
            let _ = writeln!(
                s,
                "<div class=\"narrative\"><p>{}</p><p class=\"muted\">{}{}</p></div>",
                paragraphs(&n.text),
                if n.reviewed() { "" } else { "Draft: " },
                esc(&n.credit())
            );
        }
        s.push_str("<div class=\"cards\">");
        // A critical card only when there is something critical, so most reports keep four.
        for risk in RISKS.into_iter().filter(|&r| r != "critical" || count(r) > 0) {
            let _ = write!(
            s,
            "<div class=\"card {risk}-edge\"><div class=\"num\">{}</div><div><span class=\"badge {risk}\">{}</span>\
             <p>{}</p></div></div>",
            count(risk),
            risk_title(risk),
            risk_meaning(risk)
        );
        }
        s.push_str("</div>\n");
        let mut tested: Vec<String> =
            r.scope.iter().flat_map(|sc| &sc.include).map(|x| format!("<code>{}</code>", esc(x))).collect();
        if tested.is_empty() {
            tested = hosts.iter().map(|h| format!("<code>{}</code>", esc(h))).collect();
        }
        if !tested.is_empty() {
            let _ = writeln!(s, "<p><strong>What was tested:</strong> {}</p>", tested.join(", "));
        }
        if let Some(t) = left_out_text(r) {
            let link = if r.agent_false_positives.is_empty() {
                ""
            } else {
                " <a href=\"#agent-fp\">See the ones an agent marked.</a>"
            };
            let _ = writeln!(s, "<p class=\"note\">{}{link}</p>", esc(&t));
        }
    }
    // That it is cut short, or unredacted, is said whatever sections the report has.
    if r.summary.truncated {
        let _ = writeln!(
            s,
            "<p class=\"note\">This report shows {} of {} findings (raise <code>--limit</code> to include more).</p>",
            r.summary.included, r.summary.total
        );
    }
    if r.summary.redacted.is_none() {
        let _ = writeln!(s, "<p class=\"note\"><strong>{}</strong></p>", esc(&redaction_text(r)));
    }
    let urgent: Vec<(usize, &AlertGroup)> = r
        .alerts
        .iter()
        .enumerate()
        .filter(|(_, g)| matches!(g.risk.as_str(), "critical" | "high" | "medium"))
        .take(10)
        .collect();
    // Links go to the issue sections, when there are any.
    let issues = layout.has(Section::Issues);
    let anchor =
        |i: usize, name: &str| if issues { format!("<a href=\"#a{}\">{}</a>", i + 1, esc(name)) } else { esc(name) };
    if layout.has(Section::FixFirst) && !urgent.is_empty() {
        s.push_str("<h3>Fix these first</h3><ol class=\"fixfirst\">");
        for (i, g) in urgent {
            let n = g.instances.len();
            let _ = write!(
                s,
                "<li>{} <span class=\"badge {}\">{}</span> \
                 <span class=\"muted\">· {n} place{}</span><br>{}</li>",
                anchor(i, &g.name),
                g.risk,
                risk_title(&g.risk),
                if n == 1 { "" } else { "s" },
                esc(first_sentence(&g.solution))
            );
        }
        s.push_str("</ol>\n");
    }

    if let Some(p) = r.posture.as_ref().filter(|_| layout.has(Section::Posture)) {
        html_posture(&mut s, p);
    }
    if let Some(letter) = r.retest.as_ref().filter(|_| layout.has(Section::Retest)) {
        html_retest(&mut s, letter);
    }

    // ---- All issues, most serious first.
    let rated = r.alerts.iter().any(|g| g.cvss.is_some());
    if layout.has(Section::List) && !r.alerts.is_empty() {
        let _ = writeln!(
            s,
            "<h2>All issues</h2>\n<table><thead><tr><th class=\"n\">#</th><th>Issue</th><th>Risk</th>{}<th class=\"n\">Places</th></tr></thead><tbody>",
            if rated { "<th class=\"n\">CVSS</th>" } else { "" }
        );
        for (i, g) in r.alerts.iter().enumerate() {
            let cvss = match (&g.cvss, rated) {
                (Some(c), _) => format!("<td class=\"n\">{:.1}</td>", c.score),
                (None, true) => "<td class=\"n muted\">–</td>".to_string(),
                (None, false) => String::new(),
            };
            let _ = writeln!(
                s,
                "<tr><td class=\"n\">{}</td><td>{}</td><td><span class=\"badge {}\">{}</span></td>{cvss}<td class=\"n\">{}</td></tr>",
                i + 1,
                anchor(i, &g.name),
                g.risk,
                risk_title(&g.risk),
                g.instances.len()
            );
        }
        s.push_str("</tbody></table>\n");
    }
    for (i, g) in r.alerts.iter().enumerate().filter(|_| issues) {
        let _ = writeln!(
            s,
            "<section class=\"issue\"><h2 id=\"a{}\">{}. {} <span class=\"badge {}\">{}</span></h2>",
            i + 1,
            i + 1,
            esc(&g.name),
            g.risk,
            risk_title(&g.risk)
        );
        if let Some(c) = &g.cvss {
            let _ = writeln!(
                s,
                "<p class=\"cvss\"><strong>CVSS 4.0 {:.1}</strong> ({}) <code>{}</code></p>",
                c.score,
                c.severity,
                esc(&c.vector)
            );
        }
        for n in &g.narratives {
            let _ = writeln!(
                s,
                "<h3>{}</h3><div class=\"narrative\"><p>{}</p><p class=\"muted\">{}</p></div>",
                esc(&narrative_title(g, n)),
                paragraphs(&n.narrative.text),
                esc(&n.narrative.credit())
            );
        }
        for (h, text) in [("What this means", &g.description), ("How to fix it", &g.solution)] {
            if !text.trim().is_empty() {
                let _ = writeln!(s, "<h3>{h}</h3><p>{}</p>", paragraphs(text));
            }
        }
        let _ = writeln!(s, "<h3>Where it was found ({})</h3>", g.instances.len());
        s.push_str(
            "<table class=\"where\"><thead><tr><th>Address</th><th>Field</th><th>Certainty</th></tr></thead><tbody>",
        );
        for inst in &g.instances {
            // Only a person's confirmation reads as checked by the tester.
            let mut state = match inst.state.as_str() {
                "confirmed" if by_a_person(inst.state_origin.as_deref()) => " <span class=\"tag\">confirmed</span>",
                "confirmed" if inst.state_origin.as_deref() == Some("mcp") => {
                    " <span class=\"tag\">confirmed via MCP (an agent)</span>"
                }
                "confirmed" => " <span class=\"tag\">confirmed (by whom is unknown)</span>",
                _ => "",
            }
            .to_string();
            // Who removed it; MCP calls can't remove, so this names a person or an unknown origin.
            if inst.state == "removed" {
                let by = provenance::describe(inst.state_origin.as_deref());
                let _ = write!(state, " <span class=\"tag\">removed {by}</span>");
            }
            // A finding an agent recorded through `findings add` isn't a person's manual testing.
            if inst.source == MANUAL_SOURCE && inst.origin.as_deref() == Some("mcp") {
                state.push_str(" <span class=\"tag\">added via MCP (an agent)</span>");
            } else if inst.source == MANUAL_SOURCE {
                state.push_str(" <span class=\"tag\">found by hand</span>");
            }
            if let Some(t) = &inst.agent_trail {
                state.push_str(if t.reviewed_by.is_some() {
                    " <span class=\"tag\">agent's work reviewed</span>"
                } else {
                    " <span class=\"tag\">agent's work not reviewed</span>"
                });
            }
            let _ = write!(
                s,
                "<tr><td><code>{} {}</code>{state}</td><td>{}</td><td>{}</td></tr>",
                esc(&inst.method),
                esc(&inst.url),
                if inst.param.is_empty() {
                    "<span class=\"muted\">–</span>".to_string()
                } else {
                    format!("<code>{}</code>", esc(&inst.param))
                },
                esc(&inst.confidence)
            );
        }
        s.push_str("</tbody></table>\n");

        if layout.has(Section::Reproduce) {
            let lines: Vec<String> = g.instances.iter().filter_map(|i| i.request.as_ref().map(curl)).collect();
            if !lines.is_empty() {
                let _ = writeln!(s, "<h3>How to reproduce</h3><pre>{}</pre>", esc(&lines.join("\n\n")));
            }
        }
        if !layout.has(Section::Evidence) {
            s.push_str("</section>\n");
            continue;
        }
        // Everything a developer needs to reproduce it, folded away.
        s.push_str("<details class=\"tech\"><summary>Technical details</summary>");
        let mut meta = vec![format!("Rule <code>{}</code>", esc(&g.alert_ref))];
        if let Some(c) = g.cwe {
            meta.push(format!("CWE {}", link(&cwe_url(c), &c.to_string())));
        }
        if let Some(w) = g.wasc {
            meta.push(format!("WASC {w}"));
        }
        let _ = writeln!(s, "<p class=\"muted\">{}</p>", meta.join(" · "));
        if !g.references.is_empty() {
            s.push_str("<p><strong>References</strong></p><ul>");
            for u in &g.references {
                let _ = write!(s, "<li>{}</li>", link(u, u));
            }
            s.push_str("</ul>\n");
        }
        for inst in &g.instances {
            let _ = write!(
                s,
                "<div class=\"inst\"><div><strong>{}</strong> <code>{}</code></div><dl>",
                esc(&inst.method),
                esc(&inst.url)
            );
            let mut row = |k: &str, v: String| {
                let _ = write!(s, "<dt>{k}</dt><dd>{v}</dd>");
            };
            row(
                "Finding",
                format!("#{} · {} · {}× seen · {}", inst.id, esc(&inst.source), inst.hits, esc(&inst.state)),
            );
            row("Added", esc(provenance::describe(inst.origin.as_deref())));
            if inst.state_origin.is_some() || inst.state != "open" {
                row("State", esc(&inst.state_text));
            }
            for (k, v) in [("Parameter", &inst.param), ("Evidence", &inst.evidence), ("Attack", &inst.attack)] {
                if !v.is_empty() {
                    row(k, format!("<code>{}</code>", esc(v)));
                }
            }
            if let Some(n) = inst.note.as_deref().filter(|n| !n.is_empty()) {
                row("Note", format!("{} <span class=\"muted\">({})</span>", esc(n), esc(&note_by(inst))));
            }
            if let Some(c) = inst.cwe {
                row("CWE", link(&cwe_url(c), &c.to_string()));
            }
            if inst.history_ids.len() > 1 {
                row("History", history_list(&inst.history_ids));
            }
            if let Some(t) = latest_text(inst) {
                row("Seen", esc(&t));
            }
            if let Some(t) = &inst.agent_trail {
                row("Agent trail", esc(&trail_text(t)));
            }
            if !inst.tickets.is_empty() {
                let links: Vec<String> =
                    inst.tickets.iter().map(|t| link(&t.url, &format!("{} ticket", t.tracker))).collect();
                row("Tickets", links.join(", "));
            }
            s.push_str("</dl>");
            if !inst.other_info.is_empty() {
                let _ = write!(s, "<pre>{}</pre>", esc(&inst.other_info));
            }
            if let Some(req) = &inst.request {
                let _ = write!(
                    s,
                    "<details><summary>Request and response (history #{})</summary><pre>{}</pre></details>",
                    inst.history_id.unwrap_or(0),
                    esc(&http_text(req, inst.response.as_ref()))
                );
            }
            if let Some(ex) = &inst.latest {
                let _ = write!(
                    s,
                    "<details><summary>Latest sighting (history #{})</summary><pre>{}</pre></details>",
                    inst.last_history_id.unwrap_or(0),
                    esc(&http_text(&ex.request, ex.response.as_ref()))
                );
            }
            s.push_str("</div>\n");
        }
        s.push_str("</details></section>\n");
    }

    // ---- What an agent hid.
    if (issues || layout.has(Section::List)) && !r.agent_false_positives.is_empty() {
        s.push_str(
            "<h2 id=\"agent-fp\">Marked false positive by an agent</h2><p>These findings were marked false positive \
             via MCP (an agent), not by a person, and are left out above.</p>\
             <table><thead><tr><th class=\"n\">#</th><th>Issue</th><th>Risk</th><th>Address</th><th>Marked</th>\
             <th>Note</th></tr></thead><tbody>\n",
        );
        for h in &r.agent_false_positives {
            let _ = writeln!(
                s,
                "<tr><td class=\"n\">{}</td><td>{}</td><td><span class=\"badge {}\">{}</span></td>\
                 <td><code>{} {}</code>{}</td><td>{}</td><td>{}</td></tr>",
                h.id,
                esc(&h.name),
                esc(&h.risk),
                risk_title(&h.risk),
                esc(&h.method),
                esc(&h.url),
                if h.param.is_empty() { String::new() } else { format!(" <code>{}</code>", esc(&h.param)) },
                esc(h.state_changed_at.as_deref().unwrap_or("")),
                esc(h.note.as_deref().unwrap_or(""))
            );
        }
        s.push_str("</tbody></table>\n");
    }

    // ---- How to read it.
    if !layout.has(Section::About) {
        s.push_str("</main></body></html>\n");
        return s;
    }
    s.push_str(
        "<h2>About this report</h2>\
         <p>The findings come from automated tests that look at the site's traffic and send attack requests, as an \
         attacker would. <strong>Certainty</strong> says how sure a test is: low-certainty findings need a person to \
         confirm them, and some may turn out not to be real. A finding marked <span class=\"tag\">confirmed</span> was \
         checked by the tester, from the desktop app or the command line; one marked <span class=\"tag\">confirmed via \
         MCP (an agent)</span> was confirmed by an AI agent and not by a person. Each finding also says how it was \
         added (from the desktop app, from the command line, or via MCP, by an AI agent) and, in its technical \
         details, who last changed its state and when. Automated tests can't find every problem (for example flaws in business logic), so \
         a short or empty report doesn't prove a site is secure.",
    );
    let manual = r.alerts.iter().flat_map(|g| &g.instances).filter(|i| i.source == MANUAL_SOURCE);
    if manual.clone().any(|i| i.origin.as_deref() != Some("mcp")) {
        s.push_str(
            " A finding marked <span class=\"tag\">found by hand</span> was recorded during manual testing \
             rather than raised by an automated test.",
        );
    }
    if manual.clone().any(|i| i.origin.as_deref() == Some("mcp")) {
        s.push_str(
            " A finding marked <span class=\"tag\">added via MCP (an agent)</span> was recorded by an AI agent, \
             not raised by an automated test nor checked by a person.",
        );
    }
    if r.summary.redacted.is_some() {
        let _ = write!(s, " {}", esc(&redaction_text(r)));
    }
    s.push_str("</p>\n");
    s.push_str("</main></body></html>\n");
    s
}

/// One finding as the report shows it: its texts, redacted evidence and fingerprint.
fn one_finding(store: &Store, id: i64, redact: bool) -> Result<(AlertGroup, Instance)> {
    let opts = ReportOptions {
        filter: FindingFilter { ids: Some(vec![id]), state: Some("all".into()), ..Default::default() },
        redact,
        max_evidence: 16 * 1024,
        drafts: false,
        ..Default::default()
    };
    let r = build(store, &opts)?;
    let mut g = r.alerts.into_iter().next().ok_or_else(|| crate::error::Error::NotFound(format!("finding {id}")))?;
    let inst = g.instances.remove(0);
    Ok((g, inst))
}

/// The text around a finding's evidence in a response, for a repro pack.
fn excerpt(resp: &HttpResponse, evidence: &str) -> Option<String> {
    let text = format!(
        "{}\n{}",
        resp.headers.iter().map(|(k, v)| format!("{k}: {v}")).collect::<Vec<_>>().join("\n"),
        resp.body.text
    );
    let at = text.find(evidence).filter(|_| !evidence.is_empty())?;
    let start = text[..at].char_indices().rev().nth(200).map_or(0, |(i, _)| i);
    let end = text[at + evidence.len()..].char_indices().nth(200).map_or(text.len(), |(i, _)| at + evidence.len() + i);
    Some(text[start..end].to_string())
}

/// A repro pack: everything needed to see a finding again by hand or in CI, secrets masked
/// unless `redact` is off.
pub fn repro(store: &Store, id: i64, redact: bool) -> Result<Value> {
    let (g, i) = one_finding(store, id, redact)?;
    // An active check starts from a GET of the URL; another method or a body needs the scan
    // to start from the original request, which the pack's (attack) exchange isn't.
    let plain_get = i.method.eq_ignore_ascii_case("GET") && i.request.as_ref().is_none_or(|r| r.body.length == 0);
    let what = match g.alert_ref.strip_prefix("check:") {
        Some(c) => format!("--checks SOURCE --check-ids={}", sh_quote(c)),
        None => format!("--rules={}", g.rule_id),
    };
    let check = match i.source.as_str() {
        "passive" => format!("brainproxy findings retest {id}"),
        "active" if plain_get => format!("brainproxy scan active {} {what}", sh_quote(&i.url)),
        "active" => format!(
            "brainproxy scan active --history-id BASELINE --include-methods {} {what}  \
             # BASELINE: the history id of the original {} request, not the attack in this pack",
            sh_quote(&i.method),
            i.method
        ),
        "authz" => "brainproxy authz run (with the same identities)".to_string(),
        _ => "retest by hand, then `brainproxy findings mark` with a note".to_string(),
    };
    let oracle = match i.source.as_str() {
        "manual" => format!("Recorded by hand as \"{}\"; the tester's evidence is what to look for.", g.name),
        s => format!(
            "The {s} rule {} raises \"{}\" when it sees this{}.",
            g.alert_ref,
            g.name,
            if i.evidence.is_empty() {
                String::new()
            } else {
                format!(": the response contains {}", md_code(&i.evidence))
            }
        ),
    };
    Ok(json!({
        "finding": {
            "id": i.id, "issue_id": i.issue_id, "fingerprint": i.fingerprint, "alert_ref": g.alert_ref, "name": g.name,
            "risk": i.risk, "confidence": i.confidence, "state": i.state, "source": i.source,
            "method": i.method, "url": i.url, "param": i.param, "evidence": i.evidence, "attack": i.attack,
            "cvss": i.cvss,
        },
        "history_id": i.history_id,
        "latest_history_id": i.last_history_id,
        "request": i.request.as_ref().map(|r| http_text(r, None)),
        "curl": i.request.as_ref().map(curl),
        "response_excerpt": i.response.as_ref().and_then(|r| excerpt(r, &i.evidence)),
        "oracle": oracle,
        "check": check,
        "redacted": redact,
    }))
}

/// A finding written up for an issue tracker (github or jira): a title, a Markdown body with
/// what it is, where, how to fix and reproduce it, and its fingerprint; secrets masked.
pub fn ticket(store: &Store, id: i64, tracker: &str, target: Option<&str>) -> Result<Value> {
    let (g, i) = one_finding(store, id, true)?;
    let title = format!("[{}] {} on {}", risk_title(&i.risk), g.name, i.host);
    let mut body = String::new();
    let _ = writeln!(
        body,
        "**Risk:** {} · **Confidence:** {} · **State:** {}",
        risk_title(&i.risk),
        i.confidence,
        i.state.replace('_', " ")
    );
    if let Some(c) = &i.cvss {
        let _ = writeln!(body, "**CVSS 4.0:** {:.1} ({}) {}", c.score, c.severity, md_code(&c.vector));
    }
    let _ = writeln!(
        body,
        "\n**Where:** {}{}",
        // Quoted from the target: a backquote in it can't end the code span.
        md_code(&format!("{} {}", i.method, i.url)),
        if i.param.is_empty() { String::new() } else { format!(" (parameter {})", md_code(&i.param)) }
    );
    // The reviewed write-up, as the report has it (known secrets scrubbed).
    for n in g.narratives.iter().filter(|n| Some(n.issue_id) == i.issue_id) {
        let _ = writeln!(body, "\n{}\n\n_{}_", md_no_html(n.narrative.text.trim()), n.narrative.credit());
    }
    let prose = |t: &str| if is_manual(&g) { md_no_html(t.trim()) } else { t.trim().to_string() };
    if !g.description.trim().is_empty() {
        let _ = writeln!(body, "\n### What this means\n\n{}", prose(&g.description));
    }
    if !g.solution.trim().is_empty() {
        let _ = writeln!(body, "\n### How to fix it\n\n{}", prose(&g.solution));
    }
    if let Some(req) = &i.request {
        let _ = writeln!(body, "\n### How to reproduce\n\n{}", md_block(&curl(req), "sh"));
    }
    if !i.evidence.is_empty() {
        let _ = writeln!(body, "\n**Evidence:** {}", md_code(&i.evidence));
    }
    if !g.references.is_empty() {
        let _ = writeln!(body, "\n### References\n");
        for u in &g.references {
            let _ = writeln!(body, "- <{}>", u.replace(['<', '>', ' '], ""));
        }
    }
    let _ = writeln!(body, "\n---\nbrainproxy finding #{} · fingerprint `{}`", i.id, i.fingerprint);
    let labels = vec!["security".to_string(), format!("risk:{}", i.risk)];
    Ok(match tracker {
        "github" => {
            let repo = target.unwrap_or("OWNER/REPO");
            // The body comes from this command again, piped in. No --label: gh refuses a label
            // the repository doesn't have; `labels` lists them for whoever adds them.
            let command = format!(
                "brainproxy findings ticket {} --to github --repo {repo} --format json | jq -r .data.body \\\n  \
                 | gh issue create --repo {repo} --title {} --body-file -",
                i.id,
                sh_quote(&title),
                repo = sh_quote(repo)
            );
            json!({
                "tracker": "github",
                "title": title,
                "body": body,
                "labels": labels,
                "command": command,
            })
        }
        "jira" => {
            // The payload comes from this command again, piped in.
            let command = format!(
                "brainproxy findings ticket {} --to jira --key {} --format json | jq .data.payload \\\n  \
                 | curl -sS -u \"$JIRA_USER:$JIRA_TOKEN\" -H 'Content-Type: application/json' \\\n  \
                 -X POST \"$JIRA_URL/rest/api/2/issue\" --data @-",
                i.id,
                sh_quote(target.unwrap_or("KEY"))
            );
            json!({
                "tracker": "jira",
                "title": title,
                "body": body,
                "payload": {"fields": {
                    "project": {"key": target.unwrap_or("KEY")},
                    "summary": title,
                    "description": jira_noformat(&body),
                    "issuetype": {"name": "Bug"},
                    "labels": labels.iter().map(|l| l.replace(':', "-")).collect::<Vec<_>>(),
                }},
                "command": command,
            })
        }
        other => return Err(crate::error::Error::InvalidInput(format!("unknown tracker {other:?}: github or jira"))),
    })
}

/// Jira's REST v2 renders a description as wiki markup, where the Markdown's code spans protect
/// nothing: a response quoting `!https://host/p.png!` would embed that image. The body goes in a
/// `{noformat}` block instead, which Jira shows as it is; one inside it can't end the block.
fn jira_noformat(body: &str) -> String {
    let mut out = String::with_capacity(body.len() + 32);
    let mut rest = body;
    while let Some(at) = rest.find('{') {
        out.push_str(&rest[..=at]);
        rest = &rest[at + 1..];
        if rest.get(..8).is_some_and(|w| w.eq_ignore_ascii_case("noformat")) {
            out.push(' ');
        }
    }
    out.push_str(rest);
    format!("{{noformat}}\n{}\n{{noformat}}", out.trim_end())
}

/// The agent-trail line of a finding, in words.
fn trail_text(t: &TrailSummary) -> String {
    let span = match (t.first_history_id, t.last_history_id) {
        (Some(a), Some(b)) if a != b => format!(" (history #{a} to #{b})"),
        (Some(a), _) => format!(" (history #{a})"),
        _ => String::new(),
    };
    let review = match (&t.reviewed_by, &t.reviewed_at) {
        (Some(by), Some(at)) => format!("reviewed by a person {by} on {}", day(at)),
        _ => "not reviewed by a person since".to_string(),
    };
    format!(
        "an agent sent {} request{}{span} and made {} change{} to it; {review}",
        t.requests,
        if t.requests == 1 { "" } else { "s" },
        t.agent_changes,
        if t.agent_changes == 1 { "" } else { "s" }
    )
}

/// A write-up's heading line: "Write-up" or "Write-up for HOST", "(draft)" when unreviewed.
fn narrative_title(g: &AlertGroup, n: &IssueNarrative) -> String {
    let mut t = "Write-up".to_string();
    if g.narratives.len() > 1 {
        t.push_str(&format!(" for {}", n.host));
    }
    if !n.narrative.reviewed() {
        t.push_str(" (draft, not reviewed)");
    }
    t
}

/// A shell word in single quotes.
fn sh_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', "'\\''"))
}

/// A curl command that sends `req` again (as the report shows it: masked secrets stay masked).
fn curl(req: &HttpRequest) -> String {
    // A method token may hold | & $ and backquotes: it is quoted like everything else.
    // --globoff: [ ] { } in the URL (a masked "[redacted]") are text, not curl patterns;
    // --path-as-is: /a/../b is sent as recorded.
    // HEAD is -I: with -X HEAD curl waits for a body that never comes. --url: a URL is never
    // read as an option.
    let method = if req.method == "HEAD" { "-I".to_string() } else { format!("-X {}", sh_quote(&req.method)) };
    let mut out = format!("curl -sS --globoff --path-as-is {method} --url {}", sh_quote(&req.url));
    // Host goes as recorded, so a virtual host or Host header test reproduces.
    for (k, v) in &req.headers {
        if !k.eq_ignore_ascii_case("content-length") {
            // "X:" would make curl drop the header; "X;" sends it empty.
            let h = if v.is_empty() { format!("{k};") } else { format!("{k}: {v}") };
            out.push_str(&format!(" \\\n  -H {}", sh_quote(&h)));
        }
    }
    if req.body.binary {
        out.push_str(" \\\n  # the body is binary: send it from the request in history");
    } else if !req.body.text.is_empty() {
        out.push_str(&format!(" \\\n  --data-raw {}", sh_quote(&req.body.text)));
    }
    out
}

/// The posture section: open issues by risk, recent scans, retests.
fn html_posture(s: &mut String, p: &Value) {
    s.push_str("<h2>Posture</h2>\n<div class=\"cards\">");
    for risk in RISKS {
        let issues = p["open"]["issues"][risk].as_i64().unwrap_or(0);
        if risk == "critical" && issues == 0 {
            continue;
        }
        let instances = p["open"]["instances"][risk].as_i64().unwrap_or(0);
        let _ = write!(
            s,
            "<div class=\"card {risk}-edge\"><div class=\"num\">{issues}</div><div><span class=\"badge {risk}\">{}</span>\
             <p>open issue{} in {instances} place{}</p></div></div>",
            risk_title(risk),
            if issues == 1 { "" } else { "s" },
            if instances == 1 { "" } else { "s" }
        );
    }
    s.push_str("</div>\n");
    let state = |k: &str| p["by_state"][k].as_i64().unwrap_or(0);
    let retests = |k: &str| p["retests"][k].as_i64().unwrap_or(0);
    let _ = writeln!(
        s,
        "<p>{} fixed, {} accepted as a risk, {} awaiting a retest. Retests: {} not reproduced, {} still there. \
         {} came back after a fix.</p>",
        state("fixed"),
        state("accepted_risk"),
        state("retest_pending"),
        retests("not_reproduced"),
        retests("still_present"),
        p["regressed"].as_i64().unwrap_or(0)
    );
    let scans = p["scans"].as_array().map(Vec::as_slice).unwrap_or_default();
    if !scans.is_empty() {
        s.push_str(
            "<table><thead><tr><th>Scan</th><th>Finished</th><th class=\"n\">New</th><th class=\"n\">Still there</th>\
             <th class=\"n\">No longer found</th></tr></thead><tbody>",
        );
        for scan in scans.iter().rev().take(10) {
            let _ = write!(
                s,
                "<tr><td>#{}</td><td>{}</td><td class=\"n\">{}</td><td class=\"n\">{}</td><td class=\"n\">{}</td></tr>",
                scan["job"],
                esc(day(scan["finished"].as_str().unwrap_or(""))),
                scan["new"],
                scan["still"],
                scan["gone"]
            );
        }
        s.push_str("</tbody></table>\n");
    }
}

/// The retest section: what changed since a day, with the requests that show it.
fn html_retest(s: &mut String, l: &RetestLetter) {
    let _ = writeln!(
        s,
        "<h2>Retest since {}</h2><p><strong>{} fixed</strong>, {} still there, {} came back after a fix, \
         {} awaiting a retest.</p>",
        esc(&l.since),
        l.fixed.len(),
        l.still_present.len(),
        l.regressed.len(),
        l.pending.len()
    );
    for (title, rows) in [
        ("Fixed", &l.fixed),
        ("Still there", &l.still_present),
        ("Not reproduced, not marked fixed", &l.not_reproduced),
        ("Came back after a fix", &l.regressed),
        ("Awaiting a retest", &l.pending),
    ] {
        if rows.is_empty() {
            continue;
        }
        let _ = write!(
            s,
            "<h3>{title}</h3><table class=\"letter\"><thead><tr><th class=\"n\">#</th><th>Issue</th><th>Risk</th>\
             <th>Address</th><th>What happened</th><th>Proof</th></tr></thead><tbody>"
        );
        for row in rows {
            let _ = write!(
                s,
                "<tr><td class=\"n\">{}</td><td>{}</td><td><span class=\"badge {}\">{}</span></td><td><code>{} {}</code>{}</td>\
                 <td>{}</td><td>{}</td></tr>",
                row.id,
                esc(&row.name),
                esc(&row.risk),
                risk_title(&row.risk),
                esc(&row.method),
                esc(&row.url),
                if row.param.is_empty() { String::new() } else { format!(" <code>{}</code>", esc(&row.param)) },
                esc(&match (&row.event, &row.time) {
                    (Some(e), Some(t)) => format!("{e} on {}", day(t)),
                    _ => row.state.replace('_', " "),
                }),
                row.history_id.map(|h| format!("history #{h}")).unwrap_or_default()
            );
        }
        s.push_str("</tbody></table>\n");
    }
}

/// "2026-10-22" from an RFC 3339 time.
fn day(t: &str) -> &str {
    t.get(..10).unwrap_or(t)
}

// ---------- SARIF 2.1.0 ----------

fn sarif_level(risk: &str) -> &'static str {
    match risk {
        "critical" | "high" => "error",
        "medium" => "warning",
        "low" => "note",
        _ => "none",
    }
}

/// GitHub code scanning reads `security-severity` (0.0–10.0) to bucket alerts.
fn security_severity(risk: &str) -> &'static str {
    match risk {
        "critical" => "9.5",
        "high" => "8.0",
        "medium" => "5.5",
        "low" => "3.0",
        _ => "0.0",
    }
}

fn sarif_headers(h: &[(String, String)]) -> Value {
    let mut m = serde_json::Map::new();
    for (k, v) in h {
        match m.get_mut(k) {
            Some(Value::String(prev)) => {
                prev.push_str(", ");
                prev.push_str(v);
            }
            _ => {
                m.insert(k.clone(), json!(v));
            }
        }
    }
    Value::Object(m)
}

fn sarif_body(b: &Body) -> Value {
    let mut v = json!({"text": b.text});
    if b.truncated || b.binary {
        v["properties"] = json!({"length": b.length, "truncated": b.truncated, "binary": b.binary});
    }
    v
}

fn sarif(r: &Report) -> Value {
    let rules: Vec<Value> = r
        .alerts
        .iter()
        .map(|g| {
            let mut tags = vec!["security".to_string()];
            if let Some(c) = g.cwe {
                tags.push(format!("external/cwe/cwe-{c}"));
            }
            tags.extend(g.tags.iter().cloned());
            let mut rule = json!({
                "id": g.alert_ref,
                "name": g.name.split(|c: char| !c.is_alphanumeric()).filter(|w| !w.is_empty())
                    .map(|w| { let mut c = w.chars(); c.next().map(|f| f.to_uppercase().chain(c).collect::<String>()).unwrap_or_default() })
                    .collect::<String>(),
                "shortDescription": {"text": g.name},
                "fullDescription": {"text": if g.description.is_empty() { &g.name } else { &g.description }},
                "defaultConfiguration": {"level": sarif_level(&g.risk)},
                "properties": {
                    "tags": tags,
                    "security-severity": g.cvss.as_ref().map_or_else(|| security_severity(&g.risk).to_string(), |c| format!("{:.1}", c.score)),
                    "risk": g.risk,
                    "pluginId": g.rule_id,
                },
            });
            if !g.solution.is_empty() {
                // A tester's text may quote the target: plain text, fenced code apart.
                let markdown = if is_manual(g) { md_no_html(&g.solution) } else { g.solution.clone() };
                rule["help"] = json!({"text": g.solution, "markdown": markdown});
            }
            if let Some(u) = g.references.iter().find(|u| u.starts_with("http")) {
                rule["helpUri"] = json!(u);
            }
            if let Some(c) = g.cwe {
                rule["relationships"] = json!([{
                    "target": {"id": c.to_string(), "toolComponent": {"name": "CWE"}},
                    "kinds": ["superset"],
                }]);
            }
            rule
        })
        .collect();

    let mut results = Vec::new();
    for (idx, g) in r.alerts.iter().enumerate() {
        for inst in &g.instances {
            let mut msg = g.name.clone();
            if !inst.param.is_empty() {
                let _ = write!(msg, " (parameter: {})", inst.param);
            }
            if !inst.evidence.is_empty() {
                let ev: String = inst.evidence.chars().take(200).collect();
                let _ = write!(msg, ". Evidence: {ev}");
            }
            let mut res = json!({
                "ruleId": g.alert_ref,
                "ruleIndex": idx,
                "level": sarif_level(&inst.risk),
                "message": {"text": msg},
                "locations": [{"physicalLocation": {"artifactLocation": {"uri": inst.url.replace(crate::scan::redact::MASK, "%5Bredacted%5D")}}}],
                // The project's own dedup key, so a finding seen again with another query string
                // or session id in its path is the same result to code scanning, as it is to
                // brainproxy. v3 since the key dropped path parameters (v2 kept them).
                "partialFingerprints": {"brainproxy/v3": inst.fingerprint},
                "properties": {
                    "findingId": inst.id,
                    "source": inst.source,
                    "risk": inst.risk,
                    "confidence": inst.confidence,
                    "method": inst.method,
                    "param": inst.param,
                    "evidence": inst.evidence,
                    "attack": inst.attack,
                    "otherInfo": inst.other_info,
                    "hits": inst.hits,
                    "state": inst.state,
                    "historyId": inst.history_id,
                    "origin": inst.origin,
                    "originText": format!("added {}", provenance::describe(inst.origin.as_deref())),
                    "stateOrigin": inst.state_origin,
                    "stateChangedAt": inst.state_changed_at,
                    "stateText": inst.state_text,
                },
            });
            if !inst.history_ids.is_empty() {
                res["properties"]["historyIds"] = json!(inst.history_ids);
            }
            if let Some(c) = inst.cwe {
                res["properties"]["cwe"] = json!(c);
            }
            if let Some(c) = &inst.cvss {
                res["properties"]["cvssV4"] = json!({"vector": c.vector, "score": c.score, "severity": c.severity});
            }
            if let Some(n) = &inst.note {
                res["properties"]["note"] = json!(n);
                res["properties"]["noteOrigin"] = json!(inst.note_origin);
                res["properties"]["noteChangedAt"] = json!(inst.note_changed_at);
            }
            if let Some(b) = inst.baseline_state {
                res["baselineState"] = json!(b);
            }
            // Triaged as not to be fixed: code scanning shows it as dismissed, not open.
            if matches!(inst.state.as_str(), "false_positive" | "accepted_risk") {
                let mut s = json!({"kind": "external", "status": "accepted"});
                if let Some(n) = &inst.note {
                    s["justification"] = json!(n);
                }
                res["suppressions"] = json!([s]);
            }
            // Marked fixed (listed with --state all): a pass, not an open problem.
            if inst.state == "fixed" {
                res["kind"] = json!("pass");
                res["level"] = json!("none");
            }
            if let Some(l) = inst.latest_id() {
                res["properties"]["lastHistoryId"] = json!(l);
            }
            if let Some(t) = &inst.last_seen {
                res["properties"]["lastSeen"] = json!(t);
            }
            if let Some(req) = &inst.request {
                res["webRequest"] = json!({
                    "protocol": "HTTP",
                    "target": req.url,
                    "method": req.method,
                    "headers": sarif_headers(&req.headers),
                    "body": sarif_body(&req.body),
                });
            }
            if let Some(resp) = &inst.response {
                let mut w = json!({
                    "protocol": "HTTP",
                    "headers": sarif_headers(&resp.headers),
                    "body": sarif_body(&resp.body),
                });
                if let Some(code) = resp.status {
                    w["statusCode"] = json!(code);
                }
                if let Some(reason) = &resp.reason {
                    w["reasonPhrase"] = json!(reason);
                }
                res["webResponse"] = w;
            }
            results.push(res);
        }
    }

    json!({
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {
                "name": r.tool.name,
                "version": r.tool.version,
                "semanticVersion": r.tool.version,
                "informationUri": "https://github.com/r4nd0mth1ngs/brainproxy",
                "rules": rules,
            }},
            "automationDetails": {"id": format!("brainproxy/{}", r.generated)},
            "columnKind": "unicodeCodePoints",
            "results": results,
            "properties": {
                "summary": r.summary,
                "scope": r.scope,
                "filters": r.filters,
                "agentFalsePositives": r.agent_false_positives,
            },
        }],
    })
}

#[cfg(test)]
mod tests {
    #[test]
    fn a_jira_description_is_shown_as_it_is() {
        let d = super::jira_noformat("see !https://evil.test/p.png! {noFormat}[a|https://evil.test]");
        assert_eq!(d, "{noformat}\nsee !https://evil.test/p.png! { noFormat}[a|https://evil.test]\n{noformat}");
    }

    use super::*;
    use crate::capture::Capture;
    use crate::http::Target;
    use crate::scan::{passive, Risk};

    fn store_with_findings() -> Store {
        let mut s = Store::open_in_memory().unwrap();
        let target = Target { scheme: "http".into(), host: "app.test".into(), port: 80 };
        let req = b"GET /a?q=1 HTTP/1.1\r\nHost: app.test\r\n\r\n";
        let resp = b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nX-Powered-By: PHP/5.1\r\nContent-Length: 47\r\n\r\n<html><body><script>alert(1)</script>`x`</body>";
        let c = Capture::new("send", &target, req, Some(resp), Some(5), None);
        s.record(&c).unwrap();
        passive::scan_pending(&mut s).unwrap();
        s
    }

    #[test]
    fn builds_grouped_report_with_evidence() {
        let s = store_with_findings();
        let r = build(&s, &ReportOptions::default()).unwrap();
        assert!(r.summary.total > 0);
        assert_eq!(r.summary.total, r.summary.included);
        assert!(!r.summary.truncated);
        assert_eq!(r.summary.by_risk.iter().map(|c| c.count).sum::<usize>(), r.summary.total);
        let xpb = r.alerts.iter().find(|g| g.alert_ref == "10037").expect("X-Powered-By finding");
        assert!(!xpb.description.is_empty() && !xpb.solution.is_empty());
        let inst = &xpb.instances[0];
        let req = inst.request.as_ref().unwrap();
        assert_eq!(req.method, "GET");
        assert_eq!(inst.response.as_ref().unwrap().status, Some(200));
        // Sorted by risk: no group is riskier than the one before it.
        let lv = |r: &str| RISKS.iter().position(|x| *x == r).unwrap();
        assert!(r.alerts.windows(2).all(|w| lv(&w[0].risk) <= lv(&w[1].risk)));
    }

    #[test]
    fn secrets_are_masked_unless_asked_and_latest_sighting_kept() {
        let mut s = Store::open_in_memory().unwrap();
        let target = Target { scheme: "http".into(), host: "app.test".into(), port: 80 };
        let req = b"GET /a?q=1&access_token=QWERTY123456 HTTP/1.1\r\nHost: app.test\r\nCookie: sid=SESSION987654\r\nAuthorization: Bearer BEARERTOKEN42\r\n\r\n";
        let resp = b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nX-Powered-By: PHP/5.1\r\nSet-Cookie: sid=SESSION987654; Path=/\r\nContent-Length: 34\r\n\r\n<p>Welcome back SESSION987654</p>";
        for _ in 0..2 {
            s.record(&Capture::new("send", &target, req, Some(resp), Some(5), None)).unwrap();
        }
        passive::scan_pending(&mut s).unwrap();
        let secrets = ["QWERTY123456", "SESSION987654", "BEARERTOKEN42"];

        let r = build(&s, &ReportOptions::default()).unwrap();
        assert!(r.summary.redacted.unwrap() > 0);
        for kind in [ReportKind::Json, ReportKind::Markdown, ReportKind::Html, ReportKind::Sarif] {
            let out = render(&r, kind);
            for secret in secrets {
                assert!(!out.contains(secret), "{secret} in {}", kind.as_str());
            }
            assert!(out.contains("[redacted]"), "{}", kind.as_str());
        }
        let html = render(&r, ReportKind::Html);
        assert!(html.contains("Bearer [redacted]") && html.contains("sid=[redacted]") && html.contains("places."));

        // Seen in two history entries: the latest sighting is carried alongside the first.
        let xpb = r.alerts.iter().find(|g| g.alert_ref == "10037").unwrap();
        let inst = &xpb.instances[0];
        assert_eq!((inst.history_id, inst.last_history_id), (Some(1), Some(2)));
        assert_eq!(
            inst.latest.as_ref().unwrap().request.headers.iter().find(|(k, _)| k == "Cookie").unwrap().1,
            "sid=[redacted]"
        );
        assert!(render(&r, ReportKind::Markdown).contains("Latest sighting (history #2)"));
        // The SARIF fingerprint is the project's dedup key, hashed: no URL, so no secret in it.
        let sarif: Value = serde_json::from_str(&render(&r, ReportKind::Sarif)).unwrap();
        let res = sarif["runs"][0]["results"].as_array().unwrap().iter().find(|x| x["ruleId"] == "10037").unwrap();
        assert_eq!(res["partialFingerprints"]["brainproxy/v3"], fingerprint("10037", "GET", "http://app.test/a", ""));
        assert_eq!(res["partialFingerprints"]["brainproxy/v3"].as_str().unwrap().len(), 32);
        assert_eq!(res["properties"]["lastHistoryId"], 2);
        assert!(res.get("baselineState").is_none());

        let raw = build(&s, &ReportOptions { redact: false, ..Default::default() }).unwrap();
        assert_eq!(raw.summary.redacted, None);
        let out = render(&raw, ReportKind::Html);
        assert!(secrets.iter().all(|x| out.contains(x)) && out.contains("This report is not redacted"));

        // --no-evidence: nothing is read from history, and secrets are still masked by place.
        let bare = build(&s, &ReportOptions { evidence: false, ..Default::default() }).unwrap();
        let out = render(&bare, ReportKind::Json);
        assert!(bare.alerts.iter().flat_map(|g| &g.instances).all(|i| i.request.is_none() && i.latest.is_none()));
        assert!(secrets.iter().all(|x| !out.contains(x)));
    }

    #[test]
    fn known_secrets_baselines_and_hidden_findings() {
        let mut s = Store::open_in_memory().unwrap();
        let target = Target { scheme: "http".into(), host: "app.test".into(), port: 80 };
        // A custom header no rule knows, echoed in a page: the auth profile says it is secret.
        let req = b"GET /app;jsessionid=PATHSECRET99/a?token=QUERYSECRET1 HTTP/1.1\r\nHost: app.test\r\nX-Tenant-Auth: CUSTOMSECRET77\r\n\r\n";
        let resp = b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nX-Powered-By: PHP/5.1\r\nContent-Length: 24\r\n\r\n<p>key CUSTOMSECRET77</p>";
        s.record(&Capture::new("send", &target, req, Some(resp), Some(5), None)).unwrap();
        passive::scan_pending(&mut s).unwrap();
        let profile = crate::auth::AuthProfile {
            name: "tenant".into(),
            headers: vec![("X-Tenant-Auth".into(), "CUSTOMSECRET77".into())],
            ..Default::default()
        };
        s.auth_save_profile(&profile).unwrap();
        let manual = s.finding_add(&by_hand("Order IDOR", vec![1, 1])).unwrap();

        let id = |r: &Report, alert: &str| r.alerts.iter().find(|g| g.alert_ref == alert).unwrap().instances[0].id;
        let r = build(&s, &ReportOptions::default()).unwrap();
        let xpb = id(&r, "10037");
        let opts =
            ReportOptions { baseline: Some(std::collections::HashMap::from([(xpb, true)])), ..Default::default() };
        let r = build(&s, &opts).unwrap();
        for kind in [ReportKind::Json, ReportKind::Markdown, ReportKind::Html, ReportKind::Sarif] {
            let out = render(&r, kind);
            assert!(!out.contains("CUSTOMSECRET77") && !out.contains("QUERYSECRET1"), "{}", kind.as_str());
        }
        // A secret in the path stays out of the SARIF fingerprint.
        let sarif = render(&r, ReportKind::Sarif);
        assert!(!sarif.contains("PATHSECRET99"));
        // With a baseline (`--scan`), each result says whether it is new; without one, nothing.
        let v: Value = serde_json::from_str(&sarif).unwrap();
        let results = v["runs"][0]["results"].as_array().unwrap();
        assert!(results.iter().any(|x| x["ruleId"] == "10037" && x["baselineState"] == "new"));
        assert!(results.iter().filter(|x| x["ruleId"] != "10037").all(|x| x.get("baselineState").is_none()));
        // A finding added by hand lists its entries; none is a "latest sighting".
        let m = r.alerts.iter().flat_map(|g| &g.instances).find(|i| i.id == manual).unwrap();
        assert!(m.latest.is_none() && m.latest_id().is_none());

        // A false positive an agent marked is listed outside the findings, its URL masked too.
        s.conn
            .execute("UPDATE findings SET state = 'false_positive', state_origin = 'mcp' WHERE id = ?1", [xpb])
            .unwrap();
        let r = build(&s, &ReportOptions::default()).unwrap();
        let hidden = r.agent_false_positives.iter().find(|h| h.id == xpb).unwrap();
        assert!(hidden.url.contains("jsessionid=[redacted]") && !hidden.url.contains("PATHSECRET99"), "{}", hidden.url);

        // With every state, SARIF says which results were dismissed, and why.
        s.finding_mark(xpb, None, Some("Framework banner is public")).unwrap();
        let all = ReportOptions {
            filter: FindingFilter { state: Some("all".into()), ..Default::default() },
            ..Default::default()
        };
        let v: Value = serde_json::from_str(&render(&build(&s, &all).unwrap(), ReportKind::Sarif)).unwrap();
        let results = v["runs"][0]["results"].as_array().unwrap();
        let dismissed = results.iter().find(|x| x["ruleId"] == "10037").unwrap();
        assert_eq!(
            dismissed["suppressions"],
            json!([{"kind": "external", "status": "accepted", "justification": "Framework banner is public"}])
        );
        assert!(results.iter().filter(|x| x["ruleId"] != "10037").all(|x| x.get("suppressions").is_none()));
    }

    #[test]
    fn presets_branding_cvss_and_the_retest_letter() {
        use crate::scan::layout::{Layout, Preset};
        let mut s = store_with_findings();
        let xpb = s.findings_list(&FindingFilter { alert_ref: Some("10037".into()), ..Default::default() }, 1).unwrap()
            [0]["id"]
            .as_i64()
            .unwrap();
        let issue = s.finding_get(xpb).unwrap()["issue_id"].as_i64().unwrap();
        s.issue_set_cvss(issue, "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N").unwrap();
        let with = |s: &Store, layout: Layout| build(s, &ReportOptions { layout, ..Default::default() }).unwrap();

        // Technical, branded: everything, with the issue's CVSS and the brand on the cover.
        let brand = Layout {
            company: Some("Acme <Labs>".into()),
            accent: Some("#0a7cff".into()),
            logo: Some("data:image/png;base64,iVBORw0KGgo=".into()),
            ..Default::default()
        };
        let html = render(&with(&s, brand), ReportKind::Html);
        assert!(html.contains("Security assessment by Acme &lt;Labs&gt;") && html.contains("--brand:#0a7cff"));
        assert!(html.contains("<img class=\"logo\" alt=\"\" src=\"data:image/png;base64,iVBORw0KGgo=\">"));
        assert!(html.contains("CVSS 4.0 6.9</strong> (medium)") && html.contains("Technical details"));
        let sarif: Value = serde_json::from_str(&render(&with(&s, Layout::default()), ReportKind::Sarif)).unwrap();
        let rule = sarif["runs"][0]["tool"]["driver"]["rules"]
            .as_array()
            .unwrap()
            .iter()
            .find(|r| r["id"] == "10037")
            .unwrap()
            .clone();
        assert_eq!(rule["properties"]["security-severity"], "6.9");

        // Executive: the posture, no evidence or issue sections. Developer: curl, no summary.
        let exec = render(&with(&s, Layout { preset: Preset::Executive, ..Default::default() }), ReportKind::Html);
        assert!(exec.contains("<h2>Posture</h2>") && exec.contains("At a glance"));
        assert!(!exec.contains("Technical details") && !exec.contains("<section class=\"issue\">"));
        let dev = render(&with(&s, Layout { preset: Preset::Developer, ..Default::default() }), ReportKind::Html);
        let at = dev.find("How to reproduce").map(|i| &dev[i..(i + 300).min(dev.len())]);
        assert!(
            at.is_some_and(|a| a.contains("curl -sS --globoff --path-as-is -X ")) && !dev.contains("At a glance"),
            "{at:?}"
        );
        // Every part of a curl line is quoted for the shell, a method token included.
        let req = HttpRequest {
            method: "GET|id".into(),
            url: "http://a.test/it's".into(),
            headers: vec![("X-A".into(), "$(id)".into()), ("Host".into(), "a.test".into())],
            body: Body { text: "a'b".into(), length: 3, truncated: false, binary: false },
        };
        assert_eq!(
            curl(&req),
            "curl -sS --globoff --path-as-is -X 'GET|id' --url 'http://a.test/it'\\''s' \\\n  -H 'X-A: $(id)' \\\n  -H 'Host: a.test' \\\n  --data-raw 'a'\\''b'"
        );
        // HEAD is -I, and an empty header is sent empty rather than dropped.
        let head = HttpRequest {
            method: "HEAD".into(),
            url: "http://a.test/".into(),
            headers: vec![("X-Empty".into(), String::new())],
            body: Body { text: String::new(), length: 0, truncated: false, binary: false },
        };
        assert_eq!(curl(&head), "curl -sS --globoff --path-as-is -I --url 'http://a.test/' \\\n  -H 'X-Empty;'");
        let md = render(&with(&s, Layout { preset: Preset::Developer, ..Default::default() }), ReportKind::Markdown);
        assert!(md.contains("### How to reproduce") && !md.contains("## Summary"));

        // Retest letter: a fix since the day, and one waiting.
        s.finding_retested(xpb, crate::scan::issues::Retest::NotReproduced, Some(1), "GET /", true).unwrap();
        let other = s.findings_list(&FindingFilter::default(), 10).unwrap()[0]["id"].as_i64().unwrap();
        s.finding_mark(other, Some("retest_pending"), None).unwrap();
        let r = with(&s, Layout { preset: Preset::Retest, since: Some("2000-01-01".into()), ..Default::default() });
        let letter = r.retest.as_ref().unwrap();
        assert_eq!((letter.fixed.len(), letter.pending.len()), (1, 1));
        assert_eq!(letter.fixed[0].history_id, Some(1));
        let html = render(&r, ReportKind::Html);
        assert!(html.contains("Retest since 2000-01-01") && html.contains("retest: not reproduced on"));
        assert!(!html.contains("At a glance"));

        // A fix by hand after a retest that still saw it is "marked fixed", with no proof.
        s.finding_retested(xpb, crate::scan::issues::Retest::StillPresent, Some(1), "GET /", true).unwrap();
        s.finding_mark(xpb, Some("fixed"), None).unwrap();
        let r = with(&s, Layout { preset: Preset::Retest, since: Some("2000-01-01".into()), ..Default::default() });
        let fixed = &r.retest.as_ref().unwrap().fixed[0];
        assert_eq!((fixed.event.as_deref(), fixed.history_id), (Some("marked fixed"), None));
        // A retest that still sees it, recorded without marking, puts it under "still there".
        s.finding_retested(xpb, crate::scan::issues::Retest::StillPresent, Some(1), "GET /", false).unwrap();
        let r = with(&s, Layout { preset: Preset::Retest, since: Some("2000-01-01".into()), ..Default::default() });
        let letter = r.retest.as_ref().unwrap();
        assert_eq!((letter.fixed.len(), letter.still_present.len()), (0, 1));
        assert_eq!(letter.still_present[0].state, "fixed");
        // One not reproduced, recorded without marking, has its own list instead of none.
        s.finding_retested(other, crate::scan::issues::Retest::NotReproduced, Some(1), "GET /", false).unwrap();
        let r = with(&s, Layout { preset: Preset::Retest, since: Some("2000-01-01".into()), ..Default::default() });
        assert_eq!(r.retest.as_ref().unwrap().not_reproduced.len(), 1);
        assert!(render(&r, ReportKind::Markdown).contains("### Not reproduced, not marked fixed"));
        // The extra sections keep to the report's filters.
        let other_host = ReportOptions {
            filter: FindingFilter { host: Some("b.test".into()), ..Default::default() },
            ..Default::default()
        };
        let scoped = build(
            &s,
            &ReportOptions {
                layout: Layout { preset: Preset::Retest, since: Some("2000-01-01".into()), ..Default::default() },
                ..other_host.clone()
            },
        )
        .unwrap();
        let letter = scoped.retest.as_ref().unwrap();
        assert!(letter.fixed.is_empty() && letter.pending.is_empty());
        let posture = build(
            &s,
            &ReportOptions { layout: Layout { preset: Preset::Executive, ..Default::default() }, ..other_host },
        )
        .unwrap();
        assert_eq!(posture.posture.as_ref().unwrap()["open"]["instances"]["low"], 0);

        // Markdown has the executive sections; a developer report says it was cut short; the
        // print version opens its evidence.
        let md = render(&with(&s, Layout { preset: Preset::Executive, ..Default::default() }), ReportKind::Markdown);
        assert!(md.contains("## Posture") && md.contains("## Fix these first"), "{md}");
        let cut = build(
            &s,
            &ReportOptions {
                limit: 1,
                layout: Layout { preset: Preset::Developer, ..Default::default() },
                ..Default::default()
            },
        )
        .unwrap();
        assert!(render(&cut, ReportKind::Html).contains("This report shows 1 of"));
        let print = render_print_html(&with(&s, Layout::default()));
        assert!(
            print.contains("<details class=\"tech\" open>") && print.contains("@media print{.tech{display:block}}")
        );
    }

    #[test]
    fn the_retest_letter_masks_secrets_of_findings_the_report_leaves_out() {
        use crate::scan::layout::{Layout, Preset};
        let mut s = Store::open_in_memory().unwrap();
        let target = Target { scheme: "http".into(), host: "app.test".into(), port: 80 };
        let req = b"GET /LIVECOOKIE987654 HTTP/1.1\r\nHost: app.test\r\nCookie: sid=LIVECOOKIE987654\r\n\r\n";
        let resp = b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nX-Powered-By: PHP/5.1\r\nContent-Length: 0\r\n\r\n";
        s.record(&Capture::new("send", &target, req, Some(resp), Some(5), None)).unwrap();
        passive::scan_pending(&mut s).unwrap();
        let ids: Vec<i64> =
            s.findings_list(&FindingFilter::default(), 50).unwrap().iter().map(|f| f["id"].as_i64().unwrap()).collect();
        s.findings_mark(&ids, Some("fixed"), None).unwrap();
        // The fixed findings are out of the list (the default state), but in the letter.
        let opts = ReportOptions {
            layout: Layout { preset: Preset::Retest, since: Some("2000-01-01".into()), ..Default::default() },
            ..Default::default()
        };
        let r = build(&s, &opts).unwrap();
        assert!(r.alerts.is_empty() && !r.retest.as_ref().unwrap().fixed.is_empty());
        let json = render(&r, ReportKind::Json);
        assert!(!json.contains("LIVECOOKIE987654"), "{json}");
    }

    #[test]
    fn notes_are_masked_in_every_format() {
        let mut s = Store::open_in_memory().unwrap();
        let target = Target { scheme: "http".into(), host: "app.test".into(), port: 80 };
        let req = b"GET / HTTP/1.1\r\nHost: app.test\r\nCookie: sid=NOTECOOKIE5550\r\n\r\n";
        let resp = b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nX-Powered-By: PHP/5.1\r\nContent-Length: 0\r\n\r\n";
        s.record(&Capture::new("send", &target, req, Some(resp), Some(5), None)).unwrap();
        passive::scan_pending(&mut s).unwrap();
        let id = s.findings_list(&FindingFilter::default(), 1).unwrap()[0]["id"].as_i64().unwrap();
        s.finding_mark(id, None, Some("Replayed with sid=NOTECOOKIE5550 and it still works")).unwrap();
        let r = build(&s, &ReportOptions::default()).unwrap();
        for kind in [ReportKind::Csv, ReportKind::DefectDojo, ReportKind::Html, ReportKind::Sarif] {
            assert!(!render(&r, kind).contains("NOTECOOKIE5550"), "{}", kind.as_str());
        }
    }

    #[test]
    fn retest_rows_are_redacted_like_the_findings() {
        let row = |url: &str, param: &str| RetestRow {
            id: 1,
            name: "x".into(),
            risk: "low".into(),
            method: "GET".into(),
            url: url.into(),
            param: param.into(),
            state: "fixed".into(),
            event: None,
            time: None,
            history_id: None,
        };
        let mut letter = RetestLetter {
            fixed: vec![row("http://a.test/?access_token=LETTERSECRET9", "access_token=LETTERSECRET9")],
            ..Default::default()
        };
        let mut groups = vec![AlertGroup {
            alert_ref: "1".into(),
            rule_id: 1,
            name: "x".into(),
            risk: "low".into(),
            cwe: None,
            wasc: None,
            description: String::new(),
            solution: String::new(),
            references: vec![],
            tags: vec![],
            cvss: None,
            narratives: vec![],
            instances: vec![],
        }];
        let mut red = Redactor::default();
        redact_findings(&mut red, &mut groups, &mut [], Some(&mut letter), None);
        assert_eq!(letter.fixed[0].url, "http://a.test/?access_token=[redacted]");
        assert_eq!(letter.fixed[0].param, "access_token=[redacted]");
    }

    #[test]
    fn limit_and_filters() {
        let s = store_with_findings();
        let all = build(&s, &ReportOptions::default()).unwrap();
        let one = build(&s, &ReportOptions { limit: 1, evidence: false, ..Default::default() }).unwrap();
        assert_eq!(one.summary.included, 1);
        assert_eq!(one.summary.total, all.summary.total);
        assert_eq!(one.summary.truncated, all.summary.total > 1);
        assert!(one.alerts[0].instances[0].request.is_none());

        let mut filter = FindingFilter { min_risk: Some(Risk::High), ..Default::default() };
        let high = build(&s, &ReportOptions { filter: filter.clone(), ..Default::default() }).unwrap();
        assert!(high.alerts.iter().all(|g| g.risk == "high"));

        filter.min_risk = None;
        filter.min_confidence = Some(crate::scan::Confidence::High);
        let conf = build(&s, &ReportOptions { filter, ..Default::default() }).unwrap();
        assert!(conf.alerts.iter().flat_map(|g| &g.instances).all(|i| i.confidence == "high"));

        // False positives are hidden unless asked for.
        let id = all.alerts[0].instances[0].id;
        s.finding_mark(id, Some("false_positive"), None).unwrap();
        let after = build(&s, &ReportOptions::default()).unwrap();
        assert_eq!(after.summary.total, all.summary.total - 1);
        let fp = FindingFilter { state: Some("false_positive".into()), ..Default::default() };
        let fps = build(&s, &ReportOptions { filter: fp, ..Default::default() }).unwrap();
        assert_eq!(fps.summary.total, 1);
        assert!(build(&s, &ReportOptions { limit: 0, ..Default::default() }).is_err());
    }

    #[test]
    fn body_truncation_and_binary() {
        let b = Body::new("héllo".as_bytes(), 2);
        assert_eq!((b.text.as_str(), b.truncated, b.binary), ("h", true, false));
        let b = Body::new(&[0xff, 0xfe, 0x00], 10);
        assert!(b.binary && b.text.contains("3 bytes"));
    }

    #[test]
    fn markdown_code_cannot_be_escaped() {
        assert_eq!(md_code("a`b"), "``a`b``");
        assert_eq!(md_code("`x`"), "`` `x` ``");
        assert_eq!(md_code("a\nb"), "`a b`");
        let block = md_block("```\nevil\n```", "http");
        assert!(block.starts_with("````http\n") && block.ends_with("````\n"));
    }

    #[test]
    fn html_escapes_target_data_and_blocks_scripts() {
        let s = store_with_findings();
        let r = build(&s, &ReportOptions::default()).unwrap();
        let h = render(&r, ReportKind::Html);
        assert!(h.starts_with("<!doctype html>"));
        assert!(h.contains("default-src 'none'"));
        assert!(!h.contains("<script"), "target markup must be escaped");
        assert!(h.contains("&lt;script&gt;"));
        assert!(!h.contains("http://cdn") && !h.contains("<link"), "no external assets");
        assert_eq!(link("javascript:alert(1)", "x"), "x");
        // Plain-language parts first, technical details folded away.
        let glance = h.find("<h2>At a glance</h2>").unwrap();
        assert!(glance < h.find("What this means").unwrap() && h.contains("<details class=\"tech\">"));
        assert!(h.contains("class=\"verdict\"") && h.contains("About this report"));
        assert_eq!(first_sentence("Update PHP. Then restart."), "Update PHP.");
        assert_eq!(first_sentence("No full stop"), "No full stop");
        assert_eq!(first_sentence(&"é".repeat(300)).chars().count(), 240);
        assert_eq!(first_sentence("Use X.\nThen Y."), "Use X.");
        assert_eq!(first_sentence("Phase: Design\nUse a library. More."), "Use a library.");
        assert_eq!(
            first_sentence("Set it on the server, proxy, etc. so it applies."),
            "Set it on the server, proxy, etc. so it applies."
        );
    }

    #[test]
    fn markdown_lists_every_alert() {
        let s = store_with_findings();
        let r = build(&s, &ReportOptions::default()).unwrap();
        let md = render(&r, ReportKind::Markdown);
        assert!(md.starts_with("# brainproxy security report"));
        for g in &r.alerts {
            assert!(md.contains(&g.name), "{} missing", g.name);
        }
        assert!(md.contains("```http\nGET http://app.test/a?q=1"));
    }

    #[test]
    fn sarif_shape() {
        let s = store_with_findings();
        let r = build(&s, &ReportOptions::default()).unwrap();
        let v: Value = serde_json::from_str(&render(&r, ReportKind::Sarif)).unwrap();
        assert_eq!(v["version"], "2.1.0");
        let run = &v["runs"][0];
        let rules = run["tool"]["driver"]["rules"].as_array().unwrap();
        let results = run["results"].as_array().unwrap();
        assert_eq!(rules.len(), r.alerts.len());
        assert_eq!(results.len(), r.summary.included);
        for res in results {
            let idx = res["ruleIndex"].as_u64().unwrap() as usize;
            assert_eq!(rules[idx]["id"], res["ruleId"]);
            assert!(["error", "warning", "note", "none"].contains(&res["level"].as_str().unwrap()));
            assert!(res["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
                .as_str()
                .unwrap()
                .starts_with("http://app.test/"));
            assert_eq!(res["webResponse"]["statusCode"], 200);
        }
        let xpb = rules.iter().find(|r| r["id"] == "10037").unwrap();
        assert!(xpb["properties"]["tags"]
            .as_array()
            .unwrap()
            .iter()
            .any(|t| t.as_str().unwrap().starts_with("external/cwe/")));
    }

    #[test]
    fn findings_added_by_hand_in_every_format() {
        let mut s = store_with_findings();
        let target = Target { scheme: "http".into(), host: "app.test".into(), port: 80 };
        let entry = |path: &str| {
            let req = format!("GET {path} HTTP/1.1\r\nHost: app.test\r\n\r\n");
            s.record(&Capture::new("send", &target, req.as_bytes(), None, None, None)).unwrap()
        };
        let (second, third) = (entry("/b"), entry("/c"));
        let id = s
            .finding_add(&crate::scan::findings_db::ManualFinding {
                title: "Order IDOR".into(),
                risk: Risk::High,
                confidence: crate::scan::Confidence::High,
                url: Some("http://app.test/orders/7".into()),
                method: None,
                param: "id".into(),
                evidence: "another user's <order>".into(),
                description: "Any **user** can read <script>x</script> orders.".into(),
                solution: "Check the owner.".into(),
                cwe: Some(639),
                history: vec![1, second, third],
                replace_text: false,
            })
            .unwrap();
        s.finding_add(&crate::scan::findings_db::ManualFinding {
            title: "<img src=x> | note".into(),
            risk: Risk::Low,
            confidence: crate::scan::Confidence::Low,
            url: Some("http://app.test/".into()),
            method: None,
            param: String::new(),
            evidence: String::new(),
            description: String::new(),
            solution: String::new(),
            cwe: None,
            history: vec![],
            replace_text: false,
        })
        .unwrap();
        let r = build(&s, &ReportOptions::default()).unwrap();
        let g = r.alerts.iter().find(|g| g.alert_ref == "manual:order-idor").unwrap();
        assert_eq!((g.cwe, g.tags.clone()), (Some(639), vec!["manual".to_string()]));
        assert_eq!(g.solution, "Check the owner.");
        let inst = &g.instances[0];
        assert_eq!((inst.id, inst.source.as_str(), inst.history_ids.clone()), (id, "manual", vec![1, second, third]));
        // The first linked entry is the evidence.
        assert_eq!(inst.request.as_ref().unwrap().url, "http://app.test/a?q=1");

        let md = render(&r, ReportKind::Markdown);
        assert!(md.contains("Any \\*\\*user\\*\\* can read &lt;script&gt;x&lt;\\/script&gt; orders\\."), "{md}");
        assert!(md.contains(&format!("- History: #1, #{second}, #{third}")));
        let html = render(&r, ReportKind::Html);
        assert!(html.contains("found by hand") && !html.contains("<script>x"));
        assert!(html.contains("<code>another user&#39;s &lt;order&gt;</code>"));
        let sarif: Value = serde_json::from_str(&render(&r, ReportKind::Sarif)).unwrap();
        let results = sarif["runs"][0]["results"].as_array().unwrap();
        let res = results.iter().find(|x| x["ruleId"] == "manual:order-idor").unwrap();
        assert_eq!(res["properties"]["source"], "manual");
        assert_eq!(res["properties"]["historyIds"], json!([1, second, third]));
        let only = |source: &str| {
            let filter = FindingFilter { source: Some(source.into()), ..Default::default() };
            build(&s, &ReportOptions { filter, ..Default::default() }).unwrap().summary.total
        };
        assert_eq!(only("manual"), 2);
        assert_eq!(only("passive") + 2, r.summary.total);
        // A title is the tester's text: no raw HTML in Markdown either.
        assert!(md.contains("&lt;img src\\=x&gt; \\| note") && !md.contains("<img"), "{md}");
    }

    #[test]
    fn each_finding_added_by_hand_keeps_its_cwe() {
        let mut s = store_with_findings();
        // The first (high) has no CWE, the second (medium) has one.
        let mut f = by_hand("Order IDOR", vec![]);
        f.risk = Risk::High;
        s.finding_add(&f).unwrap();
        let mut f = by_hand("Order IDOR", vec![]);
        f.url = Some("http://app.test/y".into());
        f.cwe = Some(639);
        s.finding_add(&f).unwrap();
        // A third with another CWE says so itself.
        f.url = Some("http://app.test/z".into());
        f.cwe = Some(284);
        s.finding_add(&f).unwrap();
        let r = build(&s, &ReportOptions::default()).unwrap();
        let g = r.alerts.iter().find(|g| g.alert_ref == "manual:order-idor").unwrap();
        assert_eq!(g.cwe, Some(639));
        let cwes: Vec<Option<i64>> = g.instances.iter().map(|i| i.cwe).collect();
        assert_eq!(cwes, [None, None, Some(284)]);
        let md = render(&r, ReportKind::Markdown);
        assert!(md.contains("**CWE:** [639]") && md.contains("- CWE: [284]"), "{md}");
        let html = render(&r, ReportKind::Html);
        assert!(html.contains("<dt>CWE</dt><dd><a href=\"https://cwe.mitre.org/data/definitions/284.html\""));
        let sarif: Value = serde_json::from_str(&render(&r, ReportKind::Sarif)).unwrap();
        let rule = sarif["runs"][0]["tool"]["driver"]["rules"]
            .as_array()
            .unwrap()
            .iter()
            .find(|r| r["id"] == "manual:order-idor")
            .unwrap()
            .clone();
        assert!(rule["properties"]["tags"].as_array().unwrap().contains(&json!("external/cwe/cwe-639")), "{rule}");
        assert_eq!(rule["relationships"][0]["target"]["id"], "639");
        let results = sarif["runs"][0]["results"].as_array().unwrap();
        let own: Vec<&Value> = results.iter().filter_map(|x| x["properties"].get("cwe")).collect();
        assert_eq!(own, [&json!(284)]);
        // Scanner instances never carry their own.
        let json: Value = serde_json::from_str(&render(&r, ReportKind::Json)).unwrap();
        for g in json["alerts"].as_array().unwrap().iter().filter(|g| g["alert_ref"] != "manual:order-idor") {
            assert!(g["instances"].as_array().unwrap().iter().all(|i| i.get("cwe").is_none()), "{g}");
        }
    }

    #[test]
    fn a_tester_solution_is_no_raw_html_in_sarif_markdown() {
        let mut s = store_with_findings();
        let mut f = by_hand("Order IDOR", vec![]);
        f.solution = "Check the owner. <img src=x onerror=alert(1)> ![p](https://attacker.test/p?d=1)".into();
        f.description = "See [here](https://attacker.test/) and \\[x](https://attacker.test/b).".into();
        s.finding_add(&f).unwrap();
        let r = build(&s, &ReportOptions::default()).unwrap();
        let sarif: Value = serde_json::from_str(&render(&r, ReportKind::Sarif)).unwrap();
        let rule = sarif["runs"][0]["tool"]["driver"]["rules"]
            .as_array()
            .unwrap()
            .iter()
            .find(|r| r["id"] == "manual:order-idor")
            .unwrap()
            .clone();
        let help = rule["help"]["markdown"].as_str().unwrap();
        assert_inert(help);
        assert!(help.contains("&lt;img src\\=x onerror\\=alert\\(1\\)&gt;"), "{help}");
        assert!(help.contains("\\!\\[p\\]\\(https\\:\\/\\/attacker\\.test\\/p\\?d\\=1\\)"), "{help}");
        // The plain text stays as written.
        assert!(rule["help"]["text"].as_str().unwrap().contains("<img src=x"));
        // The Markdown report has no link or image either, even after a backslash.
        let md = render(&r, ReportKind::Markdown);
        assert!(md.contains("See \\[here\\]\\(https\\:\\/\\/attacker\\.test\\/\\)"), "{md}");
        assert!(md.contains("and \\\\\\[x\\]\\(https\\:\\/\\/attacker\\.test\\/b\\)\\."), "{md}");
        assert!(!md.contains("![p]("), "{md}");
        assert_eq!(md_no_html("![x](http://e/)"), "\\!\\[x\\]\\(http\\:\\/\\/e\\/\\)");
    }

    #[test]
    fn a_tester_fence_is_kept_as_written() {
        let mut s = store_with_findings();
        let mut f = by_hand("Order IDOR", vec![]);
        f.description = "Send `GET /orders?ids[]=1&a=2` as <b>bob</b>:\n\n  ```http\n  POST /x?a[0]=<script> HTTP/1.1\n  \\[y](https://attacker.test/)\n  ```\nDone.".into();
        f.solution = "Use ``a`b`` and `<i>` but not ` <img src=x>.\n~~~\n```\n<img src=x>\n".into();
        s.finding_add(&f).unwrap();
        let r = build(&s, &ReportOptions::default()).unwrap();
        let md = render(&r, ReportKind::Markdown);
        // A fence keeps its text, in a fence of ours; a code span around it is text.
        assert!(
            md.contains("Send \\`GET \\/orders\\?ids\\[\\]\\=1&amp;a\\=2\\` as &lt;b&gt;bob&lt;\\/b&gt;\\:"),
            "{md}"
        );
        assert!(
            md.contains("\n```http\nPOST /x?a[0]=<script> HTTP/1.1\n\\[y](https://attacker.test/)\n```\nDone\\."),
            "{md}"
        );
        // An unclosed fence is closed in our own, longer than any backtick run inside it.
        assert!(
            md.contains("Use \\`\\`a\\`b\\`\\` and \\`&lt;i&gt;\\` but not \\` &lt;img src\\=x&gt;\\.\n````\n```\n<img src=x>\n````\n"),
            "{md}"
        );
        let sarif: Value = serde_json::from_str(&render(&r, ReportKind::Sarif)).unwrap();
        let rule = sarif["runs"][0]["tool"]["driver"]["rules"]
            .as_array()
            .unwrap()
            .iter()
            .find(|r| r["id"] == "manual:order-idor")
            .unwrap()
            .clone();
        assert_eq!(rule["help"]["markdown"], md_no_html(f.solution.trim()));
        // The HTML report escapes the same text its own way: no backslashes, no fences.
        let html = render(&r, ReportKind::Html);
        assert!(html.contains("Use ``a`b`` and `&lt;i&gt;` but not ` &lt;img src=x&gt;.<br>~~~<br>```"), "{html}");
        assert!(!html.contains("\\`") && !html.contains("<img"), "{html}");
    }

    #[test]
    fn spans_tables_and_pipes_are_text() {
        // Backtick runs that would pair across lines into a span hiding HTML.
        let t = md_no_html("`x``y` |\n``<img src=x onerror=alert(1)>`z``");
        assert_eq!(t, "\\`x\\`\\`y\\` \\|\n\\`\\`&lt;img src\\=x onerror\\=alert\\(1\\)&gt;\\`z\\`\\`");
        // A line of only U+00A0 is no blank line, but there's no table to keep going.
        let t = md_no_html("| a |\n|---|\n\u{a0}\n| `x|<img src=x onerror=alert(1)>` |");
        assert_inert(&t);
        assert!(t.starts_with("\\| a \\|\n\\|\\-\\-\\-\\|\n\u{a0}\n\\| \\`x\\|&lt;img"), "{t}");
        let t = md_no_html("| a | b |\n|---|---|\n| `x|<b>` | `<i>` |");
        assert_eq!(t, "\\| a \\| b \\|\n\\|\\-\\-\\-\\|\\-\\-\\-\\|\n\\| \\`x\\|&lt;b&gt;\\` \\| \\`&lt;i&gt;\\` \\|");
        assert_eq!(md_no_html("Try `x|<img src=x>` here."), "Try \\`x\\|&lt;img src\\=x&gt;\\` here\\.");
        assert_eq!(md_no_html("After `<c>` and **b**_i_"), "After \\`&lt;c&gt;\\` and \\*\\*b\\*\\*\\_i\\_");
        // Leading blanks come off, so no indented code block; entities can't be smuggled in.
        assert_eq!(md_no_html("a\n\n    &lt;b&gt;\n\t1. x"), "a\n\n&amp;lt\\;b&amp;gt\\;\n1\\. x");
        for t in ["`x``y` |\n``<img src=x onerror=alert(1)>`z``", "| `x|<img src=x>` |", "<a href=x>\r<b>"] {
            assert_inert(&md_no_html(t));
        }
    }

    #[test]
    fn a_fence_closes_only_as_commonmark_allows() {
        // Four spaces of indent, a shorter run, the other character or text after: content.
        let s = "````\n    ````\n```\n~~~~\n```` x\n   `````  \n<b>after</b>";
        assert_eq!(md_no_html(s), "`````\n    ````\n```\n~~~~\n```` x\n`````\n&lt;b&gt;after&lt;\\/b&gt;");
        let s = "  ~~~\n      ~~~\n  x\n\t~~~\n ~~~\nok";
        assert_eq!(md_no_html(s), "```\n    ~~~\nx\n\t~~~\n```\nok");
        // A closer may have up to three spaces of indent, whatever the opener's.
        let s = "```\nx\n    ```\n<img src=x onerror=alert(1)>\n```\nok";
        assert_eq!(md_no_html(s), "````\nx\n    ```\n<img src=x onerror=alert(1)>\n````\nok");
        let s = "  ```\nx\n     ```\n<img src=x>\n```";
        assert_eq!(md_no_html(s), "````\nx\n   ```\n<img src=x>\n````");
        // Our fence is longer than any backtick run inside, and the info string is a plain name.
        assert_eq!(md_no_html("```js\na ````` b\n```"), "``````js\na ````` b\n``````");
        assert_eq!(md_no_html("~~~ <b>x\n<i>\n~~~"), "```\n<i>\n```");
        // A fence in a list item, four spaces in, is text like the rest.
        let s = "- step:\n    ```\n    <b>y</b>\n    ```";
        assert_eq!(md_no_html(s), "\\- step\\:\n\\`\\`\\`\n&lt;b&gt;y&lt;\\/b&gt;\n\\`\\`\\`");
    }

    #[test]
    fn an_unclosed_fence_keeps_what_follows_as_code() {
        // Whatever follows a fence that never closes is literal code in a block of ours, closed
        // by a fence longer than any run inside it, so none of it is read as HTML.
        let s = "Repro:\n  ```\n  x\n      ```\n\n<img src=x onerror=alert(1)>\n````` x";
        let t = md_no_html(s);
        assert_eq!(t, "Repro\\:\n``````\nx\n    ```\n\n<img src=x onerror=alert(1)>\n````` x\n``````");
        assert_inert(&t);
    }

    /// Outside our own fences (a backtick run at column 0, closed by the same run alone), no
    /// ASCII punctuation is left but backslash escapes and the `&amp;`, `&lt;` and `&gt;` entities.
    fn assert_inert(md: &str) {
        let mut fence: Option<&str> = None;
        for line in md.lines() {
            if let Some(f) = fence {
                if line == f {
                    fence = None;
                }
                continue;
            }
            let run = line.len() - line.trim_start_matches('`').len();
            if run >= 3 {
                fence = Some(&line[..run]);
                continue;
            }
            let rest = line.replace("&amp;", "").replace("&lt;", "").replace("&gt;", "");
            let mut chars = rest.chars();
            while let Some(c) = chars.next() {
                if c == '\\' {
                    assert!(chars.next().is_some_and(|e| e.is_ascii_punctuation()), "{md}");
                } else {
                    assert!(!c.is_ascii_punctuation(), "raw {c:?} in {md}");
                }
            }
        }
    }

    fn by_hand(title: &str, history: Vec<i64>) -> crate::scan::findings_db::ManualFinding {
        crate::scan::findings_db::ManualFinding {
            title: title.into(),
            risk: Risk::Medium,
            confidence: crate::scan::Confidence::Medium,
            url: Some("http://app.test/x".into()),
            method: None,
            param: String::new(),
            evidence: String::new(),
            description: String::new(),
            solution: String::new(),
            cwe: None,
            history,
            replace_text: false,
        }
    }

    #[test]
    fn scanner_only_reports_are_unchanged() {
        let r = build(&store_with_findings(), &ReportOptions::default()).unwrap();
        // No manual note in About, and no history_ids key on scanner instances.
        assert!(!render(&r, ReportKind::Html).contains("found by hand"));
        let json: Value = serde_json::from_str(&render(&r, ReportKind::Json)).unwrap();
        let insts = json["alerts"].as_array().unwrap().iter().flat_map(|g| g["instances"].as_array().unwrap().clone());
        assert!(insts.into_iter().all(|i| i.get("history_ids").is_none()));
        assert!(!render(&r, ReportKind::Markdown).contains("- History:"));
        let sarif: Value = serde_json::from_str(&render(&r, ReportKind::Sarif)).unwrap();
        assert!(sarif["runs"][0]["results"]
            .as_array()
            .unwrap()
            .iter()
            .all(|x| x["properties"].get("historyIds").is_none()));
    }

    #[test]
    fn a_tester_title_cannot_break_out_of_its_place() {
        let mut s = store_with_findings();
        s.finding_add(&by_hand("Broken\n## Fake heading <b>x</b>", vec![1])).unwrap();
        let r = build(&s, &ReportOptions::default()).unwrap();
        let md = render(&r, ReportKind::Markdown);
        assert!(!md.lines().any(|l| l.starts_with("## Fake")), "{md}");
        assert!(md.contains("Broken \\#\\# Fake heading &lt;b&gt;x&lt;\\/b&gt;"), "{md}");
        // One linked entry is the evidence; no History line or row for it.
        assert!(!md.contains("- History:"), "{md}");
        let html = render(&r, ReportKind::Html);
        assert!(!html.contains("<b>x</b>") && html.contains("&lt;b&gt;x&lt;/b&gt;"));
        assert!(html.contains("found by hand") && !html.contains("<dt>History</dt>"));
        let json: Value = serde_json::from_str(&render(&r, ReportKind::Json)).unwrap();
        let g = json["alerts"]
            .as_array()
            .unwrap()
            .iter()
            .find(|g| g["alert_ref"] == "manual:broken-fake-heading-b-x-b")
            .unwrap();
        assert_eq!(g["instances"][0]["history_ids"], json!([1]));
        assert_eq!(g["instances"][0]["source"], "manual");
    }

    #[test]
    fn a_removed_finding_is_left_out_unless_asked_for() {
        let mut s = store_with_findings();
        let id = s.finding_add(&by_hand("Order IDOR", vec![1])).unwrap();
        // The About note doesn't say who recorded it: a person or an agent.
        let html = render(&build(&s, &ReportOptions::default()).unwrap(), ReportKind::Html);
        assert!(html.contains("recorded during manual testing") && !html.contains("written up by the tester"));
        s.findings_remove(&[id]).unwrap();
        let r = build(&s, &ReportOptions::default()).unwrap();
        assert!(r.alerts.iter().all(|g| g.alert_ref != "manual:order-idor"));
        assert!(!render(&r, ReportKind::Html).contains("found by hand"));
        let all = ReportOptions {
            filter: FindingFilter { state: Some("all".into()), ..Default::default() },
            ..Default::default()
        };
        let r = build(&s, &all).unwrap();
        let g = r.alerts.iter().find(|g| g.alert_ref == "manual:order-idor").unwrap();
        assert_eq!(g.instances[0].state, "removed");
        assert!(render(&r, ReportKind::Html).contains("<span class=\"tag\">removed from the command line</span>"));
    }

    #[test]
    fn a_merged_issue_s_write_up_names_every_host() {
        let mut s = Store::open_in_memory().unwrap();
        let resp = b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nX-Powered-By: PHP/5.1\r\nContent-Length: 0\r\n\r\n";
        for host in ["a.test", "b.test"] {
            let target = Target { scheme: "http".into(), host: host.into(), port: 80 };
            let req = format!("GET / HTTP/1.1\r\nHost: {host}\r\n\r\n");
            s.record(&Capture::new("send", &target, req.as_bytes(), Some(resp), None, None)).unwrap();
        }
        passive::scan_pending(&mut s).unwrap();
        let filter = FindingFilter { alert_ref: Some("10037".into()), ..Default::default() };
        let issues = s.issues_list(&filter, 10).unwrap();
        let id = |host: &str| issues.iter().find(|i| i["host"] == host).unwrap()["id"].as_i64().unwrap();
        let (a, b) = (id("a.test"), id("b.test"));
        s.issues_merge(a, &[b]).unwrap();
        s.issue_set_narrative(a, "PHP's version is in every reply.").unwrap();
        let r = build(&s, &ReportOptions { filter, drafts: true, ..Default::default() }).unwrap();
        let g = r.alerts.iter().find(|g| g.alert_ref == "10037").unwrap();
        assert_eq!(g.narratives.len(), 1);
        assert_eq!(g.narratives[0].host, "a.test, b.test");
    }
}
