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
use crate::scan::findings_db::FindingFilter;
use crate::store::Store;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReportKind {
    Json,
    Markdown,
    Html,
    Sarif,
}

impl ReportKind {
    pub fn as_str(self) -> &'static str {
        match self {
            ReportKind::Json => "json",
            ReportKind::Markdown => "markdown",
            ReportKind::Html => "html",
            ReportKind::Sarif => "sarif",
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
}

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
    pub instances: Vec<Instance>,
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
    pub request: Option<HttpRequest>,
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

const RISKS: [&str; 4] = ["high", "medium", "low", "info"];

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
            coalesce(t.description, ''), coalesce(t.solution, ''), coalesce(t.refs, '[]'), coalesce(t.tags, '[]')
         FROM (SELECT * FROM findings WHERE {where_sql}) f LEFT JOIN finding_types t ON t.alert_ref = f.alert_ref
         ORDER BY f.risk_level DESC, f.alert_ref, f.id LIMIT {}",
        opts.limit
    );
    let mut groups: Vec<AlertGroup> = Vec::new();
    let mut stmt = conn.prepare(&sql)?;
    let mut rows = stmt.query(rusqlite::params_from_iter(args.iter()))?;
    let mut included = 0;
    while let Some(r) = rows.next()? {
        included += 1;
        let inst = Instance {
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
            state: r.get(13)?,
            note: r.get(14)?,
            history_id: r.get(15)?,
            request: None,
            response: None,
        };
        let alert_ref: String = r.get(16)?;
        // Rows are sorted by risk, so the first instance of a type carries its highest risk.
        match groups.iter_mut().find(|g| g.alert_ref == alert_ref) {
            Some(g) => g.instances.push(inst),
            None => {
                let list = |s: String| serde_json::from_str::<Vec<String>>(&s).unwrap_or_default();
                groups.push(AlertGroup {
                    alert_ref,
                    rule_id: r.get(17)?,
                    name: r.get(18)?,
                    risk: inst.risk.clone(),
                    cwe: r.get::<_, Option<i64>>(19)?.filter(|&c| c > 0),
                    wasc: r.get::<_, Option<i64>>(20)?.filter(|&w| w > 0),
                    description: r.get(21)?,
                    solution: r.get(22)?,
                    references: list(r.get(23)?),
                    tags: list(r.get(24)?),
                    instances: vec![inst],
                })
            }
        }
    }
    drop(rows);
    drop(stmt);

    if opts.evidence {
        for inst in groups.iter_mut().flat_map(|g| g.instances.iter_mut()) {
            if let Some(hid) = inst.history_id {
                if let Some((req, resp)) = evidence(store, hid, opts.max_evidence)? {
                    inst.request = Some(req);
                    inst.response = resp;
                }
            }
        }
    }

    let generated: String = conn.query_row("SELECT strftime('%Y-%m-%dT%H:%M:%SZ','now')", [], |r| r.get(0))?;
    let f = &opts.filter;
    let mut filters = json!({
        "min_risk": f.min_risk.map(|r| r.as_str()),
        "min_confidence": f.min_confidence.map(|c| c.as_str()),
        "host": f.host,
        "alert": f.alert_ref,
        "state": f.state.clone().unwrap_or_else(|| "open,confirmed".into()),
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
        summary: Summary { total, included, truncated: included < total, alert_types: groups.len(), by_risk },
        alerts: groups,
    })
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
pub fn render(report: &Report, kind: ReportKind) -> String {
    match kind {
        ReportKind::Json => serde_json::to_string_pretty(report).unwrap_or_default() + "\n",
        ReportKind::Markdown => markdown(report),
        ReportKind::Html => html(report),
        ReportKind::Sarif => serde_json::to_string_pretty(&sarif(report)).unwrap_or_default() + "\n",
    }
}

fn risk_title(risk: &str) -> &'static str {
    match risk {
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

/// Text from our own rule definitions; only table pipes and line breaks need care.
fn md_text(s: &str) -> String {
    s.replace('|', "\\|").replace(['\r', '\n'], " ")
}

fn markdown(r: &Report) -> String {
    let mut s = String::new();
    let _ = writeln!(s, "# {}\n", md_text(&r.title));
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
    s.push_str("## Summary\n\n| Risk | Findings |\n|---|---:|\n");
    for rc in &r.summary.by_risk {
        let _ = writeln!(s, "| {} | {} |", risk_title(&rc.risk), rc.count);
    }
    let _ = writeln!(s, "| **Total** | **{}** |\n", r.summary.total);
    if r.summary.truncated {
        let _ = writeln!(
            s,
            "> Showing {} of {} findings (raise `--limit` to include more).\n",
            r.summary.included, r.summary.total
        );
    }
    if r.alerts.is_empty() {
        s.push_str("No findings match the filters.\n");
        return s;
    }
    s.push_str("| # | Risk | Alert | Instances |\n|---:|---|---|---:|\n");
    for (i, g) in r.alerts.iter().enumerate() {
        let _ = writeln!(s, "| {} | {} | {} | {} |", i + 1, risk_title(&g.risk), md_text(&g.name), g.instances.len());
    }
    s.push('\n');
    for (i, g) in r.alerts.iter().enumerate() {
        let _ = writeln!(s, "## {}. {} ({})\n", i + 1, md_text(&g.name), risk_title(&g.risk));
        let mut meta = vec![format!("**Alert:** `{}`", g.alert_ref)];
        if let Some(c) = g.cwe {
            meta.push(format!("**CWE:** [{c}]({})", cwe_url(c)));
        }
        if let Some(w) = g.wasc {
            meta.push(format!("**WASC:** {w}"));
        }
        let _ = writeln!(s, "{}\n", meta.join(" · "));
        if !g.description.is_empty() {
            let _ = writeln!(s, "### Description\n\n{}\n", g.description.trim());
        }
        if !g.solution.is_empty() {
            let _ = writeln!(s, "### Solution\n\n{}\n", g.solution.trim());
        }
        if !g.references.is_empty() {
            s.push_str("### References\n\n");
            for u in &g.references {
                let _ = writeln!(s, "- <{}>", u.replace(['<', '>', ' '], ""));
            }
            s.push('\n');
        }
        let _ = writeln!(s, "### Instances ({})\n", g.instances.len());
        for inst in &g.instances {
            let _ = writeln!(s, "#### {} {}\n", inst.method, md_code(&inst.url));
            let _ = writeln!(
                s,
                "- Finding #{} · {} · confidence {} · {} · seen {}×",
                inst.id, inst.source, inst.confidence, inst.state, inst.hits
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
                let _ = writeln!(s, "- Note: {}", md_code(n));
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
        }
    }
    s
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
--high:#c62828;--medium:#d9730d;--low:#b59a00;--info:#3d6fb6}
@media (prefers-color-scheme:dark){:root{--bg:#16181c;--fg:#e4e6ea;--muted:#9aa0aa;--line:#2e323a;
--card:#1e2126;--code:#262a31;--high:#ef5350;--medium:#f0953e;--low:#d8c13c;--info:#6c9be0}}
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
.high{background:var(--high)}.medium{background:var(--medium)}.low{background:var(--low)}.info{background:var(--info)}
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
.high-edge{border-left-color:var(--high)}.medium-edge{border-left-color:var(--medium)}.low-edge{border-left-color:var(--low)}.info-edge{border-left-color:var(--info)}
.fixfirst li{margin:6px 0}
.tag{display:inline-block;padding:0 6px;border:1px solid var(--line);border-radius:4px;font-size:.8em}
.tech{margin:12px 0;border:1px solid var(--line);border-radius:8px;padding:6px 12px}
@media print{body{font-size:11pt;background:#fff;color:#000}main{max-width:none;padding:0}a{color:inherit;text-decoration:none}
.card,.inst,tr{break-inside:avoid}h2,h3{break-after:avoid}.tech{display:none}}
"#;

/// What a risk level means, in plain words, for the report's readers.
fn risk_meaning(risk: &str) -> &'static str {
    match risk {
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
         <title>{}</title><style>{CSS}</style></head><body><main>\n",
        esc(&r.title)
    );
    let count = |risk: &str| r.summary.by_risk.iter().find(|c| c.risk == risk).map_or(0, |c| c.count);
    let instances = || r.alerts.iter().flat_map(|g| &g.instances);
    let mut hosts: Vec<&str> = instances().map(|i| i.host.as_str()).collect();
    hosts.sort_unstable();
    hosts.dedup();
    let first = instances().map(|i| i.time.as_str()).min();
    let last = instances().map(|i| i.time.as_str()).max();

    let _ = writeln!(
        s,
        "<header class=\"cover\"><div class=\"kicker\">Security assessment</div><h1>{}</h1>",
        esc(&r.title)
    );
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
    s.push_str("<h2>At a glance</h2>\n");
    let (high, medium) = (count("high"), count("medium"));
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
    s.push_str("<div class=\"cards\">");
    for risk in RISKS {
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
    if r.summary.truncated {
        let _ = writeln!(
            s,
            "<p class=\"note\">This report shows {} of {} findings (raise <code>--limit</code> to include more).</p>",
            r.summary.included, r.summary.total
        );
    }
    let urgent: Vec<(usize, &AlertGroup)> =
        r.alerts.iter().enumerate().filter(|(_, g)| g.risk == "high" || g.risk == "medium").take(10).collect();
    if !urgent.is_empty() {
        s.push_str("<h3>Fix these first</h3><ol class=\"fixfirst\">");
        for (i, g) in urgent {
            let n = g.instances.len();
            let _ = write!(
                s,
                "<li><a href=\"#a{}\">{}</a> <span class=\"badge {}\">{}</span> \
                 <span class=\"muted\">· {n} place{}</span><br>{}</li>",
                i + 1,
                esc(&g.name),
                g.risk,
                risk_title(&g.risk),
                if n == 1 { "" } else { "s" },
                esc(first_sentence(&g.solution))
            );
        }
        s.push_str("</ol>\n");
    }

    // ---- All issues, most serious first.
    if !r.alerts.is_empty() {
        s.push_str("<h2>All issues</h2>\n<table><thead><tr><th class=\"n\">#</th><th>Issue</th><th>Risk</th><th class=\"n\">Places</th></tr></thead><tbody>\n");
        for (i, g) in r.alerts.iter().enumerate() {
            let _ = writeln!(
                s,
                "<tr><td class=\"n\">{}</td><td><a href=\"#a{}\">{}</a></td><td><span class=\"badge {}\">{}</span></td><td class=\"n\">{}</td></tr>",
                i + 1,
                i + 1,
                esc(&g.name),
                g.risk,
                risk_title(&g.risk),
                g.instances.len()
            );
        }
        s.push_str("</tbody></table>\n");
    }
    for (i, g) in r.alerts.iter().enumerate() {
        let _ = writeln!(
            s,
            "<section class=\"issue\"><h2 id=\"a{}\">{}. {} <span class=\"badge {}\">{}</span></h2>",
            i + 1,
            i + 1,
            esc(&g.name),
            g.risk,
            risk_title(&g.risk)
        );
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
            let state = match inst.state.as_str() {
                "confirmed" => " <span class=\"tag\">confirmed</span>",
                _ => "",
            };
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
            for (k, v) in [("Parameter", &inst.param), ("Evidence", &inst.evidence), ("Attack", &inst.attack)] {
                if !v.is_empty() {
                    row(k, format!("<code>{}</code>", esc(v)));
                }
            }
            if let Some(n) = inst.note.as_deref().filter(|n| !n.is_empty()) {
                row("Note", esc(n));
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
            s.push_str("</div>\n");
        }
        s.push_str("</details></section>\n");
    }

    // ---- How to read it.
    s.push_str(
        "<h2>About this report</h2>\
         <p>The findings come from automated tests that look at the site's traffic and send attack requests, as an \
         attacker would. <strong>Certainty</strong> says how sure a test is: low-certainty findings need a person to \
         confirm them, and some may turn out not to be real. A finding marked <span class=\"tag\">confirmed</span> was \
         checked by the tester. Automated tests can't find every problem (for example flaws in business logic), so \
         a short or empty report doesn't prove a site is secure.</p>\n",
    );
    s.push_str("</main></body></html>\n");
    s
}

/// "2026-10-22" from an RFC 3339 time.
fn day(t: &str) -> &str {
    t.get(..10).unwrap_or(t)
}

// ---------- SARIF 2.1.0 ----------

fn sarif_level(risk: &str) -> &'static str {
    match risk {
        "high" => "error",
        "medium" => "warning",
        "low" => "note",
        _ => "none",
    }
}

/// GitHub code scanning reads `security-severity` (0.0–10.0) to bucket alerts.
fn security_severity(risk: &str) -> &'static str {
    match risk {
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
                    "security-severity": security_severity(&g.risk),
                    "risk": g.risk,
                    "pluginId": g.rule_id,
                },
            });
            if !g.solution.is_empty() {
                rule["help"] = json!({"text": g.solution, "markdown": g.solution});
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
                "locations": [{"physicalLocation": {"artifactLocation": {"uri": inst.url}}}],
                "partialFingerprints": {
                    "brainproxy/v1": format!("{}|{}|{}|{}|{}", g.alert_ref, inst.host, inst.method, inst.url, inst.param),
                },
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
                },
            });
            if let Some(n) = &inst.note {
                res["properties"]["note"] = json!(n);
            }
            if inst.state == "confirmed" {
                res["baselineState"] = json!("unchanged");
                res["kind"] = json!("fail");
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
            "properties": {"summary": r.summary, "scope": r.scope, "filters": r.filters},
        }],
    })
}

#[cfg(test)]
mod tests {
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
}
