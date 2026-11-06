//! Reports for other tools: CSV for spreadsheets, JUnit XML for CI dashboards, and
//! DefectDojo's Generic Findings Import JSON. Each names a finding by its fingerprint, as the
//! JSON report, SARIF and tickets do, so one finding is the same row everywhere.

use std::fmt::Write as _;

use serde_json::{json, Value};

use super::{md_code, md_no_html, risk_title, Instance, Report};

/// States that are still work to do.
fn active(state: &str) -> bool {
    matches!(state, "open" | "confirmed" | "retest_pending")
}

fn rows(r: &Report) -> impl Iterator<Item = (&super::AlertGroup, &Instance)> {
    r.alerts.iter().flat_map(|g| g.instances.iter().map(move |i| (g, i)))
}

/// A CSV field: quoted when it needs to be, and with a leading = + - @ (or tab, return)
/// defused, so a spreadsheet shows a value from the target rather than running it.
fn csv_field(s: &str) -> String {
    // A formula can follow leading whitespace or line breaks, and spreadsheets read the
    // fullwidth signs (＝ ＋ － ＠) as formulas too.
    let lead = s.trim_start_matches([' ', '\t', '\r', '\n']);
    let risky = s.starts_with(['\t', '\r', '\n'])
        || lead.starts_with(['=', '+', '-', '@', '\u{ff1d}', '\u{ff0b}', '\u{ff0d}', '\u{ff20}']);
    let s = if risky { format!("'{s}") } else { s.to_string() };
    if s.contains([',', '"', '\n', '\r']) {
        format!("\"{}\"", s.replace('"', "\"\""))
    } else {
        s
    }
}

pub fn csv(r: &Report) -> String {
    let mut out = String::from(
        "finding_id,issue_id,fingerprint,alert_ref,name,risk,cvss_score,cvss_vector,confidence,state,source,host,\
         method,url,param,cwe,first_seen,last_seen,hits,note,tickets\r\n",
    );
    for (g, i) in rows(r) {
        let fields = [
            i.id.to_string(),
            i.issue_id.map(|x| x.to_string()).unwrap_or_default(),
            i.fingerprint.clone(),
            g.alert_ref.clone(),
            g.name.clone(),
            i.risk.clone(),
            i.cvss.as_ref().map(|c| format!("{:.1}", c.score)).unwrap_or_default(),
            i.cvss.as_ref().map(|c| c.vector.clone()).unwrap_or_default(),
            i.confidence.clone(),
            i.state.clone(),
            i.source.clone(),
            i.host.clone(),
            i.method.clone(),
            i.url.clone(),
            i.param.clone(),
            i.cwe.or(g.cwe).map(|c| c.to_string()).unwrap_or_default(),
            i.time.clone(),
            i.last_seen.clone().unwrap_or_default(),
            i.hits.to_string(),
            i.note.clone().unwrap_or_default(),
            i.tickets.iter().map(|t| t.url.as_str()).collect::<Vec<_>>().join(" "),
        ];
        let line: Vec<String> = fields.iter().map(|f| csv_field(f)).collect();
        out.push_str(&line.join(","));
        out.push_str("\r\n");
    }
    out
}

/// XML text or attribute: escaped, without the characters XML 1.0 can't hold.
fn xml(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&apos;"),
            '\t' | '\n' | '\r' => out.push(c),
            c if (c as u32) < 0x20 || c == '\u{fffe}' || c == '\u{ffff}' => out.push('\u{fffd}'),
            c => out.push(c),
        }
    }
    out
}

/// JUnit XML: a test suite per alert type, a test case per finding, failing while the
/// finding is work to do and skipped once it is closed (false positive, accepted, fixed).
pub fn junit(r: &Report) -> String {
    let total: usize = r.alerts.iter().map(|g| g.instances.len()).sum();
    let failing = rows(r).filter(|(_, i)| active(&i.state)).count();
    let mut out = format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<testsuites name=\"{}\" tests=\"{total}\" failures=\"{failing}\">\n",
        xml(&r.title)
    );
    for g in &r.alerts {
        let fails = g.instances.iter().filter(|i| active(&i.state)).count();
        let skipped = g.instances.len() - fails;
        let _ = writeln!(
            out,
            "  <testsuite name=\"{}\" tests=\"{}\" failures=\"{fails}\" skipped=\"{skipped}\">",
            xml(&format!("{} ({})", g.name, g.alert_ref)),
            g.instances.len()
        );
        for i in &g.instances {
            let name = if i.param.is_empty() {
                format!("{} {}", i.method, i.url)
            } else {
                format!("{} {} [{}]", i.method, i.url, i.param)
            };
            let _ = write!(
                out,
                "    <testcase classname=\"{}\" name=\"{}\" id=\"{}\">",
                xml(&g.alert_ref),
                xml(&name),
                xml(&i.fingerprint)
            );
            if active(&i.state) {
                let mut detail = format!(
                    "{}\nRisk: {}, confidence {}, {}.",
                    g.name,
                    i.risk,
                    i.confidence,
                    i.state.replace('_', " ")
                );
                if !i.evidence.is_empty() {
                    detail.push_str(&format!("\nEvidence: {}", i.evidence));
                }
                if let Some(c) = &i.cvss {
                    detail.push_str(&format!("\nCVSS 4.0: {:.1} {}", c.score, c.vector));
                }
                let _ = write!(
                    out,
                    "<failure type=\"{}\" message=\"{}\">{}</failure>",
                    xml(&i.risk),
                    xml(&format!("{} ({})", g.name, risk_title(&i.risk))),
                    xml(&detail)
                );
            } else {
                let _ = write!(out, "<skipped message=\"{}\"/>", xml(&i.state.replace('_', " ")));
            }
            out.push_str("</testcase>\n");
        }
        out.push_str("  </testsuite>\n");
    }
    out.push_str("</testsuites>\n");
    out
}

/// DefectDojo's endpoint fields from a URL.
fn endpoint(url: &str) -> Value {
    match url::Url::parse(url) {
        Ok(u) => json!({
            "protocol": u.scheme(),
            "host": u.host_str().unwrap_or_default(),
            "port": u.port_or_known_default(),
            "path": u.path(),
            "query": u.query().unwrap_or_default(),
        }),
        Err(_) => json!({"host": url}),
    }
}

/// DefectDojo's Generic Findings Import (JSON): one finding per instance, with its
/// fingerprint as `unique_id_from_tool`, so a re-import updates rather than duplicates.
pub fn defectdojo(r: &Report) -> String {
    let findings: Vec<Value> = rows(r)
        .map(|(g, i)| {
            let mut description = String::new();
            // A write-up says who drafted and reviewed it, and a draft says it is one.
            for n in g.narratives.iter().filter(|n| Some(n.issue_id) == i.issue_id) {
                let draft = if n.narrative.reviewed() { "" } else { "**Draft, not reviewed.** " };
                let _ = write!(
                    description,
                    "{draft}{}\n\n_{}_\n\n",
                    md_no_html(n.narrative.text.trim()),
                    n.narrative.credit()
                );
            }
            if !g.description.trim().is_empty() {
                let _ = write!(description, "{}\n\n", md_no_html(g.description.trim()));
            }
            let _ = write!(description, "**Where:** {}", md_code(&format!("{} {}", i.method, i.url)));
            if !i.param.is_empty() {
                let _ = write!(description, " (parameter {})", md_code(&i.param));
            }
            if !i.evidence.is_empty() {
                let _ = write!(description, "\n\n**Evidence:** {}", md_code(&i.evidence));
            }
            if let Some(c) = &i.cvss {
                let _ = write!(description, "\n\n**CVSS 4.0:** {:.1} ({}) {}", c.score, c.severity, md_code(&c.vector));
            }
            if let Some(n) = i.note.as_deref().filter(|n| !n.is_empty()) {
                let by = crate::provenance::describe(i.note_origin.as_deref());
                let _ = write!(description, "\n\n**Note** ({by}): {}", md_no_html(n));
            }
            let _ = write!(description, "\n\nbrainproxy finding #{} ({}).", i.id, i.source);
            let mut f = json!({
                "title": g.name,
                "description": description,
                "severity": match i.risk.as_str() {
                    "critical" => "Critical",
                    "high" => "High",
                    "medium" => "Medium",
                    "low" => "Low",
                    _ => "Info",
                },
                "mitigation": g.solution,
                "references": g.references.join("\n"),
                "date": i.time.get(..10).unwrap_or(&i.time),
                "active": active(&i.state),
                "verified": i.state == "confirmed",
                "false_p": i.state == "false_positive",
                "risk_accepted": i.state == "accepted_risk",
                "is_mitigated": i.state == "fixed",
                "unique_id_from_tool": i.fingerprint,
                "vuln_id_from_tool": g.alert_ref,
                "param": i.param,
                "payload": i.attack,
                "endpoints": [endpoint(&i.url)],
            });
            if let Some(c) = i.cwe.or(g.cwe) {
                f["cwe"] = json!(c);
            }
            f
        })
        .collect();
    // A name and type of its own, so DefectDojo can be told to deduplicate this scan type by
    // unique_id_from_tool (see the manual).
    serde_json::to_string_pretty(&json!({
        "name": "brainproxy",
        "type": "brainproxy",
        "version": r.tool.version,
        "findings": findings,
    }))
    .unwrap_or_default()
        + "\n"
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn csv_fields_are_quoted_and_formulas_defused() {
        assert_eq!(csv_field("plain"), "plain");
        assert_eq!(csv_field("a,b"), "\"a,b\"");
        assert_eq!(csv_field("say \"hi\""), "\"say \"\"hi\"\"\"");
        assert_eq!(csv_field("=HYPERLINK(\"http://x\")"), "\"'=HYPERLINK(\"\"http://x\"\")\"");
        assert_eq!(csv_field("-1+1"), "'-1+1");
        assert_eq!(csv_field("\n=1+1"), "\"'\n=1+1\"");
        assert_eq!(csv_field("  =1"), "'  =1");
        assert_eq!(csv_field("\u{ff1d}1+1"), "'\u{ff1d}1+1");
        assert_eq!(xml("<a & 'b'>\u{1}"), "&lt;a &amp; &apos;b&apos;&gt;\u{fffd}");
        assert_eq!(endpoint("https://a.test:8443/x?y=1")["port"], 8443);
    }
}
