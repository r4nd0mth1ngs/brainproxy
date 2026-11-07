//! The report as a Word document (DOCX): the same sections as the HTML report, in Word's
//! own headings, tables and code paragraphs, so a consultancy can restyle and edit it.
//! Written by hand: a few XML parts in a zip.

use std::fmt::Write as _;
use std::io::Write as _;

use super::{
    curl, day, first_sentence, http_text, left_out_text, narrative_title, redaction_text, risk_title, trail_text,
    Report, RetestRow, RISKS,
};
use crate::scan::layout::Section;

/// XML text: escaped, and without the characters XML 1.0 can't hold (evidence may have them).
fn x(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\t' | '\n' | '\r' => out.push(c),
            c if (c as u32) < 0x20 || c == '\u{fffe}' || c == '\u{ffff}' => out.push('\u{fffd}'),
            c => out.push(c),
        }
    }
    out
}

struct Doc {
    body: String,
}

impl Doc {
    fn para(&mut self, style: &str, text: &str) {
        let _ = write!(
            self.body,
            "<w:p><w:pPr><w:pStyle w:val=\"{style}\"/></w:pPr><w:r><w:t xml:space=\"preserve\">{}</w:t></w:r></w:p>",
            x(text)
        );
    }

    fn heading(&mut self, level: u8, text: &str) {
        self.para(&format!("Heading{level}"), text);
    }

    fn text(&mut self, text: &str) {
        for p in text.split("\n\n").map(str::trim).filter(|p| !p.is_empty()) {
            self.para("Normal", p);
        }
    }

    /// A bold label, then text, in one paragraph.
    fn labelled(&mut self, label: &str, text: &str) {
        let _ = write!(
            self.body,
            "<w:p><w:r><w:rPr><w:b/></w:rPr><w:t xml:space=\"preserve\">{} </w:t></w:r>\
             <w:r><w:t xml:space=\"preserve\">{}</w:t></w:r></w:p>",
            x(label),
            x(text)
        );
    }

    /// Preformatted text: one paragraph with line breaks, in the Code style.
    fn code(&mut self, text: &str) {
        let mut runs = String::new();
        for (i, line) in text.lines().enumerate() {
            if i > 0 {
                runs.push_str("<w:br/>");
            }
            let _ = write!(runs, "<w:t xml:space=\"preserve\">{}</w:t>", x(line));
        }
        let _ = write!(self.body, "<w:p><w:pPr><w:pStyle w:val=\"Code\"/></w:pPr><w:r>{runs}</w:r></w:p>");
    }

    fn table(&mut self, headers: &[&str], rows: &[Vec<String>]) {
        let cell = |t: &str, bold: bool| {
            format!(
                "<w:tc><w:p><w:r>{}<w:t xml:space=\"preserve\">{}</w:t></w:r></w:p></w:tc>",
                if bold { "<w:rPr><w:b/></w:rPr>" } else { "" },
                x(t)
            )
        };
        // The grid Word's schema requires: equal columns across the text width (A4 less margins).
        let col = 9638 / headers.len().max(1);
        let grid: String = headers.iter().map(|_| format!("<w:gridCol w:w=\"{col}\"/>")).collect();
        let _ = write!(
            self.body,
            "<w:tbl><w:tblPr><w:tblStyle w:val=\"Grid\"/><w:tblW w:w=\"5000\" w:type=\"pct\"/></w:tblPr>\
             <w:tblGrid>{grid}</w:tblGrid><w:tr><w:trPr><w:tblHeader/></w:trPr>"
        );
        for h in headers {
            self.body.push_str(&cell(h, true));
        }
        self.body.push_str("</w:tr>");
        for row in rows {
            self.body.push_str("<w:tr><w:trPr><w:cantSplit/></w:trPr>");
            for c in row {
                self.body.push_str(&cell(c, false));
            }
            self.body.push_str("</w:tr>");
        }
        // Word needs a paragraph between two tables and after the last one.
        self.body.push_str("</w:tbl><w:p/>");
    }
}

fn letter_rows(rows: &[RetestRow]) -> Vec<Vec<String>> {
    rows.iter()
        .map(|r| {
            vec![
                r.id.to_string(),
                r.name.clone(),
                risk_title(&r.risk).to_string(),
                format!(
                    "{} {}{}",
                    r.method,
                    r.url,
                    if r.param.is_empty() { String::new() } else { format!(" [{}]", r.param) }
                ),
                match (&r.event, &r.time) {
                    (Some(e), Some(t)) => format!("{e} on {}", day(t)),
                    _ => r.state.replace('_', " "),
                },
                r.history_id.map(|h| format!("history #{h}")).unwrap_or_default(),
            ]
        })
        .collect()
}

pub fn render(r: &Report) -> Vec<u8> {
    let layout = &r.layout;
    let mut d = Doc { body: String::new() };
    d.para("Title", &r.title);
    let mut sub = match &layout.company {
        Some(c) => format!("Security assessment by {c}. "),
        None => String::new(),
    };
    let _ = write!(sub, "Generated {} by {} {}.", day(&r.generated), r.tool.name, r.tool.version);
    d.para("Subtitle", &sub);
    let count = |risk: &str| r.summary.by_risk.iter().find(|c| c.risk == risk).map_or(0, |c| c.count);

    if layout.has(Section::Summary) {
        d.heading(1, "At a glance");
        let rows: Vec<Vec<String>> = RISKS
            .iter()
            .filter(|&&k| k != "critical" || count(k) > 0)
            .map(|&k| vec![risk_title(k).to_string(), count(k).to_string()])
            .collect();
        d.table(&["Risk", "Findings"], &rows);
        if let Some(n) = &r.summary_narrative {
            d.heading(2, if n.reviewed() { "Executive summary" } else { "Executive summary (draft, not reviewed)" });
            d.text(&n.text);
            d.para("Subtitle", &n.credit());
        }
    }
    // What the report leaves out, and whether it is redacted, whatever its sections.
    if r.summary.truncated {
        d.text(&format!("This report shows {} of {} findings.", r.summary.included, r.summary.total));
    }
    if let Some(t) = left_out_text(r) {
        d.text(&t);
    }
    d.text(&redaction_text(r));
    if layout.has(Section::FixFirst) {
        let urgent: Vec<_> =
            r.alerts.iter().filter(|g| matches!(g.risk.as_str(), "critical" | "high" | "medium")).take(10).collect();
        if !urgent.is_empty() {
            d.heading(2, "Fix these first");
            for (i, g) in urgent.iter().enumerate() {
                d.labelled(&format!("{}. {} ({}):", i + 1, g.name, risk_title(&g.risk)), first_sentence(&g.solution));
            }
        }
    }
    if let Some(p) = r.posture.as_ref().filter(|_| layout.has(Section::Posture)) {
        d.heading(1, "Posture");
        let rows: Vec<Vec<String>> = RISKS
            .iter()
            .map(|&k| {
                vec![
                    risk_title(k).to_string(),
                    p["open"]["issues"][k].as_i64().unwrap_or(0).to_string(),
                    p["open"]["instances"][k].as_i64().unwrap_or(0).to_string(),
                ]
            })
            .filter(|row| row[0] != "Critical" || row[1] != "0")
            .collect();
        d.table(&["Risk", "Open issues", "Places"], &rows);
        let scans: Vec<Vec<String>> = p["scans"]
            .as_array()
            .map(Vec::as_slice)
            .unwrap_or_default()
            .iter()
            .rev()
            .take(10)
            .map(|s| {
                vec![
                    format!("#{}", s["job"]),
                    day(s["finished"].as_str().unwrap_or("")).to_string(),
                    s["new"].to_string(),
                    s["still"].to_string(),
                    s["gone"].to_string(),
                ]
            })
            .collect();
        if !scans.is_empty() {
            d.table(&["Scan", "Finished", "New", "Still there", "No longer found"], &scans);
        }
    }
    if let Some(l) = r.retest.as_ref().filter(|_| layout.has(Section::Retest)) {
        d.heading(1, &format!("Retest since {}", l.since));
        d.text(&format!(
            "{} fixed, {} still there, {} came back after a fix, {} awaiting a retest.",
            l.fixed.len(),
            l.still_present.len(),
            l.regressed.len(),
            l.pending.len()
        ));
        for (title, rows) in [
            ("Fixed", &l.fixed),
            ("Still there", &l.still_present),
            ("Not reproduced, not marked fixed", &l.not_reproduced),
            ("Came back after a fix", &l.regressed),
            ("Awaiting a retest", &l.pending),
        ] {
            if !rows.is_empty() {
                d.heading(2, title);
                d.table(&["#", "Issue", "Risk", "Address", "What happened", "Proof"], &letter_rows(rows));
            }
        }
    }
    if layout.has(Section::List) && !r.alerts.is_empty() {
        d.heading(1, "All issues");
        let rows: Vec<Vec<String>> = r
            .alerts
            .iter()
            .enumerate()
            .map(|(i, g)| {
                vec![
                    (i + 1).to_string(),
                    g.name.clone(),
                    risk_title(&g.risk).to_string(),
                    g.cvss.as_ref().map(|c| format!("{:.1}", c.score)).unwrap_or_else(|| "–".into()),
                    g.instances.len().to_string(),
                ]
            })
            .collect();
        d.table(&["#", "Issue", "Risk", "CVSS", "Places"], &rows);
    }
    if layout.has(Section::Issues) {
        for (i, g) in r.alerts.iter().enumerate() {
            d.heading(1, &format!("{}. {} ({})", i + 1, g.name, risk_title(&g.risk)));
            if let Some(c) = &g.cvss {
                d.labelled("CVSS 4.0:", &format!("{:.1} ({}) {}", c.score, c.severity, c.vector));
            }
            for n in &g.narratives {
                d.heading(2, &narrative_title(g, n));
                d.text(&n.narrative.text);
                d.para("Subtitle", &n.narrative.credit());
            }
            for (h, text) in [("What this means", &g.description), ("How to fix it", &g.solution)] {
                if !text.trim().is_empty() {
                    d.heading(2, h);
                    d.text(text);
                }
            }
            d.heading(2, &format!("Where it was found ({})", g.instances.len()));
            let rows: Vec<Vec<String>> = g
                .instances
                .iter()
                .map(|inst| {
                    vec![
                        format!("{} {}", inst.method, inst.url),
                        inst.param.clone(),
                        inst.confidence.clone(),
                        inst.state.replace('_', " "),
                    ]
                })
                .collect();
            d.table(&["Address", "Field", "Certainty", "State"], &rows);
            if layout.has(Section::Reproduce) {
                let lines: Vec<String> = g.instances.iter().filter_map(|i| i.request.as_ref().map(curl)).collect();
                if !lines.is_empty() {
                    d.heading(2, "How to reproduce");
                    d.code(&lines.join("\n\n"));
                }
            }
            if layout.has(Section::Evidence) {
                for inst in &g.instances {
                    d.heading(3, &format!("Finding #{}: {} {}", inst.id, inst.method, inst.url));
                    for (k, v) in [("Evidence:", &inst.evidence), ("Attack:", &inst.attack)] {
                        if !v.is_empty() {
                            d.labelled(k, v);
                        }
                    }
                    if let Some(n) = inst.note.as_deref().filter(|n| !n.is_empty()) {
                        d.labelled("Note:", n);
                    }
                    if let Some(t) = &inst.agent_trail {
                        d.labelled("Agent trail:", &trail_text(t));
                    }
                    for t in &inst.tickets {
                        d.labelled(&format!("Ticket ({}):", t.tracker), &t.url);
                    }
                    if let Some(req) = &inst.request {
                        d.code(&http_text(req, inst.response.as_ref()));
                    }
                }
            }
        }
    }
    if (layout.has(Section::Issues) || layout.has(Section::List)) && !r.agent_false_positives.is_empty() {
        d.heading(1, "Marked false positive by an agent");
        d.text(
            "These findings were marked false positive via MCP (an agent), not by a person, and are left out above.",
        );
        let rows: Vec<Vec<String>> = r
            .agent_false_positives
            .iter()
            .map(|h| {
                vec![
                    h.id.to_string(),
                    h.name.clone(),
                    risk_title(&h.risk).to_string(),
                    format!(
                        "{} {}{}",
                        h.method,
                        h.url,
                        if h.param.is_empty() { String::new() } else { format!(" [{}]", h.param) }
                    ),
                    h.state_changed_at.clone().unwrap_or_default(),
                    h.note.clone().unwrap_or_default(),
                ]
            })
            .collect();
        d.table(&["#", "Issue", "Risk", "Address", "Marked", "Note"], &rows);
    }
    if layout.has(Section::About) {
        d.heading(1, "About this report");
        d.text(
            "The findings come from automated tests that look at the site's traffic and send attack requests, as an \
             attacker would, and from the tester's own work. Certainty says how sure a test is: low-certainty \
             findings need a person to confirm them. Automated tests can't find every problem (for example flaws in \
             business logic), so a short or empty report doesn't prove a site is secure.",
        );
    }
    package(&d.body)
}

const STYLES: &str = r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<w:styles xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">
<w:docDefaults><w:rPrDefault><w:rPr><w:rFonts w:ascii="Calibri" w:hAnsi="Calibri" w:cs="Calibri"/><w:sz w:val="21"/></w:rPr></w:rPrDefault>
<w:pPrDefault><w:pPr><w:spacing w:after="120" w:line="276" w:lineRule="auto"/></w:pPr></w:pPrDefault></w:docDefaults>
<w:style w:type="paragraph" w:default="1" w:styleId="Normal"><w:name w:val="Normal"/></w:style>
<w:style w:type="paragraph" w:styleId="Title"><w:name w:val="Title"/><w:basedOn w:val="Normal"/><w:rPr><w:b/><w:sz w:val="48"/></w:rPr></w:style>
<w:style w:type="paragraph" w:styleId="Subtitle"><w:name w:val="Subtitle"/><w:basedOn w:val="Normal"/><w:rPr><w:color w:val="5D6370"/></w:rPr></w:style>
<w:style w:type="paragraph" w:styleId="Heading1"><w:name w:val="heading 1"/><w:basedOn w:val="Normal"/><w:next w:val="Normal"/><w:pPr><w:keepNext/><w:spacing w:before="360"/><w:outlineLvl w:val="0"/></w:pPr><w:rPr><w:b/><w:sz w:val="32"/></w:rPr></w:style>
<w:style w:type="paragraph" w:styleId="Heading2"><w:name w:val="heading 2"/><w:basedOn w:val="Normal"/><w:next w:val="Normal"/><w:pPr><w:keepNext/><w:spacing w:before="240"/><w:outlineLvl w:val="1"/></w:pPr><w:rPr><w:b/><w:sz w:val="26"/></w:rPr></w:style>
<w:style w:type="paragraph" w:styleId="Heading3"><w:name w:val="heading 3"/><w:basedOn w:val="Normal"/><w:next w:val="Normal"/><w:pPr><w:keepNext/><w:outlineLvl w:val="2"/></w:pPr><w:rPr><w:b/></w:rPr></w:style>
<w:style w:type="paragraph" w:styleId="Code"><w:name w:val="Code"/><w:basedOn w:val="Normal"/><w:pPr><w:shd w:val="clear" w:color="auto" w:fill="EEF0F3"/><w:spacing w:after="120" w:line="240" w:lineRule="auto"/></w:pPr><w:rPr><w:rFonts w:ascii="Consolas" w:hAnsi="Consolas" w:cs="Consolas"/><w:sz w:val="16"/></w:rPr></w:style>
<w:style w:type="table" w:styleId="Grid"><w:name w:val="Grid"/><w:tblPr><w:tblBorders>
<w:top w:val="single" w:sz="4" w:color="DFE2E7"/><w:left w:val="single" w:sz="4" w:color="DFE2E7"/><w:bottom w:val="single" w:sz="4" w:color="DFE2E7"/>
<w:right w:val="single" w:sz="4" w:color="DFE2E7"/><w:insideH w:val="single" w:sz="4" w:color="DFE2E7"/><w:insideV w:val="single" w:sz="4" w:color="DFE2E7"/>
</w:tblBorders><w:tblCellMar><w:left w:w="80" w:type="dxa"/><w:right w:w="80" w:type="dxa"/></w:tblCellMar></w:tblPr></w:style>
</w:styles>"#;

/// The document's parts, zipped.
fn package(body: &str) -> Vec<u8> {
    let document = format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>\
         <w:document xmlns:w=\"http://schemas.openxmlformats.org/wordprocessingml/2006/main\"><w:body>{body}\
         <w:sectPr><w:pgSz w:w=\"11906\" w:h=\"16838\"/><w:pgMar w:top=\"1134\" w:right=\"1134\" w:bottom=\"1134\" \
         w:left=\"1134\" w:header=\"567\" w:footer=\"567\" w:gutter=\"0\"/></w:sectPr></w:body></w:document>"
    );
    let parts: [(&str, &str); 5] = [
        (
            "[Content_Types].xml",
            "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>\
             <Types xmlns=\"http://schemas.openxmlformats.org/package/2006/content-types\">\
             <Default Extension=\"rels\" ContentType=\"application/vnd.openxmlformats-package.relationships+xml\"/>\
             <Default Extension=\"xml\" ContentType=\"application/xml\"/>\
             <Override PartName=\"/word/document.xml\" ContentType=\"application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml\"/>\
             <Override PartName=\"/word/styles.xml\" ContentType=\"application/vnd.openxmlformats-officedocument.wordprocessingml.styles+xml\"/>\
             </Types>",
        ),
        (
            "_rels/.rels",
            "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>\
             <Relationships xmlns=\"http://schemas.openxmlformats.org/package/2006/relationships\">\
             <Relationship Id=\"rId1\" Type=\"http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument\" Target=\"word/document.xml\"/>\
             </Relationships>",
        ),
        (
            "word/_rels/document.xml.rels",
            "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>\
             <Relationships xmlns=\"http://schemas.openxmlformats.org/package/2006/relationships\">\
             <Relationship Id=\"rId1\" Type=\"http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles\" Target=\"styles.xml\"/>\
             </Relationships>",
        ),
        ("word/styles.xml", STYLES),
        ("word/document.xml", &document),
    ];
    zip(&parts)
}

/// A zip archive of `files`, deflated, with a fixed timestamp so the same report gives the
/// same bytes.
fn zip(files: &[(&str, &str)]) -> Vec<u8> {
    let mut out = Vec::new();
    let mut central = Vec::new();
    // 1980-01-01 00:00, the earliest DOS date.
    let (time, date) = (0u16, (1u16 << 5) | 1);
    for (name, content) in files {
        let mut crc = flate2::Crc::new();
        crc.update(content.as_bytes());
        let mut enc = flate2::write::DeflateEncoder::new(Vec::new(), flate2::Compression::default());
        let _ = enc.write_all(content.as_bytes());
        let packed = enc.finish().unwrap_or_default();
        let offset = out.len() as u32;
        let header = |sig: u32, central: bool| {
            let mut h = Vec::new();
            h.extend_from_slice(&sig.to_le_bytes());
            if central {
                h.extend_from_slice(&20u16.to_le_bytes()); // made by
            }
            h.extend_from_slice(&20u16.to_le_bytes()); // needed to extract
            h.extend_from_slice(&0x0800u16.to_le_bytes()); // UTF-8 names
            h.extend_from_slice(&8u16.to_le_bytes()); // deflate
            h.extend_from_slice(&time.to_le_bytes());
            h.extend_from_slice(&date.to_le_bytes());
            h.extend_from_slice(&crc.sum().to_le_bytes());
            h.extend_from_slice(&(packed.len() as u32).to_le_bytes());
            h.extend_from_slice(&(content.len() as u32).to_le_bytes());
            h.extend_from_slice(&(name.len() as u16).to_le_bytes());
            h.extend_from_slice(&0u16.to_le_bytes()); // extra
            if central {
                h.extend_from_slice(&0u16.to_le_bytes()); // comment
                h.extend_from_slice(&0u16.to_le_bytes()); // disk
                h.extend_from_slice(&0u16.to_le_bytes()); // internal attributes
                h.extend_from_slice(&0u32.to_le_bytes()); // external attributes
                h.extend_from_slice(&offset.to_le_bytes());
            }
            h.extend_from_slice(name.as_bytes());
            h
        };
        out.extend(header(0x0403_4b50, false));
        out.extend_from_slice(&packed);
        central.extend(header(0x0201_4b50, true));
    }
    let start = out.len() as u32;
    out.extend_from_slice(&central);
    out.extend_from_slice(&0x0605_4b50u32.to_le_bytes());
    out.extend_from_slice(&[0, 0, 0, 0]); // disk numbers
    out.extend_from_slice(&(files.len() as u16).to_le_bytes());
    out.extend_from_slice(&(files.len() as u16).to_le_bytes());
    out.extend_from_slice(&(central.len() as u32).to_le_bytes());
    out.extend_from_slice(&start.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The entries of a zip, read back by inflating each local file.
    fn unzip(z: &[u8]) -> Vec<(String, String)> {
        use std::io::Read;
        let mut out = Vec::new();
        let mut at = 0;
        while z[at..].starts_with(&0x0403_4b50u32.to_le_bytes()) {
            let n = |o: usize| u16::from_le_bytes([z[at + o], z[at + o + 1]]) as usize;
            let size = u32::from_le_bytes(z[at + 18..at + 22].try_into().unwrap()) as usize;
            let (name_len, extra) = (n(26), n(28));
            let name = String::from_utf8(z[at + 30..at + 30 + name_len].to_vec()).unwrap();
            let data = &z[at + 30 + name_len + extra..at + 30 + name_len + extra + size];
            let mut text = String::new();
            flate2::read::DeflateDecoder::new(data).read_to_string(&mut text).unwrap();
            out.push((name, text));
            at += 30 + name_len + extra + size;
        }
        out
    }

    #[test]
    fn a_word_document_with_escaped_text() {
        let mut d = Doc { body: String::new() };
        d.heading(1, "XSS in <search> & \"more\"");
        d.code("GET /?q=<script>\u{1}\nHost: a");
        d.table(&["A"], &[vec!["x & y".into()]]);
        let z = package(&d.body);
        let parts = unzip(&z);
        let names: Vec<&str> = parts.iter().map(|(n, _)| n.as_str()).collect();
        assert_eq!(
            names,
            [
                "[Content_Types].xml",
                "_rels/.rels",
                "word/_rels/document.xml.rels",
                "word/styles.xml",
                "word/document.xml"
            ]
        );
        let doc = &parts[4].1;
        assert!(doc.contains("XSS in &lt;search&gt; &amp; &quot;more&quot;"));
        assert!(doc.contains("GET /?q=&lt;script&gt;\u{fffd}</w:t><w:br/>"));
        assert!(!doc.contains('\u{1}') && doc.contains("x &amp; y"));
        // The same document gives the same bytes.
        assert_eq!(package(&d.body), z);
    }
}
