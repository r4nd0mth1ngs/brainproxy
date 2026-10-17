//! Ported from ZAP CharsetMismatchScanRule (pscanrules, Apache License 2.0).
//!
//! 90011-3 (META charset versus META content-type) is raised by ZAP only at LOW threshold and
//! isn't ported. ZAP also alerts on an XML declaration without `encoding` (reporting `null`);
//! that's skipped here, since such a document is UTF-8 by default.

use std::sync::LazyLock;

use regex::Regex;

use crate::scan::passive::rules::params::common::{eq_ic, is_response_html, response_charset};
use crate::scan::passive::util::tags;
use crate::scan::{AlertDef, Confidence, Finding, Message, PassiveRule, Risk};

const DESCRIPTION: &str = "This check identifies responses where the HTTP Content-Type header declares a charset \
    different from the charset defined by the body of the HTML or XML. When there's a charset mismatch between the \
    HTTP header and content body Web browsers can be forced into an undesirable content-sniffing mode to determine \
    the content's correct character set.\n\nAn attacker could manipulate content on the page to be interpreted in \
    an encoding of their choice. For example, if an attacker can control content at the beginning of the page, \
    they could inject script using UTF-7 encoded text and manipulate some browsers into interpreting that text.";
const SOLUTION: &str =
    "Force UTF-8 for all text content in both the HTTP header and meta tags in HTML or encoding declarations in XML.";
const REFERENCES: &[&str] =
    &["https://code.google.com/archive/p/browsersec/wikis/Part2.wiki#Character_set_handling_and_detection"];
const TAGS: &[&str] = &["OWASP_2025_A02", "OWASP_2021_A05", "OWASP_2017_A06", "SYSTEMIC"];

macro_rules! alert {
    ($r:literal, $name:literal) => {
        AlertDef {
            alert_ref: $r,
            name: $name,
            risk: Risk::Info,
            confidence: Confidence::Low,
            cwe: 436,
            wasc: 15,
            description: DESCRIPTION,
            solution: SOLUTION,
            references: REFERENCES,
            tags: TAGS,
        }
    };
}

static META_CONTENT_TYPE: AlertDef = alert!("90011-1", "Charset Mismatch (Header Versus Meta Content-Type Charset)");
static META_CHARSET: AlertDef = alert!("90011-2", "Charset Mismatch (Header Versus Meta Charset)");
static XML: AlertDef = alert!("90011-4", "Charset Mismatch");

static ALERTS: [&AlertDef; 3] = [&META_CONTENT_TYPE, &META_CHARSET, &XML];

static XML_ENCODING: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"(?i)^<\?xml\s[^>]*?\bencoding\s*=\s*(?:"([^"]*)"|'([^']*)')"#).unwrap());

pub struct CharsetMismatch;

impl PassiveRule for CharsetMismatch {
    fn id(&self) -> u32 {
        90011
    }

    fn name(&self) -> &'static str {
        "Charset Mismatch"
    }

    fn alerts(&self) -> &'static [&'static AlertDef] {
        &ALERTS
    }

    fn scan(&self, msg: &Message, out: &mut Vec<Finding>) {
        let body = msg.body();
        let Some(header) = response_charset(msg).map(str::trim).filter(|_| !body.is_empty()) else { return };
        let mismatch = |def: &'static AlertDef, what: &str, declared: &str| {
            def.raise("", "").other_info(format!(
                "There was a charset mismatch between the HTTP Header and the {what} encoding declaration{}: \
                 [{header}] and [{declared}] do not match.",
                if def.alert_ref == "90011-1" { "s" } else { "" }
            ))
        };
        if is_response_html(msg) {
            let (mut content_charset, mut meta_charset) = (None, None);
            let tags = tags(body);
            for t in tags.iter().filter(|t| t.name == "meta") {
                if meta_charset.is_none_or(|c: &str| c.trim().is_empty()) {
                    meta_charset = t.attr("charset");
                }
                if let (Some(equiv), Some(content)) = (t.attr("http-equiv"), t.attr("content")) {
                    if equiv.eq_ignore_ascii_case("content-type") {
                        // ZAP: everything after "charset=", the last such meta wins.
                        let content = content.trim();
                        content_charset = content.find("charset=").map(|i| &content[i + 8..]);
                    }
                }
            }
            if let Some(cs) = content_charset.filter(|c| !c.is_empty() && !eq_ic(c, header)) {
                out.push(mismatch(&META_CONTENT_TYPE, "META content-type", cs));
            }
            if let Some(cs) = meta_charset.filter(|c| !c.is_empty() && !eq_ic(c, header)) {
                out.push(mismatch(&META_CHARSET, "META charset", cs));
            }
        } else if let Some(c) = XML_ENCODING.captures(body.trim_start_matches('\u{feff}')) {
            // Only the leading XML declaration counts, as for Jericho's isXML and declaration lookup.
            let encoding = c.get(1).or(c.get(2)).map_or("", |m| m.as_str());
            if !eq_ic(encoding, header) {
                out.push(mismatch(&XML, "XML", encoding));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scan::passive::util::testing::msg;

    fn scan(ct: &str, body: &str) -> Vec<Finding> {
        msg("https://a.test/").header("Content-Type", ct).body(body).scan(&CharsetMismatch)
    }

    #[test]
    fn html_meta_mismatches() {
        let f = scan(
            "text/html; charset=UTF-8",
            r#"<meta http-equiv="Content-Type" content="text/html; charset=EUC-JP"><meta charset="ISO-8859-1">"#,
        );
        let refs: Vec<_> = f.iter().map(|f| f.def.alert_ref).collect();
        assert_eq!(refs, ["90011-1", "90011-2"]);
        assert_eq!(
            f[0].other_info,
            "There was a charset mismatch between the HTTP Header and the META content-type encoding declarations: \
             [UTF-8] and [EUC-JP] do not match."
        );
        assert_eq!(
            f[1].other_info,
            "There was a charset mismatch between the HTTP Header and the META charset encoding declaration: \
             [UTF-8] and [ISO-8859-1] do not match."
        );
        assert_eq!(f[0].def.risk, Risk::Info);
    }

    #[test]
    fn html_matches_and_missing_charsets_are_quiet() {
        assert!(scan("text/html; charset=utf-8", r#"<meta charset="UTF-8"><p>x</p>"#).is_empty());
        assert!(scan("text/html", r#"<meta charset="ISO-8859-1">"#).is_empty());
        assert!(scan("text/html; charset=utf-8", r#"<meta http-equiv="content-type" content="text/html">"#).is_empty());
        assert!(scan("text/html; charset=utf-8", "").is_empty());
    }

    #[test]
    fn xml_declaration_mismatch() {
        let f = scan("application/xml; charset=UTF-8", "<?xml version=\"1.0\" encoding='ISO-8859-1'?><a/>");
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].def.alert_ref, "90011-4");
        assert!(f[0].other_info.ends_with("XML encoding declaration: [UTF-8] and [ISO-8859-1] do not match."));
        assert!(scan("text/xml; charset=utf-8", "<?xml version=\"1.0\" encoding=\"UTF-8\"?><a/>").is_empty());
        assert!(scan("text/xml; charset=utf-8", "<?xml version=\"1.0\"?><a/>").is_empty());
        assert!(scan("text/plain; charset=utf-8", "no declaration").is_empty());
    }
}
