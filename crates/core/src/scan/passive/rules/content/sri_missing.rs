//! Ported from ZAP SubResourceIntegrityAttributeScanRule (pscanrules, Apache License 2.0).

use super::common::{element_source, uri_has_illegal_chars};
use crate::scan::passive::util::{find_ci, tags, url_host};
use crate::scan::{AlertDef, Confidence, Finding, Message, PassiveRule, Risk};

static ALERT: AlertDef = AlertDef {
    alert_ref: "90003",
    name: "Sub Resource Integrity Attribute Missing",
    risk: Risk::Medium,
    confidence: Confidence::High,
    cwe: 345,
    wasc: 15,
    description: "The integrity attribute is missing on a script or link tag served by an external server. The \
        integrity tag prevents an attacker who have gained access to this server from injecting a malicious content.",
    solution: "Provide a valid integrity attribute to the tag.",
    references: &["https://developer.mozilla.org/en-US/docs/Web/Security/Defenses/Subresource_Integrity"],
    tags: &["OWASP_2025_A02", "OWASP_2021_A05", "OWASP_2017_A06", "SYSTEMIC"],
};

static ALERTS: [&AlertDef; 1] = [&ALERT];

/// java.net.URI semantics: `None` for a syntax error or an absolute URI without
/// a host; the page origin for data: and relative (incl. protocol-relative) URLs.
fn resource_host(origin: &str, url: Option<&str>) -> Option<String> {
    let Some(url) = url.filter(|u| !u.starts_with("data:")) else { return Some(origin.to_string()) };
    if uri_has_illegal_chars(url) {
        return None;
    }
    let scheme_len = url.find(':').filter(|&i| {
        let s = &url[..i];
        s.starts_with(|c: char| c.is_ascii_alphabetic())
            && s.chars().all(|c| c.is_ascii_alphanumeric() || "+-.".contains(c))
    });
    if scheme_len.is_none() {
        return Some(origin.to_string());
    }
    url_host(url).map(|h| h.trim_start_matches('[').trim_end_matches(']').to_string())
}

pub struct SriMissing;

impl PassiveRule for SriMissing {
    fn id(&self) -> u32 {
        90003
    }

    fn name(&self) -> &'static str {
        "Sub Resource Integrity Attribute Missing"
    }

    fn alerts(&self) -> &'static [&'static AlertDef] {
        &ALERTS
    }

    fn scan(&self, msg: &Message, out: &mut Vec<Finding>) {
        let html = msg.body();
        // ZAP parses every response; skip the tokenizer when no candidate tag exists.
        if find_ci(html, "<script", 0).is_none() && find_ci(html, "<link", 0).is_none() {
            return;
        }
        for t in tags(html) {
            let url = match t.name.as_str() {
                "script" => t.attr("src"),
                "link" => {
                    let relevant = t.attr("rel").is_none_or(|rel| {
                        rel.to_lowercase().split(' ').any(|r| matches!(r, "stylesheet" | "preload" | "modulepreload"))
                    });
                    if !relevant {
                        continue;
                    }
                    t.attr("href")
                }
                _ => continue,
            };
            if t.has("integrity") {
                continue;
            }
            let trusted = resource_host(&msg.host, url).is_some_and(|h| h.eq_ignore_ascii_case(&msg.host));
            if !trusted {
                out.push(ALERT.raise("", element_source(html, &t)));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scan::passive::util::testing::msg;

    #[test]
    fn flags_external_resources_without_integrity() {
        let html = r#"<link rel="stylesheet" href="https://cdn.test/a.css"><script src="https://cdn.test/b.js"></script>
            <link rel="icon" href="https://cdn.test/i.png">"#;
        let f = msg("https://a.test/").html(html).scan(&SriMissing);
        assert_eq!(f.len(), 2);
        assert_eq!(f[0].evidence, r#"<link rel="stylesheet" href="https://cdn.test/a.css">"#);
        assert_eq!(f[1].evidence, r#"<script src="https://cdn.test/b.js"></script>"#);
    }

    #[test]
    fn ignores_same_origin_relative_inline_and_sri() {
        let html = r#"<script src="https://a.test/x.js"></script><script src="/y.js"></script>
            <script src="//cdn.test/z.js"></script><script>inline()</script><link href="data:text/css,x">
            <script src="https://cdn.test/b.js" integrity="sha384-x"></script>"#;
        assert!(msg("https://a.test/").html(html).scan(&SriMissing).is_empty());
    }
}
