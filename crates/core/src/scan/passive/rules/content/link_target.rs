//! Ported from ZAP LinkTargetScanRule (pscanrules, Apache License 2.0).

use super::common::{element_source, is_other_domain};
use crate::scan::passive::util::tags;
use crate::scan::{AlertDef, Confidence, Finding, Message, PassiveRule, Risk};

static ALERT: AlertDef = AlertDef {
    alert_ref: "10108",
    name: "Reverse Tabnabbing",
    risk: Risk::Medium,
    confidence: Confidence::Medium,
    cwe: 1022,
    wasc: 0,
    description: "At least one link on this page is vulnerable to Reverse tabnabbing as it uses a target attribute \
        without using both of the \"noopener\" and \"noreferrer\" keywords in the \"rel\" attribute, which allows \
        the target page to take control of this page.",
    solution: "Do not use a target attribute, or if you have to then also add the attribute: rel=\"noopener \
        noreferrer\".",
    references: &[
        "https://owasp.org/www-community/attacks/Reverse_Tabnabbing",
        "https://dev.to/ben/the-targetblank-vulnerability-by-example",
        "https://mathiasbynens.github.io/rel-noopener/",
        "https://medium.com/@jitbit/target-blank-the-most-underestimated-vulnerability-ever-96e328301f4c",
    ],
    tags: &["OWASP_2025_A06", "OWASP_2021_A04", "OWASP_2017_A06"],
};

static ALERTS: [&AlertDef; 1] = [&ALERT];

pub struct LinkTarget;

impl PassiveRule for LinkTarget {
    fn id(&self) -> u32 {
        10108
    }

    fn name(&self) -> &'static str {
        "Reverse Tabnabbing"
    }

    fn alerts(&self) -> &'static [&'static AlertDef] {
        &ALERTS
    }

    fn scan(&self, msg: &Message, out: &mut Vec<Finding>) {
        if msg.resp_body.is_empty() || !msg.is_html() {
            return;
        }
        let html = msg.body();
        let all = tags(html);
        // All <a> elements, then all <area> elements (ZAP order).
        let links = all.iter().filter(|t| t.name == "a").chain(all.iter().filter(|t| t.name == "area"));
        for link in links {
            let Some(href) = link.attr("href") else { continue };
            if !is_other_domain(&msg.host, href) || link.attr("target").is_none() {
                continue;
            }
            // ZAP only flags links that opt in to the opener (MEDIUM threshold).
            let rel = link.attr("rel").map(str::to_lowercase).unwrap_or_default();
            if rel.contains("opener") && !rel.contains("noopener") {
                out.push(ALERT.raise("", element_source(html, link)));
                return;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scan::passive::util::testing::msg;

    #[test]
    fn flags_cross_domain_opener_link() {
        let html = r#"<a href="/x" target=_blank rel=opener>in</a>
            <a href="https://b.test/" target="_blank" rel="opener">out</a>
            <a href="https://c.test/" target="_blank" rel="opener">second</a>"#;
        let f = msg("https://a.test/").html(html).scan(&LinkTarget);
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].evidence, r#"<a href="https://b.test/" target="_blank" rel="opener">out</a>"#);
        let f = msg("https://a.test/").html(r#"<area href="//b.test/" target=x rel="noreferrer opener">"#);
        assert_eq!(f.scan(&LinkTarget).len(), 1);
    }

    #[test]
    fn ignores_safe_links() {
        let html = r#"<a href="https://b.test/" target="_blank">no rel</a>
            <a href="https://b.test/" target="_blank" rel="noopener">safe</a>
            <a href="https://b.test/" rel="opener">no target</a>"#;
        assert!(msg("https://a.test/").html(html).scan(&LinkTarget).is_empty());
    }
}
