//! Ported from ZAP ModernAppDetectionScanRule (pscanrules, Apache License 2.0).

use super::common::element_source;
use crate::scan::passive::util::tags;
use crate::scan::{AlertDef, Confidence, Finding, Message, PassiveRule, Risk};

static ALERT: AlertDef = AlertDef {
    alert_ref: "10109",
    name: "Modern Web Application",
    risk: Risk::Info,
    confidence: Confidence::Medium,
    cwe: 0,
    wasc: 0,
    description: "The application appears to be a modern web application. If you need to explore it automatically \
        then the Client Spider may well be more effective than the standard one.",
    solution: "This is an informational alert and so no changes are required.",
    references: &[],
    tags: &["SYSTEMIC"],
};

static ALERTS: [&AlertDef; 1] = [&ALERT];

const OTHER_NOLINKS: &str =
    "No links have been found while there are scripts, which is an indication that this is a modern web application.";
const OTHER_LINKS: &str = "Links have been found that do not have traditional href attributes, which is an \
    indication that this is a modern web application.";
const OTHER_SELF: &str = "Links have been found with a target of '_self' - this is often used by modern frameworks \
    to force a full page reload.";
const OTHER_NOSCRIPT: &str = "A noScript tag has been found, which is an indication that the application works \
    differently with JavaScript enabled compared to when it is not.";

pub struct ModernApp;

impl PassiveRule for ModernApp {
    fn id(&self) -> u32 {
        10109
    }

    fn name(&self) -> &'static str {
        "Modern Web Application"
    }

    fn alerts(&self) -> &'static [&'static AlertDef] {
        &ALERTS
    }

    fn scan(&self, msg: &Message, out: &mut Vec<Finding>) {
        if !msg.is_html() {
            return;
        }
        let html = msg.body();
        let all = tags(html);
        let mut found: Option<(&str, &str)> = None;
        let mut links = all.iter().filter(|t| t.name == "a").peekable();
        if links.peek().is_none() {
            if let Some(s) = all.iter().find(|t| t.name == "script") {
                found = Some((element_source(html, s), OTHER_NOLINKS));
            }
        } else {
            for link in links {
                if matches!(link.attr("href"), None | Some("") | Some("#")) {
                    found = Some((element_source(html, link), OTHER_LINKS));
                    break;
                }
                if link.attr("target") == Some("_self") {
                    found = Some((element_source(html, link), OTHER_SELF));
                    break;
                }
            }
        }
        if found.is_none() {
            if let Some(ns) = all.iter().find(|t| t.name == "noscript") {
                found = Some((element_source(html, ns), OTHER_NOSCRIPT));
            }
        }
        if let Some((evidence, other)) = found.filter(|(e, _)| !e.is_empty()) {
            out.push(ALERT.raise("", evidence).other_info(other));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scan::passive::util::testing::msg;

    #[test]
    fn flags_scripts_without_links() {
        let f = msg("https://a.test/").html("<html><script src=app.js></script></html>").scan(&ModernApp);
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].evidence, "<script src=app.js></script>");
        assert_eq!(f[0].other_info, OTHER_NOLINKS);
    }

    #[test]
    fn flags_hrefless_and_self_links_and_noscript() {
        let f = msg("https://a.test/").html("<a href=/x>x</a><a onclick=go()>y</a>").scan(&ModernApp);
        assert_eq!((f[0].evidence.as_str(), f[0].other_info.as_str()), ("<a onclick=go()>y</a>", OTHER_LINKS));
        let f = msg("https://a.test/").html("<a href=/x target=_self>x</a>").scan(&ModernApp);
        assert_eq!(f[0].other_info, OTHER_SELF);
        let f = msg("https://a.test/").html("<a href=/x>x</a><noscript>Enable JS</noscript>").scan(&ModernApp);
        assert_eq!(f[0].evidence, "<noscript>Enable JS</noscript>");
    }

    #[test]
    fn ignores_traditional_pages() {
        assert!(msg("https://a.test/").html("<a href=/x>x</a><script>1</script>").scan(&ModernApp).is_empty());
        assert!(msg("https://a.test/").body("<script></script>").scan(&ModernApp).is_empty());
    }
}
