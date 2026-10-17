//! Ported from ZAP InformationDisclosureDebugErrorsScanRule (pscanrules, Apache License 2.0).

use std::sync::LazyLock;

use regex::{Regex, RegexSet};

use super::common::{data_lines, is_javascript, is_text};
use crate::scan::{AlertDef, Confidence, Finding, Message, PassiveRule, Risk};

static ALERT: AlertDef = AlertDef {
    alert_ref: "10023",
    name: "Information Disclosure - Debug Error Messages",
    risk: Risk::Low,
    confidence: Confidence::Medium,
    cwe: 1295,
    wasc: 13,
    description: "The response appeared to contain common error messages returned by platforms such as ASP.NET, and \
        Web-servers such as IIS and Apache. You can configure the list of common debug messages.",
    solution: "Disable debugging messages before pushing to production.",
    references: &[],
    tags: &["OWASP_2025_A01", "OWASP_2021_A01", "OWASP_2017_A03", "WSTG-v42-ERRH-01"],
};

static ALERTS: [&AlertDef; 1] = [&ALERT];

pub(crate) const EMBEDDED: &str = include_str!("../../data/debug-error-messages.txt");

/// One case-insensitive literal per message, in file order.
fn patterns() -> Vec<String> {
    data_lines(crate::data::get("debug-error-messages.txt")).map(|l| format!("(?i){}", regex::escape(l))).collect()
}

/// Number of messages (data files are validated before use; see `crate::data`).
pub(crate) fn validate(text: &str) -> crate::Result<usize> {
    Ok(text.lines().map(str::trim).filter(|l| !l.is_empty() && !l.starts_with('#')).count())
}

static SET: LazyLock<RegexSet> = LazyLock::new(|| RegexSet::new(patterns()).unwrap());
static REGEXES: LazyLock<Vec<Regex>> = LazyLock::new(|| patterns().iter().map(|p| Regex::new(p).unwrap()).collect());

pub struct DebugErrors;

impl PassiveRule for DebugErrors {
    fn id(&self) -> u32 {
        10023
    }

    fn name(&self) -> &'static str {
        "Information Disclosure - Debug Error Messages"
    }

    fn alerts(&self) -> &'static [&'static AlertDef] {
        &ALERTS
    }

    fn scan(&self, msg: &Message, out: &mut Vec<Finding>) {
        if msg.resp_body.is_empty() || !is_text(msg) || is_javascript(msg) {
            return;
        }
        let body = msg.body();
        // The first message in file order that occurs anywhere wins.
        if let Some(i) = SET.matches(body).iter().next() {
            if let Some(m) = REGEXES[i].find(body) {
                out.push(ALERT.raise("", m.as_str()));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scan::passive::util::testing::msg;

    #[test]
    fn flags_debug_message_case_insensitively() {
        let f = msg("https://a.test/")
            .html("<b>php warning</b>: something; also an internal server error")
            .scan(&DebugErrors);
        assert_eq!(f.len(), 1);
        // "Internal Server Error" precedes "PHP Warning" in the file.
        assert_eq!(f[0].evidence, "internal server error");
    }

    #[test]
    fn ignores_javascript_and_clean_pages() {
        assert!(msg("https://a.test/").html("<p>All good</p>").scan(&DebugErrors).is_empty());
        let js = msg("https://a.test/a.js").header("Content-Type", "text/plain").body("PHP Warning");
        assert!(js.scan(&DebugErrors).is_empty());
        assert!(msg("https://a.test/").body("PHP Warning").scan(&DebugErrors).is_empty());
    }
}
