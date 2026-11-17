//! Ported from ZAP InformationDisclosureDebugErrorsScanRule (pscanrules, Apache License 2.0).

use std::sync::LazyLock;

use regex::{Regex, RegexSet};

use super::common::{data_lines, generic_in_data, is_javascript, is_source_map, is_text};
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
        // Diverges from ZAP: source maps (library code in strings) aren't read, and a generic
        // phrase in JSON data (a hint, a translation) isn't taken for an error message.
        if msg.resp_body.is_empty() || !is_text(msg) || is_javascript(msg) || is_source_map(msg) {
            return;
        }
        let body = msg.body();
        // The first message in file order that occurs anywhere wins.
        let found =
            SET.matches(body).iter().filter_map(|i| REGEXES[i].find(body)).find(|m| !generic_in_data(msg, m.as_str()));
        if let Some(m) = found {
            out.push(ALERT.raise("", m.as_str()));
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

    /// Juice Shop's /api/Hints and an Angular translation file have "Internal Server Error" in
    /// their text; a source map has library code. None of them is an error page.
    #[test]
    fn ignores_generic_phrases_in_json_data_and_source_maps() {
        let json = |status: u16, body: &str| {
            msg("https://a.test/api/Hints").status(status).header("Content-Type", "application/json").body(body)
        };
        let hint = r#"{"data":[{"text":"500 Internal Server Error is always an interesting status code"}]}"#;
        assert!(json(200, hint).scan(&DebugErrors).is_empty());
        assert_eq!(json(500, hint).scan(&DebugErrors).len(), 1);
        // A specific message still counts in data.
        assert_eq!(json(200, r#"{"e":"PHP Warning: x"}"#).scan(&DebugErrors)[0].evidence, "PHP Warning");
        let map = msg("https://a.test/main.js.map").header("Content-Type", "application/json");
        assert!(map.body(r#"{"version":3,"sourcesContent":["throw 'PHP Warning'"]}"#).scan(&DebugErrors).is_empty());
    }

    #[test]
    fn ignores_javascript_and_clean_pages() {
        assert!(msg("https://a.test/").html("<p>All good</p>").scan(&DebugErrors).is_empty());
        let js = msg("https://a.test/a.js").header("Content-Type", "text/plain").body("PHP Warning");
        assert!(js.scan(&DebugErrors).is_empty());
        assert!(msg("https://a.test/").body("PHP Warning").scan(&DebugErrors).is_empty());
    }
}
