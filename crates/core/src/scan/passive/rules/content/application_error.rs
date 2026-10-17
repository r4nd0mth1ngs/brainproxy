//! Ported from ZAP ApplicationErrorScanRule (pscanrules, Apache License 2.0).

use std::sync::LazyLock;

use regex::{Regex, RegexSet};

use super::common::{is_css, is_javascript, xml_unescape};
use crate::scan::{AlertDef, Confidence, Finding, Message, PassiveRule, Risk};

static ALERT: AlertDef = AlertDef {
    alert_ref: "90022",
    name: "Application Error Disclosure",
    risk: Risk::Medium,
    confidence: Confidence::Medium,
    cwe: 550,
    wasc: 13,
    description: "This page contains an error/warning message that may disclose sensitive information like the \
        location of the file that produced the unhandled exception. This information can be used to launch further \
        attacks against the web application. The alert could be a false positive if the error message is found \
        inside a documentation page.",
    solution: "Review the source code of this page. Implement custom error pages. Consider implementing a mechanism \
        to provide a unique error reference/identifier to the client (browser) while logging the details on the \
        server side and not exposing them to the user.",
    references: &[],
    tags: &["OWASP_2025_A02", "OWASP_2021_A05", "OWASP_2017_A06", "WSTG-v42-ERRH-01", "WSTG-v42-ERRH-02"],
};

static ALERTS: [&AlertDef; 1] = [&ALERT];

pub(crate) const EMBEDDED: &str = include_str!("../../data/application_errors.xml");

/// ZAP's ContentMatcher patterns: (literal strings, regexes), each in file order.
struct Matcher {
    strings: Vec<String>,
    string_set: RegexSet,
    regexes: Vec<Regex>,
    regex_set: RegexSet,
}

/// Java regex escapes that mean something else (or nothing) in Rust: `\<` and
/// `\>` are literals in Java but word-boundary assertions in Rust.
fn java_regex_to_rust(p: &str) -> String {
    p.replace(r"\<", "<").replace(r"\>", ">")
}

fn parse_patterns(data: &str) -> (Vec<String>, Vec<String>) {
    let (mut strings, mut regexes) = (Vec::new(), Vec::new());
    let mut rest = data;
    while let Some(i) = rest.find("<Pattern ") {
        rest = &rest[i..];
        let Some(gt) = rest.find('>') else { break };
        let attrs = &rest[..gt];
        let Some(end) = rest.find("</Pattern>") else { break };
        let text = xml_unescape(&rest[gt + 1..end]);
        if attrs.contains("type=\"regex\"") {
            regexes.push(java_regex_to_rust(&text));
        } else {
            strings.push(text);
        }
        rest = &rest[end..];
    }
    (strings, regexes)
}

static MATCHER: LazyLock<Matcher> = LazyLock::new(|| {
    let (strings, regex_src) = parse_patterns(crate::data::get("application_errors.xml"));
    let string_set = RegexSet::new(strings.iter().map(|s| regex::escape(s))).unwrap();
    let regexes = regex_src.iter().map(|r| Regex::new(r).unwrap()).collect();
    let regex_set = RegexSet::new(&regex_src).unwrap();
    Matcher { strings, string_set, regexes, regex_set }
});

/// Number of patterns; every regex must compile (see `crate::data`).
pub(crate) fn validate(text: &str) -> crate::Result<usize> {
    let (strings, regexes) = parse_patterns(text);
    RegexSet::new(&regexes).map_err(|e| crate::Error::InvalidInput(e.to_string()))?;
    Ok(strings.len() + regexes.len())
}

/// ResourceIdentificationUtils.responseContainsControlChars: binary content.
fn contains_control_chars(body: &[u8]) -> bool {
    body.iter().any(|&b| b <= 0x08 || (0x0E..=0x1F).contains(&b))
}

pub struct ApplicationError;

impl PassiveRule for ApplicationError {
    fn id(&self) -> u32 {
        90022
    }

    fn name(&self) -> &'static str {
        "Application Error Disclosure"
    }

    fn alerts(&self) -> &'static [&'static AlertDef] {
        &ALERTS
    }

    fn scan(&self, msg: &Message, out: &mut Vec<Finding>) {
        if contains_control_chars(&msg.resp_body) {
            return;
        }
        if msg.status == 500 {
            out.push(ALERT.raise("", "HTTP/1.1 500 Internal Server Error").risk(Risk::Low));
            return;
        }
        if msg.status == 404
            || msg.content_type().contains("application/wasm")
            || is_javascript(msg)
            || is_css(msg)
            || msg.resp_body.is_empty()
        {
            return;
        }
        let body = msg.body();
        let m = &*MATCHER;
        // All literal strings first, then the regexes; first in file order wins.
        if let Some(i) = m.string_set.matches(body).iter().next() {
            out.push(ALERT.raise("", m.strings[i].as_str()));
        } else if let Some(i) = m.regex_set.matches(body).iter().next() {
            if let Some(found) = m.regexes[i].find(body) {
                out.push(ALERT.raise("", found.as_str()));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scan::passive::util::testing::msg;

    #[test]
    fn all_patterns_compile() {
        let m = &*MATCHER;
        assert_eq!(m.strings.len(), 88);
        assert_eq!(m.regexes.len(), 22);
        assert!(m.regexes.iter().any(|r| r.as_str().contains(r"\&quot\;\\\&quot;")));
    }

    #[test]
    fn flags_strings_before_regexes() {
        let f = msg("https://a.test/")
            .html("ORA-01756: quoted string; You have an error in your SQL syntax near")
            .scan(&ApplicationError);
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].evidence, "You have an error in your SQL syntax");
        let f = msg("https://a.test/").html("<p>ora-00933: SQL command</p>").scan(&ApplicationError);
        assert_eq!(f[0].evidence, "ora-00933: ");
        let php = "<b>Warning</b>:  include(x.php) in <b>/var/www/a.php</b> on line <b>3</b><br />";
        assert_eq!(msg("https://a.test/").html(php).scan(&ApplicationError)[0].evidence, php);
    }

    #[test]
    fn status_500_is_low() {
        let f = msg("https://a.test/").status(500).html("oops").scan(&ApplicationError);
        assert_eq!((f.len(), f[0].risk), (1, Risk::Low));
    }

    #[test]
    fn ignores_404_js_and_clean_pages() {
        assert!(msg("https://a.test/").status(404).html("internal error").scan(&ApplicationError).is_empty());
        let js = msg("https://a.test/app.js").header("Content-Type", "application/javascript").body("internal error");
        assert!(js.scan(&ApplicationError).is_empty());
        assert!(msg("https://a.test/").html("<p>hello</p>").scan(&ApplicationError).is_empty());
    }
}
