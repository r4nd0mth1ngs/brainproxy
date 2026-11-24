//! Ported from ZAP JsFunctionScanRule (pscanrulesBeta, Apache License 2.0).
//!
//! The function names are ZAP's `js-function-list.txt`, refreshed by `scan data update`. ZAP's
//! custom payloads (its "JS-Function" category) have no counterpart here.

use std::sync::LazyLock;

use regex::Regex;

use super::common::{data_lines, element_source, is_javascript};
use crate::scan::passive::util::tags;
use crate::scan::{AlertDef, Confidence, Finding, Message, PassiveRule, Risk};

static ALERT: AlertDef = AlertDef {
    alert_ref: "10110",
    name: "Dangerous JS Functions",
    risk: Risk::Low,
    confidence: Confidence::Low,
    cwe: 749,
    wasc: 0,
    description: "A dangerous JS function seems to be in use that would leave the site vulnerable.",
    solution: "See the references for security advice on the use of these functions.",
    references: &["https://v17.angular.io/guide/security"],
    tags: &["OWASP_2025_A06", "OWASP_2021_A04", "WSTG-v42-CLNT-02"],
};

static ALERTS: [&AlertDef; 1] = [&ALERT];

pub(crate) const EMBEDDED: &str = include_str!("../../data/js-function-list.txt");

/// ZAP's pattern for a listed name: a call, `$` optional (it is taken out of the name).
fn pattern(name: &str) -> String {
    format!(r"(?i)\b\$?{}\s{{0,5}}\(", name.replace('$', ""))
}

/// The data file's entries, each a pattern that compiles.
pub(crate) fn validate(text: &str) -> crate::Result<usize> {
    let lines: Vec<&str> = text.lines().map(str::trim).filter(|l| !l.is_empty() && !l.starts_with('#')).collect();
    for l in &lines {
        Regex::new(&pattern(l)).map_err(|e| crate::Error::InvalidInput(format!("{l:?}: {e}")))?;
    }
    Ok(lines.len())
}

/// In the list's order: the first that matches gives the evidence.
static PATTERNS: LazyLock<Vec<Regex>> = LazyLock::new(|| {
    data_lines(crate::data::get("js-function-list.txt")).filter_map(|l| Regex::new(&pattern(l)).ok()).collect()
});

fn first_call(text: &str) -> Option<&str> {
    PATTERNS.iter().find_map(|p| p.find(text).map(|m| m.as_str()))
}

pub struct JsFunction;

impl PassiveRule for JsFunction {
    fn id(&self) -> u32 {
        10110
    }

    fn name(&self) -> &'static str {
        "Dangerous JS Functions"
    }

    fn alerts(&self) -> &'static [&'static AlertDef] {
        &ALERTS
    }

    fn scan(&self, msg: &Message, out: &mut Vec<Finding>) {
        if msg.resp_body.is_empty() {
            return;
        }
        let body = msg.body();
        let evidence = if msg.is_html() {
            // The page's script elements, tags included, in order.
            tags(body).iter().filter(|t| t.name == "script").find_map(|t| first_call(element_source(body, t)))
        } else if is_javascript(msg) {
            first_call(body)
        } else {
            None
        };
        if let Some(e) = evidence {
            out.push(ALERT.raise("", e));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scan::passive::util::testing::msg;

    #[test]
    fn a_call_in_a_script_or_a_javascript_file() {
        let f = msg("https://a.test/")
            .html("<p>eval(x) in text</p><script>var a = 1;</script><script>$scope.$evalAsync (fn)</script>")
            .scan(&JsFunction);
        // `\b` never stands before a `$` that follows `.`, so (as in ZAP) the match starts at the name.
        assert_eq!((f.len(), f[0].evidence.as_str()), (1, "evalAsync ("));
        let f = msg("https://a.test/app.js").body("x = this.sanitizer.bypassSecurityTrustHtml(v);").scan(&JsFunction);
        assert_eq!(f[0].evidence, "bypassSecurityTrustHtml(");
    }

    #[test]
    fn text_names_and_other_types_pass() {
        assert!(msg("https://a.test/")
            .html("<p>eval(x)</p><script>evaluate(1); medieval (2)</script>")
            .scan(&JsFunction)
            .is_empty());
        assert!(msg("https://a.test/a.json")
            .header("Content-Type", "application/json")
            .body("{\"f\":\"eval(1)\"}")
            .scan(&JsFunction)
            .is_empty());
    }

    #[test]
    fn the_list_validates() {
        assert_eq!(validate(EMBEDDED).unwrap(), 10);
    }
}
