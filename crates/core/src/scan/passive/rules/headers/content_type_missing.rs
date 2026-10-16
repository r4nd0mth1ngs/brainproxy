//! Ported from ZAP ContentTypeMissingScanRule (pscanrules, Apache License 2.0).

use super::common::header_values;
use crate::scan::{AlertDef, Confidence, Finding, Message, PassiveRule, Risk};

const DESC: &str = "The Content-Type header was either missing or empty.";
const SOLN: &str = "Ensure each page is setting the specific and appropriate content-type value for the content \
    being delivered.";
const REFS: &[&str] = &[
    "https://learn.microsoft.com/en-us/previous-versions/windows/internet-explorer/ie-developer/compatibility/gg622941(v=vs.85)",
];
const TAGS: &[&str] = &["OWASP_2025_A02", "OWASP_2021_A05", "OWASP_2017_A06", "SYSTEMIC"];

static MISSING: AlertDef = AlertDef {
    alert_ref: "10019-1",
    name: "Content-Type Header Missing",
    risk: Risk::Info,
    confidence: Confidence::Medium,
    cwe: 345,
    wasc: 12,
    description: DESC,
    solution: SOLN,
    references: REFS,
    tags: TAGS,
};

static EMPTY: AlertDef = AlertDef {
    alert_ref: "10019-2",
    name: "Content-Type Header Empty",
    risk: Risk::Info,
    confidence: Confidence::Medium,
    cwe: 345,
    wasc: 12,
    description: DESC,
    solution: SOLN,
    references: REFS,
    tags: TAGS,
};

static ALERTS: [&AlertDef; 2] = [&MISSING, &EMPTY];

pub struct ContentTypeMissing;

impl PassiveRule for ContentTypeMissing {
    fn id(&self) -> u32 {
        10019
    }

    fn name(&self) -> &'static str {
        "Content-Type Header Missing"
    }

    fn alerts(&self) -> &'static [&'static AlertDef] {
        &ALERTS
    }

    fn scan(&self, msg: &Message, out: &mut Vec<Finding>) {
        if msg.resp_body.is_empty() {
            return;
        }
        let mut any = false;
        for v in header_values(msg, "Content-Type") {
            any = true;
            if v.is_empty() {
                out.push(EMPTY.raise("Content-Type", ""));
            }
        }
        if !any {
            out.push(MISSING.raise("Content-Type", ""));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scan::passive::util::testing::msg;

    #[test]
    fn flags_missing_and_empty() {
        let f = msg("https://a.test/").body("x").scan(&ContentTypeMissing);
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].def.alert_ref, "10019-1");
        let f = msg("https://a.test/").header("Content-Type", " ").body("x").scan(&ContentTypeMissing);
        assert_eq!(f.len(), 1);
        assert_eq!((f[0].def.alert_ref, f[0].param.as_str()), ("10019-2", "Content-Type"));
    }

    #[test]
    fn ignores_present_or_empty_body() {
        assert!(msg("https://a.test/").html("<p>").scan(&ContentTypeMissing).is_empty());
        assert!(msg("https://a.test/").scan(&ContentTypeMissing).is_empty());
    }
}
