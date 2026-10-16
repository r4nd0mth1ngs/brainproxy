//! Ported from ZAP XDebugTokenScanRule (pscanrules, Apache License 2.0).

use super::common::first_line_with_prefix;
use crate::scan::{AlertDef, Confidence, Finding, Message, PassiveRule, Risk};

static ALERT: AlertDef = AlertDef {
    alert_ref: "10056",
    name: "X-Debug-Token Information Leak",
    risk: Risk::Low,
    confidence: Confidence::High,
    cwe: 489,
    wasc: 13,
    description: "The response contained an X-Debug-Token or X-Debug-Token-Link header. This indicates that \
        Symfony's Profiler may be in use and exposing sensitive data.",
    solution: "Limit access to Symfony's Profiler, either via authentication/authorization or limiting inclusion \
        of the header to specific clients (by IP, etc.).",
    references: &[
        "https://symfony.com/doc/current/profiler.html",
        "https://symfony.com/blog/new-in-symfony-2-4-quicker-access-to-the-profiler-when-working-on-an-api",
    ],
    tags: &["OWASP_2025_A01", "OWASP_2021_A01", "OWASP_2017_A03", "WSTG-v42-ERRH-01", "SYSTEMIC"],
};

static ALERTS: [&AlertDef; 1] = [&ALERT];

const OTHER_INFO: &str = "By accessing a URL in the form https://target_host/_profiler/token_value (i.e.: \
    https://example.com/_profiler_/123ab4), you may gain access to the profiler and further leaked information.";

pub struct XDebugToken;

impl PassiveRule for XDebugToken {
    fn id(&self) -> u32 {
        10056
    }

    fn name(&self) -> &'static str {
        "X-Debug-Token Information Leak"
    }

    fn alerts(&self) -> &'static [&'static AlertDef] {
        &ALERTS
    }

    fn scan(&self, msg: &Message, out: &mut Vec<Finding>) {
        for header in ["X-Debug-Token-Link", "X-Debug-Token"] {
            if msg.resp_header(header).is_some() {
                let evidence = first_line_with_prefix(msg, header).unwrap_or_default();
                out.push(ALERT.raise("", evidence).other_info(OTHER_INFO));
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
    fn prefers_link_header() {
        let f = msg("https://a.test/")
            .header("X-Debug-Token", "123ab4")
            .header("X-Debug-Token-Link", "/_profiler/123ab4")
            .scan(&XDebugToken);
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].evidence, "X-Debug-Token-Link: /_profiler/123ab4");
        let f = msg("https://a.test/").header("x-debug-token", "123ab4").scan(&XDebugToken);
        assert_eq!(f[0].evidence, "x-debug-token: 123ab4");
    }

    #[test]
    fn ignores_absent_headers() {
        assert!(msg("https://a.test/").header("X-Debug", "1").scan(&XDebugToken).is_empty());
    }
}
