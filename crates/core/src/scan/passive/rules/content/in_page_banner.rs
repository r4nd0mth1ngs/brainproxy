//! Ported from ZAP InPageBannerInfoLeakScanRule (pscanrules, Apache License 2.0).

use std::sync::LazyLock;

use regex::{Regex, RegexSet};

use crate::scan::{AlertDef, Confidence, Finding, Message, PassiveRule, Risk};

static ALERT: AlertDef = AlertDef {
    alert_ref: "10009",
    name: "In Page Banner Information Leak",
    risk: Risk::Low,
    confidence: Confidence::High,
    cwe: 497,
    wasc: 13,
    description: "The server returned a version banner string in the response content. Such information leaks may \
        allow attackers to further target specific issues impacting the product and version in use.",
    solution: "Configure the server to prevent such information leaks. For example:\nUnder Tomcat this is done via \
        the \"server\" directive and implementation of custom error pages.\nUnder Apache this is done via the \
        \"ServerSignature\" and \"ServerTokens\" directives.",
    references: &[
        "https://owasp.org/www-project-web-security-testing-guide/v41/4-Web_Application_Security_Testing/08-Testing_for_Error_Handling/",
    ],
    tags: &["OWASP_2025_A02", "OWASP_2021_A05", "OWASP_2017_A06", "WSTG-v42-INFO-02", "SYSTEMIC"],
};

static ALERTS: [&AlertDef; 1] = [&ALERT];

const OTHER: &str = "There is a chance that the highlight in the finding is on a value in the headers, versus the \
    actual matched string in the response body.";

/// Tomcat, Apache, nginx, Jetty, Squid, in ZAP's order. Diverges from ZAP: Express, last,
/// as an error page built with its error handler names it (`App (Express ^4.22.1)`);
/// case-sensitive and with a full version, so prose about "express" doesn't count.
const PATTERNS: [&str; 6] = [
    r"(?i)Tomcat/[0-9]\.[0-9]\.[0-9]{1,2}",
    r"(?i)Apache/[0-9]\.[0-9]\.[0-9]{1,2}",
    r"(?i)nginx/[0-9]\.[0-9]{1,2}\.[0-9]{1,2}",
    r"(?i)Jetty://[0-9]\.[0-9]{1,2}",
    r"(?i)squid/[0-9]\.[0-9]{1,2}",
    r"\bExpress [\^~]?[0-9]{1,2}\.[0-9]{1,3}\.[0-9]{1,3}\b",
];

static SET: LazyLock<RegexSet> = LazyLock::new(|| RegexSet::new(PATTERNS).unwrap());
static REGEXES: LazyLock<Vec<Regex>> = LazyLock::new(|| PATTERNS.iter().map(|p| Regex::new(p).unwrap()).collect());

pub struct InPageBanner;

impl PassiveRule for InPageBanner {
    fn id(&self) -> u32 {
        10009
    }

    fn name(&self) -> &'static str {
        "In Page Banner Information Leak"
    }

    fn alerts(&self) -> &'static [&'static AlertDef] {
        &ALERTS
    }

    fn scan(&self, msg: &Message, out: &mut Vec<Finding>) {
        if !(msg.is_client_error() || msg.is_server_error()) {
            return;
        }
        let body = msg.body();
        // The first pattern (in list order) that matches anywhere wins.
        if let Some(i) = SET.matches(body).iter().next() {
            if let Some(m) = REGEXES[i].find(body) {
                out.push(ALERT.raise("", m.as_str()).other_info(OTHER));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scan::passive::util::testing::msg;

    #[test]
    fn flags_banner_in_error_page() {
        let f = msg("https://a.test/")
            .status(404)
            .html("<hr><address>nginx/1.18.0 at a.test; Apache/2.4.41 (Ubuntu)</address>")
            .scan(&InPageBanner);
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].evidence, "Apache/2.4.41");
    }

    /// Express's error handler page names the framework and its version range.
    #[test]
    fn flags_express_version_in_error_page() {
        let page = "<h1>OWASP Juice Shop (Express ^4.22.1)</h1><h2><em>500</em> Error</h2>";
        let f = msg("https://a.test/rest/x").status(500).html(page).scan(&InPageBanner);
        assert_eq!(f[0].evidence, "Express ^4.22.1");
        assert!(msg("https://a.test/").html(page).scan(&InPageBanner).is_empty());
        let prose = "<p>Built with Express 4 and Angular.</p>";
        assert!(msg("https://a.test/").status(404).html(prose).scan(&InPageBanner).is_empty());
    }

    #[test]
    fn ignores_success_and_unversioned() {
        assert!(msg("https://a.test/").html("Apache/2.4.41").scan(&InPageBanner).is_empty());
        assert!(msg("https://a.test/").status(500).html("Apache Tomcat").scan(&InPageBanner).is_empty());
    }
}
