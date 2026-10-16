//! Ported from ZAP ServerHeaderInfoLeakScanRule (pscanrules, Apache License 2.0).
//!
//! The Info-level 10036-1 alert (Server header without a version) is only raised
//! by ZAP at LOW threshold and is not ported.

use super::common::header_values;
use crate::scan::{AlertDef, Confidence, Finding, Message, PassiveRule, Risk};

static VERSION_LEAK: AlertDef = AlertDef {
    alert_ref: "10036-2",
    name: "Server Leaks Version Information via \"Server\" HTTP Response Header Field",
    risk: Risk::Low,
    confidence: Confidence::High,
    cwe: 497,
    wasc: 13,
    description: "The web/application server is leaking version information via the \"Server\" HTTP response \
        header. Access to such information may facilitate attackers identifying other vulnerabilities your \
        web/application server is subject to.",
    solution: "Ensure that your web server, application server, load balancer, etc. is configured to suppress the \
        \"Server\" header or provide generic details.",
    references: &[
        "https://httpd.apache.org/docs/current/mod/core.html#servertokens",
        "https://learn.microsoft.com/en-us/previous-versions/msp-n-p/ff648552(v=pandp.10)",
        "https://www.troyhunt.com/shhh-dont-let-your-response-headers/",
    ],
    tags: &["OWASP_2025_A02", "OWASP_2021_A05", "OWASP_2017_A06", "WSTG-v42-INFO-02", "SYSTEMIC"],
};

static ALERTS: [&AlertDef; 1] = [&VERSION_LEAK];

pub struct ServerHeader;

impl PassiveRule for ServerHeader {
    fn id(&self) -> u32 {
        10036
    }

    fn name(&self) -> &'static str {
        "HTTP Server Response Header"
    }

    fn alerts(&self) -> &'static [&'static AlertDef] {
        &ALERTS
    }

    fn scan(&self, msg: &Message, out: &mut Vec<Finding>) {
        for v in header_values(msg, "Server") {
            // ZAP: ".*\d.*" with matches(), i.e. contains a digit ('.' never crosses a line break).
            if v.bytes().any(|b| b.is_ascii_digit()) && !v.contains(['\n', '\r']) {
                out.push(VERSION_LEAK.raise("", v));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scan::passive::util::testing::msg;

    #[test]
    fn flags_versioned_server() {
        let f = msg("https://a.test/").header("Server", "Apache/2.4.1 (Unix)").scan(&ServerHeader);
        assert_eq!((f.len(), f[0].evidence.as_str()), (1, "Apache/2.4.1 (Unix)"));
    }

    #[test]
    fn ignores_versionless_server() {
        assert!(msg("https://a.test/").header("Server", "nginx").scan(&ServerHeader).is_empty());
        assert!(msg("https://a.test/").scan(&ServerHeader).is_empty());
    }
}
