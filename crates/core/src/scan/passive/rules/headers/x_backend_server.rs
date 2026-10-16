//! Ported from ZAP XBackendServerInformationLeakScanRule (pscanrules, Apache License 2.0).

use super::common::header_values;
use crate::scan::{AlertDef, Confidence, Finding, Message, PassiveRule, Risk};

static ALERT: AlertDef = AlertDef {
    alert_ref: "10039",
    name: "X-Backend-Server Header Information Leak",
    risk: Risk::Low,
    confidence: Confidence::Medium,
    cwe: 497,
    wasc: 13,
    description: "The server is leaking information pertaining to backend systems (such as hostnames or IP \
        addresses). Armed with this information an attacker may be able to attack other systems or more \
        directly/efficiently attack those systems.",
    solution: "Ensure that your web server, application server, load balancer, etc. is configured to suppress \
        X-Backend-Server headers.",
    references: &[],
    tags: &["OWASP_2025_A02", "OWASP_2021_A05", "OWASP_2017_A06", "WSTG-v42-INFO-02", "SYSTEMIC"],
};

static ALERTS: [&AlertDef; 1] = [&ALERT];

pub struct XBackendServer;

impl PassiveRule for XBackendServer {
    fn id(&self) -> u32 {
        10039
    }

    fn name(&self) -> &'static str {
        "X-Backend-Server Header Information Leak"
    }

    fn alerts(&self) -> &'static [&'static AlertDef] {
        &ALERTS
    }

    fn scan(&self, msg: &Message, out: &mut Vec<Finding>) {
        for v in header_values(msg, "X-Backend-Server") {
            out.push(ALERT.raise("", v));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scan::passive::util::testing::msg;

    #[test]
    fn flags_each_header() {
        let f = msg("https://a.test/")
            .header("X-Backend-Server", "dev.local")
            .header("x-backend-server", "10.0.0.1")
            .scan(&XBackendServer);
        assert_eq!(f.len(), 2);
        assert_eq!(f[0].evidence, "dev.local");
        assert_eq!(f[1].evidence, "10.0.0.1");
    }

    #[test]
    fn ignores_absent_header() {
        assert!(msg("https://a.test/").header("Server", "x").scan(&XBackendServer).is_empty());
    }
}
