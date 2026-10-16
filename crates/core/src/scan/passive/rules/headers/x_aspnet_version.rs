//! Ported from ZAP XAspNetVersionScanRule (pscanrules, Apache License 2.0).

use super::common::header_values;
use crate::scan::{AlertDef, Confidence, Finding, Message, PassiveRule, Risk};

static ALERT: AlertDef = AlertDef {
    alert_ref: "10061",
    name: "X-AspNet-Version Response Header",
    risk: Risk::Low,
    confidence: Confidence::High,
    cwe: 933,
    wasc: 14,
    description: "Server leaks information via \"X-AspNet-Version\"/\"X-AspNetMvc-Version\" HTTP response header \
        field(s).",
    solution: "Configure the server so it will not return those headers.",
    references: &[
        "https://www.troyhunt.com/shhh-dont-let-your-response-headers/",
        "https://learn.microsoft.com/en-us/archive/blogs/varunm/remove-unwanted-http-response-headers",
    ],
    tags: &["OWASP_2025_A02", "OWASP_2021_A05", "OWASP_2017_A06", "WSTG-v42-INFO-08", "SYSTEMIC"],
};

static ALERTS: [&AlertDef; 1] = [&ALERT];

const OTHER_INFO: &str = "An attacker can use this information to exploit known vulnerabilities.";

pub struct XAspNetVersion;

impl PassiveRule for XAspNetVersion {
    fn id(&self) -> u32 {
        10061
    }

    fn name(&self) -> &'static str {
        "X-AspNet-Version Response Header"
    }

    fn alerts(&self) -> &'static [&'static AlertDef] {
        &ALERTS
    }

    fn scan(&self, msg: &Message, out: &mut Vec<Finding>) {
        for name in ["X-AspNet-Version", "X-AspNetMvc-Version"] {
            if let Some(v) = header_values(msg, name).next() {
                out.push(ALERT.raise("", v).other_info(OTHER_INFO));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scan::passive::util::testing::msg;

    #[test]
    fn flags_each_header_name_once() {
        let f = msg("https://a.test/")
            .header("X-AspNet-Version", "4.0.30319")
            .header("X-AspNet-Version", "2.0")
            .header("X-AspNetMvc-Version", "5.2")
            .scan(&XAspNetVersion);
        assert_eq!(f.len(), 2);
        assert_eq!((f[0].evidence.as_str(), f[1].evidence.as_str()), ("4.0.30319", "5.2"));
        assert_eq!(f[0].other_info, OTHER_INFO);
    }

    #[test]
    fn ignores_other_headers() {
        assert!(msg("https://a.test/").header("X-Powered-By", "ASP.NET").scan(&XAspNetVersion).is_empty());
    }
}
