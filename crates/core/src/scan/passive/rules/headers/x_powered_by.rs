//! Ported from ZAP XPoweredByHeaderInfoLeakScanRule (pscanrules, Apache License 2.0).

use super::common::{header_lines, starts_with_ci};
use crate::scan::{AlertDef, Confidence, Finding, Message, PassiveRule, Risk};

static ALERT: AlertDef = AlertDef {
    alert_ref: "10037",
    name: "Server Leaks Information via \"X-Powered-By\" HTTP Response Header Field(s)",
    risk: Risk::Low,
    confidence: Confidence::Medium,
    cwe: 497,
    wasc: 13,
    description: "The web/application server is leaking information via one or more \"X-Powered-By\" HTTP response \
        headers. Access to such information may facilitate attackers identifying other frameworks/components your \
        web application is reliant upon and the vulnerabilities such components may be subject to.",
    solution: "Ensure that your web server, application server, load balancer, etc. is configured to suppress \
        \"X-Powered-By\" headers.",
    references: &[
        "https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/01-Information_Gathering/08-Fingerprint_Web_Application_Framework",
        "https://www.troyhunt.com/shhh-dont-let-your-response-headers/",
    ],
    tags: &["OWASP_2025_A01", "OWASP_2021_A01", "OWASP_2017_A03", "WSTG-v42-INFO-08", "SYSTEMIC"],
};

static ALERTS: [&AlertDef; 1] = [&ALERT];

pub struct XPoweredBy;

impl PassiveRule for XPoweredBy {
    fn id(&self) -> u32 {
        10037
    }

    fn name(&self) -> &'static str {
        "Server Leaks Information via \"X-Powered-By\" HTTP Response Header Field(s)"
    }

    fn alerts(&self) -> &'static [&'static AlertDef] {
        &ALERTS
    }

    fn scan(&self, msg: &Message, out: &mut Vec<Finding>) {
        if msg.resp_header("X-Powered-By").is_none() {
            return;
        }
        // ZAP collects every header line matching ^X-Powered-By.* (a prefix match).
        let mut lines = header_lines(msg).filter(|l| starts_with_ci(l, "X-Powered-By"));
        let Some(evidence) = lines.next() else { return };
        let mut other = String::new();
        for l in lines {
            if other.is_empty() {
                other.push_str("The following X-Powered-By headers were also found:\n");
            }
            other.push_str(&l);
            other.push_str("\r\n");
        }
        out.push(ALERT.raise("", evidence).other_info(other));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scan::passive::util::testing::msg;

    #[test]
    fn flags_with_extra_headers_listed() {
        let f = msg("https://a.test/")
            .header("X-Powered-By", "PHP/5.4")
            .header("x-powered-by", "ASP.NET")
            .header("X-Powered-By-Plesk", "PleskLin")
            .scan(&XPoweredBy);
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].evidence, "X-Powered-By: PHP/5.4");
        assert_eq!(
            f[0].other_info,
            "The following X-Powered-By headers were also found:\nx-powered-by: ASP.NET\r\nX-Powered-By-Plesk: PleskLin\r\n"
        );
        let f = msg("https://a.test/").header("X-Powered-By", "Express").scan(&XPoweredBy);
        assert_eq!((f[0].evidence.as_str(), f[0].other_info.as_str()), ("X-Powered-By: Express", ""));
    }

    #[test]
    fn ignores_only_prefixed_header() {
        assert!(msg("https://a.test/").header("X-Powered-By-Plesk", "PleskLin").scan(&XPoweredBy).is_empty());
    }
}
