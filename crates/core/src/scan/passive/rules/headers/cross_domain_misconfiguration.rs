//! Ported from ZAP CrossDomainMisconfigurationScanRule (pscanrules, Apache License 2.0).

use super::common::{header_first, headers_block};
use crate::scan::{AlertDef, Confidence, Finding, Message, PassiveRule, Risk};

static ALERT: AlertDef = AlertDef {
    alert_ref: "10098",
    name: "Cross-Domain Misconfiguration",
    risk: Risk::Medium,
    confidence: Confidence::Medium,
    cwe: 264,
    wasc: 14,
    description: "Web browser data loading may be possible, due to a Cross Origin Resource Sharing (CORS) \
        misconfiguration on the web server.",
    solution: "Ensure that sensitive data is not available in an unauthenticated manner (using IP address \
        white-listing, for instance).\nConfigure the \"Access-Control-Allow-Origin\" HTTP header to a more \
        restrictive set of domains, or remove all CORS headers entirely, to allow the web browser to enforce the \
        Same Origin Policy (SOP) in a more restrictive manner.",
    references: &[
        "https://vulncat.fortify.com/en/detail?category=HTML5&subcategory=Overly%20Permissive%20CORS%20Policy",
    ],
    tags: &["OWASP_2025_A01", "OWASP_2021_A01", "OWASP_2017_A05", "SYSTEMIC"],
};

static ALERTS: [&AlertDef; 1] = [&ALERT];

const OTHER_INFO: &str = "The CORS misconfiguration on the web server permits cross-domain read requests from \
    arbitrary third party domains, using unauthenticated APIs on this domain. Web browser implementations do not \
    permit arbitrary third parties to read the response from authenticated APIs, however. This reduces the risk \
    somewhat. This misconfiguration could be used by an attacker to access data that is available in an \
    unauthenticated manner, but which uses some other form of security, such as IP address white-listing.";

const ACAO: &str = "access-control-allow-origin";

pub struct CrossDomainMisconfiguration;

impl PassiveRule for CrossDomainMisconfiguration {
    fn id(&self) -> u32 {
        10098
    }

    fn name(&self) -> &'static str {
        "Cross-Domain Misconfiguration"
    }

    fn alerts(&self) -> &'static [&'static AlertDef] {
        &ALERTS
    }

    fn scan(&self, msg: &Message, out: &mut Vec<Finding>) {
        if header_first(msg, ACAO) != Some("*") {
            return;
        }
        // Evidence: from the first textual occurrence in the header block to the end of that line.
        let block = headers_block(msg);
        let lower = block.to_ascii_lowercase();
        let Some(start) = lower.find(ACAO) else { return };
        let end = block[start..].find('\r').map(|e| start + e).unwrap_or(block.len());
        out.push(ALERT.raise("", &block[start..end]).other_info(OTHER_INFO));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scan::passive::util::testing::msg;

    #[test]
    fn flags_wildcard_origin() {
        let f = msg("https://a.test/").header("Access-Control-Allow-Origin", "*").scan(&CrossDomainMisconfiguration);
        assert_eq!((f.len(), f[0].evidence.as_str()), (1, "Access-Control-Allow-Origin: *"));
        assert_eq!(f[0].other_info, OTHER_INFO);
    }

    #[test]
    fn ignores_specific_origin() {
        let m = msg("https://a.test/").header("Access-Control-Allow-Origin", "https://b.test");
        assert!(m.scan(&CrossDomainMisconfiguration).is_empty());
        assert!(msg("https://a.test/").scan(&CrossDomainMisconfiguration).is_empty());
    }
}
