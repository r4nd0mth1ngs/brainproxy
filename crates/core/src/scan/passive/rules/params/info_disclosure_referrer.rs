//! Ported from ZAP InformationDisclosureReferrerScanRule (pscanrules, Apache License 2.0).

use super::common::{is_valid_luhn, CREDIT_CARD, EMAIL, SENSITIVE_STRINGS, SSN};
use crate::scan::passive::util::url_host;
use crate::scan::{AlertDef, Confidence, Finding, Message, PassiveRule, Risk};

static ALERT: AlertDef = AlertDef {
    alert_ref: "10025",
    name: "Information Disclosure - Sensitive Information in HTTP Referrer Header",
    risk: Risk::Info,
    confidence: Confidence::Medium,
    cwe: 598,
    wasc: 13,
    description: "The HTTP header may have leaked a potentially sensitive parameter to another domain. This can \
        violate PCI and most organizational compliance policies. You can configure the list of strings for this \
        check to add or remove values specific to your environment.",
    solution: "Do not pass sensitive information in URIs.",
    references: &[],
    tags: &["OWASP_2025_A01", "OWASP_2021_A01", "OWASP_2017_A03", "SYSTEMIC"],
};

static ALERTS: [&AlertDef; 1] = [&ALERT];

/// ZAP's sameDomain: a path-only referer, or one whose (parsable) URL host is the request host.
fn same_domain(host: &str, referer: &str) -> bool {
    if referer.starts_with('/') {
        return true;
    }
    // commons-httpclient parses it as an escaped URI: unparsable means "not the same".
    let parsable = !referer.contains(|c: char| c.is_whitespace() || c.is_control() || "\"<>\\^`{|}".contains(c));
    parsable && url_host(referer).is_some_and(|h| h.eq_ignore_ascii_case(host))
}

pub struct InformationDisclosureReferrer;

impl PassiveRule for InformationDisclosureReferrer {
    fn id(&self) -> u32 {
        10025
    }

    fn name(&self) -> &'static str {
        "Information Disclosure - Sensitive Information in HTTP Referrer Header"
    }

    fn alerts(&self) -> &'static [&'static AlertDef] {
        &ALERTS
    }

    fn scan(&self, msg: &Message, out: &mut Vec<Finding>) {
        let Some(first) = msg.req_header("referer") else { return };
        if same_domain(&msg.host, first) {
            return;
        }
        for r in msg.req_headers_named("referer") {
            let lc = r.to_lowercase();
            if let Some((start, s)) = SENSITIVE_STRINGS.iter().find_map(|s| lc.find(s).map(|i| (i, s))) {
                // Report the text as written; fall back to the list entry if lower-casing moved offsets.
                let evidence = r.get(start..start + s.len()).filter(|e| e.eq_ignore_ascii_case(s)).unwrap_or(s);
                out.push(
                    ALERT.raise("", evidence).other_info(
                        "The URL in the HTTP referrer header field appears to contain sensitive information.",
                    ),
                );
            }
            if let Some(m) = CREDIT_CARD.find(r) {
                if is_valid_luhn(m.as_str()) {
                    out.push(ALERT.raise("", m.as_str()).other_info(
                        "The URL in the HTTP referrer header field appears to contain credit card information.",
                    ));
                }
            }
            if let Some(m) = EMAIL.find(r) {
                out.push(
                    ALERT
                        .raise("", m.as_str())
                        .other_info("The URL in the HTTP referrer header field contains email address(es)."),
                );
            }
            if let Some(m) = SSN.find(r) {
                out.push(ALERT.raise("", m.as_str()).other_info(
                    "The URL in the HTTP referrer header field appears to contain US Social Security Number(s).",
                ));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scan::passive::util::testing::msg;

    #[test]
    fn flags_sensitive_data_in_cross_site_referer() {
        let f = msg("https://a.test/")
            .req_header("Referer", "https://other.test/x?PassWord=1&cc=4111111111111111&m=a@b.org&s=123-45-6789")
            .scan(&InformationDisclosureReferrer);
        let ev: Vec<&str> = f.iter().map(|f| f.evidence.as_str()).collect();
        assert_eq!(ev, ["Pass", "4111111111111111", "a@b.org", "123-45-6789"]);
        assert_eq!(f[1].confidence, Confidence::Medium);
    }

    #[test]
    fn ignores_same_site_and_bad_luhn() {
        let same = msg("https://a.test/").req_header("Referer", "https://A.test/login?password=x");
        assert!(same.scan(&InformationDisclosureReferrer).is_empty());
        let rel = msg("https://a.test/").req_header("Referer", "/login?password=x");
        assert!(rel.scan(&InformationDisclosureReferrer).is_empty());
        let card = msg("https://a.test/").req_header("Referer", "https://o.test/?n=4111111111111112");
        assert!(card.scan(&InformationDisclosureReferrer).is_empty());
        assert!(msg("https://a.test/").scan(&InformationDisclosureReferrer).is_empty());
    }
}
