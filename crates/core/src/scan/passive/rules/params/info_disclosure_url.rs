//! Ported from ZAP InformationDisclosureInUrlScanRule (pscanrules, Apache License 2.0).

use super::common::{url_params, CREDIT_CARD, EMAIL, SENSITIVE_STRINGS, SSN};
use crate::scan::{AlertDef, Confidence, Finding, Message, PassiveRule, Risk};

static ALERT: AlertDef = AlertDef {
    alert_ref: "10024",
    name: "Information Disclosure - Sensitive Information in URL",
    risk: Risk::Info,
    confidence: Confidence::Medium,
    cwe: 598,
    wasc: 13,
    description: "The request appeared to contain sensitive information leaked in the URL. This can violate PCI and \
        most organizational compliance policies. You can configure the list of strings for this check to add or \
        remove values specific to your environment.",
    solution: "Do not pass sensitive information in URIs.",
    references: &[],
    tags: &["OWASP_2025_A01", "OWASP_2021_A01", "OWASP_2017_A03", "SYSTEMIC"],
};

static ALERTS: [&AlertDef; 1] = [&ALERT];

pub struct InformationDisclosureInUrl;

impl PassiveRule for InformationDisclosureInUrl {
    fn id(&self) -> u32 {
        10024
    }

    fn name(&self) -> &'static str {
        "Information Disclosure - Sensitive Information in URL"
    }

    fn alerts(&self) -> &'static [&'static AlertDef] {
        &ALERTS
    }

    fn scan(&self, msg: &Message, out: &mut Vec<Finding>) {
        if msg.query.as_deref().is_none_or(str::is_empty) {
            return;
        }
        for (name, value) in url_params(msg) {
            let lc = name.to_lowercase();
            if let Some(s) = SENSITIVE_STRINGS.iter().find(|s| lc.contains(**s)) {
                let info = format!(
                    "The URL contains potentially sensitive information. The following string was found via the \
                     pattern: {s}\n{name}"
                );
                out.push(ALERT.raise(name.clone(), name.clone()).other_info(info));
            }
            if CREDIT_CARD.is_match(&value) {
                out.push(
                    ALERT
                        .raise(name.clone(), value.clone())
                        .other_info("The URL appears to contain credit card information."),
                );
            }
            if EMAIL.is_match(&value) {
                out.push(ALERT.raise(name.clone(), value.clone()).other_info("The URL contains email address(es)."));
            }
            if SSN.is_match(&value) {
                out.push(
                    ALERT
                        .raise(name.clone(), value.clone())
                        .other_info("The URL appears to contain US Social Security Number(s)."),
                );
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scan::passive::util::testing::msg;

    #[test]
    fn flags_sensitive_names_and_values() {
        let f = msg("https://a.test/?UserName=bob&to=bob%40example.com&cc=4111111111111111&ssn=123-45-6789")
            .scan(&InformationDisclosureInUrl);
        let infos: Vec<(&str, &str)> = f.iter().map(|f| (f.param.as_str(), f.evidence.as_str())).collect();
        assert_eq!(
            infos,
            [("UserName", "UserName"), ("cc", "4111111111111111"), ("ssn", "123-45-6789"), ("to", "bob@example.com")]
        );
        assert_eq!(
            f[0].other_info,
            "The URL contains potentially sensitive information. The following string was found via the pattern: \
             user\nUserName"
        );
    }

    #[test]
    fn ignores_benign_urls() {
        assert!(msg("https://a.test/?q=hello&page=2").scan(&InformationDisclosureInUrl).is_empty());
        assert!(msg("https://a.test/user/password").scan(&InformationDisclosureInUrl).is_empty());
    }
}
