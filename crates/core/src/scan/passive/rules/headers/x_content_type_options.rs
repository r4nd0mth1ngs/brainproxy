//! Ported from ZAP XContentTypeOptionsScanRule (pscanrules, Apache License 2.0).

use super::common::{header_values, is_error, is_redirect};
use crate::scan::{AlertDef, Confidence, Finding, Message, PassiveRule, Risk};

static ALERT: AlertDef = AlertDef {
    alert_ref: "10021",
    name: "X-Content-Type-Options Header Missing",
    risk: Risk::Low,
    confidence: Confidence::Medium,
    cwe: 693,
    wasc: 15,
    description: "The Anti-MIME-Sniffing header X-Content-Type-Options was not set to 'nosniff'. This allows older \
        versions of Internet Explorer and Chrome to perform MIME-sniffing on the response body, potentially causing \
        the response body to be interpreted and displayed as a content type other than the declared content type. \
        Current (early 2014) and legacy versions of Firefox will use the declared content type (if one is set), \
        rather than performing MIME-sniffing.",
    solution: "Ensure that the application/web server sets the Content-Type header appropriately, and that it sets \
        the X-Content-Type-Options header to 'nosniff' for all web pages.\nIf possible, ensure that the end user \
        uses a standards-compliant and modern web browser that does not perform MIME-sniffing at all, or that can \
        be directed by the web application/web server to not perform MIME-sniffing.",
    references: &[
        "https://learn.microsoft.com/en-us/previous-versions/windows/internet-explorer/ie-developer/compatibility/gg622941(v=vs.85)",
        "https://owasp.org/www-community/Security_Headers",
    ],
    tags: &["OWASP_2025_A02", "OWASP_2021_A05", "OWASP_2017_A06", "SYSTEMIC"],
};

static ALERTS: [&AlertDef; 1] = [&ALERT];

const OTHER_INFO: &str = "This issue still applies to error type pages (401, 403, 500, etc.) as those pages are \
    often still affected by injection issues, in which case there is still concern for browsers sniffing pages away \
    from their actual content type.\nAt \"High\" threshold this scan rule will not alert on client or server error \
    responses.";

const HEADER: &str = "X-Content-Type-Options";

pub struct XContentTypeOptions;

impl PassiveRule for XContentTypeOptions {
    fn id(&self) -> u32 {
        10021
    }

    fn name(&self) -> &'static str {
        "X-Content-Type-Options Header Missing"
    }

    fn alerts(&self) -> &'static [&'static AlertDef] {
        &ALERTS
    }

    fn scan(&self, msg: &Message, out: &mut Vec<Finding>) {
        if msg.resp_body.is_empty() || is_error(msg.status) || is_redirect(msg.status) {
            return;
        }
        let mut any = false;
        for v in header_values(msg, HEADER) {
            any = true;
            if !v.to_lowercase().contains("nosniff") {
                out.push(ALERT.raise(HEADER, v).other_info(OTHER_INFO));
            }
        }
        if !any {
            out.push(ALERT.raise(HEADER, "").other_info(OTHER_INFO));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scan::passive::util::testing::msg;

    #[test]
    fn flags_missing_or_wrong_value() {
        let f = msg("https://a.test/").html("<p>").scan(&XContentTypeOptions);
        assert_eq!((f.len(), f[0].evidence.as_str(), f[0].param.as_str()), (1, "", HEADER));
        let f = msg("https://a.test/").html("<p>").header(HEADER, "sniff").scan(&XContentTypeOptions);
        assert_eq!(f[0].evidence, "sniff");
    }

    #[test]
    fn ignores_nosniff_errors_redirects_and_empty() {
        assert!(msg("https://a.test/").html("<p>").header(HEADER, "NoSniff").scan(&XContentTypeOptions).is_empty());
        assert!(msg("https://a.test/").html("<p>").status(500).scan(&XContentTypeOptions).is_empty());
        assert!(msg("https://a.test/").html("<p>").status(301).scan(&XContentTypeOptions).is_empty());
        assert!(msg("https://a.test/").scan(&XContentTypeOptions).is_empty());
    }
}
