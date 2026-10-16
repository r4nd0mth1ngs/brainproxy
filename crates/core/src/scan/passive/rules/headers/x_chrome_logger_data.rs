//! Ported from ZAP XChromeLoggerDataInfoLeakScanRule (pscanrules, Apache License 2.0).

use super::common::{header_values, java_base64_decode};
use crate::scan::{AlertDef, Confidence, Finding, Message, PassiveRule, Risk};

static ALERT: AlertDef = AlertDef {
    alert_ref: "10052",
    name: "X-ChromeLogger-Data (XCOLD) Header Information Leak",
    risk: Risk::Medium,
    confidence: Confidence::High,
    cwe: 532,
    wasc: 13,
    description: "The server is leaking information through the X-ChromeLogger-Data (or X-ChromePhp-Data) response \
        header. The content of such headers can be customized by the developer, however it is not uncommon to find: \
        server file system locations, vhost declarations, etc.",
    solution: "Disable this functionality in Production when it might leak information that could be leveraged by \
        an attacker. Alternatively ensure that use of the functionality is tied to a strong authorization check and \
        only available to administrators or support personnel for troubleshooting purposes not general users.",
    references: &["https://craig.is/writing/chrome-logger"],
    tags: &["OWASP_2025_A06", "OWASP_2021_A04", "OWASP_2017_A03", "WSTG-v42-INFO-05", "SYSTEMIC"],
};

static ALERTS: [&AlertDef; 1] = [&ALERT];

fn other_info(value: &str) -> String {
    match java_base64_decode(value) {
        Some(bytes) => format!(
            "The following represents an attempt to base64 decode the value:\n{}",
            String::from_utf8_lossy(&bytes)
        ),
        None => format!("Header value could not be base64 decoded: {value}"),
    }
}

pub struct XChromeLoggerData;

impl PassiveRule for XChromeLoggerData {
    fn id(&self) -> u32 {
        10052
    }

    fn name(&self) -> &'static str {
        "X-ChromeLogger-Data (XCOLD) Header Information Leak"
    }

    fn alerts(&self) -> &'static [&'static AlertDef] {
        &ALERTS
    }

    fn scan(&self, msg: &Message, out: &mut Vec<Finding>) {
        for v in header_values(msg, "X-ChromeLogger-Data").chain(header_values(msg, "X-ChromePhp-Data")) {
            out.push(ALERT.raise("", v).other_info(other_info(v)));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scan::passive::util::testing::msg;

    #[test]
    fn flags_and_decodes() {
        let f = msg("https://a.test/")
            .header("X-ChromeLogger-Data", "eyJ2ZXJzaW9uIjoiNC4wIn0=")
            .header("X-ChromePhp-Data", "not base64!")
            .scan(&XChromeLoggerData);
        assert_eq!(f.len(), 2);
        assert_eq!(
            f[0].other_info,
            "The following represents an attempt to base64 decode the value:\n{\"version\":\"4.0\"}"
        );
        assert_eq!(f[1].other_info, "Header value could not be base64 decoded: not base64!");
        assert_eq!(f[1].evidence, "not base64!");
    }

    #[test]
    fn ignores_absent_headers() {
        assert!(msg("https://a.test/").header("X-Logger", "x").scan(&XChromeLoggerData).is_empty());
    }
}
