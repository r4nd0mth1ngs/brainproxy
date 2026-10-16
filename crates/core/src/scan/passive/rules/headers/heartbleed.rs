//! Ported from ZAP HeartBleedScanRule (pscanrules, Apache License 2.0).

use std::sync::LazyLock;

use regex::Regex;

use super::common::headers_block;
use crate::scan::{AlertDef, Confidence, Finding, Message, PassiveRule, Risk};

static ALERT: AlertDef = AlertDef {
    alert_ref: "10034",
    name: "Heartbleed OpenSSL Vulnerability (Indicative)",
    risk: Risk::High,
    confidence: Confidence::Low,
    cwe: 119,
    wasc: 20,
    description: "The TLS and DTLS implementations in OpenSSL 1.0.1 before 1.0.1g do not properly handle Heartbeat \
        Extension packets, which allows remote attackers to obtain sensitive information from process memory via \
        crafted packets that trigger a buffer over-read, potentially disclosing sensitive information.",
    solution: "Update to OpenSSL 1.0.1g or later. Re-issue HTTPS certificates. Change asymmetric private keys and \
        shared secret keys, since these may have been compromised, with no evidence of compromise in the server log \
        files.",
    references: &["https://nvd.nist.gov/vuln/detail/cve-2014-0160"],
    tags: &["OWASP_2025_A04", "OWASP_2021_A06", "OWASP_2017_A09", "WSTG-v42-CRYP-01", "CVE-2014-0160"],
};

static ALERTS: [&AlertDef; 1] = [&ALERT];

// Java: Server:.*?(OpenSSL/([0-9.]+[a-z-0-9]+)) — '.' never crosses a line break.
static OPENSSL: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)Server:[^\r\n]*?(OpenSSL/([0-9.]+[a-z0-9-]+))").unwrap());

const VULNERABLE: &[&str] = &[
    "1.0.1-Beta1",
    "1.0.1-Beta2",
    "1.0.1-Beta3",
    "1.0.1",
    "1.0.1a",
    "1.0.1b",
    "1.0.1c",
    "1.0.1d",
    "1.0.1e",
    "1.0.1f",
    "1.0.2-beta",
];

pub struct HeartBleed;

impl PassiveRule for HeartBleed {
    fn id(&self) -> u32 {
        10034
    }

    fn name(&self) -> &'static str {
        "Heartbleed OpenSSL Vulnerability (Indicative)"
    }

    fn alerts(&self) -> &'static [&'static AlertDef] {
        &ALERTS
    }

    fn scan(&self, msg: &Message, out: &mut Vec<Finding>) {
        if !msg.resp_headers.iter().any(|(_, v)| v.as_bytes().windows(8).any(|w| w.eq_ignore_ascii_case(b"openssl/"))) {
            return;
        }
        let block = headers_block(msg);
        for c in OPENSSL.captures_iter(&block) {
            let full = &c[1];
            if VULNERABLE.iter().any(|v| v.eq_ignore_ascii_case(&c[2])) {
                out.push(ALERT.raise("", full).other_info(format!(
                    "{full} is in use. Note however that the reported version could contain back-ported security \
                     fixes, and so the issue could be a false positive. This is common on Red Hat, for instance."
                )));
                return;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scan::passive::util::testing::msg;

    #[test]
    fn flags_vulnerable_openssl() {
        let f = msg("https://a.test/").header("Server", "Apache/2.2.15 (Unix) OpenSSL/1.0.1e").scan(&HeartBleed);
        assert_eq!((f.len(), f[0].evidence.as_str()), (1, "OpenSSL/1.0.1e"));
        assert!(f[0].other_info.starts_with("OpenSSL/1.0.1e is in use."));
        let f = msg("https://a.test/").header("Server", "x OpenSSL/1.0.1").scan(&HeartBleed);
        assert_eq!(f[0].evidence, "OpenSSL/1.0.1");
    }

    #[test]
    fn ignores_patched_openssl() {
        assert!(msg("https://a.test/").header("Server", "Apache OpenSSL/1.0.1g").scan(&HeartBleed).is_empty());
        assert!(msg("https://a.test/").header("X-Lib", "OpenSSL/1.0.1e").scan(&HeartBleed).is_empty());
    }
}
