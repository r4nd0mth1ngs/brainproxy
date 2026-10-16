//! Ported from ZAP UserAgentScanRule (ascanrules, Apache License 2.0).

use super::common::with_request_line;
use crate::http::RawRequest;
use crate::scan::active::{ActiveRule, BoxFuture, Cx, RuleScope};
use crate::scan::{AlertDef, Confidence, Risk};

static ALERT: AlertDef = AlertDef {
    alert_ref: "10104",
    name: "User Agent Fuzzer",
    risk: Risk::Info,
    confidence: Confidence::Medium,
    cwe: 0,
    wasc: 0,
    description: "Check for differences in response based on fuzzed User Agent (eg. mobile sites, access as a Search \
        Engine Crawler). Compares the response statuscode and the hashcode of the response body with the original \
        response.",
    solution: "",
    references: &["https://owasp.org/www-project-web-security-testing-guide/"],
    tags: &["CUSTOM_PAYLOADS", "SYSTEMIC"],
};

static ALERTS: [&AlertDef; 1] = [&ALERT];

const PARAM_NAME: &str = "Header User-Agent";

const USER_AGENTS: [&str; 12] = [
    "Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1)",
    "Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.0)",
    "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)",
    "Mozilla/5.0 (Windows NT 10.0; Trident/7.0; rv:11.0) like Gecko",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/75.0.3739.0 Safari/537.36 Edg/75.0.109.0",
    "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
    "msnbot/1.1 (+http://search.msn.com/msnbot.htm)",
    "Mozilla/5.0 (compatible; Yahoo! Slurp; http://help.yahoo.com/help/us/ysearch/slurp)",
    "Mozilla/5.0 (iPhone; U; CPU iPhone OS 3_0 like Mac OS X; en-us) AppleWebKit/528.18 (KHTML, like Gecko) Version/4.0 Mobile/7A341 Safari/528.16",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 8_0_2 like Mac OS X) AppleWebKit/600.1.4 (KHTML, like Gecko) Version/8.0 Mobile/12A366 Safari/600.1.4",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:93.0) Gecko/20100101 Firefox/91.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
];

/// Whether the fuzzed response differs from the original in status or body.
fn differs(orig_status: u16, orig_body: &[u8], status: u16, body: &[u8]) -> bool {
    orig_status != status || orig_body != body
}

pub struct UserAgent;

impl ActiveRule for UserAgent {
    fn id(&self) -> u32 {
        10104
    }

    fn name(&self) -> &'static str {
        "User Agent Fuzzer"
    }

    fn alerts(&self) -> &'static [&'static AlertDef] {
        &ALERTS
    }

    fn scope(&self) -> RuleScope {
        RuleScope::Page
    }

    fn scan<'a>(&'a self, cx: &'a Cx) -> BoxFuture<'a> {
        Box::pin(async move {
            let base = cx.base();
            let (orig_status, orig_body) = (base.status, base.resp_body.clone());
            // Keep the base request as-is (method, path, params), only the UA changes.
            let line_target = {
                let head = String::from_utf8_lossy(base_line(cx.base_request()));
                head.split(' ').nth(1).unwrap_or("/").to_string()
            };
            let method = base.method.clone();
            for ua in USER_AGENTS {
                if cx.stopped() {
                    return;
                }
                let raw = with_request_line(cx.base_request(), &method, &line_target);
                let req = RawRequest::from_bytes(raw).set_header("User-Agent", ua).into_bytes();
                let Ok(resp) = cx.send(req).await else { continue };
                if differs(orig_status, &orig_body, resp.status, &resp.body) {
                    cx.report(ALERT.raise(PARAM_NAME, "").attack(ua), &resp);
                }
            }
        })
    }
}

/// The request line bytes.
fn base_line(raw: &[u8]) -> &[u8] {
    let end = raw.windows(2).position(|w| w == b"\r\n").unwrap_or(raw.len());
    &raw[..end]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn user_agents() {
        assert_eq!(USER_AGENTS.len(), 12);
        assert!(USER_AGENTS[5].contains("Googlebot"));
    }

    #[test]
    fn difference() {
        assert!(!differs(200, b"hello", 200, b"hello"));
        assert!(differs(200, b"hello", 200, b"world"));
        assert!(differs(200, b"hello", 301, b"hello"));
    }
}
