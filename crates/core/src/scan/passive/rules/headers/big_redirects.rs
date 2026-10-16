//! Ported from ZAP BigRedirectsScanRule (pscanrules, Apache License 2.0).

use std::sync::LazyLock;

use regex::bytes::Regex;

use super::common::{fmt_int, header_first};
use crate::scan::{AlertDef, Confidence, Finding, Message, PassiveRule, Risk};

const TAGS: &[&str] = &["OWASP_2025_A06", "OWASP_2021_A04", "OWASP_2017_A03", "WSTG-v42-INFO-05"];
const SOLN: &str = "Ensure that no sensitive information is leaked via redirect responses. Redirect responses should \
    have almost no content.";

static BIG: AlertDef = AlertDef {
    alert_ref: "10044-1",
    name: "Big Redirect Detected (Potential Sensitive Information Leak)",
    risk: Risk::Low,
    confidence: Confidence::Medium,
    cwe: 201,
    wasc: 13,
    description: "The server has responded with a redirect that seems to provide a large response. This may \
        indicate that although the server sent a redirect it also responded with body content (which may include \
        sensitive details, PII, etc.).",
    solution: SOLN,
    references: &[],
    tags: TAGS,
};

static MULTI_HREF: AlertDef = AlertDef {
    alert_ref: "10044-2",
    name: "Multiple HREFs Redirect Detected (Potential Sensitive Information Leak)",
    risk: Risk::Low,
    confidence: Confidence::Medium,
    cwe: 201,
    wasc: 13,
    description: "The server has responded with a redirect that seems to contain multiple links. This may indicate \
        that although the server sent a redirect it also responded with body content links (which may include \
        sensitive details, PII, lead to admin panels, etc.).",
    solution: SOLN,
    references: &[],
    tags: TAGS,
};

static ALERTS: [&AlertDef; 2] = [&BIG, &MULTI_HREF];

static HREF: LazyLock<Regex> = LazyLock::new(|| Regex::new("(?i)href").unwrap());

pub struct BigRedirects;

impl PassiveRule for BigRedirects {
    fn id(&self) -> u32 {
        10044
    }

    fn name(&self) -> &'static str {
        "Big Redirect Detected (Potential Sensitive Information Leak)"
    }

    fn alerts(&self) -> &'static [&'static AlertDef] {
        &ALERTS
    }

    fn scan(&self, msg: &Message, out: &mut Vec<Finding>) {
        if !(300..=399).contains(&msg.status) || msg.status == 304 {
            return;
        }
        let Some(loc) = header_first(msg, "Location") else { return };
        // Java String.length(): UTF-16 code units.
        let len = loc.encode_utf16().count();
        if len == 0 {
            return;
        }
        let predicted = len + 300;
        let body_len = msg.resp_body.len();
        if body_len > predicted {
            out.push(BIG.raise("", "").other_info(format!(
                "Location header URI length: {} [{loc}].\nPredicted response size: {}.\nResponse Body Length: {}.",
                fmt_int(len as i64),
                fmt_int(predicted as i64),
                fmt_int(body_len as i64)
            )));
        } else {
            let count = HREF.find_iter(&msg.resp_body).count();
            if count > 1 {
                out.push(
                    MULTI_HREF.raise("", "").other_info(format!(
                        "The response contained {} occurrences of \"HREF\".",
                        fmt_int(count as i64)
                    )),
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
    fn flags_big_body_and_many_links() {
        let body = "x".repeat(1500);
        let f = msg("https://a.test/").status(302).header("Location", "/next").body(&body).scan(&BigRedirects);
        assert_eq!(f[0].def.alert_ref, "10044-1");
        assert_eq!(
            f[0].other_info,
            "Location header URI length: 5 [/next].\nPredicted response size: 305.\nResponse Body Length: 1,500."
        );
        let f = msg("https://a.test/")
            .status(301)
            .header("Location", "/next")
            .body("<a href=/a>a</a><A HREF=/b>b</a>")
            .scan(&BigRedirects);
        assert_eq!(f[0].def.alert_ref, "10044-2");
        assert_eq!(f[0].other_info, "The response contained 2 occurrences of \"HREF\".");
    }

    #[test]
    fn ignores_small_redirects_and_non_redirects() {
        let small = msg("https://a.test/").status(302).header("Location", "/n").body("<a href=/n>moved</a>");
        assert!(small.scan(&BigRedirects).is_empty());
        let big = "x".repeat(1500);
        assert!(msg("https://a.test/").status(304).header("Location", "/n").body(&big).scan(&BigRedirects).is_empty());
        assert!(msg("https://a.test/").status(200).header("Location", "/n").body(&big).scan(&BigRedirects).is_empty());
        assert!(msg("https://a.test/").status(302).body(&big).scan(&BigRedirects).is_empty());
    }
}
