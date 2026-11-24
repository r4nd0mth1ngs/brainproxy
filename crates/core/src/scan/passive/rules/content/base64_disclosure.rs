//! Ported from ZAP Base64Disclosure (pscanrulesAlpha, Apache License 2.0).
//!
//! At the MEDIUM threshold, as ZAP: one finding per response, for the first string that
//! decodes as Base64 and has the mix of characters Base64 data of its length almost always
//! has. ZAP decodes data with an ASP.NET ViewState preamble here too and raises 10094-1 and
//! 10094-2 for it; brainproxy's Viewstate rule (10032) already reports ViewStates, so such
//! data is passed over here rather than reported twice.

use std::sync::LazyLock;

use regex::Regex;

use crate::scan::passive::rules::headers::common::java_base64_decode;
use crate::scan::{AlertDef, Confidence, Finding, Message, PassiveRule, Risk};

static ALERT: AlertDef = AlertDef {
    alert_ref: "10094-3",
    name: "Base64 Disclosure",
    risk: Risk::Info,
    confidence: Confidence::Medium,
    cwe: 319,
    wasc: 13,
    description: "Base64 encoded data was disclosed by the application/web server. Note: in the interests of \
        performance not all base64 strings in the response were analyzed individually, the entire response should be \
        looked at by the analyst/security team/developer(s).",
    solution: "Manually confirm that the Base64 data does not leak sensitive information, and that the data cannot be \
        aggregated/used to exploit other vulnerabilities.",
    references: &["https://projects.webappsec.org/w/page/13246936/Information%20Leakage"],
    tags: &["OWASP_2025_A06", "OWASP_2021_A04", "OWASP_2017_A03"],
};

static ALERTS: [&AlertDef; 1] = [&ALERT];

/// Standard and URL-safe alphabets, at least 30 characters. (ZAP's class also holds `\`, which
/// never decodes, so a string with one is passed over.)
static BASE64: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"[a-zA-Z0-9+\\/\-_]{30,}={0,2}").expect("static regex compiles"));

/// Headers whose Base64 is expected and says nothing (ZAP's list).
const IGNORED_HEADERS: [&str; 4] = ["ETag", "Authorization", "X-ChromeLogger-Data", "X-ChromePhp-Data"];

/// The MEDIUM threshold: a string missing a character class that Base64 data of its length
/// lacks less than 25% of the time isn't taken for Base64.
const PROBABILITY_THRESHOLD: f32 = 0.25;

/// Whether `s` (URL-safe characters already mapped) has the character mix of Base64 data.
fn plausible(s: &str, len: usize) -> bool {
    let len = i32::try_from(len).unwrap_or(i32::MAX);
    let p = |others: f32| (others / 64.0).powi(len);
    let lacks = |f: fn(&u8) -> bool| !s.bytes().any(|b| f(&b));
    let improbable = |missing: bool, prob: f32| missing && prob < PROBABILITY_THRESHOLD;
    !(improbable(lacks(u8::is_ascii_digit), p(54.0))
        || improbable(lacks(u8::is_ascii_alphabetic), p(12.0))
        || improbable(lacks(u8::is_ascii_lowercase), p(38.0))
        || improbable(lacks(u8::is_ascii_uppercase), p(38.0)))
}

/// The first Base64 string in `text` worth reporting, with its decoded data.
fn first_base64(text: &str) -> Option<(String, Vec<u8>)> {
    BASE64.find_iter(text).find_map(|m| {
        let evidence = m.as_str();
        let standard = evidence.replace('-', "+").replace('_', "/");
        let data = java_base64_decode(&standard)?;
        if !plausible(&standard, evidence.len()) {
            return None;
        }
        // An ASP.NET ViewState (or event validation) preamble: left to the Viewstate rule.
        if data.first() == Some(&0xff) || data.get(1) == Some(&0x01) {
            return None;
        }
        Some((evidence.to_string(), data))
    })
}

pub struct Base64Disclosure;

impl PassiveRule for Base64Disclosure {
    fn id(&self) -> u32 {
        10094
    }

    fn name(&self) -> &'static str {
        "Base64 Disclosure"
    }

    fn alerts(&self) -> &'static [&'static AlertDef] {
        &ALERTS
    }

    fn scan(&self, msg: &Message, out: &mut Vec<Finding>) {
        let mut head = String::new();
        for (k, v) in &msg.resp_headers {
            if !IGNORED_HEADERS.iter().any(|h| k.eq_ignore_ascii_case(h)) {
                head.push_str(&format!("{k}: {}\r\n", v.trim()));
            }
        }
        if let Some((evidence, data)) = first_base64(&head).or_else(|| first_base64(msg.body())) {
            out.push(ALERT.raise("", evidence).other_info(String::from_utf8_lossy(&data)));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scan::passive::util::testing::msg;
    use base64::Engine;

    fn b64(s: &[u8]) -> String {
        base64::engine::general_purpose::STANDARD.encode(s)
    }

    #[test]
    fn reports_the_first_base64_string() {
        let secret = b64(b"user=admin;password=Sup3rS3cret!;role=root");
        let f = msg("https://a.test/")
            .html(&format!("<p>{secret}</p><p>{}</p>", b64(b"another one, also long")))
            .scan(&Base64Disclosure);
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].evidence, secret);
        assert_eq!(f[0].other_info, "user=admin;password=Sup3rS3cret!;role=root");
        // In a header, and URL-safe.
        let token = b64(b"\xfb\xff session 0123456789 abcdef ABCDEF").replace('+', "-").replace('/', "_");
        let f = msg("https://a.test/").header("X-Token", &token).scan(&Base64Disclosure);
        assert_eq!(f[0].evidence, token);
    }

    #[test]
    fn passes_over_what_isnt_base64_data() {
        let etag = b64(b"etag value that is long enough to match");
        for page in [
            // A path, a word run, a hex digest: not the mix Base64 data has.
            "<a href=\"/static/js/vendors/application/bundle/main/index.js\">",
            "<p>abcdefghijklmnopqrstuvwxyzabcdefghij</p>",
            "<p>d41d8cd98f00b204e9800998ecf8427ed41d8cd9</p>",
            // A backslash never decodes.
            "<p>C:\\Users\\Admin\\AppData\\Roaming\\Microsoft9\\X</p>",
        ] {
            assert!(msg("https://a.test/").html(page).scan(&Base64Disclosure).is_empty(), "{page}");
        }
        assert!(msg("https://a.test/").header("ETag", &etag).scan(&Base64Disclosure).is_empty());
        // A ViewState is the Viewstate rule's.
        let vs = b64(b"\xff\x01\x0f\x0f\x05\x0b1234567890abcdefXYZ123456789");
        assert!(msg("https://a.test/").html(&format!("<input value=\"{vs}\">")).scan(&Base64Disclosure).is_empty());
    }
}
