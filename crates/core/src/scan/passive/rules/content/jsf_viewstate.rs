//! Ported from ZAP InsecureJsfViewStatePassiveScanRule (pscanrules, Apache License 2.0).

use std::io::Read;

use base64::Engine;

use crate::scan::passive::rules::headers::common::zap_is_text;
use crate::scan::passive::util::tags;
use crate::scan::{AlertDef, Confidence, Finding, Message, PassiveRule, Risk};

static ALERT: AlertDef = AlertDef {
    alert_ref: "90001",
    name: "Insecure JSF ViewState",
    risk: Risk::Medium,
    confidence: Confidence::Low,
    cwe: 642,
    wasc: 14,
    description: "The response at the following URL contains a ViewState value that has no cryptographic protections.",
    solution: "Secure VIEWSTATE with a MAC specific to your environment.",
    references: &["https://www.trustwave.com/hubfs/21158977/Web/Library/Advisories_txt/14213_twsl2010-001.txt"],
    tags: &["OWASP_2025_A06", "OWASP_2025_A08", "OWASP_2021_A04", "OWASP_2017_A06"],
};

static ALERTS: [&AlertDef; 1] = [&ALERT];

/// Gzip-decompresses when the value starts with the gzip magic; `None` on a broken stream.
fn decompress(value: Vec<u8>) -> Option<Vec<u8>> {
    if value.len() < 4 || value[..2] != [0x1f, 0x8b] {
        return Some(value);
    }
    let mut out = Vec::new();
    // Inflation is capped at 16 MiB (ZAP has no cap).
    flate2::read::MultiGzDecoder::new(&value[..]).take(16 << 20).read_to_end(&mut out).ok()?;
    Some(out)
}

/// ZAP: insecure when the (decoded, inflated) value contains "java".
fn is_secure(value: &str) -> bool {
    let raw = |v: &[u8]| !v.windows(4).any(|w| w == b"java");
    match super::viewstate::JAVA_B64.decode(value).ok().and_then(decompress) {
        Some(bytes) => raw(&bytes),
        None => raw(value.as_bytes()),
    }
}

pub struct InsecureJsfViewState;

impl PassiveRule for InsecureJsfViewState {
    fn id(&self) -> u32 {
        90001
    }

    fn name(&self) -> &'static str {
        "Insecure JSF ViewState"
    }

    fn alerts(&self) -> &'static [&'static AlertDef] {
        &ALERTS
    }

    fn scan(&self, msg: &Message, out: &mut Vec<Finding>) {
        let body = msg.body();
        if body.is_empty() || !zap_is_text(msg) || !body.to_ascii_lowercase().contains("javax.faces.viewstate") {
            return;
        }
        for t in tags(body).iter().filter(|t| t.name == "input") {
            let Some(id) = t.attr("id").filter(|id| id.to_lowercase().contains("javax.faces.viewstate")) else {
                continue;
            };
            let value = t.attr("value");
            // Server-side state: an id like "_id16683" or "-123:456" (ZAP stops scanning here).
            if value.is_some_and(|v| v.starts_with('_') || v.contains(':')) {
                return;
            }
            if !value.is_none_or(|v| v.is_empty() || is_secure(v)) {
                out.push(ALERT.raise("", "").other_info(format!("JSF ViewState [{id}] is insecure.")));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::io::Write;

    use super::*;
    use crate::scan::passive::util::testing::msg;

    fn scan(value: &str) -> Vec<Finding> {
        let html = format!(
            r#"<input type="hidden" name="javax.faces.ViewState" id="j_id1:javax.faces.ViewState:0" value="{value}">"#
        );
        msg("http://a.test/").html(&html).scan(&InsecureJsfViewState)
    }

    #[test]
    fn plain_and_gzipped_java_streams_are_insecure() {
        let b64 = |b: &[u8]| base64::engine::general_purpose::STANDARD.encode(b);
        let plain = b"\xac\xed\x00\x05ur\x00\x13[Ljava.lang.Object;";
        let f = scan(&b64(plain));
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].other_info, "JSF ViewState [j_id1:javax.faces.ViewState:0] is insecure.");
        let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        gz.write_all(plain).unwrap();
        assert_eq!(scan(&b64(&gz.finish().unwrap())).len(), 1);
        // Not base64 at all: checked as is.
        assert_eq!(scan("raw java state").len(), 1);
    }

    #[test]
    fn encrypted_and_server_side_states_are_quiet() {
        assert!(scan("q1w2e3r4t5y6u7i8o9p0AbCdEfGh").is_empty());
        assert!(scan("-4518633612344566134:-1234567890123456789").is_empty());
        assert!(scan("_id16683").is_empty());
        assert!(scan("").is_empty());
    }
}
