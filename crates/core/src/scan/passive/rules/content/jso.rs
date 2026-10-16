//! Ported from ZAP JsoScanRule (pscanrules, Apache License 2.0).
//!
//! ZAP runs the request half when the request is sent and the response half when
//! it is received; here both halves run on the captured exchange.

use crate::scan::message::SetCookie;
use crate::scan::{AlertDef, Confidence, Finding, Message, PassiveRule, Risk};

static ALERT: AlertDef = AlertDef {
    alert_ref: "90002",
    name: "Java Serialization Object",
    risk: Risk::Medium,
    confidence: Confidence::Medium,
    cwe: 502,
    wasc: 0,
    description: "Java Serialization seems to be in use. If not correctly validated, an attacker can send a \
        specially crafted object. This can lead to a dangerous \"Remote Code Execution\". A magic sequence \
        identifying JSO has been detected (Base64: rO0AB, Raw: 0xac, 0xed, 0x00, 0x05).",
    solution: "Deserialization of untrusted data is inherently dangerous and should be avoided.",
    references: &["https://www.oracle.com/java/technologies/javase/seccodeguide.html#8"],
    tags: &["OWASP_2025_A06", "OWASP_2021_A04", "OWASP_2017_A08"],
};

static ALERTS: [&AlertDef; 1] = [&ALERT];

const BYTE_MAGIC: [u8; 4] = [0xAC, 0xED, 0x00, 0x05];
const B64_MAGIC: &str = "rO0AB";
const URI_MAGIC: &str = "%C2%AC%C3%AD%00%05";

fn has_magic(v: &str) -> bool {
    v.starts_with(B64_MAGIC) || v.starts_with(URI_MAGIC)
}

fn body_has_magic(b: &[u8]) -> bool {
    b.starts_with(&BYTE_MAGIC) || b.starts_with(B64_MAGIC.as_bytes())
}

fn check_headers(headers: &[(String, String)], out: &mut Vec<Finding>) {
    for (k, v) in headers {
        if has_magic(v) {
            out.push(ALERT.raise("", format!("[Name={k}, Value={v}]")));
        }
    }
}

pub struct Jso;

impl PassiveRule for Jso {
    fn id(&self) -> u32 {
        90002
    }

    fn name(&self) -> &'static str {
        "Java Serialization Object"
    }

    fn alerts(&self) -> &'static [&'static AlertDef] {
        &ALERTS
    }

    fn scan(&self, msg: &Message, out: &mut Vec<Finding>) {
        // Request: raw query values, headers, cookies, body.
        if let Some(q) = msg.query.as_deref() {
            for param in q.split('&') {
                // Java split("="): the value is the text between the first and second '='.
                if let Some(v) = param.split('=').nth(1).filter(|v| !v.is_empty()) {
                    if has_magic(v) {
                        out.push(ALERT.raise("", ""));
                    }
                }
            }
        }
        check_headers(&msg.req_headers, out);
        for (name, value) in msg.request_cookies() {
            if has_magic(&value) {
                out.push(ALERT.raise("", format!("{name}={value}")));
            }
        }
        if body_has_magic(&msg.req_body) {
            out.push(ALERT.raise("", ""));
        }
        // Response: headers, Set-Cookie cookies, body.
        check_headers(&msg.resp_headers, out);
        for raw in msg.resp_headers_named("set-cookie").chain(msg.resp_headers_named("set-cookie2")) {
            for c in raw.split('\n').map(SetCookie::parse) {
                if has_magic(&c.value) {
                    out.push(ALERT.raise("", format!("{}={}", c.name, c.value)));
                }
            }
        }
        if body_has_magic(&msg.resp_body) {
            out.push(ALERT.raise("", ""));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scan::passive::util::testing::msg;

    #[test]
    fn flags_magic_everywhere() {
        let f = msg("https://a.test/?a=rO0ABXNy&b=x")
            .req_header("X-Obj", "rO0ABXQ")
            .req_header("Cookie", "s=%C2%AC%C3%AD%00%05t")
            .header("Set-Cookie", "j=rO0ABXZ; Path=/")
            .body("rO0ABXNyABFqYXZh")
            .scan(&Jso);
        let ev: Vec<&str> = f.iter().map(|f| f.evidence.as_str()).collect();
        assert_eq!(ev, ["", "[Name=X-Obj, Value=rO0ABXQ]", "s=%C2%AC%C3%AD%00%05t", "j=rO0ABXZ", ""]);
        let mut m = msg("https://a.test/").build();
        m.resp_body = vec![0xAC, 0xED, 0x00, 0x05, 0x73];
        let mut out = Vec::new();
        Jso.scan(&m, &mut out);
        assert_eq!(out.len(), 1);
    }

    #[test]
    fn ignores_magic_not_at_start() {
        let f = msg("https://a.test/?a=xrO0AB").header("X", "a rO0AB").body("data: rO0AB").scan(&Jso);
        assert!(f.is_empty());
    }
}
