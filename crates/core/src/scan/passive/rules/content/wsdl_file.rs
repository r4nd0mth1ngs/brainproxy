//! Ported from ZAP WSDLFilePassiveScanRule (soap, Apache License 2.0).

use super::common::is_text;
use crate::scan::{AlertDef, Confidence, Finding, Message, PassiveRule, Risk};

static ALERT: AlertDef = AlertDef {
    alert_ref: "90030",
    name: "WSDL File Detection",
    risk: Risk::Info,
    confidence: Confidence::Medium,
    cwe: 651,
    wasc: 13,
    description: "A WSDL File has been detected.",
    solution: "Make your WSDL files visible only for technical issues (ex: testing purposes).",
    references: &[],
    tags: &["OWASP_2025_A02", "OWASP_2021_A05", "OWASP_2017_A06"],
};

static ALERTS: [&AlertDef; 1] = [&ALERT];

/// A text, non-HTML answer for a `.wsdl` URL, a `?wsdl` query, or served as WSDL. Returns its
/// Content-Type.
fn wsdl(msg: &Message) -> Option<&str> {
    if msg.resp_body.is_empty() || !is_text(msg) || msg.is_html() {
        return None;
    }
    let ct = msg.resp_header("Content-Type")?.trim();
    let url = msg.url.trim();
    let tail = url.len().checked_sub(5).and_then(|i| url.get(i..)).unwrap_or_default();
    (url.ends_with(".wsdl") || tail.eq_ignore_ascii_case("?wsdl") || ct == "application/wsdl+xml").then_some(ct)
}

pub struct WsdlFile;

impl PassiveRule for WsdlFile {
    fn id(&self) -> u32 {
        90030
    }

    fn name(&self) -> &'static str {
        "WSDL File Detection"
    }

    fn alerts(&self) -> &'static [&'static AlertDef] {
        &ALERTS
    }

    fn scan(&self, msg: &Message, out: &mut Vec<Finding>) {
        if matches!(msg.status, 404 | 500) {
            return;
        }
        if let Some(ct) = wsdl(msg) {
            out.push(ALERT.raise("", ct).other_info("A WSDL File has been detected."));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scan::passive::util::testing::msg;

    const WSDL: &str = "<definitions xmlns=\"http://schemas.xmlsoap.org/wsdl/\"/>";

    #[test]
    fn by_url_or_type() {
        let f = msg("https://a.test/svc?WSDL").header("Content-Type", "text/xml").body(WSDL).scan(&WsdlFile);
        assert_eq!((f.len(), f[0].evidence.as_str()), (1, "text/xml"));
        assert_eq!(
            msg("https://a.test/a.wsdl").header("Content-Type", "application/xml").body(WSDL).scan(&WsdlFile).len(),
            1
        );
        let f = msg("https://a.test/svc").header("Content-Type", "application/wsdl+xml").body(WSDL).scan(&WsdlFile);
        assert_eq!(f[0].evidence, "application/wsdl+xml");
    }

    #[test]
    fn errors_html_and_other_urls_pass() {
        assert!(msg("https://a.test/svc?wsdl").html("<p>nope</p>").scan(&WsdlFile).is_empty());
        assert!(msg("https://a.test/svc?wsdl")
            .status(404)
            .header("Content-Type", "text/xml")
            .body(WSDL)
            .scan(&WsdlFile)
            .is_empty());
        assert!(msg("https://a.test/svc").header("Content-Type", "text/xml").body(WSDL).scan(&WsdlFile).is_empty());
        assert!(msg("https://a.test/svc?wsdl").header("Content-Type", "text/xml").scan(&WsdlFile).is_empty());
    }
}
