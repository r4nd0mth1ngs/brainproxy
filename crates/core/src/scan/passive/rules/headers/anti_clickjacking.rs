//! Ported from ZAP AntiClickjackingScanRule (pscanrules, Apache License 2.0).

use super::common::{header_values, is_error, is_redirect, meta_http_equiv, zap_is_text};
use crate::scan::{AlertDef, Confidence, Finding, Message, PassiveRule, Risk};

const TAGS: &[&str] = &["OWASP_2025_A02", "OWASP_2021_A05", "OWASP_2017_A06", "WSTG-v42-CLNT-09", "SYSTEMIC"];
const HEADER: &str = "X-Frame-Options";

static MISSING: AlertDef = AlertDef {
    alert_ref: "10020-1",
    name: "Missing Anti-clickjacking Header",
    risk: Risk::Medium,
    confidence: Confidence::Medium,
    cwe: 1021,
    wasc: 15,
    description: "The response does not protect against 'ClickJacking' attacks. It should include either \
        Content-Security-Policy with 'frame-ancestors' directive or X-Frame-Options.",
    solution: "Modern Web browsers support the Content-Security-Policy and X-Frame-Options HTTP headers. Ensure one \
        of them is set on all web pages returned by your site/app.\nIf you expect the page to be framed only by \
        pages on your server (e.g. it's part of a FRAMESET) then you'll want to use SAMEORIGIN, otherwise if you \
        never expect the page to be framed, you should use DENY. Alternatively consider implementing Content \
        Security Policy's \"frame-ancestors\" directive.",
    references: &["https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/X-Frame-Options"],
    tags: TAGS,
};

static MULTIPLE: AlertDef = AlertDef {
    alert_ref: "10020-2",
    name: "Multiple X-Frame-Options Header Entries",
    risk: Risk::Medium,
    confidence: Confidence::Medium,
    cwe: 1021,
    wasc: 15,
    description: "X-Frame-Options (XFO) headers were found, a response with multiple XFO header entries may not be \
        predictably treated by all user-agents.",
    solution: "Ensure only a single X-Frame-Options header is present in the response.",
    references: &["https://datatracker.ietf.org/doc/html/rfc7034"],
    tags: TAGS,
};

static META: AlertDef = AlertDef {
    alert_ref: "10020-3",
    name: "X-Frame-Options Defined via META (Non-compliant with Spec)",
    risk: Risk::Medium,
    confidence: Confidence::Medium,
    cwe: 1021,
    wasc: 15,
    description: "An X-Frame-Options (XFO) META tag was found, defining XFO via a META tag is explicitly not \
        supported by the spec (RFC 7034).",
    solution: "Ensure X-Frame-Options is set via a response header field. Alternatively consider implementing \
        Content Security Policy's \"frame-ancestors\" directive.",
    references: &["https://datatracker.ietf.org/doc/html/rfc7034#section-4"],
    tags: TAGS,
};

static MALFORMED: AlertDef = AlertDef {
    alert_ref: "10020-4",
    name: "X-Frame-Options Setting Malformed",
    risk: Risk::Medium,
    confidence: Confidence::Medium,
    cwe: 1021,
    wasc: 15,
    description: "An X-Frame-Options header was present in the response but the value was not correctly set.",
    solution: "Ensure a valid setting is used on all web pages returned by your site (if you expect the page to be \
        framed only by pages on your server (e.g. it's part of a FRAMESET) then you'll want to use SAMEORIGIN, \
        otherwise if you never expect the page to be framed, you should use DENY. Alternatively consider \
        implementing Content Security Policy's \"frame-ancestors\" directive.",
    references: &["https://datatracker.ietf.org/doc/html/rfc7034#section-2.1"],
    tags: TAGS,
};

static ALERTS: [&AlertDef; 4] = [&MISSING, &MULTIPLE, &META, &MALFORMED];

pub struct AntiClickjacking;

impl PassiveRule for AntiClickjacking {
    fn id(&self) -> u32 {
        10020
    }

    fn name(&self) -> &'static str {
        "Anti-clickjacking Header"
    }

    fn alerts(&self) -> &'static [&'static AlertDef] {
        &ALERTS
    }

    fn scan(&self, msg: &Message, out: &mut Vec<Finding>) {
        if !msg.is_html() || msg.resp_body.is_empty() || !zap_is_text(msg) {
            return;
        }
        if is_error(msg.status) || is_redirect(msg.status) {
            return;
        }
        // ZAP: plain substring test on the joined CSP header values, no parsing.
        if header_values(msg, "Content-Security-Policy").any(|v| v.contains("frame-ancestors")) {
            return;
        }
        let xfo: Vec<&str> = header_values(msg, HEADER).collect();
        if xfo.is_empty() {
            out.push(MISSING.raise(HEADER, ""));
        } else {
            for v in &xfo {
                let lv = v.to_lowercase();
                if !lv.contains("deny") && !lv.contains("sameorigin") {
                    out.push(MALFORMED.raise(HEADER, *v));
                }
            }
            if xfo.len() > 1 {
                out.push(MULTIPLE.raise(HEADER, ""));
            }
        }
        let body = msg.body();
        if let Some(meta) = meta_http_equiv(body, HEADER) {
            out.push(META.raise(HEADER, &body[meta.start..meta.end]));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scan::passive::util::testing::msg;

    fn refs(f: &[Finding]) -> Vec<&str> {
        f.iter().map(|f| f.def.alert_ref).collect()
    }

    #[test]
    fn flags_missing_malformed_multiple_and_meta() {
        let f = msg("https://a.test/").html("<p>").scan(&AntiClickjacking);
        assert_eq!(refs(&f), ["10020-1"]);
        assert_eq!(f[0].param, HEADER);
        let f = msg("https://a.test/")
            .html("<head><meta http-equiv=\"x-frame-options\" content=\"DENY\"></head>")
            .header(HEADER, "ALLOW-FROM https://b.test")
            .header(HEADER, "DENY")
            .scan(&AntiClickjacking);
        assert_eq!(refs(&f), ["10020-4", "10020-2", "10020-3"]);
        assert_eq!(f[0].evidence, "ALLOW-FROM https://b.test");
        assert_eq!(f[2].evidence, "<meta http-equiv=\"x-frame-options\" content=\"DENY\">");
    }

    #[test]
    fn ignores_good_header_csp_and_out_of_scope() {
        assert!(msg("https://a.test/").html("<p>").header(HEADER, "SAMEORIGIN").scan(&AntiClickjacking).is_empty());
        let csp = msg("https://a.test/").html("<p>").header("Content-Security-Policy", "frame-ancestors 'none'");
        assert!(csp.scan(&AntiClickjacking).is_empty());
        assert!(msg("https://a.test/").html("<p>").status(404).scan(&AntiClickjacking).is_empty());
        assert!(msg("https://a.test/").html("<p>").status(302).scan(&AntiClickjacking).is_empty());
        assert!(msg("https://a.test/")
            .header("Content-Type", "text/plain")
            .body("x")
            .scan(&AntiClickjacking)
            .is_empty());
        assert!(msg("https://a.test/").html("").scan(&AntiClickjacking).is_empty());
    }
}
