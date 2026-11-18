//! Ported from ZAP ContentSecurityPolicyMissingScanRule (pscanrules, Apache License 2.0).

use super::common::{has_markup, is_redirect, meta_http_equiv};
use crate::scan::{AlertDef, Confidence, Finding, Message, PassiveRule, Risk};

const TAGS: &[&str] = &["OWASP_2025_A02", "OWASP_2021_A05", "OWASP_2017_A06", "SYSTEMIC"];
const DESC: &str = "Content Security Policy (CSP) is an added layer of security that helps to detect and mitigate \
    certain types of attacks, including Cross Site Scripting (XSS) and data injection attacks. These attacks are \
    used for everything from data theft to site defacement or distribution of malware. CSP provides a set of \
    standard HTTP headers that allow website owners to declare approved sources of content that browsers should be \
    allowed to load on that page \u{2014} covered types are JavaScript, CSS, HTML frames, fonts, images and \
    embeddable objects such as Java applets, ActiveX, audio and video files.";
const SOLN: &str = "Ensure that your web server, application server, load balancer, etc. is configured to set the \
    Content-Security-Policy header.";
const REFS: &[&str] = &[
    "https://developer.mozilla.org/en-US/docs/Web/HTTP/Guides/CSP",
    "https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html",
    "https://www.w3.org/TR/CSP/",
    "https://w3c.github.io/webappsec-csp/",
    "https://web.dev/articles/csp",
    "https://caniuse.com/#feat=contentsecuritypolicy",
    "https://content-security-policy.com/",
];

static MISSING: AlertDef = AlertDef {
    alert_ref: "10038-1",
    name: "Content Security Policy (CSP) Header Not Set",
    risk: Risk::Medium,
    confidence: Confidence::High,
    cwe: 693,
    wasc: 15,
    description: DESC,
    solution: SOLN,
    references: REFS,
    tags: TAGS,
};

static OBSOLETE: AlertDef = AlertDef {
    alert_ref: "10038-2",
    name: "Obsolete Content Security Policy (CSP) Header Found",
    risk: Risk::Info,
    confidence: Confidence::High,
    cwe: 693,
    wasc: 15,
    description: "The \"X-Content-Security-Policy\" and \"X-WebKit-CSP\" headers are no longer recommended.",
    solution: SOLN,
    references: REFS,
    tags: TAGS,
};

static REPORT_ONLY: AlertDef = AlertDef {
    alert_ref: "10038-3",
    name: "Content Security Policy (CSP) Report-Only Header Found",
    risk: Risk::Info,
    confidence: Confidence::High,
    cwe: 693,
    wasc: 15,
    description: "The response contained a Content-Security-Policy-Report-Only header, this may indicate a \
        work-in-progress implementation, or an oversight in promoting pre-Prod to Prod, etc.\n\nContent Security \
        Policy (CSP) is an added layer of security that helps to detect and mitigate certain types of attacks, \
        including Cross Site Scripting (XSS) and data injection attacks. These attacks are used for everything from \
        data theft to site defacement or distribution of malware. CSP provides a set of standard HTTP headers that \
        allow website owners to declare approved sources of content that browsers should be allowed to load on \
        that page \u{2014} covered types are JavaScript, CSS, HTML frames, fonts, images and embeddable objects such \
        as Java applets, ActiveX, audio and video files.",
    solution: SOLN,
    references: &[
        "https://www.w3.org/TR/CSP2/",
        "https://w3c.github.io/webappsec-csp/",
        "https://caniuse.com/#feat=contentsecuritypolicy",
        "https://content-security-policy.com/",
    ],
    tags: TAGS,
};

static ALERTS: [&AlertDef; 3] = [&MISSING, &OBSOLETE, &REPORT_ONLY];

pub struct CspMissing;

impl PassiveRule for CspMissing {
    fn id(&self) -> u32 {
        10038
    }

    fn name(&self) -> &'static str {
        "Content Security Policy (CSP) Header Not Set"
    }

    fn alerts(&self) -> &'static [&'static AlertDef] {
        &ALERTS
    }

    fn page_level(&self) -> bool {
        true
    }

    fn scan(&self, msg: &Message, out: &mut Vec<Finding>) {
        if !msg.is_html() || is_redirect(msg.status) {
            return;
        }
        // Diverges from ZAP: a text/html body without markup can't run a script to restrict.
        if has_markup(msg)
            && msg.resp_header("Content-Security-Policy").is_none()
            && meta_http_equiv(msg.body(), "Content-Security-Policy").is_none()
        {
            out.push(MISSING.raise("", ""));
        }
        // Diverges from ZAP: OBSOLETE (10038-2) isn't raised, since the CSP rule's 10055-1/-2
        // report the same obsolete headers with their values. It stays listed so findings
        // recorded before still have their texts.
        if msg.resp_header("Content-Security-Policy-Report-Only").is_some() {
            out.push(REPORT_ONLY.raise("", ""));
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
    fn flags_missing_obsolete_and_report_only() {
        assert_eq!(refs(&msg("https://a.test/").html("<p>").scan(&CspMissing)), ["10038-1"]);
        assert_eq!(refs(&msg("https://a.test/").html("<p>").status(500).scan(&CspMissing)), ["10038-1"]);
        let f = msg("https://a.test/")
            .html("<p>")
            .header("X-WebKit-CSP", "default-src 'self'")
            .header("Content-Security-Policy-Report-Only", "default-src 'self'")
            .scan(&CspMissing);
        // The obsolete header is the CSP rule's 10055-2, not reported twice.
        assert_eq!(refs(&f), ["10038-1", "10038-3"]);
    }

    /// socket.io answers a POST with `ok` as text/html: not a page that runs scripts.
    #[test]
    fn ignores_html_without_markup() {
        let ok = msg("https://a.test/socket.io/?EIO=4&transport=polling").method("POST").html("ok");
        assert!(ok.scan(&CspMissing).is_empty());
    }

    #[test]
    fn ignores_present_policy_and_out_of_scope() {
        let h = msg("https://a.test/").html("<p>").header("Content-Security-Policy", "default-src 'self'");
        assert!(h.scan(&CspMissing).is_empty());
        let m = msg("https://a.test/").html("<meta http-equiv='content-security-policy' content=\"x\">");
        assert!(m.scan(&CspMissing).is_empty());
        assert!(msg("https://a.test/").html("<p>").status(301).scan(&CspMissing).is_empty());
        assert!(msg("https://a.test/")
            .header("Content-Type", "application/json")
            .body("{}")
            .scan(&CspMissing)
            .is_empty());
    }
}
