//! Ported from ZAP PermissionsPolicyScanRule (pscanrulesBeta, Apache License 2.0).

use super::common::{header_values, is_redirect};
use crate::scan::passive::rules::content::common::is_javascript;
use crate::scan::{AlertDef, Confidence, Finding, Message, PassiveRule, Risk};

static MISSING: AlertDef = AlertDef {
    alert_ref: "10063-1",
    name: "Permissions Policy Header Not Set",
    risk: Risk::Low,
    confidence: Confidence::Medium,
    cwe: 693,
    wasc: 15,
    description: "Permissions Policy Header is an added layer of security that helps to restrict from unauthorized \
        access or usage of browser/client features by web resources. This policy ensures the user privacy by limiting \
        or specifying the features of the browsers can be used by the web resources. Permissions Policy provides a \
        set of standard HTTP headers that allow website owners to limit which features of browsers can be used by \
        the page such as camera, microphone, location, full screen etc.",
    solution: "Ensure that your web server, application server, load balancer, etc. is configured to set the \
        Permissions-Policy header.",
    references: &[
        "https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Permissions-Policy",
        "https://developer.chrome.com/blog/feature-policy/",
        "https://scotthelme.co.uk/a-new-security-header-feature-policy/",
        "https://w3c.github.io/webappsec-feature-policy/",
        "https://www.smashingmagazine.com/2018/12/feature-policy/",
    ],
    tags: TAGS,
};

static DEPRECATED: AlertDef = AlertDef {
    alert_ref: "10063-2",
    name: "Deprecated Feature Policy Header Set",
    risk: Risk::Low,
    confidence: Confidence::Medium,
    cwe: 16,
    wasc: 15,
    description: "The header has now been renamed to Permissions-Policy.",
    solution: "Ensure that your web server, application server, load balancer, etc. is configured to set the \
        Permissions-Policy header instead of the Feature-Policy header.",
    references: &[
        "https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Permissions-Policy",
        "https://scotthelme.co.uk/goodbye-feature-policy-and-hello-permissions-policy/",
    ],
    tags: TAGS,
};

const TAGS: &[&str] = &["OWASP_2025_A01", "OWASP_2021_A01", "OWASP_2017_A05", "SYSTEMIC"];

static ALERTS: [&AlertDef; 2] = [&MISSING, &DEPRECATED];

const HEADER: &str = "Permissions-Policy";
const DEPRECATED_HEADER: &str = "Feature-Policy";

pub struct PermissionsPolicy;

impl PassiveRule for PermissionsPolicy {
    fn id(&self) -> u32 {
        10063
    }

    fn name(&self) -> &'static str {
        "Permissions Policy Header Not Set"
    }

    fn alerts(&self) -> &'static [&'static AlertDef] {
        &ALERTS
    }

    fn page_level(&self) -> bool {
        true
    }

    fn scan(&self, msg: &Message, out: &mut Vec<Finding>) {
        // ZAP raises redirects only at the LOW threshold. An empty body (ZAP judges it too) has no
        // feature to restrict.
        if (!msg.is_html() && !is_javascript(msg)) || is_redirect(msg.status) || msg.resp_body.is_empty() {
            return;
        }
        if header_values(msg, DEPRECATED_HEADER).next().is_some() {
            out.push(DEPRECATED.raise("", DEPRECATED_HEADER));
        } else if header_values(msg, HEADER).next().is_none() {
            out.push(MISSING.raise("", ""));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scan::passive::util::testing::msg;

    #[test]
    fn missing_or_deprecated() {
        let f = msg("https://a.test/").html("<p>").scan(&PermissionsPolicy);
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].def.alert_ref, "10063-1");
        let f = msg("https://a.test/app.js").body("x()").scan(&PermissionsPolicy);
        assert_eq!(f[0].def.alert_ref, "10063-1", "a script by its path");
        let f = msg("https://a.test/")
            .html("<p>")
            .header("Feature-Policy", "camera 'none'")
            .header(HEADER, "camera=()")
            .scan(&PermissionsPolicy);
        assert_eq!((f.len(), f[0].def.alert_ref, f[0].evidence.as_str()), (1, "10063-2", "Feature-Policy"));
    }

    #[test]
    fn set_redirects_and_other_types_pass() {
        assert!(msg("https://a.test/").html("<p>").header(HEADER, "camera=()").scan(&PermissionsPolicy).is_empty());
        assert!(msg("https://a.test/").html("<p>").status(302).scan(&PermissionsPolicy).is_empty());
        assert!(msg("https://a.test/").html("").scan(&PermissionsPolicy).is_empty(), "an empty body");
        assert!(msg("https://a.test/x.json")
            .header("Content-Type", "application/json")
            .body("{}")
            .scan(&PermissionsPolicy)
            .is_empty());
    }
}
