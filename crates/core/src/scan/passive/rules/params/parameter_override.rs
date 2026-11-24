//! Ported from ZAP ServletParameterPollutionScanRule (pscanrulesBeta, Apache License 2.0).
//!
//! ZAP raises this only at the LOW threshold, and only when the context's technology includes
//! JSP/Servlet, which by default is every context. brainproxy's passive rules have no
//! threshold, so instead the page must show it is served by a Java servlet container (see
//! [`servlet`]): a form without an action is common elsewhere, and harmless where the
//! framework doesn't merge query and body parameters.

use super::super::content::common::element_source;
use crate::scan::passive::util::tags;
use crate::scan::{AlertDef, Confidence, Finding, Message, PassiveRule, Risk};

static ALERT: AlertDef = AlertDef {
    alert_ref: "10026",
    name: "HTTP Parameter Override",
    risk: Risk::Medium,
    confidence: Confidence::Low,
    cwe: 20,
    wasc: 20,
    description: "Unspecified form action: HTTP parameter override attack potentially possible. This is a known \
        problem with Java Servlets but other platforms may also be vulnerable.",
    solution: "All forms must specify the action URL.",
    references: &[
        "https://download.oracle.com/javaee-archive/servlet-spec.java.net/jsr340-experts/att-0317/OnParameterPollutionAttacks.pdf",
    ],
    tags: &["OWASP_2025_A06", "OWASP_2021_A04", "OWASP_2017_A06"],
};

static ALERTS: [&AlertDef; 1] = [&ALERT];

/// Whether the exchange shows a Java servlet container: a `JSESSIONID` cookie either way, a
/// `.jsp`, `.jspx`, `.do` or `.action` path, or a `Servlet`/`JSP` product in `X-Powered-By`.
fn servlet(msg: &Message) -> bool {
    let path = msg.path.to_ascii_lowercase();
    let path = path.split(';').next().unwrap_or_default();
    let cookie = |v: &str| v.to_ascii_lowercase().contains("jsessionid=");
    [".jsp", ".jspx", ".do", ".action"].iter().any(|e| path.ends_with(e))
        || msg.path.to_ascii_lowercase().contains(";jsessionid=")
        || msg.req_headers_named("Cookie").any(cookie)
        || msg.resp_headers_named("Set-Cookie").any(cookie)
        || msg.resp_headers_named("X-Powered-By").any(|v| {
            let v = v.to_ascii_lowercase();
            v.contains("servlet") || v.contains("jsp")
        })
}

pub struct ParameterOverride;

impl PassiveRule for ParameterOverride {
    fn id(&self) -> u32 {
        10026
    }

    fn name(&self) -> &'static str {
        "HTTP Parameter Override"
    }

    fn alerts(&self) -> &'static [&'static AlertDef] {
        &ALERTS
    }

    fn scan(&self, msg: &Message, out: &mut Vec<Finding>) {
        if !msg.is_html() || !servlet(msg) {
            return;
        }
        let body = msg.body();
        // One per page: the first form without an action, its start tag as evidence.
        if let Some(form) =
            tags(body).into_iter().find(|t| t.name == "form" && t.attr("action").is_none_or(str::is_empty))
        {
            let start = body.get(form.start..form.end).unwrap_or_else(|| element_source(body, &form));
            out.push(ALERT.raise("", start));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scan::passive::util::testing::msg;

    const PAGE: &str = "<form action=\"/a\"></form><form method=\"post\" id=\"f\"><input name=q></form>";

    #[test]
    fn a_form_without_an_action_on_a_servlet_page() {
        let f = msg("https://a.test/search.jsp").html(PAGE).scan(&ParameterOverride);
        assert_eq!((f.len(), f[0].evidence.as_str()), (1, "<form method=\"post\" id=\"f\">"));
        let f = msg("https://a.test/search")
            .req_header("Cookie", "JSESSIONID=ABC")
            .html("<form action=\"\">")
            .scan(&ParameterOverride);
        assert_eq!(f[0].evidence, "<form action=\"\">");
    }

    #[test]
    fn other_platforms_and_forms_with_actions_pass() {
        assert!(msg("https://a.test/search").html(PAGE).scan(&ParameterOverride).is_empty());
        assert!(msg("https://a.test/a.jsp").html("<form action=\"/a\"></form>").scan(&ParameterOverride).is_empty());
    }
}
