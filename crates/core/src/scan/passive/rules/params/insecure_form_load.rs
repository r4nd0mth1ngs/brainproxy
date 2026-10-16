//! Ported from ZAP InsecureFormLoadScanRule (pscanrules, Apache License 2.0).

use super::common::{element_end, is_page_200, is_response_html};
use crate::scan::passive::util::tags;
use crate::scan::{AlertDef, Confidence, Finding, Message, PassiveRule, Risk};

static ALERT: AlertDef = AlertDef {
    alert_ref: "10041",
    name: "HTTP to HTTPS Insecure Transition in Form Post",
    risk: Risk::Medium,
    confidence: Confidence::Medium,
    cwe: 319,
    wasc: 15,
    description: "This check looks for insecure HTTP pages that host HTTPS forms. The issue is that an insecure HTTP \
        page can easily be hijacked through MITM and the secure HTTPS form can be replaced or spoofed.",
    solution: "Use HTTPS for landing pages that host secure forms.",
    references: &[],
    tags: &["OWASP_2025_A04", "OWASP_2021_A02", "OWASP_2017_A06", "WSTG-v42-CRYP-03"],
};

static ALERTS: [&AlertDef; 1] = [&ALERT];

pub struct InsecureFormLoad;

impl PassiveRule for InsecureFormLoad {
    fn id(&self) -> u32 {
        10041
    }

    fn name(&self) -> &'static str {
        "HTTP to HTTPS Insecure Transition in Form Post"
    }

    fn alerts(&self) -> &'static [&'static AlertDef] {
        &ALERTS
    }

    fn scan(&self, msg: &Message, out: &mut Vec<Finding>) {
        // ZAP compares the scheme case-sensitively with "https".
        if !is_page_200(msg) || msg.scheme == "https" || !is_response_html(msg) {
            return;
        }
        let html = msg.body();
        for form in tags(html).iter().filter(|t| t.name == "form") {
            let Some(action) = form.attr("action").map(str::trim) else { continue };
            if action.to_lowercase().starts_with("https://") {
                let info = format!(
                    "The response to the following request over HTTP included an HTTPS form tag action attribute \
                     value:\n\n{}\nThe context was:\n\n{}",
                    msg.url,
                    &html[form.start..element_end(html, form)]
                );
                out.push(ALERT.raise("", action).other_info(info));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scan::passive::util::testing::msg;

    #[test]
    fn flags_https_form_on_http_page() {
        let page = "<html><form action=\" HTTPS://a.test/login \"><input name=u></form></html>";
        let f = msg("http://a.test/").html(page).scan(&InsecureFormLoad);
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].evidence, "HTTPS://a.test/login");
        assert!(f[0]
            .other_info
            .ends_with("The context was:\n\n<form action=\" HTTPS://a.test/login \"><input name=u></form>"));
    }

    #[test]
    fn ignores_https_pages_and_http_actions() {
        let page = "<form action=\"https://a.test/login\"></form>";
        assert!(msg("https://a.test/").html(page).scan(&InsecureFormLoad).is_empty());
        let http = "<form action=\"http://a.test/login\"></form><form></form>";
        assert!(msg("http://a.test/").html(http).scan(&InsecureFormLoad).is_empty());
    }
}
