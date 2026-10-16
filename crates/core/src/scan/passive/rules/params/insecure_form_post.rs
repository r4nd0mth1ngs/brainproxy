//! Ported from ZAP InsecureFormPostScanRule (pscanrules, Apache License 2.0).

use super::common::{element_end, is_page_200, is_response_html};
use crate::scan::passive::util::tags;
use crate::scan::{AlertDef, Confidence, Finding, Message, PassiveRule, Risk};

static ALERT: AlertDef = AlertDef {
    alert_ref: "10042",
    name: "HTTPS to HTTP Insecure Transition in Form Post",
    risk: Risk::Medium,
    confidence: Confidence::Medium,
    cwe: 319,
    wasc: 15,
    description: "This check identifies secure HTTPS pages that host insecure HTTP forms. The issue is that a secure \
        page is transitioning to an insecure page when data is uploaded through a form. The user may think they're \
        submitting data to a secure page when in fact they are not.",
    solution: "Ensure sensitive data is only sent over secured HTTPS channels.",
    references: &[],
    tags: &["OWASP_2025_A04", "OWASP_2021_A02", "OWASP_2017_A06", "WSTG-v42-CRYP-03"],
};

static ALERTS: [&AlertDef; 1] = [&ALERT];

pub struct InsecureFormPost;

impl PassiveRule for InsecureFormPost {
    fn id(&self) -> u32 {
        10042
    }

    fn name(&self) -> &'static str {
        "HTTPS to HTTP Insecure Transition in Form Post"
    }

    fn alerts(&self) -> &'static [&'static AlertDef] {
        &ALERTS
    }

    fn scan(&self, msg: &Message, out: &mut Vec<Finding>) {
        // ZAP compares the scheme case-sensitively with "https".
        if !is_page_200(msg) || msg.scheme != "https" || !is_response_html(msg) {
            return;
        }
        let html = msg.body();
        for form in tags(html).iter().filter(|t| t.name == "form") {
            let Some(action) = form.attr("action").map(str::trim) else { continue };
            if action.to_lowercase().starts_with("http://") {
                let info = format!(
                    "The response to the following request over HTTPS included an HTTP form tag action attribute \
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
    fn flags_http_form_on_https_page() {
        let page = "<html><FORM ACTION='http://a.test/login' method=post><input name=u></FORM></html>";
        let f = msg("https://a.test/").html(page).scan(&InsecureFormPost);
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].evidence, "http://a.test/login");
        assert!(f[0].other_info.starts_with(
            "The response to the following request over HTTPS included an HTTP form tag action attribute value:\n\n\
             https://a.test/\nThe context was:\n\n<FORM ACTION="
        ));
    }

    #[test]
    fn ignores_http_pages_and_secure_actions() {
        let page = "<form action=\"http://a.test/login\"></form>";
        assert!(msg("http://a.test/").html(page).scan(&InsecureFormPost).is_empty());
        let ok = "<form action=\"https://a.test/login\"></form><form action=/relative></form>";
        assert!(msg("https://a.test/").html(ok).scan(&InsecureFormPost).is_empty());
    }
}
