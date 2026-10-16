//! Ported from ZAP UserControlledJavascriptEventScanRule (pscanrules, Apache License 2.0).

use super::common::{eq_ic, is_page_200, is_response_html, request_params};
use crate::scan::passive::util::tags;
use crate::scan::{AlertDef, Confidence, Finding, Message, PassiveRule, Risk};

static ALERT: AlertDef = AlertDef {
    alert_ref: "10043",
    name: "User Controllable JavaScript Event (XSS)",
    risk: Risk::Info,
    confidence: Confidence::Low,
    cwe: 20,
    wasc: 20,
    description: "This check looks at user-supplied input in query string parameters and POST data to identify where \
        certain HTML attribute values might be controlled. This provides hot-spot detection for XSS (cross-site \
        scripting) that will require further review by a security analyst to determine exploitability.",
    solution: "Validate all input and sanitize output it before writing to any Javascript on* events.",
    references: &["https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html"],
    tags: &["OWASP_2025_A05", "OWASP_2021_A03", "OWASP_2017_A01"],
};

static ALERTS: [&AlertDef; 1] = [&ALERT];

const JAVASCRIPT_EVENTS: [&str; 38] = [
    "onabort",
    "onbeforeunload",
    "onblur",
    "onchange",
    "onclick",
    "oncontextmenu",
    "ondblclick",
    "ondrag",
    "ondragend",
    "ondragenter",
    "ondragleave",
    "ondragover",
    "ondragstart",
    "ondrop",
    "onerror",
    "onfocus",
    "onhashchange",
    "onkeydown",
    "onkeypress",
    "onkeyup",
    "onload",
    "onmessage",
    "onmousedown",
    "onmousemove",
    "onmouseout",
    "onmouseover",
    "onmouseup",
    "onmousewheel",
    "onoffline",
    "ononline",
    "onpopstate",
    "onreset",
    "onresize",
    "onscroll",
    "onselect",
    "onstorage",
    "onsubmit",
    "onunload",
];

pub struct UserControlledJavascriptEvent;

impl PassiveRule for UserControlledJavascriptEvent {
    fn id(&self) -> u32 {
        10043
    }

    fn name(&self) -> &'static str {
        "User Controllable JavaScript Event (XSS)"
    }

    fn alerts(&self) -> &'static [&'static AlertDef] {
        &ALERTS
    }

    fn scan(&self, msg: &Message, out: &mut Vec<Finding>) {
        if !is_page_200(msg) || !is_response_html(msg) {
            return;
        }
        let params: Vec<_> = request_params(msg).into_iter().filter(|(_, v)| !v.is_empty()).collect();
        if params.is_empty() {
            return;
        }
        for tag in tags(msg.body()) {
            for (attr, value) in &tag.attrs {
                if JAVASCRIPT_EVENTS.binary_search(&attr.as_str()).is_err() {
                    continue;
                }
                for (name, pv) in &params {
                    for part in value.split([';', '=', ',', ':']) {
                        if eq_ic(part, pv) {
                            let info = format!(
                                "User-controlled javascript event(s) was found. Exploitability will need to be \
                                 manually determined. The page at the following URL:\n\n{}\n\nincludes the following \
                                 Javascript event which may be attacker-controllable:\n\nUser-input was found in the \
                                 following data of an [{attr}] event:\n{value}\n\nThe user input was:\n{pv}",
                                msg.url
                            );
                            out.push(ALERT.raise(name.clone(), "").other_info(info));
                        }
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scan::passive::util::testing::msg;

    #[test]
    fn events_are_sorted_for_binary_search() {
        assert!(JAVASCRIPT_EVENTS.windows(2).all(|w| w[0] < w[1]));
    }

    #[test]
    fn flags_param_in_event_handler() {
        let f = msg("https://a.test/p?fn=doThing&x=")
            .html("<html><body><a href=# OnClick=\"DOTHING;return false\">x</a></body></html>")
            .scan(&UserControlledJavascriptEvent);
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].param, "fn");
        assert!(f[0].other_info.contains("an [onclick] event:\nDOTHING;return false\n\nThe user input was:\ndoThing"));
    }

    #[test]
    fn flags_each_matching_part_and_form_params() {
        let f = msg("https://a.test/p")
            .method("POST")
            .req_header("Content-Type", "application/x-www-form-urlencoded")
            .req_body("v=1")
            .html("<body onload=\"f(x=1,y=1)\"><div onclick></div>")
            .scan(&UserControlledJavascriptEvent);
        // "f(x", "1", "y", "1)" -> only the exact "1" part matches.
        assert_eq!(f.len(), 1);
    }

    #[test]
    fn ignores_untrimmed_parts_non_events_and_non_html() {
        let page = "<a onclick=\"go(); doThing\" title=doThing>x</a>";
        assert!(msg("https://a.test/?q=doThing").html(page).scan(&UserControlledJavascriptEvent).is_empty());
        let json = msg("https://a.test/?q=go").header("Content-Type", "application/json").body("<a onclick=go>");
        assert!(json.scan(&UserControlledJavascriptEvent).is_empty());
        let redirect = msg("https://a.test/?q=go").status(302).html("<a onclick=go>");
        assert!(redirect.scan(&UserControlledJavascriptEvent).is_empty());
    }
}
