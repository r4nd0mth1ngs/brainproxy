//! Ported from ZAP CsrfCountermeasuresScanRule (pscanrules, Apache License 2.0).

use super::common::{element_end, has_parent_element};
use crate::scan::passive::util::{find_ci, tags};
use crate::scan::{AlertDef, Confidence, Finding, Message, PassiveRule, Risk};

// Text reconstructed from ZAP core vulnerabilities.xml (wasc_9).
static ALERT: AlertDef = AlertDef {
    alert_ref: "10202",
    name: "Absence of Anti-CSRF Tokens",
    risk: Risk::Medium,
    confidence: Confidence::Low,
    cwe: 352,
    wasc: 9,
    description: "No Anti-CSRF tokens were found in a HTML submission form.\nA cross-site request forgery is an \
        attack that involves forcing a victim to send an HTTP request to a target destination without their \
        knowledge or intent in order to perform an action as the victim. The underlying cause is application \
        functionality using predictable URL/form actions in a repeatable way. The nature of the attack is that \
        CSRF exploits the trust that a web site has for a user. By contrast, cross-site scripting (XSS) exploits \
        the trust that a user has for a web site. Like XSS, CSRF attacks are not necessarily cross-site, but they \
        can be. Cross-site request forgery is also known as CSRF, XSRF, one-click attack, session riding, confused \
        deputy, and sea surf.\n\nCSRF attacks are effective in a number of situations, including:\n    * The \
        victim has an active session on the target site.\n    * The victim is authenticated via HTTP auth on the \
        target site.\n    * The victim is on the same local network as the target site.\n\nCSRF has primarily been \
        used to perform an action against a target site using the victim's privileges, but recent techniques have \
        been discovered to disclose information by gaining access to the response. The risk of information \
        disclosure is dramatically increased when the target site is vulnerable to XSS, because XSS can be used as \
        a platform for CSRF, allowing the attack to operate within the bounds of the same-origin policy.",
    solution: "Phase: Architecture and Design\n\nUse a vetted library or framework that does not allow this weakness \
        to occur or provides constructs that make this weakness easier to avoid.\n\nFor example, use anti-CSRF \
        packages such as the OWASP CSRFGuard.\n\nPhase: Implementation\n\nEnsure that your application is free of \
        cross-site scripting issues, because most CSRF defenses can be bypassed using attacker-controlled \
        script.\n\nPhase: Architecture and Design\n\nGenerate a unique nonce for each form, place the nonce into \
        the form, and verify the nonce upon receipt of the form. Be sure that the nonce is not predictable \
        (CWE-330).\n\nNote that this can be bypassed using XSS.\n\nIdentify especially dangerous operations. When \
        the user performs a dangerous operation, send a separate confirmation request to ensure that the user \
        intended to perform that operation.\n\nNote that this can be bypassed using XSS.\n\nUse the ESAPI Session \
        Management control.\n\nThis control includes a component for CSRF.\n\nDo not use the GET method for any \
        request that triggers a state change.\n\nPhase: Implementation\n\nCheck the HTTP Referer header to see if \
        the request originated from an expected page. This could break legitimate functionality, because users or \
        proxies may have disabled sending the Referer for privacy reasons.",
    references: &[
        "https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html",
        "https://cwe.mitre.org/data/definitions/352.html",
    ],
    tags: &["OWASP_2025_A01", "OWASP_2021_A01", "OWASP_2017_A05", "WSTG-v42-SESS-05", "SYSTEMIC"],
};

static ALERTS: [&AlertDef; 1] = [&ALERT];

/// ZAP's default anti-CSRF token names (Options > Anti-CSRF Tokens), compared case-insensitively.
const ANTI_CSRF_TOKENS: [&str; 15] = [
    "anticsrf",
    "CSRFToken",
    "__RequestVerificationToken",
    "csrfmiddlewaretoken",
    "authenticity_token",
    "OWASP_CSRFTOKEN",
    "anoncsrf",
    "csrf_token",
    "_csrf",
    "_csrfSecret",
    "__csrf_magic",
    "CSRF",
    "_token",
    "_csrf_token",
    "_csrfToken",
];

fn is_anti_csrf_token(name: &str) -> bool {
    ANTI_CSRF_TOKENS.iter().any(|t| t.eq_ignore_ascii_case(name))
}

pub struct CsrfCountermeasures;

impl PassiveRule for CsrfCountermeasures {
    fn id(&self) -> u32 {
        10202
    }

    fn name(&self) -> &'static str {
        "Absence of Anti-CSRF Tokens"
    }

    fn alerts(&self) -> &'static [&'static AlertDef] {
        &ALERTS
    }

    fn scan(&self, msg: &Message, out: &mut Vec<Finding>) {
        if !msg.is_html() {
            return;
        }
        let html = msg.body();
        if find_ci(html, "<form", 0).is_none() {
            return;
        }
        let all = tags(html);
        let mut form_idx = 0;
        for (i, form) in all.iter().enumerate() {
            if form.name != "form" {
                continue;
            }
            form_idx += 1;
            if form.attr("method").is_none_or(|m| m.eq_ignore_ascii_case("GET")) {
                continue;
            }
            if !has_parent_element(html, &all, i) {
                continue;
            }
            let end = element_end(html, form);
            let mut names: Vec<&str> = Vec::new();
            let mut found_token = false;
            for input in all[i + 1..].iter().take_while(|t| t.start < end).filter(|t| t.name == "input") {
                let id = input.attr("id");
                if let Some(id) = id {
                    if !names.iter().any(|n| n.to_lowercase() == id.to_lowercase()) {
                        names.push(id);
                    }
                    found_token |= is_anti_csrf_token(id);
                }
                if let Some(name) = input.attr("name") {
                    if id.is_none() && !names.iter().any(|n| n.to_lowercase() == name.to_lowercase()) {
                        names.push(name);
                    }
                    found_token |= is_anti_csrf_token(name);
                }
            }
            if found_token {
                continue;
            }
            names.sort_by_key(|n| n.to_lowercase());
            let info = format!(
                "No known Anti-CSRF token [{}] was found in the following HTML form: [Form {form_idx}: \"{}\" ].",
                ANTI_CSRF_TOKENS.join(", "),
                names.join("\" \"")
            );
            out.push(ALERT.raise("", &html[form.start..form.end]).other_info(info));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scan::passive::util::testing::msg;

    fn scan(html: &str) -> Vec<Finding> {
        msg("https://a.test/").html(html).scan(&CsrfCountermeasures)
    }

    #[test]
    fn flags_post_form_without_token() {
        let f = scan(
            "<html><body><form method=get></form><form id=\"no_csrf_token\" method=\"POST\"><input id=\"Cat\"/>\
             <input name=\"bar\"/><input id=\"art\" name=\"x\"/><input id=\"cat\"><input type=submit></form></body></html>",
        );
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].evidence, "<form id=\"no_csrf_token\" method=\"POST\">");
        assert_eq!(
            f[0].other_info,
            format!(
                "No known Anti-CSRF token [{}] was found in the following HTML form: [Form 2: \"art\" \"bar\" \"Cat\" ].",
                ANTI_CSRF_TOKENS.join(", ")
            )
        );
        assert!(f[0].other_info.contains("[anticsrf, CSRFToken, __RequestVerificationToken,"));
    }

    #[test]
    fn ignores_forms_with_tokens_get_forms_and_parentless_forms() {
        assert!(scan("<html><body><form method=post><input name=CSRFTOKEN></form></body></html>").is_empty());
        assert!(scan("<html><body><form method=post><input type=hidden id=_csrf></form></body></html>").is_empty());
        assert!(scan("<html><body><form><input name=q></form></body></html>").is_empty());
        assert!(scan("<form method=post><input name=q></form>").is_empty());
        let json = msg("https://a.test/").header("Content-Type", "application/json").body("<html><form method=post>");
        assert!(json.scan(&CsrfCountermeasures).is_empty());
    }

    #[test]
    fn token_outside_form_does_not_count() {
        let f = scan("<html><body><form method=post><input name=q></form><input name=_csrf></body></html>");
        assert_eq!(f.len(), 1);
        assert!(f[0].other_info.ends_with("[Form 1: \"q\" ]."));
    }
}
