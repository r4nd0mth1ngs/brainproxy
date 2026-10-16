//! Ported from ZAP UserControlledOpenRedirectScanRule (pscanrules, Apache License 2.0).

use super::common::{eq_ic, is_get, java_url, request_params, url_authority};
use crate::scan::{AlertDef, Confidence, Finding, Message, PassiveRule, Risk};

static ALERT: AlertDef = AlertDef {
    alert_ref: "10028",
    name: "Off-site Redirect",
    risk: Risk::High,
    confidence: Confidence::Medium,
    cwe: 601,
    wasc: 38,
    description: "Open redirects are one of the OWASP 2010 Top Ten vulnerabilities. This check looks at user-supplied \
        input in query string parameters and POST data to identify where open redirects might be possible. Open \
        redirects occur when an application allows user-supplied input (e.g. https://nottrusted.com) to control an \
        off-site destination. This is generally a pretty accurate way to find where 301 or 302 redirects could be \
        exploited by spammers or phishing attacks.\n\nFor example an attacker could supply a user with the \
        following link: https://example.com/example.php?url=https://malicious.example.com.\n\nNOTE: For the \
        purposes of the passive check the authority portion of the origin and destination were compared. Manual \
        testing may be required to validate the impact of this finding.",
    solution: "To avoid the open redirect vulnerability, parameters of the application script/program must be \
        validated before sending 302 HTTP code (redirect) to the client browser. Implement safe redirect \
        functionality that only redirects to relative URI's, or a list of trusted domains.",
    references: &[
        "https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html",
        "https://cwe.mitre.org/data/definitions/601.html",
    ],
    tags: &["OWASP_2025_A05", "OWASP_2021_A03", "OWASP_2017_A01", "WSTG-v42-CLNT-04"],
};

static ALERTS: [&AlertDef; 1] = [&ALERT];

const GET_TEXT: &str =
    "The 301 or 302 response to a request for the following URL appeared to contain user input in the location \
     header:\n\n";
const POST_TEXT: &str = "An open redirect controlled by POST parameters was detected. To test if this is a more \
     serious issue, you should try resending that request as a GET, with the POST parameter included as a query \
     string parameter. For example: https://nottrusted.com/page?url=https://lookout.net.\n\nThe 301 or 302 response \
     to a request for the following URL appeared to contain user input in the location header:\n\n";

pub struct UserControlledOpenRedirect;

impl PassiveRule for UserControlledOpenRedirect {
    fn id(&self) -> u32 {
        10028
    }

    fn name(&self) -> &'static str {
        "Off-site Redirect"
    }

    fn alerts(&self) -> &'static [&'static AlertDef] {
        &ALERTS
    }

    fn scan(&self, msg: &Message, out: &mut Vec<Finding>) {
        if msg.status != 301 && msg.status != 302 {
            return;
        }
        let Some(loc) = msg.resp_header("location") else { return };
        // Relative locations can never match (no authority, no "://").
        let absolute = loc.find("://").is_some_and(|i| i > 0);
        if !absolute {
            return;
        }
        let params = request_params(msg);
        if params.is_empty() {
            return;
        }
        let Some(url) = java_url(loc) else { return };
        let domain = url.authority;
        if let (Some(req), Some(d)) = (url_authority(&msg.url), domain) {
            if eq_ic(req, d) {
                return;
            }
        }
        let intro = match is_get(msg) {
            Some(true) => GET_TEXT,
            Some(false) => POST_TEXT,
            None => "",
        };
        for (name, value) in &params {
            if value.is_empty() {
                continue;
            }
            if domain.is_some_and(|d| eq_ic(value, d)) || value.contains(loc) {
                let info = format!(
                    "{intro}{}\n\nThe user input found was:\n\n{name}={value}\n\nThe context was:\n\n{loc}",
                    msg.url
                );
                out.push(ALERT.raise(name.clone(), "").other_info(info));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scan::passive::util::testing::msg;

    #[test]
    fn flags_param_controlled_offsite_location() {
        let f = msg("https://a.test/go?url=https://evil.test/x&x=1")
            .status(302)
            .header("Location", "https://evil.test/x")
            .scan(&UserControlledOpenRedirect);
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].param, "url");
        assert!(f[0].other_info.starts_with(GET_TEXT));
        assert!(f[0].other_info.ends_with("url=https://evil.test/x\n\nThe context was:\n\nhttps://evil.test/x"));
    }

    #[test]
    fn flags_post_param_equal_to_authority() {
        let f = msg("https://a.test/go")
            .method("POST")
            .req_header("Content-Type", "application/x-www-form-urlencoded")
            .req_body("host=EVIL.test")
            .status(301)
            .header("Location", "http://evil.test/landing")
            .scan(&UserControlledOpenRedirect);
        assert_eq!(f.len(), 1);
        assert!(f[0].other_info.starts_with("An open redirect controlled by POST"));
    }

    #[test]
    fn ignores_same_site_relative_and_other_statuses() {
        let same = msg("https://a.test/go?u=https://a.test/x").status(302).header("Location", "https://a.test/x");
        assert!(same.scan(&UserControlledOpenRedirect).is_empty());
        let rel = msg("https://a.test/go?u=/x").status(302).header("Location", "/x");
        assert!(rel.scan(&UserControlledOpenRedirect).is_empty());
        let s303 = msg("https://a.test/go?u=https://e.test/").status(303).header("Location", "https://e.test/");
        assert!(s303.scan(&UserControlledOpenRedirect).is_empty());
        let unrelated = msg("https://a.test/go?u=hello").status(302).header("Location", "https://e.test/");
        assert!(unrelated.scan(&UserControlledOpenRedirect).is_empty());
    }
}
