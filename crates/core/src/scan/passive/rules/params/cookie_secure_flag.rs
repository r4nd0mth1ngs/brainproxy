//! Ported from ZAP CookieSecureFlagScanRule (pscanrules, Apache License 2.0).

use crate::scan::message::SetCookie;
use crate::scan::passive::util::{cookie_expired, set_cookie_evidence, set_cookie_values};
use crate::scan::{AlertDef, Confidence, Finding, Message, PassiveRule, Risk};

static ALERT: AlertDef = AlertDef {
    alert_ref: "10011",
    name: "Cookie Without Secure Flag",
    risk: Risk::Low,
    confidence: Confidence::Medium,
    cwe: 614,
    wasc: 13,
    description: "A cookie has been set without the secure flag, which means that the cookie can be accessed via \
        unencrypted connections.",
    solution: "Whenever a cookie contains sensitive information or is a session token, then it should always be \
        passed using an encrypted channel. Ensure that the secure flag is set for cookies containing such \
        sensitive information.",
    references: &["https://owasp.org/www-project-web-security-testing-guide/v41/4-Web_Application_Security_Testing/06-Session_Management_Testing/02-Testing_for_Cookies_Attributes.html"],
    tags: &["OWASP_2025_A02", "OWASP_2021_A05", "OWASP_2017_A06", "WSTG-v42-SESS-02", "SYSTEMIC"],
};

static ALERTS: [&AlertDef; 1] = [&ALERT];

pub struct CookieSecureFlag;

impl PassiveRule for CookieSecureFlag {
    fn id(&self) -> u32 {
        10011
    }

    fn name(&self) -> &'static str {
        "Cookie Without Secure Flag"
    }

    fn alerts(&self) -> &'static [&'static AlertDef] {
        &ALERTS
    }

    fn scan(&self, msg: &Message, out: &mut Vec<Finding>) {
        if !msg.is_https() {
            return;
        }
        for raw in set_cookie_values(msg) {
            let c = SetCookie::parse(raw);
            if c.has("secure") || cookie_expired(&c) || !raw.contains('=') {
                continue;
            }
            out.push(ALERT.raise(c.name.clone(), set_cookie_evidence(msg, raw, &c.name)));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scan::passive::util::testing::msg;

    #[test]
    fn flags_https_cookie_without_secure() {
        let f = msg("https://a.test/").header("set-cookie", "sid=1; Path=/; HttpOnly").scan(&CookieSecureFlag);
        assert_eq!(f.len(), 1);
        assert_eq!((f[0].param.as_str(), f[0].evidence.as_str()), ("sid", "set-cookie: sid"));
    }

    #[test]
    fn ignores_secure_expired_and_plain_http() {
        let m = msg("https://a.test/")
            .header("Set-Cookie", "a=1; Secure")
            .header("Set-Cookie", "b=2; expires=Thu, 01 Jan 1970 00:00:00 GMT");
        assert!(m.scan(&CookieSecureFlag).is_empty());
        assert!(msg("http://a.test/").header("Set-Cookie", "a=1").scan(&CookieSecureFlag).is_empty());
    }
}
