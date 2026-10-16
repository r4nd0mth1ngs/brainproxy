//! Ported from ZAP CookieHttpOnlyScanRule (pscanrules, Apache License 2.0).

use crate::scan::message::SetCookie;
use crate::scan::passive::util::{cookie_expired, set_cookie_evidence, set_cookie_values};
use crate::scan::{AlertDef, Confidence, Finding, Message, PassiveRule, Risk};

static ALERT: AlertDef = AlertDef {
    alert_ref: "10010",
    name: "Cookie No HttpOnly Flag",
    risk: Risk::Low,
    confidence: Confidence::Medium,
    cwe: 1004,
    wasc: 13,
    description: "A cookie has been set without the HttpOnly flag, which means that the cookie can be accessed by \
        JavaScript. If a malicious script can be run on this page then the cookie will be accessible and can be \
        transmitted to another site. If this is a session cookie then session hijacking may be possible.",
    solution: "Ensure that the HttpOnly flag is set for all cookies.",
    references: &["https://owasp.org/www-community/HttpOnly"],
    tags: &["OWASP_2025_A02", "OWASP_2021_A05", "OWASP_2017_A06", "WSTG-v42-SESS-02", "SYSTEMIC"],
};

static ALERTS: [&AlertDef; 1] = [&ALERT];

pub struct CookieHttpOnly;

impl PassiveRule for CookieHttpOnly {
    fn id(&self) -> u32 {
        10010
    }

    fn name(&self) -> &'static str {
        "Cookie No HttpOnly Flag"
    }

    fn alerts(&self) -> &'static [&'static AlertDef] {
        &ALERTS
    }

    fn scan(&self, msg: &Message, out: &mut Vec<Finding>) {
        for raw in set_cookie_values(msg) {
            let c = SetCookie::parse(raw);
            if c.has("httponly") || cookie_expired(&c) || !raw.contains('=') {
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
    fn flags_cookie_without_httponly() {
        let f = msg("https://a.test/").header("Set-Cookie", "sid=1; Path=/").scan(&CookieHttpOnly);
        assert_eq!(f.len(), 1);
        assert_eq!((f[0].param.as_str(), f[0].evidence.as_str()), ("sid", "Set-Cookie: sid"));
    }

    #[test]
    fn ignores_httponly_and_expired() {
        let m = msg("https://a.test/")
            .header("Set-Cookie", "a=1; HttpOnly")
            .header("set-cookie", "b=; expires=Thu, 01-Jan-1970 00:00:00 GMT");
        assert!(m.scan(&CookieHttpOnly).is_empty());
    }
}
