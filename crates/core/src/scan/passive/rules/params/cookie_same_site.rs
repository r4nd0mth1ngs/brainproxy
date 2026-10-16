//! Ported from ZAP CookieSameSiteScanRule (pscanrules, Apache License 2.0).

use crate::scan::message::SetCookie;
use crate::scan::passive::util::{cookie_expired, set_cookie_evidence, set_cookie_values};
use crate::scan::{AlertDef, Confidence, Finding, Message, PassiveRule, Risk};

static MISSING: AlertDef = AlertDef {
    alert_ref: "10054-1",
    name: "Cookie without SameSite Attribute",
    risk: Risk::Low,
    confidence: Confidence::Medium,
    cwe: 1275,
    wasc: 13,
    description: "A cookie has been set without the SameSite attribute, which means that the cookie can be sent as a \
        result of a 'cross-site' request. The SameSite attribute is an effective counter measure to cross-site \
        request forgery, cross-site script inclusion, and timing attacks.",
    solution: "Ensure that the SameSite attribute is set to either 'lax' or ideally 'strict' for all cookies.",
    references: &["https://datatracker.ietf.org/doc/html/draft-ietf-httpbis-cookie-same-site"],
    tags: &["OWASP_2025_A01", "OWASP_2021_A01", "OWASP_2017_A05", "WSTG-v42-SESS-02", "SYSTEMIC"],
};

static NONE: AlertDef = AlertDef {
    alert_ref: "10054-2",
    name: "Cookie with SameSite Attribute None",
    risk: Risk::Low,
    confidence: Confidence::Medium,
    cwe: 1275,
    wasc: 13,
    description: "A cookie has been set with its SameSite attribute set to \"none\", which means that the cookie can \
        be sent as a result of a 'cross-site' request. The SameSite attribute is an effective counter measure to \
        cross-site request forgery, cross-site script inclusion, and timing attacks.",
    solution: "Ensure that the SameSite attribute is set to either 'lax' or ideally 'strict' for all cookies.",
    references: &["https://datatracker.ietf.org/doc/html/draft-ietf-httpbis-cookie-same-site"],
    tags: &["OWASP_2025_A01", "OWASP_2021_A01", "OWASP_2017_A05", "WSTG-v42-SESS-02", "SYSTEMIC"],
};

static INVALID: AlertDef = AlertDef {
    alert_ref: "10054-3",
    name: "Cookie with Invalid SameSite Attribute",
    risk: Risk::Low,
    confidence: Confidence::Medium,
    cwe: 1275,
    wasc: 13,
    description: "A cookie has been set with an invalid SameSite attribute value, which means that the cookie can be \
        sent as a result of a 'cross-site' request. The SameSite attribute is an effective counter measure to \
        cross-site request forgery, cross-site script inclusion, and timing attacks.",
    solution: "Ensure that the SameSite attribute is set to either 'lax' or ideally 'strict' for all cookies.",
    references: &["https://datatracker.ietf.org/doc/html/draft-ietf-httpbis-cookie-same-site"],
    tags: &["OWASP_2025_A01", "OWASP_2021_A01", "OWASP_2017_A05", "WSTG-v42-SESS-02", "SYSTEMIC"],
};

static ALERTS: [&AlertDef; 3] = [&MISSING, &NONE, &INVALID];

pub struct CookieSameSite;

impl PassiveRule for CookieSameSite {
    fn id(&self) -> u32 {
        10054
    }

    fn name(&self) -> &'static str {
        "Cookie without SameSite Attribute"
    }

    fn alerts(&self) -> &'static [&'static AlertDef] {
        &ALERTS
    }

    fn scan(&self, msg: &Message, out: &mut Vec<Finding>) {
        for raw in set_cookie_values(msg) {
            let c = SetCookie::parse(raw);
            if cookie_expired(&c) || !raw.contains('=') {
                continue;
            }
            let def = match c.attr("samesite") {
                None => &MISSING,
                Some(v) if v.eq_ignore_ascii_case("none") => &NONE,
                Some(v) if v.eq_ignore_ascii_case("strict") || v.eq_ignore_ascii_case("lax") => continue,
                Some(_) => &INVALID,
            };
            out.push(def.raise(c.name.clone(), set_cookie_evidence(msg, raw, &c.name)));
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
    fn flags_missing_none_and_invalid() {
        let f = msg("https://a.test/")
            .header("Set-Cookie", "a=1; Path=/")
            .header("Set-Cookie", "b=1; SameSite=None; Secure")
            .header("Set-Cookie", "c=1; SameSite")
            .header("Set-Cookie", "d=1; SameSite=bogus")
            .scan(&CookieSameSite);
        assert_eq!(refs(&f), ["10054-1", "10054-2", "10054-3", "10054-3"]);
        assert_eq!((f[1].param.as_str(), f[1].evidence.as_str()), ("b", "Set-Cookie: b"));
    }

    #[test]
    fn accepts_strict_lax_and_expired() {
        let f = msg("https://a.test/")
            .header("Set-Cookie", "a=1; SameSite=Strict")
            .header("Set-Cookie", "b=1; samesite=LAX")
            .header("Set-Cookie", "c=; Expires=Thu, 01-Jan-1970 00:00:00 GMT")
            .scan(&CookieSameSite);
        assert!(f.is_empty());
    }
}
