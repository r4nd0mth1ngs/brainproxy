//! Ported from ZAP CookieLooselyScopedScanRule (pscanrules, Apache License 2.0).

use std::sync::LazyLock;

use regex::Regex;

use crate::scan::passive::util::set_cookie_values;
use crate::scan::{AlertDef, Confidence, Finding, Message, PassiveRule, Risk};

static ALERT: AlertDef = AlertDef {
    alert_ref: "90033",
    name: "Loosely Scoped Cookie",
    risk: Risk::Info,
    confidence: Confidence::Low,
    cwe: 565,
    wasc: 15,
    description: "Cookies can be scoped by domain or path. This check is only concerned with domain scope.The domain \
        scope applied to a cookie determines which domains can access it. For example, a cookie can be scoped \
        strictly to a subdomain e.g. www.nottrusted.com, or loosely scoped to a parent domain e.g. nottrusted.com. \
        In the latter case, any subdomain of nottrusted.com can access the cookie. Loosely scoped cookies are \
        common in mega-applications like google.com and live.com. Cookies set from a subdomain like app.foo.bar \
        are transmitted only to that domain by the browser. However, cookies scoped to a parent-level domain may \
        be transmitted to the parent, or any subdomain of the parent.",
    solution: "Always scope cookies to a FQDN (Fully Qualified Domain Name).",
    references: &["https://datatracker.ietf.org/doc/html/rfc6265#section-4.1", "https://owasp.org/www-project-web-security-testing-guide/v41/4-Web_Application_Security_Testing/06-Session_Management_Testing/02-Testing_for_Cookies_Attributes.html", "https://code.google.com/archive/p/browsersec/wikis/Part2.wiki"],
    tags: &["OWASP_2025_A08", "OWASP_2021_A08", "OWASP_2017_A06", "WSTG-v42-SESS-02", "SYSTEMIC"],
};

static ALERTS: [&AlertDef; 1] = [&ALERT];

static DOMAIN_PATTERN: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?i)\bdomain\b\s*=\s*[^;]+").unwrap());

/// The parts of a `java.net.HttpCookie` the rule uses.
struct JavaCookie {
    name: String,
    /// Lower-cased Domain attribute (first one with a value), as written otherwise.
    domain: Option<String>,
}

const RESERVED: [&str; 11] = [
    "comment",
    "commenturl",
    "discard",
    "domain",
    "expires",
    "httponly",
    "max-age",
    "path",
    "port",
    "secure",
    "version",
];

/// `java.net.HttpCookie.parse(header)`; invalid cookies (which make Java throw) are dropped.
fn parse_cookies(header: &str) -> Vec<JavaCookie> {
    let lc = header.to_ascii_lowercase();
    let v1 = !lc.contains("expires=") && (lc.contains("version=") || lc.contains("max-age"));
    if v1 {
        split_outside_quotes(header).into_iter().filter_map(parse_cookie).collect()
    } else {
        parse_cookie(header).into_iter().collect()
    }
}

fn split_outside_quotes(s: &str) -> Vec<&str> {
    let mut out = Vec::new();
    let (mut start, mut quoted) = (0, false);
    for (i, c) in s.char_indices() {
        match c {
            '"' => quoted = !quoted,
            ',' if !quoted => {
                out.push(&s[start..i]);
                start = i + 1;
            }
            _ => {}
        }
    }
    out.push(&s[start..]);
    out
}

fn parse_cookie(s: &str) -> Option<JavaCookie> {
    let mut parts = s.split(';');
    let (name, _) = parts.next()?.split_once('=')?;
    let name = name.trim();
    let valid = !name.is_empty()
        && !name.starts_with('$')
        && !RESERVED.iter().any(|r| r.eq_ignore_ascii_case(name))
        && name.chars().all(|c| (' '..'\u{7f}').contains(&c) && !",; ".contains(c));
    if !valid {
        return None;
    }
    let mut domain = None;
    for a in parts {
        if let Some((k, v)) = a.split_once('=') {
            if domain.is_none() && k.trim().eq_ignore_ascii_case("domain") {
                let v = v.trim();
                let v = v.strip_prefix('"').and_then(|x| x.strip_suffix('"')).unwrap_or(v);
                domain = Some(v.to_lowercase());
            }
        }
    }
    Some(JavaCookie { name: name.to_string(), domain })
}

fn is_loosely_scoped(domain: &str, origin: &str) -> bool {
    if domain.is_empty() {
        return false;
    }
    let origin = origin.to_lowercase();
    let d = domain.strip_prefix('.').unwrap_or(domain);
    if d == origin || d.len() > origin.len() {
        return false;
    }
    origin.ends_with(&format!(".{d}"))
}

fn extract_evidence<'a>(headers: &[&'a str], cookie: &JavaCookie) -> Option<&'a str> {
    let domain = cookie.domain.as_deref()?;
    for h in headers {
        for p in parse_cookies(h) {
            if p.name == cookie.name && p.domain.as_deref() == Some(domain) {
                if let Some(m) = DOMAIN_PATTERN.find_iter(h).find(|m| m.as_str().to_lowercase().contains(domain)) {
                    return Some(m.as_str());
                }
            }
        }
    }
    None
}

pub struct CookieLooselyScoped;

impl PassiveRule for CookieLooselyScoped {
    fn id(&self) -> u32 {
        90033
    }

    fn name(&self) -> &'static str {
        "Loosely Scoped Cookie"
    }

    fn alerts(&self) -> &'static [&'static AlertDef] {
        &ALERTS
    }

    fn scan(&self, msg: &Message, out: &mut Vec<Finding>) {
        let headers = set_cookie_values(msg);
        if headers.is_empty() {
            return;
        }
        let host = &msg.host;
        let loose: Vec<JavaCookie> = headers
            .iter()
            .flat_map(|h| parse_cookies(h))
            .filter(|c| c.domain.as_deref().is_some_and(|d| is_loosely_scoped(d, host)))
            .collect();
        let Some(first) = loose.first() else { return };
        let names: String = loose.iter().map(|c| format!("Cookie name: {}\n", c.name)).collect();
        let evidence = extract_evidence(&headers, first).unwrap_or("");
        out.push(
            ALERT
                .raise("", evidence)
                .other_info(format!("The origin domain used for comparison was:\n{host}\n{names}")),
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scan::passive::util::testing::msg;

    #[test]
    fn flags_parent_domain_cookies_once() {
        let f = msg("https://sub.example.com/")
            .header("Set-Cookie", "a=1; Domain = .Example.com; Path=/")
            .header("Set-Cookie", "b=2; domain=example.com")
            .header("Set-Cookie", "c=3; domain=sub.example.com")
            .scan(&CookieLooselyScoped);
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].evidence, "Domain = .Example.com");
        assert_eq!(
            f[0].other_info,
            "The origin domain used for comparison was:\nsub.example.com\nCookie name: a\nCookie name: b\n"
        );
    }

    #[test]
    fn ignores_host_and_unrelated_domains() {
        let f = msg("https://example.com/")
            .header("Set-Cookie", "a=1; Domain=example.com")
            .header("Set-Cookie", "b=1; Domain=other.com")
            .header("Set-Cookie", "c=1")
            .header("Set-Cookie", "domain=1; Domain=com")
            .scan(&CookieLooselyScoped);
        assert!(f.is_empty());
    }
}
