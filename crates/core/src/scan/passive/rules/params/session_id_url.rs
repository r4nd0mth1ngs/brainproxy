//! Ported from ZAP InfoSessionIdUrlScanRule (pscanrules, Apache License 2.0).

use std::sync::LazyLock;

use regex::Regex;

use super::common::url_params;
use crate::scan::passive::util::find_ci;
use crate::scan::{AlertDef, Confidence, Finding, Message, PassiveRule, Risk};

static URL_PARAM: AlertDef = AlertDef {
    alert_ref: "3-1",
    name: "Session ID in URL Rewrite",
    risk: Risk::Medium,
    confidence: Confidence::High,
    cwe: 598,
    wasc: 13,
    description: "URL rewrite is used to track user session ID. The session ID may be disclosed via cross-site \
        referer header. In addition, the session ID might be stored in browser history or server logs.",
    solution: "For secure content, put session ID in a cookie. To be even more secure consider using a combination of \
        cookie and URL rewrite.",
    references: &["https://seclists.org/webappsec/2002/q4/111"],
    tags: &["OWASP_2025_A01", "OWASP_2021_A01", "OWASP_2017_A03", "WSTG-v42-SESS-04", "SYSTEMIC"],
};

static URL_PATH: AlertDef = AlertDef {
    alert_ref: "3-2",
    name: "Session ID in URL Rewrite",
    risk: Risk::Medium,
    confidence: Confidence::High,
    cwe: 598,
    wasc: 13,
    description: "URL rewrite is used to track user session ID. The session ID may be disclosed via cross-site \
        referer header. In addition, the session ID might be stored in browser history or server logs.",
    solution: "For secure content, put session ID in a cookie. To be even more secure consider using a combination of \
        cookie and URL rewrite.",
    references: &["https://seclists.org/webappsec/2002/q4/111"],
    tags: &["OWASP_2025_A01", "OWASP_2021_A01", "OWASP_2017_A03", "WSTG-v42-SESS-04", "SYSTEMIC"],
};

static REFERER: AlertDef = AlertDef {
    alert_ref: "3-3",
    name: "Referer Exposes Session ID",
    risk: Risk::Medium,
    confidence: Confidence::Medium,
    cwe: 598,
    wasc: 13,
    description: "A hyperlink pointing to another host name was found. As session ID URL rewrite is used, it may be \
        disclosed in referer header to external hosts.",
    solution: "This is a risk if the session ID is sensitive and the hyperlink refers to an external or third party \
        host. For secure content, put session ID in secured session cookie.",
    references: &["https://seclists.org/webappsec/2002/q4/111"],
    tags: &["OWASP_2025_A01", "OWASP_2021_A01", "OWASP_2017_A03", "WSTG-v42-SESS-04", "SYSTEMIC"],
};

static ALERTS: [&AlertDef; 3] = [&URL_PARAM, &URL_PATH, &REFERER];

/// ZAP's default session token names (HTTP Sessions options), compared case-insensitively.
const SESSION_IDS: [&str; 11] = [
    "asp.net_sessionid",
    "aspsessionid",
    "siteserver",
    "cfid",
    "cftoken",
    "jsessionid",
    "phpsessid",
    "sessid",
    "sid",
    "viewstate",
    "zenid",
];

const SESSION_TOKEN_MIN_LENGTH: usize = 8;

static EXT_LINK_PATTERNS: LazyLock<[Regex; 3]> = LazyLock::new(|| {
    const EXT_LINK: &str = r"https?://([\w.\-]+)";
    [
        Regex::new(&format!(r#"(?i-u)src\s*=\s*["']?{EXT_LINK}"#)).unwrap(),
        Regex::new(&format!(r#"(?i-u)href\s*=\s*["']?{EXT_LINK}"#)).unwrap(),
        Regex::new(&format!(r#"(?i-u)[=(]\s*["']{EXT_LINK}"#)).unwrap(),
    ]
});

/// Java `(?i)jsessionid=[\dA-Z]{8,}` `find()`: the first match in `path`.
fn path_session_id(path: &str) -> Option<&str> {
    const KEY: &str = "jsessionid=";
    let mut from = 0;
    while let Some(i) = find_ci(path, KEY, from) {
        let run = path[i + KEY.len()..].bytes().take_while(u8::is_ascii_alphanumeric).count();
        if run >= SESSION_TOKEN_MIN_LENGTH {
            return Some(&path[i..i + KEY.len() + run]);
        }
        from = i + 1;
    }
    None
}

pub struct InfoSessionIdUrl;

impl PassiveRule for InfoSessionIdUrl {
    fn id(&self) -> u32 {
        3
    }

    fn name(&self) -> &'static str {
        "Session ID in URL Rewrite"
    }

    fn alerts(&self) -> &'static [&'static AlertDef] {
        &ALERTS
    }

    fn scan(&self, msg: &Message, out: &mut Vec<Finding>) {
        let mut found = false;
        if msg.query.is_some() {
            for (name, value) in url_params(msg) {
                if SESSION_IDS.contains(&name.to_lowercase().as_str())
                    && value.encode_utf16().count() > SESSION_TOKEN_MIN_LENGTH
                {
                    out.push(URL_PARAM.raise(name, value));
                    found = true;
                }
            }
        }
        if !found {
            let path = percent_encoding::percent_decode_str(&msg.path).decode_utf8_lossy();
            if let Some(m) = path_session_id(&path) {
                out.push(URL_PATH.raise("", m));
                found = true;
            }
        }
        if !found {
            return;
        }
        let body = msg.body();
        for p in EXT_LINK_PATTERNS.iter() {
            let Some(link_host) = p.captures(body).and_then(|c| c.get(1)) else { continue };
            if !link_host.as_str().eq_ignore_ascii_case(&msg.host) {
                let risk = if msg.is_https() { Risk::Medium } else { Risk::Low };
                out.push(REFERER.raise("", link_host.as_str()).risk(risk));
                break;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scan::passive::util::testing::msg;

    #[test]
    fn flags_session_param_and_external_link() {
        let f = msg("https://a.test/page?PHPSESSID=0123456789abcdef&sid=short")
            .html("<a href=\"https://a.test/x\">in</a><img src='http://cdn.other.test/i.png'>")
            .scan(&InfoSessionIdUrl);
        assert_eq!(f.len(), 2);
        assert_eq!((f[0].def.alert_ref, f[0].param.as_str()), ("3-1", "PHPSESSID"));
        assert_eq!(f[0].evidence, "0123456789abcdef");
        assert_eq!((f[1].def.alert_ref, f[1].evidence.as_str(), f[1].risk), ("3-3", "cdn.other.test", Risk::Medium));
    }

    #[test]
    fn flags_jsessionid_in_path() {
        let f = msg("http://a.test/app;jsessionid=1A530637289A03B0?x=1")
            // Only the first match of each pattern counts: href -> a.test (same host), then `= '...'` -> ext.test.
            .html("<script>var u = 'https://ext.test/';</script><a href=\"http://a.test/\">same</a>")
            .scan(&InfoSessionIdUrl);
        assert_eq!(f.len(), 2);
        assert_eq!((f[0].def.alert_ref, f[0].evidence.as_str()), ("3-2", "jsessionid=1A530637289A03B0"));
        assert_eq!((f[1].def.alert_ref, f[1].evidence.as_str(), f[1].risk), ("3-3", "ext.test", Risk::Low));
    }

    #[test]
    fn ignores_short_or_unknown_tokens() {
        let f = msg("https://a.test/x;jsessionid=1234567?aspsessionidabc=0123456789&sid=12345678")
            .html("<img src=\"https://other.test/\">")
            .scan(&InfoSessionIdUrl);
        assert!(f.is_empty());
    }
}
