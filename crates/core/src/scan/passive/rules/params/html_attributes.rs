//! Ported from ZAP UserControlledHTMLAttributesScanRule (pscanrules, Apache License 2.0).

use std::sync::LazyLock;

use regex::Regex;

use super::common::{eq_ic, is_page_200, is_response_html, java_url, request_params};
use crate::scan::passive::util::tags;
use crate::scan::{AlertDef, Confidence, Finding, Message, PassiveRule, Risk};

static ALERT: AlertDef = AlertDef {
    alert_ref: "10031",
    name: "User Controllable HTML Element Attribute (Potential XSS)",
    risk: Risk::Info,
    confidence: Confidence::Low,
    cwe: 20,
    wasc: 20,
    description: "This check looks at user-supplied input in query string parameters and POST data to identify where \
        certain HTML attribute values might be controlled. This provides hot-spot detection for XSS (cross-site \
        scripting) that will require further review by a security analyst to determine exploitability.",
    solution: "Validate all input and sanitize output it before writing to any HTML attributes.",
    references: &["https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html"],
    tags: &["OWASP_2025_A05", "OWASP_2021_A03", "OWASP_2017_A01"],
};

static ALERTS: [&AlertDef; 1] = [&ALERT];

/// Java `^\s*?[0-9]+?\s*?;\s*?url\s*?=.*` with `matches()` (whole string, `.`
/// excluding line terminators, ASCII `\s`).
static META_REFRESH: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\A[ \t\n\x0B\x0C\r]*[0-9]+[ \t\n\x0B\x0C\r]*;[ \t\n\x0B\x0C\r]*url[ \t\n\x0B\x0C\r]*=[^\n\r\u{85}\u{2028}\u{2029}]*\z")
        .unwrap()
});

fn is_short(v: &str) -> bool {
    v.chars().nth(1).is_none()
}

/// Java `String.trim()`.
fn java_trim(s: &str) -> &str {
    s.trim_matches(|c: char| c <= ' ')
}

pub struct UserControlledHtmlAttributes;

impl PassiveRule for UserControlledHtmlAttributes {
    fn id(&self) -> u32 {
        10031
    }

    fn name(&self) -> &'static str {
        "User Controllable HTML Element Attribute (Potential XSS)"
    }

    fn alerts(&self) -> &'static [&'static AlertDef] {
        &ALERTS
    }

    fn scan(&self, msg: &Message, out: &mut Vec<Finding>) {
        if !is_page_200(msg) || !is_response_html(msg) {
            return;
        }
        let params: Vec<(String, String, String)> =
            request_params(msg).into_iter().map(|(n, v)| (v.to_lowercase(), n, v)).collect();
        if params.is_empty() {
            return;
        }
        for tag in tags(msg.body()) {
            'attr: for (attr, value) in &tag.attrs {
                let mut v = value.to_lowercase();
                let meta_content = tag.name == "meta" && attr == "content";
                if meta_content && META_REFRESH.is_match(&v) {
                    // Java takes substring(indexOf("url=") + 4), i.e. from 3 when "url=" is absent.
                    let from = v.find("url=").map(|i| i + 4).unwrap_or(3);
                    v = java_trim(&v[from..]).to_string();
                }
                if v.is_empty() {
                    continue;
                }
                let has_scheme = v.find("://").is_some_and(|i| i > 0);
                let (mut protocol, mut domain, mut token) = (None, None, None);
                if has_scheme {
                    let Some(url) = java_url(&v) else { continue };
                    token = url.query.map(|q| match q.find('/') {
                        Some(i) if i > 0 => &q[..i],
                        _ => q,
                    });
                    domain = url.authority;
                    protocol = Some(url.protocol);
                }
                let mut raise = |name: &str, pvalue: &str| {
                    let info = format!(
                        "User-controlled HTML attribute values were found. Try injecting special characters to see if \
                         XSS might be possible. The page at the following URL:\n\n{}\n\nappears to include user input \
                         in:\na(n) [{}] tag [{attr}] attribute\n\nThe user input found was:\n{name}={pvalue}\n\nThe \
                         user-controlled value was:\n{v}",
                        msg.url, tag.name
                    );
                    out.push(ALERT.raise(name, "").other_info(info));
                };
                for (pv, name, original) in &params {
                    if meta_content {
                        if v.contains("charset") || is_short(pv) {
                            continue;
                        }
                        if v.split([';', '=', ',']).any(|s| java_trim(s) == pv) {
                            raise(name, original);
                            continue 'attr;
                        }
                    }
                    if !is_short(pv)
                        && (v.starts_with(pv.as_str())
                            || protocol.as_deref().is_some_and(|p| eq_ic(pv, p))
                            || domain.is_some_and(|d| eq_ic(pv, d))
                            || token.is_some_and(|t| eq_ic(pv, t))
                            || (has_scheme && pv.starts_with(v.as_str())))
                    {
                        raise(name, original);
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

    fn scan(url: &str, html: &str) -> Vec<Finding> {
        msg(url).html(html).scan(&UserControlledHtmlAttributes)
    }

    #[test]
    fn flags_attribute_starting_with_param() {
        let f = scan("https://a.test/?name=Fred", "<html><img alt='fred smith' src=x.png></html>");
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].param, "name");
        assert!(f[0].other_info.contains("a(n) [img] tag [alt] attribute\n\nThe user input found was:\nname=Fred"));
        assert!(f[0].other_info.ends_with("The user-controlled value was:\nfred smith"));
    }

    #[test]
    fn flags_controlled_url_parts() {
        let f = scan(
            "https://a.test/?h=evil.test&p=https",
            "<a href=\"http://x.test/\">a</a><a href=\"https://evil.test/\">b</a>",
        );
        // href #1: protocol "http" != "https"; href #2: protocol and domain both match.
        assert_eq!(f.iter().map(|f| f.param.as_str()).collect::<Vec<_>>(), ["h", "p"]);
        let f = scan("https://a.test/?q=id=5", "<a href=\"https://b.test/x?id=5/extra\">b</a>");
        assert_eq!(f.len(), 1);
    }

    #[test]
    fn flags_meta_refresh_target_once() {
        let f = scan(
            "https://a.test/?next=https://evil.test/&y=evil.test",
            "<meta http-equiv=refresh content=\"0; URL=https://evil.test/\">",
        );
        // The split match on the meta content stops processing that attribute.
        assert_eq!(f.len(), 1);
        assert!(f[0].other_info.ends_with("The user-controlled value was:\nhttps://evil.test/"));
    }

    #[test]
    fn ignores_short_values_unparsable_urls_and_non_html() {
        assert!(scan("https://a.test/?a=f", "<img alt=fred>").is_empty());
        assert!(scan("https://a.test/?a=evil.test", "<a href=\"https://evil.test/a b\">x</a>").is_empty());
        assert!(scan("https://a.test/?a=zzz", "<img alt=fred>").is_empty());
        let json = msg("https://a.test/?a=fred").header("Content-Type", "application/json").body("<img alt=fred>");
        assert!(json.scan(&UserControlledHtmlAttributes).is_empty());
    }
}
