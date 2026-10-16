//! Ported from ZAP UserControlledCharsetScanRule (pscanrules, Apache License 2.0).

use std::sync::LazyLock;

use regex::Regex;

use super::common::{eq_ic, is_page_200, is_response_html, request_params, response_charset};
use crate::scan::passive::util::{decode_entities, find_ci, tags};
use crate::scan::{AlertDef, Confidence, Finding, Message, PassiveRule, Risk};

static ALERT: AlertDef = AlertDef {
    alert_ref: "10030",
    name: "User Controllable Charset",
    risk: Risk::Info,
    confidence: Confidence::Low,
    cwe: 20,
    wasc: 20,
    description: "This check looks at user-supplied input in query string parameters and POST data to identify where \
        Content-Type or meta tag charset declarations might be user-controlled. Such charset declarations should \
        always be declared by the application. If an attacker can control the response charset, they could \
        manipulate the HTML to perform XSS or other attacks. For example, an attacker controlling the <meta> \
        element charset value is able to declare UTF-7 and is also able to include enough user-controlled payload \
        early in the HTML document to have it interpreted as UTF-7. By encoding their payload with UTF-7 the \
        attacker is able to bypass any server-side XSS protections and embed script in the page.",
    solution: "Force UTF-8 in all charset declarations. If user-input is required to decide a charset declaration, \
        ensure that only an allowed list is used.",
    references: &[],
    tags: &["OWASP_2025_A05", "OWASP_2021_A03", "OWASP_2017_A01", "SYSTEMIC"],
};

static ALERTS: [&AlertDef; 1] = [&ALERT];

static XML_ENCODING: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"(?i)\sencoding\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s?>]*))"#).unwrap());

/// Jericho `Source.isXML()`: starts with an XML declaration, or has an XHTML doctype.
fn is_xml(body: &str) -> bool {
    if body.trim_start_matches(['\u{feff}', ' ', '\t', '\r', '\n']).starts_with("<?xml") {
        return true;
    }
    find_ci(body, "<!doctype", 0)
        .and_then(|s| body[s..].find('>').map(|e| &body[s..s + e]))
        .is_some_and(|d| find_ci(d, "xhtml", 0).is_some())
}

/// The encoding attribute of the first `<?xml ...?>` declaration.
fn xml_encoding(body: &str) -> Option<String> {
    let start = body.find("<?xml")?;
    let rest = &body[start + 5..];
    if !rest.starts_with(|c: char| c.is_ascii_whitespace()) {
        return None;
    }
    let decl = &rest[..rest.find("?>").unwrap_or(rest.len())];
    let c = XML_ENCODING.captures(decl)?;
    let v = c.get(1).or(c.get(2)).or(c.get(3))?.as_str();
    Some(decode_entities(v))
}

pub struct UserControlledCharset;

impl UserControlledCharset {
    fn raise(out: &mut Vec<Finding>, params: &[(String, String)], tag: &str, attr: &str, charset: &str) {
        for (name, value) in params {
            if eq_ic(charset, value) {
                let info = format!(
                    "A(n) [{tag}] tag [{attr}] attribute\n\nThe user input found was:\n{name}={value}\n\nThe \
                     charset value it controlled was:\n{charset}"
                );
                out.push(ALERT.raise(name.clone(), "").other_info(info));
            }
        }
    }
}

impl PassiveRule for UserControlledCharset {
    fn id(&self) -> u32 {
        10030
    }

    fn name(&self) -> &'static str {
        "User Controllable Charset"
    }

    fn alerts(&self) -> &'static [&'static AlertDef] {
        &ALERTS
    }

    fn scan(&self, msg: &Message, out: &mut Vec<Finding>) {
        if !is_page_200(msg) {
            return;
        }
        let params = request_params(msg);
        if params.is_empty() {
            return;
        }
        let body = msg.body();
        if is_response_html(msg) {
            for t in tags(body).iter().filter(|t| t.name == "meta") {
                let (Some(equiv), Some(content)) = (t.attr("http-equiv"), t.attr("content")) else { continue };
                if !equiv.eq_ignore_ascii_case("content-type") {
                    continue;
                }
                let content = content.trim();
                let Some(i) = content.find("charset=") else { continue };
                Self::raise(out, &params, "META", "Content-Type", &content[i + 8..]);
            }
        } else if is_xml(body) {
            if let Some(enc) = xml_encoding(body).filter(|e| !e.is_empty()) {
                Self::raise(out, &params, "\\?xml", "encoding", &enc);
            }
        } else {
            return;
        }
        if let Some(cs) = response_charset(msg) {
            Self::raise(out, &params, "Content-Type HTTP header", "charset", cs);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scan::passive::util::testing::msg;

    #[test]
    fn flags_meta_and_header_charset() {
        let f = msg("https://a.test/?cs=utf-7")
            .header("Content-Type", "text/html; charset=UTF-7")
            .body("<html><head><META HTTP-EQUIV=\"Content-Type\" content=\"text/html; charset=UTF-7\"></head></html>")
            .scan(&UserControlledCharset);
        assert_eq!(f.len(), 2);
        assert_eq!(
            f[0].other_info,
            "A(n) [META] tag [Content-Type] attribute\n\nThe user input found was:\ncs=utf-7\n\nThe charset value \
             it controlled was:\nUTF-7"
        );
        assert!(f[1].other_info.starts_with("A(n) [Content-Type HTTP header] tag [charset] attribute"));
    }

    #[test]
    fn flags_xml_declaration_encoding() {
        let f = msg("https://a.test/?e=ISO-8859-1")
            .header("Content-Type", "application/xml")
            .body("<?xml version=\"1.0\" encoding=\"iso-8859-1\"?><a/>")
            .scan(&UserControlledCharset);
        assert_eq!(f.len(), 1);
        assert!(f[0].other_info.starts_with("A(n) [\\?xml] tag [encoding] attribute"));
    }

    #[test]
    fn ignores_uncontrolled_charsets_and_non_200() {
        let page = "<meta http-equiv=content-type content=\"text/html; charset=utf-8\"><meta charset=utf-7>";
        let m = msg("https://a.test/?cs=utf-7").header("Content-Type", "text/html").body(page);
        assert!(m.scan(&UserControlledCharset).is_empty());
        let m = msg("https://a.test/?cs=utf-8").status(404).header("Content-Type", "text/html").body(page);
        assert!(m.scan(&UserControlledCharset).is_empty());
        let text = msg("https://a.test/?cs=utf-8").header("Content-Type", "text/plain; charset=utf-8");
        assert!(text.scan(&UserControlledCharset).is_empty());
    }
}
