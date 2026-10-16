//! Ported from ZAP UserControlledCookieScanRule (pscanrules, Apache License 2.0).

use super::common::{is_get, request_params, response_charset};
use crate::scan::{AlertDef, Confidence, Finding, Message, PassiveRule, Risk};

static ALERT: AlertDef = AlertDef {
    alert_ref: "10029",
    name: "Cookie Poisoning",
    risk: Risk::Info,
    confidence: Confidence::Low,
    cwe: 565,
    wasc: 20,
    description: "This check looks at user-supplied input in query string parameters and POST data to identify where \
        cookie parameters might be controlled. This is called a cookie poisoning attack, and becomes exploitable \
        when an attacker can manipulate the cookie in various ways. In some cases this will not be exploitable, \
        however, allowing URL parameters to set cookie values is generally considered a bug.",
    solution: "Do not allow user input to control cookie names and values. If some query string parameters must be \
        set in cookie values, be sure to filter out semicolon's that can serve as name/value pair delimiters.",
    references: &["https://en.wikipedia.org/wiki/HTTP_cookie", "https://cwe.mitre.org/data/definitions/565.html"],
    tags: &["OWASP_2025_A05", "OWASP_2021_A03", "OWASP_2017_A01", "SYSTEMIC"],
};

static ALERTS: [&AlertDef; 1] = [&ALERT];

const GET_TEXT: &str = "An attacker may be able to poison cookie values through URL parameters. Try injecting a \
     semicolon to see if you can add cookie values (e.g. name=controlledValue;name=anotherValue;).\n\n";
const POST_TEXT: &str = "An attacker may be able to poison cookie values through POST parameters. To test if this \
     is a more serious issue, you should try resending that request as a GET, with the POST parameter included as a \
     query string parameter. For example: https://nottrusted.com/page?value=maliciousInput.\n\n";

/// `java.net.URLDecoder.decode(cookie, charset)`: '+' becomes a space and %XX
/// escapes are decoded as UTF-8 when the response charset says so, ISO-8859-1
/// otherwise. Malformed escapes (where Java throws) leave the value as is.
fn decode_cookie(cookie: &str, charset: Option<&str>) -> String {
    if !cookie.contains(['%', '+']) {
        return cookie.to_string();
    }
    let utf8 = charset.is_some_and(|c| c.eq_ignore_ascii_case("utf-8") || c.eq_ignore_ascii_case("utf8"));
    let flush = |buf: &mut Vec<u8>, out: &mut String| {
        if utf8 {
            out.push_str(&String::from_utf8_lossy(buf));
        } else {
            // ISO-8859-1: every byte is the code point of the same value.
            out.extend(buf.iter().map(|&c| c as char));
        }
        buf.clear();
    };
    let mut out = String::with_capacity(cookie.len());
    let mut buf = Vec::new();
    let mut chars = cookie.char_indices();
    while let Some((i, c)) = chars.next() {
        if c == '%' {
            let hex = cookie.get(i + 1..i + 3).and_then(|h| u8::from_str_radix(h, 16).ok());
            let Some(v) = hex else { return cookie.to_string() };
            buf.push(v);
            chars.nth(1);
            continue;
        }
        flush(&mut buf, &mut out);
        out.push(if c == '+' { ' ' } else { c });
    }
    flush(&mut buf, &mut out);
    out
}

pub struct UserControlledCookie;

impl PassiveRule for UserControlledCookie {
    fn id(&self) -> u32 {
        10029
    }

    fn name(&self) -> &'static str {
        "Cookie Poisoning"
    }

    fn alerts(&self) -> &'static [&'static AlertDef] {
        &ALERTS
    }

    fn scan(&self, msg: &Message, out: &mut Vec<Finding>) {
        if msg.resp_header("set-cookie").is_none() {
            return;
        }
        let params: Vec<_> = request_params(msg).into_iter().filter(|(_, v)| v.chars().count() > 1).collect();
        if params.is_empty() {
            return;
        }
        let charset = response_charset(msg);
        let intro = match is_get(msg) {
            Some(true) => GET_TEXT,
            Some(false) => POST_TEXT,
            None => "",
        };
        for raw in msg.resp_headers_named("set-cookie") {
            let cookie = decode_cookie(raw, charset);
            if cookie.is_empty() {
                continue;
            }
            for part in cookie.split([';', '=', '|']) {
                for (name, value) in &params {
                    if value == part {
                        let info = format!(
                            "{intro}This was identified at:\n\n{}\n\nUser-input was found in the following \
                             cookie:\n{cookie}\n\nThe user input was:\n{name}={value}",
                            msg.url
                        );
                        out.push(ALERT.raise(name.clone(), "").other_info(info));
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
    fn flags_param_value_in_cookie() {
        let f =
            msg("https://a.test/?lang=fr%20ca").header("Set-Cookie", "lang=fr+ca; Path=/").scan(&UserControlledCookie);
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].param, "lang");
        assert!(f[0].other_info.starts_with(GET_TEXT));
        assert!(f[0].other_info.contains("following cookie:\nlang=fr ca; Path=/\n\nThe user input was:\nlang=fr ca"));
    }

    #[test]
    fn decodes_and_survives_malformed_escapes() {
        assert_eq!(decode_cookie("a=%E9", None), "a=\u{e9}");
        assert_eq!(decode_cookie("a=%C3%A9", Some("UTF-8")), "a=\u{e9}");
        assert_eq!(decode_cookie("a=%zz+", None), "a=%zz+");
        let f = msg("https://a.test/?v=%zz").header("Set-Cookie", "v=%zz").scan(&UserControlledCookie);
        assert_eq!(f.len(), 1);
    }

    #[test]
    fn ignores_short_case_mismatched_and_untrimmed_values() {
        let m = msg("https://a.test/?a=1&b=Path&c=Abc")
            .header("Set-Cookie", "x=1; Path=/")
            .header("Set-Cookie", "y=abc")
            .header("Set-Cookie2", "z=Abc");
        assert!(m.scan(&UserControlledCookie).is_empty());
    }
}
