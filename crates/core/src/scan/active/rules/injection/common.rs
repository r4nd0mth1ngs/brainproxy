//! Helpers shared by the injection rules, rebuilt from ZAP core (`AbstractPlugin`,
//! `MessageFormat`) and commons-text behaviour the ascanrules classes rely on.

use crate::scan::active::points::form_encode;
use crate::scan::active::{Cx, Strength};

/// ZAP SQL injection texts (`ascanrules.sqlinjection.*`), shared by 40018 and the
/// RDBMS-specific time based rules.
pub(super) const SQL_DESC: &str = "SQL injection may be possible.";
pub(super) const SQL_SOLN: &str = "Do not trust client side input, even if there is client side validation in place.\n\
    In general, type check all data on the server side.\n\
    If the application uses JDBC, use PreparedStatement or CallableStatement, with parameters passed by '?'\n\
    If the application uses ASP, use ADO Command Objects with strong type checking and parameterized queries.\n\
    If database Stored Procedures can be used, use them.\n\
    Do *not* concatenate strings into queries in the stored procedure, or use 'exec', 'exec immediate', or \
    equivalent functionality!\n\
    Do not create dynamic SQL queries using simple string concatenation.\n\
    Escape all data received from the client.\n\
    Apply an 'allow list' of allowed characters, or a 'deny list' of disallowed characters in user input.\n\
    Apply the principle of least privilege by using the least privileged database user possible.\n\
    In particular, avoid using the 'sa' or 'db-owner' database users. This does not eliminate SQL injection, but \
    minimizes its impact.\n\
    Grant the minimum database access that is necessary for the application.";
pub(super) const SQL_REFS: &[&str] =
    &["https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html"];
/// Tags of the RDBMS-specific time based SQL injection rules.
pub(super) const SQL_TIMING_TAGS: &[&str] =
    &["OWASP_2025_A05", "OWASP_2021_A03", "OWASP_2017_A01", "WSTG-v42-INPV-05", "HIPAA", "PCI_DSS", "TEST_TIMING"];

/// Picks the value for an attack strength from `[LOW, MEDIUM, HIGH, INSANE]`.
pub(super) fn by_strength<T: Copy>(s: Strength, v: [T; 4]) -> T {
    match s {
        Strength::Low => v[0],
        Strength::Medium => v[1],
        Strength::High => v[2],
        Strength::Insane => v[3],
    }
}

/// The parameter name and original (decoded) value of the point under attack.
pub(super) fn point(cx: &Cx) -> (String, String) {
    let p = cx.point();
    (p.name.clone(), p.value.clone())
}

/// `java.util.regex` source to Rust `regex` source: `\Q...\E` quoted sections
/// become escaped literals; everything else is kept.
pub(super) fn java_regex(src: &str) -> String {
    let mut out = String::new();
    let mut rest = src;
    while let Some(i) = rest.find(r"\Q") {
        out.push_str(&rest[..i]);
        let quoted = &rest[i + 2..];
        let end = quoted.find(r"\E").unwrap_or(quoted.len());
        out.push_str(&regex::escape(&quoted[..end]));
        rest = quoted.get(end + 2..).unwrap_or("");
    }
    out.push_str(rest);
    out
}

/// Java `String.valueOf(double)` for the small whole numbers rules use as delays
/// (`5.0`), which ZAP puts in some payloads.
pub(super) fn java_double(x: f64) -> String {
    if x.fract() == 0.0 && x.abs() < 1e7 {
        format!("{x:.1}")
    } else {
        format!("{x}")
    }
}

/// A number as `java.text.MessageFormat` prints it in alert texts (`5,012`).
pub(super) fn grouped(n: i64) -> String {
    let digits = n.unsigned_abs().to_string();
    let mut out = String::new();
    for (i, c) in digits.chars().enumerate() {
        if i > 0 && (digits.len() - i).is_multiple_of(3) {
            out.push(',');
        }
        out.push(c);
    }
    if n < 0 {
        out.insert(0, '-');
    }
    out
}

/// Java `String.length()` (UTF-16 code units).
pub(super) fn java_len(s: &str) -> usize {
    s.encode_utf16().count()
}

/// ZAP `AbstractPlugin.getHTMLEncode` (reconstructed: only `<` and `>` are encoded).
pub(super) fn zap_html_encode(s: &str) -> String {
    s.replace('<', "&#60;").replace('>', "&#62;")
}

/// commons-text `StringEscapeUtils.escapeXml10`.
pub(super) fn escape_xml10(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '"' => out.push_str("&quot;"),
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '\'' => out.push_str("&apos;"),
            '\u{0}'..='\u{8}' | '\u{b}' | '\u{c}' | '\u{e}'..='\u{1f}' | '\u{fffe}' | '\u{ffff}' => {}
            '\u{7f}'..='\u{84}' | '\u{86}'..='\u{9f}' => out.push_str(&format!("&#{};", c as u32)),
            _ => out.push(c),
        }
    }
    out
}

/// ZAP `SqlInjectionScanRule.stripOff`: removes `pattern` from `body` as sent,
/// URL-encoded, HTML-encoded (raw and URL-encoded) and XML-escaped.
pub(super) fn strip_off(body: &str, pattern: &str) -> String {
    if pattern.is_empty() {
        return body.to_string();
    }
    let url = form_encode(pattern);
    let html1 = zap_html_encode(pattern);
    let html2 = zap_html_encode(&url);
    let xml = escape_xml10(pattern);
    // Unlike ZAP, the value as sent goes last: `x%` would leave `25` of an echoed `x%25`.
    let mut result = body.to_string();
    for p in [&url, &html2, &html1, &xml] {
        if !p.is_empty() {
            result = result.replace(p.as_str(), "");
        }
    }
    result.replace(pattern, "")
}

/// ZAP `stripOffOriginalAndAttackParam`.
pub(super) fn strip_off_both(body: &str, original: &str, attack: &str) -> String {
    strip_off(&strip_off(body, attack), original)
}

/// ISO-8859-1 entity names for U+00A0..=U+00FF, in code point order.
const ISO8859_1: [&str; 96] = [
    "nbsp", "iexcl", "cent", "pound", "curren", "yen", "brvbar", "sect", "uml", "copy", "ordf", "laquo", "not", "shy",
    "reg", "macr", "deg", "plusmn", "sup2", "sup3", "acute", "micro", "para", "middot", "cedil", "sup1", "ordm",
    "raquo", "frac14", "frac12", "frac34", "iquest", "Agrave", "Aacute", "Acirc", "Atilde", "Auml", "Aring", "AElig",
    "Ccedil", "Egrave", "Eacute", "Ecirc", "Euml", "Igrave", "Iacute", "Icirc", "Iuml", "ETH", "Ntilde", "Ograve",
    "Oacute", "Ocirc", "Otilde", "Ouml", "times", "Oslash", "Ugrave", "Uacute", "Ucirc", "Uuml", "Yacute", "THORN",
    "szlig", "agrave", "aacute", "acirc", "atilde", "auml", "aring", "aelig", "ccedil", "egrave", "eacute", "ecirc",
    "euml", "igrave", "iacute", "icirc", "iuml", "eth", "ntilde", "ograve", "oacute", "ocirc", "otilde", "ouml",
    "divide", "oslash", "ugrave", "uacute", "ucirc", "uuml", "yacute", "thorn", "yuml",
];

fn named_entity(name: &str) -> Option<char> {
    match name {
        "quot" => Some('"'),
        "amp" => Some('&'),
        "lt" => Some('<'),
        "gt" => Some('>'),
        _ => ISO8859_1.iter().position(|n| *n == name).and_then(|i| char::from_u32(0xa0 + i as u32)),
    }
}

/// commons-text `StringEscapeUtils.unescapeHtml4` for numeric entities and the
/// basic and ISO-8859-1 named ones (the HTML 4.0 extended names are left as-is).
pub(super) fn unescape_html4(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut rest = s;
    while let Some(i) = rest.find('&') {
        out.push_str(&rest[..i]);
        rest = &rest[i..];
        let decoded = rest[1..].find(';').filter(|&end| end > 0 && end <= 10).and_then(|end| {
            let name = &rest[1..1 + end];
            let c = if let Some(num) = name.strip_prefix('#') {
                let v = match num.strip_prefix(['x', 'X']) {
                    Some(hex) => u32::from_str_radix(hex, 16).ok(),
                    None => num.parse::<u32>().ok(),
                };
                v.and_then(char::from_u32)
            } else {
                named_entity(name)
            };
            c.map(|c| (c, end + 2))
        });
        match decoded {
            Some((c, len)) => {
                out.push(c);
                rest = &rest[len..];
            }
            None => {
                out.push('&');
                rest = &rest[1..];
            }
        }
    }
    out.push_str(rest);
    out
}

/// ZAP `CommandInjectionScanRule.insertUninitVar`: puts an uninitialised shell
/// variable (`$a`, `$ab`) before each whitespace and `/` to evade filters.
pub(super) fn insert_uninit_var(cmd: &str) -> String {
    let r = crate::scan::active::rand_u64();
    let len = 1 + (r % 2) as usize; // 1 or 2 letters after '$'
    let mut var = String::from("$");
    for i in 0..len {
        var.push((b'a' + ((r >> (8 * (i + 1))) % 26) as u8) as char);
    }
    let mut out = String::with_capacity(cmd.len() * 2);
    for c in cmd.chars() {
        if c.is_whitespace() {
            out.push_str(&var);
            out.push(' ');
        } else if c == '/' {
            out.push_str(&var);
            out.push('/');
        } else {
            out.push(c);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn java_regex_quotes() {
        assert_eq!(java_regex(r"\Q[Microsoft]\E"), r"\[Microsoft\]");
        assert_eq!(java_regex(r#"near ".+": syntax error"#), r#"near ".+": syntax error"#);
        assert_eq!(java_regex(r"\QhSql.\E"), r"hSql\.");
        assert_eq!(java_regex(r"a\Q.\Eb\Q*\E"), r"a\.b\*");
    }

    #[test]
    fn java_formatting() {
        assert_eq!(java_double(5.0), "5.0");
        assert_eq!(java_double(1.0), "1.0");
        assert_eq!(grouped(5012), "5,012");
        assert_eq!(grouped(100), "100");
        assert_eq!(grouped(1234567), "1,234,567");
        assert_eq!(grouped(0), "0");
        assert_eq!(java_len("a\u{1F600}"), 3);
        assert_eq!(by_strength(Strength::High, [1, 2, 3, 4]), 3);
    }

    #[test]
    fn encoders() {
        assert_eq!(zap_html_encode("<a>"), "&#60;a&#62;");
        assert_eq!(escape_xml10("'a\"&<>\u{1}\u{80}"), "&apos;a&quot;&amp;&lt;&gt;&#128;");
        assert_eq!(
            unescape_html4("root&#58;x&#x3a;0:0 &lt;b&gt; &amp;amp; &eacute; &bogus; & &"),
            "root:x:0:0 <b> &amp; é &bogus; & &"
        );
    }

    #[test]
    fn strip_off_variants() {
        // As sent and URL-encoded (form encoding, like Java's URLEncoder).
        assert_eq!(
            strip_off("You searched for 1 AND 1=1 -- , 1+AND+1%3D1+--+.", "1 AND 1=1 -- "),
            "You searched for , ."
        );
        assert_eq!(strip_off("x <x> y", "<x>"), "x  y");
        assert_eq!(strip_off("x &#60;x&#62; y", "<x>"), "x  y");
        assert_eq!(strip_off("a 'q' &apos;q&apos;", "'q'"), "a  ");
        assert_eq!(strip_off("keep", ""), "keep");
        assert_eq!(strip_off("/a/x%25", "x%"), "/a/");
        // Original and attack both go, so a value always on the page doesn't skew results.
        assert_eq!(strip_off_both("about cats. You sent cats AND 1=1", "cats", "cats AND 1=1"), "about . You sent ");
    }

    #[test]
    fn uninit_var() {
        for _ in 0..20 {
            let s = insert_uninit_var("cat /etc/passwd");
            let var = &s[3..s.find(' ').unwrap()];
            assert!(var.starts_with('$') && (2..=3).contains(&var.len()), "{s}");
            assert!(var[1..].chars().all(|c| c.is_ascii_lowercase()), "{s}");
            assert_eq!(s, format!("cat{var} {var}/etc{var}/passwd"));
        }
    }
}
