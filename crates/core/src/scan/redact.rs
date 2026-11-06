//! Masks session secrets in a report before it leaves the project: cookie values,
//! `Authorization` credentials, API-key headers, token and password parameters in URLs,
//! forms, multipart and JSON bodies, hidden form fields, and JWTs. A report is meant to be
//! handed to someone, and the traffic it quotes carries the tester's live sessions.
//!
//! Masking is two passes. [`Redactor::know`] takes the secrets the project already holds
//! (its auth profiles' passwords, tokens, cookies and keys), and [`Redactor::exchange`] and
//! [`Redactor::text`] mask what is a secret by its place (a header, a parameter name, a
//! JWT's shape) and remember each masked value; [`Redactor::scrub`] then replaces every
//! known value wherever else it appears, such as a session id quoted in a finding's evidence
//! or echoed in a response body.

use std::collections::BTreeSet;
use std::sync::LazyLock;

use regex::{Captures, Regex};

use crate::scan::report::{HttpRequest, HttpResponse};

/// What a masked value reads as.
pub const MASK: &str = "[redacted]";

/// Values shorter than this are masked where they stand but not searched for elsewhere: a
/// cookie such as `lang=en` would otherwise mask every "en" in the report.
const MIN_SCRUB: usize = 6;

/// Headers whose whole value is a credential.
const SECRET_HEADERS: &[&str] = &[
    "x-api-key",
    "api-key",
    "apikey",
    "x-auth-token",
    "x-access-token",
    "x-session-token",
    "x-csrf-token",
    "x-xsrf-token",
    "x-amz-security-token",
    "x-goog-api-key",
    "private-token",
];

/// Parameter or JSON key names that hold a secret: compared lowercased, as a part of the name.
const SECRET_NAME_PARTS: &[&str] = &[
    "password",
    "passwd",
    "passphrase",
    "secret",
    "token",
    "apikey",
    "api_key",
    "api-key",
    "accesskey",
    "access_key",
    "privatekey",
    "private_key",
    "session",
    "sessid",
    "jwt",
    "csrf",
    "xsrf",
    "signature",
];

/// Parameter or JSON key names that hold a secret only as the whole name.
const SECRET_NAMES: &[&str] =
    &["pwd", "pass", "sid", "auth", "authorization", "otp", "sig", "key", "credential", "credentials"];

/// The header names [`HEADER_LINE`] and [`HEADER_INLINE`] look for, longest first so
/// `set-cookie` is taken whole rather than as `cookie`.
fn header_names() -> String {
    let mut names: Vec<&str> = ["proxy-authorization", "authorization", "set-cookie", "cookie"].into();
    names.extend(SECRET_HEADERS);
    names.sort_by_key(|n| std::cmp::Reverse(n.len()));
    names.join("|")
}

/// A header line inside free text, such as a finding's evidence.
static HEADER_LINE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(&format!(r"(?im)^([ \t]*)({})([ \t]*:[ \t]*)([^\r\n]+)", header_names())).unwrap());

/// A header quoted inside a line (`curl -H "Authorization: Bearer ..."`, an escaped
/// `\r\n`-joined header block): its value ends at a quote, a backslash or a tag.
static HEADER_INLINE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(&format!(r#"(?i)(\b)({})([ \t]*:[ \t]*)([^\r\n"'\\<>]+)"#, header_names())).unwrap());

/// A JSON string member; a body cut short may end before the closing quote.
static JSON_MEMBER: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#""([A-Za-z0-9_.\-]{1,64})"(\s*:\s*)"((?:[^"\\]|\\.)*)("|$)"#).unwrap());

/// A JSON member whose value is a number, such as a one-time code.
static JSON_NUMBER: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#""([A-Za-z0-9_.\-]{1,64})"(\s*:\s*)(-?[0-9][0-9.eE+\-]*)"#).unwrap());

/// A `name=value` pair in a query string, form body or link; the name may be percent-encoded.
/// A value ends at a backslash, which in quoted text starts an escape such as `\r\n`.
static FORM_PAIR: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"(^|[?&;\s"'])([A-Za-z0-9_.%\-\[\]]{1,96})=([^&#\s;"'<>\\]+)"#).unwrap());

/// A multipart field: its headers, a blank line, then the value's first line.
static MULTIPART_FIELD: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r#"(?i)(content-disposition:[^\r\n]*?\bname="([^"\r\n]{1,64})"[^\r\n]*\r?\n(?:[^\r\n]+\r?\n)*\r?\n)([^\r\n]*)"#,
    )
    .unwrap()
});

/// An HTML `<input>` or `<meta>` tag, whose value may be a hidden CSRF token or a password.
static HTML_TAG: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?i)<(?:input|meta)\b[^>]*>").unwrap());
static ATTR_NAME: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"(?i)[\s/](?:name|id)\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s"'>]+))"#).unwrap());
static ATTR_VALUE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"(?i)[\s/](?:value|content)\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s"'>/]+))"#).unwrap());
static PASSWORD_TYPE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r#"(?i)[\s/]type\s*=\s*["']?password\b"#).unwrap());

/// A JSON Web Token anywhere.
static JWT: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"eyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]*").unwrap());

#[derive(Debug, Default)]
pub struct Redactor {
    /// Values masked so far, to find again elsewhere.
    secrets: BTreeSet<String>,
    /// `secrets`, longest first (so a value that contains another is masked whole); rebuilt
    /// when a secret is added.
    order: Vec<String>,
    /// How many places a value was masked in.
    pub masked: usize,
}

fn secret_name(name: &str) -> bool {
    let n = percent_encoding::percent_decode_str(name).decode_utf8_lossy().to_ascii_lowercase();
    let n = n.trim_end_matches("[]");
    SECRET_NAMES.contains(&n) || SECRET_NAME_PARTS.iter().any(|p| n.contains(p))
}

/// Whether a value masked because of its name is worth finding elsewhere. A plain word or
/// a short number (`"token_type":"bearer"`, `sid=deleted`, `"otp":123456`) is masked where
/// it stands, but masking it everywhere would hide ordinary text.
fn distinctive(v: &str) -> bool {
    let word = v.len() < 12 && v.chars().all(|c| c.is_ascii_alphabetic());
    let number = v.len() < 10 && v.chars().all(|c| c.is_ascii_digit());
    v.len() >= MIN_SCRUB && !word && !number
}

/// The forms a value may take elsewhere in a report: as recorded, unquoted, with JSON
/// escapes undone, percent-decoded, and percent-encoded.
fn forms(v: &str) -> Vec<String> {
    let bare = v.trim_matches(|c| c == '"' || c == '\'');
    let unescaped = serde_json::from_str::<String>(&format!("\"{bare}\"")).unwrap_or_else(|_| bare.to_string());
    let decoded = percent_encoding::percent_decode_str(bare).decode_utf8_lossy().into_owned();
    let encoded = url::form_urlencoded::byte_serialize(bare.as_bytes()).collect::<String>();
    let mut out = vec![v.to_string(), bare.to_string(), unescaped, decoded, encoded];
    out.sort();
    out.dedup();
    out
}

impl Redactor {
    /// Remembers values the project already knows are secrets, such as its auth profiles'
    /// passwords and session tokens, so they are masked wherever a report quotes them.
    pub fn know<I: IntoIterator<Item = String>>(&mut self, values: I) {
        for v in values {
            self.remember(&v, true);
        }
    }

    fn remember(&mut self, value: &str, known: bool) {
        let v = value.trim();
        if v.is_empty() || v == MASK {
            return;
        }
        for f in forms(v) {
            let keep = if known { f.len() >= MIN_SCRUB } else { distinctive(&f) };
            if keep && f != MASK && self.secrets.insert(f) {
                self.order.clear();
            }
        }
    }

    /// Masks one value and remembers it.
    fn secret(&mut self, value: &str) -> String {
        let v = value.trim();
        if v.is_empty() || v == MASK {
            return value.to_string();
        }
        self.remember(v, false);
        self.masked += 1;
        MASK.to_string()
    }

    /// `name=value` with the value masked; anything without `=` is kept.
    fn pair(&mut self, item: &str) -> String {
        match item.split_once('=') {
            Some((k, v)) => format!("{k}={}", self.secret(v)),
            None => item.to_string(),
        }
    }

    /// A header's value with its secret parts masked, or None when it isn't a credential
    /// header (its value may still hold a secret: see [`Redactor::headers`]).
    fn header_value(&mut self, name: &str, value: &str) -> Option<String> {
        let n = name.trim().to_ascii_lowercase();
        Some(match n.as_str() {
            // Cookie names say which session it was; only the values are secret.
            "cookie" => value.split(';').map(|c| self.pair(c.trim())).collect::<Vec<_>>().join("; "),
            "set-cookie" => match value.split_once(';') {
                Some((first, attrs)) => format!("{};{attrs}", self.pair(first.trim())),
                None => self.pair(value.trim()),
            },
            // The scheme (Basic, Bearer, ...) is useful to a reader; the credential is not.
            "authorization" | "proxy-authorization" => match value.trim().split_once(' ') {
                Some((scheme, cred)) => format!("{scheme} {}", self.secret(cred)),
                None => self.secret(value),
            },
            n if SECRET_HEADERS.contains(&n) => self.secret(value),
            _ => return None,
        })
    }

    /// Masks credential headers, and secrets inside any other header's value: a token in a
    /// `Location` or `Referer` URL, a JWT in a custom header.
    pub fn headers(&mut self, headers: &mut [(String, String)]) {
        for (name, value) in headers.iter_mut() {
            match self.header_value(name, value) {
                Some(v) => *value = v,
                None => self.text(value),
            }
        }
    }

    /// Masks secrets in free text by their place: header lines, secret-named JSON members,
    /// `name=value` pairs, multipart fields and form inputs, and JWTs.
    pub fn text(&mut self, s: &mut String) {
        let header = |red: &mut Self, c: &Captures| {
            let v = red.header_value(&c[2], &c[4]).unwrap_or_else(|| c[4].to_string());
            format!("{}{}{}{v}", &c[1], &c[2], &c[3])
        };
        let mut out = HEADER_LINE.replace_all(s, |c: &Captures| header(self, c)).into_owned();
        out = HEADER_INLINE.replace_all(&out, |c: &Captures| header(self, c)).into_owned();
        out = MULTIPART_FIELD
            .replace_all(&out, |c: &Captures| {
                if secret_name(&c[2]) {
                    format!("{}{}", &c[1], self.secret(&c[3]))
                } else {
                    c[0].to_string()
                }
            })
            .into_owned();
        out = JSON_MEMBER
            .replace_all(&out, |c: &Captures| {
                if secret_name(&c[1]) {
                    format!("\"{}\"{}\"{}{}", &c[1], &c[2], self.secret(&c[3]), &c[4])
                } else {
                    c[0].to_string()
                }
            })
            .into_owned();
        out = JSON_NUMBER
            .replace_all(&out, |c: &Captures| {
                if secret_name(&c[1]) {
                    format!("\"{}\"{}\"{}\"", &c[1], &c[2], self.secret(&c[3]))
                } else {
                    c[0].to_string()
                }
            })
            .into_owned();
        out = FORM_PAIR
            .replace_all(&out, |c: &Captures| {
                if secret_name(&c[2]) {
                    format!("{}{}={}", &c[1], &c[2], self.secret(&c[3]))
                } else {
                    c[0].to_string()
                }
            })
            .into_owned();
        out = HTML_TAG.replace_all(&out, |c: &Captures| self.tag(&c[0])).into_owned();
        out = JWT.replace_all(&out, |c: &Captures| self.secret(&c[0])).into_owned();
        *s = out;
    }

    /// An `<input>` or `<meta>` tag with its value masked when its name says it is secret or
    /// it is a password field.
    fn tag(&mut self, tag: &str) -> String {
        fn attr<'h>(c: &Captures<'h>) -> Option<regex::Match<'h>> {
            c.get(1).or(c.get(2)).or(c.get(3))
        }
        let named = ATTR_NAME.captures(tag).and_then(|c| attr(&c).map(|m| secret_name(m.as_str()))).unwrap_or(false);
        if !named && !PASSWORD_TYPE.is_match(tag) {
            return tag.to_string();
        }
        let Some(value) = ATTR_VALUE.captures(tag).and_then(|c| attr(&c)) else {
            return tag.to_string();
        };
        if value.as_str().is_empty() {
            return tag.to_string();
        }
        format!("{}{}{}", &tag[..value.start()], self.secret(value.as_str()), &tag[value.end()..])
    }

    /// Masks a recorded request and response: headers, URL and bodies.
    pub fn exchange(&mut self, req: &mut HttpRequest, resp: Option<&mut HttpResponse>) {
        self.headers(&mut req.headers);
        self.text(&mut req.url);
        if !req.body.binary {
            self.text(&mut req.body.text);
        }
        if let Some(resp) = resp {
            self.headers(&mut resp.headers);
            if !resp.body.binary {
                self.text(&mut resp.body.text);
            }
        }
    }

    /// Replaces every value known so far wherever it appears in `s`.
    pub fn scrub(&mut self, s: &mut String) {
        if self.secrets.is_empty() {
            return;
        }
        if self.order.is_empty() {
            self.order = self.secrets.iter().cloned().collect();
            self.order.sort_by_key(|v| std::cmp::Reverse(v.len()));
        }
        for v in &self.order {
            let n = s.matches(v.as_str()).count();
            if n > 0 {
                *s = s.replace(v.as_str(), MASK);
                self.masked += n;
            }
        }
    }

    /// Scrubs a request and response the same way as [`Redactor::scrub`].
    pub fn scrub_exchange(&mut self, req: &mut HttpRequest, resp: Option<&mut HttpResponse>) {
        self.scrub(&mut req.url);
        for (_, v) in req.headers.iter_mut() {
            self.scrub(v);
        }
        if !req.body.binary {
            self.scrub(&mut req.body.text);
        }
        if let Some(resp) = resp {
            for (_, v) in resp.headers.iter_mut() {
                self.scrub(v);
            }
            if !resp.body.binary {
                self.scrub(&mut resp.body.text);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn masked(s: &str) -> (String, usize) {
        let mut r = Redactor::default();
        let mut s = s.to_string();
        r.text(&mut s);
        (s, r.masked)
    }

    fn redacted(s: &str) -> String {
        masked(s).0
    }

    #[test]
    fn headers_keep_names_and_schemes() {
        let mut r = Redactor::default();
        let mut h = vec![
            ("Cookie".to_string(), "session=abc123456; lang=en".to_string()),
            ("Set-Cookie".to_string(), "sid=zzz999888; Path=/; HttpOnly".to_string()),
            ("Authorization".to_string(), "Bearer tok.en.value".to_string()),
            ("X-Api-Key".to_string(), "k-1234567".to_string()),
            ("Accept".to_string(), "text/html".to_string()),
            ("Location".to_string(), "https://app.test/cb?access_token=Zq81kd0&state=x".to_string()),
        ];
        r.headers(&mut h);
        assert_eq!(h[0].1, "session=[redacted]; lang=[redacted]");
        assert_eq!(h[1].1, "sid=[redacted]; Path=/; HttpOnly");
        assert_eq!(h[2].1, "Bearer [redacted]");
        assert_eq!(h[3].1, "[redacted]");
        assert_eq!(h[4].1, "text/html");
        assert_eq!(h[5].1, "https://app.test/cb?access_token=[redacted]&state=x");
        assert_eq!(r.masked, 6);
        // "en" is too short to look for elsewhere; the session id is not.
        let mut ev = "Set-Cookie: session=abc123456 sent in en".to_string();
        r.scrub(&mut ev);
        assert_eq!(ev, "Set-Cookie: session=[redacted] sent in en");
    }

    #[test]
    fn text_masks_by_place() {
        assert_eq!(redacted("Authorization: Basic dXNlcjpwYXNz"), "Authorization: Basic [redacted]");
        assert_eq!(
            redacted(r#"{"user":"bob","password":"hunter22","nested":{"access_token":"a\"b"}}"#),
            r#"{"user":"bob","password":"[redacted]","nested":{"access_token":"[redacted]"}}"#
        );
        assert_eq!(
            redacted("http://app.test/cb?code=1&api_key=XYZ987&next=/home"),
            "http://app.test/cb?code=1&api_key=[redacted]&next=/home"
        );
        assert_eq!(redacted("user=bob&pass=hunter2&remember=1"), "user=bob&pass=[redacted]&remember=1");
        assert_eq!(redacted(r#"<a href="/x?csrf_token=abcdef">"#), r#"<a href="/x?csrf_token=[redacted]">"#);
        let jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.c2lnbmF0dXJl";
        assert_eq!(redacted(&format!("token is {jwt} here")), "token is [redacted] here");
        // A body cut off mid-value.
        assert_eq!(redacted(r#"{"refresh_token":"abcdefgh"#), r#"{"refresh_token":"[redacted]"#);
        // Nothing secret: unchanged, nothing counted.
        assert_eq!(masked("q=shoes&page=2 author=me"), ("q=shoes&page=2 author=me".to_string(), 0));
    }

    #[test]
    fn bodies_of_every_kind() {
        // A number, and a percent-encoded name.
        assert_eq!(redacted(r#"{"otp": 123456, "n": 2}"#), r#"{"otp": "[redacted]", "n": 2}"#);
        assert_eq!(redacted("user=bob&pass%77ord=hunter2"), "user=bob&pass%77ord=[redacted]");
        // A multipart field.
        let body = "--b\r\nContent-Disposition: form-data; name=\"password\"\r\n\r\nhunter22\r\n--b\r\n\
                    Content-Disposition: form-data; name=\"user\"\r\n\r\nbob\r\n--b--";
        let want = body.replace("hunter22", "[redacted]");
        assert_eq!(redacted(body), want);
        // Hidden inputs and meta tags, by name or as a password field; others kept.
        assert_eq!(
            redacted(r#"<input type="hidden" name="csrf_token" value="Abc123xyz"><input name="q" value="shoes">"#),
            r#"<input type="hidden" name="csrf_token" value="[redacted]"><input name="q" value="shoes">"#
        );
        assert_eq!(
            redacted(r#"<meta content='k9Zp0q1w' name="csrf-token"/><input type=password name=pw value=hunter2>"#),
            r#"<meta content='[redacted]' name="csrf-token"/><input type=password name=pw value=[redacted]>"#
        );
        // A header quoted mid-line, without taking the rest of the line.
        assert_eq!(
            redacted(r#"curl -H "Authorization: Bearer abc.def.ghi" https://app.test/"#),
            r#"curl -H "Authorization: Bearer [redacted]" https://app.test/"#
        );
        assert_eq!(
            redacted(r"GET / HTTP/1.1\r\nCookie: sid=Zx81kq0\r\nHost: a"),
            r"GET / HTTP/1.1\r\nCookie: sid=[redacted]\r\nHost: a"
        );
    }

    #[test]
    fn values_are_found_again_in_any_form_but_plain_words_are_not() {
        let mut r = Redactor::default();
        let mut s = r#"Cookie: sid="Qk2+z/9w"; theme=dark"#.to_string();
        r.text(&mut s);
        let mut echo = "id Qk2+z/9w, url ?s=Qk2%2Bz%2F9w, dark".to_string();
        r.scrub(&mut echo);
        assert_eq!(echo, "id [redacted], url ?s=[redacted], dark");
        // A word or short number masked by name stays readable elsewhere.
        let mut s = r#"{"token_type":"bearer","otp":123456}"#.to_string();
        r.text(&mut s);
        let mut text = "Authorization uses bearer tokens; order 123456".to_string();
        r.scrub(&mut text);
        assert_eq!(text, "Authorization uses bearer tokens; order 123456");
        // Known secrets are found again even when they are plain words.
        r.know(["letmein".to_string(), "abc".to_string()]);
        let mut text = "password letmein, abc".to_string();
        r.scrub(&mut text);
        assert_eq!(text, "password [redacted], abc");
    }

    #[test]
    fn masking_twice_counts_once() {
        let mut r = Redactor::default();
        let mut s = "Cookie: sid=abcdef123".to_string();
        r.text(&mut s);
        r.text(&mut s);
        r.scrub(&mut s);
        assert_eq!((s.as_str(), r.masked), ("Cookie: sid=[redacted]", 1));
    }
}
