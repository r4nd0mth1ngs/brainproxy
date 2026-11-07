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

use aho_corasick::{AhoCorasick, MatchKind};
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
const SECRET_NAMES: &[&str] = &[
    "pwd",
    "pass",
    "sid",
    "auth",
    "authorization",
    "otp",
    "otp_code",
    "sig",
    "key",
    "credential",
    "credentials",
    "x-amz-credential",
];

/// A name that says its value is a one-time code only when the value is long enough to be
/// one: an OAuth `code=`, not `"code": 404`.
const CODE_NAMES: &[&str] = &["code", "auth_code", "authorization_code"];
const CODE_MIN: usize = 10;

/// The header names [`HEADER_LINE`] and [`HEADER_INLINE`] look for, longest first so
/// `set-cookie` is taken whole rather than as `cookie`.
fn header_names() -> String {
    let mut names: Vec<&str> = ["proxy-authorization", "authorization", "set-cookie", "cookie"].into();
    names.extend(SECRET_HEADERS);
    names.sort_by_key(|n| std::cmp::Reverse(n.len()));
    names.join("|")
}

/// A `name: value` line inside free text, such as a header in a finding's evidence or a
/// `password: x` line in a note; masked when the name is a credential header or secret.
static HEADER_LINE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?im)^([ \t]*)([A-Za-z][A-Za-z0-9_\-]{0,63})([ \t]*:[ \t]*)([^\r\n]+)").unwrap());

/// A header quoted inside a line (`curl -H "Authorization: Bearer ..."`, an escaped
/// `\r\n`-joined header block): its value ends at a quote, a backslash or a tag. The known
/// credential headers, or any hyphenated name that says it is secret (`X-Refresh-Token`).
static HEADER_INLINE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(&format!(
        r#"(?i)(\b)({}|[A-Za-z0-9]+(?:-[A-Za-z0-9]+)+)([ \t]*:[ \t]*)([^\r\n"'\\<>]+)"#,
        header_names()
    ))
    .unwrap()
});

/// A JSON string member; a body cut short may end before the closing quote.
static JSON_MEMBER: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#""([A-Za-z0-9_.\-]{1,64})"(\s*:\s*)"((?:[^"\\]|\\.)*)("|$)"#).unwrap());

/// A JSON member whose value is an array, such as a list of tokens.
static JSON_ARRAY: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#""([A-Za-z0-9_.\-]{1,64})"(\s*:\s*)\[([^\]]{0,8192})\]"#).unwrap());
static JSON_STRING: LazyLock<Regex> = LazyLock::new(|| Regex::new(r#""((?:[^"\\]|\\.)*)""#).unwrap());

/// A JSON member inside a JSON-encoded string (`"payload":"{\"secret\":\"x\"}"`).
static JSON_ESCAPED_MEMBER: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"\\"([A-Za-z0-9_.\-]{1,64})\\"(\s*:\s*)\\"((?:[^"\\]|\\[^"])*)\\""#).unwrap());

/// A key and quoted value in script or config text: `apiKey: "x"`, `'authToken': 'x'`,
/// `token = "x"`. One pattern per quote, since a value may hold the other one.
static KEY_DOUBLE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(^|[\s{,(])(['"]?)([A-Za-z_$][A-Za-z0-9_$\-]{0,63})(['"]?\s*[:=]\s*")((?:[^"\\\r\n]|\\.)*)""#)
        .unwrap()
});
static KEY_SINGLE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(^|[\s{,(])(['"]?)([A-Za-z_$][A-Za-z0-9_$\-]{0,63})(['"]?\s*[:=]\s*')((?:[^'\\\r\n]|\\.)*)'"#)
        .unwrap()
});

/// An XML element with text only: `<password>x</password>`, `<wsse:BinarySecurityToken>`.
static XML_ELEMENT: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"<((?:[A-Za-z_][\w.\-]*:)?([A-Za-z_][\w.\-]*))(\s[^<>]*)?>([^<]{1,8192})</").unwrap());

/// A quoted attribute anywhere (`data-token="x"`); masked when its name says it is secret.
static QUOTED_ATTR: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"(\s)([A-Za-z_][A-Za-z0-9_:.\-]{0,63})(\s*=\s*")([^"]*)""#).unwrap());

/// Credentials in a URL: `https://user:password@host`.
static USERINFO: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)\b([a-z][a-z0-9+.\-]{1,15}://[^/\s:@"'<>]{1,128}:)([^/\s@"'<>]{1,256})@"#).unwrap()
});

/// A secret named in a sentence: `password: x`, `token=x` (one word).
static PROSE_SECRET: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)\b(password|passwd|passphrase|pwd|secret|api[_-]?key|access[_-]?token)(\s*[:=]\s*)([^\s"'<>,;&#?\\]{4,})"#)
        .unwrap()
});

/// A Digest credential's response or client nonce, quoted where the header isn't whole (an
/// escaped curl line).
static DIGEST_PARAM: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"(?i)(\b(?:response|cnonce)\s*=\s*(?:\\?")?)([^"\\\s,]{6,})"#).unwrap());

/// A percent escape, to write in lowercase hex.
static PERCENT_HEX: LazyLock<Regex> = LazyLock::new(|| Regex::new("%[0-9A-F]{2}").unwrap());

/// What the Basic-auth rule wrote before it stopped quoting the password.
static QUOTED_PASSWORD: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(\band password \[)([^\]\r\n]*)(\])").unwrap());

/// A JSON member whose value is a number, such as a one-time code.
static JSON_NUMBER: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#""([A-Za-z0-9_.\-]{1,64})"(\s*:\s*)(-?[0-9][0-9.eE+\-]*)"#).unwrap());

/// A `name=value` pair in a query string, fragment, form body or link; the name may be
/// percent-encoded. A value ends at a backslash, which in quoted text starts an escape such
/// as `\r\n`, and at `?`, so a pair in a path (`;v=1?token=x`) or a nested URL
/// (`next=/a?session=x`) leaves the query after it to be read too.
static FORM_PAIR: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"(^|[?&;#\s"'])([A-Za-z0-9_.%\-\[\]]{1,96})=([^&#?\s;"'<>\\]+)"#).unwrap());

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

/// A JSON Web Token anywhere, also one cut short before its signature.
static JWT: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"eyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}(?:\.[A-Za-z0-9_-]*)?").unwrap());

#[derive(Debug, Default)]
pub struct Redactor {
    /// Values masked so far, to find again elsewhere.
    secrets: BTreeSet<String>,
    /// A matcher for `secrets` (leftmost-longest, so a value that contains another is masked
    /// whole; ASCII case ignored); rebuilt when a secret is added.
    matcher: Option<AhoCorasick>,
    /// How many places a value was masked in.
    pub masked: usize,
}

fn secret_name(name: &str) -> bool {
    let n = percent_encoding::percent_decode_str(name).decode_utf8_lossy().to_ascii_lowercase();
    let n = n.trim_end_matches("[]");
    // Rails' `csrf-param` names the token's field (authenticity_token), and isn't one.
    if n.ends_with("-param") {
        return false;
    }
    SECRET_NAMES.contains(&n) || SECRET_NAME_PARTS.iter().any(|p| n.contains(p))
}

/// Whether `name = value` holds a secret: a secret name, or a code name with a long value.
fn secret_pair(name: &str, value: &str) -> bool {
    let code = value.len() >= CODE_MIN
        && value.chars().any(|c| c.is_ascii_digit())
        && value.chars().any(|c| c.is_ascii_alphabetic());
    secret_name(name) || (code && CODE_NAMES.contains(&name.to_ascii_lowercase().as_str()))
}

/// Whether a header's whole value is a credential (beyond Cookie, Set-Cookie and
/// Authorization, whose names or schemes are kept): a known API-key header, or a name that
/// says it is secret.
pub fn secret_header(name: &str) -> bool {
    let n = name.trim().to_ascii_lowercase();
    SECRET_HEADERS.contains(&n.as_str()) || secret_name(&n)
}

/// Whether a value masked because of its name is worth finding elsewhere. A plain word or
/// a short number (`"token_type":"bearer"`, `sid=deleted`, `"otp":123456`) is masked where
/// it stands, but masking it everywhere would hide ordinary text.
pub fn distinctive(v: &str) -> bool {
    let word = v.len() < 12 && v.chars().all(|c| c.is_ascii_alphabetic());
    let number = v.len() < 10 && v.chars().all(|c| c.is_ascii_digit());
    v.len() >= MIN_SCRUB && !word && !number
}

/// The forms a value may take elsewhere in a report: as recorded, unquoted, with JSON
/// escapes undone, percent-decoded, percent-encoded (either case of hex), JSON-escaped
/// (`\/`, as PHP writes it), HTML-escaped, and in base64. Case is ignored when matching.
fn forms(v: &str) -> Vec<String> {
    use base64::Engine;
    let bare = v.trim_matches(|c| c == '"' || c == '\'');
    let unescaped = serde_json::from_str::<String>(&format!("\"{bare}\"")).unwrap_or_else(|_| bare.to_string());
    let decoded = percent_encoding::percent_decode_str(bare).decode_utf8_lossy().into_owned();
    let mut out = vec![v.to_string(), bare.to_string(), unescaped.clone(), decoded.clone()];
    for plain in [&unescaped, &decoded] {
        let encoded = url::form_urlencoded::byte_serialize(plain.as_bytes()).collect::<String>();
        // %2f as well as %2F: some frameworks write lowercase hex.
        let lower = PERCENT_HEX.replace_all(&encoded, |c: &Captures| c[0].to_ascii_lowercase()).into_owned();
        let json = plain.replace('\\', "\\\\").replace('"', "\\\"").replace('/', "\\/");
        let html = plain
            .replace('&', "&amp;")
            .replace('"', "&quot;")
            .replace('\'', "&#39;")
            .replace('<', "&lt;")
            .replace('>', "&gt;")
            .replace('/', "&#x2F;");
        // Every symbol as a hex entity, as some templates escape them.
        let entities: String = plain
            .chars()
            .map(|c| if c.is_ascii_alphanumeric() { c.to_string() } else { format!("&#x{:X};", c as u32) })
            .collect();
        out.extend([encoded, lower, json, html, entities]);
        if plain.len() >= MIN_SCRUB {
            out.push(base64::engine::general_purpose::STANDARD.encode(plain));
            out.push(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(plain));
        }
    }
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
            // A value the mask itself holds ("redacted") would mask the masks.
            if keep && !MASK.to_ascii_lowercase().contains(&f.to_ascii_lowercase()) && self.secrets.insert(f) {
                self.matcher = None;
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

    /// A cookie's `name=value` with the value masked; anything without `=` is kept. The
    /// parts of a signed value (`s:ID.signature`) are learned too, since a page may quote the
    /// session id alone.
    fn pair(&mut self, item: &str) -> String {
        match item.split_once('=') {
            Some((k, v)) => {
                let decoded = percent_encoding::percent_decode_str(v).decode_utf8_lossy().into_owned();
                for value in [v, decoded.as_str()] {
                    for part in value.split(['.', ':', '|']).filter(|p| p.len() >= 12 && distinctive(p)) {
                        self.remember(part, false);
                    }
                }
                format!("{k}={}", self.secret(v))
            }
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
                Some((scheme, cred)) => {
                    self.credential_parts(scheme, cred.trim());
                    format!("{scheme} {}", self.secret(cred))
                }
                None => self.secret(value),
            },
            n if secret_header(n) => self.secret(value),
            _ => return None,
        })
    }

    /// Learns what an Authorization value quotes elsewhere: a Basic credential's decoded
    /// `user:password` and password, and a Digest response's `response`, `nonce` and `cnonce`.
    fn credential_parts(&mut self, scheme: &str, cred: &str) {
        use base64::Engine;
        if scheme.eq_ignore_ascii_case("basic") {
            let decoded = base64::engine::general_purpose::STANDARD
                .decode(cred.trim_end_matches('='))
                .or_else(|_| base64::engine::general_purpose::STANDARD.decode(cred))
                .ok()
                .map(|b| String::from_utf8_lossy(&b).into_owned());
            if let Some(d) = decoded {
                self.remember(&d, true);
                if let Some((_, pass)) = d.split_once(':') {
                    self.remember(pass, true);
                }
            }
        } else if scheme.eq_ignore_ascii_case("digest") {
            for part in cred.split(',') {
                if let Some((k, v)) = part.split_once('=') {
                    if matches!(k.trim().to_ascii_lowercase().as_str(), "response" | "nonce" | "cnonce") {
                        self.remember(v.trim().trim_matches('"'), true);
                    }
                }
            }
        }
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
        out = USERINFO.replace_all(&out, |c: &Captures| format!("{}{}@", &c[1], self.secret(&c[2]))).into_owned();
        if out.to_ascii_lowercase().contains("digest") {
            out =
                DIGEST_PARAM.replace_all(&out, |c: &Captures| format!("{}{}", &c[1], self.secret(&c[2]))).into_owned();
        }
        out = PROSE_SECRET
            .replace_all(&out, |c: &Captures| format!("{}{}{}", &c[1], &c[2], self.secret(&c[3])))
            .into_owned();
        out = QUOTED_PASSWORD
            .replace_all(&out, |c: &Captures| match &c[2] {
                "null" | "not shown" => c[0].to_string(),
                p => format!("{}{}{}", &c[1], self.secret(p), &c[3]),
            })
            .into_owned();
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
                if secret_pair(&c[1], &c[3]) {
                    format!("\"{}\"{}\"{}{}", &c[1], &c[2], self.secret(&c[3]), &c[4])
                } else {
                    c[0].to_string()
                }
            })
            .into_owned();
        out = JSON_ESCAPED_MEMBER
            .replace_all(&out, |c: &Captures| {
                if secret_pair(&c[1], &c[3]) {
                    format!("\\\"{}\\\"{}\\\"{}\\\"", &c[1], &c[2], self.secret(&c[3]))
                } else {
                    c[0].to_string()
                }
            })
            .into_owned();
        out = JSON_ARRAY
            .replace_all(&out, |c: &Captures| {
                if !secret_name(&c[1]) {
                    return c[0].to_string();
                }
                let items = JSON_STRING.replace_all(&c[3], |v: &Captures| format!("\"{}\"", self.secret(&v[1])));
                format!("\"{}\"{}[{items}]", &c[1], &c[2])
            })
            .into_owned();
        for re in [&*KEY_DOUBLE, &*KEY_SINGLE] {
            out = re
                .replace_all(&out, |c: &Captures| {
                    if secret_pair(&c[3], &c[5]) {
                        let quote = &c[4][c[4].len() - 1..];
                        format!("{}{}{}{}{}{quote}", &c[1], &c[2], &c[3], &c[4], self.secret(&c[5]))
                    } else {
                        c[0].to_string()
                    }
                })
                .into_owned();
        }
        out = XML_ELEMENT
            .replace_all(&out, |c: &Captures| {
                if secret_name(&c[2]) {
                    format!("<{}{}>{}</", &c[1], c.get(3).map_or("", |m| m.as_str()), self.secret(&c[4]))
                } else {
                    c[0].to_string()
                }
            })
            .into_owned();
        out = QUOTED_ATTR
            .replace_all(&out, |c: &Captures| {
                // name, id, value and content are read with the tag they are in.
                let plain = matches!(c[2].to_ascii_lowercase().as_str(), "name" | "id" | "value" | "content" | "type");
                if !plain && secret_name(&c[2]) {
                    format!("{}{}{}{}\"", &c[1], &c[2], &c[3], self.secret(&c[4]))
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
                if secret_pair(&c[2], &c[3]) {
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
        // Any name or id: `<input id="f1" name="_csrf">` is named by its second attribute.
        let named = ATTR_NAME.captures_iter(tag).any(|c| attr(&c).is_some_and(|m| secret_name(m.as_str())));
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

    /// Replaces every value known so far wherever it appears in `s`, in one pass.
    pub fn scrub(&mut self, s: &mut String) {
        if self.secrets.is_empty() {
            return;
        }
        if self.matcher.is_none() {
            self.matcher = AhoCorasick::builder()
                .match_kind(MatchKind::LeftmostLongest)
                .ascii_case_insensitive(true)
                .build(&self.secrets)
                .ok();
        }
        let Some(m) = &self.matcher else { return };
        let mut n = 0;
        let mut out = String::with_capacity(s.len());
        m.replace_all_with(s, &mut out, |_, _, dst| {
            n += 1;
            dst.push_str(MASK);
            true
        });
        if n > 0 {
            *s = out;
            self.masked += n;
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
    fn the_places_review_found_unmasked() {
        // A URL's query after a path parameter, a nested URL, and a fragment.
        assert_eq!(redacted("http://a/x;v=1?access_token=SWALLOW1&b=2"), "http://a/x;v=1?access_token=[redacted]&b=2");
        assert_eq!(redacted("next=/acct?session=REFSESS1"), "next=/acct?session=[redacted]");
        assert_eq!(
            redacted("https://app/cb#access_token=FRAGTOK1&token_type=bearer"),
            "https://app/cb#access_token=[redacted]&token_type=[redacted]"
        );
        // Secret-named headers, at a line's start and inside one.
        assert_eq!(redacted("X-Refresh-Token: REFRESH1"), "X-Refresh-Token: [redacted]");
        assert_eq!(redacted(r#"curl -H "x-api-token: ATTACK1" x"#), r#"curl -H "x-api-token: [redacted]" x"#);
        // id before name; Rails' csrf-param isn't a token.
        assert_eq!(
            redacted(r#"<input id="f1" name="_csrf" value="HIDDEN1">"#),
            r#"<input id="f1" name="_csrf" value="[redacted]">"#
        );
        let rails = r#"<meta name="csrf-param" content="authenticity_token">"#;
        assert_eq!(redacted(rails), rails);
        // JSON arrays and escaped JSON, XML, attributes, script and config text.
        assert_eq!(redacted(r#"{"tokens":["ARR1","ARR2"]}"#), r#"{"tokens":["[redacted]","[redacted]"]}"#);
        assert_eq!(redacted(r#""payload":"{\"secret\":\"NESTED1\"}""#), r#""payload":"{\"secret\":\"[redacted]\"}""#);
        assert_eq!(
            redacted("<wsse:BinarySecurityToken>XMLTOK1</wsse:BinarySecurityToken>"),
            "<wsse:BinarySecurityToken>[redacted]</wsse:BinarySecurityToken>"
        );
        assert_eq!(redacted(r#"<div data-token="DATA1">"#), r#"<div data-token="[redacted]">"#);
        assert_eq!(
            redacted(r#"{apiKey: "JSKEY1", 'authToken': 'JSTOK1'}"#),
            r#"{apiKey: "[redacted]", 'authToken': '[redacted]'}"#
        );
        assert_eq!(redacted("password: YAML1xx"), "password: [redacted]");
        assert_eq!(redacted("Repro: password: NOTEPW1 then"), "Repro: password: [redacted] then");
        // Credentials in a URL, a cut-short JWT, an OAuth code but not an error code.
        assert_eq!(redacted("see https://bob:hunter22@h.test/"), "see https://bob:[redacted]@h.test/");
        assert_eq!(redacted("t eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ4eXoxMjM0NTY3OCJ9"), "t [redacted]");
        assert_eq!(redacted("?code=OAUTHCODE77&state=x"), "?code=[redacted]&state=x");
        assert_eq!(redacted(r#"{"code":"NOT_FOUND"}"#), r#"{"code":"NOT_FOUND"}"#);
        // What the Basic-auth rule wrote before it stopped quoting the password.
        assert_eq!(redacted("username [alice] and password [abc]."), "username [alice] and password [[redacted]].");
    }

    #[test]
    fn credentials_are_found_again_decoded_and_in_any_case() {
        use base64::Engine;
        let mut r = Redactor::default();
        let basic = base64::engine::general_purpose::STANDARD.encode("alice:BASICPASS1");
        let mut h = vec![
            ("Authorization".to_string(), format!("Basic {basic}")),
            ("Cookie".to_string(), "connect.sid=s%3ACOOKIESECRET01.signaturepart; lang=en".to_string()),
        ];
        r.headers(&mut h);
        r.know(["PROF/PASS+Q1".to_string()]);
        let mut body = "your password is BASICPASS1; echo s%3acookiesecret01; PROF%2fPASS%2bQ1 PROF\\/PASS+Q1 \
                        PROF&#x2F;PASS&#x2B;Q1"
            .to_string();
        r.scrub(&mut body);
        for leak in ["BASICPASS1", "cookiesecret01", "PROF"] {
            assert!(!body.to_ascii_lowercase().contains(&leak.to_ascii_lowercase()), "{leak}: {body}");
        }
        // A value inside a longer known one is masked once, whole.
        let mut r = Redactor::default();
        r.know(["abcdef12".to_string(), "ef12XYZW".to_string(), "redacted".to_string()]);
        let mut s = "abcdef12XYZW and [redacted]".to_string();
        r.scrub(&mut s);
        assert_eq!(s, "[redacted]XYZW and [redacted]");
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
