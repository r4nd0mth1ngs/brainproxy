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

use aho_corasick::automaton::Automaton;
use aho_corasick::nfa::contiguous;
use aho_corasick::{Anchored, Input, MatchKind};
use regex::{Captures, Regex};

use crate::scan::report::{HttpRequest, HttpResponse};

/// What a masked value reads as.
pub const MASK: &str = "[redacted]";

/// Values shorter than this are masked where they stand but not searched for elsewhere: a
/// cookie such as `lang=en` would otherwise mask every "en" in the report.
const MIN_SCRUB: usize = 6;

/// How long a cookie item without `=` must be to be masked as a bare session value.
const BARE_COOKIE_MIN: usize = 8;

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
    LazyLock::new(|| Regex::new(&format!(r#""({JSON_NAME})"(\s*:\s*)"((?:[^"\\]|\\.)*)("|$)"#)).unwrap());

/// A JSON member's name, which may spell its letters as `\u` escapes (`"\u0070assword"`).
const JSON_NAME: &str = r"(?:[A-Za-z0-9_.\-]|\\u[0-9A-Fa-f]{4}){1,64}";

/// A JSON member's name with its `\u` escapes undone, to judge it by.
fn json_name(name: &str) -> std::borrow::Cow<'_, str> {
    if !name.contains("\\u") {
        return name.into();
    }
    serde_json::from_str::<String>(&format!("\"{name}\"")).map_or(name.into(), Into::into)
}

/// A JSON member whose value is an array, such as a list of tokens.
static JSON_ARRAY: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(&format!(r#""({JSON_NAME})"(\s*:\s*)\[([^\]]{{0,8192}})\]"#)).unwrap());
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
    LazyLock::new(|| Regex::new(&format!(r#""({JSON_NAME})"(\s*:\s*)(-?[0-9][0-9.eE+\-]*)"#)).unwrap());

/// A credential after an auth scheme in text (`Bearer abc123`, `token: Basic dXNl...`), as
/// a body or a log line may quote one: a token68 value of at least 8 characters.
static SCHEME_CREDENTIAL: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)\b(bearer|basic|token|negotiate)([ \t]+)([A-Za-z0-9\-._~+/]{8,}=*)").unwrap());

/// Whether a word after an auth scheme reads as a credential rather than prose: not a plain
/// lowercase or capitalised word (`Bearer tokens`, `Basic Authentication`).
fn credential_shaped(v: &str) -> bool {
    let letters = v.trim_end_matches('=');
    let mut chars = letters.chars();
    let first_upper = chars.next().is_some_and(|c| c.is_ascii_uppercase());
    let rest_lower = chars.all(|c| c.is_ascii_lowercase());
    let word = letters.chars().all(|c| c.is_ascii_lowercase()) || (first_upper && rest_lower);
    !word
}

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
    /// A matcher for `secrets` (ASCII case ignored); rebuilt when a secret is added.
    matcher: Option<Matcher>,
    /// How many places a value was masked in.
    pub masked: usize,
}

/// An automaton that knows, at each place in a text, every value that ends there. Only the
/// longest one matters to [`Redactor::scrub`]: the others lie inside it.
#[derive(Debug)]
struct Matcher {
    nfa: contiguous::NFA,
    /// The length of the longest value a match state ends, by state id (0: not worked out
    /// yet), worked out once per state.
    longest: Vec<usize>,
}

impl Matcher {
    fn new(secrets: &BTreeSet<String>) -> Option<Matcher> {
        // Standard semantics: each match state holds every value that ends there.
        let nfa = contiguous::Builder::new()
            .match_kind(MatchKind::Standard)
            .ascii_case_insensitive(true)
            .build(secrets)
            .ok()?;
        Some(Matcher { nfa, longest: Vec::new() })
    }

    /// The spans of `s` the values cover, those that overlap or touch merged, in order. One
    /// pass over `s`, whatever the number of values that match at a place, skipping text no
    /// value can start in.
    fn spans(&mut self, s: &str) -> Vec<(usize, usize)> {
        let nfa = &self.nfa;
        let Ok(start) = nfa.start_state(Anchored::No) else { return Vec::new() };
        let bytes = s.as_bytes();
        let longest_value = nfa.max_pattern_len();
        let mut merged: Vec<(usize, usize)> = Vec::new();
        let (mut sid, mut i, mut next_find) = (start, 0, 0);
        while i < bytes.len() {
            // Outside any value: the next match to end (found by the automaton's prefilter, fast)
            // ends first of all those to come, so none starts before its end less the longest
            // value's length.
            if sid == start && i >= next_find {
                match nfa.try_find(&Input::new(s).span(i..bytes.len())) {
                    Ok(Some(m)) => {
                        i = i.max(m.end().saturating_sub(longest_value));
                        next_find = m.end();
                    }
                    Ok(None) => break,
                    Err(_) => next_find = usize::MAX,
                }
            }
            sid = nfa.next_state(Anchored::No, sid, bytes[i]);
            i += 1;
            if !nfa.is_match(sid) {
                continue;
            }
            let at = sid.as_usize();
            if self.longest.len() <= at {
                self.longest.resize(at + 1, 0);
            }
            if self.longest[at] == 0 {
                let lens = (0..nfa.match_len(sid)).map(|k| nfa.pattern_len(nfa.match_pattern(sid, k)));
                self.longest[at] = lens.max().unwrap_or(0);
            }
            let len = self.longest[at];
            let (mut from, end) = (i - len, i);
            // Matches come by where they end; a longer one may start before spans already found.
            while let Some(&(s0, e0)) = merged.last() {
                if from > e0 {
                    break;
                }
                from = from.min(s0);
                merged.pop();
            }
            merged.push((from, end));
        }
        merged
    }
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

/// Whether `name = value` holds a secret: a secret name, a code name with a long value, or
/// `refresh` with a value shaped like a token (not `?refresh=60`, `"refresh": true` or a
/// `Refresh: 5; url=/x` header; `refresh_token` and the like are secret by name).
fn secret_pair(name: &str, value: &str) -> bool {
    let code = value.len() >= CODE_MIN
        && value.chars().any(|c| c.is_ascii_digit())
        && value.chars().any(|c| c.is_ascii_alphabetic());
    let n = name.to_ascii_lowercase();
    let refresh = n == "refresh" && refresh_token(value.trim().trim_matches('"'));
    secret_name(name) || refresh || (code && CODE_NAMES.contains(&n.as_str()))
}

/// Whether a value named `refresh` reads as a token rather than a period, a flag, a
/// timestamp or a redirect (base64 padding at the end is allowed).
fn refresh_token(v: &str) -> bool {
    let core = v.trim_end_matches('=');
    v.len() >= 8 && !core.contains(['=', ';', ' ']) && !core.bytes().all(|b| b.is_ascii_digit()) && credential_shaped(v)
}

/// Whether a header's whole value is a credential (beyond Cookie, Set-Cookie and
/// Authorization, whose names or schemes are kept): a known API-key header, or a name that
/// says it is secret.
pub fn secret_header(name: &str) -> bool {
    let n = name.trim().to_ascii_lowercase();
    SECRET_HEADERS.contains(&n.as_str()) || secret_name(&n)
}

/// Headers whose names say "auth" or end in `-key` but whose values are no credential: an
/// auth challenge (the scheme and realm a server asks for), a WebSocket handshake's nonce,
/// and a retry's idempotency key.
const PLAIN_HEADERS: &[&str] = &["www-authenticate", "proxy-authenticate", "sec-websocket-key", "idempotency-key"];

/// WebSocket subprotocol names that are no credential, lowercase. Browsers can't set
/// headers on a WebSocket, so apps send a token as a subprotocol instead (`Bearer, <token>`,
/// `access_token, <token>`, `graphql-transport-ws, <token>`, Kubernetes'
/// `base64url.bearer.authorization.k8s.io.<token>`): every other item is masked.
const PLAIN_SUBPROTOCOLS: &[&str] = &[
    "graphql-ws",
    "graphql-transport-ws",
    "subscriptions-transport-ws",
    "wamp",
    "wamp.2.json",
    "wamp.2.msgpack",
    "wamp.2.cbor",
    "wamp.2.ubjson",
    "mqtt",
    "mqttv3.1",
    "mqttv3.1.1",
    "mqttv5",
    "soap",
    "stomp",
    "xmpp",
    "sip",
    "msrp",
    "chat",
    "superchat",
    "json",
    "msgpack",
    "cbor",
    "binary",
    "base64",
    "text",
    "jsonrpc",
    "json-rpc",
    "jsonrpc2",
    "echo-protocol",
    "actioncable-v1-json",
    "actioncable-v1-msgpack",
    "actioncable-v1-ext-json",
    "actioncable-unsupported",
    "ocpp1.2",
    "ocpp1.5",
    "ocpp1.6",
    "ocpp2.0",
    "ocpp2.0.1",
    "ocpp2.1",
    "channel.k8s.io",
    "base64.channel.k8s.io",
    "binary.k8s.io",
    "base64.binary.k8s.io",
];

/// A versioned subprotocol name (`v1`, `v10.stomp`, `v4.channel.k8s.io`, `v2.json`): short
/// lowercase words after a version, nothing a token looks like.
static VERSIONED_SUBPROTOCOL: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^v[0-9]{1,3}(?:\.[0-9]{1,3}){0,2}(?:[.\-][a-z][a-z0-9]{0,11}){0,4}$").unwrap());

/// Where Kubernetes puts a bearer token in `Sec-WebSocket-Protocol`.
const K8S_BEARER: &str = "base64url.bearer.authorization.k8s.io.";

/// Whether a `Sec-WebSocket-Protocol` item names a subprotocol rather than carries a token.
fn plain_subprotocol(item: &str) -> bool {
    let item = item.trim();
    let i = item.to_ascii_lowercase();
    // A version name is matched as sent: a token's capitals don't pass as a lowercase name.
    !i.starts_with(K8S_BEARER)
        && (PLAIN_SUBPROTOCOLS.contains(&i.as_str()) || (item.len() <= 40 && VERSIONED_SUBPROTOCOL.is_match(item)))
}

/// Whether a `Sec-WebSocket-Protocol` value carries anything but plain subprotocol names.
fn subprotocol_credential(value: &str) -> bool {
    value.split(',').map(str::trim).any(|i| !i.is_empty() && !plain_subprotocol(i))
}

/// The schemes a credential value starts with (`Authorization: Bearer ...`), lowercase.
const AUTH_SCHEMES: &[&str] = &["bearer", "basic", "token", "digest", "negotiate"];

/// The scheme `value` starts with, when it starts with one followed by whitespace and more.
fn auth_scheme(value: &str) -> Option<&str> {
    let v = value.trim_start();
    let end = v.find(char::is_whitespace)?;
    let (scheme, rest) = v.split_at(end);
    (AUTH_SCHEMES.contains(&scheme.to_ascii_lowercase().as_str()) && !rest.trim().is_empty()).then_some(scheme)
}

/// The word before `-key` in a header name whose key is data, not a credential: a cache's,
/// a table's or a retry's (X-Cache-Key, Sort-Key, Primary-Key, X-Idempotency-Key), or a
/// public one.
const PLAIN_KEY_KINDS: &[&str] = &[
    "cache",
    "sort",
    "primary",
    "partition",
    "range",
    "hash",
    "row",
    "routing",
    "idempotency",
    "dedup",
    "deduplication",
    "correlation",
    "foreign",
    "lookup",
    "object",
    "shard",
    "group",
    "public",
    "websocket",
];

/// Whether a header name, lowercased, reads as a credential's: it says `auth` (X-Api-Auth,
/// X-Authorization, X-Authorisation, Authentication, Grpc-Metadata-Authorization, but not
/// `:authority`, Author or X-Authority), or it ends in `-key` and the word before isn't one
/// of [`PLAIN_KEY_KINDS`] (User-Key and X-Functions-Key are credentials; X-Cache-Key and
/// Sort-Key are data).
fn auth_or_key_name(n: &str) -> bool {
    let author = n.contains("author") && !n.contains("authoriz") && !n.contains("authoris");
    let auth = n.contains("auth") && !author;
    let Some(rest) = n.strip_suffix("-key") else { return auth };
    let kind = rest.rsplit('-').next().unwrap_or_default();
    auth || !PLAIN_KEY_KINDS.contains(&kind)
}

/// Whether a value starts with an auth scheme followed by something credential-shaped
/// (`Token abc123def`, not `Token based` or `Basic is required`).
fn scheme_credential(value: &str) -> bool {
    auth_scheme(value).is_some_and(|scheme| {
        let rest = value.trim_start()[scheme.len()..].trim_start();
        rest.split(|c: char| c.is_whitespace() || c == ',').next().is_some_and(credential_shaped)
    })
}

/// Whether a header holds a credential, by its name or its value: the one rule a HAR file's
/// import (which takes credentials out) and every export (which masks them) share. A known
/// API-key header, a name [`crate::apiimport::looks_secret`] or the report rules call secret,
/// one that says `auth` or names a credential key (see [`auth_or_key_name`]), or a value that
/// starts with an auth scheme (Bearer, Basic, Token, Digest, Negotiate) and a credential-shaped
/// word whatever the name, and a `Sec-WebSocket-Protocol` list
/// with any item but a plain subprotocol name (a token sent as one). Auth challenges and
/// nonces ([`PLAIN_HEADERS`]) are not.
pub fn credential_header(name: &str, value: &str) -> bool {
    let n = name.trim().to_ascii_lowercase();
    if PLAIN_HEADERS.contains(&n.as_str()) {
        return false;
    }
    if n == "sec-websocket-protocol" {
        return subprotocol_credential(value);
    }
    secret_header(&n) || crate::apiimport::looks_secret(&n) || auth_or_key_name(&n) || scheme_credential(value)
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

/// The value a signed cookie signs (`s:VALUE.signature`, as Express's connect.sid writes
/// it, also percent-encoded as `s%3AVALUE.signature`), or None for any other value.
fn unsigned_half(v: &str) -> Option<String> {
    let decoded = percent_encoding::percent_decode_str(v.trim_matches('"')).decode_utf8_lossy().into_owned();
    let rest = decoded.strip_prefix("s:")?;
    let (id, sig) = rest.rsplit_once('.')?;
    (!id.is_empty() && !sig.is_empty()).then(|| id.to_string())
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
        // A signed cookie's session id is the secret, and a page may quote it on its own. One
        // learnt from traffic must be distinctive like any other (`s:session.abc` is no reason
        // to mask the word "session" everywhere).
        if let Some(id) = unsigned_half(v) {
            self.remember_forms(&id, known);
        }
        self.remember_forms(v, known);
    }

    fn remember_forms(&mut self, v: &str, known: bool) {
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

    /// A cookie's `name=value` with the value masked; an item without `=` is a bare value
    /// (some servers set one), masked when it is long enough to be a session id. The
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
            None if item.len() >= BARE_COOKIE_MIN => self.secret(item),
            None => item.to_string(),
        }
    }

    /// A header's value with its secret parts masked, or None when it isn't a credential
    /// header (its value may still hold a secret: see [`Redactor::headers`]). A recorded
    /// header (`recorded`) is judged by [`credential_header`]; a `name: value` line found in
    /// free text, which may be prose (`Author: ...`, `Note: Basic auth is off`), by its name
    /// alone, and by the wider name rules only when it is hyphenated as headers are.
    fn header_value(&mut self, name: &str, value: &str, recorded: bool) -> Option<String> {
        let n = name.trim().to_ascii_lowercase();
        let wide = recorded || n.contains('-');
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
            n if PLAIN_HEADERS.contains(&n) => return None,
            // A list of subprotocols, which may carry a token: the plain names are kept.
            "sec-websocket-protocol" if subprotocol_credential(value) => self.subprotocols(value),
            "sec-websocket-protocol" => return None,
            n if recorded && credential_header(n, value) => self.credential(value),
            n if secret_header(n) || (wide && (crate::apiimport::looks_secret(n) || auth_or_key_name(n))) => {
                self.credential(value)
            }
            _ => return None,
        })
    }

    /// A `Sec-WebSocket-Protocol` list with every item but a plain subprotocol name masked:
    /// a token, the word that marks one (`Bearer`, `access_token`), and a Kubernetes bearer
    /// item whole (its token, base64url-decoded, is learned too).
    fn subprotocols(&mut self, value: &str) -> String {
        use base64::Engine;
        let items: Vec<String> = value
            .split(',')
            .map(|item| {
                let i = item.trim();
                if i.is_empty() || plain_subprotocol(i) {
                    return i.to_string();
                }
                if i.len() > K8S_BEARER.len() && i[..K8S_BEARER.len()].eq_ignore_ascii_case(K8S_BEARER) {
                    let token = &i[K8S_BEARER.len()..];
                    if let Ok(b) = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(token.trim_end_matches('='))
                    {
                        self.remember(&String::from_utf8_lossy(&b), true);
                    }
                    self.remember(token, true);
                }
                // A token has digits or is long; a marker word (`Bearer`, `access_token`) is
                // masked where it stands, not looked for elsewhere.
                let token = i.len() >= 20 || i.chars().any(|c| c.is_ascii_digit());
                if token && distinctive(i) {
                    return self.secret(i);
                }
                self.masked += 1;
                MASK.to_string()
            })
            .collect();
        items.join(", ")
    }

    /// A credential header's value masked, keeping the scheme it starts with, if any.
    fn credential(&mut self, value: &str) -> String {
        match auth_scheme(value) {
            Some(scheme) => {
                let cred = value.trim_start()[scheme.len()..].trim().to_string();
                self.credential_parts(scheme, &cred);
                format!("{scheme} {}", self.secret(&cred))
            }
            None => self.secret(value),
        }
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
            match self.header_value(name, value, true) {
                Some(v) => *value = v,
                None => self.text(value),
            }
        }
    }

    /// Masks secrets in free text by their place: header lines, secret-named JSON members,
    /// `name=value` pairs, multipart fields and form inputs, and JWTs.
    pub fn text(&mut self, s: &mut String) {
        let header = |red: &mut Self, c: &Captures| {
            let v = red.header_value(&c[2], &c[4], false).unwrap_or_else(|| c[4].to_string());
            format!("{}{}{}{v}", &c[1], &c[2], &c[3])
        };
        let mut out = HEADER_LINE.replace_all(s, |c: &Captures| header(self, c)).into_owned();
        out = HEADER_INLINE.replace_all(&out, |c: &Captures| header(self, c)).into_owned();
        out = SCHEME_CREDENTIAL
            .replace_all(&out, |c: &Captures| {
                if !credential_shaped(&c[3]) {
                    return c[0].to_string();
                }
                self.credential_parts(&c[1], &c[3]);
                format!("{}{}{}", &c[1], &c[2], self.secret(&c[3]))
            })
            .into_owned();
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
                if secret_pair(&c[2], &c[3]) {
                    format!("{}{}", &c[1], self.secret(&c[3]))
                } else {
                    c[0].to_string()
                }
            })
            .into_owned();
        out = JSON_MEMBER
            .replace_all(&out, |c: &Captures| {
                if secret_pair(&json_name(&c[1]), &c[3]) {
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
                if !secret_name(&json_name(&c[1])) {
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
                if secret_pair(&c[2], &c[4]) {
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
                if !plain && secret_pair(&c[2], &c[4]) {
                    format!("{}{}{}{}\"", &c[1], &c[2], &c[3], self.secret(&c[4]))
                } else {
                    c[0].to_string()
                }
            })
            .into_owned();
        out = JSON_NUMBER
            .replace_all(&out, |c: &Captures| {
                if secret_name(&json_name(&c[1])) {
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

    /// Replaces every value known so far wherever it appears in `s`. Every match is found,
    /// overlapping ones too, and the spans that overlap or touch are masked as one, so no
    /// part of a second value that shares characters with the first is left in the text.
    pub fn scrub(&mut self, s: &mut String) {
        if self.secrets.is_empty() {
            return;
        }
        if self.matcher.is_none() {
            self.matcher = Matcher::new(&self.secrets);
        }
        let Some(m) = &mut self.matcher else { return };
        let merged = m.spans(s);
        if merged.is_empty() {
            return;
        }
        let mut out = String::with_capacity(s.len());
        let mut at = 0;
        for &(start, end) in &merged {
            out.push_str(&s[at..start]);
            out.push_str(MASK);
            at = end;
        }
        out.push_str(&s[at..]);
        *s = out;
        self.masked += merged.len();
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
    fn credential_headers_by_name_or_scheme() {
        let token = "Bearer OPAQUE7f3k9Qz1";
        let leaked = [
            "X-Authorization",
            "Authentication",
            "X-Auth-Key",
            "X-Access-Key",
            "Ocp-Apim-Subscription-Key",
            "X-Functions-Key",
            "X-Client-Key",
            "X-Consumer-Key",
            "X-Api-Auth",
            "X-Upstream-Auth",
            "Grpc-Metadata-Authorization",
            "X-Pin",
        ];
        let mut r = Redactor::default();
        let mut h: Vec<(String, String)> = leaked.iter().map(|n| (n.to_string(), token.to_string())).collect();
        r.headers(&mut h);
        for (n, v) in &h {
            assert_eq!(v, "Bearer [redacted]", "{n}");
            assert!(credential_header(n, token), "{n}");
        }
        // By name alone, the whole value; by scheme whatever the name, case ignored.
        let mut h = vec![
            ("X-Functions-Key".to_string(), "fk-9Qz1x7Lm".to_string()),
            ("X-Custom".to_string(), "basic dXNlcjpwYXNzd29yZA==".to_string()),
            ("X-Other".to_string(), "Negotiate YIIGhgYGKwYBBQUC".to_string()),
            ("X-Plain".to_string(), "Token\tabc123def".to_string()),
        ];
        r.headers(&mut h);
        assert_eq!(h[0].1, "[redacted]");
        assert_eq!(h[1].1, "basic [redacted]");
        assert_eq!(h[2].1, "Negotiate [redacted]");
        assert_eq!(h[3].1, "Token [redacted]");
        // The decoded Basic password is found again.
        let mut echo = "logged in with password".to_string();
        r.scrub(&mut echo);
        assert_eq!(echo, "logged in with [redacted]");
        // Harmless headers, auth challenges and nonces are kept.
        let plain = [
            ("Accept", "*/*"),
            ("Content-Type", "application/json"),
            ("Cache-Control", "no-cache"),
            ("Keep-Alive", "timeout=5"),
            ("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ=="),
            ("Idempotency-Key", "8e03978e-40d5-43e8-bc93-6894a57f9324"),
            ("WWW-Authenticate", "Bearer realm=\"api\""),
            ("Proxy-Authenticate", "Basic realm=\"proxy\""),
            (":authority", "app.test"),
            ("Author", "Jane Doe"),
            ("Vary", "Authorization"),
            ("X-Mode", "Basic"),
        ];
        let mut h: Vec<(String, String)> = plain.iter().map(|(n, v)| (n.to_string(), v.to_string())).collect();
        let before = h.clone();
        let mut r = Redactor::default();
        r.headers(&mut h);
        assert_eq!(h, before);
        assert_eq!(r.masked, 0);
        for (n, v) in plain {
            assert!(!credential_header(n, v), "{n}");
        }
        // In free text a bare word before a colon may be prose; a hyphenated name is a header.
        assert_eq!(redacted("Author: Jane\nNote: Basic"), "Author: Jane\nNote: Basic");
        assert_eq!(redacted("X-Functions-Key: fk-9Qz1x7Lm"), "X-Functions-Key: [redacted]");
        assert_eq!(redacted(r#"curl -H "X-Api-Auth: s3cr3tvalue1""#), r#"curl -H "X-Api-Auth: [redacted]""#);
    }

    #[test]
    fn plain_headers_and_params_the_wider_rules_left_alone() {
        // Keys that are data, scheme words in prose, a Refresh period, author names.
        let plain = [
            ("Sort-Key", "createdAt"),
            ("Primary-Key", "id"),
            ("X-Cache-Key", "GET:/api/items:v2"),
            ("X-Idempotency-Key", "8e03978e-40d5-43e8-bc93-6894a57f9324"),
            ("X-Mode", "Token based"),
            ("X-Help", "Basic is required"),
            ("Accept-Language", "token en"),
            ("Refresh", "5; url=/x"),
            ("X-Author", "Jane Doe"),
            ("X-Authority", "registry.test"),
        ];
        let mut h: Vec<(String, String)> = plain.iter().map(|(n, v)| (n.to_string(), v.to_string())).collect();
        let before = h.clone();
        let mut r = Redactor::default();
        r.headers(&mut h);
        assert_eq!((h, r.masked), (before, 0));
        for (n, v) in plain {
            assert!(!credential_header(n, v), "{n}");
        }
        for s in ["/feed?refresh=60&x=1", "/feed?refresh=true", r#"{"refresh": 30, "auto": "refresh"}"#] {
            assert_eq!(redacted(s), s);
        }
        // Credential keys, a scheme with a credential after it, and Authorization whatever it holds.
        for (n, v) in [
            ("X-Api-Key", "k"),
            ("Api-Key", "k"),
            ("X-Partner-Key", "k"),
            ("Ocp-Apim-Subscription-Key", "k"),
            ("X-Custom-Key", "k"),
            ("X-Mode", "Token abc123def"),
            ("Authorization", "Token based"),
            ("X-Auth-Token", "k"),
        ] {
            let mut h = vec![(n.to_string(), v.to_string())];
            let mut r = Redactor::default();
            r.headers(&mut h);
            assert!(h[0].1.contains(MASK), "{n}: {}", h[0].1);
        }
        assert!(crate::apiimport::looks_secret("X-Authorization") && crate::apiimport::looks_secret("X-Auth-Token"));
        assert!(!crate::apiimport::looks_secret("X-Author") && !crate::apiimport::looks_secret("X-Authority"));
        // refresh_token is secret whatever its value; `refresh` when it holds a token.
        assert_eq!(redacted("refresh_token=60"), "refresh_token=[redacted]");
        assert_eq!(redacted("Refresh: rt-91kd0aZ"), "Refresh: rt-91kd0aZ");
        assert_eq!(redacted("x?refresh=rt-91kd0aZ"), "x?refresh=[redacted]");
    }

    #[test]
    fn websocket_subprotocols_that_carry_a_token() {
        // A token as browsers must send one, in Sec-WebSocket-Protocol's comma-separated list.
        let k8s_token = "eyJhbGciOiJSUzI1NiJ9-K8STOKEN42";
        let k8s = {
            use base64::Engine;
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(k8s_token)
        };
        let cases = [
            ("Bearer, OPAQUE7f3k9Qz1", "[redacted], [redacted]"),
            ("access_token, OPAQUE7f3k9Qz1", "[redacted], [redacted]"),
            ("graphql-transport-ws, OPAQUE7f3k9Qz1", "graphql-transport-ws, [redacted]"),
            (
                &*format!("v4.channel.k8s.io, base64url.bearer.authorization.k8s.io.{k8s}"),
                "v4.channel.k8s.io, [redacted]",
            ),
        ];
        for (value, masked) in cases {
            assert!(credential_header("Sec-WebSocket-Protocol", value), "{value}");
            let mut r = Redactor::default();
            let mut h = vec![("Sec-WebSocket-Protocol".to_string(), value.to_string())];
            r.headers(&mut h);
            assert_eq!(h[0].1, masked, "{value}");
            // In text too: a header line, and one quoted in a curl command.
            assert_eq!(
                redacted(&format!("Sec-WebSocket-Protocol: {value}")),
                format!("Sec-WebSocket-Protocol: {masked}")
            );
            assert_eq!(
                redacted(&format!(r#"curl -H "Sec-WebSocket-Protocol: {value}" ws://x"#)),
                format!(r#"curl -H "Sec-WebSocket-Protocol: {masked}" ws://x"#)
            );
        }
        // The token is found again elsewhere, the marker words are not.
        let mut r = Redactor::default();
        let mut h = vec![("Sec-WebSocket-Protocol".to_string(), "access_token, OPAQUE7f3k9Qz1".to_string())];
        r.headers(&mut h);
        let mut echo = "token OPAQUE7f3k9Qz1 in access_token".to_string();
        r.scrub(&mut echo);
        assert_eq!(echo, "token [redacted] in access_token");
        // A Kubernetes token is learned decoded as well.
        let mut r = Redactor::default();
        let mut h = vec![(
            "Sec-WebSocket-Protocol".to_string(),
            format!("base64url.bearer.authorization.k8s.io.{k8s}, v4.channel.k8s.io"),
        )];
        r.headers(&mut h);
        assert_eq!(h[0].1, "[redacted], v4.channel.k8s.io");
        let mut echo = format!("Authorization: Bearer {k8s_token}");
        r.scrub(&mut echo);
        assert!(!echo.contains("K8STOKEN42"), "{echo}");
        // Plain subprotocol lists are kept.
        for value in [
            "graphql-ws",
            "graphql-transport-ws",
            "wamp.2.json, wamp.2.msgpack",
            "v10.stomp, v11.stomp",
            "mqtt",
            "v4.channel.k8s.io",
        ] {
            assert!(!credential_header("Sec-WebSocket-Protocol", value), "{value}");
            let mut r = Redactor::default();
            let mut h = vec![("Sec-WebSocket-Protocol".to_string(), value.to_string())];
            r.headers(&mut h);
            assert_eq!((h[0].1.as_str(), r.masked), (value, 0));
            assert_eq!(
                redacted(&format!("Sec-WebSocket-Protocol: {value}")),
                format!("Sec-WebSocket-Protocol: {value}")
            );
        }
    }

    #[test]
    fn the_gaps_the_second_review_found() {
        // Any `-key` header that isn't data, and the British spelling of Authorization.
        for n in ["User-Key", "Admin-Key", "Hmac-Key", "Write-Key", "Merchant-Key", "Authorisation", "X-Authorisation"]
        {
            assert!(credential_header(n, "k"), "{n}");
        }
        // A refresh token with base64 padding is one; a timestamp isn't.
        let padded = "dGhpcyBpcyBhIHJlZnJlc2g=";
        assert!(!redacted(&format!("/feed?refresh={padded}")).contains(padded));
        assert!(!redacted(&format!(r#"{{"refresh": "{padded}="}}"#)).contains(padded));
        assert_eq!(redacted("/feed?refresh=1700000000123"), "/feed?refresh=1700000000123");
        // A version-style subprotocol is matched as sent, so a token's capitals give it away.
        for v in ["v1.aB3dE5gH7jK9", "V1.QWERTYUIOPAS"] {
            assert!(subprotocol_credential(v), "{v}");
        }
        assert!(!subprotocol_credential("v10.stomp, v4.channel.k8s.io"));
    }

    #[test]
    fn the_gaps_the_export_review_found() {
        // A cookie item without `=`, long enough to be a session; a short one is kept.
        let mut r = Redactor::default();
        let mut h = vec![("Cookie".to_string(), "BARECOOKIESECRET42; lang=en; ab".to_string())];
        r.headers(&mut h);
        assert_eq!(h[0].1, "[redacted]; lang=[redacted]; ab");
        // A JSON name spelt with \u escapes is judged by what it spells.
        assert_eq!(
            redacted(r#"{"\u0070assword": "hunter22", "name": "bob", "\u006ftp": 123456}"#),
            r#"{"\u0070assword": "[redacted]", "name": "bob", "\u006ftp": "[redacted]"}"#
        );
        assert_eq!(redacted(r#"{"\u0074okens": ["Zq81kd0aa"]}"#), r#"{"\u0074okens": ["[redacted]"]}"#);
        // A credential after an auth scheme in a body; prose after one is kept.
        assert_eq!(redacted("log: sent Bearer OPAQUE7f3k9Qz1 to the API"), "log: sent Bearer [redacted] to the API");
        assert_eq!(redacted(r#"{"h": "Basic dXNlcjpodW50ZXIy"}"#), r#"{"h": "Basic [redacted]"}"#);
        let prose = "Bearer tokens and Basic Authentication are both accepted";
        assert_eq!(masked(prose), (prose.to_string(), 0));
        // `refresh` names a refresh token.
        assert_eq!(redacted(r#"{"refresh": "rt-91kd0aZ"}"#), r#"{"refresh": "[redacted]"}"#);
        assert_eq!(
            redacted("grant_type=refresh_token&refresh=rt-91kd0aZ"),
            "grant_type=refresh_token&refresh=[redacted]"
        );
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
        // Two known values that overlap are masked together, and one inside another once, whole.
        let mut r = Redactor::default();
        r.know(["abcdef12".to_string(), "ef12XYZW".to_string(), "redacted".to_string()]);
        let mut s = "abcdef12XYZW and [redacted]".to_string();
        r.scrub(&mut s);
        assert_eq!((s.as_str(), r.masked), ("[redacted] and [redacted]", 1));
        r.know(["Zq81kd0aa1".to_string(), "81kd0aa".to_string()]);
        let mut s = "x Zq81kd0aa1 y 81kd0aa z".to_string();
        r.scrub(&mut s);
        assert_eq!(s, "x [redacted] y [redacted] z");
        // A longer value that starts before spans already found takes them in.
        let mut r = Redactor::default();
        r.know(["bbbbbb".to_string(), "dddddd".to_string(), "abbbbbbcddddddd".to_string()]);
        let mut s = "bbbbbb abbbbbbcddddddd".to_string();
        r.scrub(&mut s);
        assert_eq!((s.as_str(), r.masked), ("[redacted] [redacted]", 2));
    }

    #[test]
    fn many_nested_values_over_long_text_are_scrubbed_in_one_pass() {
        // 500 values each inside the next, and 64 KB that every one of them matches all over:
        // millions of overlapping matches, of which one span is left.
        let token: String = (0..600).map(|i| (b'a' + (i % 3) as u8) as char).collect();
        let mut r = Redactor::default();
        r.know((0..500).map(|n| token[..6 + n].to_string()));
        let text = token.repeat(64 * 1024 / token.len() + 1);
        let mut s = format!("start {text} end");
        let started = std::time::Instant::now();
        r.scrub(&mut s);
        let took = started.elapsed();
        assert_eq!(s, "start [redacted] end");
        // Generous for a debug build on a slow CI runner (Windows took 246 ms); collecting every
        // overlapping match took seconds.
        assert!(took < std::time::Duration::from_millis(750), "{took:?}");

        // Text the values are seldom in is skipped, but each one in it is found.
        let mut s = format!("{} {} {}", "xyz abd ".repeat(4096), &token[..40], "ab ".repeat(8192));
        let started = std::time::Instant::now();
        r.scrub(&mut s);
        let took = started.elapsed();
        assert_eq!(s.matches(MASK).count(), 1);
        assert!(!s.contains("abcabc"));
        assert!(took < std::time::Duration::from_millis(750), "{took:?}");
    }

    #[test]
    fn a_signed_cookies_session_id_is_found_alone() {
        // Shorter than the parts a cookie's value is split into, raw and percent-encoded, and
        // from a profile's known cookie as well as from traffic.
        let mut r = Redactor::default();
        let mut h = vec![("Cookie".to_string(), "connect.sid=s%3AshortID9.c2lnbmF0dXJl".to_string())];
        r.headers(&mut h);
        r.know(["s:PROFSID7.sigsigsig".to_string()]);
        let mut s = "session shortID9 and PROFSID7, signed s:PROFSID7.sigsigsig".to_string();
        r.scrub(&mut s);
        assert_eq!(s, "session [redacted] and [redacted], signed [redacted]");
        // One learnt from traffic that is a plain word is masked where it stands, not everywhere;
        // a profile's is known to be a secret, word or not.
        let mut r = Redactor::default();
        let mut h = vec![("Cookie".to_string(), "connect.sid=s%3Asession.abcdef".to_string())];
        r.headers(&mut h);
        r.know(["s:account.sigsigsig".to_string()]);
        let mut s = "the session of an account".to_string();
        r.scrub(&mut s);
        assert_eq!(s, "the session of an [redacted]");
        // Any other value with a dot in it is not split.
        assert_eq!(unsigned_half("abc.def"), None);
        assert_eq!(unsigned_half("s%3AID12345.sig").as_deref(), Some("ID12345"));
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
