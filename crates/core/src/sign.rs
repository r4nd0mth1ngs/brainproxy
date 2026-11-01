//! Request signing: HMAC signatures and JWTs for APIs that reject unsigned requests.
//!
//! A signer is data on a profile, next to its macros and session rules, and a rule's
//! `sign:NAME` action uses it. The action only writes placeholders
//! (`«auth:PROFILE:sign:NAME»`) into the request, so records of it hold no signature or
//! token. The vault computes the value as the bytes go on the wire, after every mutation,
//! every other placeholder and the Content-Length update, so what is signed is what is sent.
//!
//! Signers hold where the key is (an environment variable or a file), never the key, so
//! nothing that shows a profile or reads the project can reveal it. Templates only name
//! parts of the request: nothing here runs code.

use std::path::PathBuf;

use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine;
use ring::{hmac, rand, signature};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};

use crate::error::{Error, Result};
use crate::http::request::{find, split_head_body};
use crate::http::{RawRequest, Target};

/// Where a signing key is read from when a signer first signs; never stored.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum KeySource {
    Env(String),
    File(PathBuf),
}

#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum KeyEncoding {
    #[default]
    Raw,
    Hex,
    Base64,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum HmacAlg {
    Sha1,
    Sha256,
    Sha384,
    Sha512,
}

impl HmacAlg {
    pub fn parse(s: &str) -> Result<HmacAlg> {
        Ok(match s.trim().to_ascii_lowercase().replace('-', "").as_str() {
            "sha1" => HmacAlg::Sha1,
            "sha256" => HmacAlg::Sha256,
            "sha384" => HmacAlg::Sha384,
            "sha512" => HmacAlg::Sha512,
            _ => {
                return Err(Error::InvalidInput(format!(
                    "unknown HMAC hash {s:?}; one of sha1, sha256, sha384, sha512"
                )))
            }
        })
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq)]
pub enum JwtAlg {
    HS256,
    HS384,
    HS512,
    RS256,
}

impl JwtAlg {
    pub fn parse(s: &str) -> Result<JwtAlg> {
        Ok(match s.trim().to_ascii_uppercase().as_str() {
            "HS256" => JwtAlg::HS256,
            "HS384" => JwtAlg::HS384,
            "HS512" => JwtAlg::HS512,
            "RS256" => JwtAlg::RS256,
            _ => {
                return Err(Error::InvalidInput(format!(
                    "unknown JWT algorithm {s:?}; one of HS256, HS384, HS512, RS256"
                )))
            }
        })
    }

    fn name(self) -> &'static str {
        match self {
            JwtAlg::HS256 => "HS256",
            JwtAlg::HS384 => "HS384",
            JwtAlg::HS512 => "HS512",
            JwtAlg::RS256 => "RS256",
        }
    }
}

#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum Output {
    #[default]
    Hex,
    Base64,
    Base64url,
}

/// What a signer makes.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "kind", rename_all = "lowercase")]
pub enum SignKind {
    /// An HMAC over `canonical` (see [`VARS`]; `\n`, `\r`, `\t` and `\\` unescape).
    Hmac {
        alg: HmacAlg,
        canonical: String,
        #[serde(default)]
        output: Output,
    },
    /// A JWT with the claims of the `claims` JSON template.
    Jwt {
        alg: JwtAlg,
        claims: String,
        /// Seconds of validity: sets `iat` and `exp` unless the claims do.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        ttl: Option<u64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        kid: Option<String>,
        /// Start from the token already in the request: its header and claims, with
        /// `claims` on top.
        #[serde(default)]
        resign: bool,
    },
}

/// Where the value goes. A body parameter isn't offered: it would change what a body
/// hash covers.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum Place {
    Header(String),
    Query(String),
}

impl std::fmt::Display for Place {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Place::Header(n) => write!(f, "header:{n}"),
            Place::Query(n) => write!(f, "query:{n}"),
        }
    }
}

impl Place {
    /// Parses `header:NAME` or `query:NAME`.
    pub fn parse(s: &str) -> Result<Place> {
        match s.split_once(':') {
            Some((k, n)) if k.eq_ignore_ascii_case("header") => Ok(Place::Header(n.trim().to_string())),
            Some((k, n)) if k.eq_ignore_ascii_case("query") => Ok(Place::Query(n.trim().to_string())),
            _ => Err(Error::InvalidInput(format!("{s:?}: use header:NAME or query:NAME"))),
        }
    }

    fn name(&self) -> &str {
        match self {
            Place::Header(n) | Place::Query(n) => n,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Signer {
    pub name: String,
    pub key: KeySource,
    #[serde(default)]
    pub key_encoding: KeyEncoding,
    /// Origins the value may be sent to.
    pub origins: Vec<String>,
    pub to: Place,
    /// A header's value around `{{signature}}`, e.g. `Bearer {{signature}}`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub format: Option<String>,
    /// Headers set before signing (`X-Timestamp`, `{{timestamp}}`), so the server gets
    /// the values the signature covers.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub headers: Vec<(String, String)>,
    #[serde(flatten)]
    pub kind: SignKind,
}

/// The names a template can use, besides `header:NAME`.
pub const VARS: &[&str] = &[
    "method",
    "host",
    "path",
    "query",
    "body",
    "body_sha256",
    "body_sha256_base64",
    "timestamp",
    "timestamp_ms",
    "nonce",
];

/// Headers the transport or the session owns.
const RESERVED: &[&str] = &["host", "content-length", "transfer-encoding", "connection", "cookie"];

impl Signer {
    pub fn validate(&self) -> Result<()> {
        let what = |e: String| Error::InvalidInput(format!("signer {:?}: {e}", self.name));
        if self.name.is_empty() || !self.name.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.'))
        {
            return Err(what("use letters, digits, '_', '-' and '.' in its name".into()));
        }
        if self.origins.is_empty() {
            return Err(what("name the origins it may sign for".into()));
        }
        for o in &self.origins {
            Target::from_url(o).map_err(|e| what(format!("origin {o:?}: {e}")))?;
        }
        let name_ok = match &self.to {
            Place::Header(n) => valid_token(n),
            // Sent as written, so nothing that means something in a query.
            Place::Query(n) => {
                !n.is_empty() && n.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~'))
            }
        };
        if !name_ok {
            return Err(what(format!("bad destination name {:?}", self.to.name())));
        }
        if let Place::Header(n) = &self.to {
            if RESERVED.iter().any(|r| r.eq_ignore_ascii_case(n)) {
                return Err(what(format!("can't put the value in {n}")));
            }
        }
        match (&self.to, &self.format) {
            (Place::Query(_), Some(_)) => return Err(what("--wrap is for a header".into())),
            (_, Some(f)) if f.matches("{{signature}}").count() != 1 => {
                return Err(what("--wrap needs {{signature}} once".into()))
            }
            (_, Some(f)) if f.contains(['\r', '\n']) => return Err(what("--wrap can't hold a line break".into())),
            _ => {}
        }
        for (k, tpl) in &self.headers {
            if !valid_token(k) || RESERVED.iter().any(|r| r.eq_ignore_ascii_case(k)) {
                return Err(what(format!("can't set header {k:?}")));
            }
            // A header value has no business holding the body.
            check_vars(tpl, &["body"]).map_err(|e| what(format!("header {k}: {e}")))?;
            if tpl.contains(['\r', '\n']) {
                return Err(what(format!("header {k} can't hold a line break")));
            }
        }
        match &self.kind {
            SignKind::Hmac { canonical, .. } => check_vars(canonical, &[]).map_err(what)?,
            SignKind::Jwt { claims, .. } => {
                check_vars(claims, &[]).map_err(what)?;
                // Only the times are numbers: anything else needs its quotes in the JSON.
                let sample = |v: &str| Some(if v.starts_with("timestamp") { b"0".to_vec() } else { b"x".to_vec() });
                claims_object(&render(claims, &sample, Mode::Json)).map_err(|e| what(format!("--claims: {e}")))?;
            }
        }
        Ok(())
    }

    fn mark(&self, profile: &str) -> String {
        crate::auth::placeholder(profile, &format!("sign:{}", self.name))
    }

    /// Closes a token to re-sign, which stands between this and [`Signer::mark`].
    fn end_mark(&self, profile: &str) -> String {
        crate::auth::placeholder(profile, &format!("sign:{}:end", self.name))
    }

    /// What a destination's current value says to put in the placeholders: nothing, or
    /// for a re-signer the token in it, marked off. A value already placed keeps its token.
    fn slot(&self, profile: &str, old: Option<&str>) -> String {
        let (mark, end) = (self.mark(profile), self.end_mark(profile));
        let token = old.filter(|_| matches!(self.kind, SignKind::Jwt { resign: true, .. })).and_then(|v| {
            if let Some((_, placed)) = v.split_once(&mark) {
                return placed.split_once(&end).map(|(t, _)| t);
            }
            let (before, after) =
                self.format.as_deref().and_then(|f| f.split_once("{{signature}}")).unwrap_or(("", ""));
            let bare = v.strip_prefix(before).and_then(|x| x.strip_suffix(after));
            bare.or_else(|| v.rsplit(' ').next())
        });
        match token.filter(|t| !t.is_empty()) {
            Some(t) => format!("{mark}{t}{end}"),
            None => mark,
        }
    }

    fn header_mark(&self, profile: &str, header: &str) -> String {
        crate::auth::placeholder(profile, &format!("sign:{}:h:{header}", self.name))
    }

    /// Every placeholder this signer writes.
    pub(crate) fn marks(&self, profile: &str) -> Vec<String> {
        let mut out = vec![self.mark(profile), self.end_mark(profile)];
        out.extend(self.headers.iter().map(|(k, _)| self.header_mark(profile, k)));
        out
    }

    /// The request with this signer's placeholders in place, unless the destination is
    /// in `keep` (being attacked: a bad signature is the test).
    pub(crate) fn place(&self, raw: &[u8], profile: &str, keep: &[&str]) -> Vec<u8> {
        let mut out = raw.to_vec();
        for (k, _) in self.headers.iter().filter(|(k, _)| !keep.iter().any(|x| x.eq_ignore_ascii_case(k))) {
            out = RawRequest::from_bytes(out).set_header(k, &self.header_mark(profile, k)).into_bytes();
        }
        if keep.iter().any(|k| k.eq_ignore_ascii_case(self.to.name())) {
            return out;
        }
        match &self.to {
            Place::Header(name) => {
                let old = RawRequest::from_bytes(out.clone())
                    .head()
                    .ok()
                    .and_then(|h| h.headers.into_iter().find(|(k, _)| k.eq_ignore_ascii_case(name)))
                    .map(|(_, v)| v);
                let slot = self.slot(profile, old.as_deref());
                let value = match &self.format {
                    Some(f) => f.replace("{{signature}}", &slot),
                    None => slot,
                };
                RawRequest::from_bytes(out).set_header(name, &value).into_bytes()
            }
            Place::Query(name) => set_query(&out, name, |old| self.slot(profile, old)),
        }
    }

    /// Fills the headers this signer sets, whose values other signers may cover.
    fn set_headers(&self, raw: Vec<u8>, profile: &str, target: &Target, stamp: &Stamp) -> Result<Vec<u8>> {
        let mark = self.mark(profile);
        let mut out = raw;
        for (k, tpl) in &self.headers {
            let ph = self.header_mark(profile, k);
            if find(split_head_body(&out).0, ph.as_bytes()).is_some() {
                let value = {
                    let parts = Parts::new(&out, target, &mark, stamp);
                    self.filled(render(tpl, &|v| parts.get(v), Mode::Plain))?
                };
                out = replace(&out, ph.as_bytes(), 0, &value);
            }
        }
        Ok(out)
    }

    /// A rendered template, unless it took in a placeholder not yet filled: signing that
    /// would sign something other than what is sent.
    fn filled(&self, text: Vec<u8>) -> Result<Vec<u8>> {
        if find(&text, crate::auth::MARK.as_bytes()).is_some() {
            return Err(Error::InvalidInput(format!(
                "signer {:?} covers a value not computed yet: its own signature, or that of a signer \
                 added after it (add it again to run it later)",
                self.name
            )));
        }
        Ok(text)
    }

    /// Computes this signer's value, in a request whose other placeholders are filled.
    fn sign(&self, raw: Vec<u8>, profile: &str, key: &[u8], target: &Target, stamp: &Stamp) -> Result<Vec<u8>> {
        let mark = self.mark(profile);
        let out = raw;
        let head_len = split_head_body(&out).0.len();
        let Some(at) = find(&out[..head_len], mark.as_bytes()) else { return Ok(out) };
        // A token to re-sign runs from the placeholder to its end mark.
        let token_at = at + mark.len();
        let end = self.end_mark(profile);
        let token_len = find(&out[token_at..head_len], end.as_bytes());
        let token = token_len.map_or(&[][..], |n| &out[token_at..token_at + n]);
        let now = stamp.now;
        let value = {
            let parts = Parts::new(&out, target, &mark, stamp);
            match &self.kind {
                SignKind::Hmac { alg, canonical, output } => {
                    let text = self.filled(render(canonical, &|v| parts.get(v), Mode::Canonical))?;
                    encode_output(*output, &hmac_digest(*alg, key, &text))
                }
                SignKind::Jwt { alg, claims, ttl, kid, resign } => {
                    let text = self.filled(render(claims, &|v| parts.get(v), Mode::Json))?;
                    let mut payload = claims_object(&text)?;
                    let mut header = Map::new();
                    if *resign && !token.is_empty() {
                        let old = crate::codec::decode_jwt(&String::from_utf8_lossy(token)).map_err(|_| {
                            Error::InvalidInput(format!("signer {:?}: no JWT to re-sign in {}", self.name, self.to))
                        })?;
                        let object = |v: &Value| v.as_object().cloned().unwrap_or_default();
                        header = object(&old["header"]);
                        let mut merged = object(&old["payload"]);
                        merged.append(&mut payload);
                        payload = merged;
                    }
                    if let Some(ttl) = ttl {
                        // `claims` wins, but a re-signed token's old times don't.
                        let own = claims_object(&text)?;
                        for (claim, at) in [("iat", now.as_secs()), ("exp", now.as_secs().saturating_add(*ttl))] {
                            if !own.contains_key(claim) {
                                payload.insert(claim.into(), at.into());
                            }
                        }
                    }
                    if let Some(kid) = kid {
                        header.insert("kid".into(), kid.clone().into());
                    }
                    header.insert("alg".into(), alg.name().into());
                    header.entry("typ").or_insert_with(|| "JWT".into());
                    let bytes =
                        |m: Map<String, Value>| serde_json::to_vec(&m).map_err(|e| Error::InvalidInput(e.to_string()));
                    jwt_token(*alg, key, &bytes(header)?, &bytes(payload)?)
                        .map_err(|e| Error::InvalidInput(format!("signer {:?}: {e}", self.name)))?
                }
            }
        };
        let value = match self.to {
            Place::Query(_) => url::form_urlencoded::byte_serialize(value.as_bytes()).collect::<String>(),
            Place::Header(_) => value,
        };
        let trailing = token_len.map_or(0, |n| n + end.len());
        Ok(replace(&out, mark.as_bytes(), trailing, value.as_bytes()))
    }
}

/// Reads a signer's key. The message of a key that can't be loaded names where
/// it should have come from, never what was there.
pub(crate) fn load_key(s: &Signer) -> std::result::Result<Vec<u8>, String> {
    let (raw, from) = match &s.key {
        KeySource::Env(var) => {
            let v = std::env::var_os(var).ok_or_else(|| format!("environment variable {var} is not set"))?;
            (v.into_encoded_bytes(), format!("environment variable {var}"))
        }
        KeySource::File(path) => {
            let from = format!("file {}", path.display());
            (std::fs::read(path).map_err(|_| format!("{from} can't be read"))?, from)
        }
    };
    let trimmed = String::from_utf8_lossy(&raw);
    match s.key_encoding {
        KeyEncoding::Raw => Ok(raw),
        KeyEncoding::Hex => hex::decode(trimmed.trim()).map_err(|_| format!("{from} is not hex")),
        KeyEncoding::Base64 => STANDARD
            .decode(trimmed.trim())
            .or_else(|_| URL_SAFE_NO_PAD.decode(trimmed.trim().trim_end_matches('=')))
            .map_err(|_| format!("{from} is not base64")),
    }
}

/// A signer as the vault keeps it, with its key once it has signed: a key no request
/// needs stays where it is.
#[derive(Clone)]
pub(crate) struct Loaded {
    pub profile: String,
    pub signer: Signer,
    key: std::sync::OnceLock<std::result::Result<Vec<u8>, String>>,
}

impl Loaded {
    pub(crate) fn new(profile: &str, signer: Signer) -> Self {
        Loaded { profile: profile.to_string(), signer, key: Default::default() }
    }

    fn check_origin(&self, target: &Target) -> Result<()> {
        if self.signer.origins.iter().any(|o| same_origin(o, target)) {
            return Ok(());
        }
        Err(Error::InvalidInput(format!("signer {:?} doesn't sign for {}", self.signer.name, target.origin())))
    }

    fn used(&self, raw: &[u8]) -> bool {
        let (head, _) = split_head_body(raw);
        self.signer.marks(&self.profile).iter().any(|m| find(head, m.as_bytes()).is_some())
    }

    /// Fills the headers of this signer in a request that has its placeholders.
    pub(crate) fn set_headers(&self, raw: Vec<u8>, target: &Target, stamp: &Stamp) -> Result<Vec<u8>> {
        if !self.used(&raw) {
            return Ok(raw);
        }
        self.check_origin(target)?;
        self.signer.set_headers(raw, &self.profile, target, stamp)
    }

    /// Computes this signer's value; none of its placeholders may stay in the request.
    pub(crate) fn sign(&self, raw: Vec<u8>, target: &Target, stamp: &Stamp) -> Result<Vec<u8>> {
        if !self.used(&raw) {
            return Ok(raw);
        }
        self.check_origin(target)?;
        let name = &self.signer.name;
        let key = self.key.get_or_init(|| load_key(&self.signer));
        let key = key.as_ref().map_err(|e| Error::InvalidInput(format!("signer {name:?}: {e}")))?;
        let out = self.signer.sign(raw, &self.profile, key, target, stamp)?;
        if self.used(&out) {
            return Err(Error::InvalidInput(format!("signer {name:?} has a placeholder out of place in this request")));
        }
        Ok(out)
    }
}

/// The time and nonce of one send, the same for every template that names them.
pub(crate) struct Stamp {
    nonce: String,
    now: std::time::Duration,
}

impl Stamp {
    pub(crate) fn new() -> Result<Stamp> {
        Ok(Stamp {
            nonce: nonce()?,
            now: std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default(),
        })
    }
}

pub(crate) fn same_origin(origin: &str, target: &Target) -> bool {
    Target::from_url(origin).is_ok_and(|t| t.origin() == target.origin())
}

/// The parts of a request a template can name.
struct Parts<'a> {
    method: &'a str,
    path: &'a str,
    query: String,
    headers: Vec<(String, String)>,
    /// The body the server will read: without chunk framing.
    body: std::borrow::Cow<'a, [u8]>,
    host: String,
    nonce: &'a str,
    now: std::time::Duration,
}

impl<'a> Parts<'a> {
    fn new(raw: &'a [u8], target: &Target, mark: &str, stamp: &'a Stamp) -> Self {
        let (head, body) = split_head_body(raw);
        let line_end = head.iter().position(|&b| b == b'\n').unwrap_or(head.len());
        let line = std::str::from_utf8(&head[..line_end]).unwrap_or_default().trim_end();
        let mut words = line.split(' ');
        let method = words.next().unwrap_or_default();
        let uri = words.next().unwrap_or_default();
        // The origin of an absolute-form target isn't part of the path.
        let uri = match uri.find("://").filter(|_| !uri.starts_with('/')) {
            Some(i) => uri[i + 3..].find('/').map_or("/", |j| &uri[i + 3 + j..]),
            None => uri,
        };
        let (path, query) = uri.split_once('?').unwrap_or((uri, ""));
        // A signature in the query can't cover itself.
        let query = query.split('&').filter(|p| !p.contains(mark)).collect::<Vec<_>>().join("&");
        let headers = RawRequest::from_bytes(head.to_vec()).head().map(|h| h.headers).unwrap_or_default();
        let host = headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case("host"))
            .map_or_else(|| target.host.clone(), |(_, v)| v.clone());
        let chunked = headers
            .iter()
            .any(|(k, v)| k.eq_ignore_ascii_case("transfer-encoding") && v.to_ascii_lowercase().contains("chunked"));
        let body = if chunked { crate::http::response::dechunk(body).into() } else { body.into() };
        Parts { method, path, query, headers, body, host, nonce: &stamp.nonce, now: stamp.now }
    }

    fn get(&self, var: &str) -> Option<Vec<u8>> {
        if let Some(name) = var.strip_prefix("header:") {
            let found = self.headers.iter().find(|(k, _)| k.eq_ignore_ascii_case(name.trim()));
            return Some(found.map(|(_, v)| v.clone().into_bytes()).unwrap_or_default());
        }
        Some(match var {
            "method" => self.method.as_bytes().to_vec(),
            "host" => self.host.clone().into_bytes(),
            "path" => self.path.as_bytes().to_vec(),
            "query" => self.query.clone().into_bytes(),
            "body" => self.body.to_vec(),
            "body_sha256" => hex::encode(Sha256::digest(&*self.body)).into_bytes(),
            "body_sha256_base64" => STANDARD.encode(Sha256::digest(&*self.body)).into_bytes(),
            "timestamp" => self.now.as_secs().to_string().into_bytes(),
            "timestamp_ms" => self.now.as_millis().to_string().into_bytes(),
            "nonce" => self.nonce.as_bytes().to_vec(),
            _ => return None,
        })
    }
}

fn check_vars(tpl: &str, refused: &[&str]) -> std::result::Result<(), String> {
    let mut rest = tpl;
    while let Some(i) = rest.find("{{") {
        let after = &rest[i + 2..];
        let end = after.find("}}").ok_or_else(|| format!("unclosed {{{{ in {tpl:?}"))?;
        let var = after[..end].trim();
        if refused.contains(&var) {
            return Err(format!("{{{{{var}}}}} can't be used here"));
        }
        if !VARS.contains(&var) && !var.strip_prefix("header:").is_some_and(|n| valid_token(n.trim())) {
            return Err(format!("unknown {{{{{var}}}}}; one of {}, header:NAME", VARS.join(", ")));
        }
        rest = &after[end + 2..];
    }
    Ok(())
}

/// How a template is read.
#[derive(Clone, Copy, PartialEq)]
enum Mode {
    /// A header value: as written.
    Plain,
    /// The escapes `\n`, `\r`, `\t` and `\\` are read, in the template only, never in
    /// a request's values.
    Canonical,
    /// JSON: values are escaped for a JSON string.
    Json,
}

/// Fills a checked template.
fn render(tpl: &str, value: &dyn Fn(&str) -> Option<Vec<u8>>, mode: Mode) -> Vec<u8> {
    let mut out = Vec::with_capacity(tpl.len());
    let text = |out: &mut Vec<u8>, s: &str| {
        if mode != Mode::Canonical {
            return out.extend_from_slice(s.as_bytes());
        }
        let mut chars = s.chars();
        while let Some(c) = chars.next() {
            let c = match (c, chars.as_str().chars().next()) {
                ('\\', Some(e @ ('n' | 'r' | 't' | '\\'))) => {
                    chars.next();
                    match e {
                        'n' => '\n',
                        'r' => '\r',
                        't' => '\t',
                        _ => '\\',
                    }
                }
                _ => c,
            };
            out.extend_from_slice(c.encode_utf8(&mut [0; 4]).as_bytes());
        }
    };
    let mut rest = tpl;
    while let Some(i) = rest.find("{{") {
        text(&mut out, &rest[..i]);
        let after = &rest[i + 2..];
        let Some(end) = after.find("}}") else {
            rest = &rest[i..];
            break;
        };
        let v = value(after[..end].trim()).unwrap_or_default();
        if mode == Mode::Json {
            out.extend_from_slice(crate::auth::encode(&String::from_utf8_lossy(&v), crate::auth::Enc::Json).as_bytes());
        } else {
            out.extend_from_slice(&v);
        }
        rest = &after[end + 2..];
    }
    text(&mut out, rest);
    out
}

fn claims_object(text: &[u8]) -> Result<Map<String, Value>> {
    match serde_json::from_slice(text) {
        Ok(Value::Object(m)) => Ok(m),
        Ok(_) => Err(Error::InvalidInput("JWT claims must be a JSON object".into())),
        // The error's position, not the claims: they can hold request values.
        Err(e) => Err(Error::InvalidInput(format!("JWT claims are not JSON (column {})", e.column()))),
    }
}

fn valid_token(name: &str) -> bool {
    !name.is_empty() && name.bytes().all(|b| b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b))
}

fn replace(raw: &[u8], mark: &[u8], trailing: usize, value: &[u8]) -> Vec<u8> {
    let Some(at) = find(raw, mark) else { return raw.to_vec() };
    let mut out = raw.to_vec();
    out.splice(at..at + mark.len() + trailing, value.iter().copied());
    out
}

/// The request with the query parameter `name` set to what `value` makes of its old
/// value, and no other parameter of that name.
pub(crate) fn set_query(raw: &[u8], name: &str, value: impl Fn(Option<&str>) -> String) -> Vec<u8> {
    let (head, body) = split_head_body(raw);
    let line_end = head.iter().position(|&b| b == b'\n').unwrap_or(head.len());
    let line = String::from_utf8_lossy(&head[..line_end]);
    let mut words: Vec<&str> = line.trim_end().split(' ').collect();
    let Some(uri) = words.get(1).copied() else { return raw.to_vec() };
    let (path, query) = uri.split_once('?').unwrap_or((uri, ""));
    // By decoded name: `%73ig=old` is the same parameter to the server.
    let named = |p: &str| {
        let key = p.split('=').next().unwrap_or_default();
        percent_encoding::percent_decode_str(key).decode_utf8_lossy() == name
    };
    let old = query.split('&').find(|p| named(p)).and_then(|p| p.split_once('=')).map(|(_, v)| v);
    let mut params: Vec<String> = query.split('&').filter(|p| !p.is_empty() && !named(p)).map(str::to_string).collect();
    params.push(format!("{name}={}", value(old)));
    let uri = format!("{path}?{}", params.join("&"));
    words[1] = &uri;
    let mut out = words.join(" ").into_bytes();
    out.extend_from_slice(if head[..line_end].ends_with(b"\r") { b"\r" } else { b"" });
    out.extend_from_slice(&head[line_end..]);
    out.extend_from_slice(body);
    out
}

fn nonce() -> Result<String> {
    use rand::SecureRandom;
    let mut b = [0u8; 16];
    rand::SystemRandom::new().fill(&mut b).map_err(|_| Error::InvalidInput("no random bytes for a nonce".into()))?;
    Ok(hex::encode(b))
}

fn encode_output(output: Output, bytes: &[u8]) -> String {
    match output {
        Output::Hex => hex::encode(bytes),
        Output::Base64 => STANDARD.encode(bytes),
        Output::Base64url => URL_SAFE_NO_PAD.encode(bytes),
    }
}

/// HMAC of `data`.
pub fn hmac_digest(alg: HmacAlg, key: &[u8], data: &[u8]) -> Vec<u8> {
    let alg = match alg {
        HmacAlg::Sha1 => hmac::HMAC_SHA1_FOR_LEGACY_USE_ONLY,
        HmacAlg::Sha256 => hmac::HMAC_SHA256,
        HmacAlg::Sha384 => hmac::HMAC_SHA384,
        HmacAlg::Sha512 => hmac::HMAC_SHA512,
    };
    hmac::sign(&hmac::Key::new(alg, key), data).as_ref().to_vec()
}

/// A signed compact JWT of the given header and payload JSON. For RS256 `key` is a PEM
/// RSA private key (PKCS#8 or PKCS#1). Errors never quote the key.
pub fn jwt_token(alg: JwtAlg, key: &[u8], header: &[u8], payload: &[u8]) -> Result<String> {
    let input = format!("{}.{}", URL_SAFE_NO_PAD.encode(header), URL_SAFE_NO_PAD.encode(payload));
    let sig = match alg {
        JwtAlg::HS256 => hmac_digest(HmacAlg::Sha256, key, input.as_bytes()),
        JwtAlg::HS384 => hmac_digest(HmacAlg::Sha384, key, input.as_bytes()),
        JwtAlg::HS512 => hmac_digest(HmacAlg::Sha512, key, input.as_bytes()),
        JwtAlg::RS256 => {
            let bad = || {
                Error::InvalidInput(
                    "the RS256 key must be an unencrypted PEM RSA private key of 2048 bits or more".into(),
                )
            };
            let pem = pem::parse(key).map_err(|_| bad())?;
            let pair = match pem.tag() {
                "PRIVATE KEY" => signature::RsaKeyPair::from_pkcs8(pem.contents()),
                "RSA PRIVATE KEY" => signature::RsaKeyPair::from_der(pem.contents()),
                _ => return Err(bad()),
            }
            .map_err(|_| bad())?;
            let mut sig = vec![0; pair.public().modulus_len()];
            pair.sign(&signature::RSA_PKCS1_SHA256, &rand::SystemRandom::new(), input.as_bytes(), &mut sig)
                .map_err(|_| bad())?;
            sig
        }
    };
    Ok(format!("{input}.{}", URL_SAFE_NO_PAD.encode(sig)))
}

/// `{"alg":ALG,"typ":"JWT"}` over the claims JSON: the check DSL's `generate_jwt`. Like
/// Nuclei's, `expires` is a unix time: one still ahead sets `exp` and `iat`, unless the
/// claims have an `exp`.
pub(crate) fn generate_jwt(claims: &str, alg: JwtAlg, key: &[u8], expires: Option<u64>) -> Result<String> {
    let mut payload = claims_object(claims.as_bytes())?;
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_secs();
    if let Some(at) = expires.filter(|at| *at > now + 1 && !payload.contains_key("exp")) {
        payload.insert("exp".into(), at.into());
        payload.insert("iat".into(), now.into());
    }
    let header = serde_json::json!({"alg": alg.name(), "typ": "JWT"}).to_string();
    let payload = serde_json::to_vec(&payload).map_err(|e| Error::InvalidInput(e.to_string()))?;
    jwt_token(alg, key, header.as_bytes(), &payload)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A throwaway key made for this test, used nowhere else.
    const TEST_RSA_KEY: &str = "-----BEGIN PRIVATE KEY-----
MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQDn0QX9AjDtonr4
xsvYUVkcc2BTmFzRFbrELqv0SYW14Lo36K7jsRR+CUI6vQRW46YRuapkZJ3IDrUf
LSgbU2mpDzMsgGJkYgzJf930lAhmBGLStc8F5TncIkeHdYVwvAX7njyZ2lmxxZ1K
Ohhq6ct5x986W2CdfujXSlFwjVEc3OwlDGmeIN/1Y4A9E+zWh8ZtptxB+N97c/Pp
beaJoDDm9ohz/K2GHz5fB1kvF8hopkbzeNzFSQoAT/Pn0tdGL8fybp8YzkR3uKhA
Ipp4nOdOpkl8DeeKnPILi7HykOZtICW+oa9vD0SoTBKNcEror+k5lQBPv2V/T88O
ts4fLF4rAgMBAAECggEATqGyHE4f9ptEhxo3jtqZFXN1WyW1Zh6uyVjjbut5dWYT
BF/i4szwHIhbdL0kuaxiamTGDWOruW5ztW2Fyy8SCgxj2VZ7CX3QxJCg4xNLff9C
3iJZZLCKXccq6CHO75x3kw/rkmxkPE7BuanXGnzPTjGj4JGaRhIEPPKyiTEGMHmC
RB4CyNu1sLA2BlhcLvvaraPhYkvK+4LFrMPAnZWKI7o1xcTzz2FpTkhLO3YMagA2
ig8ovAcnfhM8kWoH8DIo5kWvHhcnpmh6wAbhy+T2ItEytLiLVaMCBuZPDhSa6VGg
rQ/N+A5lbeNs9pKAw44ToFS0kJOl4QHYRzx6TtqGsQKBgQD0iPT9hWKXpXFPsbG0
GcFmNVUR7a1QzxoGRukEPuDM0+k3Tdori7hJ23a6G+MrwLVyn0rUcToWQ9cJyPYZ
iiF5+yDFSf8lmw2CPlnhBT90usGUz9F0fheRSBwn3hehXvqIUdCvWTaM2ZubT7gH
m/CE4cROVnWb+0eKBEBTJuERjQKBgQDyr2l/aRKwLochA7ibvHmdQq1sMhopgIBU
9iGxSaPqwCfymmREzS0o+/Udhe+WLvhDM5HvmfYs3ULrlkyLrv7iMdJQhF3gIMXC
kn98IXRo+dclOxa+2E28l8NmMRVSnzgKYZglSJTq+yd2RhYmElQ187bvaIHLrFdk
g1lH9jwUlwKBgGiJ2Do9eJ2dw6gvLenxjMVWDW0hr5M5RkXisKD5BH9sJGpZJOiy
zXD9mm8Llv1QYAGFaacSVKPKErcDK3pVm+Qa4LKW5LW96HOClkflR3Bumm00vrVP
ZmHccvT0NCPvh6kZWN5thC2IpcYquWC/YH5eSd63hYXOUZIGKT2jBFrNAoGAVv+3
LCu4vVwQqS8yUPIiDtRGY1Eau+ILH2oU7f9eOduk9n2OkHOVSun4FxtaplY0PbMR
D/n7nF29jcMVscWMLf56TM8G8EAPZQ8rkI5VswRNslUadFQKmh81tz7FTBcz+dS+
vC7m484heW7qpb9QXP7/h5fJYABqW+gSa4/EPgUCgYAAmkgKubHlLLr1urOgUNjt
ghbbW733XrWSZ5ErOjH7JNdZWHCbqNbk58wwSISs9J6G9UkiiAehZq+snu4il0UA
86wNAlWTsrL29Oo6nDnNqDgaEuPPbF4t5kMiV4IyrBE25GJKy1A9UR3aqtsON1Hr
31kRVm5D9jVfYvh6toP7pA==
-----END PRIVATE KEY-----
";

    fn hmac_signer(canonical: &str, to: Place) -> Signer {
        Signer {
            name: "s".into(),
            key: KeySource::Env("UNUSED".into()),
            key_encoding: KeyEncoding::Raw,
            origins: vec!["https://a.test".into()],
            to,
            format: None,
            headers: vec![],
            kind: SignKind::Hmac { alg: HmacAlg::Sha256, canonical: canonical.into(), output: Output::Hex },
        }
    }

    fn applied(l: &Loaded, raw: Vec<u8>, target: &Target) -> Result<Vec<u8>> {
        let stamp = Stamp::new()?;
        l.sign(l.set_headers(raw, target, &stamp)?, target, &stamp)
    }

    fn signed(s: &Signer, raw: &[u8], key: &[u8]) -> Result<String> {
        let loaded = Loaded { profile: "p".into(), signer: s.clone(), key: Ok(key.to_vec()).into() };
        let target = Target::from_url("https://a.test").unwrap();
        Ok(String::from_utf8(applied(&loaded, s.place(raw, "p", &[]), &target)?).unwrap())
    }

    #[test]
    fn hmac_matches_published_vectors() {
        // RFC 2202 and RFC 4231, test case 2.
        let (key, data) = (b"Jefe", b"what do ya want for nothing?");
        let hex_of = |alg| hex::encode(hmac_digest(alg, key, data));
        assert_eq!(hex_of(HmacAlg::Sha1), "effcdf6ae5eb2fa2d27416d5f184df9c259a7c79");
        assert_eq!(hex_of(HmacAlg::Sha256), "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843");
        assert_eq!(
            hex_of(HmacAlg::Sha384),
            "af45d2e376484031617f78d2b58a6b1b9c7ef464f5a01b47e42ec3736322445e8e2240ca5e69e2c78b3239ecfab21649"
        );
        assert_eq!(
            hex_of(HmacAlg::Sha512),
            "164b7a7bfcf819e2e395fbe73b56e0a387bd64222e831fd610270cd7ea2505549758bf75c05a994a6d034f65f8f0e6fdcaeab1a34d4a6b4b636e070a38bce737"
        );
    }

    #[test]
    fn jwt_matches_published_vectors() {
        // RFC 7515 appendix A.1, whose header has a line break in it.
        let key = URL_SAFE_NO_PAD
            .decode("AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow")
            .unwrap();
        let token = jwt_token(
            JwtAlg::HS256,
            &key,
            b"{\"typ\":\"JWT\",\r\n \"alg\":\"HS256\"}",
            b"{\"iss\":\"joe\",\r\n \"exp\":1300819380,\r\n \"http://example.com/is_root\":true}",
        )
        .unwrap();
        assert_eq!(
            token,
            "eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9.\
             eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.\
             dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
        );
        // The example on jwt.io.
        let token = jwt_token(
            JwtAlg::HS256,
            b"your-256-bit-secret",
            br#"{"alg":"HS256","typ":"JWT"}"#,
            br#"{"sub":"1234567890","name":"John Doe","iat":1516239022}"#,
        )
        .unwrap();
        assert!(token.ends_with(".SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"), "{token}");
    }

    #[test]
    fn rs256_verifies_and_a_bad_key_says_nothing_of_itself() {
        let token = jwt_token(JwtAlg::RS256, TEST_RSA_KEY.as_bytes(), b"{\"alg\":\"RS256\"}", b"{}").unwrap();
        let (input, sig) = token.rsplit_once('.').unwrap();
        let pem = pem::parse(TEST_RSA_KEY).unwrap();
        let pair = signature::RsaKeyPair::from_pkcs8(pem.contents()).unwrap();
        signature::UnparsedPublicKey::new(&signature::RSA_PKCS1_2048_8192_SHA256, pair.public().as_ref())
            .verify(input.as_bytes(), &URL_SAFE_NO_PAD.decode(sig).unwrap())
            .unwrap();
        let e = jwt_token(JwtAlg::RS256, b"hunter2-not-a-pem", b"{}", b"{}").unwrap_err().to_string();
        assert!(!e.contains("hunter2"), "{e}");
    }

    #[test]
    fn hmac_covers_the_request_as_sent() {
        let mut s = hmac_signer(r"{{method}}\n{{path}}\n{{query}}\n{{body_sha256}}", Place::Header("X-Sig".into()));
        s.format = Some("v1={{signature}}".into());
        let raw = b"POST /a/b?x=1&y=2 HTTP/1.1\r\nHost: a.test\r\nContent-Length: 3\r\n\r\nabc";
        let out = signed(&s, raw, b"k").unwrap();
        let body_hash = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
        let text = format!("POST\n/a/b\nx=1&y=2\n{body_hash}");
        let want = hex::encode(hmac_digest(HmacAlg::Sha256, b"k", text.as_bytes()));
        assert!(out.contains(&format!("X-Sig: v1={want}\r\n")), "{out}");
        assert!(out.contains("Content-Length: 3\r\n") && out.ends_with("\r\n\r\nabc"), "{out}");
    }

    #[test]
    fn a_url_in_the_query_is_not_the_origin() {
        let s = hmac_signer(r"{{path}}\n{{query}}", Place::Header("X-Sig".into()));
        let want = hex::encode(hmac_digest(HmacAlg::Sha256, b"k", b"/a\nnext=https://b.test/c"));
        for target in ["/a?next=https://b.test/c", "https://a.test/a?next=https://b.test/c"] {
            let raw = format!("GET {target} HTTP/1.1\r\nHost: a.test\r\n\r\n");
            let out = signed(&s, raw.as_bytes(), b"k").unwrap();
            assert!(out.contains(&format!("X-Sig: {want}\r\n")), "{out}");
        }
    }

    #[test]
    fn a_query_signature_leaves_itself_out_and_is_url_encoded() {
        let mut s = hmac_signer("{{path}}?{{query}}", Place::Query("sig".into()));
        s.kind =
            SignKind::Hmac { alg: HmacAlg::Sha256, canonical: "{{path}}?{{query}}".into(), output: Output::Base64 };
        let out = signed(&s, b"GET /a?sig=old&x=1 HTTP/1.1\r\nHost: a.test\r\n\r\n", b"k").unwrap();
        let want = STANDARD.encode(hmac_digest(HmacAlg::Sha256, b"k", b"/a?x=1"));
        let want: String = url::form_urlencoded::byte_serialize(want.as_bytes()).collect();
        assert!(out.starts_with(&format!("GET /a?x=1&sig={want} HTTP/1.1\r\n")), "{out}");
    }

    #[test]
    fn a_parameter_with_an_encoded_name_is_replaced_too() {
        let s = hmac_signer("{{query}}", Place::Query("sig".into()));
        let out = signed(&s, b"GET /a?%73ig=old&x=1 HTTP/1.1\r\nHost: a.test\r\n\r\n", b"k").unwrap();
        let want = hex::encode(hmac_digest(HmacAlg::Sha256, b"k", b"x=1"));
        assert!(out.starts_with(&format!("GET /a?x=1&sig={want} HTTP/1.1\r\n")), "{out}");
    }

    #[test]
    fn a_chunked_body_is_hashed_without_its_framing() {
        let s = hmac_signer("{{body_sha256}}", Place::Header("X-Sig".into()));
        let raw = b"POST / HTTP/1.1\r\nHost: a.test\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n0\r\n\r\n";
        let out = signed(&s, raw, b"k").unwrap();
        let body_hash = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
        let want = hex::encode(hmac_digest(HmacAlg::Sha256, b"k", body_hash.as_bytes()));
        assert!(out.contains(&format!("X-Sig: {want}\r\n")), "{out}");
    }

    #[test]
    fn escapes_are_only_read_in_a_canonical_string() {
        let mut s = hmac_signer("{{path}}", Place::Header("X-Sig".into()));
        s.headers = vec![("X-Test".into(), r"ok\r\nHost: other.test".into())];
        assert!(s.validate().is_ok());
        let out = signed(&s, b"GET / HTTP/1.1\r\nHost: a.test\r\n\r\n", b"k").unwrap();
        assert!(out.contains("X-Test: ok\\r\\nHost: other.test\r\n"), "{out}");
        assert_eq!(out.matches("\r\nHost:").count(), 1, "{out}");
    }

    #[test]
    fn headers_set_before_signing_are_covered() {
        let mut s = hmac_signer("{{header:X-Ts}}.{{timestamp}}", Place::Header("X-Sig".into()));
        s.headers = vec![("X-Ts".into(), "{{timestamp}}".into())];
        let out = signed(&s, b"GET / HTTP/1.1\r\nHost: a.test\r\n\r\n", b"k").unwrap();
        let line = |name: &str| out.lines().find_map(|l| l.strip_prefix(name)).unwrap().to_string();
        let ts = line("X-Ts: ");
        assert!(ts.parse::<u64>().is_ok(), "{out}");
        let want = hex::encode(hmac_digest(HmacAlg::Sha256, b"k", format!("{ts}.{ts}").as_bytes()));
        assert_eq!(line("X-Sig: "), want);
    }

    fn jwt_signer(claims: &str, ttl: Option<u64>, resign: bool) -> Signer {
        let mut s = hmac_signer("", Place::Header("Authorization".into()));
        s.format = Some("Bearer {{signature}}".into());
        s.kind = SignKind::Jwt { alg: JwtAlg::HS256, claims: claims.into(), ttl, kid: Some("k1".into()), resign };
        s
    }

    fn bearer(out: &str) -> serde_json::Value {
        let token = out.lines().find_map(|l| l.strip_prefix("Authorization: Bearer ")).unwrap();
        crate::codec::decode_jwt(token).unwrap()
    }

    #[test]
    fn jwt_claims_are_templated_and_escaped() {
        let s = jwt_signer(r#"{"sub":"admin","path":"{{path}}","x":"{{header:X-Q}}"}"#, Some(60), false);
        let out = signed(&s, b"GET /p HTTP/1.1\r\nHost: a.test\r\nX-Q: a\"b\r\n\r\n", b"k").unwrap();
        let v = bearer(&out);
        assert_eq!((v["header"]["alg"].as_str(), v["header"]["kid"].as_str()), (Some("HS256"), Some("k1")));
        assert_eq!((v["payload"]["sub"].as_str(), v["payload"]["path"].as_str()), (Some("admin"), Some("/p")));
        assert_eq!(v["payload"]["x"], "a\"b");
        let (iat, exp) = (v["payload"]["iat"].as_u64().unwrap(), v["payload"]["exp"].as_u64().unwrap());
        assert_eq!(exp - iat, 60);
    }

    #[test]
    fn resigning_keeps_the_old_claims_under_the_new() {
        let old = jwt_token(JwtAlg::HS256, b"old", br#"{"alg":"HS256","cty":"x"}"#, br#"{"sub":"bob","exp":1,"n":1}"#);
        let raw = format!("GET / HTTP/1.1\r\nHost: a.test\r\nAuthorization: Bearer {}\r\n\r\n", old.unwrap());
        let out = signed(&jwt_signer(r#"{"sub":"admin"}"#, Some(60), true), raw.as_bytes(), b"k").unwrap();
        let v = bearer(&out);
        assert_eq!((v["payload"]["sub"].as_str(), v["payload"]["n"].as_u64()), (Some("admin"), Some(1)));
        assert!(v["payload"]["exp"].as_u64().unwrap() > 1, "{v}");
        assert_eq!(v["header"]["cty"], "x");
        assert_eq!(out.matches("Bearer ").count(), 1, "{out}");
    }

    #[test]
    fn placing_a_re_signer_twice_keeps_one_token() {
        let old = jwt_token(JwtAlg::HS256, b"old", br#"{"alg":"HS256"}"#, br#"{"n":1}"#).unwrap();
        let raw = format!("GET / HTTP/1.1\r\nHost: a.test\r\nAuthorization: Bearer {old}\r\n\r\n");
        let s = jwt_signer("{}", None, true);
        let once = s.place(raw.as_bytes(), "p", &[]);
        assert_eq!(s.place(&once, "p", &[]), once);
        let out = signed(&s, &once, b"k").unwrap();
        assert_eq!(bearer(&out)["payload"]["n"], 1, "{out}");
        // With no token to start from, it signs the claims alone.
        let bare = s.place(b"GET / HTTP/1.1\r\nHost: a.test\r\n\r\n", "p", &[]);
        assert_eq!(s.place(&bare, "p", &[]), bare);
    }

    #[test]
    fn text_after_the_signature_in_a_wrap_stays() {
        let mut s = hmac_signer("{{path}}", Place::Header("X-Sig".into()));
        s.format = Some("{{signature}}-v1".into());
        let out = signed(&s, b"GET / HTTP/1.1\r\nHost: a.test\r\n\r\n", b"k").unwrap();
        let want = hex::encode(hmac_digest(HmacAlg::Sha256, b"k", b"/"));
        assert!(out.contains(&format!("X-Sig: {want}-v1\r\n")), "{out}");
        let old = jwt_token(JwtAlg::HS256, b"old", br#"{"alg":"HS256"}"#, br#"{"n":1}"#).unwrap();
        let mut s = jwt_signer("{}", None, true);
        s.format = Some("Bearer {{signature}}-v1".into());
        let raw = format!("GET / HTTP/1.1\r\nAuthorization: Bearer {old}-v1\r\n\r\n");
        let out = signed(&s, raw.as_bytes(), b"k").unwrap();
        let value = out.lines().find_map(|l| l.strip_prefix("Authorization: Bearer ")).unwrap();
        let token = value.strip_suffix("-v1").expect(&out);
        assert_eq!(crate::codec::decode_jwt(token).unwrap()["payload"]["n"], 1, "{out}");
    }

    #[test]
    fn a_signer_can_cover_the_headers_of_a_signer_after_it_but_not_an_unmade_signature() {
        let target = Target::from_url("https://a.test").unwrap();
        let load =
            |signer: &Signer| Loaded { profile: "p".into(), signer: signer.clone(), key: Ok(b"k".to_vec()).into() };
        let mut covers = hmac_signer("{{header:X-Time}}", Place::Header("X-Sig".into()));
        covers.name = "covers".into();
        let mut sets = hmac_signer("{{path}}", Place::Header("X-Other".into()));
        sets.name = "sets".into();
        sets.headers = vec![("X-Time".into(), "{{timestamp}}".into())];
        let raw = b"GET / HTTP/1.1\r\nHost: a.test\r\n\r\n".to_vec();
        let raw = covers.place(&sets.place(&raw, "p", &[]), "p", &[]);
        let (first, second) = (load(&covers), load(&sets));
        let stamp = Stamp::new().unwrap();
        let mut out = raw.clone();
        for l in [&first, &second] {
            out = l.set_headers(out, &target, &stamp).unwrap();
        }
        for l in [&first, &second] {
            out = l.sign(out, &target, &stamp).unwrap();
        }
        let text = String::from_utf8(out).unwrap();
        let line = |name: &str| text.lines().find_map(|l| l.strip_prefix(name)).unwrap().to_string();
        let want = hex::encode(hmac_digest(HmacAlg::Sha256, b"k", line("X-Time: ").as_bytes()));
        assert_eq!(line("X-Sig: "), want, "{text}");
        // A signature made later can't be covered: refused, not signed as a placeholder.
        let mut needs = hmac_signer("{{header:X-Other}}", Place::Header("X-Sig".into()));
        needs.name = "needs".into();
        let raw = needs.place(&sets.place(b"GET / HTTP/1.1\r\nHost: a.test\r\n\r\n", "p", &[]), "p", &[]);
        assert!(load(&needs).sign(raw, &target, &stamp).unwrap_err().to_string().contains("not computed yet"));
    }

    #[test]
    fn an_attacked_destination_is_left_alone() {
        let s = hmac_signer("{{path}}", Place::Header("X-Sig".into()));
        let out = s.place(b"GET / HTTP/1.1\r\nX-Sig: PAYLOAD\r\n\r\n", "p", &["x-sig"]);
        assert!(String::from_utf8(out).unwrap().contains("X-Sig: PAYLOAD\r\n"));
    }

    #[test]
    fn signing_stays_on_its_origins_and_needs_its_key() {
        let s = hmac_signer("{{path}}", Place::Header("X-Sig".into()));
        let raw = s.place(b"GET / HTTP/1.1\r\nHost: b.test\r\n\r\n", "p", &[]);
        let other = Target::from_url("https://b.test").unwrap();
        let loaded = Loaded { profile: "p".into(), signer: s.clone(), key: Ok(b"k".to_vec()).into() };
        assert!(applied(&loaded, raw.clone(), &other).is_err());
        let here = Target::from_url("https://a.test").unwrap();
        let loaded =
            Loaded { profile: "p".into(), signer: s, key: Err("environment variable K is not set".to_string()).into() };
        assert!(applied(&loaded, raw, &here).unwrap_err().to_string().contains("K is not set"));
    }

    #[test]
    fn signing_alone_checks_the_origin() {
        let s = hmac_signer("{{path}}", Place::Header("X-Sig".into()));
        let raw = s.place(b"GET / HTTP/1.1\r\nHost: b.test\r\n\r\n", "p", &[]);
        let loaded = Loaded { profile: "p".into(), signer: s, key: Ok(b"k".to_vec()).into() };
        let (other, stamp) = (Target::from_url("https://b.test").unwrap(), Stamp::new().unwrap());
        assert!(loaded.sign(raw, &other, &stamp).unwrap_err().to_string().contains("doesn't sign for"));
    }

    #[test]
    fn a_key_loads_when_first_needed_and_says_little() {
        let mut s = hmac_signer("{{path}}", Place::Header("X-Sig".into()));
        s.key = KeySource::File("/nonexistent/brainproxy-key".into());
        let loaded = Loaded::new("p", s.clone());
        let target = Target::from_url("https://a.test").unwrap();
        applied(&loaded, b"GET / HTTP/1.1\r\nHost: a.test\r\n\r\n".to_vec(), &target).unwrap();
        assert!(loaded.key.get().is_none(), "no placeholder, no read");
        let raw = s.place(b"GET / HTTP/1.1\r\nHost: a.test\r\n\r\n", "p", &[]);
        let e = applied(&loaded, raw, &target).unwrap_err().to_string();
        assert!(e.contains("can't be read") && !e.contains("NotFound") && !e.contains("not found"), "{e}");
    }

    #[test]
    fn a_query_signer_refuses_to_cover_a_query_signature_not_made_yet() {
        let mut first = hmac_signer("{{query}}", Place::Query("a".into()));
        first.name = "first".into();
        let mut second = hmac_signer("{{path}}", Place::Query("b".into()));
        second.name = "second".into();
        let raw = second.place(&first.place(b"GET /?x=1 HTTP/1.1\r\nHost: a.test\r\n\r\n", "p", &[]), "p", &[]);
        let loaded = Loaded { profile: "p".into(), signer: first, key: Ok(b"k".to_vec()).into() };
        let e = applied(&loaded, raw, &Target::from_url("https://a.test").unwrap()).unwrap_err().to_string();
        assert!(e.contains("not computed yet"), "{e}");
    }

    #[test]
    fn resigning_needs_a_jwt_when_the_destination_has_a_value() {
        let raw = b"GET / HTTP/1.1\r\nHost: a.test\r\nAuthorization: Bearer notajwt\r\n\r\n";
        let e = signed(&jwt_signer("{}", None, true), raw, b"k").unwrap_err().to_string();
        assert!(e.contains("no JWT to re-sign in header:Authorization"), "{e}");
    }

    #[test]
    fn generate_jwt_takes_a_unix_time_like_nuclei() {
        let now = Stamp::new().unwrap().now.as_secs();
        let claims = |json: &str, at| {
            let token = generate_jwt(json, JwtAlg::HS256, b"k", Some(at)).unwrap();
            crate::codec::decode_jwt(&token).unwrap()["payload"].clone()
        };
        let v = claims("{}", now + 600);
        assert_eq!(v["exp"], now + 600);
        assert!(v["iat"].as_u64().unwrap() >= now, "{v}");
        assert!(claims("{}", now.saturating_sub(5)).get("exp").is_none(), "a time gone by sets nothing");
        assert_eq!(claims(r#"{"exp":7}"#, now + 600)["exp"], 7, "the claims' own exp stays");
    }

    #[test]
    fn validation() {
        let good = hmac_signer("{{method}} {{header:X-A}}", Place::Header("X-Sig".into()));
        assert!(good.validate().is_ok());
        let bad = |f: &dyn Fn(&mut Signer)| {
            let mut s = good.clone();
            f(&mut s);
            s.validate().is_err()
        };
        assert!(bad(&|s| s.origins.clear()));
        assert!(bad(&|s| s.name = "a b".into()));
        assert!(bad(&|s| s.to = Place::Header("Content-Length".into())));
        assert!(bad(&|s| s.format = Some("no slot".into())));
        assert!(bad(&|s| s.format = Some("{{signature}}\r\nX: y".into())));
        assert!(bad(&|s| s.headers = vec![("X-B".into(), "{{body}}".into())]));
        assert!(bad(&|s| s.headers = vec![("Host".into(), "x".into())]));
        assert!(bad(&|s| {
            s.kind = SignKind::Hmac { alg: HmacAlg::Sha1, canonical: "{{env}}".into(), output: Output::Hex }
        }));
        assert!(!jwt_signer(r#"{"iat":{{timestamp}}}"#, None, false).validate().is_err());
        assert!(jwt_signer("[1]", None, false).validate().is_err());
        assert!(jwt_signer(r#"{"p":{{path}}}"#, None, false).validate().is_err(), "needs its quotes");
        assert!(jwt_signer(r#"{"p":"{{path}}"}"#, None, false).validate().is_ok());
        for name in ["a&b", "a+b", "a%62", "a#b", "a'b", "a=b", ""] {
            assert!(bad(&|s| s.to = Place::Query(name.into())), "{name}");
        }
        assert!(!bad(&|s| s.to = Place::Query("sig_1.v-2~".into())));
    }
}
