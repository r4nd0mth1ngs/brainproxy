//! Proof-of-concept pages, written from a recorded request: a CSRF page that sends the request
//! from a victim's browser, and a clickjacking page that frames a URL under a decoy.
//!
//! Nothing here sends anything, so the scope guard isn't involved. A page is meant to be
//! opened in a browser, and the requests it makes then go from that browser straight to the
//! target, outside brainproxy and its scope checks (unless the browser uses the proxy).
//!
//! Every recorded value is target-controlled text that lands in HTML: in attributes and text it
//! goes through [`escape_attr`] and [`escape_text`], and in a script only as JSON with `<`, `>`
//! and `&` written as `\u` escapes ([`js`]), so no value can close the script or start markup.

use base64::Engine as _;
use serde::Serialize;

use crate::error::{Error, Result};
use crate::http::{RawRequest, ResponseHead, Target};
use crate::scan::message::{url_decode, SetCookie};
use crate::scan::passive::rules::headers::anti_clickjacking::xfo_blocks;
use crate::scan::passive::rules::params::csrf_countermeasures::is_anti_csrf_token;

/// How a CSRF page sends its request.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Technique {
    /// An HTML form: no script needed unless it submits itself, and a top-level navigation,
    /// which SameSite=Lax cookies travel with for GET.
    #[default]
    Form,
    /// `fetch` with the visitor's cookies; `no-cors` for what a form could send too.
    Fetch,
}

#[derive(Clone, Debug, Default)]
pub struct CsrfOptions {
    pub technique: Technique,
    /// The page sends the request as soon as it opens.
    pub auto_submit: bool,
    /// Parameters (fields, query parameters, top-level JSON members) left out of the page.
    pub drop_params: Vec<String>,
    /// Set-Cookie values recorded from the request's host, oldest first: what the cookies the
    /// request carried were set with (SameSite).
    pub set_cookies: Vec<String>,
}

/// One parameter the page sends.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Field {
    pub name: String,
    /// The value as text (a file part's bytes as lossy UTF-8).
    pub value: String,
    /// A multipart file part's file name.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub filename: Option<String>,
    /// A file part's bytes and Content-Type, for the fetch technique.
    #[serde(skip)]
    file: Option<(Vec<u8>, String)>,
}

impl Field {
    fn new(name: impl Into<String>, value: impl Into<String>) -> Self {
        Self { name: name.into(), value: value.into(), filename: None, file: None }
    }
}

/// How the recorded request carried its parameters.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Encoding {
    /// A GET (or bodiless) request: the query string.
    Query,
    Urlencoded,
    Multipart,
    Json,
    /// Any other body: sent as text/plain.
    Text,
}

#[derive(Clone, Debug, Serialize)]
pub struct CsrfPoc {
    /// The method the page sends (POST for a form when the request used another).
    pub method: String,
    /// Where the page sends it.
    pub action: String,
    pub encoding: Encoding,
    pub technique: Technique,
    pub fields: Vec<Field>,
    pub auto_submit: bool,
    pub warnings: Vec<String>,
    pub html: String,
}

/// Headers a browser sets itself, or a form sends anyway: a recorded one isn't a reason the
/// page can't stand in for the request. Anything else the server may need (`Authorization`,
/// `X-Requested-With`, a token header) a cross-site page can only send after a CORS preflight.
const BROWSER_HEADERS: &[&str] = &[
    "accept",
    "accept-encoding",
    "accept-language",
    "cache-control",
    "connection",
    "content-length",
    "content-type",
    "cookie",
    "dnt",
    "host",
    "if-match",
    "if-modified-since",
    "if-none-match",
    "if-range",
    "if-unmodified-since",
    "keep-alive",
    "origin",
    "pragma",
    "priority",
    "range",
    "referer",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
    "upgrade-insecure-requests",
    "user-agent",
    "via",
];

fn is_browser_header(name: &str) -> bool {
    let n = name.to_ascii_lowercase();
    BROWSER_HEADERS.contains(&n.as_str()) || n.starts_with("sec-") || n.starts_with("proxy-") || n.starts_with(':')
}

/// Name parts that say a value is a credential or a secret: a recorded one ends up in the page.
const SECRET_WORDS: &[&str] = &[
    "apikey",
    "auth",
    "bearer",
    "credential",
    "credentials",
    "cvc",
    "cvv",
    "jwt",
    "otp",
    "pass",
    "passcode",
    "passphrase",
    "passwd",
    "password",
    "pin",
    "pwd",
    "secret",
    "session",
    "sessionid",
    "sessid",
    "sid",
    "ssn",
    "token",
];

/// The name looks like it holds a password, token or session: by its words (split at
/// punctuation and camelCase) or a long secret word anywhere in it (`newpassword`).
pub fn looks_secret(name: &str) -> bool {
    let lower = name.to_lowercase();
    if ["password", "passwd", "secret", "token", "session", "apikey", "api_key", "api-key"]
        .iter()
        .any(|w| lower.contains(w))
    {
        return true;
    }
    let mut words = Vec::new();
    let mut cur = String::new();
    let mut prev_lower = false;
    for c in name.chars() {
        if !c.is_alphanumeric() {
            words.push(std::mem::take(&mut cur));
            prev_lower = false;
            continue;
        }
        if c.is_uppercase() && prev_lower {
            words.push(std::mem::take(&mut cur));
        }
        prev_lower = c.is_lowercase() || c.is_ascii_digit();
        cur.extend(c.to_lowercase());
    }
    words.push(cur);
    words.iter().any(|w| SECRET_WORDS.contains(&w.as_str()))
}

/// Text escaped for an HTML attribute value in double quotes. CR and LF are written as
/// character references: the parser would turn a literal CR LF into LF.
pub fn escape_attr(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            '\r' => out.push_str("&#13;"),
            '\n' => out.push_str("&#10;"),
            '\t' => out.push_str("&#9;"),
            c => out.push(c),
        }
    }
    out
}

/// Text escaped for HTML element content.
pub fn escape_text(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            c => out.push(c),
        }
    }
    out
}

/// A value as a JavaScript literal inside `<script>`: JSON, with `<`, `>` and `&` (so `</script>`
/// and `<!--`) and the line separators written as `\u` escapes.
pub fn js<T: Serialize + ?Sized>(v: &T) -> String {
    let json = serde_json::to_string(v).expect("strings, numbers and lists of them always serialize as JSON");
    let mut out = String::with_capacity(json.len());
    for c in json.chars() {
        match c {
            '<' => out.push_str("\\u003c"),
            '>' => out.push_str("\\u003e"),
            '&' => out.push_str("\\u0026"),
            '\u{2028}' => out.push_str("\\u2028"),
            '\u{2029}' => out.push_str("\\u2029"),
            c => out.push(c),
        }
    }
    out
}

/// An http(s) URL, refused otherwise: a page must never get a `javascript:` or `data:` one.
fn web_url(url: &str) -> Result<url::Url> {
    let u = url::Url::parse(url).map_err(|e| Error::InvalidInput(format!("invalid URL {url:?}: {e}")))?;
    match u.scheme() {
        "http" | "https" => Ok(u),
        s => Err(Error::InvalidInput(format!("{url:?}: only http and https URLs make a page (not {s})"))),
    }
}

/// The URL a request goes to: its absolute request target, or `target` and the path.
fn request_url(target_line: &str, target: &Target) -> Result<url::Url> {
    let lower = target_line.to_ascii_lowercase();
    if lower.starts_with("http://") || lower.starts_with("https://") {
        return web_url(target_line);
    }
    if !target_line.starts_with('/') {
        return Err(Error::InvalidInput(format!(
            "request target {target_line:?} isn't a path or URL a browser can send to"
        )));
    }
    web_url(&format!("{}{target_line}", target.origin()))
}

fn header<'a>(headers: &'a [(String, String)], name: &str) -> Option<&'a str> {
    headers.iter().find(|(k, _)| k.eq_ignore_ascii_case(name)).map(|(_, v)| v.trim())
}

/// The cookies' names a Cookie header carries, each once.
pub fn cookie_names(cookie_header: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for pair in cookie_header.split(';') {
        let name = pair.split_once('=').map_or(pair, |(n, _)| n).trim();
        if !name.is_empty() && !out.iter().any(|n| n == name) {
            out.push(name.to_string());
        }
    }
    out
}

/// Where the page's request goes as far as SameSite is concerned.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Context {
    /// A cross-site top-level GET navigation (a GET form): Lax cookies go too.
    TopLevelGet,
    /// Any other cross-site request: a POST form, fetch, or a frame.
    Other,
}

/// What the SameSite attributes the cookies `names` were last set with mean for a cross-site
/// request in `ctx`.
fn samesite_warnings(names: &[String], set_cookies: &[String], ctx: Context, what: &str) -> Vec<String> {
    let (mut strict, mut lax, mut unset) = (Vec::new(), Vec::new(), Vec::new());
    for name in names {
        let Some(c) = set_cookies.iter().rev().map(|v| SetCookie::parse(v)).find(|c| &c.name == name) else {
            continue;
        };
        match c.attr("samesite").map(str::to_ascii_lowercase).as_deref() {
            Some("strict") => strict.push(name.as_str()),
            Some("lax") => lax.push(name.as_str()),
            Some("none") => {}
            _ => unset.push(name.as_str()),
        }
    }
    let mut out = Vec::new();
    if !strict.is_empty() {
        out.push(format!(
            "cookie {} is SameSite=Strict: no cross-site request carries it, so {what} arrives without it",
            strict.join(", ")
        ));
    }
    if ctx == Context::Other && !lax.is_empty() {
        out.push(format!(
            "cookie {} is SameSite=Lax: only a top-level GET navigation carries it cross-site, so {what} arrives \
             without it",
            lax.join(", ")
        ));
    }
    if ctx == Context::Other && !unset.is_empty() {
        out.push(format!(
            "cookie {} was set without SameSite: Chromium-based browsers treat it as Lax (a POST within two minutes \
             of it being set aside), so there {what} arrives without it; Firefox and Safari send it",
            unset.join(", ")
        ));
    }
    out
}

/// The request's body split into one text/plain form field, `name=value`, whose encoding
/// (`name` `=` `value` CR LF) is the body again. A body with an `=` is split at it, so it comes
/// out byte for byte; a JSON object without one gains a member to hold the `=`, and any other
/// body ends in `=`. The second value is a warning when the body changes.
fn text_plain_field(body: &str, json: bool) -> (Field, Option<String>) {
    if let Some((name, value)) = body.split_once('=') {
        return (Field::new(name, value), None);
    }
    let trimmed = body.trim_end();
    if json && trimmed.ends_with('}') {
        if let Ok(serde_json::Value::Object(o)) = serde_json::from_str::<serde_json::Value>(trimmed) {
            let open = &trimmed[..trimmed.len() - 1];
            let sep = if o.is_empty() { "" } else { "," };
            let key = (0..).map(|i| format!("_{}", "_".repeat(i))).find(|k| !o.contains_key(k)).unwrap_or_default();
            let name = format!("{open}{sep}\"{key}\":\"");
            return (
                Field::new(name, "\"}"),
                Some(format!(
                    "a text/plain form always sends an '=': the JSON body gains the member \"{key}\": \"=\" to hold \
                     it; the server must ignore it (or use --technique fetch, which sends the body as recorded)"
                )),
            );
        }
    }
    (
        Field::new(body, ""),
        Some(
            "a text/plain form always sends an '=': the body ends in '=' (or use --technique fetch, which sends the \
             body as recorded)"
                .into(),
        ),
    )
}

/// The page that sends `request` (as recorded for `target`) from a victim's browser.
pub fn csrf(request: &RawRequest, target: &Target, opts: &CsrfOptions) -> Result<CsrfPoc> {
    let head = request.head()?;
    let recorded_method = head.method.to_ascii_uppercase();
    let mut url = request_url(&head.target, target)?;
    url.set_fragment(None);
    let raw_body = request.body();
    let body_bytes = crate::capture::decode_body(&head.headers, raw_body);
    let ctype = header(&head.headers, "content-type").unwrap_or("").to_string();
    let lower_ct = ctype.to_ascii_lowercase();
    let mut warnings = Vec::new();

    let looks_json = |b: &[u8]| serde_json::from_slice::<serde_json::Value>(b).is_ok();
    let encoding = if body_bytes.is_empty() && lower_ct.is_empty() {
        if recorded_method == "GET" || recorded_method == "HEAD" {
            Encoding::Query
        } else {
            Encoding::Urlencoded
        }
    } else if lower_ct.starts_with("application/x-www-form-urlencoded") {
        Encoding::Urlencoded
    } else if lower_ct.starts_with("multipart/form-data") {
        Encoding::Multipart
    } else if lower_ct.contains("json") || (lower_ct.is_empty() && looks_json(&body_bytes)) {
        Encoding::Json
    } else if body_bytes.is_empty() && (recorded_method == "GET" || recorded_method == "HEAD") {
        Encoding::Query
    } else {
        Encoding::Text
    };

    let body_text = match std::str::from_utf8(&body_bytes) {
        Ok(s) => s.to_string(),
        Err(_) if encoding != Encoding::Multipart => {
            warnings.push("the body isn't UTF-8 text: bytes that aren't are written as U+FFFD".into());
            String::from_utf8_lossy(&body_bytes).into_owned()
        }
        Err(_) => String::new(),
    };

    let mut fields: Vec<Field> = match encoding {
        Encoding::Query => {
            let q: Vec<Field> = url.query_pairs().map(|(k, v)| Field::new(k.into_owned(), v.into_owned())).collect();
            if opts.technique == Technique::Form {
                // A GET form replaces the action's query with its fields.
                url.set_query(None);
            }
            q
        }
        Encoding::Urlencoded => body_text
            .split('&')
            .filter(|p| !p.is_empty())
            .map(|p| {
                let (k, v) = p.split_once('=').unwrap_or((p, ""));
                Field::new(url_decode(k), url_decode(v))
            })
            .collect(),
        Encoding::Multipart => {
            let (h, _) = request.split();
            let rebuilt = [h, &body_bytes].concat();
            let parts = crate::scan::active::points::multipart_parts(&rebuilt);
            if parts.is_empty() && !body_bytes.is_empty() {
                warnings.push("the multipart body has no parts this could read (a boundary missing?)".into());
            }
            parts
                .into_iter()
                .map(|p| {
                    let value = &rebuilt[p.value.clone()];
                    let mut f = Field::new(p.name, String::from_utf8_lossy(value).into_owned());
                    if let Some(r) = p.filename {
                        let part = &rebuilt[p.span.clone()];
                        let (part_head, _) = crate::http::request::split_head_body(part);
                        let ct = String::from_utf8_lossy(part_head)
                            .lines()
                            .find_map(|l| {
                                let (k, v) = l.split_once(':')?;
                                k.trim().eq_ignore_ascii_case("content-type").then(|| v.trim().to_string())
                            })
                            .unwrap_or_else(|| "application/octet-stream".into());
                        f.filename = Some(String::from_utf8_lossy(&rebuilt[r]).into_owned());
                        f.file = Some((value.to_vec(), ct));
                    }
                    f
                })
                .collect()
        }
        Encoding::Json | Encoding::Text => Vec::new(),
    };

    // --drop-param, then what is left becomes the page's fields (or body).
    let mut json_body = body_text.clone();
    for name in &opts.drop_params {
        let before = fields.len();
        fields.retain(|f| &f.name != name);
        let mut hit = fields.len() != before;
        if encoding == Encoding::Json {
            if let Ok(serde_json::Value::Object(mut o)) = serde_json::from_str::<serde_json::Value>(&json_body) {
                if o.shift_remove(name).is_some() {
                    hit = true;
                    json_body = serde_json::Value::Object(o).to_string();
                }
            }
        }
        if !hit {
            warnings.push(format!("--drop-param {name}: the request has no such parameter"));
        }
    }

    let json_like = matches!(encoding, Encoding::Json | Encoding::Text);
    if json_like {
        if opts.technique == Technique::Form {
            let (f, w) = text_plain_field(&json_body, encoding == Encoding::Json);
            warnings.extend(w);
            fields = vec![f];
        } else {
            fields = vec![Field::new("", json_body.clone())];
        }
        let what = if encoding == Encoding::Json { "JSON body" } else { "body" };
        let sent_as = if ctype.is_empty() { String::new() } else { format!(" instead of {ctype}") };
        warnings.push(format!(
            "the {what} goes as Content-Type text/plain{sent_as}: a cross-site page can't send another type without \
             a CORS preflight, so the server must accept text/plain"
        ));
    }

    // Anti-CSRF tokens and secrets: recorded values the page carries.
    let param_names: Vec<String> = if json_like {
        match serde_json::from_str::<serde_json::Value>(&json_body) {
            Ok(serde_json::Value::Object(o)) => o.keys().cloned().collect(),
            _ => Vec::new(),
        }
    } else {
        fields.iter().map(|f| f.name.clone()).collect()
    };
    let tokens: Vec<&str> = param_names.iter().filter(|n| is_anti_csrf_token(n)).map(String::as_str).collect();
    if !tokens.is_empty() {
        warnings.push(format!(
            "{} looks like an anti-CSRF token: the page keeps the recorded value, which a real attacker wouldn't \
             know; --drop-param {} shows whether the server checks it",
            tokens.join(", "),
            tokens[0]
        ));
    }
    let secrets: Vec<&str> =
        param_names.iter().filter(|n| !is_anti_csrf_token(n) && looks_secret(n)).map(String::as_str).collect();
    if !secrets.is_empty() {
        warnings.push(format!(
            "{} looks like a password, token or session value: the recorded value is written into the page; \
             replace or drop it (--drop-param) before sharing the page",
            secrets.join(", ")
        ));
    }
    let files: Vec<&str> = fields.iter().filter(|f| f.file.is_some()).map(|f| f.name.as_str()).collect();
    if !files.is_empty() && opts.technique == Technique::Form {
        warnings.push(format!(
            "file part {} is left out: a form can't fill a file input; --technique fetch sends it",
            files.join(", ")
        ));
        fields.retain(|f| f.file.is_none());
    }

    // What a cross-site page can't do as the request did.
    let simple_method = matches!(recorded_method.as_str(), "GET" | "POST");
    let method = match (opts.technique, simple_method) {
        (_, true) => recorded_method.clone(),
        (Technique::Form, false) => {
            let m = if encoding == Encoding::Query { "GET" } else { "POST" };
            warnings.push(format!(
                "the request is {recorded_method}, which a form can't send: the page sends {m} (a server that \
                 takes a method override such as _method may still treat it as {recorded_method}); {recorded_method} \
                 from another site needs a CORS preflight the server must allow (see rule 40040)"
            ));
            m.to_string()
        }
        (Technique::Fetch, false) => {
            warnings.push(format!(
                "{recorded_method} from another site needs a CORS preflight the server must allow (see rule 40040)"
            ));
            recorded_method.clone()
        }
    };
    let custom: Vec<&str> =
        head.headers.iter().map(|(k, _)| k.as_str()).filter(|k| !is_browser_header(k)).collect::<Vec<_>>();
    let mut custom_names: Vec<&str> = Vec::new();
    for c in custom {
        if !custom_names.iter().any(|n| n.eq_ignore_ascii_case(c)) {
            custom_names.push(c);
        }
    }
    if !custom_names.is_empty() {
        warnings.push(format!(
            "the request carries {}, which the page doesn't send: if the server needs {}, a cross-site request needs \
             a CORS preflight the server must allow (see rule 40040)",
            custom_names.join(", "),
            if custom_names.len() == 1 { "it" } else { "them" }
        ));
    }

    let carried = header(&head.headers, "cookie").map(cookie_names).unwrap_or_default();
    if carried.is_empty() && header(&head.headers, "authorization").is_none() {
        warnings.push(
            "the request carries no cookies: unless the server trusts something else the browser adds (HTTP or \
             client-certificate authentication, the network it's on), the page sends nothing a forgery needs"
                .into(),
        );
    }
    let ctx = if opts.technique == Technique::Form && method == "GET" { Context::TopLevelGet } else { Context::Other };
    warnings.extend(samesite_warnings(&carried, &opts.set_cookies, ctx, "the page's request"));

    let action = url.to_string();
    let html = match opts.technique {
        Technique::Form => form_html(&method, &action, encoding, &fields, opts.auto_submit),
        Technique::Fetch => fetch_html(&method, &action, encoding, &fields, &ctype, simple_method, opts.auto_submit),
    };
    Ok(CsrfPoc {
        method,
        action,
        encoding,
        technique: opts.technique,
        fields,
        auto_submit: opts.auto_submit,
        warnings,
        html,
    })
}

const NOTE: &str = "<!-- Written by brainproxy from a recorded request. Opening this page in a browser sends \
    requests from that browser straight to the target, outside brainproxy and its scope checks. -->";

fn page(title: &str, style: &str, body: &str) -> String {
    format!(
        "<!doctype html>\n<html lang=\"en\">\n<head>\n<meta charset=\"utf-8\">\n<meta name=\"viewport\" \
         content=\"width=device-width, initial-scale=1\">\n<title>{}</title>\n{NOTE}\n{style}</head>\n<body>\n{body}\
         </body>\n</html>\n",
        escape_text(title)
    )
}

fn form_html(method: &str, action: &str, encoding: Encoding, fields: &[Field], auto: bool) -> String {
    let enctype = match encoding {
        Encoding::Multipart => " enctype=\"multipart/form-data\"",
        Encoding::Json | Encoding::Text => " enctype=\"text/plain\"",
        Encoding::Query | Encoding::Urlencoded => "",
    };
    let mut body = format!(
        "<h1>CSRF proof of concept</h1>\n<p>Sends <code>{} {}</code> with this browser's cookies for the site.</p>\n\
         <form id=\"poc\" method=\"{}\" action=\"{}\"{enctype}>\n",
        escape_text(method),
        escape_text(action),
        if method == "GET" { "get" } else { "post" },
        escape_attr(action),
    );
    for f in fields {
        body.push_str(&format!(
            "<input type=\"hidden\" name=\"{}\" value=\"{}\">\n",
            escape_attr(&f.name),
            escape_attr(&f.value)
        ));
    }
    body.push_str("<button type=\"submit\">Send the request</button>\n</form>\n");
    if auto {
        // The prototype's submit: a field named "submit" would hide the form's own.
        body.push_str(
            "<script>\nHTMLFormElement.prototype.submit.call(document.getElementById(\"poc\"));\n</script>\n",
        );
    }
    page("CSRF proof of concept", "", &body)
}

fn fetch_html(
    method: &str,
    action: &str,
    encoding: Encoding,
    fields: &[Field],
    ctype: &str,
    simple: bool,
    auto: bool,
) -> String {
    let pairs: Vec<[&str; 2]> =
        fields.iter().filter(|f| f.file.is_none()).map(|f| [f.name.as_str(), f.value.as_str()]).collect();
    let mut script = String::from("\"use strict\";\n");
    script.push_str(&format!("const action = {};\n", js(action)));
    let mut init = vec![
        format!("method: {}", js(method)),
        format!("mode: {}", js(if simple { "no-cors" } else { "cors" })),
        "credentials: \"include\"".to_string(),
    ];
    let mut target = "action".to_string();
    match encoding {
        Encoding::Query => {
            script.push_str(&format!(
                "const url = new URL(action);\nurl.search = \"\";\nfor (const [k, v] of {}) url.searchParams.append(k, \
                 v);\n",
                js(&pairs)
            ));
            target = "url".into();
        }
        Encoding::Urlencoded => {
            script.push_str(&format!("const body = new URLSearchParams({});\n", js(&pairs)));
            init.push("body".into());
        }
        Encoding::Multipart => {
            script.push_str(&format!(
                "const body = new FormData();\nfor (const [k, v] of {}) body.append(k, v);\n",
                js(&pairs)
            ));
            let b64 = base64::engine::general_purpose::STANDARD;
            for f in fields {
                if let (Some((bytes, ct)), Some(name)) = (&f.file, &f.filename) {
                    script.push_str(&format!(
                        "body.append({}, new Blob([Uint8Array.from(atob({}), (c) => c.charCodeAt(0))], {{ type: {} }}), \
                         {});\n",
                        js(&f.name),
                        js(&b64.encode(bytes)),
                        js(ct),
                        js(name)
                    ));
                }
            }
            init.push("body".into());
        }
        Encoding::Json | Encoding::Text => {
            let body = fields.first().map(|f| f.value.as_str()).unwrap_or("");
            script.push_str(&format!("const body = {};\n", js(body)));
            // A request that needs a preflight anyway may as well say what it is.
            let ct = if simple || ctype.is_empty() { "text/plain" } else { ctype };
            init.push(format!("headers: {{ \"Content-Type\": {} }}", js(ct)));
            init.push("body".into());
        }
    }
    script.push_str(&format!(
        "async function send() {{\n  const result = document.getElementById(\"result\");\n  try {{\n    await \
         fetch({target}, {{ {} }});\n    result.textContent = \"Sent. A page on another site can't read the response: \
         check the request's effect on the target.\";\n  }} catch (e) {{\n    result.textContent = \"Not sent: \" + \
         e;\n  }}\n}}\ndocument.getElementById(\"send\").addEventListener(\"click\", send);\n",
        init.join(", ")
    ));
    if auto {
        script.push_str("send();\n");
    }
    let body = format!(
        "<h1>CSRF proof of concept</h1>\n<p>Sends <code>{} {}</code> with this browser's cookies for the site.</p>\n\
         <button id=\"send\" type=\"button\">Send the request</button>\n<p id=\"result\"></p>\n<script>\n{script}\
         </script>\n",
        escape_text(method),
        escape_text(action)
    );
    page("CSRF proof of concept", "", &body)
}

/// Whether a response may be shown in a cross-site frame, from its headers.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Framing {
    /// The X-Frame-Options values, joined with ", ".
    pub x_frame_options: Option<String>,
    /// The frame-ancestors source lists of the enforced Content-Security-Policy, joined with "; ".
    pub frame_ancestors: Option<String>,
    /// A browser refuses to show it in another site's frame. None when there was no response.
    pub blocked: Option<bool>,
}

/// Reads [`Framing`] from response headers. frame-ancestors, where a policy has it, decides
/// and X-Frame-Options is then ignored, as browsers do; otherwise an X-Frame-Options value
/// rule 10020 takes as valid (DENY or SAMEORIGIN) blocks.
pub fn framing(headers: &[(String, String)]) -> Framing {
    let xfo: Vec<&str> =
        headers.iter().filter(|(k, _)| k.eq_ignore_ascii_case("x-frame-options")).map(|(_, v)| v.trim()).collect();
    let mut ancestors: Vec<String> = Vec::new();
    for (_, v) in headers.iter().filter(|(k, _)| k.eq_ignore_ascii_case("content-security-policy")) {
        // A header may carry several policies, comma-separated; each is enforced.
        for policy in v.split(',') {
            let found = policy.split(';').find_map(|d| {
                let d = d.trim();
                let (name, value) = d.split_once(char::is_whitespace).unwrap_or((d, ""));
                name.eq_ignore_ascii_case("frame-ancestors").then(|| value.trim().to_string())
            });
            ancestors.extend(found);
        }
    }
    let blocked = if !ancestors.is_empty() {
        // Each policy must allow the frame: one that names neither every host nor the scheme
        // blocks a page on another site.
        ancestors.iter().any(|list| {
            !list
                .split_whitespace()
                .any(|s| s == "*" || s.eq_ignore_ascii_case("https:") || s.eq_ignore_ascii_case("http:"))
        })
    } else {
        xfo.iter().any(|v| xfo_blocks(v))
    };
    Framing {
        x_frame_options: (!xfo.is_empty()).then(|| xfo.join(", ")),
        frame_ancestors: (!ancestors.is_empty()).then(|| ancestors.join("; ")),
        blocked: Some(blocked),
    }
}

#[derive(Clone, Debug)]
pub struct ClickjackingOptions {
    /// The frame's opacity at first, 0 to 1 (the page has a slider).
    pub opacity: f64,
    /// The decoy button's text.
    pub decoy: String,
    /// The cookies the framed page needs (the recorded request's), for the SameSite warnings.
    pub cookies: Vec<String>,
    /// Set-Cookie values recorded from the URL's host, oldest first.
    pub set_cookies: Vec<String>,
}

impl Default for ClickjackingOptions {
    fn default() -> Self {
        Self { opacity: 0.5, decoy: "Click me".into(), cookies: Vec::new(), set_cookies: Vec::new() }
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct ClickjackingPoc {
    pub url: String,
    pub framing: Framing,
    pub warnings: Vec<String>,
    pub html: String,
}

/// The page that frames `url` under a decoy button. `response` is the recorded response's head,
/// if there is one, for whether browsers let it be framed.
pub fn clickjacking(url: &str, response: Option<&ResponseHead>, opts: &ClickjackingOptions) -> Result<ClickjackingPoc> {
    let url = web_url(url)?.to_string();
    if !opts.opacity.is_finite() || !(0.0..=1.0).contains(&opts.opacity) {
        return Err(Error::InvalidInput(format!("--opacity {}: give a number from 0 to 1", opts.opacity)));
    }
    let mut warnings = Vec::new();
    let framing = match response {
        Some(r) => framing(&r.headers),
        None => {
            warnings.push(
                "no response is recorded for this URL: whether a browser lets another site frame it is unknown".into(),
            );
            Framing { x_frame_options: None, frame_ancestors: None, blocked: None }
        }
    };
    if framing.blocked == Some(true) {
        let why = match (&framing.frame_ancestors, &framing.x_frame_options) {
            (Some(fa), _) => format!("Content-Security-Policy frame-ancestors {fa}"),
            (None, Some(x)) => format!("X-Frame-Options: {x}"),
            (None, None) => "its headers".into(),
        };
        warnings.push(format!("the response says it can't be framed ({why}): browsers show nothing in the frame"));
    }
    if let Some(r) = response {
        if (300..400).contains(&r.status) {
            warnings.push(format!(
                "the recorded response is a redirect ({}): what the frame shows depends on where it goes",
                r.status
            ));
        }
    }
    warnings.extend(samesite_warnings(&opts.cookies, &opts.set_cookies, Context::Other, "the framed page"));
    let opacity = opts.opacity;
    let style = "<style>\nbody { margin: 0; font: 14px system-ui, sans-serif; }\n#controls { position: fixed; top: 0; \
                 left: 0; right: 0; z-index: 3; display: flex; flex-wrap: wrap; gap: 12px; align-items: center; \
                 padding: 8px 12px; background: #fff; color: #111; border-bottom: 1px solid #ccc; }\n#stage { \
                 position: absolute; top: 48px; left: 0; right: 0; bottom: 0; }\n#target { position: absolute; \
                 inset: 0; width: 100%; height: 100%; border: 0; z-index: 2; }\n#decoy { position: absolute; \
                 z-index: 1; padding: 10px 18px; font-size: 16px; }\ninput[type=number] { width: 5em; }\n</style>\n";
    let body = format!(
        "<div id=\"controls\">\n<strong>Clickjacking proof of concept</strong>\n<label>Frame opacity <input \
         id=\"opacity\" type=\"range\" min=\"0\" max=\"1\" step=\"0.01\" value=\"{opacity}\"> <output \
         id=\"opacity-value\">{opacity}</output></label>\n<label>Decoy x <input id=\"x\" type=\"number\" \
         value=\"200\"></label>\n<label>y <input id=\"y\" type=\"number\" value=\"200\"></label>\n<label><input \
         id=\"place\" type=\"checkbox\"> Place the decoy with a click (clicks pass through the frame)</label>\n\
         </div>\n<div id=\"stage\">\n<button id=\"decoy\" type=\"button\">{}</button>\n<iframe id=\"target\" \
         src=\"{}\" title=\"Framed page\"></iframe>\n</div>\n<script>\n\"use strict\";\nconst frame = \
         document.getElementById(\"target\");\nconst decoy = document.getElementById(\"decoy\");\nconst opacity = \
         document.getElementById(\"opacity\");\nconst shown = document.getElementById(\"opacity-value\");\nconst x = \
         document.getElementById(\"x\");\nconst y = document.getElementById(\"y\");\nconst place = \
         document.getElementById(\"place\");\nfunction update() {{\n  frame.style.opacity = opacity.value;\n  \
         shown.textContent = opacity.value;\n  decoy.style.left = (Number(x.value) || 0) + \"px\";\n  decoy.style.top \
         = (Number(y.value) || 0) + \"px\";\n  frame.style.pointerEvents = place.checked ? \"none\" : \"auto\";\n}}\n\
         for (const el of [opacity, x, y, place]) el.addEventListener(\"input\", update);\n\
         document.getElementById(\"stage\").addEventListener(\"click\", (e) => {{\n  if (!place.checked) return;\n  \
         const r = e.currentTarget.getBoundingClientRect();\n  x.value = Math.round(e.clientX - r.left - \
         decoy.offsetWidth / 2);\n  y.value = Math.round(e.clientY - r.top - decoy.offsetHeight / 2);\n  update();\n\
         }});\nupdate();\n</script>\n",
        escape_text(&opts.decoy),
        escape_attr(&url),
    );
    Ok(ClickjackingPoc { url, framing, warnings, html: page("Clickjacking proof of concept", style, &body) })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn req(text: &str) -> RawRequest {
        RawRequest::from_bytes(text.as_bytes().to_vec()).normalize_line_endings()
    }

    fn target() -> Target {
        Target::from_url("https://shop.test").expect("a valid test target")
    }

    fn make(text: &str, opts: &CsrfOptions) -> CsrfPoc {
        csrf(&req(text), &target(), opts).expect("a page for the test request")
    }

    fn form() -> CsrfOptions {
        CsrfOptions::default()
    }

    fn fetch() -> CsrfOptions {
        CsrfOptions { technique: Technique::Fetch, ..Default::default() }
    }

    /// The HTML text/plain form encoding: each entry as name, "=", value, CR LF.
    fn text_plain(fields: &[Field]) -> String {
        fields.iter().map(|f| format!("{}={}\r\n", f.name, f.value)).collect()
    }

    fn names(p: &CsrfPoc) -> Vec<(&str, &str)> {
        p.fields.iter().map(|f| (f.name.as_str(), f.value.as_str())).collect()
    }

    const COOKIE: &str = "Cookie: sid=1\n";

    fn post(ctype: &str, body: &str) -> String {
        format!("POST /x HTTP/1.1\nHost: shop.test\n{COOKIE}Content-Type: {ctype}\n\n{body}")
    }

    #[test]
    fn urlencoded_body_becomes_hidden_inputs() {
        let p = make(
            &format!(
                "POST /account/email?x=1 HTTP/1.1\nHost: shop.test\n{COOKIE}Content-Type: \
                 application/x-www-form-urlencoded\n\nemail=a%40b.test&note=two+words&empty="
            ),
            &form(),
        );
        assert_eq!(p.encoding, Encoding::Urlencoded);
        assert_eq!(p.method, "POST");
        assert_eq!(p.action, "https://shop.test/account/email?x=1");
        assert_eq!(names(&p), [("email", "a@b.test"), ("note", "two words"), ("empty", "")]);
        assert!(p.html.contains("<form id=\"poc\" method=\"post\" action=\"https://shop.test/account/email?x=1\">"));
        assert!(p.html.contains("<input type=\"hidden\" name=\"email\" value=\"a@b.test\">"));
        assert!(!p.html.contains("<script>"), "no script without --auto-submit");
        assert!(p.warnings.is_empty(), "{:?}", p.warnings);
        let auto =
            make(&post("application/x-www-form-urlencoded", "a=1"), &CsrfOptions { auto_submit: true, ..form() });
        assert!(auto.html.contains("HTMLFormElement.prototype.submit.call"));
        let f = make(&post("application/x-www-form-urlencoded", "a=1"), &fetch());
        assert!(f.html.contains("new URLSearchParams([[\"a\",\"1\"]])"), "{}", f.html);
    }

    #[test]
    fn get_query_becomes_a_get_form() {
        let p = make(&format!("GET /transfer?to=bob&amount=10 HTTP/1.1\nHost: shop.test\n{COOKIE}\n"), &form());
        assert_eq!(p.encoding, Encoding::Query);
        assert_eq!(p.method, "GET");
        assert_eq!(p.action, "https://shop.test/transfer");
        assert_eq!(names(&p), [("to", "bob"), ("amount", "10")]);
        assert!(p.html.contains("method=\"get\""));
        let f = make(&format!("GET /transfer?to=bob HTTP/1.1\nHost: shop.test\n{COOKIE}\n"), &fetch());
        assert!(f.html.contains("url.searchParams.append"));
        assert!(f.html.contains("mode: \"no-cors\""));
        assert!(f.html.contains("credentials: \"include\""));
    }

    const MULTIPART: &str = "POST /upload HTTP/1.1\nHost: shop.test\nCookie: sid=1\nContent-Type: multipart/form-data; \
                             boundary=XyZ\n\n--XyZ\r\nContent-Disposition: form-data; name=\"title\"\r\n\r\nHello\r\n\
                             --XyZ\r\nContent-Disposition: form-data; name=\"doc\"; filename=\"a.txt\"\r\nContent-Type: \
                             text/plain\r\n\r\nfile body\r\n--XyZ--\r\n";

    #[test]
    fn multipart_becomes_a_multipart_form_or_form_data() {
        let p = make(MULTIPART, &form());
        assert_eq!(p.encoding, Encoding::Multipart);
        assert!(p.html.contains("enctype=\"multipart/form-data\""));
        assert_eq!(names(&p), [("title", "Hello")]);
        assert!(p.warnings.iter().any(|w| w.contains("file part doc is left out")), "{:?}", p.warnings);
        let f = make(MULTIPART, &fetch());
        assert_eq!(names(&f), [("title", "Hello"), ("doc", "file body")]);
        assert_eq!(f.fields[1].filename.as_deref(), Some("a.txt"));
        assert!(f.html.contains("new FormData()"));
        let b64 = base64::engine::general_purpose::STANDARD.encode("file body");
        assert!(f.html.contains(&format!("atob(\"{b64}\")")), "{}", f.html);
        assert!(f.html.contains("\"a.txt\""));
        assert!(f.html.contains("type: \"text/plain\""));
        assert!(f.warnings.is_empty(), "{:?}", f.warnings);
    }

    #[test]
    fn json_goes_as_text_plain_and_round_trips() {
        // An '=' in the body: split there, the form sends the body as it was.
        let body = r#"{"email":"a@b.test","q":"x=y","n":1}"#;
        let p = make(&post("application/json", body), &form());
        assert_eq!(p.encoding, Encoding::Json);
        assert!(p.html.contains("enctype=\"text/plain\""));
        let sent = text_plain(&p.fields);
        assert_eq!(sent, format!("{body}\r\n"));
        let v: serde_json::Value = serde_json::from_str(&sent).expect("the form sends JSON");
        assert_eq!(v, serde_json::from_str::<serde_json::Value>(body).expect("test JSON"));
        assert!(p.warnings.iter().any(|w| w.contains("text/plain")), "{:?}", p.warnings);

        // No '=': one member more holds it, the rest is the same JSON.
        let body = r#"{"email":"a@b.test","n":[1,2]}"#;
        let p = make(&post("application/json", body), &form());
        let sent: serde_json::Value = serde_json::from_str(&text_plain(&p.fields)).expect("the form sends JSON");
        let mut want: serde_json::Value = serde_json::from_str(body).expect("test JSON");
        want["_"] = "=".into();
        assert_eq!(sent, want);
        assert!(p.warnings.iter().any(|w| w.contains("gains the member \"_\"")), "{:?}", p.warnings);
        // An empty object too, and a member called _ already.
        let p = make(&post("application/json", "{}"), &form());
        let sent: serde_json::Value = serde_json::from_str(&text_plain(&p.fields)).expect("the form sends JSON");
        assert_eq!(sent, serde_json::json!({"_": "="}));
        let p = make(&post("application/json", r#"{"_":1}"#), &form());
        let sent: serde_json::Value = serde_json::from_str(&text_plain(&p.fields)).expect("the form sends JSON");
        assert_eq!(sent, serde_json::json!({"_": 1, "__": "="}));

        // fetch sends it exactly, as text/plain, without a preflight.
        let f = make(&post("application/json", body), &fetch());
        assert!(f.html.contains(&format!("const body = {};", js(body))));
        assert!(f.html.contains("\"Content-Type\": \"text/plain\""));
        assert!(f.html.contains("mode: \"no-cors\""));
    }

    #[test]
    fn other_bodies_go_as_text() {
        let p = make(&post("application/xml", "<a>1</a>"), &form());
        assert_eq!(p.encoding, Encoding::Text);
        assert_eq!(text_plain(&p.fields), "<a>1</a>=\r\n");
        assert!(p.warnings.iter().any(|w| w.contains("instead of application/xml")), "{:?}", p.warnings);
    }

    #[test]
    fn drop_param_removes_fields_and_json_members() {
        let opts = CsrfOptions { drop_params: vec!["csrf_token".into(), "nope".into()], ..form() };
        let p = make(&post("application/x-www-form-urlencoded", "a=1&csrf_token=t"), &opts);
        assert_eq!(names(&p), [("a", "1")]);
        assert!(p.warnings.iter().any(|w| w.contains("--drop-param nope")));
        assert!(!p.warnings.iter().any(|w| w.contains("anti-CSRF")));
        let opts = CsrfOptions { drop_params: vec!["token".into()], ..fetch() };
        let p = make(&post("application/json", r#"{"a":1,"token":"t"}"#), &opts);
        assert_eq!(p.fields[0].value, r#"{"a":1}"#);
    }

    #[test]
    fn hostile_values_stay_values() {
        let body = "%22%3E%3Cscript%3Ealert(1)%3C%2Fscript%3E=%22%3E%3Cscript%3Ealert(2)%3C%2Fscript%3E\
                    &a%27b%22c=%3C%2Fscript%3E%3C%21--";
        let ctype = "application/x-www-form-urlencoded";
        let p = make(&post(ctype, body), &CsrfOptions { auto_submit: true, ..form() });
        assert_eq!(p.fields[0].name, "\"><script>alert(1)</script>");
        assert_eq!(p.fields[1].name, "a'b\"c");
        assert!(!p.html.contains("<script>alert"));
        assert!(p.html.contains("name=\"&quot;&gt;&lt;script&gt;alert(1)&lt;/script&gt;\""));
        assert!(p.html.contains("name=\"a&#39;b&quot;c\" value=\"&lt;/script&gt;&lt;!--\""));
        assert_eq!(p.html.matches("<script>").count(), 1);
        assert_eq!(p.html.matches("</script>").count(), 1);

        let opts = CsrfOptions { technique: Technique::Fetch, auto_submit: true, ..Default::default() };
        let p = make(&post(ctype, body), &opts);
        assert_eq!(p.html.matches("</script").count(), 1, "{}", p.html);
        assert!(p.html.contains("\\u003c/script\\u003e"));
        assert!(!p.html.contains("<!--\""));
        let j = make(&post("application/json", r#"{"a":"</script><script>alert(1)</script>"}"#), &opts);
        assert_eq!(j.html.matches("</script").count(), 1, "{}", j.html);

        // A hostile path is percent-encoded by the URL parser.
        let p = make(&format!("GET /\"><img src=x> HTTP/1.1\nHost: shop.test\n{COOKIE}\n"), &form());
        assert!(!p.html.contains("<img"));
        assert_eq!(escape_attr("a\r\nb\t"), "a&#13;&#10;b&#9;");
        assert_eq!(escape_text("<b>&\"'"), "&lt;b&gt;&amp;&quot;&#39;");
        assert_eq!(js("</script><!--&\u{2028}"), r#""\u003c/script\u003e\u003c!--\u0026\u2028""#);
    }

    #[test]
    fn warnings_name_what_a_page_cannot_do() {
        let opts = CsrfOptions {
            set_cookies: vec![
                "sid=old; SameSite=None".into(),
                "sid=1; Path=/; SameSite=Lax".into(),
                "pref=dark; SameSite=Strict".into(),
                "plain=1".into(),
            ],
            ..form()
        };
        let p = make(
            "PUT /x HTTP/1.1\nHost: shop.test\nCookie: sid=1; pref=dark; plain=1\nX-Requested-With: XMLHttpRequest\n\
             Sec-Fetch-Site: same-origin\nContent-Type: application/x-www-form-urlencoded\n\n\
             authenticity_token=t&new_password=p&userSessionId=s&author=me",
            &opts,
        );
        assert_eq!(p.method, "POST");
        let all = p.warnings.join("\n");
        assert!(all.contains("the request is PUT, which a form can't send"), "{all}");
        assert!(all.contains("40040"), "{all}");
        assert!(all.contains("carries X-Requested-With,"), "{all}");
        assert!(!all.contains("Sec-Fetch-Site"), "{all}");
        assert!(all.contains("authenticity_token looks like an anti-CSRF token"), "{all}");
        assert!(all.contains("new_password, userSessionId looks like a password"), "{all}");
        assert!(!all.contains("author"), "{all}");
        assert!(all.contains("cookie sid is SameSite=Lax"), "{all}");
        assert!(all.contains("cookie pref is SameSite=Strict"), "{all}");
        assert!(all.contains("cookie plain was set without SameSite"), "{all}");

        // A GET form is a top-level navigation: Lax cookies go with it.
        let opts = CsrfOptions { set_cookies: vec!["sid=1; SameSite=Lax".into()], ..form() };
        let p = make("GET /x?a=1 HTTP/1.1\nHost: shop.test\nCookie: sid=1\n\n", &opts);
        assert!(p.warnings.is_empty(), "{:?}", p.warnings);
        let p =
            make("POST /x HTTP/1.1\nHost: shop.test\nContent-Type: application/x-www-form-urlencoded\n\na=1", &form());
        assert!(p.warnings.iter().any(|w| w.contains("carries no cookies")), "{:?}", p.warnings);
        let p = make("DELETE /x/1 HTTP/1.1\nHost: shop.test\nCookie: sid=1\n\n", &fetch());
        assert_eq!(p.method, "DELETE");
        assert!(p.html.contains("mode: \"cors\""));
        assert!(p.warnings.iter().any(|w| w.contains("DELETE from another site needs a CORS preflight")));
    }

    #[test]
    fn secret_names() {
        for n in [
            "password",
            "new_password",
            "userPassword",
            "pwd",
            "api_key",
            "X-Auth",
            "sessionId",
            "otp",
            "pin",
            "accessToken",
        ] {
            assert!(looks_secret(n), "{n}");
        }
        for n in ["email", "author", "username", "comment", "shipping", "spinner", "q"] {
            assert!(!looks_secret(n), "{n}");
        }
    }

    #[test]
    fn only_web_urls_make_a_page() {
        let t = target();
        for line in ["GET javascript:alert(1) HTTP/1.1\nHost: a\n\n", "OPTIONS * HTTP/1.1\nHost: a\n\n"] {
            assert!(csrf(&req(line), &t, &form()).is_err(), "{line}");
        }
        let abs = make("POST http://other.test:8080/a HTTP/1.1\nHost: other.test\nCookie: s=1\n\n", &form());
        assert_eq!(abs.action, "http://other.test:8080/a");
        let o = ClickjackingOptions::default();
        assert!(clickjacking("javascript:alert(1)", None, &o).is_err());
        assert!(clickjacking("data:text/html,x", None, &o).is_err());
        for opacity in [-0.1, 1.5, f64::NAN] {
            assert!(clickjacking("https://a.test/", None, &ClickjackingOptions { opacity, ..o.clone() }).is_err());
        }
    }

    fn h(pairs: &[(&str, &str)]) -> Vec<(String, String)> {
        pairs.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect()
    }

    #[test]
    fn framing_parse() {
        let f = framing(&h(&[("X-Frame-Options", "DENY")]));
        assert_eq!(f, Framing { x_frame_options: Some("DENY".into()), frame_ancestors: None, blocked: Some(true) });
        assert_eq!(framing(&h(&[("x-frame-options", "sameorigin")])).blocked, Some(true));
        // Browsers ignore ALLOW-FROM: framed anywhere.
        assert_eq!(framing(&h(&[("X-Frame-Options", "ALLOW-FROM https://b.test")])).blocked, Some(false));
        assert_eq!(framing(&[]).blocked, Some(false));
        // frame-ancestors decides over X-Frame-Options.
        let both =
            h(&[("X-Frame-Options", "DENY"), ("Content-Security-Policy", "default-src 'self'; frame-ancestors *")]);
        let f = framing(&both);
        assert_eq!(f.blocked, Some(false));
        assert_eq!(f.frame_ancestors.as_deref(), Some("*"));
        assert_eq!(f.x_frame_options.as_deref(), Some("DENY"));
        let f = framing(&h(&[("Content-Security-Policy", "Frame-Ancestors 'self' https://partner.test")]));
        assert_eq!(f.blocked, Some(true));
        assert_eq!(framing(&h(&[("Content-Security-Policy", "frame-ancestors https:")])).blocked, Some(false));
        // Every policy must allow it; a report-only one enforces nothing.
        let two = h(&[("Content-Security-Policy", "frame-ancestors *, frame-ancestors 'none'")]);
        assert_eq!(framing(&two).blocked, Some(true));
        let ro = h(&[("Content-Security-Policy-Report-Only", "frame-ancestors 'none'")]);
        assert_eq!(framing(&ro).blocked, Some(false));
    }

    #[test]
    fn clickjacking_page() {
        let head =
            crate::http::parse_response_head(b"HTTP/1.1 200 OK\r\nX-Frame-Options: DENY\r\n\r\n").expect("a head");
        let opts = ClickjackingOptions {
            opacity: 0.25,
            decoy: "<b>Win</b>".into(),
            cookies: vec!["sid".into()],
            set_cookies: vec!["sid=1; SameSite=Lax".into()],
        };
        let p = clickjacking("https://a.test/settings?x=\"><script>", Some(&head), &opts).expect("a page");
        assert_eq!(p.framing.blocked, Some(true));
        assert!(p.warnings.iter().any(|w| w.contains("X-Frame-Options: DENY")), "{:?}", p.warnings);
        assert!(p.warnings.iter().any(|w| w.contains("SameSite=Lax")), "{:?}", p.warnings);
        assert!(p.html.contains("value=\"0.25\""));
        assert!(p.html.contains("&lt;b&gt;Win&lt;/b&gt;"));
        assert!(p.html.contains("src=\"https://a.test/settings?x=%22%3E%3Cscript%3E\""), "{}", p.html);
        assert_eq!(p.html.matches("<script>").count(), 1);
        let none = clickjacking("https://a.test/", None, &ClickjackingOptions::default()).expect("a page");
        assert_eq!(none.framing.blocked, None);
        assert!(none.warnings.iter().any(|w| w.contains("no response is recorded")));
    }
}
