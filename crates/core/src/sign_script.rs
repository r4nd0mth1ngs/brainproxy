//! Postman pre-request scripts, run for a signer that asks for one (`auth sign add --script`).
//!
//! These are the only documents' code brainproxy runs, and only by that explicit choice. The
//! interpreter is memory safe and has no way out but the few helpers here: no files, no
//! network, no process. A run gets its own context, a loop and recursion limit, and a time
//! limit, and can change only the request's headers and query, on the signer's origins.
//!
//! Nothing can bound an allocation inside the interpreter, so a hostile script can still
//! use up memory, which is why a run is never automatic.

use std::sync::mpsc;
use std::time::Duration;

use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine;
use boa_engine::{js_string, Context, JsError, JsResult, JsString, JsValue, NativeFunction, Script, Source};
use ring::rand::SecureRandom;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::Digest;

const SHIM: &str = include_str!("sign_script.js");
const LOOP_LIMIT: u64 = 2_000_000;
const RECURSION_LIMIT: usize = 200;
/// The interpreter recurses on the native stack.
const STACK_BYTES: usize = 16 * 1024 * 1024;
const TIME_LIMIT: Duration = Duration::from_secs(5);

/// Calls that a run refuses, so a preview can say so before anything is chosen.
const UNSUPPORTED: &[&str] =
    &["pm.sendRequest", "pm.cookies", "pm.vault", "pm.execution.skipRequest", "pm.expect", "pm.visualizer"];

/// A pre-request script found in a collection.
#[derive(Debug, Clone, PartialEq)]
pub struct Found {
    /// `collection`, or the path of the folder or request holding it.
    pub scope: String,
    pub text: String,
    /// Requests it applies to.
    pub requests: usize,
}

fn script_text(event: &Value) -> Option<String> {
    if event.get("listen").and_then(Value::as_str) != Some("prerequest")
        || event.get("disabled").and_then(Value::as_bool) == Some(true)
    {
        return None;
    }
    let text = match event.pointer("/script/exec")? {
        Value::Array(lines) => lines.iter().filter_map(Value::as_str).collect::<Vec<_>>().join("\n"),
        Value::String(s) => s.clone(),
        _ => return None,
    };
    (!text.trim().is_empty()).then_some(text)
}

fn count_requests(node: &Value) -> usize {
    match node.get("item").and_then(Value::as_array) {
        Some(items) => items.iter().map(count_requests).sum(),
        None => usize::from(node.get("request").is_some()),
    }
}

/// Every enabled pre-request script of a collection, outermost first.
pub fn prerequest_scripts(doc: &Value) -> Vec<Found> {
    fn walk(node: &Value, scope: &str, out: &mut Vec<Found>) {
        let requests = count_requests(node);
        for e in node.get("event").and_then(Value::as_array).into_iter().flatten() {
            if let Some(text) = script_text(e) {
                out.push(Found { scope: scope.to_string(), text, requests });
            }
        }
        for item in node.get("item").and_then(Value::as_array).into_iter().flatten() {
            let name = item.get("name").and_then(Value::as_str).unwrap_or("(unnamed)");
            let child = if scope == "collection" { name.to_string() } else { format!("{scope}/{name}") };
            walk(item, &child, out);
        }
    }
    let mut out = Vec::new();
    walk(doc, "collection", &mut out);
    out
}

/// Whether a script seems to sign something, for telling it apart from test set-up.
pub fn seems_to_sign(text: &str) -> bool {
    let t = text.to_ascii_lowercase();
    [
        "cryptojs",
        "crypto-js",
        "require('crypto",
        "require(\"crypto",
        "hmac",
        "sha1",
        "sha256",
        "sha512",
        "signature",
        "jsrsasign",
        "jwt",
    ]
    .iter()
    .any(|w| t.contains(w))
}

/// The refused calls `text` makes.
pub fn unsupported_calls(text: &str) -> Vec<String> {
    let mut out: Vec<String> = UNSUPPORTED.iter().filter(|c| text.contains(**c)).map(|c| c.to_string()).collect();
    if text.contains("jsrsasign") || text.contains("KJUR") {
        out.push("jsrsasign".into());
    }
    out
}

/// Whether `text` parses, without running it. The error holds a position, not the text.
pub fn check_syntax(text: &str) -> std::result::Result<(), String> {
    let mut ctx = Context::default();
    Script::parse(Source::from_bytes(text), None, &mut ctx).map(|_| ()).map_err(|e| {
        let e = e.to_string();
        let at = e.rfind(" at ").map_or("", |i| &e[i..]);
        format!("the script doesn't parse{}", at.chars().take(60).collect::<String>())
    })
}

/// The hard-coded parts a signer reads when it first signs: never stored in the project.
#[derive(Debug, Default, Serialize, Deserialize)]
pub(crate) struct Bundle {
    pub script: String,
    pub vars: Vec<(String, String)>,
    /// Headers each request of the collection fills from variables, as `{{name}}` templates.
    /// The importer strips those as credentials; a variable the script sets brings them back.
    pub templates: Vec<Templates>,
}

/// One collection request's header templates, and how to know it again on the wire.
#[derive(Debug, Default, Clone, Serialize, Deserialize, PartialEq)]
pub(crate) struct Templates {
    pub method: String,
    /// Its path segments; one with a variable in it matches any.
    pub path: Vec<String>,
    pub headers: Vec<(String, String)>,
}

impl Templates {
    /// How closely a request fits: its method, and its path ending in this one's (the base
    /// URL a variable gives can add segments in front). Segments matched, then how many of
    /// them literally; None when it doesn't fit. Both sides are compared decoded: a
    /// collection may write `a%20b`.
    fn score(&self, method: &str, path: &str) -> Option<(usize, usize)> {
        let segs: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();
        if !self.method.eq_ignore_ascii_case(method) || segs.len() < self.path.len() {
            return None;
        }
        let decoded = |s: &str| percent_encoding::percent_decode_str(s).decode_utf8_lossy().into_owned();
        let tail = &segs[segs.len() - self.path.len()..];
        let mut literal = 0;
        for (want, got) in self.path.iter().zip(tail) {
            if want.contains("{{") || want.starts_with(':') {
                continue;
            }
            if decoded(want) != decoded(got) {
                return None;
            }
            literal += 1;
        }
        Some((self.path.len(), literal))
    }
}

/// The collection request a sent request is: of those that fit, the most specific, and of
/// equally specific ones the first in the collection.
pub(crate) fn templates_for<'a>(all: &'a [Templates], method: &str, path: &str) -> Option<&'a Templates> {
    let mut best: Option<((usize, usize), &Templates)> = None;
    for t in all {
        if let Some(s) = t.score(method, path) {
            if best.is_none_or(|(b, _)| s > b) {
                best = Some((s, t));
            }
        }
    }
    best.map(|(_, t)| t)
}

fn auth_param<'a>(auth: &'a Value, kind: &str, key: &str) -> Option<&'a str> {
    match auth.get(kind)? {
        Value::Array(items) => {
            items.iter().find(|i| i.get("key").and_then(Value::as_str) == Some(key))?.get("value")?.as_str()
        }
        section => section.get(key)?.as_str(),
    }
}

/// The path segments of a Postman request URL, with whatever gives its origin left out.
fn url_path(url: &Value) -> Vec<String> {
    if let Some(parts) = url.get("path").and_then(Value::as_array) {
        return parts
            .iter()
            .filter_map(|p| p.as_str().or_else(|| p.get("value")?.as_str()))
            .filter(|s| !s.is_empty())
            .map(str::to_string)
            .collect();
    }
    let raw = url.as_str().or_else(|| url.get("raw")?.as_str()).unwrap_or_default();
    let raw = raw.split(['?', '#']).next().unwrap_or_default();
    let rest = if raw.starts_with("{{") {
        raw.split_once("}}").map_or("", |(_, r)| r)
    } else if let Some((_, r)) = raw.split_once("://") {
        r.split_once('/').map_or("", |(_, p)| p)
    } else {
        raw.split_once('/').map_or("", |(_, p)| p)
    };
    rest.split('/').filter(|s| !s.is_empty()).map(str::to_string).collect()
}

/// Each request's header templates: its own headers, and the auth it has or inherits.
pub(crate) fn header_templates(doc: &Value) -> Vec<Templates> {
    fn from_auth(auth: Option<&Value>, out: &mut Vec<(String, String)>) {
        let Some(auth) = auth else { return };
        match auth.get("type").and_then(Value::as_str) {
            Some("bearer") => {
                if let Some(t) = auth_param(auth, "bearer", "token") {
                    out.push(("Authorization".into(), format!("Bearer {t}")));
                }
            }
            Some("apikey") if auth_param(auth, "apikey", "in") != Some("query") => {
                if let (Some(k), Some(v)) = (auth_param(auth, "apikey", "key"), auth_param(auth, "apikey", "value")) {
                    out.push((k.to_string(), v.to_string()));
                }
            }
            _ => {}
        }
    }
    fn own(a: Option<&Value>) -> Option<&Value> {
        a.filter(|a| a.get("type").and_then(Value::as_str) != Some("inherit"))
    }
    fn walk<'a>(node: &'a Value, inherited: Option<&'a Value>, out: &mut Vec<Templates>) {
        let auth = own(node.get("auth")).or(inherited);
        if let Some(request) = node.get("request") {
            let auth = own(request.get("auth")).or(auth);
            let mut headers = Vec::new();
            from_auth(auth, &mut headers);
            for h in request.get("header").and_then(Value::as_array).into_iter().flatten() {
                if h.get("disabled").and_then(Value::as_bool) == Some(true) {
                    continue;
                }
                if let (Some(k), Some(v)) =
                    (h.get("key").and_then(Value::as_str), h.get("value").and_then(Value::as_str))
                {
                    headers.push((k.to_string(), v.to_string()));
                }
            }
            headers.retain(|(_, v)| v.contains("{{"));
            if !headers.is_empty() {
                let method = request.get("method").and_then(Value::as_str).unwrap_or("GET").to_ascii_uppercase();
                let url = if request.is_string() { request } else { request.get("url").unwrap_or(&Value::Null) };
                out.push(Templates { method, path: url_path(url), headers });
            }
        }
        for item in node.get("item").and_then(Value::as_array).into_iter().flatten() {
            walk(item, auth, out);
        }
    }
    let mut out = Vec::new();
    walk(doc, None, &mut out);
    out
}

/// A request as a script sees it.
#[derive(Debug, Clone, Default, Serialize)]
pub(crate) struct ScriptRequest {
    pub method: String,
    pub scheme: String,
    pub host: String,
    pub port: u16,
    pub path: String,
    pub query: String,
    pub headers: Vec<(String, String)>,
    pub body: String,
}

/// What a run leaves behind.
#[derive(Debug, Default, Deserialize)]
pub(crate) struct Outcome {
    pub headers: Vec<(String, String)>,
    pub query: String,
    /// The variables it set.
    pub set: Vec<(String, String)>,
}

fn text_arg(args: &[JsValue], i: usize, ctx: &mut Context) -> JsResult<String> {
    Ok(args.get(i).cloned().unwrap_or_default().to_string(ctx)?.to_std_string_escaped())
}

fn bytes_arg(args: &[JsValue], i: usize, ctx: &mut Context) -> JsResult<Vec<u8>> {
    hex::decode(text_arg(args, i, ctx)?).map_err(|_| JsError::from_opaque(js_string!("bad bytes").into()))
}

fn js_text(s: &str) -> JsValue {
    JsString::from(s).into()
}

fn digest_of(alg: &str, data: &[u8]) -> JsResult<Vec<u8>> {
    use md5::Md5;
    use sha1::Sha1;
    use sha2::{Sha256, Sha384, Sha512};
    Ok(match alg {
        "md5" => Md5::digest(data).to_vec(),
        "sha1" => Sha1::digest(data).to_vec(),
        "sha256" => Sha256::digest(data).to_vec(),
        "sha384" => Sha384::digest(data).to_vec(),
        "sha512" => Sha512::digest(data).to_vec(),
        _ => return Err(JsError::from_opaque(js_string!("unknown hash").into())),
    })
}

fn native_digest(_: &JsValue, args: &[JsValue], ctx: &mut Context) -> JsResult<JsValue> {
    let alg = text_arg(args, 0, ctx)?;
    let data = bytes_arg(args, 1, ctx)?;
    Ok(js_text(&hex::encode(digest_of(&alg, &data)?)))
}

fn native_hmac(_: &JsValue, args: &[JsValue], ctx: &mut Context) -> JsResult<JsValue> {
    let alg = text_arg(args, 0, ctx)?;
    let key = bytes_arg(args, 1, ctx)?;
    let data = bytes_arg(args, 2, ctx)?;
    let mac = match alg.as_str() {
        "sha1" => crate::sign::hmac_digest(crate::sign::HmacAlg::Sha1, &key, &data),
        "sha256" => crate::sign::hmac_digest(crate::sign::HmacAlg::Sha256, &key, &data),
        "sha384" => crate::sign::hmac_digest(crate::sign::HmacAlg::Sha384, &key, &data),
        "sha512" => crate::sign::hmac_digest(crate::sign::HmacAlg::Sha512, &key, &data),
        "md5" => hmac_md5(&key, &data),
        _ => return Err(JsError::from_opaque(js_string!("unknown HMAC hash").into())),
    };
    Ok(js_text(&hex::encode(mac)))
}

fn hmac_md5(key: &[u8], data: &[u8]) -> Vec<u8> {
    use md5::{Digest as _, Md5};
    let mut block = [0u8; 64];
    if key.len() > 64 {
        block[..16].copy_from_slice(&Md5::digest(key));
    } else {
        block[..key.len()].copy_from_slice(key);
    }
    let pad = |x: u8| block.iter().map(|b| b ^ x).collect::<Vec<u8>>();
    let inner = Md5::new().chain_update(pad(0x36)).chain_update(data).finalize();
    Md5::new().chain_update(pad(0x5c)).chain_update(inner).finalize().to_vec()
}

fn native_utf8_to_hex(_: &JsValue, args: &[JsValue], ctx: &mut Context) -> JsResult<JsValue> {
    let s = args.first().cloned().unwrap_or_default().to_string(ctx)?;
    Ok(js_text(&hex::encode(String::from_utf16_lossy(s.as_str().to_vec().as_slice()))))
}

fn native_hex_to_utf8(_: &JsValue, args: &[JsValue], ctx: &mut Context) -> JsResult<JsValue> {
    Ok(js_text(&String::from_utf8_lossy(&bytes_arg(args, 0, ctx)?)))
}

fn native_latin1_to_hex(_: &JsValue, args: &[JsValue], ctx: &mut Context) -> JsResult<JsValue> {
    let s = args.first().cloned().unwrap_or_default().to_string(ctx)?;
    let bytes: Vec<u8> = s.as_str().to_vec().iter().map(|u| *u as u8).collect();
    Ok(js_text(&hex::encode(bytes)))
}

fn native_hex_to_latin1(_: &JsValue, args: &[JsValue], ctx: &mut Context) -> JsResult<JsValue> {
    let units: Vec<u16> = bytes_arg(args, 0, ctx)?.iter().map(|b| u16::from(*b)).collect();
    Ok(JsString::from(units.as_slice()).into())
}

fn native_hex_to_b64(_: &JsValue, args: &[JsValue], ctx: &mut Context) -> JsResult<JsValue> {
    Ok(js_text(&STANDARD.encode(bytes_arg(args, 0, ctx)?)))
}

fn native_b64_to_hex(_: &JsValue, args: &[JsValue], ctx: &mut Context) -> JsResult<JsValue> {
    let text = text_arg(args, 0, ctx)?;
    let bytes = STANDARD
        .decode(text.trim())
        .or_else(|_| URL_SAFE_NO_PAD.decode(text.trim().trim_end_matches('=')))
        .map_err(|_| JsError::from_opaque(js_string!("bad base64").into()))?;
    Ok(js_text(&hex::encode(bytes)))
}

fn native_random_hex(_: &JsValue, args: &[JsValue], ctx: &mut Context) -> JsResult<JsValue> {
    let n = args.first().cloned().unwrap_or_default().to_u32(ctx)?.min(4096) as usize;
    let mut b = vec![0u8; n];
    ring::rand::SystemRandom::new()
        .fill(&mut b)
        .map_err(|_| JsError::from_opaque(js_string!("no random bytes").into()))?;
    Ok(js_text(&hex::encode(b)))
}

type Native = fn(&JsValue, &[JsValue], &mut Context) -> JsResult<JsValue>;

fn run_here(script: &str, vars: &[(String, String)], request: &ScriptRequest) -> std::result::Result<Outcome, String> {
    let mut ctx = Context::default();
    let limits = ctx.runtime_limits_mut();
    limits.set_loop_iteration_limit(LOOP_LIMIT);
    limits.set_recursion_limit(RECURSION_LIMIT);
    let natives: [(&str, usize, Native); 9] = [
        ("__digest", 2, native_digest),
        ("__hmac", 3, native_hmac),
        ("__utf8ToHex", 1, native_utf8_to_hex),
        ("__hexToUtf8", 1, native_hex_to_utf8),
        ("__latin1ToHex", 1, native_latin1_to_hex),
        ("__hexToLatin1", 1, native_hex_to_latin1),
        ("__hexToB64", 1, native_hex_to_b64),
        ("__b64ToHex", 1, native_b64_to_hex),
        ("__randomHex", 1, native_random_hex),
    ];
    let shim_failed = |_| "the script runner failed to start".to_string();
    for (name, len, f) in natives {
        ctx.register_global_callable(JsString::from(name), len, NativeFunction::from_fn_ptr(f)).map_err(shim_failed)?;
    }
    let input = serde_json::json!({"vars": vars, "request": request}).to_string();
    let global = ctx.global_object();
    global
        .set(js_string!("__input"), js_text(&input), false, &mut ctx)
        .map_err(|_| "the script runner failed to start".to_string())?;
    ctx.eval(Source::from_bytes(SHIM)).map_err(|e| format!("the script runner failed to start: {e}"))?;
    let explain = |e: JsError, ctx: &mut Context| {
        let text = e.try_native(ctx).map_or_else(|_| "it threw a value".to_string(), |n| n.to_string());
        match text.split_once("__unsupported:") {
            Some((_, name)) => {
                format!("it uses {}, which isn't available here", name.chars().take(80).collect::<String>())
            }
            None => text.chars().take(200).collect(),
        }
    };
    if let Err(e) = ctx.eval(Source::from_bytes(script)) {
        return Err(explain(e, &mut ctx));
    }
    let _ = ctx.run_jobs();
    let done = ctx.eval(Source::from_bytes("__finish()")).map_err(|e| explain(e, &mut ctx))?;
    let text = done.to_string(&mut ctx).map_err(|e| explain(e, &mut ctx))?.to_std_string_escaped();
    serde_json::from_str(&text).map_err(|_| "its result couldn't be read".to_string())
}

/// Runs `script` over `request`, on its own thread: deep recursion needs a large stack, and
/// a run past the time limit is left behind rather than holding up the scan. Messages
/// have the values of `vars` masked, as a script's own errors can quote them.
pub(crate) fn run(
    script: &str,
    vars: Vec<(String, String)>,
    request: ScriptRequest,
) -> std::result::Result<Outcome, String> {
    let (send, recv) = mpsc::channel();
    let script = script.to_string();
    let secrets: Vec<String> = vars.iter().map(|(_, v)| v.clone()).filter(|v| v.len() >= 4).collect();
    std::thread::Builder::new()
        .name("postman-script".into())
        .stack_size(STACK_BYTES)
        .spawn(move || {
            let _ = send.send(run_here(&script, &vars, &request));
        })
        .map_err(|_| "the script couldn't start".to_string())?;
    let result = recv.recv_timeout(TIME_LIMIT).map_err(|_| "it ran past the time limit".to_string())?;
    result.map_err(|mut e| {
        for s in &secrets {
            e = e.replace(s.as_str(), "********");
        }
        e
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn request() -> ScriptRequest {
        ScriptRequest {
            method: "POST".into(),
            scheme: "https".into(),
            host: "api.test".into(),
            port: 443,
            path: "/v1/items".into(),
            query: "a=1&b=x%20y".into(),
            headers: vec![("Host".into(), "api.test".into()), ("Content-Type".into(), "application/json".into())],
            body: "{\"n\":1}".into(),
        }
    }

    fn go(script: &str) -> std::result::Result<Outcome, String> {
        run(script, vec![("secret".into(), "k3y-value".into()), ("base".into(), "https://api.test".into())], request())
    }

    fn header<'a>(o: &'a Outcome, name: &str) -> &'a str {
        o.headers.iter().find(|(k, _)| k == name).map_or("", |(_, v)| v.as_str())
    }

    #[test]
    fn a_typical_signing_script_matches_a_real_hmac() {
        let o = go(r#"
            const secret = pm.environment.get("secret");
            const ts = "1700000000";
            const text = [pm.request.method, pm.request.url.getPath(), pm.request.url.getQueryString(), ts,
                          CryptoJS.SHA256(pm.request.body.toString()).toString(CryptoJS.enc.Hex)].join("\n");
            const sig = CryptoJS.HmacSHA256(text, secret).toString(CryptoJS.enc.Base64);
            pm.request.headers.upsert({key: "X-Signature", value: sig});
            pm.request.headers.add({key: "X-Timestamp", value: ts});
            pm.request.url.query.add({key: "ts", value: ts});
            pm.collectionVariables.set("sig", sig);
        "#)
        .unwrap();
        let body_hash = hex::encode(sha2::Sha256::digest(b"{\"n\":1}"));
        let text = format!("POST\n/v1/items\na=1&b=x%20y\n1700000000\n{body_hash}");
        let want =
            STANDARD.encode(crate::sign::hmac_digest(crate::sign::HmacAlg::Sha256, b"k3y-value", text.as_bytes()));
        assert_eq!(header(&o, "X-Signature"), want);
        assert_eq!(header(&o, "X-Timestamp"), "1700000000");
        assert_eq!(o.query, "a=1&b=x%20y&ts=1700000000");
        assert_eq!(o.set, [("sig".to_string(), want)]);
    }

    #[test]
    fn a_request_with_no_body_still_has_one_to_read() {
        let mut r = request();
        r.body = String::new();
        let o = run(
            "pm.environment.set('b', '[' + pm.request.body.toString() + ']' + pm.request.body.isEmpty());",
            vec![],
            r,
        );
        assert_eq!(o.unwrap().set, [("b".to_string(), "[]true".to_string())]);
    }

    #[test]
    fn the_older_api_and_modules_work() {
        let o = go(r#"
            var c = require("crypto-js");
            var hash = c.MD5("abc").toString();
            var node = require("crypto").createHmac("sha256", "k").update("abc").digest("hex");
            var word = c.enc.Utf8.parse("abc");
            var again = c.enc.Base64.stringify(word);
            var viaHasher = c.algo.HMAC.create(c.algo.SHA1, "k").update("a").finalize("bc").toString();
            postman.setEnvironmentVariable("out", [hash, node, again, btoa("abc"), viaHasher, request.method].join("|"));
            pm.request.headers.remove("content-type");
        "#)
        .unwrap();
        let (_, out) = &o.set[0];
        let mac = hex::encode(crate::sign::hmac_digest(crate::sign::HmacAlg::Sha256, b"k", b"abc"));
        let sha1 = hex::encode(crate::sign::hmac_digest(crate::sign::HmacAlg::Sha1, b"k", b"abc"));
        assert_eq!(*out, format!("900150983cd24fb0d6963f7d28e17f72|{mac}|YWJj|YWJj|{sha1}|POST"));
        assert_eq!(header(&o, "Content-Type"), "");
    }

    #[test]
    fn hmac_md5_matches_rfc_2202() {
        assert_eq!(hex::encode(hmac_md5(b"Jefe", b"what do ya want for nothing?")), "750c783e6ab0b503eaa86e310a5db738");
    }

    #[test]
    fn what_has_no_place_here_is_refused_and_says_so() {
        for (script, what) in [
            ("pm.sendRequest('http://evil.test', () => {})", "pm.sendRequest"),
            ("require('fs')", "require('fs')"),
            ("pm.request.url = 'http://evil.test'", "changing pm.request.url"),
            ("pm.request.method = 'DELETE'", "changing pm.request.method"),
        ] {
            let Err(e) = go(script) else { panic!("{script} ran") };
            assert!(e.contains(what), "{e}");
        }
        for script in ["fetch('http://x')", "new XMLHttpRequest()", "process.exit(1)", "Deno.exit()"] {
            assert!(go(script).is_err(), "{script}");
        }
    }

    #[test]
    fn a_runaway_script_ends_and_errors_keep_secrets_out() {
        assert!(go("while (true) {}").is_err());
        assert!(go("function f() { return f(); } f();").is_err());
        let e = go("throw new Error('leak ' + pm.environment.get('secret'))").err().unwrap();
        assert!(e.contains("********") && !e.contains("k3y-value"), "{e}");
    }

    #[test]
    fn scripts_are_found_with_their_reach() {
        let doc = json!({
            "event": [{"listen": "prerequest", "script": {"exec": ["a();", "b();"]}},
                      {"listen": "test", "script": {"exec": ["t();"]}}],
            "item": [
                {"name": "F", "event": [{"listen": "prerequest", "script": {"exec": "c();"}}],
                 "item": [{"name": "R", "request": {"url": "http://a.test"},
                           "event": [{"listen": "prerequest", "script": {"exec": [""]}}]}]},
                {"name": "S", "request": {"url": "http://a.test"},
                 "event": [{"listen": "prerequest", "disabled": true, "script": {"exec": ["d();"]}}]}
            ]
        });
        let found = prerequest_scripts(&doc);
        assert_eq!(found.len(), 2);
        assert_eq!(
            (found[0].scope.as_str(), found[0].text.as_str(), found[0].requests),
            ("collection", "a();\nb();", 2)
        );
        assert_eq!((found[1].scope.as_str(), found[1].requests), ("F", 1));
        assert!(seems_to_sign("CryptoJS.HmacSHA256(a, b)") && !seems_to_sign("pm.environment.set('a', 1)"));
        assert_eq!(unsupported_calls("pm.sendRequest(x); pm.cookies.get('a')"), ["pm.sendRequest", "pm.cookies"]);
        assert!(check_syntax("const a = 1;").is_ok());
        assert!(check_syntax("const = ;").is_err());
    }

    #[test]
    fn templates_belong_to_their_request() {
        let doc = json!({
            "auth": {"type": "bearer", "bearer": [{"key": "token", "value": "{{tok}}"}]},
            "item": [
                {"name": "R", "request": {"method": "POST", "url": "{{base}}/v1/items/:id",
                    "header": [{"key": "X-Sig", "value": "First {{sig}}"}, {"key": "X-Plain", "value": "1"},
                               {"key": "X-Off", "value": "{{off}}", "disabled": true}]}},
                {"name": "F", "auth": {"type": "noauth"}, "item": [
                    {"name": "S", "request": {"url": {"raw": "http://a.test/two", "path": ["two"]},
                        "header": [{"key": "X-Sig", "value": "Second {{sig}}"}]}}]}
            ]
        });
        let t = header_templates(&doc);
        let pair = |k: &str, v: &str| (k.to_string(), v.to_string());
        assert_eq!(t[0].headers, [pair("Authorization", "Bearer {{tok}}"), pair("X-Sig", "First {{sig}}")]);
        assert_eq!(t[1].headers, [pair("X-Sig", "Second {{sig}}")], "the folder's noauth wins");
        assert!(t[0].score("post", "/api/v1/items/42").is_some() && t[0].score("GET", "/api/v1/items/42").is_none());
        assert!(
            t[0].score("POST", "/two").is_none()
                && t[1].score("GET", "/two").is_some()
                && t[1].score("GET", "/v1/items/42").is_none()
        );
        // The most specific fits, and encoded segments compare decoded on both sides.
        let tpl = |path: &[&str], h: &str| Templates {
            method: "GET".into(),
            path: path.iter().map(|s| s.to_string()).collect(),
            headers: vec![(h.to_string(), "{{sig}}".to_string())],
        };
        let all = [tpl(&["users"], "X-User-Sig"), tpl(&["admin", "users"], "X-Admin-Sig"), tpl(&["a%20b"], "X-Space")];
        assert_eq!(templates_for(&all, "GET", "/api/admin/users").unwrap().headers[0].0, "X-Admin-Sig");
        assert_eq!(templates_for(&all, "GET", "/api/users").unwrap().headers[0].0, "X-User-Sig");
        assert_eq!(templates_for(&all, "GET", "/a%20b").unwrap().headers[0].0, "X-Space");
        let tie = [tpl(&["users"], "X-First"), tpl(&["users"], "X-Second")];
        assert_eq!(
            templates_for(&tie, "GET", "/users").unwrap().headers[0].0,
            "X-First",
            "a tie keeps collection order"
        );
    }
}
