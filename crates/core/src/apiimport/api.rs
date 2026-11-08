//! `import api` and `scan active --api`: a document of any supported format turned
//! into requests under stricter rules than the format-specific commands. Credentials
//! in the document are never sent or stored, only reported; what can't be built is
//! listed rather than fatal, so a caller can ask for a base URL and look again.

use std::collections::BTreeMap;
use std::sync::LazyLock;

use regex::Regex;
use serde::Serialize;
use serde_json::Value;

use super::postman::Variable;
use super::values::{resolve, scalar};
use super::{
    build_raw, graphql, har, looks_secret, merge_credential, openapi, parse_base, parse_document, postman, shown_url,
    ApiRequest, Built, Credential, Skipped, MAX_DOCUMENT,
};
use crate::auth::MARK;
use crate::error::{Error, Result};
use crate::guard::Guard;
use crate::http::request::find;
use crate::http::{RawRequest, Target};

/// Methods sent and attacked by default. Not all safe: POST can change data or send email,
/// but a scan without it misses too much, so it stays on with a warning. Replaying the
/// others (DELETE, PUT, PATCH, ...) is opt-in.
pub const DEFAULT_METHODS: &[&str] = &["GET", "HEAD", "OPTIONS", "POST"];

const MASK: &str = "********";

const ACCEPTED: &str = "accepted formats: OpenAPI 3.x, Swagger 2.0, and Postman collection v2.0/v2.1, as JSON or \
     YAML; a GraphQL schema or introspection result; a HAR file";

/// What `--include-methods` calls GraphQL mutations, which all travel as POST.
pub const MUTATION: &str = "MUTATION";

/// What a recorded request needs opting in to with `--include-methods`, unless sent by
/// default (`free`): its method, and MUTATION too for a GraphQL mutation, or an operation
/// that can't be shown read-only. Both count: a DELETE that looks like a persisted query
/// needs DELETE as well as MUTATION. None when `included` has them all, or ALL (a scan's
/// check, a scan's or `authz run`'s named request).
pub fn missing_opt_in(request: &[u8], free: &[&str], included: &[String]) -> Option<String> {
    if included.iter().any(|m| m.eq_ignore_ascii_case("ALL")) {
        return None;
    }
    let method =
        RawRequest::from_bytes(request.to_vec()).head().map(|h| h.method.to_ascii_uppercase()).unwrap_or_default();
    let mutation = super::graphql::is_mutation_request(request).then(|| MUTATION.to_string());
    let given = |m: &str| free.contains(&m) || included.iter().any(|i| i.eq_ignore_ascii_case(m));
    [Some(method), mutation].into_iter().flatten().find(|m| !given(m))
}

#[derive(Debug, Clone, Copy, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Format {
    Openapi3,
    Swagger2,
    Postman,
    Graphql,
    Har,
}

impl Format {
    fn describe(self) -> &'static str {
        match self {
            Format::Openapi3 => "an OpenAPI 3 document",
            Format::Swagger2 => "a Swagger 2.0 document",
            Format::Postman => "a Postman collection",
            Format::Graphql => "a GraphQL schema",
            Format::Har => "a HAR file",
        }
    }
}

/// What only a HAR file's import takes.
#[derive(Debug, Default, Clone)]
pub struct HarOptions {
    /// Keep scripts, styles, images, fonts and media.
    pub keep_static: bool,
    /// Send the recorded `Cookie`, `Authorization` and other credential headers as they were
    /// recorded, instead of leaving them out. They are still listed in `credentials`, and
    /// masked in the preview.
    pub keep_credentials: bool,
}

#[derive(Debug, Default, Clone)]
pub struct Options {
    pub base_url: Option<String>,
    pub server: Option<usize>,
    pub vars: Vec<(String, String)>,
    pub expect_sha256: Option<String>,
    /// The text of a Postman environment file, and the hash it must have.
    pub environment: Option<String>,
    pub expect_environment_sha256: Option<String>,
    /// Where the document was fetched from.
    pub spec_url: Option<String>,
    pub har: HarOptions,
    /// Refuse anything but a HAR file (`import har`).
    pub require_har: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct Server {
    pub index: usize,
    pub url: String,
    pub description: Option<String>,
}

/// A document turned into requests. A request's index in `requests` identifies it
/// for one document and one set of options.
#[derive(Debug)]
pub struct Loaded {
    pub format: Format,
    pub title: Option<String>,
    pub version: Option<String>,
    pub document_sha256: String,
    pub servers: Vec<Server>,
    pub base_url_required: bool,
    pub variables: Vec<Variable>,
    pub unresolved_variables: Vec<String>,
    pub credentials: Vec<Credential>,
    pub skipped: Vec<Skipped>,
    pub warnings: Vec<String>,
    pub requests: Vec<ApiRequest>,
    pub environment: Option<EnvironmentInfo>,
    pub scripts: Vec<ScriptInfo>,
    pub oauth: Vec<OAuthHint>,
    pub aws: Vec<AwsHint>,
    /// A HAR file's recorded credential headers are sent (`--keep-credentials`).
    pub credentials_kept: bool,
}

/// An OAuth setup a document declares: never a client secret, only where to get tokens.
#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct OAuthHint {
    pub source: String,
    /// As `auth add --oauth-flow` names it; none for OpenID Connect.
    pub flow: Option<String>,
    pub token_url: Option<String>,
    pub authorize_url: Option<String>,
    pub scopes: Vec<String>,
    pub openid_url: Option<String>,
}

/// A Postman collection's AWS Signature settings.
#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct AwsHint {
    pub source: String,
    pub region: Option<String>,
    pub service: Option<String>,
}

/// The OAuth setups in an OpenAPI or Swagger document's security schemes.
fn declared_oauth(doc: &Value) -> Vec<OAuthHint> {
    let mut out = Vec::new();
    let roots = [doc.pointer("/components/securitySchemes"), doc.get("securityDefinitions")];
    for (name, scheme) in roots.into_iter().flatten().filter_map(Value::as_object).flatten() {
        let s = resolve(doc, scheme);
        let text = |v: &Value, k: &str| v.get(k).and_then(Value::as_str).map(str::to_string);
        let scopes = |v: &Value| -> Vec<String> {
            v.get("scopes").and_then(Value::as_object).map(|m| m.keys().cloned().collect()).unwrap_or_default()
        };
        let source = format!("scheme:{name}");
        match text(s, "type").unwrap_or_default().to_ascii_lowercase().as_str() {
            "openidconnect" => out.push(OAuthHint {
                source,
                flow: None,
                token_url: None,
                authorize_url: None,
                scopes: vec![],
                openid_url: text(s, "openIdConnectUrl"),
            }),
            "oauth2" => {
                // OpenAPI 3 lists flows by name; Swagger 2 has one, in its own words.
                let flows = s.get("flows").and_then(Value::as_object).cloned().unwrap_or_default();
                let mut add = |flow: &str, v: &Value| {
                    out.push(OAuthHint {
                        source: source.clone(),
                        flow: Some(flow.to_string()),
                        token_url: text(v, "tokenUrl"),
                        authorize_url: text(v, "authorizationUrl"),
                        scopes: scopes(v),
                        openid_url: None,
                    })
                };
                for (k, flow) in [
                    ("clientCredentials", "client_credentials"),
                    ("authorizationCode", "authorization_code"),
                    ("password", "password"),
                ] {
                    if let Some(v) = flows.get(k) {
                        add(flow, v);
                    }
                }
                match text(s, "flow").as_deref() {
                    Some("application") => add("client_credentials", s),
                    Some("accessCode") => add("authorization_code", s),
                    Some("password") => add("password", s),
                    _ => {}
                }
            }
            _ => {}
        }
    }
    out
}

/// A Postman auth block's setting. `known` fills variables whose values may be shown; a
/// setting that still needs one is left out, as it can't be used as written.
fn postman_auth_setting(auth: &Value, kind: &str, key: &str, known: &[Variable]) -> Option<String> {
    let raw = match auth.get(kind)? {
        Value::Array(items) => {
            items.iter().find(|i| i.get("key").and_then(Value::as_str) == Some(key))?.get("value")?.as_str()?
        }
        section => section.get(key)?.as_str()?,
    };
    let mut text = raw.to_string();
    for v in known {
        if let Some(value) = v.value.as_deref().filter(|_| !v.secret) {
            text = text.replace(&format!("{{{{{}}}}}", v.name), value);
        }
    }
    (!text.is_empty() && !text.contains("{{")).then_some(text)
}

/// The OAuth and AWS settings in a collection's auth blocks. Client ids and secrets stay out.
fn postman_auth_hints(doc: &Value, known: &[Variable]) -> (Vec<OAuthHint>, Vec<AwsHint>) {
    fn walk(node: &Value, label: &str, known: &[Variable], out: &mut (Vec<OAuthHint>, Vec<AwsHint>)) {
        let source = format!("auth:{label}");
        let auth = node.get("auth").or(node.pointer("/request/auth"));
        match auth.and_then(|a| a.get("type")).and_then(Value::as_str) {
            Some("oauth2") => {
                let a = auth.unwrap_or(&Value::Null);
                let flow = match postman_auth_setting(a, "oauth2", "grant_type", known).as_deref() {
                    Some("client_credentials") => Some("client_credentials"),
                    Some("password_credentials") => Some("password"),
                    Some("authorization_code" | "authorization_code_with_pkce") => Some("authorization_code"),
                    _ => None,
                };
                let hint = OAuthHint {
                    source,
                    flow: flow.map(str::to_string),
                    token_url: postman_auth_setting(a, "oauth2", "accessTokenUrl", known),
                    authorize_url: postman_auth_setting(a, "oauth2", "authUrl", known),
                    scopes: postman_auth_setting(a, "oauth2", "scope", known)
                        .map(|s| s.split_whitespace().map(str::to_string).collect())
                        .unwrap_or_default(),
                    openid_url: None,
                };
                if !out.0.contains(&hint) {
                    out.0.push(hint);
                }
            }
            Some("awsv4") => {
                let a = auth.unwrap_or(&Value::Null);
                let hint = AwsHint {
                    source,
                    region: postman_auth_setting(a, "awsv4", "region", known),
                    service: postman_auth_setting(a, "awsv4", "service", known),
                };
                if !out.1.iter().any(|h| h.region == hint.region && h.service == hint.service) {
                    out.1.push(hint);
                }
            }
            _ => {}
        }
        for item in node.get("item").and_then(Value::as_array).into_iter().flatten() {
            let name = item.get("name").and_then(Value::as_str).unwrap_or("(unnamed)");
            let child = if label == "collection" { name.to_string() } else { format!("{label}/{name}") };
            walk(item, &child, known, out);
        }
    }
    let mut out = Default::default();
    walk(doc, "collection", known, &mut out);
    out
}

/// The environment file a preview used.
#[derive(Debug, Clone, Serialize)]
pub struct EnvironmentInfo {
    pub name: Option<String>,
    pub sha256: String,
    pub variables: usize,
}

/// A document's URL ends up in history, messages, and the job table: no credentials in it.
pub fn check_source(source: &str) -> Result<()> {
    let Some(u) = url::Url::parse(source).ok().filter(|u| matches!(u.scheme(), "http" | "https")) else {
        return Ok(());
    };
    if !u.username().is_empty() || u.password().is_some() {
        return Err(Error::InvalidInput("the document's URL holds a username or password; use --auth".into()));
    }
    if let Some((k, _)) = u.query_pairs().find(|(k, _)| looks_secret(k)) {
        return Err(Error::InvalidInput(format!("the document's URL holds a credential ({k}); use --auth")));
    }
    Ok(())
}

/// A --base-url going in the job table: no credentials in it either.
pub fn check_base_url(base: &str) -> Result<()> {
    let u = parse_base(base)?;
    if !u.username().is_empty() || u.password().is_some() || u.query_pairs().any(|(k, _)| looks_secret(&k)) {
        return Err(Error::InvalidInput(
            "--base-url holds a credential and --background would store it with the job; use an auth profile".into(),
        ));
    }
    Ok(())
}

/// Parses `text`, works out its format, and builds its requests.
pub fn load(text: &str, opts: &Options) -> Result<Loaded> {
    let document_sha256 = crate::fetch::sha256_hex(text.as_bytes());
    if let Some(want) = opts.expect_sha256.as_deref().filter(|w| !w.trim().eq_ignore_ascii_case(&document_sha256)) {
        return Err(Error::InvalidInput(format!(
            "the document changed: its sha256 is {document_sha256}, expected {}",
            want.trim()
        )));
    }
    if let Some(b) = &opts.base_url {
        parse_base(b)?;
    }
    let (format, doc) = detect(text)?;
    let info = doc.get("info").unwrap_or(&Value::Null);
    let field = |keys: &[&str]| {
        keys.iter().filter_map(|k| info.get(*k)).find(|v| matches!(v, Value::String(_) | Value::Number(_))).map(scalar)
    };
    let (title, version) = (field(&["title", "name"]), field(&["version"]));
    let mut loaded = Loaded {
        format,
        title,
        version,
        document_sha256,
        servers: vec![],
        base_url_required: false,
        variables: vec![],
        unresolved_variables: vec![],
        credentials: vec![],
        skipped: vec![],
        warnings: vec![],
        requests: vec![],
        environment: None,
        scripts: vec![],
        oauth: vec![],
        aws: vec![],
        credentials_kept: false,
    };
    if opts.require_har && format != Format::Har {
        return Err(Error::InvalidInput(format!(
            "this is {}, not a HAR file: use `import api` for it",
            format.describe()
        )));
    }
    if format != Format::Har && (opts.har.keep_static || opts.har.keep_credentials) {
        return Err(Error::InvalidInput("--keep-static and --keep-credentials are for HAR files".into()));
    }
    let environment = match &opts.environment {
        Some(text) => {
            if format != Format::Postman {
                return Err(Error::InvalidInput("--environment is for Postman collections".into()));
            }
            let sha256 = crate::fetch::sha256_hex(text.as_bytes());
            let want = opts.expect_environment_sha256.as_deref();
            if let Some(want) = want.filter(|w| !w.trim().eq_ignore_ascii_case(&sha256)) {
                return Err(Error::InvalidInput(format!(
                    "the environment file changed: its sha256 is {sha256}, expected {}",
                    want.trim()
                )));
            }
            let env = postman::parse_environment(text)?;
            loaded.environment = Some(EnvironmentInfo { name: env.name.clone(), sha256, variables: env.values.len() });
            env
        }
        None => postman::Environment::default(),
    };
    let mut built = match format {
        Format::Graphql => {
            if opts.server.is_some() {
                return Err(Error::InvalidInput("--server: a GraphQL schema has no servers".into()));
            }
            if !opts.vars.is_empty() {
                loaded.warnings.push("--var only applies to Postman collections; it was ignored".into());
            }
            match opts.base_url.as_deref().or(opts.spec_url.as_deref()) {
                Some(endpoint) => graphql::build(&doc, endpoint, true)?,
                None => {
                    let mut b = Built { base_url_required: true, ..Default::default() };
                    b.skip("every operation".into(), "a schema file names no endpoint: give the GraphQL URL".into());
                    b
                }
            }
        }
        Format::Postman => {
            if opts.server.is_some() {
                return Err(Error::InvalidInput("--server: a Postman collection has no servers".into()));
            }
            loaded.scripts = postman_scripts(&doc);
            let a = postman::analyze(&doc, &environment, &opts.vars);
            loaded.variables = a.variables;
            (loaded.oauth, loaded.aws) = postman_auth_hints(&doc, &loaded.variables);
            loaded.unresolved_variables = a.unresolved;
            loaded.credentials = a.credentials;
            loaded.warnings = a.warnings;
            postman::build(
                &doc,
                &postman::Options {
                    base_url: opts.base_url.clone(),
                    vars: environment
                        .values
                        .iter()
                        .map(|v| (v.name.clone(), v.value.clone()))
                        .chain(opts.vars.iter().cloned())
                        .collect(),
                    guarded: true,
                    withheld: a.withheld,
                },
            )?
        }
        Format::Har => {
            if opts.server.is_some() {
                return Err(Error::InvalidInput("--server: a HAR file has no servers".into()));
            }
            if !opts.vars.is_empty() {
                loaded.warnings.push("--var only applies to Postman collections; it was ignored".into());
            }
            let o = har::Options { base_url: opts.base_url.clone(), keep_static: opts.har.keep_static };
            let (built, creator) = har::build(text, &o)?;
            (loaded.title, loaded.version) = (creator.name, creator.version);
            loaded.credentials_kept = opts.har.keep_credentials;
            built
        }
        Format::Openapi3 | Format::Swagger2 => {
            if !doc.get("paths").is_none_or(Value::is_object) {
                return Err(Error::InvalidInput("the document's \"paths\" must be an object".into()));
            }
            if !opts.vars.is_empty() {
                loaded.warnings.push("--var only applies to Postman collections; it was ignored".into());
            }
            let o = openapi::Options {
                base_url: opts.base_url.clone(),
                spec_url: opts.spec_url.clone(),
                server: opts.server,
                guarded: true,
            };
            let listed = openapi::servers(&doc, &o);
            if let Some(n) = opts.server.filter(|n| *n >= listed.len()) {
                return Err(Error::InvalidInput(format!(
                    "--server {n}: the document lists {} server(s), counted from 0",
                    listed.len()
                )));
            }
            loaded.servers = listed
                .into_iter()
                .enumerate()
                .map(|(index, (url, description))| Server { index, url: shown_url(&url), description })
                .collect();
            loaded.credentials = security_schemes(&doc);
            loaded.oauth = declared_oauth(&doc);
            openapi::build(&doc, &o)?
        }
    };
    harden(&mut built, format, &loaded.credentials, loaded.credentials_kept);
    built.credentials.drain(..).for_each(|c| merge_credential(&mut loaded.credentials, c));
    loaded.warnings.append(&mut built.warnings);
    loaded.base_url_required = built.base_url_required;
    loaded.skipped = built.skipped;
    loaded.requests = built.requests;
    Ok(loaded)
}

fn detect(text: &str) -> Result<(Format, Value)> {
    let t = text.trim_start_matches('\u{feff}').trim_start();
    let unknown = |what: &str| Error::InvalidInput(format!("{what}; {ACCEPTED}"));
    if t.is_empty() {
        return Err(unknown("the document is empty"));
    }
    // Only a HAR file may be larger: it often holds every response, which isn't read.
    if t.len() > MAX_DOCUMENT {
        if t.starts_with('{') && har::is_har(t) {
            return Ok((Format::Har, Value::Null));
        }
        return Err(Error::InvalidInput(format!(
            "the document is larger than {} MiB (a HAR file may be up to {} MiB)",
            MAX_DOCUMENT >> 20,
            har::MAX_HAR >> 20
        )));
    }
    if graphql::looks_like_sdl(t) {
        return Ok((Format::Graphql, graphql::parse_sdl(t)?));
    }
    if t.starts_with('<') {
        return Err(unknown("this looks like HTML or XML, not an API description"));
    }
    let mut doc = parse_document(text)
        .map_err(|_| unknown(&format!("the document is not valid JSON or YAML{}", where_invalid(t))))?;
    if !doc.is_object() {
        return Err(unknown("the document is not a JSON or YAML object"));
    }
    // YAML reads an unquoted 2.0 or 3.1 as a number.
    let version = |d: &Value, k: &str| d.get(k).filter(|v| !v.is_null()).map(scalar);
    let short = |v: String| v.chars().take(20).collect::<String>();
    if let Some(v) = version(&doc, "openapi") {
        if !v.starts_with("3.") {
            return Err(unknown(&format!("OpenAPI version {:?} isn't supported", short(v))));
        }
        doc["openapi"] = Value::String(v);
        return Ok((Format::Openapi3, doc));
    }
    if let Some(v) = version(&doc, "swagger") {
        if !v.starts_with("2") {
            return Err(unknown(&format!("Swagger version {:?} isn't supported", short(v))));
        }
        doc["swagger"] = Value::String(v);
        return Ok((Format::Swagger2, doc));
    }
    if let Some(v) = version(&doc, "swaggerVersion") {
        return Err(unknown(&format!("Swagger version {:?} isn't supported", short(v))));
    }
    let schema = doc.pointer("/info/schema").and_then(Value::as_str).unwrap_or_default();
    if schema.contains("/collection/v1") || (doc.get("requests").is_some() && doc.get("order").is_some()) {
        return Err(unknown("Postman collection v1 isn't supported; export it as v2.1"));
    }
    if doc.get("item").is_some_and(Value::is_array) {
        return Ok((Format::Postman, doc));
    }
    if doc.get("_postman_variable_scope").is_some() {
        return Err(unknown("this is a Postman environment, not a collection: pass it with --environment"));
    }
    if doc.pointer("/data/__schema").is_some() || doc.get("__schema").is_some() {
        return Ok((Format::Graphql, doc));
    }
    if doc.get("errors").is_some() {
        return Err(unknown("this is a GraphQL error, not a schema: introspection may be turned off"));
    }
    if doc.pointer("/log/entries").is_some_and(Value::is_array) {
        return Ok((Format::Har, doc));
    }
    Err(unknown("the document's format wasn't recognised (no \"openapi\", \"swagger\", or Postman \"item\" field)"))
}

/// Where JSON parsing stopped, for a document that looks like JSON. Never the text there.
fn where_invalid(text: &str) -> String {
    if !text.starts_with(['{', '[']) {
        return String::new();
    }
    serde_json::from_str::<serde::de::IgnoredAny>(text)
        .err()
        .map(|e| format!(" (line {}, column {})", e.line(), e.column()))
        .unwrap_or_default()
}

/// The credentials an OpenAPI or Swagger document declares.
fn security_schemes(doc: &Value) -> Vec<Credential> {
    let mut out = Vec::new();
    let roots = [
        ("securitySchemes", doc.pointer("/components/securitySchemes")),
        ("securityDefinitions", doc.get("securityDefinitions")),
    ];
    for (label, root) in roots {
        for (name, scheme) in root.and_then(Value::as_object).into_iter().flatten() {
            let s = resolve(doc, scheme);
            let text = |k: &str| s.get(k).and_then(Value::as_str).map(str::to_string);
            let ty = text("type").unwrap_or_default().to_ascii_lowercase();
            let http = text("scheme").unwrap_or_default().to_ascii_lowercase();
            let (kind, at, param) = match (ty.as_str(), http.as_str()) {
                ("apikey", _) => ("api_key", text("in"), text("name")),
                ("http", "bearer") => ("bearer", Some("header".into()), Some("Authorization".into())),
                ("http", "basic") | ("basic", _) => ("basic", Some("header".into()), Some("Authorization".into())),
                ("http", _) => ("other", Some("header".into()), Some("Authorization".into())),
                ("oauth2", _) => ("oauth2", None, None),
                ("openidconnect", _) => ("openid", None, None),
                ("mutualtls", _) => ("mutual_tls", None, None),
                _ => ("other", None, None),
            };
            merge_credential(
                &mut out,
                Credential {
                    kind: kind.into(),
                    location: at,
                    name: param,
                    source: format!("{label}:{name}"),
                    embedded: false,
                },
            );
        }
    }
    out
}

/// Removes every credential from the built requests, reporting each, and skips those
/// holding the auth placeholder marker or that can't be sent. `declared` adds the names the
/// document itself says are credentials, whatever they look like. `keep_headers` (a HAR
/// file's `--keep-credentials`) leaves credential headers in place, still reported; those in
/// the URL and the body are taken out all the same, as URLs are shown and logged.
fn harden(built: &mut Built, format: Format, declared: &[Credential], keep_headers: bool) {
    let secret = secret_test(format);
    let is_declared = |place: &str, name: &str| {
        declared.iter().any(|c| {
            c.location.as_deref() == Some(place)
                && c.name.as_deref().is_some_and(|n| {
                    // Header names ignore case; query parameter names don't.
                    n == name || (place == "header" && n.eq_ignore_ascii_case(name))
                })
        })
    };
    for mut r in std::mem::take(&mut built.requests) {
        let label = match url::Url::parse(&r.url) {
            Ok(u) => format!("{} {}", r.method, percent_decoded(u.path())),
            Err(_) => r.name.clone(),
        };
        if holds_marker(&r) {
            built.skip(label, "contains a reserved placeholder".into());
            continue;
        }
        let authority = r.url.split("://").nth(1).unwrap_or_default().split(['/', '?']).next().unwrap_or_default();
        if authority.contains('{') {
            built.base_url_required = true;
            built.skip(label, "the server's host has an unfilled variable, so it needs a base URL".into());
            continue;
        }
        let mut u = match url::Url::parse(&r.url) {
            Ok(u) => u,
            Err(e) => {
                built.skip(label, format!("invalid URL {:?}: {e}", shown_url(&r.url)));
                continue;
            }
        };
        if format == Format::Postman {
            warn_unresolved(built, &label, &r);
            for seg in u.path_segments().into_iter().flatten().filter(|s| s.starts_with(':')) {
                built.warn(format!("{label}: path variable {seg} has no value"));
            }
        } else if percent_decoded(u.path()).contains(['{', '}']) {
            built.warn(format!("{label}: the URL still has an unfilled {{variable}}"));
        }
        let source = format!("request:{label}");
        if !u.username().is_empty() || u.password().is_some() {
            built.credential(Credential {
                kind: "basic".into(),
                location: None,
                name: None,
                source: source.clone(),
                embedded: true,
            });
            let _ = u.set_username("");
            let _ = u.set_password(None);
        }
        u.set_fragment(None);
        if let Some(q) = u.query().map(str::to_string) {
            let mut kept = Vec::new();
            for part in q.split('&') {
                let names = part.split(';').map(|p| form_decoded(p.split('=').next().unwrap_or_default()));
                match names.into_iter().find(|n| secret(n) || is_declared("query", n)) {
                    Some(name) => {
                        let value = part.split_once('=').map_or("", |(_, v)| v);
                        built.credential(Credential {
                            kind: "api_key".into(),
                            location: Some("query".into()),
                            name: Some(name),
                            source: source.clone(),
                            embedded: !value.contains("%7B%7B") && !is_stand_in(value),
                        });
                    }
                    None => kept.push(part),
                }
            }
            u.set_query((!kept.is_empty()).then(|| kept.join("&")).as_deref());
        }
        for (k, v) in std::mem::take(&mut r.headers) {
            if !secret(&k) && !is_declared("header", &k) {
                r.headers.push((k, v));
                continue;
            }
            let embedded = !is_stand_in(&v);
            let kept = keep_headers.then(|| (k.clone(), v.clone()));
            if k.eq_ignore_ascii_case("cookie") {
                for name in v.split(';').filter_map(|c| c.split('=').next()).map(str::trim).filter(|n| !n.is_empty()) {
                    built.credential(Credential {
                        kind: "other".into(),
                        location: Some("cookie".into()),
                        name: Some(name.to_string()),
                        source: source.clone(),
                        embedded,
                    });
                }
                r.headers.extend(kept);
                continue;
            }
            let lower = v.trim_start().to_ascii_lowercase();
            let kind = if !k.eq_ignore_ascii_case("authorization") {
                "api_key"
            } else if lower.starts_with("bearer") {
                "bearer"
            } else if lower.starts_with("basic") {
                "basic"
            } else {
                "other"
            };
            built.credential(Credential {
                kind: kind.into(),
                location: Some("header".into()),
                name: Some(k),
                source: source.clone(),
                embedded,
            });
            r.headers.extend(kept);
        }
        let (body, fields) = without_credentials(&r.headers, &r.body, secret);
        r.body = body;
        for name in fields {
            built.credential(Credential {
                kind: "other".into(),
                location: None,
                name: Some(name),
                source: source.clone(),
                embedded: true,
            });
        }
        r.url = u.to_string();
        if let Err(e) = Target::from_url(&r.url).and_then(|_| build_raw(&r, &[])) {
            built.fail(true, label, &e);
            continue;
        }
        built.requests.push(r);
    }
}

/// How a build tells a credential by its name. A HAR file's values were recorded from a live
/// session, so its names are judged as reports judge them too (`X-Session-Id`, `sid`, `jwt`,
/// `signature`, ...); a description's examples only by [`looks_secret`].
fn secret_test(format: Format) -> fn(&str) -> bool {
    fn recorded(name: &str) -> bool {
        looks_secret(name) || crate::scan::redact::secret_header(name)
    }
    if format == Format::Har {
        recorded
    } else {
        looks_secret
    }
}

fn percent_decoded(s: &str) -> String {
    percent_encoding::percent_decode_str(s).decode_utf8_lossy().into_owned()
}

fn form_decoded(s: &str) -> String {
    url::form_urlencoded::parse(s.as_bytes()).next().map(|(k, _)| k.into_owned()).unwrap_or_default()
}

fn holds_marker(r: &ApiRequest) -> bool {
    r.name.contains(MARK)
        || r.url.contains(MARK)
        || percent_decoded(&r.url).contains(MARK)
        || r.headers.iter().any(|(k, v)| k.contains(MARK) || v.contains(MARK))
        || find(&r.body, MARK.as_bytes()).is_some()
}

fn warn_unresolved(built: &mut Built, label: &str, r: &ApiRequest) {
    let names = |s: &str| {
        let mut out = std::collections::BTreeSet::new();
        let mut rest = s;
        while let Some((_, after)) = rest.split_once("{{") {
            let Some((name, tail)) = after.split_once("}}") else { break };
            out.insert(name.trim().to_string());
            rest = tail;
        }
        out
    };
    let places = [
        ("URL", names(&r.url)),
        (
            "header",
            names(
                &r.headers
                    .iter()
                    .filter(|(k, _)| !looks_secret(k))
                    .map(|(_, v)| v.as_str())
                    .collect::<Vec<_>>()
                    .join(" "),
            ),
        ),
        ("body", names(&String::from_utf8_lossy(&r.body))),
    ];
    for (place, found) in places {
        for name in found {
            built.warn(format!("{label}: {{{{{name}}}}} stays unresolved in the {place}"));
        }
    }
}

/// The name to opt in to a request by, if its method doesn't say: a GraphQL mutation, from a
/// schema's mutation type, or from the request as built (a Postman GraphQL body, a persisted
/// query's hash), as a scan reads it.
fn opt_in_name(format: Format, r: &ApiRequest) -> Option<String> {
    let from_schema = format == Format::Graphql && r.name.starts_with("mutation ");
    (from_schema || built(r).is_some_and(|req| super::graphql::is_mutation_request(&req))).then(|| MUTATION.to_string())
}

/// The request as it goes out, for reading it as a scan does.
fn built(r: &ApiRequest) -> Option<Vec<u8>> {
    RawRequest::build(&r.method, &r.url, &r.headers, &r.body).ok().map(|(req, _)| req.into_bytes())
}

/// A Postman pre-request script's facts: enough to choose one and to fetch its text.
#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct ScriptInfo {
    /// Pins a signer to this text.
    pub sha256: String,
    /// Where it runs: `collection`, or the folders and requests that hold it.
    pub scopes: Vec<String>,
    /// Requests under the widest of those scopes.
    pub requests: usize,
    pub lines: usize,
    /// Whether it seems to be signing something.
    pub signs: bool,
    /// Calls it makes that the runner refuses.
    pub unsupported: Vec<String>,
    /// With --show-scripts only: a script can hold a hard-coded secret.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub text: Option<String>,
}

fn postman_scripts(doc: &Value) -> Vec<ScriptInfo> {
    let mut out: Vec<ScriptInfo> = Vec::new();
    for s in crate::sign_script::prerequest_scripts(doc) {
        let sha256 = crate::fetch::sha256_hex(s.text.as_bytes());
        match out.iter_mut().find(|i| i.sha256 == sha256) {
            Some(i) => {
                i.scopes.push(s.scope);
                i.requests = i.requests.max(s.requests);
            }
            None => out.push(ScriptInfo {
                sha256,
                scopes: vec![s.scope],
                requests: s.requests,
                lines: s.text.lines().count(),
                signs: crate::sign_script::seems_to_sign(&s.text),
                unsupported: crate::sign_script::unsupported_calls(&s.text),
                text: None,
            }),
        }
    }
    out
}

/// Fills in each listed script's text from the document it came from.
pub fn add_script_text(loaded: &mut Loaded, document: &str) {
    let Ok(doc) = super::parse_document(document) else { return };
    let scripts = crate::sign_script::prerequest_scripts(&doc);
    for info in &mut loaded.scripts {
        info.text =
            scripts.iter().find(|s| crate::fetch::sha256_hex(s.text.as_bytes()) == info.sha256).map(|s| s.text.clone());
    }
}

/// Which built requests to use.
#[derive(Debug, Default, Clone)]
pub struct Selection {
    /// Methods besides the default ones (upper case; `ALL` for every method).
    pub include_methods: Vec<String>,
    pub only: Option<Vec<usize>>,
}

/// One built request and whether it goes out.
#[derive(Debug, Clone)]
pub struct Planned {
    pub index: usize,
    pub request: ApiRequest,
    pub host: String,
    pub port: u16,
    pub in_scope: bool,
    /// False for a name only an IP or CIDR target could allow, which is decided at connect time.
    pub scope_confirmed: bool,
    /// None when selected: `not_selected`, `method`, or `scope`.
    pub excluded_reason: Option<&'static str>,
}

#[derive(Debug, Clone)]
pub struct Plan {
    pub items: Vec<Planned>,
}

impl Loaded {
    /// Applies --only, the method filter, and the scope.
    pub fn plan(&self, sel: &Selection, guard: &Guard) -> Result<Plan> {
        if let Some(bad) = sel.only.iter().flatten().find(|i| **i >= self.requests.len()) {
            return Err(Error::InvalidInput(format!(
                "--only {bad}: the document has {} request(s), counted from 0",
                self.requests.len()
            )));
        }
        let all = sel.include_methods.iter().any(|m| m == "ALL");
        let mut items = Vec::new();
        for (index, request) in self.requests.iter().enumerate() {
            let target = Target::from_url(&request.url)?;
            let method = request.method.to_ascii_uppercase();
            let in_scope = guard.may_allow(&target.host, target.port);
            let scope_confirmed = in_scope && guard.confirms(&target.host, target.port);
            // Its method, and MUTATION too for a mutation: neither stands for the other.
            let given = |m: &str| all || DEFAULT_METHODS.contains(&m) || sel.include_methods.iter().any(|i| i == m);
            let mutation = opt_in_name(self.format, request);
            let method_ok = given(&method) && mutation.as_deref().is_none_or(given);
            let excluded_reason = if sel.only.as_ref().is_some_and(|o| !o.contains(&index)) {
                Some("not_selected")
            } else if !method_ok {
                Some("method")
            } else if !in_scope {
                Some("scope")
            } else {
                None
            };
            items.push(Planned {
                index,
                request: request.clone(),
                host: target.host,
                port: target.port,
                in_scope,
                scope_confirmed,
                excluded_reason,
            });
        }
        Ok(Plan { items })
    }

    /// The preview of `plan`, listing up to `limit` requests.
    pub fn preview(&self, plan: &Plan, limit: usize) -> Preview {
        let mut hosts: BTreeMap<(String, u16), (bool, bool)> = BTreeMap::new();
        for i in &plan.items {
            hosts.insert((i.host.clone(), i.port), (i.in_scope, i.scope_confirmed));
        }
        Preview {
            kind: "api",
            format: self.format,
            title: self.title.clone(),
            version: self.version.clone(),
            document_sha256: self.document_sha256.clone(),
            servers: self.servers.clone(),
            base_url_required: self.base_url_required,
            variables: self.variables.clone(),
            unresolved_variables: self.unresolved_variables.clone(),
            credentials: self.credentials.clone(),
            environment: self.environment.clone(),
            scripts: self.scripts.clone(),
            oauth: self.oauth.clone(),
            aws: self.aws.clone(),
            credentials_kept: self.credentials_kept,
            built: self.requests.len(),
            selected: plan.selected(),
            skipped: self.skipped.clone(),
            warnings: self.warnings.clone(),
            hosts: hosts
                .into_iter()
                .map(|((host, port), (in_scope, scope_confirmed))| Host { host, port, in_scope, scope_confirmed })
                .collect(),
            requests_truncated: plan.items.len() > limit,
            requests: plan.items.iter().take(limit).map(|i| PreviewRequest::new(i, self.format)).collect(),
        }
    }

    /// Why there's nothing to send, if so.
    pub fn check_runnable(&self, plan: &Plan) -> Result<()> {
        if plan.selected() > 0 {
            return Ok(());
        }
        if self.requests.is_empty() {
            let why = if self.base_url_required {
                "it needs a base URL (--base-url)".to_string()
            } else {
                self.skipped
                    .first()
                    .map(|s| format!("first skipped: {}: {}", s.operation, s.reason))
                    .or_else(|| self.warnings.first().cloned())
                    .unwrap_or_else(|| "it has no operations".into())
            };
            return Err(Error::InvalidInput(format!("no requests could be built from the document: {why}")));
        }
        let wanted = plan.items.iter().any(|i| i.excluded_reason == Some("scope"));
        if wanted || !plan.items.iter().any(|i| i.in_scope) {
            let mut hosts: Vec<&str> = plan.items.iter().filter(|i| !i.in_scope).map(|i| i.host.as_str()).collect();
            hosts.sort_unstable();
            hosts.dedup();
            return Err(Error::OutOfScope(format!(
                "none of the selected requests is in scope (hosts: {}); nothing was sent",
                hosts.join(", ")
            )));
        }
        Err(Error::InvalidInput(
            "no requests selected: check --only, or --include-methods for PUT, PATCH, DELETE, and GraphQL's MUTATION"
                .into(),
        ))
    }
}

impl Plan {
    pub fn selected(&self) -> usize {
        self.items.iter().filter(|i| i.excluded_reason.is_none()).count()
    }

    /// The selected requests, at most `max`, and how many that left out. Those only out of
    /// scope come along for `run`, which counts them and sends nothing.
    pub fn to_send(&self, max: usize) -> (Vec<ApiRequest>, usize) {
        let selected = self.items.iter().filter(|i| i.excluded_reason.is_none());
        let mut out: Vec<ApiRequest> = selected.map(|i| i.request.clone()).collect();
        let over = out.len().saturating_sub(max);
        out.truncate(max);
        out.extend(self.items.iter().filter(|i| i.excluded_reason == Some("scope")).map(|i| i.request.clone()));
        (out, over)
    }
}

#[derive(Debug, Serialize)]
pub struct Host {
    pub host: String,
    pub port: u16,
    pub in_scope: bool,
    pub scope_confirmed: bool,
}

/// One row of the preview.
#[derive(Debug, Serialize)]
pub struct PreviewRequest {
    pub index: usize,
    pub name: String,
    pub method: String,
    pub url: String,
    pub headers: Vec<String>,
    /// With secret-named values masked. The caller shapes it for output.
    #[serde(skip)]
    pub body: Vec<u8>,
    pub state_changing: bool,
    /// What `--include-methods` calls it, when that isn't its method.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub opt_in: Option<String>,
    pub in_scope: bool,
    pub scope_confirmed: bool,
    pub included: bool,
    pub excluded_reason: Option<&'static str>,
}

impl PreviewRequest {
    fn new(i: &Planned, format: Format) -> Self {
        let r = &i.request;
        let opt_in = opt_in_name(format, r);
        let secret = secret_test(format);
        PreviewRequest {
            index: i.index,
            name: r.name.clone(),
            method: r.method.clone(),
            url: r.url.clone(),
            // Only a HAR file's --keep-credentials leaves any; never shown.
            headers: r
                .headers
                .iter()
                .map(|(k, v)| if secret(k) { format!("{k}: {MASK}") } else { format!("{k}: {v}") })
                .collect(),
            body: masked_body(&r.headers, &r.body),
            state_changing: opt_in.is_some()
                || matches!(r.method.to_ascii_uppercase().as_str(), "PUT" | "PATCH" | "DELETE"),
            opt_in,
            in_scope: i.in_scope,
            scope_confirmed: i.scope_confirmed,
            included: i.excluded_reason.is_none(),
            excluded_reason: i.excluded_reason,
        }
    }
}

/// What `import api --dry-run` shows; a real run shows the same without `requests`.
#[derive(Debug, Serialize)]
pub struct Preview {
    pub kind: &'static str,
    pub format: Format,
    pub title: Option<String>,
    pub version: Option<String>,
    pub document_sha256: String,
    pub servers: Vec<Server>,
    pub base_url_required: bool,
    pub variables: Vec<Variable>,
    pub unresolved_variables: Vec<String>,
    pub credentials: Vec<Credential>,
    pub environment: Option<EnvironmentInfo>,
    pub scripts: Vec<ScriptInfo>,
    pub oauth: Vec<OAuthHint>,
    pub aws: Vec<AwsHint>,
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub credentials_kept: bool,
    pub built: usize,
    pub selected: usize,
    pub skipped: Vec<Skipped>,
    pub warnings: Vec<String>,
    pub hosts: Vec<Host>,
    pub requests_truncated: bool,
    pub requests: Vec<PreviewRequest>,
}

/// `body` with the values of secret-named JSON, form, and multipart fields masked.
pub fn masked_body(headers: &[(String, String)], body: &[u8]) -> Vec<u8> {
    replace_fields(headers, body, looks_secret, &mut |_, _| Some(MASK.to_string()))
}

/// Values the builders make up, and nothing a document could leak.
fn is_stand_in(value: &str) -> bool {
    value.is_empty() || value.contains("{{") || ["test", "Passw0rd!", "true", "false", "1", "1.5"].contains(&value)
}

/// `body` with what the document gives for secret-named fields replaced by a test value, and those fields' names.
fn without_credentials(headers: &[(String, String)], body: &[u8], secret: Secret) -> (Vec<u8>, Vec<String>) {
    let mut found = Vec::new();
    let out = replace_fields(headers, body, secret, &mut |name, value| {
        (!is_stand_in(value)).then(|| {
            found.push(name.to_string());
            "test".to_string()
        })
    });
    (out, found)
}

/// `body` with JSON, form, and multipart fields whose names `secret` calls secret set to what
/// `with` returns for their name and value, where it returns one.
fn replace_fields(headers: &[(String, String)], body: &[u8], secret: Secret, with: &mut Replace<'_>) -> Vec<u8> {
    let ct = headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("content-type"))
        .map(|(_, v)| v.to_ascii_lowercase())
        .unwrap_or_default();
    let text = String::from_utf8_lossy(body);
    if text.trim_start().starts_with(['{', '[']) {
        return match serde_json::from_slice::<Value>(body) {
            Ok(mut v) => {
                if replace_json(&mut v, secret, with) {
                    serde_json::to_vec(&v).unwrap_or_default()
                } else {
                    body.to_vec()
                }
            }
            // {{variables}} can leave a raw body that doesn't parse.
            Err(_) => replace_pairs(&text, secret, with).into_bytes(),
        };
    }
    if ct.contains("xml") {
        return replace_xml(&text, secret, with).into_bytes();
    }
    if ct.contains("x-www-form-urlencoded") {
        let mut changed = false;
        let pairs: Vec<(String, String)> = url::form_urlencoded::parse(body)
            .into_owned()
            .map(|(k, v)| {
                let new = if secret(&k) { with(&k, &v) } else { None };
                changed |= new.is_some();
                let v = new.unwrap_or(v);
                (k, v)
            })
            .collect();
        return if changed {
            url::form_urlencoded::Serializer::new(String::new()).extend_pairs(pairs).finish().into_bytes()
        } else {
            body.to_vec()
        };
    }
    if ct.contains("multipart/form-data") {
        return replace_parts(&text, secret, with).into_bytes();
    }
    body.to_vec()
}

type Replace<'a> = dyn FnMut(&str, &str) -> Option<String> + 'a;

/// Whether a field's name says it holds a credential.
type Secret = fn(&str) -> bool;

fn replace_json(v: &mut Value, secret: Secret, with: &mut Replace<'_>) -> bool {
    let mut changed = false;
    match v {
        Value::Array(a) => a.iter_mut().for_each(|x| changed |= replace_json(x, secret, with)),
        Value::Object(m) => {
            for (k, x) in m.iter_mut() {
                if !secret(k) {
                    changed |= replace_json(x, secret, with);
                } else if !x.is_null() {
                    let text = x.as_str().map_or_else(|| x.to_string(), str::to_string);
                    if let Some(new) = with(k, &text) {
                        *x = Value::String(new);
                        changed = true;
                    }
                }
            }
        }
        _ => {}
    }
    changed
}

/// `"key": "value"` pairs of text that is almost JSON.
fn replace_pairs(text: &str, secret: Secret, with: &mut Replace<'_>) -> String {
    static PAIR: LazyLock<Regex> =
        LazyLock::new(|| Regex::new(r#""([^"\\]*)"\s*:\s*("(?:[^"\\]|\\.)*"|[^\s,}\]]+)"#).expect("valid regex"));
    PAIR.replace_all(text, |c: &regex::Captures| {
        let new = if secret(&c[1]) { with(&c[1], c[2].trim_matches('"')) } else { None };
        match new {
            Some(new) => format!("\"{}\": \"{new}\"", &c[1]),
            None => c[0].to_string(),
        }
    })
    .into_owned()
}

/// `<name attrs>value</name>` elements of an XML body.
fn replace_xml(text: &str, secret: Secret, with: &mut Replace<'_>) -> String {
    static ELEMENT: LazyLock<Regex> =
        LazyLock::new(|| Regex::new(r"<([\w.:-]+)([^<>]*)>([^<]*)</([\w.:-]+)>").expect("valid regex"));
    ELEMENT
        .replace_all(text, |c: &regex::Captures| {
            let local = c[1].rsplit(':').next().unwrap_or_default();
            let new = if c[1] == c[4] && secret(local) { with(local, &c[3]) } else { None };
            match new {
                Some(new) => format!("<{}{}>{new}</{}>", &c[1], &c[2], &c[4]),
                None => c[0].to_string(),
            }
        })
        .into_owned()
}

/// The parts of a multipart body, by the `name` in their Content-Disposition (not a
/// `filename`), whatever follows it on that line and whatever headers (a part's own
/// Content-Type, say) come before the value.
fn replace_parts(text: &str, secret: Secret, with: &mut Replace<'_>) -> String {
    static PART: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(r#"(?s)\bname="([^"]*)"([^\r\n]*\r\n(?:[^\r\n]+\r\n)*\r\n)(.*?)\r\n--"#).expect("valid regex")
    });
    PART.replace_all(text, |c: &regex::Captures| {
        let new = if secret(&c[1]) { with(&c[1], &c[3]) } else { None };
        match new {
            Some(new) => format!("name=\"{}\"{}{new}\r\n--", &c[1], &c[2]),
            None => c[0].to_string(),
        }
    })
    .into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn a_request_needs_its_method_and_mutation_opted_in() {
        let given = |l: &[&str]| l.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        let delete = b"DELETE /api/shares?documentId=42 HTTP/1.1\r\nHost: a.test\r\n\r\n";
        assert_eq!(missing_opt_in(delete, DEFAULT_METHODS, &given(&["MUTATION"])).as_deref(), Some("DELETE"));
        assert_eq!(missing_opt_in(delete, DEFAULT_METHODS, &given(&["delete"])).as_deref(), Some("MUTATION"));
        assert_eq!(missing_opt_in(delete, DEFAULT_METHODS, &given(&["DELETE", "MUTATION"])), None);
        assert_eq!(missing_opt_in(delete, DEFAULT_METHODS, &given(&["all"])), None);
        let mutation = b"POST /graphql HTTP/1.1\r\nHost: a.test\r\n\r\n{\"query\":\"mutation { a }\"}";
        assert_eq!(missing_opt_in(mutation, DEFAULT_METHODS, &[]).as_deref(), Some("MUTATION"));
        assert_eq!(missing_opt_in(mutation, crate::authz::SAFE_METHODS, &[]).as_deref(), Some("POST"));
        let get = b"GET /items HTTP/1.1\r\nHost: a.test\r\n\r\n";
        assert_eq!(missing_opt_in(get, crate::authz::SAFE_METHODS, &[]), None);
    }

    fn opts() -> Options {
        Options::default()
    }

    fn guard() -> std::sync::Arc<Guard> {
        let scope = crate::guard::ScopeSpec { name: None, include: vec!["api.test".into()], exclude: vec![] };
        Guard::from_specs(vec![scope]).unwrap()
    }

    fn err(text: &str) -> String {
        load(text, &opts()).unwrap_err().to_string()
    }

    #[test]
    fn formats_are_detected_and_others_named() {
        let f = |t: &str| load(t, &opts()).unwrap().format;
        assert_eq!(f("openapi: 3.1.0\npaths: {}"), Format::Openapi3);
        assert_eq!(f("openapi: 3.1\npaths: {}"), Format::Openapi3);
        assert_eq!(f("swagger: 2.0\nhost: a.test\npaths: {}"), Format::Swagger2);
        assert_eq!(f(r#"{"info": {"name": "x"}, "item": []}"#), Format::Postman);
        assert_eq!(f("type Query {\n  a: Int\n}\n"), Format::Graphql);
        assert!(err("type Other {\n  a: Int\n}\n").contains("no Query type"));
        assert_eq!(f(r#"{"data": {"__schema": {"queryType": {"name": "Query"}, "types": []}}}"#), Format::Graphql);
        assert_eq!(f(r#"{"log": {"version": "1.2", "entries": []}}"#), Format::Har);
        for (text, says) in [
            ("openapi: 4.0.0\npaths: {}", "OpenAPI version \"4.0.0\" isn't supported"),
            ("swagger: 1.2\npaths: {}", "Swagger version \"1.2\" isn't supported"),
            ("swaggerVersion: 1.2\napis: []", "Swagger version"),
            (r#"{"errors": [{"message": "off"}]}"#, "introspection"),
            (r#"{"values": [], "_postman_variable_scope": "environment"}"#, "--environment"),
            (r#"{"requests": [], "order": []}"#, "Postman collection v1"),
            ("<html></html>", "HTML"),
            ("", "empty"),
            ("[1, 2]", "not a JSON or YAML object"),
            ("just: fine", "wasn't recognised"),
        ] {
            let e = err(text);
            assert!(e.contains(says), "{text:?}: {e}");
            assert!(e.contains("accepted formats"), "{text:?}: {e}");
        }
    }

    #[test]
    fn malformed_documents_say_where_not_what() {
        let e = err("{\"openapi\": \"3.0.0\",\n \"password\": [SECRETVALUE}}");
        assert!(e.contains("not valid JSON or YAML") && e.contains("line 2"), "{e}");
        assert!(!e.contains("SECRETVALUE"), "{e}");
        let e = err("a: [unclosed SECRETVALUE\nb: {");
        assert!(e.contains("not valid JSON or YAML") && !e.contains("SECRETVALUE"), "{e}");
        let e = err("openapi: 3.0.0\npaths: [1]");
        assert!(e.contains("\"paths\" must be an object"), "{e}");
    }

    #[test]
    fn expected_sha256_is_checked() {
        let text = "openapi: 3.0.0\npaths: {}";
        let sha = load(text, &opts()).unwrap().document_sha256;
        let o = Options { expect_sha256: Some(sha.to_uppercase()), ..opts() };
        assert!(load(text, &o).is_ok());
        let o = Options { expect_sha256: Some("00".into()), ..opts() };
        assert!(load(text, &o).unwrap_err().to_string().contains("changed"));
    }

    #[test]
    fn a_postman_graphql_mutation_needs_mutation_and_a_delete_its_method() {
        let doc = json!({
            "info": {"name": "c"},
            "item": [
                {"name": "Delete user", "request": {"method": "POST", "url": "https://api.test/graphql",
                    "body": {"mode": "graphql", "graphql": {"query": "mutation { deleteUser(id: 1) }"}}}},
                {"name": "Unshare", "request": {"method": "DELETE", "url": "https://api.test/shares?documentId=42"}},
                {"name": "Me", "request": {"method": "POST", "url": "https://api.test/graphql",
                    "body": {"mode": "graphql", "graphql": {"query": "{ me { id } }"}}}}]});
        let l = load(&doc.to_string(), &opts()).unwrap();
        let g = guard();
        let reasons = |methods: &[&str]| {
            let sel = Selection { include_methods: methods.iter().map(|m| m.to_string()).collect(), only: None };
            l.plan(&sel, &g).unwrap().items.iter().map(|i| i.excluded_reason).collect::<Vec<_>>()
        };
        assert_eq!(reasons(&[]), [Some("method"), Some("method"), None]);
        assert_eq!(reasons(&["MUTATION"]), [None, Some("method"), None]);
        assert_eq!(reasons(&["DELETE"]), [Some("method"), Some("method"), None]);
        assert_eq!(reasons(&["DELETE", "MUTATION"]), [None, None, None]);
        assert_eq!(reasons(&["ALL"]), [None, None, None]);
        let p = l.preview(&l.plan(&Selection::default(), &g).unwrap(), 100);
        assert_eq!(p.requests[0].opt_in.as_deref(), Some("MUTATION"));
        assert!(p.requests[0].state_changing && !p.requests[2].state_changing);
    }

    #[test]
    fn credentials_never_survive_a_build() {
        let doc = json!({
            "info": {"name": "c"},
            "auth": {"type": "bearer", "bearer": [{"key": "token", "value": "COLLECTIONSECRET"}]},
            "variable": [{"key": "base", "value": "https://user:URLPASS@api.test/v1"}],
            "item": [{"name": "one", "request": {"method": "POST",
                "url": "{{base}}/a?limit=1&api_key=QUERYSECRET&X-Auth=QS2&b=2#FRAGSECRET",
                "header": [
                    {"key": "Authorization", "value": "Bearer HEADERSECRET"},
                    {"key": "Cookie", "value": "sid=COOKIESECRET; theme=dark"},
                    {"key": "x-auth-user", "value": "HS3"},
                    {"key": "Accept", "value": "application/json"}],
                "body": {"mode": "raw", "raw": "{\"name\": \"x\", \"password\": \"BODYSECRET\"}",
                         "options": {"raw": {"language": "json"}}}}}]});
        let l = load(&doc.to_string(), &opts()).unwrap();
        let g = guard();
        let plan = l.plan(&Selection::default(), &g).unwrap();
        let p = l.preview(&plan, 100);
        let r = &p.requests[0];
        assert_eq!(r.url, "https://api.test/v1/a?limit=1&b=2");
        assert_eq!(r.headers, ["Accept: application/json", "Content-Type: application/json"]);
        assert_eq!(String::from_utf8_lossy(&r.body), r#"{"name":"x","password":"********"}"#);
        let body = String::from_utf8_lossy(&r.body).into_owned();
        let shown = format!("{}{body}", serde_json::to_string(&p).unwrap());
        for s in [
            "COLLECTIONSECRET",
            "URLPASS",
            "QUERYSECRET",
            "QS2",
            "HEADERSECRET",
            "COOKIESECRET",
            "HS3",
            "FRAGSECRET",
            "BODYSECRET",
        ] {
            assert!(!shown.contains(s), "{s} in {shown}");
        }
        let has = |at: Option<&str>, n: Option<&str>| {
            p.credentials.iter().any(|c| c.location.as_deref() == at && c.name.as_deref() == n)
        };
        assert!(has(Some("query"), Some("api_key")) && has(Some("query"), Some("X-Auth")));
        assert!(has(Some("header"), Some("Authorization")) && has(Some("header"), Some("x-auth-user")));
        assert!(has(Some("cookie"), Some("sid")) && has(None, None), "{:?}", p.credentials);
        // The body that goes out has a test value in its place, not the document's.
        assert_eq!(String::from_utf8_lossy(&l.requests[0].body), r#"{"name":"x","password":"test"}"#);
        assert!(has(None, Some("password")), "{:?}", p.credentials);
        // Values the builders made up are left alone and not reported.
        let spec = r#"{"openapi": "3.0.0", "servers": [{"url": "https://api.test"}], "paths": {"/u": {"post": {
            "requestBody": {"content": {"application/json": {"schema": {"properties": {
                "password": {"type": "string", "format": "password"}, "token": {"type": "string"}}}}}}}}}}"#;
        let l = load(spec, &opts()).unwrap();
        assert_eq!(String::from_utf8_lossy(&l.requests[0].body), r#"{"password":"Passw0rd!","token":"test"}"#);
        assert!(l.credentials.is_empty(), "{:?}", l.credentials);
    }

    fn har() -> String {
        json!({"log": {"version": "1.2", "creator": {"name": "WebInspector", "version": "537.36"}, "entries": [
            {"request": {"method": "GET", "url": "https://api.test/me?access_token=QUERYSECRET&x=1",
                "headers": [{"name": "Cookie", "value": "sid=COOKIESECRET; theme=dark"},
                    {"name": "Authorization", "value": "Bearer HEADERSECRET"},
                    {"name": "X-CSRF-Token", "value": "CSRFSECRET"},
                    {"name": "Accept", "value": "application/json"}]},
             "response": {"status": 200, "content": {"mimeType": "application/json", "text": "{\"me\": 1}"}}},
            {"request": {"method": "POST", "url": "https://api.test/login",
                "headers": [{"name": "Content-Type", "value": "application/json"}],
                "postData": {"mimeType": "application/json", "text": "{\"user\": \"a\", \"password\": \"BODYSECRET\"}"}},
             "response": {"status": 200, "content": {}}},
            {"request": {"method": "DELETE", "url": "https://api.test/items/1"}, "response": {"content": {}}},
            {"request": {"method": "GET", "url": "https://tracker.example/collect?id=1"}, "response": {"content": {}}}
        ]}})
        .to_string()
    }

    #[test]
    fn a_har_file_is_imported_without_its_credentials() {
        let l = load(&har(), &opts()).unwrap();
        assert_eq!(
            (l.format, l.title.as_deref(), l.version.as_deref()),
            (Format::Har, Some("WebInspector"), Some("537.36"))
        );
        let g = guard();
        let plan = l.plan(&Selection::default(), &g).unwrap();
        let reasons: Vec<_> = plan.items.iter().map(|i| i.excluded_reason).collect();
        // The DELETE needs opting in to, as for any format; the tracker is out of scope.
        assert_eq!(reasons, [None, None, Some("method"), Some("scope")]);
        let p = l.preview(&plan, 100);
        assert_eq!(p.requests[0].url, "https://api.test/me?x=1");
        assert_eq!(p.requests[0].headers, ["Accept: application/json"]);
        let shown = format!("{}{}", serde_json::to_string(&p).unwrap(), String::from_utf8_lossy(&p.requests[1].body));
        for s in ["COOKIESECRET", "HEADERSECRET", "CSRFSECRET", "QUERYSECRET", "BODYSECRET"] {
            assert!(!shown.contains(s), "{s} in {shown}");
        }
        assert!(!shown.contains("credentials_kept"), "{shown}");
        let has = |at: &str, n: &str| {
            p.credentials
                .iter()
                .any(|c| c.location.as_deref() == Some(at) && c.name.as_deref() == Some(n) && c.embedded)
        };
        assert!(has("cookie", "sid") && has("cookie", "theme") && has("header", "Authorization"));
        assert!(has("header", "X-CSRF-Token") && has("query", "access_token"), "{:?}", p.credentials);
        assert!(l.requests.iter().all(|r| !String::from_utf8_lossy(&r.body).contains("BODYSECRET")));
        let e = l.check_runnable(&l.plan(&Selection { only: Some(vec![3]), ..Default::default() }, &g).unwrap());
        assert!(e.unwrap_err().to_string().contains("tracker.example"));
    }

    #[test]
    fn a_har_file_keeps_its_credential_headers_only_when_asked() {
        let o = Options { har: HarOptions { keep_credentials: true, ..Default::default() }, ..opts() };
        let l = load(&har(), &o).unwrap();
        assert!(l.credentials_kept);
        let sent = &l.requests[0];
        let header = |n: &str| sent.headers.iter().find(|(k, _)| k == n).map(|(_, v)| v.as_str());
        assert_eq!(header("Cookie"), Some("sid=COOKIESECRET; theme=dark"));
        assert_eq!(header("Authorization"), Some("Bearer HEADERSECRET"));
        // The URL and body are shown and logged: their credentials go all the same.
        assert_eq!(sent.url, "https://api.test/me?x=1");
        assert!(!String::from_utf8_lossy(&l.requests[1].body).contains("BODYSECRET"));
        let p = l.preview(&l.plan(&Selection::default(), &guard()).unwrap(), 100);
        assert!(p.requests[0].headers.contains(&"Cookie: ********".to_string()), "{:?}", p.requests[0].headers);
        let shown = serde_json::to_string(&p).unwrap();
        assert!(!shown.contains("SECRET") && shown.contains("\"credentials_kept\":true"), "{shown}");
        assert!(p.credentials.iter().any(|c| c.name.as_deref() == Some("Authorization")));
    }

    #[test]
    fn a_har_file_s_session_names_count_as_credentials() {
        // Recorded values are live ones: names a report masks are credentials here too, though
        // `looks_secret` alone would let them through.
        let doc = json!({"log": {"entries": [{"request": {"method": "POST",
            "url": "https://api.test/cart?sid=RECORDEDSID1&page=2&jwt=RECORDEDJWT1",
            "headers": [{"name": "X-Session-Id", "value": "RECORDEDHDR1"}, {"name": "Accept", "value": "*/*"},
                {"name": "Content-Type", "value": "application/json"}],
            "postData": {"mimeType": "application/json", "text": "{\"session\": \"RECORDEDBODY1\", \"qty\": 2}"}}}]}});
        let l = load(&doc.to_string(), &opts()).unwrap();
        let p = l.preview(&l.plan(&Selection::default(), &guard()).unwrap(), 100);
        let shown = format!("{}{}", serde_json::to_string(&p).unwrap(), String::from_utf8_lossy(&l.requests[0].body));
        assert!(!shown.contains("RECORDED"), "{shown}");
        assert_eq!(p.requests[0].url, "https://api.test/cart?page=2");
        assert_eq!(String::from_utf8_lossy(&l.requests[0].body), r#"{"session":"test","qty":2}"#);
        for (at, name) in
            [(Some("query"), "sid"), (Some("query"), "jwt"), (Some("header"), "X-Session-Id"), (None, "session")]
        {
            assert!(
                p.credentials.iter().any(|c| c.location.as_deref() == at && c.name.as_deref() == Some(name)),
                "{name}: {:?}",
                p.credentials
            );
        }
        // Kept, such a header is masked in the preview like any other.
        let o = Options { har: HarOptions { keep_credentials: true, ..Default::default() }, ..opts() };
        let l = load(&doc.to_string(), &o).unwrap();
        let p = l.preview(&l.plan(&Selection::default(), &guard()).unwrap(), 100);
        assert!(p.requests[0].headers.contains(&"X-Session-Id: ********".to_string()), "{:?}", p.requests[0].headers);
        assert!(l.requests[0].headers.iter().any(|(k, v)| k == "X-Session-Id" && v == "RECORDEDHDR1"));
        // Descriptions keep their narrower rule: an OpenAPI `sid` parameter is no credential.
        let spec = r#"{"openapi": "3.0.0", "servers": [{"url": "https://api.test"}], "paths": {"/a": {"get": {
            "parameters": [{"name": "sid", "in": "query", "example": "7"}]}}}}"#;
        assert_eq!(load(spec, &opts()).unwrap().requests[0].url, "https://api.test/a?sid=7");
    }

    #[test]
    fn multipart_parts_with_their_own_headers_are_cleaned_too() {
        let body = "--b\r\nContent-Disposition: form-data; name=\"password\"\r\nContent-Type: text/plain\r\n\r\nPARTSECRET1\r\n\
            --b\r\nContent-Disposition: form-data; name=\"doc\"; filename=\"secret.txt\"\r\nContent-Type: text/plain\r\n\r\nfile body\r\n\
            --b\r\nContent-Disposition: form-data; name=\"token\"\r\n\r\nPARTSECRET2\r\n--b--\r\n";
        let headers = [("Content-Type".to_string(), "multipart/form-data; boundary=b".to_string())];
        let (out, found) = without_credentials(&headers, body.as_bytes(), looks_secret);
        let out = String::from_utf8(out).unwrap();
        assert!(!out.contains("PARTSECRET"), "{out}");
        assert!(out.contains("name=\"password\"\r\nContent-Type: text/plain\r\n\r\ntest\r\n"), "{out}");
        // A file named like a secret isn't a secret field.
        assert!(out.contains("file body"), "{out}");
        assert_eq!(found, ["password", "token"]);
        assert!(!String::from_utf8_lossy(&masked_body(&headers, body.as_bytes())).contains("PARTSECRET"));
    }

    #[test]
    fn har_options_and_import_har_are_checked() {
        let spec = r#"{"openapi": "3.0.0", "paths": {}}"#;
        let only_har = Options { require_har: true, ..opts() };
        assert!(load(&har(), &only_har).is_ok());
        let e = load(spec, &only_har).unwrap_err().to_string();
        assert!(e.contains("an OpenAPI 3 document, not a HAR file") && e.contains("import api"), "{e}");
        let keep = Options { har: HarOptions { keep_static: true, ..Default::default() }, ..opts() };
        assert!(load(spec, &keep).unwrap_err().to_string().contains("for HAR files"));
        let server = Options { server: Some(0), ..opts() };
        assert!(load(&har(), &server).unwrap_err().to_string().contains("no servers"));
        let rebased = load(&har(), &Options { base_url: Some("http://127.0.0.1:9".into()), ..opts() }).unwrap();
        assert!(rebased.requests.iter().all(|r| r.url.starts_with("http://127.0.0.1:9/")));
    }

    #[test]
    fn a_har_file_may_be_larger_than_other_documents() {
        // Response bodies take up most of a HAR file, and aren't read.
        let big = "x".repeat(MAX_DOCUMENT);
        let doc = json!({"log": {"entries": [{"request": {"method": "GET", "url": "https://api.test/a"},
            "response": {"content": {"mimeType": "text/plain", "text": big}}}]}});
        let l = load(&doc.to_string(), &opts()).unwrap();
        assert_eq!((l.format, l.requests.len()), (Format::Har, 1));
        let e = err(&format!("{{\"openapi\": \"3.0.0\", \"x\": \"{big}\"}}"));
        assert!(e.contains("larger than 32 MiB"), "{e}");
    }

    #[test]
    fn selection_counts_and_reasons() {
        let text = r#"{"openapi": "3.0.0", "servers": [{"url": "https://api.test/v1"}], "paths": {
            "/a": {"get": {"operationId": "a"}, "put": {"operationId": "b"}, "delete": {"operationId": "c"}},
            "/b": {"post": {"servers": [{"url": "https://other.test"}]}}}}"#;
        let l = load(text, &opts()).unwrap();
        let g = guard();
        let reasons = |sel: &Selection| {
            let p = l.plan(sel, &g).unwrap();
            p.items.iter().map(|i| i.excluded_reason).collect::<Vec<_>>()
        };
        assert_eq!(reasons(&Selection::default()), [None, Some("method"), Some("method"), Some("scope")]);
        let sel = Selection { include_methods: vec!["PUT".into()], ..Default::default() };
        assert_eq!(reasons(&sel), [None, None, Some("method"), Some("scope")]);
        let sel = Selection { include_methods: vec!["ALL".into()], only: Some(vec![2]) };
        assert_eq!(reasons(&sel), [Some("not_selected"), Some("not_selected"), None, Some("not_selected")]);
        let plan = l.plan(&Selection::default(), &g).unwrap();
        let p = l.preview(&plan, 2);
        assert!(p.requests_truncated && p.requests.len() == 2 && p.selected == 1 && p.built == 4);
        assert!(!p.requests[0].state_changing && p.requests[1].state_changing);
        assert_eq!(p.hosts.len(), 2);
        let (send, over) = plan.to_send(10);
        assert_eq!((send.len(), over), (2, 0), "the out-of-scope one goes along to be counted");

        assert!(l.plan(&Selection { only: Some(vec![9]), ..Default::default() }, &g).is_err());
        let only_scope = l.plan(&Selection { only: Some(vec![3]), ..Default::default() }, &g).unwrap();
        assert!(matches!(l.check_runnable(&only_scope), Err(Error::OutOfScope(_))));
        let only_put = l.plan(&Selection { only: Some(vec![1]), ..Default::default() }, &g).unwrap();
        assert!(matches!(l.check_runnable(&only_put), Err(Error::InvalidInput(_))));
        assert!(l.check_runnable(&plan).is_ok());
        let outside = load(r#"{"swagger": "2.0", "host": "x.test", "paths": {"/a": {"get": {}}}}"#, &opts()).unwrap();
        let p = outside.plan(&Selection::default(), &g).unwrap();
        assert!(matches!(outside.check_runnable(&p), Err(Error::OutOfScope(_))));
    }

    #[test]
    fn a_missing_base_url_is_not_fatal() {
        let text = r#"{"swagger": "2.0", "paths": {"/a": {"get": {}}}}"#;
        let l = load(text, &opts()).unwrap();
        assert!(l.base_url_required && l.requests.is_empty() && l.skipped.len() == 1);
        let g = guard();
        let p = l.plan(&Selection::default(), &g).unwrap();
        assert!(l.check_runnable(&p).unwrap_err().to_string().contains("--base-url"));
        let o = Options { base_url: Some("https://api.test/x".into()), ..opts() };
        let l = load(text, &o).unwrap();
        assert!(!l.base_url_required);
        assert_eq!(l.requests[0].url, "https://api.test/x/a");
        // A variable left in the host.
        let text = r#"{"openapi": "3.0.0", "servers": [{"url": "https://{tenant}.api.test/v1"}], "paths": {"/a": {"get": {}}}}"#;
        let l = load(text, &opts()).unwrap();
        assert!(l.base_url_required && l.requests.is_empty(), "{l:?}");
        let o = Options { base_url: Some("https://api.test".into()), ..opts() };
        assert_eq!(load(text, &o).unwrap().requests[0].url, "https://api.test/v1/a");
    }

    #[test]
    fn server_choice_is_checked() {
        let text = r#"{"openapi": "3.0.0", "servers": [{"url": "https://u:PW@api.test/v1?k=KEY"}], "paths": {}}"#;
        let l = load(text, &opts()).unwrap();
        assert_eq!(l.servers[0].url, "https://api.test/v1");
        assert!(load(text, &Options { server: Some(1), ..opts() }).is_err());
        let postman = r#"{"item": []}"#;
        assert!(load(postman, &Options { server: Some(0), ..opts() }).is_err());
    }

    #[test]
    fn schemes_are_reported_without_values() {
        let l = load(
            r#"{"openapi": "3.0.0", "components": {"securitySchemes": {
                "KeyAuth": {"type": "apiKey", "in": "header", "name": "X-Api-Key"},
                "Tok": {"type": "http", "scheme": "bearer"},
                "O": {"type": "oauth2"}, "Oid": {"type": "openIdConnect"}, "M": {"type": "mutualTLS"}}},
              "servers": [{"url": "https://api.test"}],
              "paths": {"/a": {"get": {"parameters": [{"name": "X-Api-Key", "in": "header", "example": "EXAMPLEKEY"}]}}}}"#,
            &opts(),
        )
        .unwrap();
        let kinds: Vec<&str> = l.credentials.iter().map(|c| c.kind.as_str()).collect();
        assert_eq!(kinds, ["api_key", "bearer", "oauth2", "openid", "mutual_tls"]);
        assert_eq!(l.credentials[0].source, "securitySchemes:KeyAuth");
        assert!(l.credentials[0].embedded, "the parameter's example counts");
        assert!(l.requests[0].headers.is_empty());
        assert!(!format!("{:?}", l.credentials).contains("EXAMPLEKEY"));
    }

    #[test]
    fn bodies_are_masked_by_key() {
        let json_ct = [("Content-Type".to_string(), "application/json".to_string())];
        let form_ct = [("Content-Type".to_string(), "application/x-www-form-urlencoded".to_string())];
        let s = |b: Vec<u8>| String::from_utf8(b).unwrap();
        assert_eq!(
            s(masked_body(&json_ct, br#"{"a":[{"apiKey":"K"}],"b":1}"#)),
            r#"{"a":[{"apiKey":"********"}],"b":1}"#
        );
        assert_eq!(s(masked_body(&json_ct, b"{ \"b\" : 1 }")), "{ \"b\" : 1 }", "unchanged stays as written");
        assert_eq!(
            s(masked_body(&json_ct, br#"{"token": "K", "n": {{count}}, "secret": 5}"#)),
            r#"{"token": "********", "n": {{count}}, "secret": "********"}"#
        );
        assert_eq!(s(masked_body(&form_ct, b"user=a&password=K")), "user=a&password=********");
        let ct = [("Content-Type".to_string(), "multipart/form-data; boundary=b".to_string())];
        let part = "--b\r\nContent-Disposition: form-data; name=\"password\"\r\n\r\nK\r\n--b\r\nContent-Disposition: form-data; name=\"u\"\r\n\r\nv\r\n--b--\r\n";
        let masked = s(masked_body(&ct, part.as_bytes()));
        assert!(
            masked.contains("********") && !masked.contains("\r\nK\r\n") && masked.contains("\r\nv\r\n"),
            "{masked}"
        );
    }

    #[test]
    fn a_marker_anywhere_in_a_request_skips_it() {
        let doc = json!({"variable": [{"key": "v", "value": "«auth:p:header:X»"}],
            "item": [{"name": "a", "request": {"url": "http://api.test/{{v}}"}},
                     {"name": "b", "request": {"url": "http://api.test/ok"}}]});
        let l = load(&doc.to_string(), &opts()).unwrap();
        assert_eq!(l.requests.len(), 1);
        assert_eq!(l.skipped[0].reason, "contains a reserved placeholder");
    }
}
