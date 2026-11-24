//! brainproxy's own rule: GraphQL misconfiguration (100012). Once per GraphQL endpoint (origin
//! and path).
//!
//! It runs on a request that carries a GraphQL document (see [`graphql::documents`]), or on one
//! answered with a JSON object holding `data` or `errors` at a path where history has such a
//! request (a persisted query's, say). It never looks for GraphQL at paths nothing was seen at.
//!
//! Every request it sends is a read of the root type's name (`__typename`) or the schema's
//! query type name, never a mutation, and the base request's own operation isn't sent again:
//!
//! 1. `query{__schema{queryType{name}}}`: the smallest introspection query. An answer naming
//!    the type raises **Introspection Enabled** (100012-1).
//! 2. A root field the base request selects, misspelt (`userx` for `user`): a "Did you mean"
//!    in the errors raises **Field Suggestions Enabled** (100012-2), at Info when introspection
//!    is on anyway. Without a root field to misspell, this request isn't sent.
//! 3. A JSON array of [`BATCH`] `{__typename}` queries, and one query with [`BATCH`] aliases of
//!    `__typename`: **Batching Allowed** (100012-3), Low for an array, Info for aliases alone
//!    (almost every server takes them). The size is fixed: it shows the limit is missing,
//!    nothing more.
//! 4. `{__typename}` as a GET query parameter, a form-encoded POST and a `text/plain` POST, the
//!    requests a page on another site can make a browser send without a preflight, with only
//!    the headers such a request carries (the session's cookies, not the app's own headers):
//!    **Queries Accepted over GET or a Simple POST** (100012-4), Medium when the base request
//!    sends cookies, Low otherwise.
//!
//! The GET carries a cache buster ([`canary::bust`]); the POSTs aren't cached. Every request
//! goes through [`Cx::send`], so the session and the scope guard apply.

use serde_json::{json, Value};

use crate::apiimport::graphql;
use crate::http::RawRequest;
use crate::scan::active::canary;
use crate::scan::active::{ActiveRule, BoxFuture, Cx, Response, RuleScope};
use crate::scan::{AlertDef, Confidence, Risk};

/// Queries in a batch, and aliases in one query: enough to show there's no limit, far from
/// a load test.
const BATCH: usize = 10;

const TAGS: &[&str] = &["OWASP_2025_A02", "OWASP_2021_A05", "OWASP_2017_A06", "WSTG-v42-APIT-01"];
const REFS: &[&str] = &[
    "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/12-API_Testing/01-Testing_GraphQL",
    "https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html",
];

static INTROSPECTION: AlertDef = AlertDef {
    alert_ref: "100012-1",
    name: "GraphQL Introspection Enabled",
    risk: Risk::Low,
    confidence: Confidence::High,
    cwe: 200,
    wasc: 13,
    description: "The GraphQL endpoint answers introspection queries (`__schema`), so anyone who can reach it can \
        download the whole schema: every query, mutation, type and argument, including those the application's \
        own pages never use. It maps the API for an attacker.",
    solution: "Turn introspection off in production, or allow it only to authenticated developers. Most GraphQL \
        servers have a setting for it.",
    references: REFS,
    tags: TAGS,
};

static SUGGESTIONS: AlertDef = AlertDef {
    alert_ref: "100012-2",
    name: "GraphQL Field Suggestions Enabled",
    risk: Risk::Low,
    confidence: Confidence::High,
    cwe: 209,
    wasc: 13,
    description: "Asked for a field that doesn't exist, the GraphQL endpoint answers \"Did you mean ...?\" with \
        the names of fields that do. With introspection off, those suggestions still let an attacker rebuild \
        the schema by guessing.",
    solution: "Turn field suggestions off in production (for example Apollo Server's \
        hideSchemaDetailsFromClientErrors, or a validation rule that strips \"Did you mean\" from errors).",
    references: REFS,
    tags: TAGS,
};

static BATCHING: AlertDef = AlertDef {
    alert_ref: "100012-3",
    name: "GraphQL Batching Allowed",
    risk: Risk::Low,
    confidence: Confidence::High,
    cwe: 799,
    wasc: 21,
    description: "The GraphQL endpoint runs many operations from one HTTP request: a JSON array of queries, or \
        one query that asks for the same field under many aliases. Rate limits that count HTTP requests then \
        count one where the server did many things, which lets an attacker guess passwords, one-time codes or \
        coupon codes many times per request.",
    solution: "Limit the number of operations in a batch and of aliases (or root fields) in a query, or turn \
        array batching off, and count each operation, not each HTTP request, against rate limits and lockouts.",
    references: REFS,
    tags: TAGS,
};

static CSRF: AlertDef = AlertDef {
    alert_ref: "100012-4",
    name: "GraphQL Queries Accepted over GET or a Simple POST",
    risk: Risk::Low,
    confidence: Confidence::Medium,
    cwe: 352,
    wasc: 9,
    description: "The GraphQL endpoint answers an operation sent as a GET query parameter, or as a POST whose \
        content type a form can send (application/x-www-form-urlencoded or text/plain). A page on another site \
        can make a visitor's browser send those without a CORS preflight, with the visitor's cookies: where the \
        session is a cookie and mutations go the same way, that is cross-site request forgery. Only a read was \
        sent; whether mutations are accepted the same way wasn't tried.",
    solution: "Accept operations only as POST with Content-Type application/json (or require a header a browser \
        won't send cross-site, as Apollo Server's CSRF prevention does), never run mutations sent over GET, and \
        give session cookies SameSite=Lax or Strict.",
    references: &[
        "https://owasp.org/www-community/attacks/csrf",
        "https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html",
        "https://graphql.github.io/graphql-over-http/draft/",
    ],
    tags: &["OWASP_2025_A01", "OWASP_2021_A01", "OWASP_2017_A05", "WSTG-v42-SESS-05", "WSTG-v42-APIT-01"],
};

static ALERTS: [&AlertDef; 4] = [&INTROSPECTION, &SUGGESTIONS, &BATCHING, &CSRF];

const TYPENAME: &str = "query{__typename}";
const INTROSPECT: &str = "query{__schema{queryType{name}}}";

/// Headers a browser puts on a request another site makes it send; the app's own headers
/// (a CSRF token, `Authorization`, Apollo's preflight header) are left off.
const SIMPLE_HEADERS: &[&str] =
    &["host", "cookie", "user-agent", "accept", "accept-language", "accept-encoding", "connection"];

/// Whether `v` is an answer with `data.__typename`.
fn typename(v: &Value) -> bool {
    v.pointer("/data/__typename").is_some_and(Value::is_string)
}

fn json_of(resp: &Response) -> Option<Value> {
    serde_json::from_slice(&resp.body).ok()
}

/// A JSON object with a top-level `data` or `errors`: how a GraphQL server answers.
fn graphql_answer(resp: &Response) -> bool {
    json_of(resp)
        .as_ref()
        .and_then(Value::as_object)
        .is_some_and(|o| o.contains_key("data") || o.contains_key("errors"))
}

/// The messages of an answer's `errors`.
fn error_messages(v: &Value) -> Vec<&str> {
    v.get("errors")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|e| e.get("message").and_then(Value::as_str))
        .collect()
}

#[derive(Debug, PartialEq)]
enum Token<'a> {
    Name(&'a str),
    Punct(&'a str),
    /// A string, number or anything else that can't name a field.
    Other,
}

/// GraphQL's lexical tokens, as far as finding a root field needs: names, punctuators, and
/// strings (block strings too) and comments skipped so a brace in one isn't counted.
fn tokens(doc: &str) -> Vec<Token<'_>> {
    let b = doc.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i < b.len() {
        let c = b[i];
        if c.is_ascii_whitespace() || c == b',' {
            i += 1;
        } else if c == b'#' {
            while i < b.len() && b[i] != b'\n' && b[i] != b'\r' {
                i += 1;
            }
        } else if doc.get(i..).is_some_and(|s| s.starts_with("\"\"\"")) {
            i += 3;
            while i < b.len() && !doc.get(i..).is_some_and(|s| s.starts_with("\"\"\"")) {
                i += if b[i] == b'\\' { 2 } else { 1 };
            }
            i += 3;
            out.push(Token::Other);
        } else if c == b'"' {
            i += 1;
            while i < b.len() && b[i] != b'"' {
                i += if b[i] == b'\\' { 2 } else { 1 };
            }
            i += 1;
            out.push(Token::Other);
        } else if c == b'_' || c.is_ascii_alphabetic() {
            let start = i;
            while i < b.len() && (b[i] == b'_' || b[i].is_ascii_alphanumeric()) {
                i += 1;
            }
            out.push(Token::Name(&doc[start..i]));
        } else if doc.get(i..).is_some_and(|s| s.starts_with("...")) {
            out.push(Token::Punct("..."));
            i += 3;
        } else if b"{}():@$".contains(&c) {
            out.push(Token::Punct(&doc[i..i + 1]));
            i += 1;
        } else {
            i += 1;
            out.push(Token::Other);
        }
    }
    out
}

/// The first field a query operation in `doc` selects at its root, aliases resolved, meta
/// fields (`__typename`) and fragment spreads passed over. Fragments, mutations and
/// subscriptions are skipped: their fields aren't the query type's.
fn root_field(doc: &str) -> Option<String> {
    let t = tokens(doc);
    let mut i = 0;
    while i < t.len() {
        let query = matches!(t[i], Token::Name("query") | Token::Punct("{"));
        // The definition's selection set: the first `{` outside its variable definitions.
        let mut parens = 0;
        while i < t.len() {
            match t[i] {
                Token::Punct("(") => parens += 1,
                Token::Punct(")") => parens -= 1,
                Token::Punct("{") if parens == 0 => break,
                _ => {}
            }
            i += 1;
        }
        let (mut depth, mut parens) = (0usize, 0usize);
        while i < t.len() {
            match t[i] {
                Token::Punct("{") => depth += 1,
                Token::Punct("}") => {
                    depth = depth.saturating_sub(1);
                    if depth == 0 {
                        i += 1;
                        break;
                    }
                }
                Token::Punct("(") => parens += 1,
                Token::Punct(")") => parens = parens.saturating_sub(1),
                Token::Name(name) if query && depth == 1 && parens == 0 => {
                    let prev = |n: usize| i.checked_sub(n).map(|p| &t[p]);
                    // `...F`, `... on Type`, `@directive`, `$variable`.
                    let spread = matches!(prev(1), Some(Token::Punct("..." | "@" | "$")))
                        || (name == "on" && matches!(prev(1), Some(Token::Punct("..."))))
                        || (matches!(prev(1), Some(Token::Name("on"))) && matches!(prev(2), Some(Token::Punct("..."))));
                    if !spread {
                        let field = match (t.get(i + 1), t.get(i + 2)) {
                            (Some(Token::Punct(":")), Some(Token::Name(f))) => {
                                i += 2;
                                *f
                            }
                            _ => name,
                        };
                        if !field.starts_with("__") {
                            return Some(field.to_string());
                        }
                    }
                }
                _ => {}
            }
            i += 1;
        }
    }
    None
}

/// A root field to misspell: one the base request's queries select, or failing that (a
/// persisted query), a key of its answer's `data`.
fn known_field(request: &[u8], resp: &Response) -> Option<String> {
    let docs = graphql::documents(request);
    docs.iter().filter(|d| !graphql::defines_mutation(d)).find_map(|d| root_field(d)).or_else(|| {
        let data = json_of(resp)?.get("data")?.as_object()?.keys().find(|k| !k.starts_with("__"))?.clone();
        Some(data)
    })
}

/// Whether history holds a request carrying a GraphQL document at this origin and path.
fn seen_at(project: &std::path::Path, target: &crate::http::Target, path: &str) -> rusqlite::Result<bool> {
    use rusqlite::OpenFlags;
    let conn = rusqlite::Connection::open_with_flags(project, OpenFlags::SQLITE_OPEN_READ_ONLY)?;
    conn.busy_timeout(std::time::Duration::from_secs(2))?;
    let mut st = conn.prepare(
        "SELECT request FROM history WHERE scheme = ?1 AND host = ?2 AND port = ?3 AND path = ?4
         ORDER BY id DESC LIMIT 50",
    )?;
    let rows =
        st.query_map(rusqlite::params![target.scheme, target.host, target.port, path], |r| r.get::<_, Vec<u8>>(0))?;
    for r in rows {
        if !graphql::documents(&r?).is_empty() {
            return Ok(true);
        }
    }
    Ok(false)
}

/// `request` with a body of this type.
fn with_body(request: Vec<u8>, content_type: &str, body: &[u8]) -> Vec<u8> {
    let mut out = RawRequest::from_bytes(request)
        .set_header("Content-Type", content_type)
        .set_header("Content-Length", &body.len().to_string())
        .into_bytes();
    out.extend_from_slice(body);
    out
}

/// `request` with only the headers in [`SIMPLE_HEADERS`].
fn simple(request: Vec<u8>) -> Vec<u8> {
    let raw = RawRequest::from_bytes(request);
    let Ok(head) = raw.head() else { return raw.into_bytes() };
    head.headers
        .iter()
        .filter(|(k, _)| !SIMPLE_HEADERS.iter().any(|s| k.eq_ignore_ascii_case(s)))
        .fold(raw, |r, (k, _)| r.remove_header(k))
        .into_bytes()
}

fn query_body(query: &str) -> Vec<u8> {
    serde_json::to_vec(&json!({ "query": query })).unwrap_or_default()
}

pub struct GraphqlMisconfiguration;

impl GraphqlMisconfiguration {
    /// A POST of a JSON body to the endpoint, with the base request's headers.
    fn post_json(cx: &Cx, path: &str, body: &[u8]) -> Vec<u8> {
        with_body(cx.request_for("POST", path), "application/json", body)
    }
}

impl ActiveRule for GraphqlMisconfiguration {
    fn id(&self) -> u32 {
        100012
    }

    fn name(&self) -> &'static str {
        "GraphQL Misconfiguration"
    }

    fn alerts(&self) -> &'static [&'static AlertDef] {
        &ALERTS
    }

    fn scope(&self) -> RuleScope {
        RuleScope::Page
    }

    fn scan<'a>(&'a self, cx: &'a Cx) -> BoxFuture<'a> {
        Box::pin(async move {
            let base = cx.base();
            let path = base.path.clone();
            let key = format!("100012:{}{path}", cx.target().origin());
            let carries = !graphql::documents(cx.base_request()).is_empty();
            if !carries {
                // History is read once per endpoint: a JSON API's every answer may hold `data`.
                if !graphql_answer(cx.base_response()) || !cx.once(&format!("{key}:looked")) {
                    return;
                }
                let (project, target, at) = (cx.project().to_path_buf(), cx.target().clone(), path.clone());
                let seen = tokio::task::spawn_blocking(move || seen_at(&project, &target, &at).unwrap_or(false))
                    .await
                    .unwrap_or(false);
                if !seen {
                    return;
                }
            }
            if !cx.once(&key) {
                return;
            }
            let cookies = RawRequest::from_bytes(cx.base_request().to_vec())
                .head()
                .is_ok_and(|h| h.headers.iter().any(|(k, v)| k.eq_ignore_ascii_case("cookie") && !v.trim().is_empty()));

            // 1. Introspection.
            let mut introspection = false;
            if let Ok(resp) = cx.send(Self::post_json(cx, &path, &query_body(INTROSPECT))).await {
                let name = json_of(&resp)
                    .and_then(|v| v.pointer("/data/__schema/queryType/name").and_then(Value::as_str).map(String::from));
                if let Some(name) = name {
                    introspection = true;
                    let info = format!(
                        "The query type is named {name}. Only the query type's name was asked for; \
                         `import api --graphql` with this endpoint's URL reads the whole schema."
                    );
                    cx.report(INTROSPECTION.raise("query", "__schema").attack(INTROSPECT).other_info(info), &resp);
                }
            }

            // 2. Field suggestions, from a misspelt root field.
            if let Some(field) = known_field(cx.base_request(), cx.base_response()).filter(|_| !cx.stopped()) {
                let wrong = format!("{field}x");
                let query = format!("query{{{wrong}}}");
                if let Ok(resp) = cx.send(Self::post_json(cx, &path, &query_body(&query))).await {
                    let answer = json_of(&resp).unwrap_or_default();
                    if let Some(msg) = error_messages(&answer).into_iter().find(|m| m.contains("Did you mean")) {
                        let mut info = format!("Asked for {wrong}, the server answered: {msg}");
                        if introspection {
                            info.push_str(
                                "\nIntrospection is on too (100012-1), so the suggestions give away nothing the \
                                 schema doesn't.",
                            );
                        }
                        let risk = if introspection { Risk::Info } else { SUGGESTIONS.risk };
                        let finding = SUGGESTIONS.raise("query", "Did you mean").attack(query).other_info(info);
                        cx.report(finding.risk(risk), &resp);
                    }
                }
            }

            // 3. Batching: an array of queries, then aliases in one query.
            if cx.stopped() {
                return;
            }
            let array: Vec<Value> = (0..BATCH).map(|_| json!({ "query": TYPENAME })).collect();
            let array_body = serde_json::to_vec(&array).unwrap_or_default();
            let batched = cx.send(Self::post_json(cx, &path, &array_body)).await.ok().filter(|resp| {
                json_of(resp)
                    .as_ref()
                    .and_then(Value::as_array)
                    .is_some_and(|answers| answers.iter().filter(|a| typename(a)).count() == BATCH)
            });
            if cx.stopped() {
                return;
            }
            let aliases: Vec<String> = (0..BATCH).map(|i| format!("a{i}:__typename")).collect();
            let alias_query = format!("query{{{}}}", aliases.join(" "));
            let aliased =
                cx.send(Self::post_json(cx, &path, &query_body(&alias_query))).await.ok().filter(|resp| {
                    json_of(resp).as_ref().and_then(|v| v.get("data")).and_then(Value::as_object).is_some_and(|data| {
                        (0..BATCH).all(|i| data.get(&format!("a{i}")).is_some_and(Value::is_string))
                    })
                });
            match (&batched, &aliased) {
                (Some(resp), _) => {
                    let also = if aliased.is_some() {
                        format!(" One query with {BATCH} aliases of __typename was answered in full too.")
                    } else {
                        String::new()
                    };
                    let info = format!(
                        "A JSON array of {BATCH} queries got {BATCH} answers in one response.{also} \
                         Only {BATCH} were sent: the limit, if any, is higher."
                    );
                    let attack = format!("[{{\"query\":\"{TYPENAME}\"}} × {BATCH}]");
                    cx.report(BATCHING.raise("JSON array batch", "__typename").attack(attack).other_info(info), resp);
                }
                (None, Some(resp)) => {
                    let info = format!(
                        "One query with {BATCH} aliases of __typename was answered in full; a JSON array of \
                         queries wasn't. Almost every GraphQL server allows aliases, so this matters where a \
                         field guesses a secret (a login, a one-time code) and rate limits count requests."
                    );
                    cx.report(
                        BATCHING.raise("aliases", "a9").risk(Risk::Info).attack(alias_query).other_info(info),
                        resp,
                    );
                }
                (None, None) => {}
            }

            // 4. The requests another site can make a browser send.
            let mut accepted: Vec<(&str, Response)> = Vec::new();
            let encoded: String =
                url::form_urlencoded::Serializer::new(String::new()).append_pair("query", TYPENAME).finish();
            let origin = format!("https://{}", canary::canary());
            let probes: [(&str, Vec<u8>); 3] = [
                ("GET", canary::bust(&simple(cx.request_for("GET", &format!("{path}?{encoded}"))))),
                (
                    "POST application/x-www-form-urlencoded",
                    with_body(
                        RawRequest::from_bytes(simple(cx.request_for("POST", &path)))
                            .set_header("Origin", &origin)
                            .into_bytes(),
                        "application/x-www-form-urlencoded",
                        encoded.as_bytes(),
                    ),
                ),
                (
                    "POST text/plain",
                    with_body(
                        RawRequest::from_bytes(simple(cx.request_for("POST", &path)))
                            .set_header("Origin", &origin)
                            .into_bytes(),
                        "text/plain",
                        &query_body(TYPENAME),
                    ),
                ),
            ];
            for (how, request) in probes {
                if cx.stopped() {
                    return;
                }
                if let Ok(resp) = cx.send(request).await {
                    if json_of(&resp).as_ref().is_some_and(typename) {
                        accepted.push((how, resp));
                    }
                }
            }
            if let Some((how, resp)) = accepted.first() {
                let ways: Vec<&str> = accepted.iter().map(|(h, _)| *h).collect();
                let mut info = format!(
                    "{{__typename}} was answered when sent as: {}. Each carried only the headers a browser \
                     would send cross-site (no Authorization or custom headers; the POSTs with a foreign Origin).",
                    ways.join(", ")
                );
                info.push_str(if cookies {
                    " The base request authenticates with cookies, which a browser adds to such a request."
                } else {
                    " The base request sends no cookies, so a forged request would most likely run without a session."
                });
                let finding = CSRF
                    .raise(*how, "__typename")
                    .risk(if cookies { Risk::Medium } else { Risk::Low })
                    .attack(format!("{how}: query={TYPENAME}"))
                    .other_info(info);
                cx.report(finding, resp);
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_first_query_field_is_found() {
        assert_eq!(root_field("query { user(id: 1) { name } }").as_deref(), Some("user"));
        assert_eq!(root_field("{ __typename me: viewer { id } }").as_deref(), Some("viewer"));
        assert_eq!(
            root_field("fragment F on User { secret } query Q($a: String = \"{x}\") @live { ...F ... on Query { deep } items }")
                .as_deref(),
            Some("items")
        );
        assert_eq!(root_field("# { commented }\nquery { \"\"\" { \"\"\" posts }").as_deref(), Some("posts"));
        assert_eq!(root_field("mutation { deleteUser(id: 1) }"), None);
        assert_eq!(root_field("subscription { onEvent } query { ok }").as_deref(), Some("ok"));
        assert_eq!(root_field("{ __typename }"), None);
        assert_eq!(root_field("{ unclosed"), Some("unclosed".into()));
    }

    #[test]
    fn simple_requests_keep_only_what_a_browser_sends() {
        let req = b"POST /graphql HTTP/1.1\r\nHost: a\r\nCookie: s=1\r\nAuthorization: Bearer t\r\n\
            Apollo-Require-Preflight: true\r\nX-CSRF-Token: z\r\nAccept: */*\r\n\r\n";
        let out = String::from_utf8(simple(req.to_vec())).unwrap();
        assert_eq!(out, "POST /graphql HTTP/1.1\r\nHost: a\r\nCookie: s=1\r\nAccept: */*\r\n\r\n");
        let body = String::from_utf8(with_body(out.into_bytes(), "text/plain", b"{}")).unwrap();
        assert!(body.ends_with("Content-Type: text/plain\r\nContent-Length: 2\r\n\r\n{}"), "{body}");
    }
}
