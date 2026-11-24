//! Ported from ZAP CacheableScanRule (pscanrulesBeta, Apache License 2.0).
//!
//! Follows RFC 7234: whether a shared cache may store the response (sections 3 and 4.2.2),
//! and then whether it may serve it without asking the server again (fresh, or stale
//! without a directive that forbids it).

use super::common::header_values;
use crate::scan::passive::util::parse_http_date;
use crate::scan::{AlertDef, Confidence, Finding, Message, PassiveRule, Risk};

const TAGS: &[&str] = &["OWASP_2025_A07", "OWASP_2021_A07", "OWASP_2017_A02", "WSTG-v42-ATHN-06", "SYSTEMIC"];
const REFS: &[&str] = &[
    "https://datatracker.ietf.org/doc/html/rfc7234",
    "https://datatracker.ietf.org/doc/html/rfc7231",
    "https://www.w3.org/Protocols/rfc2616/rfc2616-sec13.html",
];

static NON_STORABLE: AlertDef = AlertDef {
    alert_ref: "10049-1",
    name: "Non-Storable Content",
    risk: Risk::Info,
    confidence: Confidence::Medium,
    cwe: 524,
    wasc: 13,
    description: "The response contents are not storable by caching components such as proxy servers. If the \
        response does not contain sensitive, personal or user-specific information, it may benefit from being stored \
        and cached, to improve performance.",
    solution: "The content may be marked as storable by ensuring that the following conditions are satisfied:\nThe \
        request method must be understood by the cache and defined as being cacheable (\"GET\", \"HEAD\", and \
        \"POST\" are currently defined as cacheable)\nThe response status code must be understood by the cache (one \
        of the 1XX, 2XX, 3XX, 4XX, or 5XX response classes are generally understood)\nThe \"no-store\" cache \
        directive must not appear in the request or response header fields\nFor caching by \"shared\" caches such \
        as \"proxy\" caches, the \"private\" response directive must not appear in the response\nFor caching by \
        \"shared\" caches such as \"proxy\" caches, the \"Authorization\" header field must not appear in the \
        request, unless the response explicitly allows it (using one of the \"must-revalidate\", \"public\", or \
        \"s-maxage\" Cache-Control response directives)\nIn addition to the conditions above, at least one of the \
        following conditions must also be satisfied by the response:\nIt must contain an \"Expires\" header \
        field\nIt must contain a \"max-age\" response directive\nFor \"shared\" caches such as \"proxy\" caches, it \
        must contain a \"s-maxage\" response directive\nIt must contain a \"Cache Control Extension\" that allows \
        it to be cached\nIt must have a status code that is defined as cacheable by default (200, 203, 204, 206, \
        300, 301, 404, 405, 410, 414, 501).",
    references: REFS,
    tags: TAGS,
};

static STORABLE_NON_CACHEABLE: AlertDef = AlertDef {
    alert_ref: "10049-2",
    name: "Storable but Non-Cacheable Content",
    risk: Risk::Info,
    confidence: Confidence::Medium,
    cwe: 524,
    wasc: 13,
    description: "The response contents are storable by caching components such as proxy servers, but will not be \
        retrieved directly from the cache, without validating the request upstream, in response to similar requests \
        from other users.",
    // ZAP gives none: a cache asks the server before reusing the response, so nothing is to be done.
    solution: "No action is needed: a cache validates the response with the server before reusing it.",
    references: REFS,
    tags: TAGS,
};

static STORABLE_CACHEABLE: AlertDef = AlertDef {
    alert_ref: "10049-3",
    name: "Storable and Cacheable Content",
    risk: Risk::Info,
    confidence: Confidence::Medium,
    cwe: 524,
    wasc: 13,
    description: "The response contents are storable by caching components such as proxy servers, and may be \
        retrieved directly from the cache, rather than from the origin server by the caching servers, in response \
        to similar requests from other users. If the response data is sensitive, personal or user-specific, this \
        may result in sensitive information being leaked. In some cases, this may even result in a user gaining \
        complete control of the session of another user, depending on the configuration of the caching components \
        in use in their environment. This is primarily an issue where \"shared\" caching servers such as \"proxy\" \
        caches are configured on the local network. This configuration is typically found in corporate or \
        educational environments, for instance.",
    solution: "Validate that the response does not contain sensitive, personal or user-specific information. If it \
        does, consider the use of the following HTTP response headers, to limit, or prevent the content being stored \
        and retrieved from the cache by another user:\nCache-Control: no-cache, no-store, must-revalidate, \
        private\nPragma: no-cache\nExpires: 0\nThis configuration directs both HTTP 1.0 and HTTP 1.1 compliant \
        caching servers to not store the response, and to not retrieve the response (without validation) from the \
        cache, in response to a similar request.",
    references: REFS,
    tags: TAGS,
};

static ALERTS: [&AlertDef; 3] = [&NON_STORABLE, &STORABLE_NON_CACHEABLE, &STORABLE_CACHEABLE];

const LIBERAL_LIFETIME: &str = "In the absence of an explicitly specified caching lifetime directive in the \
    response, a liberal lifetime heuristic of 1 year was assumed. This is permitted by rfc7234.";
const STALE_NOT_BLOCKED: &str = "The response is stale, and stale responses are not configured to be re-validated \
    or blocked, using the 'must-revalidate', 'proxy-revalidate', 's-maxage', or 'max-age' response 'Cache-Control' \
    directives.";
const SECONDS_IN_YEAR: i64 = 365 * 24 * 3600;
/// Status codes cacheable by default (RFC 7231 section 6.1).
const CACHEABLE_STATUS: [u16; 11] = [200, 203, 204, 206, 300, 301, 404, 405, 410, 414, 501];

/// The directives of header values as ZAP splits them: on spaces, less one trailing comma.
/// (`max-age=0,no-store` without a space stays one token, as in ZAP.)
fn tokens<'a>(values: &'a [&'a str]) -> impl Iterator<Item = &'a str> + 'a {
    values.iter().flat_map(|v| v.split(' ')).map(|t| t.strip_suffix(',').unwrap_or(t))
}

/// The number after `prefix` up to a comma; None when it isn't one.
fn age(token: &str, prefix: &str) -> Option<i64> {
    let rest = token.get(prefix.len()..)?;
    rest.split(',').next()?.parse().ok()
}

/// A lifetime from the single directive starting with `prefix`; two or more cancel each other.
fn lifetime_from(tokens: impl Iterator<Item = String>, prefix: &str) -> Option<(i64, String)> {
    let found: Vec<(i64, String)> = tokens
        .filter(|t| t.to_ascii_lowercase().starts_with(prefix))
        .filter_map(|t| age(&t, prefix).map(|a| (a, t)))
        .collect();
    match found.as_slice() {
        [one] => Some(one.clone()),
        _ => None,
    }
}

pub struct Cacheability;

impl PassiveRule for Cacheability {
    fn id(&self) -> u32 {
        10049
    }

    fn name(&self) -> &'static str {
        "Content Cacheability"
    }

    fn alerts(&self) -> &'static [&'static AlertDef] {
        &ALERTS
    }

    fn scan(&self, msg: &Message, out: &mut Vec<Finding>) {
        out.push(judge(msg));
    }
}

fn judge(msg: &Message) -> Finding {
    let method = msg.method.to_ascii_uppercase();
    if !["GET", "HEAD", "POST"].contains(&method.as_str()) {
        return NON_STORABLE.raise("", format!("{} ", msg.method));
    }
    if !(1..=5).contains(&(msg.status / 100)) {
        return NON_STORABLE.raise("", msg.status.to_string());
    }
    let cc: Vec<&str> = header_values(msg, "Cache-Control").collect();
    let mut both: Vec<&str> = msg.req_headers_named("Pragma").map(str::trim).collect();
    both.extend(header_values(msg, "Pragma"));
    both.extend(msg.req_headers_named("Cache-Control").map(str::trim));
    both.extend(cc.iter().copied());
    if let Some(t) = tokens(&both).find(|t| t.eq_ignore_ascii_case("no-store")) {
        return NON_STORABLE.raise("", t);
    }
    if let Some(t) = tokens(&cc).find(|t| t.eq_ignore_ascii_case("private")) {
        return NON_STORABLE.raise("", t);
    }
    let lower = |t: &str| t.to_ascii_lowercase();
    // A shared cache stores an authorized response only when the response allows it.
    if msg.req_header("Authorization").is_some()
        && !tokens(&cc).map(lower).any(|t| t == "must-revalidate" || t == "public" || t.starts_with("s-maxage="))
    {
        return NON_STORABLE.raise("", "Authorization:");
    }
    let expires: Vec<&str> = header_values(msg, "Expires").collect();
    let explicit =
        tokens(&cc).map(lower).any(|t| t.starts_with("max-age=") || t.starts_with("s-maxage=") || t == "public");
    if expires.is_empty() && !explicit && !CACHEABLE_STATUS.contains(&msg.status) {
        return NON_STORABLE.raise("", msg.status.to_string());
    }
    if let Some(t) = tokens(&cc).find(|t| t.eq_ignore_ascii_case("no-cache")) {
        return STORABLE_NON_CACHEABLE.raise("", t);
    }
    // Lifetime: s-maxage, else max-age (also split on commas), else Expires - Date.
    let lifetime = lifetime_from(tokens(&cc).map(str::to_string), "s-maxage=")
        .or_else(|| {
            let split: Vec<String> =
                cc.iter().flat_map(|v| v.split([' ', ',']).filter(|t| !t.is_empty()).map(str::to_string)).collect();
            lifetime_from(split.into_iter(), "max-age=")
        })
        .or_else(|| {
            let [exp] = expires.as_slice() else { return None };
            let dates: Vec<&str> = header_values(msg, "Date").collect();
            let [date] = dates.as_slice() else { return None };
            // An Expires that isn't a date means already expired (RFC 7234 section 5.3).
            let Some(e) = parse_http_date(exp) else { return Some((0, exp.to_string())) };
            parse_http_date(date).map(|d| (e - d, exp.to_string()))
        });
    let (lifetime, evidence, other) = match lifetime {
        Some((l, e)) => (l, e, ""),
        None => (SECONDS_IN_YEAR, String::new(), LIBERAL_LIFETIME),
    };
    if lifetime > 0 {
        return STORABLE_CACHEABLE.raise("", evidence).other_info(other);
    }
    let blocks_stale = tokens(&cc).find(|t| {
        let t = t.to_ascii_lowercase();
        t == "must-revalidate" || t == "proxy-revalidate" || t.starts_with("s-maxage=") || t.starts_with("max-age=")
    });
    match blocks_stale {
        Some(t) => STORABLE_NON_CACHEABLE.raise("", t),
        None => STORABLE_CACHEABLE.raise("", "").other_info(STALE_NOT_BLOCKED),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scan::passive::util::testing::msg;

    fn one(m: crate::scan::passive::util::testing::M) -> (&'static str, String, String) {
        let f = m.scan(&Cacheability);
        assert_eq!(f.len(), 1);
        (f[0].def.alert_ref, f[0].evidence.clone(), f[0].other_info.clone())
    }

    #[test]
    fn not_storable() {
        assert_eq!(one(msg("https://a.test/").method("PUT")).1, "PUT ");
        assert_eq!(one(msg("https://a.test/").header("Cache-Control", "no-cache, no-store")).1, "no-store");
        assert_eq!(one(msg("https://a.test/").req_header("Pragma", "no-store")).0, "10049-1");
        assert_eq!(one(msg("https://a.test/").header("Cache-Control", "private, max-age=60")).1, "private");
        let auth =
            one(msg("https://a.test/").req_header("Authorization", "Basic x").header("Cache-Control", "max-age=9"));
        assert_eq!(auth.1, "Authorization:");
        assert_eq!(one(msg("https://a.test/").status(302)).1, "302");
    }

    #[test]
    fn storable_but_validated() {
        assert_eq!(
            one(msg("https://a.test/").header("Cache-Control", "no-cache")),
            ("10049-2", "no-cache".into(), "".into())
        );
        let stale = one(msg("https://a.test/").header("Cache-Control", "max-age=0, must-revalidate"));
        assert_eq!((stale.0, stale.1.as_str()), ("10049-2", "max-age=0"));
    }

    #[test]
    fn storable_and_cacheable() {
        assert_eq!(one(msg("https://a.test/").header("Cache-Control", "public, max-age=600")).1, "max-age=600");
        assert_eq!(one(msg("https://a.test/").header("Cache-Control", "s-maxage=60")).1, "s-maxage=60");
        let heuristic = one(msg("https://a.test/"));
        assert_eq!((heuristic.0, heuristic.2.as_str()), ("10049-3", LIBERAL_LIFETIME));
        let expires = one(msg("https://a.test/")
            .header("Date", "Tue, 24 Nov 2026 10:00:00 GMT")
            .header("Expires", "Tue, 24 Nov 2026 11:00:00 GMT"));
        assert_eq!(expires.1, "Tue, 24 Nov 2026 11:00:00 GMT");
        // Expired, with nothing to stop a cache serving it stale.
        let stale = one(msg("https://a.test/").header("Date", "Tue, 24 Nov 2026 10:00:00 GMT").header("Expires", "0"));
        assert_eq!((stale.0, stale.1.as_str(), stale.2.as_str()), ("10049-3", "", STALE_NOT_BLOCKED));
        // Authorized, but the response says a shared cache may keep it.
        let public = one(msg("https://a.test/")
            .req_header("Authorization", "Bearer x")
            .header("Cache-Control", "public, max-age=5"));
        assert_eq!(public.0, "10049-3");
    }
}
