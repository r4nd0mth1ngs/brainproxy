//! Ported from ZAP StrictTransportSecurityScanRule (pscanrules, Apache License 2.0).
//!
//! 10035-4 (HSTS on a plain HTTP response) is only raised by ZAP at LOW threshold
//! and is not ported.

use std::sync::LazyLock;

use regex::Regex;

use super::common::{header_first, header_values, is_redirect, meta_http_equiv};
use crate::scan::{AlertDef, Confidence, Finding, Message, PassiveRule, Risk};

const TAGS: &[&str] = &["OWASP_2025_A02", "OWASP_2021_A05", "OWASP_2017_A06", "SYSTEMIC"];
const HSTS: &str = "Strict-Transport-Security";

macro_rules! hsts_alert {
    ($ref:literal, $name:literal, $desc:expr, $soln:expr, $refs:expr) => {
        AlertDef {
            alert_ref: $ref,
            name: $name,
            risk: Risk::Low,
            confidence: Confidence::High,
            cwe: 319,
            wasc: 15,
            description: $desc,
            solution: $soln,
            references: $refs,
            tags: TAGS,
        }
    };
}

static MISSING: AlertDef = hsts_alert!(
    "10035-1",
    "Strict-Transport-Security Header Not Set",
    "HTTP Strict Transport Security (HSTS) is a web security policy mechanism whereby a web server declares that \
        complying user agents (such as a web browser) are to interact with it using only secure HTTPS connections \
        (i.e. HTTP layered over TLS/SSL). HSTS is an IETF standards track protocol and is specified in RFC 6797.",
    "Ensure that your web server, application server, load balancer, etc. is configured to enforce \
        Strict-Transport-Security.",
    &[
        "https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Strict_Transport_Security_Cheat_Sheet.html",
        "https://owasp.org/www-community/Security_Headers",
        "https://en.wikipedia.org/wiki/HTTP_Strict_Transport_Security",
        "https://caniuse.com/stricttransportsecurity",
        "https://datatracker.ietf.org/doc/html/rfc6797",
    ]
);

static DISABLED: AlertDef = hsts_alert!(
    "10035-2",
    "Strict-Transport-Security Disabled",
    "A HTTP Strict Transport Security (HSTS) header was found, but it contains the directive max-age=0 which \
        disables the control and instructs browsers to reset any previous HSTS related settings. See RFC 6797 for \
        further details.\nHTTP Strict Transport Security (HSTS) is a web security policy mechanism whereby a web \
        server declares that complying user agents (such as a web browser) are to interact with it using only \
        secure HTTPS connections (i.e. HTTP layered over TLS/SSL).",
    "Review the configuration of this control. Ensure that your web server, application server, load balancer, etc. \
        is configured to set Strict-Transport-Security with an appropriate max-age value.",
    &["https://datatracker.ietf.org/doc/html/rfc6797#section-6.2"]
);

static MULTIPLE: AlertDef = hsts_alert!(
    "10035-3",
    "Strict-Transport-Security Multiple Header Entries (Non-compliant with Spec)",
    "HTTP Strict Transport Security (HSTS) headers were found, a response with multiple HSTS header entries is not \
        compliant with the specification (RFC 6797) and only the first HSTS header will be processed others will be \
        ignored by user agents or the HSTS policy may be incorrectly applied.\nHTTP Strict Transport Security (HSTS) \
        is a web security policy mechanism whereby a web server declares that complying user agents (such as a web \
        browser) are to interact with it using only secure HTTPS connections (i.e. HTTP layered over TLS/SSL).",
    "Ensure that only one component in your stack: code, web server, application server, load balancer, etc. is \
        configured to set or add a HTTP Strict-Transport-Security (HSTS) header.",
    &["https://datatracker.ietf.org/doc/html/rfc6797#section-8.1"]
);

static MISSING_MAX_AGE: AlertDef = hsts_alert!(
    "10035-5",
    "Strict-Transport-Security Missing Max-Age (Non-compliant with Spec)",
    "A HTTP Strict Transport Security (HSTS) header was found, but it is missing the max-age directive (or the \
        directive is missing a value). See RFC 6797 for further details.\nHTTP Strict Transport Security (HSTS) is a \
        web security policy mechanism whereby a web server declares that complying user agents (such as a web \
        browser) are to interact with it using only secure HTTPS connections (i.e. HTTP layered over TLS/SSL).",
    "Review the configuration of this control. Ensure that your web server, application server, load balancer, etc. \
        is configured to set Strict-Transport-Security with an appropriate max-age value.",
    &["https://datatracker.ietf.org/doc/html/rfc6797#section-6.2"]
);

static META: AlertDef = hsts_alert!(
    "10035-6",
    "Strict-Transport-Security Defined via META (Non-compliant with Spec)",
    "A HTTP Strict Transport Security (HSTS) META tag was found, defining HTTP Strict Transport Security (HSTS) via \
        a META tag is explicitly not supported by the spec (RFC 6797).",
    "Do not attempt to set HTTP Strict Transport Security (HSTS) via a META tag.",
    &["https://datatracker.ietf.org/doc/html/rfc6797#section-8.5"]
);

static MALFORMED_MAX_AGE: AlertDef = hsts_alert!(
    "10035-7",
    "Strict-Transport-Security Max-Age Malformed (Non-compliant with Spec)",
    "A HTTP Strict Transport Security (HSTS) header was found, but it contains quotes preceding the max-age \
        directive (the max-age value can be quoted, but the directive itself cannot be). See RFC 6797 for further \
        details.\nHTTP Strict Transport Security (HSTS) is a web security policy mechanism whereby a web server \
        declares that complying user agents (such as a web browser) are to interact with it using only secure HTTPS \
        connections (i.e. HTTP layered over TLS/SSL).",
    "Review the configuration of this control. Ensure that your web server, application server, load balancer, etc. \
        is configured to set Strict-Transport-Security with an appropriate format.",
    &["https://datatracker.ietf.org/doc/html/rfc6797#section-6.1"]
);

static MALFORMED_CONTENT: AlertDef = hsts_alert!(
    "10035-8",
    "Strict-Transport-Security Malformed Content (Non-compliant with Spec)",
    "A HTTP Strict Transport Security (HSTS) header was found, but it contains some content that was not expected \
        (perhaps curly quotes), the expectation is that the content be printable ASCII characters.",
    "Review the configuration of this control. Ensure that your web server, application server, load balancer, etc. \
        is configured to set Strict-Transport-Security with appropriate content.",
    &["https://datatracker.ietf.org/doc/html/rfc6797"]
);

static ALERTS: [&AlertDef; 7] =
    [&MISSING, &DISABLED, &MULTIPLE, &MISSING_MAX_AGE, &META, &MALFORMED_MAX_AGE, &MALFORMED_CONTENT];

static BAD_MAX_AGE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"(?i)\bmax-age\s*=\s*'*"*\s*0\s*"*'*\s*"#).unwrap());
static MAX_AGE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"(?i)\bmax-age\s*=\s*'*"*\s*\s*\d+\s*"*'*\s*"#).unwrap());
static MALFORMED_MAX_AGE_RE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r#"(?i)['+|"+]\s*max"#).unwrap());
static META_PRECHECK: LazyLock<regex::bytes::Regex> =
    LazyLock::new(|| regex::bytes::Regex::new(r"(?i)strict-transport-security").unwrap());

/// (scheme, host, explicit port) of an absolute URL, as commons-httpclient's URI
/// reports them (host case kept, port `None` when not explicit). `None` scheme
/// means a relative reference.
fn uri_parts(s: &str) -> (Option<&str>, Option<&str>, Option<&str>) {
    let scheme_end = s.find([':', '/', '?', '#']);
    let (scheme, rest) = match scheme_end {
        Some(i)
            if s.as_bytes()[i] == b':'
                && i > 0
                && s.as_bytes()[0].is_ascii_alphabetic()
                && s[..i].bytes().all(|b| b.is_ascii_alphanumeric() || b"+-.".contains(&b)) =>
        {
            (Some(&s[..i]), &s[i + 1..])
        }
        _ => (None, s),
    };
    let Some(auth) = rest.strip_prefix("//") else { return (scheme, None, None) };
    let auth = auth.split(['/', '?', '#']).next().unwrap_or("");
    let hostport = auth.rsplit('@').next().unwrap_or("");
    let (host, port) = if hostport.starts_with('[') {
        match hostport.find(']') {
            Some(e) => (&hostport[..=e], hostport[e + 1..].strip_prefix(':')),
            None => (hostport, None),
        }
    } else {
        match hostport.rsplit_once(':') {
            Some((h, p)) => (h, Some(p)),
            None => (hostport, None),
        }
    };
    (scheme, Some(host), port.filter(|p| !p.is_empty()))
}

/// ZAP (MEDIUM threshold) does not report a missing header on a redirect that
/// stays on the same HTTPS host/port, or is relative.
fn is_safe_redirect(msg: &Message) -> bool {
    let Some(loc) = header_first(msg, "Location") else { return false };
    let (scheme, host, port) = uri_parts(loc);
    let Some(scheme) = scheme else { return true };
    let (_, req_host, req_port) = uri_parts(&msg.url);
    scheme.eq_ignore_ascii_case("https") && host.is_some() && host == req_host && port == req_port
}

pub struct StrictTransportSecurity;

impl PassiveRule for StrictTransportSecurity {
    fn id(&self) -> u32 {
        10035
    }

    fn name(&self) -> &'static str {
        "Strict-Transport-Security Header"
    }

    fn alerts(&self) -> &'static [&'static AlertDef] {
        &ALERTS
    }

    fn scan(&self, msg: &Message, out: &mut Vec<Finding>) {
        if msg.is_https() {
            let sts: Vec<&str> = header_values(msg, HSTS).collect();
            match sts.as_slice() {
                [] => {
                    if !(is_redirect(msg.status) && is_safe_redirect(msg)) {
                        out.push(MISSING.raise("", ""));
                    }
                }
                [v] => {
                    if !v.bytes().all(|b| (0x20..=0x7e).contains(&b)) {
                        out.push(MALFORMED_CONTENT.raise("", HSTS));
                    } else if let Some(m) = BAD_MAX_AGE.find(v) {
                        out.push(DISABLED.raise("", m.as_str()));
                    } else if !MAX_AGE.is_match(v) {
                        out.push(MISSING_MAX_AGE.raise("", *v));
                    } else if MALFORMED_MAX_AGE_RE.is_match(v) {
                        out.push(MALFORMED_MAX_AGE.raise("", *v));
                    }
                }
                _ => out.push(MULTIPLE.raise("", "")),
            }
        }
        if META_PRECHECK.is_match(&msg.resp_body) {
            if let Some(meta) = meta_http_equiv(msg.body(), HSTS) {
                out.push(META.raise("", meta.attr("http-equiv").unwrap_or_default()));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scan::passive::util::testing::msg;

    fn refs(f: &[Finding]) -> Vec<&str> {
        f.iter().map(|f| f.def.alert_ref).collect()
    }

    #[test]
    fn flags_missing_and_bad_values() {
        assert_eq!(refs(&msg("https://a.test/").scan(&StrictTransportSecurity)), ["10035-1"]);
        let one = |v: &str| msg("https://a.test/").header(HSTS, v).scan(&StrictTransportSecurity);
        let f = one("max-age=0; includeSubDomains");
        assert_eq!((refs(&f), f[0].evidence.as_str()), (vec!["10035-2"], "max-age=0"));
        assert_eq!(refs(&one("includeSubDomains")), ["10035-5"]);
        assert_eq!(refs(&one("\"max-age=31536000\"")), ["10035-7"]);
        let f = one("max-age=31536000\u{201d}");
        assert_eq!((refs(&f), f[0].evidence.as_str()), (vec!["10035-8"], HSTS));
        let f =
            msg("https://a.test/").header(HSTS, "max-age=1").header(HSTS, "max-age=2").scan(&StrictTransportSecurity);
        assert_eq!(refs(&f), ["10035-3"]);
    }

    #[test]
    fn flags_meta_on_any_scheme() {
        let f = msg("http://a.test/")
            .html("<meta http-equiv=\"Strict-Transport-Security\" content=\"max-age=1\">")
            .scan(&StrictTransportSecurity);
        assert_eq!((refs(&f), f[0].evidence.as_str()), (vec!["10035-6"], "Strict-Transport-Security"));
    }

    #[test]
    fn redirects() {
        let r = |loc: &str| {
            msg("https://a.test/x").status(302).header("Location", loc).scan(&StrictTransportSecurity).len()
        };
        assert_eq!(r("/login"), 0);
        assert_eq!(r("https://a.test/login"), 0);
        assert_eq!(r("https://b.test/login"), 1);
        assert_eq!(r("https://a.test:8443/login"), 1);
        assert_eq!(r("http://a.test/login"), 1);
        assert_eq!(msg("https://a.test/").status(302).scan(&StrictTransportSecurity).len(), 1);
    }

    #[test]
    fn ignores_good_header_and_plain_http() {
        let ok = msg("https://a.test/").header(HSTS, "max-age=31536000; includeSubDomains");
        assert!(ok.scan(&StrictTransportSecurity).is_empty());
        assert!(msg("http://a.test/").header(HSTS, "max-age=0").scan(&StrictTransportSecurity).is_empty());
    }
}
