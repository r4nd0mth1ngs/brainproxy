//! Ported from ZAP ExternalRedirectScanRule (ascanrules, Apache License 2.0).
//!
//! ZAP strips JavaScript comments with the Rhino parser before re-checking script
//! redirects; here a small tokenizer finds `//` and `/* */` comments outside string
//! literals instead.

use std::sync::LazyLock;

use regex::Regex;

use super::common;
use crate::scan::active::{ActiveRule, BoxFuture, Cx, Response, RuleScope, Strength};
use crate::scan::passive::util::{find_ci, tags};
use crate::scan::{AlertDef, Confidence, Risk};

macro_rules! alert {
    ($name:ident, $ref:literal) => {
        static $name: AlertDef = AlertDef {
            alert_ref: $ref,
            name: "External Redirect",
            risk: Risk::High,
            confidence: Confidence::Medium,
            cwe: 601,
            wasc: 38,
            description: DESCRIPTION,
            solution: SOLUTION,
            references: REFERENCES,
            tags: &["API_2023_API6", "OWASP_2025_A05", "OWASP_2021_A03", "OWASP_2017_A01", "WSTG-v42-CLNT-04"],
        };
    };
}

const DESCRIPTION: &str = "URL redirectors represent common functionality employed by web sites to forward an incoming request to an \
        alternate resource. This can be done for a variety of reasons and is often done to allow resources to be moved \
        within the directory structure and to avoid breaking functionality for users that request the resource at its \
        previous location. URL redirectors may also be used to implement load balancing, leveraging abbreviated URLs or \
        recording outgoing links. It is this last implementation which is often used in phishing attacks as described \
        in the example below. URL redirectors do not necessarily represent a direct security vulnerability but can be \
        abused by attackers trying to social engineer victims into believing that they are navigating to a site other \
        than the true destination.";
const SOLUTION: &str = "Assume all input is malicious. Use an \"accept known good\" input validation strategy, i.e., use an allow list \
        of acceptable inputs that strictly conform to specifications. Reject any input that does not strictly conform \
        to specifications, or transform it into something that does. Do not rely exclusively on looking for malicious \
        or malformed inputs (i.e., do not rely on a deny list). However, deny lists can be useful for detecting \
        potential attacks or determining which inputs are so malformed that they should be rejected outright.\n\nWhen \
        performing input validation, consider all potentially relevant properties, including length, type of input, the \
        full range of acceptable values, missing or extra inputs, syntax, consistency across related fields, and \
        conformance to business rules. As an example of business rule logic, \"boat\" may be syntactically valid \
        because it only contains alphanumeric characters, but it is not valid if you are expecting colors such as \
        \"red\" or \"blue.\"\n\nUse an allow list of approved URLs or domains to be used for redirection.\n\nUse an \
        intermediate disclaimer page that provides the user with a clear warning that they are leaving your site. \
        Implement a long timeout before the redirect occurs, or force the user to click on the link. Be careful to \
        avoid XSS problems when generating the disclaimer page.\n\nWhen the set of acceptable objects, such as \
        filenames or URLs, is limited or known, create a mapping from a set of fixed input values (such as numeric IDs) \
        to the actual filenames or URLs, and reject all other inputs.\n\nFor example, ID 1 could map to \"/login.asp\" \
        and ID 2 could map to \"https://www.example.com/\". Features such as the ESAPI AccessReferenceMap provide this \
        capability.\n\nUnderstand all the potential areas where untrusted inputs can enter your software: parameters or \
        arguments, cookies, anything read from the network, environment variables, reverse DNS lookups, query results, \
        request headers, URL components, e-mail, files, databases, and any external systems that provide data to the \
        application. Remember that such inputs may be obtained indirectly through API calls.\n\nMany open redirect \
        problems occur because the programmer assumed that certain inputs could not be modified, such as cookies and \
        hidden form fields.";
const REFERENCES: &[&str] = &[
    "https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html",
    "https://cwe.mitre.org/data/definitions/601.html",
];

alert!(ALERT_LOCATION, "20019-1");
alert!(ALERT_REFRESH, "20019-2");
alert!(ALERT_META, "20019-3");
alert!(ALERT_JS, "20019-4");

static ALERTS: [&AlertDef; 4] = [&ALERT_LOCATION, &ALERT_REFRESH, &ALERT_META, &ALERT_JS];

const REASON_LOCATION_HEADER: &str =
    "The response contains a redirect in its Location header which allows an external Url to be set.";
const REASON_REFRESH_HEADER: &str =
    "The response contains a redirect in its Refresh header which allows an external Url to be set.";
const REASON_LOCATION_META: &str =
    "The response contains a redirect in its meta http-equiv tag for 'Location' which allows an external Url to be \
        set.";
const REASON_REFRESH_META: &str =
    "The response contains a redirect in its meta http-equiv tag for 'Refresh' which allows an external Url to be \
        set.";
const REASON_JAVASCRIPT: &str =
    "The response contains a redirect in its JavaScript code which allows an external Url to be set.";

const ORIGINAL_VALUE_PLACEHOLDER: &str = "@@@original@@@";

/// A random host under owasp.org, so a match cannot be a coincidence.
pub(crate) static REDIRECT_SITE: LazyLock<String> =
    LazyLock::new(|| format!("{}.owasp.org", crate::scan::active::rand_u64() >> 1));

static JS_PATTERNS: LazyLock<[Regex; 3]> = LazyLock::new(|| {
    let site = format!("https?://{}", *REDIRECT_SITE);
    [
        Regex::new(&format!(r#"(?i)location(?:\.href)?\s*=\s*['"]({site})['"]"#)).unwrap(),
        Regex::new(&format!(r#"(?i)location\.(?:replace|reload|assign)\s*\(\s*['"]({site})['"]"#)).unwrap(),
        Regex::new(&format!(r#"(?i)window\.(?:open|navigate)\s*\(\s*['"]({site})['"]"#)).unwrap(),
    ]
});
static REFRESH: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"(?i)^\s*\d+\s*;\s*url\s*=\s*["']?([^'"]*)["']?$"#).unwrap());
static LOCATION: LazyLock<Regex> = LazyLock::new(|| Regex::new(r#"(?i)^\s*url\s*=\s*["']?([^'"]*)["']?"#).unwrap());

/// (injection, uses the original value, expected redirect URL)
pub(crate) fn payloads() -> Vec<(String, bool, String)> {
    let s = &*REDIRECT_SITE;
    let same = |p: String, ph: bool| (p.clone(), ph, p);
    vec![
        same(s.clone(), false),
        same(format!("https://{s}"), false),
        same(format!("https://{}", s.replace('.', "%2e")), false),
        (format!("5;URL='https://{s}'"), false, format!("https://{s}")),
        (format!("URL='http://{s}'"), false, format!("http://{s}")),
        same(format!("https://{s}/?{ORIGINAL_VALUE_PLACEHOLDER}"), true),
        (format!("5;URL='https://{s}/?{ORIGINAL_VALUE_PLACEHOLDER}'"), true, format!("https://{s}")),
        same(format!("https://\\{s}"), false),
        same(format!("http://\\{s}"), false),
        same(format!("http://{s}"), false),
        same(format!("//{s}"), false),
        same(format!("\\\\{s}"), false),
        same(format!("HtTpS://{s}"), false),
        same(format!("HtTp://{s}"), false),
    ]
}

fn payload_count(strength: Strength) -> usize {
    match strength {
        Strength::Low => 3,
        Strength::Medium => 9,
        Strength::High | Strength::Insane => 14,
    }
}

pub(crate) fn refresh_url(v: &str) -> Option<String> {
    REFRESH.captures(v).map(|c| c[1].to_string())
}

pub(crate) fn location_url(v: &str) -> Option<String> {
    LOCATION.captures(v).map(|c| c[1].to_string())
}

/// checkPayload: an http(s) URL whose host is our site.
pub(crate) fn check_payload(v: Option<&str>) -> bool {
    let Some(v) = v else { return false };
    if !v.get(..4).is_some_and(|p| p.eq_ignore_ascii_case("http")) {
        return false;
    }
    let Some((_, rest)) = v.split_once("://") else { return false };
    let authority = rest.split(['/', '?', '#']).next().unwrap_or("");
    let host = authority.rsplit('@').next().unwrap_or("").split(':').next().unwrap_or("");
    host.eq_ignore_ascii_case(&REDIRECT_SITE)
}

/// Comments in a script (outside string and template literals).
pub(crate) fn js_comments(src: &str) -> Vec<&str> {
    let b = src.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            q @ (b'"' | b'\'' | b'`') => {
                i += 1;
                while i < b.len() && b[i] != q {
                    i += if b[i] == b'\\' { 2 } else { 1 };
                }
                i += 1;
            }
            b'/' if b.get(i + 1) == Some(&b'/') => {
                let end = src[i..].find('\n').map(|e| i + e).unwrap_or(b.len());
                out.push(&src[i..end]);
                i = end;
            }
            b'/' if b.get(i + 1) == Some(&b'*') => {
                let end = src[i + 2..].find("*/").map(|e| i + 2 + e + 2).unwrap_or(b.len());
                out.push(&src[i..end]);
                i = end;
            }
            _ => i += 1,
        }
    }
    out
}

fn js_redirect(re: &Regex, script: &str) -> bool {
    let present =
        |s: &str| re.captures(s).is_some_and(|c| c[1].get(..4).is_some_and(|p| p.eq_ignore_ascii_case("http")));
    if !present(script) {
        return false;
    }
    let mut stripped = script.to_string();
    for c in js_comments(script) {
        stripped = stripped.replace(c, "");
    }
    present(&stripped)
}

/// isRedirected: which redirection point (if any) carries our site.
pub(crate) fn redirect_type(resp: &Response, payload: &str) -> Option<(&'static AlertDef, &'static str)> {
    if check_payload(resp.header("location")) {
        return Some((&ALERT_LOCATION, REASON_LOCATION_HEADER));
    }
    if let Some(v) = resp.header("refresh") {
        if check_payload(refresh_url(v).as_deref()) {
            return Some((&ALERT_REFRESH, REASON_REFRESH_HEADER));
        }
    }
    let body = resp.body_str();
    let all = tags(body);
    for meta in all.iter().filter(|t| t.name == "meta") {
        let Some(equiv) = meta.attr("http-equiv") else { continue };
        if equiv.eq_ignore_ascii_case("location") {
            if check_payload(meta.attr("content").and_then(location_url).as_deref()) {
                return Some((&ALERT_META, REASON_LOCATION_META));
            }
        } else if equiv.eq_ignore_ascii_case("refresh") {
            if let Some(content) = meta.attr("content") {
                if check_payload(refresh_url(content).as_deref()) {
                    return Some((&ALERT_META, REASON_REFRESH_META));
                }
            }
        }
    }
    if find_ci(body, payload, 0).is_some() {
        for script in all.iter().filter(|t| t.name == "script") {
            let end = find_ci(body, "</script", script.end).unwrap_or(body.len());
            let content = &body[script.end.min(end)..end];
            if JS_PATTERNS.iter().any(|re| js_redirect(re, content)) {
                return Some((&ALERT_JS, REASON_JAVASCRIPT));
            }
        }
    }
    None
}

pub struct ExternalRedirect;

impl ActiveRule for ExternalRedirect {
    fn id(&self) -> u32 {
        20019
    }

    fn name(&self) -> &'static str {
        "External Redirect"
    }

    fn alerts(&self) -> &'static [&'static AlertDef] {
        &ALERTS
    }

    fn scope(&self) -> RuleScope {
        RuleScope::Param
    }

    fn scan<'a>(&'a self, cx: &'a Cx) -> BoxFuture<'a> {
        Box::pin(async move {
            let value = cx.point().value.clone();
            for (payload, placeholder, redirect_url) in payloads().into_iter().take(payload_count(cx.strength())) {
                if cx.stopped() {
                    return;
                }
                let injection = if placeholder { payload.replace(ORIGINAL_VALUE_PLACEHOLDER, &value) } else { payload };
                // Don't follow redirects.
                let Ok(resp) = common::send_no_follow(cx, &injection).await else { continue };
                if let Some((alert, reason)) = redirect_type(&resp, &redirect_url) {
                    let f = alert.raise(cx.point().name.clone(), redirect_url).attack(injection).other_info(reason);
                    cx.report(f, &resp);
                    return;
                }
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::super::common::testing::response;
    use super::*;

    #[test]
    fn url_extraction_and_host_check() {
        let s = &*REDIRECT_SITE;
        assert_eq!(refresh_url(&format!("0; url='https://{s}/'")).unwrap(), format!("https://{s}/"));
        assert_eq!(location_url(&format!("URL=http://{s}")).unwrap(), format!("http://{s}"));
        assert!(check_payload(Some(&format!("HTTPS://{s}/x"))));
        assert!(!check_payload(Some(&format!("https://{s}.evil.test/"))));
        assert!(!check_payload(Some(&format!("//{s}"))));
        assert_eq!(payloads().len(), 14);
        assert_eq!(payload_count(Strength::Medium), 9);
    }

    #[test]
    fn detects_redirect_points() {
        let s = &*REDIRECT_SITE;
        let r = response(&format!("HTTP/1.1 302 Found\r\nLocation: http://{s}\r\n\r\n"));
        assert_eq!(redirect_type(&r, &format!("http://{s}")).unwrap().0.alert_ref, "20019-1");
        let r = response(&format!(
            "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<meta http-equiv=\"refresh\" content=\"0;url=http://{s}\">"
        ));
        assert_eq!(redirect_type(&r, &format!("http://{s}")).unwrap().0.alert_ref, "20019-3");
        let r = response(&format!(
            "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<script>window.location='http://{s}';</script>"
        ));
        assert_eq!(redirect_type(&r, &format!("http://{s}")).unwrap().0.alert_ref, "20019-4");
        // Only in a comment: not a redirect.
        let r = response(&format!(
            "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<script>// location='http://{s}'\nvar a=1;</script>"
        ));
        assert!(redirect_type(&r, &format!("http://{s}")).is_none());
        let r = response("HTTP/1.1 302 Found\r\nLocation: /home\r\n\r\n");
        assert!(redirect_type(&r, &format!("http://{s}")).is_none());
    }

    #[test]
    fn comments() {
        assert_eq!(js_comments("a = '//x'; // c\n/* d */ b"), ["// c", "/* d */"]);
    }
}
