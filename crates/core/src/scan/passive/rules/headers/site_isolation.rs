//! Ported from ZAP SiteIsolationScanRule (pscanrulesBeta, Apache License 2.0).

use super::common::header_values;
use crate::scan::{AlertDef, Confidence, Finding, Message, PassiveRule, Risk};

const TAGS: &[&str] = &["OWASP_2025_A06", "OWASP_2021_A04", "OWASP_2017_A03", "SYSTEMIC"];

static CORP: AlertDef = AlertDef {
    alert_ref: "90004-1",
    name: "Cross-Origin-Resource-Policy Header Missing or Invalid",
    risk: Risk::Low,
    confidence: Confidence::Medium,
    cwe: 693,
    wasc: 14,
    description: "Cross-Origin-Resource-Policy header is an opt-in header designed to counter side-channels attacks \
        like Spectre. Resource should be specifically set as shareable amongst different origins.",
    solution: "Ensure that the application/web server sets the Cross-Origin-Resource-Policy header appropriately, \
        and that it sets the Cross-Origin-Resource-Policy header to 'same-origin' for all web pages.\n'same-site' is \
        considered as less secured and should be avoided.\nIf resources must be shared, set the header to \
        'cross-origin'.\nIf possible, ensure that the end user uses a standards-compliant and modern web browser \
        that supports the Cross-Origin-Resource-Policy header \
        (https://caniuse.com/mdn-http_headers_cross-origin-resource-policy).",
    references: &["https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Cross-Origin-Embedder-Policy"],
    tags: TAGS,
};

static COEP: AlertDef = AlertDef {
    alert_ref: "90004-2",
    name: "Cross-Origin-Embedder-Policy Header Missing or Invalid",
    risk: Risk::Low,
    confidence: Confidence::Medium,
    cwe: 693,
    wasc: 14,
    description: "Cross-Origin-Embedder-Policy header is a response header that prevents a document from loading any \
        cross-origin resources that don't explicitly grant the document permission (using CORP or CORS).",
    solution: "Ensure that the application/web server sets the Cross-Origin-Embedder-Policy header appropriately, \
        and that it sets the Cross-Origin-Embedder-Policy header to 'require-corp' for documents.\nIf possible, \
        ensure that the end user uses a standards-compliant and modern web browser that supports the \
        Cross-Origin-Embedder-Policy header (https://caniuse.com/mdn-http_headers_cross-origin-embedder-policy).",
    references: &["https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Cross-Origin-Embedder-Policy"],
    tags: TAGS,
};

static COOP: AlertDef = AlertDef {
    alert_ref: "90004-3",
    name: "Cross-Origin-Opener-Policy Header Missing or Invalid",
    risk: Risk::Low,
    confidence: Confidence::Medium,
    cwe: 693,
    wasc: 14,
    description: "Cross-Origin-Opener-Policy header is a response header that allows a site to control if others \
        included documents share the same browsing context. Sharing the same browsing context with untrusted \
        documents might lead to data leak.",
    solution: "Ensure that the application/web server sets the Cross-Origin-Opener-Policy header appropriately, and \
        that it sets the Cross-Origin-Opener-Policy header to 'same-origin' for documents.\n\
        'same-origin-allow-popups' is considered as less secured and should be avoided.\nIf possible, ensure that \
        the end user uses a standards-compliant and modern web browser that supports the Cross-Origin-Opener-Policy \
        header (https://caniuse.com/mdn-http_headers_cross-origin-opener-policy).",
    references: &["https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Cross-Origin-Opener-Policy"],
    tags: TAGS,
};

static ALERTS: [&AlertDef; 3] = [&CORP, &COEP, &COOP];

const CORP_HEADER: &str = "Cross-Origin-Resource-Policy";
const COEP_HEADER: &str = "Cross-Origin-Embedder-Policy";
const COOP_HEADER: &str = "Cross-Origin-Opener-Policy";

/// A document: a Content-Type that starts with `text/html` or `application/xml` (as ZAP,
/// case-sensitive).
fn is_document(msg: &Message) -> bool {
    header_values(msg, "Content-Type").any(|v| v.starts_with("text/html") || v.starts_with("application/xml"))
}

/// The policies a header value lists, without its `report-to` endpoint.
fn policies(value: &str) -> impl Iterator<Item = &str> {
    value.split(';').map(str::trim).filter(|p| !p.is_empty() && !p.starts_with("report-to"))
}

/// One finding when `header` is missing, else one per value `ok` doesn't accept.
fn check(msg: &Message, def: &'static AlertDef, header: &'static str, ok: fn(&str) -> bool, out: &mut Vec<Finding>) {
    let mut any = false;
    for value in header_values(msg, header) {
        any = true;
        out.extend(policies(value).filter(|p| !ok(p)).map(|p| def.raise(header, p)));
    }
    if !any {
        out.push(def.raise(header, ""));
    }
}

pub struct SiteIsolation;

impl PassiveRule for SiteIsolation {
    fn id(&self) -> u32 {
        90004
    }

    fn name(&self) -> &'static str {
        "Insufficient Site Isolation Against Spectre Vulnerability"
    }

    fn alerts(&self) -> &'static [&'static AlertDef] {
        &ALERTS
    }

    fn page_level(&self) -> bool {
        true
    }

    fn scan(&self, msg: &Message, out: &mut Vec<Finding>) {
        // A success only: an error page isn't a resource to protect, and nor is an empty body
        // (which ZAP judges too).
        if !msg.is_success() || msg.resp_body.is_empty() {
            return;
        }
        // A resource shared through CORS is meant to be read cross-origin.
        if !msg.resp_headers.iter().any(|(k, _)| k.to_ascii_lowercase().starts_with("access-control-allow-")) {
            let corp_ok = |p: &str| p.eq_ignore_ascii_case("same-origin") || p.eq_ignore_ascii_case("cross-origin");
            check(msg, &CORP, CORP_HEADER, corp_ok, out);
        }
        if is_document(msg) {
            // unsafe-none, the default, turns the checks off.
            let coep_ok = |p: &str| p.eq_ignore_ascii_case("require-corp") || p.eq_ignore_ascii_case("credentialless");
            check(msg, &COEP, COEP_HEADER, coep_ok, out);
            check(msg, &COOP, COOP_HEADER, |p| p.eq_ignore_ascii_case("same-origin"), out);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scan::passive::util::testing::msg;

    fn refs(f: &[Finding]) -> Vec<(&str, &str)> {
        f.iter().map(|f| (f.def.alert_ref, f.evidence.as_str())).collect()
    }

    #[test]
    fn a_document_without_the_headers() {
        let f = msg("https://a.test/").html("<p>").scan(&SiteIsolation);
        assert_eq!(refs(&f), [("90004-1", ""), ("90004-2", ""), ("90004-3", "")]);
        // Not a document: only CORP.
        let f = msg("https://a.test/a.png").header("Content-Type", "image/png").body("x").scan(&SiteIsolation);
        assert_eq!(refs(&f), [("90004-1", "")]);
    }

    #[test]
    fn weak_values_and_good_ones() {
        let f = msg("https://a.test/")
            .html("<p>")
            .header(CORP_HEADER, "same-site")
            .header(COEP_HEADER, "unsafe-none; report-to=\"r\"")
            .header(COOP_HEADER, "same-origin-allow-popups")
            .scan(&SiteIsolation);
        assert_eq!(
            refs(&f),
            [("90004-1", "same-site"), ("90004-2", "unsafe-none"), ("90004-3", "same-origin-allow-popups")]
        );
        let good = msg("https://a.test/")
            .html("<p>")
            .header(CORP_HEADER, "same-origin")
            .header(COEP_HEADER, "require-corp; report-to=\"r\"")
            .header(COOP_HEADER, "same-origin")
            .scan(&SiteIsolation);
        assert!(good.is_empty(), "{good:?}");
    }

    #[test]
    fn cors_errors_and_empty_bodies_are_left_alone() {
        assert!(msg("https://a.test/").html("").scan(&SiteIsolation).is_empty());
        let f = msg("https://a.test/api")
            .header("Content-Type", "application/json")
            .header("Access-Control-Allow-Origin", "*")
            .body("{}")
            .scan(&SiteIsolation);
        assert!(f.is_empty());
        assert!(msg("https://a.test/").html("<p>").status(404).scan(&SiteIsolation).is_empty());
    }
}
