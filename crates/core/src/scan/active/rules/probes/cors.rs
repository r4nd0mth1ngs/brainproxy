//! Ported from ZAP CorsScanRule (ascanrulesBeta, Apache License 2.0).
//!
//! Differences: only `Access-Control-Allow-Credentials: true` raises the risk, since
//! browsers ignore any other value (ZAP accepts any value); only the literal `null`
//! counts as the null origin (ZAP matches `nullsoft.example` too); and the evidence is
//! rebuilt from the header values, so it doesn't depend on how the server cases them.

use crate::http::RawRequest;
use crate::scan::active::{ActiveRule, BoxFuture, Cx, RuleScope};
use crate::scan::{AlertDef, Confidence, Risk};

const TAGS: &[&str] = &["OWASP_2025_A01", "OWASP_2021_A01", "OWASP_2017_A05", "WSTG-v42-CLNT-07", "SYSTEMIC"];
const SOLUTION: &str = "If a web resource contains sensitive information, the origin should be properly specified in \
    the Access-Control-Allow-Origin header. Only trusted websites needing this resource should be specified in this \
    header, with the most secured protocol supported.";
const REFERENCES: &[&str] =
    &["https://developer.mozilla.org/en-US/docs/Web/HTTP/Guides/CORS", "https://portswigger.net/web-security/cors"];
const VULN_DESCRIPTION: &str = "This CORS misconfiguration could allow an attacker to perform AJAX queries to the \
    vulnerable website from a malicious page loaded by the victim's user agent.\nIn order to perform authenticated \
    AJAX queries, the server must specify the header \"Access-Control-Allow-Credentials: true\" and the \
    \"Access-Control-Allow-Origin\" header must be set to null or the malicious page's domain. Even if this \
    misconfiguration doesn't allow authenticated AJAX requests, unauthenticated sensitive content can still be \
    accessed (e.g intranet websites).\nA malicious page can belong to a malicious website but also a trusted website \
    with flaws (e.g XSS, support of HTTP without TLS allowing code injection through MITM, etc).";

static INFO: AlertDef = AlertDef {
    alert_ref: "40040-1",
    name: "CORS Header",
    risk: Risk::Info,
    confidence: Confidence::High,
    cwe: 942,
    wasc: 14,
    description: "Cross-Origin Resource Sharing (CORS) is an HTTP-header based mechanism that allows a server to \
        indicate any other origins (domain, scheme, or port) than its own from which a browser should permit loading \
        of resources. It relaxes the Same-Origin Policy (SOP).",
    solution: SOLUTION,
    references: REFERENCES,
    tags: TAGS,
};

static MEDIUM: AlertDef = AlertDef {
    alert_ref: "40040-2",
    name: "CORS Misconfiguration",
    risk: Risk::Medium,
    confidence: Confidence::High,
    cwe: 942,
    wasc: 14,
    description: VULN_DESCRIPTION,
    solution: SOLUTION,
    references: REFERENCES,
    tags: TAGS,
};

static HIGH: AlertDef = AlertDef {
    alert_ref: "40040-3",
    name: "CORS Misconfiguration",
    risk: Risk::High,
    confidence: Confidence::High,
    cwe: 942,
    wasc: 14,
    description: VULN_DESCRIPTION,
    solution: SOLUTION,
    references: REFERENCES,
    tags: TAGS,
};

static ALERTS: [&AlertDef; 3] = [&INFO, &MEDIUM, &HIGH];

/// `Origin` values in order of likelihood and severity; None sends no `Origin`.
fn origins(scheme: &str, authority: &str, random: &str) -> [Option<String>; 7] {
    let base = format!("{scheme}://");
    [
        Some(format!("{base}{random}.com")),
        Some("null".to_string()),
        Some(format!("{base}{random}.{authority}")),
        Some(format!("{base}{authority}.{random}.com")),
        // An encoded backtick gets past weak regexes that only allow alphanumerics in the domain.
        Some(format!("{base}{authority}%60{random}.com")),
        (scheme == "https").then(|| format!("http://{authority}")),
        Some(format!("{base}{authority}")),
    ]
}

/// The alert for an `Access-Control-Allow-Origin` value and any `-Credentials` value.
fn assess(acao: &str, acac: Option<&str>, random: &str, https: bool) -> &'static AlertDef {
    if acao.contains('*') {
        &MEDIUM
    } else if acao.contains(random) || acao.trim() == "null" || (https && acao.contains("http:")) {
        if acac.is_some_and(|v| v.trim() == "true") {
            &HIGH
        } else {
            &MEDIUM
        }
    } else {
        &INFO
    }
}

fn evidence(acao: &str, acac: Option<&str>) -> String {
    match acac {
        Some(v) => format!("Access-Control-Allow-Origin: {acao}\nAccess-Control-Allow-Credentials: {v}"),
        None => format!("Access-Control-Allow-Origin: {acao}"),
    }
}

pub struct Cors;

impl ActiveRule for Cors {
    fn id(&self) -> u32 {
        40040
    }

    fn name(&self) -> &'static str {
        "CORS Header"
    }

    fn alerts(&self) -> &'static [&'static AlertDef] {
        &ALERTS
    }

    fn scope(&self) -> RuleScope {
        RuleScope::Page
    }

    fn scan<'a>(&'a self, cx: &'a Cx) -> BoxFuture<'a> {
        Box::pin(async move {
            let target = cx.target();
            let random = format!("bp{:08x}", crate::scan::active::rand_u64() as u32);
            for origin in origins(&target.scheme, &target.host_header(), &random) {
                if cx.stopped() {
                    return;
                }
                let base = RawRequest::from_bytes(cx.base_request().to_vec());
                let req = match &origin {
                    Some(o) => base.set_header("Origin", o),
                    None => base.remove_header("Origin"),
                };
                let Ok(resp) = cx.send(req.into_bytes()).await else { continue };
                let Some(acao) = resp.header("Access-Control-Allow-Origin") else { continue };
                let acac = resp.header("Access-Control-Allow-Credentials");
                let alert = assess(acao, acac, &random, target.scheme == "https");
                let finding = alert
                    .raise("", evidence(acao, acac))
                    .attack(format!("Origin: {}", origin.as_deref().unwrap_or("")));
                cx.report(finding, &resp);
                return;
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn origins_for_each_scheme() {
        let http = origins("http", "a.test:8080", "rnd");
        assert_eq!(http[0].as_deref(), Some("http://rnd.com"));
        assert_eq!(http[1].as_deref(), Some("null"));
        assert_eq!(http[2].as_deref(), Some("http://rnd.a.test:8080"));
        assert_eq!(http[3].as_deref(), Some("http://a.test:8080.rnd.com"));
        assert_eq!(http[4].as_deref(), Some("http://a.test:8080%60rnd.com"));
        assert_eq!(http[5], None, "no Origin at all");
        assert_eq!(http[6].as_deref(), Some("http://a.test:8080"));
        assert_eq!(origins("https", "a.test", "rnd")[5].as_deref(), Some("http://a.test"));
    }

    #[test]
    fn risk_of_each_answer() {
        let refs = |acao, acac, https| assess(acao, acac, "rnd", https).alert_ref;
        assert_eq!(refs("*", None, false), "40040-2");
        assert_eq!(refs("*", Some("true"), false), "40040-2", "browsers refuse credentials with a wildcard");
        assert_eq!(refs("http://rnd.com", None, false), "40040-2");
        assert_eq!(refs("http://rnd.com", Some("true"), false), "40040-3");
        assert_eq!(refs("null", Some("true"), false), "40040-3");
        assert_eq!(refs("null", Some("false"), false), "40040-2", "browsers ignore anything but true");
        assert_eq!(refs("http://a.test", Some("true"), true), "40040-3", "https trusting http");
        assert_eq!(refs("http://a.test", Some("true"), false), "40040-1", "its own origin");
        assert_eq!(refs("https://a.test", None, true), "40040-1");
        assert_eq!(refs("https://nullsoft.test", Some("true"), true), "40040-1");
    }

    #[test]
    fn evidence_names_both_headers() {
        assert_eq!(evidence("*", None), "Access-Control-Allow-Origin: *");
        assert_eq!(
            evidence("null", Some("true")),
            "Access-Control-Allow-Origin: null\nAccess-Control-Allow-Credentials: true"
        );
    }
}
