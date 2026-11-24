//! Ported from ZAP HttpParameterPollutionScanRule (ascanrulesBeta, Apache License 2.0).
//!
//! For a page with input fields: one GET with every parameter it knows (the request's query
//! and form parameters, and the page's named inputs with a value), each value followed by
//! an encoded `&` and a parameter of its own (`%26bp1a2b3c%3Dzaproxy`). A link or form action
//! on the answer that carries that parameter as a parameter of its own shows the application
//! decoded the `&` and wrote it into a URL unencoded: polluting a parameter adds others.
//!
//! ZAP instead looks for a link whose parameter has exactly the encoded payload as its value,
//! which only an input with an empty value can give, and then shows the payload correctly
//! encoded; the decoded form is the one that is a vulnerability. The parameter's name is
//! random rather than ZAP's `zap`, so a page's own links can't match.

use super::common::url_encode;
use crate::scan::active::{rand_u64, ActiveRule, BoxFuture, Cx, RuleScope};
use crate::scan::passive::util::tags;
use crate::scan::{AlertDef, Confidence, Risk};

static ALERT: AlertDef = AlertDef {
    alert_ref: "20014",
    name: "HTTP Parameter Pollution",
    risk: Risk::Info,
    confidence: Confidence::Low,
    cwe: 20,
    wasc: 20,
    description: "HTTP Parameter Pollution (HPP) attacks consist of injecting encoded query string delimiters into \
        other existing parameters. If a web application does not properly sanitize the user input, a malicious user \
        can compromise the logic of the application to perform either client-side or server-side attacks. One \
        consequence of HPP attacks is that the attacker can potentially override existing hard-coded HTTP parameters \
        to modify the behavior of an application, bypass input validation checkpoints, and access and possibly \
        exploit variables that may be out of direct reach.",
    solution: "Properly sanitize the user input for parameter delimiters.",
    references: &[
        "https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/07-Input_Validation_Testing/04-Testing_for_HTTP_Parameter_Pollution",
    ],
    tags: &["OWASP_2025_A05", "OWASP_2021_A03", "OWASP_2017_A01", "WSTG-v42-INPV-04"],
};

static ALERTS: [&AlertDef; 1] = [&ALERT];

/// The query of a URL, split into decoded-name, raw-value pairs as ZAP splits it.
fn query_pairs(url: &str) -> Vec<(String, String)> {
    let Some((_, q)) = url.split_once('?') else { return Vec::new() };
    let q = q.split('#').next().unwrap_or_default();
    q.split('&')
        .filter(|p| !p.is_empty())
        .map(|p| {
            let (k, v) = p.split_once('=').unwrap_or((p, ""));
            (k.to_string(), v.to_string())
        })
        .collect()
}

pub struct ParameterPollution;

impl ActiveRule for ParameterPollution {
    fn id(&self) -> u32 {
        20014
    }

    fn name(&self) -> &'static str {
        "HTTP Parameter Pollution"
    }

    fn alerts(&self) -> &'static [&'static AlertDef] {
        &ALERTS
    }

    fn scope(&self) -> RuleScope {
        RuleScope::Page
    }

    fn scan<'a>(&'a self, cx: &'a Cx) -> BoxFuture<'a> {
        Box::pin(async move {
            let page = cx.base_response().body_str();
            let inputs: Vec<_> = tags(page).into_iter().filter(|t| t.name == "input").collect();
            if inputs.is_empty() {
                return;
            }
            let marker = format!("bp{:08x}", rand_u64() as u32);
            let polluted = |v: &str| format!("{}%26{marker}%3Dzaproxy", url_encode(v));
            let mut params: Vec<(String, String)> = Vec::new();
            let base = cx.base();
            let known = base.form_params().into_iter().chain(base.query_params());
            let from_inputs =
                inputs.iter().filter_map(|t| Some((t.attr("name")?.to_string(), t.attr("value")?.to_string())));
            for (name, value) in known.chain(from_inputs) {
                if !params.iter().any(|(n, v)| *n == name && *v == value) {
                    params.push((name, value));
                }
            }
            if params.is_empty() {
                return;
            }
            let query: Vec<String> = params.iter().map(|(n, v)| format!("{}={}", url_encode(n), polluted(v))).collect();
            let target = format!("{}?{}", base.path, query.join("&"));
            let Ok(resp) = cx.send_following(cx.request_for("GET", &target)).await else { return };
            let body = resp.body_str();
            let mut vulnerable: Vec<String> = Vec::new();
            for t in tags(body) {
                let url = match t.name.as_str() {
                    "a" => t.attr("href"),
                    "form" => t.attr("action"),
                    _ => None,
                };
                let pairs = query_pairs(url.unwrap_or_default());
                if !pairs.iter().any(|(k, v)| *k == marker && v == "zaproxy") {
                    continue;
                }
                for (name, _) in &params {
                    if pairs.iter().any(|(k, _)| k == name) && !vulnerable.contains(name) {
                        vulnerable.push(name.clone());
                    }
                }
            }
            if !vulnerable.is_empty() {
                let attack = format!("%26{marker}%3Dzaproxy");
                cx.report(ALERT.raise(vulnerable.join(", "), format!("{marker}=zaproxy")).attack(attack), &resp);
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scan::active::rules::test_app::{get, html, scan, serve, Opts};

    fn form(q: &str) -> String {
        format!("<form><input name=q value=\"{q}\"></form>")
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_decoded_value_written_into_a_link() {
        let port = serve(|r| {
            let q = r.param("q").unwrap_or_default();
            match r.path.as_str() {
                // Builds the next-page link from the decoded value, unencoded.
                "/search" => html(&format!("{}<a href=\"/search?q={q}&page=2\">next</a>", form(&q))),
                // Encodes it, as it should.
                _ => html(&format!("{}<a href=\"/safe?q={}&page=2\">next</a>", form(&q), url_encode(&q))),
            }
        });
        let (s, found) = scan(20014, vec![get(port, "/search?q=shoes")], Opts::default()).await;
        assert_eq!(found.len(), 1, "{s:?}");
        assert_eq!(found[0].param, "q");
        let (s, found) = scan(20014, vec![get(port, "/safe?q=shoes")], Opts::default()).await;
        assert!(found.is_empty());
        assert_eq!(s.requests, 1);
    }

    #[test]
    fn link_queries() {
        assert_eq!(query_pairs("/a?x=1&bp=z#f"), [("x".into(), "1".into()), ("bp".into(), "z".into())]);
        assert!(query_pairs("/a").is_empty());
    }
}
