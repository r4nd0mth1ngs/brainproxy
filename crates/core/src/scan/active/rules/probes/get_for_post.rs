//! Ported from ZAP GetForPostScanRule (ascanrules, Apache License 2.0).

use super::common::{base_path, request_line, ComparableResponse};
use crate::scan::active::points::form_encode;
use crate::scan::active::{ActiveRule, BoxFuture, Cx, RuleScope};
use crate::scan::message::url_decode;
use crate::scan::{AlertDef, Confidence, Risk};

static ALERT: AlertDef = AlertDef {
    alert_ref: "10058",
    name: "GET for POST",
    risk: Risk::Info,
    confidence: Confidence::High,
    cwe: 16,
    wasc: 20,
    description: "A request that was originally observed as a POST was also accepted as a GET. This issue does not \
        represent a security weakness unto itself, however, it may facilitate simplification of other attacks. For \
        example if the original POST is subject to Cross-Site Scripting (XSS), then this finding may indicate that a \
        simplified (GET based) XSS may also be possible.",
    solution: "Ensure that only POST is accepted where POST is expected.",
    references: &[],
    tags: &["OWASP_2025_A06", "OWASP_2021_A04", "OWASP_2017_A06", "WSTG-v42-CONF-06"],
};

static ALERTS: [&AlertDef; 1] = [&ALERT];

/// The required similarity ratio to consider GET and POST responses to be the same.
const REQUIRED_SIMILARITY: f32 = 0.95;

/// The query string carrying the form parameters, ordered like ZAP's TreeSet
/// of parameters (by name, then value).
fn query_from_form(body: &str) -> Option<String> {
    let mut params: Vec<(String, String)> = body
        .split('&')
        .filter_map(|p| {
            let (k, v) = p.split_once('=').unwrap_or((p, ""));
            (!k.is_empty()).then(|| (url_decode(k), url_decode(v)))
        })
        .collect();
    if params.is_empty() {
        return None;
    }
    params.sort();
    params.dedup();
    Some(params.iter().map(|(k, v)| format!("{}={}", form_encode(k), form_encode(v))).collect::<Vec<_>>().join("&"))
}

pub struct GetForPost;

impl ActiveRule for GetForPost {
    fn id(&self) -> u32 {
        10058
    }

    fn name(&self) -> &'static str {
        "GET for POST"
    }

    fn alerts(&self) -> &'static [&'static AlertDef] {
        &ALERTS
    }

    fn scope(&self) -> RuleScope {
        RuleScope::Page
    }

    fn scan<'a>(&'a self, cx: &'a Cx) -> BoxFuture<'a> {
        Box::pin(async move {
            if cx.stopped() {
                return;
            }
            let base = cx.base();
            let is_form = base
                .req_header("content-type")
                .is_some_and(|ct| ct.to_ascii_lowercase().contains("application/x-www-form-urlencoded"));
            if !base.method.eq_ignore_ascii_case("POST") || !is_form {
                return;
            }
            let Some(query) = query_from_form(&base.req_body_str()) else { return };
            let path = format!("{}?{query}", base_path(cx));
            let Ok(resp) = cx.send_following(cx.request_for("GET", &path)).await else { return };
            let base_resp = cx.base_response();
            let original = ComparableResponse::new(base_resp.status, base_resp.body_str(), &[], "");
            let get = ComparableResponse::new(resp.status, resp.body_str(), &[], "");
            if original.compare_with(&get) >= REQUIRED_SIMILARITY {
                cx.report(ALERT.raise("", request_line(&resp)), &resp);
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn form_to_query() {
        assert_eq!(query_from_form("b=2&a=x+y&c=%26"), Some("a=x+y&b=2&c=%26".into()));
        assert_eq!(query_from_form(""), None);
        assert_eq!(query_from_form("=x"), None);
    }

    #[test]
    fn similarity() {
        let a = ComparableResponse::new(200, "<p>Thanks, alice</p>", &[], "");
        let b = ComparableResponse::new(200, "<p>Thanks, alice</p>", &[], "");
        assert!(a.compare_with(&b) >= REQUIRED_SIMILARITY);
        let c = ComparableResponse::new(405, "Method Not Allowed", &[], "");
        assert!(a.compare_with(&c) < REQUIRED_SIMILARITY);
        let d = ComparableResponse::new(200, "<p>Error: missing field</p>\n<p>line 2</p>", &[], "");
        assert!(a.compare_with(&d) < REQUIRED_SIMILARITY);
    }
}
