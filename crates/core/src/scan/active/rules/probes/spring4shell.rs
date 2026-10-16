//! Ported from ZAP Spring4ShellScanRule (ascanrules, Apache License 2.0).

use super::common::{base_path_query, request_line, with_body, with_request_line};
use crate::http::RawRequest;
use crate::scan::active::{ActiveRule, BoxFuture, Cx, Response, RuleScope};
use crate::scan::{AlertDef, Confidence, Risk};

static ALERT: AlertDef = AlertDef {
    alert_ref: "40045",
    name: "Spring4Shell",
    risk: Risk::High,
    confidence: Confidence::Medium,
    cwe: 78,
    wasc: 20,
    description: "The application appears to be vulnerable to CVE-2022-22965 (otherwise known as Spring4Shell) - \
        remote code execution (RCE) via data binding.",
    solution: "Upgrade Spring Framework to versions 5.3.18, 5.2.20, or newer.",
    references: &[
        "https://nvd.nist.gov/vuln/detail/cve-2022-22965",
        "https://www.rapid7.com/blog/post/2022/03/30/spring4shell-zero-day-vulnerability-in-spring-framework/",
        "https://spring.io/blog/2022/03/31/spring-framework-rce-early-announcement/#vulnerability",
        "https://spring.io/security/cve-2022-22965/",
    ],
    tags: &[
        "OWASP_2025_A03",
        "OWASP_2025_A05",
        "OWASP_2021_A03",
        "OWASP_2021_A06",
        "OWASP_2017_A01",
        "OWASP_2017_A09",
        "WSTG-v42-INPV-12",
        "CVE-2022-22965",
    ],
};

static ALERTS: [&AlertDef; 1] = [&ALERT];

const ATTACK: &str = "class.module.classLoader.DefaultAssertionStatus=nonsense";
const SAFE_PAYLOAD: &str = "aaa=bbb";
const FORM_CT: &str = "application/x-www-form-urlencoded";

fn is_400(resp: &Response) -> bool {
    resp.status == 400
}

/// The request target with `payload` appended to the query (ZAP setGetPayload).
fn append_query(path_query: &str, payload: &str) -> String {
    match path_query.split_once('?') {
        Some((p, q)) if !q.is_empty() => format!("{p}?{q}&{payload}"),
        Some((p, _)) => format!("{p}?{payload}"),
        None => format!("{path_query}?{payload}"),
    }
}

/// The POST body with `payload` appended (ZAP setPostPayload): a form body is
/// extended, anything else is replaced.
fn append_body(body: &str, is_form: bool, payload: &str) -> String {
    if body.is_empty() || !is_form {
        payload.to_string()
    } else {
        format!("{body}&{payload}")
    }
}

/// The base request as a GET with `payload` appended to the query.
fn get_payload(cx: &Cx, payload: &str) -> Vec<u8> {
    let target = append_query(&base_path_query(cx), payload);
    with_request_line(cx.base_request(), "GET", &target)
}

/// The base request as a POST with `payload` in a form-encoded body.
fn post_payload(cx: &Cx, payload: &str) -> Vec<u8> {
    let is_form = cx.base().req_header("content-type").is_some_and(|ct| ct.eq_ignore_ascii_case(FORM_CT));
    let new_body = append_body(&cx.base().req_body_str(), is_form, payload);
    let raw = with_request_line(cx.base_request(), "POST", &base_path_query(cx));
    let raw = RawRequest::from_bytes(raw).set_header("Content-Type", FORM_CT).into_bytes();
    with_body(raw, new_body.as_bytes())
}

pub struct Spring4Shell;

impl Spring4Shell {
    /// Sends the attack with the given method; a 400 that is not matched by a safe
    /// payload means vulnerable. Returns the attack exchange when vulnerable.
    async fn try_attack(cx: &Cx, is_get: bool) -> Option<Response> {
        let build = |p: &str| if is_get { get_payload(cx, p) } else { post_payload(cx, p) };
        let resp = cx.send_following(build(ATTACK)).await.ok()?;
        if !is_400(&resp) {
            return None;
        }
        let safe = cx.send_following(build(SAFE_PAYLOAD)).await.ok()?;
        (!is_400(&safe)).then_some(resp)
    }
}

impl ActiveRule for Spring4Shell {
    fn id(&self) -> u32 {
        40045
    }

    fn name(&self) -> &'static str {
        "Spring4Shell"
    }

    fn alerts(&self) -> &'static [&'static AlertDef] {
        &ALERTS
    }

    fn scope(&self) -> RuleScope {
        RuleScope::Page
    }

    fn scan<'a>(&'a self, cx: &'a Cx) -> BoxFuture<'a> {
        Box::pin(async move {
            if is_400(cx.base_response()) || cx.stopped() {
                return;
            }
            for is_get in [true, false] {
                if cx.stopped() {
                    return;
                }
                if let Some(resp) = Self::try_attack(cx, is_get).await {
                    cx.report(ALERT.raise("", request_line(&resp)).attack(ATTACK), &resp);
                    return;
                }
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn query_appending() {
        assert_eq!(append_query("/a?x=1", ATTACK), format!("/a?x=1&{ATTACK}"));
        assert_eq!(append_query("/a", ATTACK), format!("/a?{ATTACK}"));
        assert_eq!(append_query("/a?", ATTACK), format!("/a?{ATTACK}"));
    }

    #[test]
    fn body_appending() {
        assert_eq!(append_body("x=1", true, ATTACK), format!("x=1&{ATTACK}"));
        assert_eq!(append_body("{}", false, ATTACK), ATTACK);
        assert_eq!(append_body("", true, ATTACK), ATTACK);
    }
}
