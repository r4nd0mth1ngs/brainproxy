//! Ported from ZAP SlackerCookieScanRule (ascanrulesBeta, Apache License 2.0).
//!
//! Sends the page again once per cookie, with that cookie left out, and compares the response
//! body's length with the page's: a cookie whose absence changes nothing is one the page
//! ignores, and a session cookie that is ignored means the page doesn't enforce it.
//!
//! Differences from ZAP: one request per cookie and one fresh baseline (ZAP compares with the
//! recorded response and sends each request twice, the second with every cookie to restore the
//! session; with `--auth` the session is never disturbed here, so there is nothing to restore,
//! and ZAP's "session destroyed" note isn't raised). The cookies are the base request's and the
//! `--auth` session's; a dropped cookie is sent so the session neither puts it back nor learns
//! from the answer ([`Keep::unobserved`]).

use crate::auth::request_cookies;
use crate::http::RawRequest;
use crate::scan::active::{ActiveRule, BoxFuture, Cx, Keep, Response, RuleScope};
use crate::scan::{AlertDef, Confidence, Risk};

static ALERT: AlertDef = AlertDef {
    alert_ref: "90027",
    name: "Cookie Slack Detector",
    risk: Risk::Info,
    confidence: Confidence::Low,
    cwe: 205,
    wasc: 45,
    description: "Repeated GET requests: drop a different cookie each time, followed by normal request with all \
        cookies to stabilize session, compare responses against original baseline GET. This can reveal areas where \
        cookie based authentication/attributes are not actually enforced.",
    solution: "",
    references: &["https://projects.webappsec.org/Fingerprinting"],
    tags: &["OWASP_2025_A02", "OWASP_2021_A05", "OWASP_2017_A06", "WSTG-v42-SESS-02", "SYSTEMIC"],
};

static ALERTS: [&AlertDef; 1] = [&ALERT];

/// Names that make an ignored cookie worth a low risk rather than information.
const HIGH_RISK_COOKIE_NAMES: [&str; 2] = ["session", "userid"];

pub struct SlackerCookie;

impl ActiveRule for SlackerCookie {
    fn id(&self) -> u32 {
        90027
    }

    fn name(&self) -> &'static str {
        "Cookie Slack Detector"
    }

    fn alerts(&self) -> &'static [&'static AlertDef] {
        &ALERTS
    }

    fn scope(&self) -> RuleScope {
        RuleScope::Page
    }

    fn scan<'a>(&'a self, cx: &'a Cx) -> BoxFuture<'a> {
        Box::pin(async move {
            let names = cookie_names(cx);
            if names.is_empty() {
                return;
            }
            let send = |drop: Option<&str>| {
                let mut req = RawRequest::from_bytes(cx.base_request().to_vec());
                if let Some(name) = drop {
                    let left: Vec<String> = request_cookies(cx.base_request())
                        .into_iter()
                        .filter(|(k, _)| k != name)
                        .map(|(k, v)| format!("{k}={v}"))
                        .collect();
                    req = req.remove_header("Cookie");
                    if !left.is_empty() {
                        req = req.set_header("Cookie", &left.join("; "));
                    }
                }
                let keep = Keep {
                    cookies: drop.into_iter().map(str::to_string).collect(),
                    unobserved: true,
                    ..Default::default()
                };
                async move { cx.send_keeping(req.into_bytes(), &keep).await }
            };
            let Ok(baseline) = send(None).await else { return };
            let length = baseline.body.len();
            let (mut matter, mut slack) = (Vec::new(), Vec::new());
            let mut last: Option<Response> = None;
            for name in &names {
                if cx.stopped() {
                    return;
                }
                let Ok(resp) = send(Some(name)).await else { continue };
                if resp.body.len() == length {
                    slack.push(name.clone());
                    last = Some(resp);
                } else {
                    matter.push(name.clone());
                }
            }
            let Some(resp) = last else { return };
            let mut finding = ALERT.raise("", "");
            finding.other_info = other_info(&matter, &slack);
            if slack.iter().any(|c| important(c)) {
                finding.risk = Risk::Low;
            }
            cx.report(finding, &resp);
        })
    }
}

/// The cookies the page is sent with: the base request's, then the session's.
fn cookie_names(cx: &Cx) -> Vec<String> {
    let mut names: Vec<String> = request_cookies(cx.base_request()).into_iter().map(|(k, _)| k).collect();
    if let Some(auth) = cx.auth() {
        let session = auth.state().cookies.into_iter().map(|(k, _)| k);
        let fixed = crate::auth::static_cookies(&auth.profile).into_iter().map(|(k, _)| k);
        for k in session.chain(fixed) {
            if !names.contains(&k) {
                names.push(k);
            }
        }
    }
    names.dedup();
    names
}

fn important(cookie: &str) -> bool {
    let lower = cookie.to_ascii_lowercase();
    HIGH_RISK_COOKIE_NAMES.iter().any(|n| lower.contains(n))
}

/// ZAP's other info: a warning per ignored cookie with an important name, then both lists.
fn other_info(matter: &[String], slack: &[String]) -> String {
    let mut out = String::new();
    for c in slack.iter().filter(|c| important(c)) {
        out.push_str(&format!(
            "NOTE: Because of its name this cookie may be important, but dropping it appears to have no effect: [{c}]\n"
        ));
    }
    out.push_str(
        "Cookies that don't have expected effects can reveal flaws in application logic. In the worst case, this can \
         reveal where authentication via cookie token(s) is not actually enforced.\n",
    );
    out.push_str(&format!("These cookies affected the response: {}\n", matter.join(",")));
    out.push_str(&format!("These cookies did NOT affect the response: {}\n", slack.join(",")));
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_ignored_session_cookie_is_named_first() {
        let info = other_info(&["lang".into()], &["JSESSIONID".into(), "theme".into()]);
        assert!(info.starts_with("NOTE: Because of its name this cookie may be important"), "{info}");
        assert!(info.contains("[JSESSIONID]") && !info.contains("[theme]"));
        assert!(
            info.contains("affected the response: lang\n")
                && info.contains("NOT affect the response: JSESSIONID,theme")
        );
        assert!(important("my_userid") && !important("lang"));
    }
}
