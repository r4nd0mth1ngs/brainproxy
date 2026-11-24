//! Ported from ZAP SessionFixationScanRule (ascanrulesBeta, Apache License 2.0).
//!
//! Plays the victim of a fixed session: fetches the login page without a session and keeps
//! the cookies it hands out (what an attacker would get and plant), logs in once with the
//! `--auth` profile's login request carrying them, and looks at whether the login gave new
//! values for them. A cookie the login didn't renew is one an attacker could have chosen.
//! Where the profile can tell a logged-in page from one that isn't (`--check-url` with a
//! `--logged-in` or `--logged-out` pattern), the check URL is then fetched with the pre-login
//! cookies alone, as the attacker would: logged in there is a confirmed fixation.
//!
//! Opt-in ([`ActiveRule::opt_in`]): it sends a real login for the `--auth` user outside the
//! scan's session, which can end that session or count against the account. It runs only when
//! named with `--rules` or turned on in a scan policy.
//!
//! Differences from ZAP: ZAP sets each cookie, form and URL parameter of every page to null and
//! watches for a session value coming back, reporting it as information unless the page is a
//! flagged login page; it also reports session ids in URLs and their cookie flags and expiry,
//! which the passive cookie rules cover here. This port tests the login itself, so it needs
//! `--auth` with a login request (it is left out and listed in `skipped` without one), runs
//! once per login from a target on the login's origin, logs in once, and tests cookies only.
//! Its own login runs outside the scan's session; an application that allows one session per
//! user may end the scan's, which then logs in again as it would anyway.

use super::{before_login, login_here, merge_cookies, set_cookies, with_cookies};
use crate::http::RawRequest;
use crate::scan::active::{ActiveRule, BoxFuture, Cx, Response, RuleScope};
use crate::scan::{AlertDef, Confidence, Risk};

static ALERT: AlertDef = AlertDef {
    alert_ref: "40013-4",
    name: "Session Fixation",
    risk: Risk::High,
    confidence: Confidence::High,
    cwe: 384,
    wasc: 37,
    description: "Session Fixation may be possible. If this issue occurs with a login URL (where the user \
        authenticates themselves to the application), then the URL may be given by an attacker, along with a fixed \
        session id, to a victim, in order to later assume the identity of the victim using the given session id. If \
        the issue occurs with a non-login page, the URL and fixed session id may only be used by an attacker to track \
        an unauthenticated user's actions. If the vulnerability occurs on a cookie field or a form field (POST \
        parameter) rather than on a URL (GET) parameter, then some other vulnerability may also be required in order \
        to set the cookie field on the victim's browser, to allow the vulnerability to be exploited.",
    solution: "1) Prevent the attacker from gaining a session id by enforcing strict session ids, and by only \
        allocating session ids upon successful authentication to the application.\n2) The server should always \
        create a new session id upon authentication, regardless of whether a session is already in place.\n3) Bind \
        the session id to some identifiable client attribute combination, such as IP address, SSL client \
        certificate.\n4) Sessions, when destroyed, must be destroyed on the server, as well as on the client.\n5) \
        Implement a logout mechanism which will destroy all previous sessions for the client.\n6) Implement absolute \
        session timeouts.\n7) Switch from a URL based to a cookie or form based session id implementation, as the \
        latter typically require additional vulnerabilities, in order to be exploitable by an attacker.",
    references: &[
        "https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/",
        "https://owasp.org/www-community/attacks/Session_fixation",
        "https://acrossecurity.com/papers/session_fixation.pdf",
        "https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html",
    ],
    tags: &["OWASP_2025_A01", "OWASP_2021_A01", "OWASP_2017_A05", "WSTG-v42-SESS-03"],
};

static ALERTS: [&AlertDef; 1] = [&ALERT];

pub struct SessionFixation;

impl ActiveRule for SessionFixation {
    fn id(&self) -> u32 {
        40013
    }

    fn name(&self) -> &'static str {
        "Session Fixation"
    }

    fn alerts(&self) -> &'static [&'static AlertDef] {
        &ALERTS
    }

    fn scope(&self) -> RuleScope {
        RuleScope::Host
    }

    fn opt_in(&self) -> bool {
        true
    }

    fn needs_login(&self) -> bool {
        true
    }

    fn scan<'a>(&'a self, cx: &'a Cx) -> BoxFuture<'a> {
        Box::pin(async move {
            let (Some(auth), Some(login)) = (cx.auth(), login_here(cx)) else { return };
            if !cx.once(&format!("40013 {}", login.origin())) {
                return;
            }
            // What the attacker gets and plants: the cookies handed out before the login.
            let Some((planted, csrf)) = before_login(cx, true).await else { return };
            if planted.is_empty() {
                return;
            }
            let Ok(Some((target, request))) = auth.login_request(None, None, &csrf) else { return };
            let Ok(logged_in) = cx.send_anonymous_to(&target, with_cookies(&request, &planted)).await else { return };
            // A failed login renews nothing, as there is no session to renew. A redirect is judged
            // by where it leads, which the check URL looks at below.
            let redirect = (300..400).contains(&logged_in.status);
            if !redirect && auth.looks_logged_in(&logged_in.raw) == Some(false) {
                return;
            }
            let renewed = set_cookies(&logged_in);
            let kept: Vec<&(String, String)> =
                planted.iter().filter(|(k, v)| !renewed.iter().any(|(n, nv)| n == k && nv != v)).collect();
            if kept.is_empty() {
                return;
            }
            let names: Vec<&str> = kept.iter().map(|(k, _)| k.as_str()).collect();
            let mut finding = ALERT.raise(names.join(", "), "");
            finding.attack = format!("cookie field: [{}]", names.join(", "));
            let values = kept.iter().map(|(k, v)| format!("{k}={v}")).collect::<Vec<_>>().join("; ");
            let mut after = planted.clone();
            merge_cookies(&mut after, renewed.clone());
            let after = after.iter().map(|(k, v)| format!("{k}={v}")).collect::<Vec<_>>().join("; ");
            let base = format!(
                "Cookies set before the login, which the login didn't renew: [{values}]\nCookies after the login: \
                 [{after}]\n"
            );
            match confirm(cx, &planted).await {
                Some((true, resp)) => {
                    finding.other_info = format!(
                        "{base}The check URL, fetched with only the cookies set before the login, was logged in: an \
                         attacker who plants them is logged in as the victim once the victim logs in."
                    );
                    cx.report(finding, &resp);
                }
                Some((false, _)) => {}
                None => {
                    finding.risk = Risk::Medium;
                    finding.confidence = Confidence::Low;
                    finding.other_info = format!(
                        "{base}The url on which the issue was discovered was flagged as a logon page.\n\nThis issue \
                         should be manually validated by checking that the session token set on the logon page is \
                         still valid once logged in, and that the token can be used to directly access a \
                         page/resource which should require the user to be logged in. (The --auth profile has no \
                         check URL with a logged-in or logged-out pattern to do this with.)"
                    );
                    cx.report(finding, &logged_in);
                }
            }
        })
    }
}

/// Fetches the profile's check URL with only the planted cookies (logged in?), after making
/// sure it isn't logged in without any. None when the profile can't tell.
async fn confirm(cx: &Cx, planted: &[(String, String)]) -> Option<(bool, Response)> {
    let auth = cx.auth()?;
    let url = auth.profile.check_url.as_deref()?;
    let (req, target) = RawRequest::build("GET", url, &[], b"").ok()?;
    let req = req.into_bytes();
    let anonymous = cx.send_anonymous_to(&target, req.clone()).await.ok()?;
    if auth.looks_logged_in(&anonymous.raw)? {
        return None;
    }
    let resp = cx.send_anonymous_to(&target, with_cookies(&req, planted)).await.ok()?;
    let logged_in = auth.looks_logged_in(&resp.raw)?;
    Some((logged_in, resp))
}
