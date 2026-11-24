//! Ported from ZAP UsernameEnumerationScanRule (ascanrulesBeta, Apache License 2.0).
//!
//! Sends the `--auth` profile's login request with a wrong password, several times with the
//! profile's (valid) username and as many with a made-up one of the same length, and compares
//! what stays the same within each set: when the two differ, the login tells whether a user
//! exists. ZAP keeps the longest common subsequence of each set's responses; this keeps the
//! lines every response of the set has, which is the same test at line level and doesn't grow
//! with the square of the page's size.
//!
//! Opt-in ([`ActiveRule::opt_in`]): every attempt is a failed login for a real account, which
//! can lock it. It runs only when named with `--rules` or turned on in a scan policy.
//!
//! Differences from ZAP: ZAP runs on a scanned request that is the context's login URL and
//! varies each of its parameters, following redirects; this builds the login from the profile
//! (it needs `--auth` with a login request, and is listed in `skipped` without one), runs once
//! per login from a target on the login's origin, varies only the username, sends a wrong
//! password, and compares the first response (a redirect's `Location` included) without
//! following redirects. A login form that shows the username typed in back would differ for
//! every username, so the username each request sent is masked in its response. Attempts per
//! username, by strength: 2 at low, 3 at medium, 5 at high and 10 at insane (ZAP: 3, 5, 15, 50),
//! fewer because each is a failed login.

use std::sync::OnceLock;

use regex::Regex;

use super::{before_login, login_here, random_letters, with_cookies};
use crate::scan::active::{ActiveRule, BoxFuture, Cx, Response, RuleScope, Strength};
use crate::scan::{AlertDef, Confidence, Risk};

static ALERT: AlertDef = AlertDef {
    alert_ref: "40023",
    name: "Possible Username Enumeration",
    risk: Risk::Info,
    confidence: Confidence::Low,
    cwe: 204,
    wasc: 13,
    description: "It may be possible to enumerate usernames, based on differing HTTP responses when valid and invalid \
        usernames are provided. This would greatly increase the probability of success of password brute-forcing \
        attacks against the system. Note that false positives may sometimes be minimised by increasing the 'Attack \
        Strength'. Please manually check the 'Other Info' field to confirm if this is actually an issue.",
    solution: "Do not divulge details of whether a username is valid or invalid. In particular, for unsuccessful \
        login attempts, do not differentiate between an invalid user and an invalid password in the error message, \
        page title, page contents, HTTP headers, or redirection logic.",
    references: &[
        "https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/03-Identity_Management_Testing/04-Testing_for_Account_Enumeration_and_Guessable_User_Account",
        "https://dl.ifip.org/db/conf/sec/sec2011/FreilingS11.pdf",
        "https://cwe.mitre.org/data/definitions/204.html",
    ],
    tags: &["OWASP_2025_A02", "OWASP_2021_A05", "OWASP_2017_A06", "WSTG-v42-IDNT-04"],
};

static ALERTS: [&AlertDef; 1] = [&ALERT];

pub struct UsernameEnumeration;

impl ActiveRule for UsernameEnumeration {
    fn id(&self) -> u32 {
        40023
    }

    fn name(&self) -> &'static str {
        "Possible Username Enumeration"
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
            let (Some(auth), Some(_)) = (cx.auth(), login_here(cx)) else { return };
            let Some(valid) = auth.profile.username.clone() else { return };
            if !cx.once(&format!("40023 {}", cx.target().origin())) {
                return;
            }
            let attempts = match cx.strength() {
                Strength::Low => 2,
                Strength::Medium => 3,
                Strength::High => 5,
                Strength::Insane => 10,
            };
            // One wrong password for every attempt, so only the username differs.
            let password = random_letters(16);
            let invalid = random_letters(valid.chars().count());
            let Some((a, _)) = stable(cx, &valid, &password, attempts).await else { return };
            let Some((b, last)) = stable(cx, &invalid, &password, attempts).await else { return };
            if a == b {
                return;
            }
            let mut finding = ALERT.raise("username", "");
            finding.attack = format!("Manipulate [username] field: [{invalid}] and monitor the output");
            finding.other_info = format!(
                "[login] parameter [username] leaks information on whether a user exists. The differences in output, \
                 for the valid original username value [{valid}], and invalid username value [{invalid}] are:\n[{}].\n\
                 Each was sent {attempts} times with the same wrong password.",
                differences(&a, &b)
            );
            cx.report(finding, &last);
        })
    }
}

/// The lines every response to `attempts` failed logins as `username` has, normalized, and the
/// last response. None when a login can't be built or sent, or nothing stays the same.
async fn stable(cx: &Cx, username: &str, password: &str, attempts: usize) -> Option<(Vec<String>, Response)> {
    let auth = cx.auth()?;
    let mut common: Option<Vec<String>> = None;
    let mut last = None;
    for _ in 0..attempts {
        if cx.stopped() {
            return None;
        }
        let (cookies, csrf) = before_login(cx, false).await?;
        let (target, request) = auth.login_request(Some(username), Some(password), &csrf).ok()??;
        let resp = cx.send_anonymous_to(&target, with_cookies(&request, &cookies)).await.ok()?;
        let lines = normalized(&resp, username);
        common = Some(match common {
            None => lines,
            Some(c) => c.into_iter().filter(|l| lines.contains(l)).collect(),
        });
        last = Some(resp);
    }
    common.filter(|c| !c.is_empty()).zip(last)
}

/// The response as lines, with what changes on every request taken out (ZAP's): no
/// `Set-Cookie` or `Date`, any `Content-Length` alike, query values in links as `YYYY`, and
/// the username sent as `{{username}}`.
fn normalized(resp: &Response, username: &str) -> Vec<String> {
    static QUERY: OnceLock<Regex> = OnceLock::new();
    let query =
        QUERY.get_or_init(|| Regex::new(r#"((?:\?|&amp;)[^?"=&;\s]+=)[^?"=&;\s]+"#).expect("a fixed pattern compiles"));
    let mut text = String::new();
    text.push_str(&resp.status_line);
    text.push('\n');
    for (k, v) in &resp.headers {
        if k.eq_ignore_ascii_case("set-cookie") || k.eq_ignore_ascii_case("date") {
            continue;
        }
        let v = if k.eq_ignore_ascii_case("content-length") { "XXXX" } else { v };
        text.push_str(&format!("{k}: {v}\n"));
    }
    text.push_str(resp.body_str());
    let form: String = url::form_urlencoded::byte_serialize(username.as_bytes()).collect();
    for sent in [username.to_string(), form, crate::scan::active::points::xml_encode(username)] {
        if !sent.is_empty() {
            text = text.replace(&sent, "{{username}}");
        }
    }
    // ZAP's value must be followed by `&amp;` or a quote, which the next one may start with.
    let masked = query.replace_all(&text, |c: &regex::Captures| {
        let end = c.get(0).map_or(0, |m| m.end());
        let rest = &text[end..];
        if rest.starts_with("&amp;") || rest.starts_with('"') {
            format!("{}YYYY", &c[1])
        } else {
            c[0].to_string()
        }
    });
    let text = masked.into_owned();
    text.lines().map(|l| l.trim_end().to_string()).filter(|l| !l.is_empty()).collect()
}

/// The lines only one side has, as ZAP lists its diff's deltas (at most 20 lines).
fn differences(valid: &[String], invalid: &[String]) -> String {
    let only = |a: &[String], b: &[String]| a.iter().filter(|l| !b.contains(l)).cloned().collect::<Vec<_>>();
    let mut out = Vec::new();
    for l in only(valid, invalid).iter().take(10) {
        out.push(format!("Output for Valid Username  : {l}"));
    }
    for l in only(invalid, valid).iter().take(10) {
        out.push(format!("Output for Invalid Username: {l}"));
    }
    if out.is_empty() {
        out.push("(the same lines, in another order)".into());
    }
    out.join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn resp(raw: &str) -> Response {
        Response::parse(vec![], raw.as_bytes().to_vec(), Default::default()).unwrap()
    }

    #[test]
    fn what_changes_every_time_is_taken_out() {
        let a = resp(
            "HTTP/1.1 200 OK\r\nDate: Mon\r\nSet-Cookie: s=1\r\nContent-Length: 63\r\n\r\n\
             <a href=\"/x?t=123&amp;u=9\">x</a>\n<input value=\"alice\">\nNo such user",
        );
        let lines = normalized(&a, "alice");
        assert_eq!(
            lines,
            [
                "HTTP/1.1 200 OK",
                "Content-Length: XXXX",
                "<a href=\"/x?t=YYYY&amp;u=YYYY\">x</a>",
                "<input value=\"{{username}}\">",
                "No such user"
            ]
        );
        let b = normalized(
            &resp("HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\n<a href=\"/x?t=9&amp;u=1\">x</a>\n<input value=\"bob\">\nNo such user"),
            "bob",
        );
        assert_eq!(lines, b);
        let d = differences(&["Wrong password".into()], &["No such user".into()]);
        assert_eq!(d, "Output for Valid Username  : Wrong password\nOutput for Invalid Username: No such user");
    }
}
