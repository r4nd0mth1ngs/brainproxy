//! Session and login rules: session fixation and username enumeration (both send the `--auth`
//! profile's login request themselves), cookies the application ignores, and file upload.

mod file_upload;
mod session_fixation;
mod slacker_cookie;
mod username_enumeration;

#[cfg(test)]
mod e2e;

use crate::http::{RawRequest, Target};
use crate::scan::active::{ActiveRule, Cx, Response};

pub fn all() -> Vec<Box<dyn ActiveRule>> {
    vec![
        Box::new(file_upload::FileUpload),
        Box::new(session_fixation::SessionFixation),
        Box::new(slacker_cookie::SlackerCookie),
        Box::new(username_enumeration::UsernameEnumeration),
    ]
}

/// The cookies a response sets, as (name, value), in order.
fn set_cookies(resp: &Response) -> Vec<(String, String)> {
    resp.headers_named("set-cookie")
        .filter_map(|v| {
            let (k, v) = v.split(';').next()?.split_once('=')?;
            let k = k.trim();
            (!k.is_empty()).then(|| (k.to_string(), v.trim().to_string()))
        })
        .collect()
}

/// `cookies` with the ones `more` sets put in (a cookie set again takes its new value).
fn merge_cookies(cookies: &mut Vec<(String, String)>, more: Vec<(String, String)>) {
    for (k, v) in more {
        match cookies.iter_mut().find(|(n, _)| *n == k) {
            Some(c) => c.1 = v,
            None => cookies.push((k, v)),
        }
    }
}

/// `request` with exactly these cookies (none: no Cookie header).
fn with_cookies(request: &[u8], cookies: &[(String, String)]) -> Vec<u8> {
    let req = RawRequest::from_bytes(request.to_vec()).remove_header("Cookie");
    if cookies.is_empty() {
        return req.into_bytes();
    }
    let value = cookies.iter().map(|(k, v)| format!("{k}={v}")).collect::<Vec<_>>().join("; ");
    req.set_header("Cookie", &value).into_bytes()
}

/// The login's target, when it is on the origin of the target this unit scans: the rules that
/// log in run once per login, from a target of its own site.
fn login_here(cx: &Cx) -> Option<Target> {
    let auth = cx.auth()?;
    let url = auth.profile.login_url.as_deref()?;
    let login = Target::from_url(url).ok()?;
    (login.origin() == cx.target().origin()).then_some(login)
}

/// What a visitor who isn't logged in has before the login: the cookies of the login's CSRF
/// page (or the login URL's page when there is none) and the token, fetched without the
/// session. None when the page can't be fetched, or has no token the login needs.
async fn before_login(cx: &Cx, page_of_login: bool) -> Option<(Vec<(String, String)>, String)> {
    let auth = cx.auth()?;
    let (url, needs_token) = match auth.login_csrf() {
        Some((url, _)) => (url.to_string(), true),
        None if page_of_login => (auth.profile.login_url.clone()?, false),
        None => return Some((vec![], String::new())),
    };
    let (req, target) = RawRequest::build("GET", &url, &[], b"").ok()?;
    let resp = cx.send_anonymous_to(&target, req.into_bytes()).await.ok()?;
    let token = auth.csrf_token(resp.body_str());
    if needs_token && token.is_none() {
        return None;
    }
    Some((set_cookies(&resp), token.unwrap_or_default()))
}

/// Lower-case letters, `len` of them (at least 6), for a made-up username or password.
fn random_letters(len: usize) -> String {
    let mut out = String::new();
    while out.len() < len.max(6) {
        let n = crate::scan::active::rand_u64();
        out.extend(n.to_le_bytes().iter().map(|b| char::from(b'a' + b % 26)));
    }
    out.truncate(len.max(6));
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cookies_are_set_merged_and_put_on() {
        let raw = b"HTTP/1.1 200 OK\r\nSet-Cookie: sid=1; Path=/\r\nSet-Cookie: =x\r\nSet-Cookie: lang=en\r\n\r\n";
        let resp = Response::parse(vec![], raw.to_vec(), Default::default()).unwrap();
        let mut c = set_cookies(&resp);
        assert_eq!(c, [("sid".into(), "1".into()), ("lang".into(), "en".into())]);
        merge_cookies(&mut c, vec![("sid".into(), "2".into()), ("t".into(), "3".into())]);
        assert_eq!(c, [("sid".into(), "2".into()), ("lang".into(), "en".into()), ("t".into(), "3".into())]);
        let req = with_cookies(b"GET / HTTP/1.1\r\nHost: h\r\nCookie: old=1\r\n\r\n", &c);
        assert!(String::from_utf8_lossy(&req).contains("Cookie: sid=2; lang=en; t=3\r\n"));
        let none = with_cookies(&req, &[]);
        assert!(!String::from_utf8_lossy(&none).contains("Cookie"));
        assert_eq!(random_letters(3).len(), 6);
        assert!(random_letters(9).chars().all(|c| c.is_ascii_lowercase()));
    }
}
