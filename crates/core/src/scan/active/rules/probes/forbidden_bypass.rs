//! Ported from ZAP ForbiddenBypassScanRule (ascanrulesBeta, Apache License 2.0).
//!
//! For a page that answers 403: the same path spelled the ways front ends and frameworks
//! normalise differently (`/%2e/admin`, `/admin/./`, `/admin..;/`, ...), then the path in
//! `X-Original-URL` or `X-Rewrite-URL` (which some frameworks route by, behind a front end
//! that checked another path), and client-IP headers saying 127.0.0.1. The first 200 is the
//! finding. Every attack carries a random cache buster ([`bust`]), so a cache in front can
//! only keep an answer for a URL nobody else asks for. These headers name the in-scope host's
//! own paths, and the connection still goes to the target through the scope guard.
//!
//! Less noise than ZAP: redirects aren't followed (a login page reached by one isn't a
//! bypass), and a 200 that is this host's page for a path that doesn't exist doesn't count.
//! ZAP gives no solution text; this one says what fixes it.

use super::common::{base_path, fresh_request};
use crate::http::RawRequest;
use crate::scan::active::canary::bust;
use crate::scan::active::{ActiveRule, BoxFuture, Cx, Response, RuleScope};
use crate::scan::{AlertDef, Confidence, Risk};

static ALERT: AlertDef = AlertDef {
    alert_ref: "40038",
    name: "Bypassing 403",
    risk: Risk::Medium,
    confidence: Confidence::Medium,
    cwe: 348,
    wasc: 0,
    description: "Bypassing 403 endpoints may be possible, the scan rule sent a payload that caused the response to be \
        accessible (status code 200).",
    solution: "Make the access check see the request as the application routes it: normalise the path (dot segments, \
        encoded characters, trailing extras) before checking it, and don't take X-Original-URL, X-Rewrite-URL or \
        client-IP headers from outside the front end.",
    references: &[
        "https://www.acunetix.com/blog/articles/a-fresh-look-on-reverse-proxy-related-attacks/",
        "https://i.blackhat.com/us-18/Wed-August-8/us-18-Orange-Tsai-Breaking-Parser-Logic-Take-Your-Path-Normalization-Off-And-Pop-0days-Out-2.pdf",
        "https://seclists.org/fulldisclosure/2011/Oct/273",
    ],
    tags: &["OWASP_2025_A01", "OWASP_2021_A01", "OWASP_2017_A05", "WSTG-v42-ATHN-04"],
};

static ALERTS: [&AlertDef; 1] = [&ALERT];

/// ZAP's path spellings of `path`, in its order.
fn path_payloads(path: &str) -> [String; 14] {
    [
        format!("/%2e{path}"),
        format!("{path}/./"),
        format!("/.{path}/./"),
        format!("{path}%20/"),
        format!("/%20{path}%20/"),
        format!("{path}%09/"),
        format!("/%09{path}%09/"),
        format!("{path}..;/"),
        format!("{path}?"),
        format!("{path}??"),
        format!("/{path}//"),
        format!("{path}/"),
        format!("{path}/.testus"),
        format!("{path}../app.py"),
    ]
}

/// ZAP's header payloads: the header, its value, and the path to send it to.
fn header_payloads(path: &str) -> [(&'static str, String, String); 10] {
    let local = || "127.0.0.1".to_string();
    [
        ("X-Rewrite-URL", path.to_string(), "/anything".into()),
        ("X-Original-URL", path.to_string(), "/".into()),
        ("Referer", path.to_string(), "/anything".into()),
        ("X-Custom-IP-Authorization", local(), path.into()),
        ("X-Originating-IP", local(), path.into()),
        ("X-Forwarded-For", local(), path.into()),
        ("X-Remote-IP", local(), path.into()),
        ("X-Client-IP", local(), path.into()),
        ("X-Host", local(), path.into()),
        ("X-Forwarded-Host", local(), path.into()),
    ]
}

pub struct ForbiddenBypass;

impl ForbiddenBypass {
    /// Whether `resp` is the page itself: a 200 that isn't this host's page for a missing path.
    async fn opened(cx: &Cx, resp: &Response) -> bool {
        resp.status == 200 && !cx.not_found(resp).await
    }

    fn raise(cx: &Cx, resp: &Response, attack: String) {
        let original = format!("{}{}", cx.target().origin(), base_path(cx));
        cx.report(ALERT.raise("", "").attack(attack).other_info(original), resp);
    }
}

impl ActiveRule for ForbiddenBypass {
    fn id(&self) -> u32 {
        40038
    }

    fn name(&self) -> &'static str {
        "Bypassing 403"
    }

    fn alerts(&self) -> &'static [&'static AlertDef] {
        &ALERTS
    }

    fn scope(&self) -> RuleScope {
        RuleScope::Page
    }

    fn scan<'a>(&'a self, cx: &'a Cx) -> BoxFuture<'a> {
        Box::pin(async move {
            if cx.base_response().status != 403 {
                return;
            }
            let path = base_path(cx);
            for payload in path_payloads(&path) {
                if cx.stopped() {
                    return;
                }
                let req = bust(&fresh_request(cx, "GET", &payload, b""));
                let Ok(resp) = cx.send(req).await else { continue };
                if Self::opened(cx, &resp).await {
                    Self::raise(cx, &resp, payload);
                    return;
                }
            }
            for (header, value, to) in header_payloads(&path) {
                if cx.stopped() {
                    return;
                }
                let req = RawRequest::from_bytes(fresh_request(cx, "GET", &to, b"")).set_header(header, &value);
                let Ok(resp) = cx.send(bust(req.as_bytes())).await else { continue };
                if Self::opened(cx, &resp).await {
                    Self::raise(cx, &resp, format!("{header}: {value}"));
                    return;
                }
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use crate::scan::active::rules::test_app::{get, html, not_found, resp, scan, seen, serve, Opts};

    fn forbidden() -> String {
        resp(403, "text/html", &[], "<html>Forbidden</html>")
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_trailing_dot_segment_and_x_original_url() {
        let log = seen();
        let l = log.clone();
        // The front end blocks /admin exactly; the app routes /admin/./ to it.
        let port = serve(move |r| {
            l.lock().unwrap().push(r.clone());
            match r.path.as_str() {
                "/admin" => forbidden(),
                "/admin/./" => html("<html>Admin panel</html>"),
                _ => not_found(),
            }
        });
        let (_, found) = scan(40038, vec![get(port, "/admin")], Opts::default()).await;
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].attack, "/admin/./");
        // Each attack had a cache buster.
        assert!(log
            .lock()
            .unwrap()
            .iter()
            .skip(1)
            .filter(|r| !r.path.starts_with("/brainproxy-"))
            .all(|r| r.query.starts_with("bp")));

        // The framework routes by X-Original-URL.
        let port = serve(|r| match (r.path.as_str(), r.header("x-original-url")) {
            (_, Some("/admin")) => html("<html>Admin panel</html>"),
            ("/admin", _) => forbidden(),
            _ => not_found(),
        });
        let (_, found) = scan(40038, vec![get(port, "/admin")], Opts::default()).await;
        assert_eq!(found[0].attack, "X-Original-URL: /admin");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_consistent_check_and_a_catch_all_raise_nothing() {
        let strict = serve(|r| {
            if r.path.contains("admin") || r.header("x-original-url").is_some() {
                forbidden()
            } else {
                not_found()
            }
        });
        let (s, found) = scan(40038, vec![get(strict, "/admin")], Opts::default()).await;
        assert!(found.is_empty());
        assert_eq!(s.requests, 24, "14 paths and 10 headers");
        // A single-page app answers every other path with its start page.
        let spa = serve(|r| if r.path == "/admin" { forbidden() } else { html("<html>app shell</html>") });
        let (_, found) = scan(40038, vec![get(spa, "/admin")], Opts::default()).await;
        assert!(found.is_empty());
    }
}
