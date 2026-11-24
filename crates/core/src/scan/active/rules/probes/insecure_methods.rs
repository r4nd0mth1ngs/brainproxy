//! Ported from ZAP InsecureHttpMethodScanRule (ascanrulesBeta, Apache License 2.0).
//!
//! Asks the page's URL with OPTIONS which methods it allows. Of those (at HIGH and INSANE,
//! of every insecure one), TRACE and TRACK are sent to a random path with a made-up cookie,
//! which an echo gives back, and PROPFIND to the page with `Depth: 0`: these change nothing.
//! PUT and PATCH (to a new random resource, as in ZAP) and WebDAV's COPY, LOCK, MKCOL, MOVE,
//! PROPPATCH and UNLOCK can change what the server holds, so they go out only when
//! `--include-methods` names them. DELETE is never sent: an Allow header listing it is the
//! finding, as in ZAP. ZAP's CONNECT test opens a tunnel to a third-party site, which no
//! scope allows, so it isn't ported; nor are the unverified alerts ZAP raises only at the LOW
//! threshold (90028-2).

use super::common::{base_path_query, is_page_200, with_body};
use crate::http::RawRequest;
use crate::scan::active::{rand_u64, ActiveRule, BoxFuture, Cx, Response, RuleScope, Strength};
use crate::scan::{AlertDef, Confidence, Risk};

const SOLUTION: &str = "Disable insecure methods such as TRACK, TRACE, and CONNECT on the web server, and ensure \
    that the underlying service implementation does not support insecure methods.";
const REFS: &[&str] = &[
    "https://projects.webappsec.org/w/page/13246925/Fingerprinting",
    "https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/06-Test_HTTP_Methods",
];
const TAGS: &[&str] = &["OWASP_2025_A02", "OWASP_2021_A05", "OWASP_2017_A06", "WSTG-v42-CONF-06"];
const STACKEXCHANGE: &str = "See the discussion on stackexchange: \
    https://security.stackexchange.com/questions/21413/how-to-exploit-http-methods";

static DELETE: AlertDef = AlertDef {
    alert_ref: "90028-1",
    name: "Insecure HTTP Method - DELETE",
    risk: Risk::Medium,
    confidence: Confidence::Medium,
    cwe: 749,
    wasc: 45,
    description: "The insecure HTTP method [DELETE] is enabled on the web server for this resource. Depending on the \
        web server configuration, and the underlying implementation responsible for serving the resource, this might \
        or might not be exploitable. The TRACK and TRACE methods may be used by an attacker, to gain access to the \
        authorisation token/session cookie of an application user, even if the session cookie is protected using the \
        'HttpOnly' flag. For the attack to be successful, the application user must typically be using an older web \
        browser, or a web browser which has a Same Origin Policy (SOP) bypass vulnerability. The 'CONNECT' method can \
        be used by a web client to create an HTTP tunnel to third party websites or services.",
    solution: SOLUTION,
    references: REFS,
    tags: TAGS,
};

static TRACE: AlertDef = AlertDef {
    alert_ref: "90028-3",
    name: "Insecure HTTP Method - TRACE or TRACK",
    risk: Risk::Medium,
    confidence: Confidence::Medium,
    cwe: 749,
    wasc: 45,
    description: "The insecure HTTP method (TRACE or TRACK) is enabled for this resource, and is exploitable. The \
        TRACK and TRACE methods may be used by an attacker, to gain access to the authorisation token/session cookie \
        of an application user, even if the session cookie is protected using the 'HttpOnly' flag. For the attack to \
        be successful, the application user must typically be using an older web browser, or a web browser which has \
        a Same Origin Policy (SOP) bypass vulnerability.",
    solution: SOLUTION,
    references: REFS,
    tags: TAGS,
};

static WEBDAV: AlertDef = AlertDef {
    alert_ref: "90028-5",
    name: "Insecure HTTP Method - WebDAV",
    risk: Risk::Info,
    confidence: Confidence::Medium,
    cwe: 749,
    wasc: 45,
    description: "This HTTP method is a WEBDAV method: COPY, LOCK, MKCOL, MOVE, PROPFIND, PROPPATCH or UNLOCK. If \
        this server is not offering any WEBDAV services, these methods should not be available.",
    solution: SOLUTION,
    references: REFS,
    tags: TAGS,
};

static PUT_PATCH: AlertDef = AlertDef {
    alert_ref: "90028-6",
    name: "Insecure HTTP Method - PUT or PATCH",
    risk: Risk::Medium,
    confidence: Confidence::Medium,
    cwe: 749,
    wasc: 45,
    description: "This method is now most commonly used in REST services: PUT is most-often utilized for **update** \
        capabilities, PUT-ing to a known resource URI with the request body containing the newly-updated \
        representation of the original resource, and PATCH for **modify** capabilities, the request only needing to \
        contain the changes to the resource. PUT was originally intended for file management operations.",
    solution: SOLUTION,
    references: REFS,
    tags: TAGS,
};

static ALERTS: [&AlertDef; 4] = [&DELETE, &TRACE, &WEBDAV, &PUT_PATCH];

const WEBDAV_METHODS: [&str; 7] = ["COPY", "LOCK", "MKCOL", "MOVE", "PROPFIND", "PROPPATCH", "UNLOCK"];
/// ZAP's insecure methods: PATCH, PUT, then the WebDAV ones.
const INSECURE: [&str; 9] = ["PATCH", "PUT", "COPY", "LOCK", "MKCOL", "MOVE", "PROPFIND", "PROPPATCH", "UNLOCK"];

/// A random string of letters and digits.
fn random(len: usize) -> String {
    const CHARS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    (0..len).map(|_| CHARS[(rand_u64() % CHARS.len() as u64) as usize] as char).collect()
}

/// The methods an OPTIONS answer lists in `Allow` and `Public`, upper case.
fn listed(resp: &Response) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for h in ["Allow", "Public"] {
        for m in resp.headers_named(h).flat_map(|v| v.split(',')) {
            let m = m.trim().to_ascii_uppercase();
            if !m.is_empty() && !out.contains(&m) {
                out.push(m);
            }
        }
    }
    out
}

pub struct InsecureMethods;

impl InsecureMethods {
    /// TRACE or TRACK to a random path with a made-up cookie: an echo of the request gives
    /// the cookie back.
    async fn trace(cx: &Cx, method: &str) {
        let path = format!("/{}", random(12).to_ascii_lowercase());
        let (name, value) = (random(15), random(40));
        let req = RawRequest::from_bytes(cx.request_for(method, &path));
        let cookie = match cx.base().req_header("cookie") {
            Some(c) => format!("{c}; {name}={value}"),
            None => format!("{name}={value}"),
        };
        let req = http10(req.set_header("Cookie", &cookie).into_bytes());
        let Ok(resp) = cx.send(req).await else { return };
        if resp.body_str().contains(&value) {
            let info = format!(
                "A {method} request was sent for this request, with a custom cookie value [{value}]. This cookie value \
                 was disclosed in the HTTP response, confirming the vulnerability."
            );
            cx.report(TRACE.raise(method, value).other_info(info), &resp);
        }
    }

    /// A WebDAV method, PUT or PATCH; only what the scan may send goes out.
    async fn method(cx: &Cx, method: &str) {
        if method != "PROPFIND" && !cx.method_opted_in(method) {
            return;
        }
        let page = base_path_query(cx);
        let req = match method {
            // A new resource next to the page, as ZAP: never one that exists.
            "PUT" | "PATCH" => {
                let sep = if page.ends_with('/') { "" } else { "/" };
                let path = format!("{}{sep}{}", page.split('?').next().unwrap_or("/"), random(10).to_ascii_lowercase());
                let body = format!("\"{}\":\"{}\"", random(15), random(15));
                with_body(cx.request_for(method, &path), body.as_bytes())
            }
            "PROPFIND" => RawRequest::from_bytes(cx.request_for(method, &page)).set_header("Depth", "0").into_bytes(),
            _ => cx.request_for(method, &page),
        };
        let Ok(resp) = cx.send(req).await else { return };
        let ct = resp.content_type();
        if matches!(method, "PUT" | "PATCH") && (ct.contains("json") || ct.contains("xml")) {
            return;
        }
        let evidence = if is_page_200(cx, &resp).await || resp.status == 201 {
            format!("response code {} for insecure HTTP METHOD", resp.status)
        } else if matches!(resp.status, 401..=403) {
            format!("response code {} for potentially insecure HTTP METHOD", resp.status)
        } else {
            return;
        };
        let (def, info) = if WEBDAV_METHODS.contains(&method) {
            (&WEBDAV, STACKEXCHANGE.to_string())
        } else {
            (
                &PUT_PATCH,
                format!("{STACKEXCHANGE}, for understanding REST operations see https://www.restapitutorial.com/lessons/httpmethods.html"),
            )
        };
        cx.report(def.raise(method, evidence).other_info(info), &resp);
    }
}

/// `req` with its request line saying HTTP/1.0 (ZAP sends TRACE and TRACK so).
fn http10(req: Vec<u8>) -> Vec<u8> {
    let end = req.windows(2).position(|w| w == b"\r\n").unwrap_or(req.len());
    let line = String::from_utf8_lossy(&req[..end]);
    match line.rsplit_once(' ') {
        Some((start, _)) => [format!("{start} HTTP/1.0").as_bytes(), &req[end..]].concat(),
        None => req,
    }
}

impl ActiveRule for InsecureMethods {
    fn id(&self) -> u32 {
        90028
    }

    fn name(&self) -> &'static str {
        "Insecure HTTP Method"
    }

    fn alerts(&self) -> &'static [&'static AlertDef] {
        &ALERTS
    }

    fn scope(&self) -> RuleScope {
        RuleScope::Page
    }

    fn scan<'a>(&'a self, cx: &'a Cx) -> BoxFuture<'a> {
        Box::pin(async move {
            let page = base_path_query(cx);
            if !cx.once(&format!("90028|{}{}", cx.target().origin(), page)) {
                return;
            }
            let Ok(options) = cx.send(cx.request_for("OPTIONS", &page)).await else { return };
            let mut enabled = listed(&options);
            // At LOW, as in ZAP, nothing more; at MEDIUM only what OPTIONS lists.
            if cx.strength() == Strength::Low || (enabled.is_empty() && cx.strength() == Strength::Medium) {
                return;
            }
            if let Some(i) = enabled.iter().position(|m| m == "DELETE") {
                enabled.remove(i);
                let allowed = options.header("Allow").unwrap_or("").to_string();
                let info = format!(
                    "The OPTIONS method disclosed the following enabled HTTP methods for this resource: [{allowed}]"
                );
                cx.report(DELETE.raise("DELETE", "DELETE").other_info(info), &options);
            }
            let to_test: Vec<String> = if cx.strength() >= Strength::High {
                ["TRACK", "TRACE"].iter().chain(INSECURE.iter()).map(|m| m.to_string()).collect()
            } else {
                enabled
            };
            for m in to_test {
                if cx.stopped() {
                    return;
                }
                match m.as_str() {
                    "TRACE" | "TRACK" => Self::trace(cx, &m).await,
                    m if INSECURE.contains(&m) => Self::method(cx, m).await,
                    _ => {}
                }
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scan::active::rules::test_app::{get, html, resp, scan, seen, serve, Opts};

    fn allow(methods: &'static str) -> impl Fn(&crate::scan::active::rules::test_app::Req) -> String + Send + Sync {
        move |r| match r.method.as_str() {
            "OPTIONS" => resp(200, "", &[("Allow", methods)], ""),
            // An echo of the request, cookies and all.
            "TRACE" | "TRACK" => resp(
                200,
                "message/http",
                &[],
                &format!("{} {}\r\nCookie: {}", r.method, r.target, r.header("cookie").unwrap_or("")),
            ),
            "PROPFIND" => resp(207, "application/xml", &[], "<multistatus/>"),
            "PUT" => resp(201, "text/plain", &[], "created"),
            _ => html("<html>page</html>"),
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn what_options_lists_is_tested_and_only_safe_methods_go_out() {
        let log = seen();
        let l = log.clone();
        let echo = allow("GET, POST, OPTIONS, TRACE, PROPFIND, PUT, DELETE, MOVE");
        let port = serve(move |r| {
            l.lock().unwrap().push(r.clone());
            echo(r)
        });
        let (_, found) = scan(90028, vec![get(port, "/files/")], Opts::default()).await;
        let refs: Vec<&str> = found.iter().map(|f| f.alert_ref.as_str()).collect();
        assert_eq!(refs, ["90028-1", "90028-3"], "{found:?}");
        let methods: Vec<String> = log.lock().unwrap().iter().map(|r| r.method.clone()).collect();
        // The baseline GET, then no PUT, MOVE or DELETE without --include-methods.
        assert_eq!(methods, ["GET", "OPTIONS", "TRACE", "PROPFIND"]);
        let trace = log.lock().unwrap().iter().find(|r| r.method == "TRACE").cloned().unwrap();
        assert_ne!(trace.path, "/files/");
        let propfind = log.lock().unwrap().iter().find(|r| r.method == "PROPFIND").cloned().unwrap();
        assert_eq!((propfind.path.as_str(), propfind.header("depth")), ("/files/", Some("0")));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn put_needs_include_methods_and_a_quiet_server_raises_nothing() {
        let log = seen();
        let l = log.clone();
        let echo = allow("GET, PUT");
        let port = serve(move |r| {
            l.lock().unwrap().push(r.clone());
            echo(r)
        });
        let opts = Opts { methods: vec!["PUT".into()], ..Default::default() };
        let (_, found) = scan(90028, vec![get(port, "/files/")], opts).await;
        assert_eq!(found.iter().map(|f| f.alert_ref.as_str()).collect::<Vec<_>>(), ["90028-6"]);
        let put = log.lock().unwrap().iter().find(|r| r.method == "PUT").cloned().unwrap();
        assert!(put.path.starts_with("/files/") && put.path.len() > "/files/".len(), "a new resource: {}", put.path);

        // Fixed: OPTIONS lists only GET and POST, TRACE isn't echoed.
        let safe = serve(|r| match r.method.as_str() {
            "OPTIONS" => resp(200, "", &[("Allow", "GET, POST, OPTIONS")], ""),
            "GET" => html("<html>page</html>"),
            _ => resp(405, "text/plain", &[], "no"),
        });
        let (s, found) =
            scan(90028, vec![get(safe, "/files/")], Opts { strength: Some(Strength::High), ..Default::default() })
                .await;
        assert!(found.is_empty(), "{found:?}");
        // OPTIONS, TRACK, TRACE, PROPFIND: the rest need --include-methods.
        assert_eq!(s.requests, 4, "{s:?}");
    }
}
