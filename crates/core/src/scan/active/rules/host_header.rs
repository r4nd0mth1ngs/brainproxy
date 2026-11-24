//! brainproxy's own rule: Host header injection and password-reset poisoning (100010). Once
//! per page (method and path, whatever the query).
//!
//! A made-up host is put, one request at a time, where an application may read "its own" host
//! from: `X-Forwarded-Host`, `X-Host`, `X-Forwarded-Server`, `X-Original-Host`,
//! `Forwarded: host=`, an absolute-URI request line (`GET http://made-up/path`) keeping the
//! real Host, and a second `Host` header after the real one. The connection always goes to the
//! target, through the scope guard; only the header text names another host. Over HTTP/2 and
//! HTTP/3 the last two are left out: `:authority` can't say them.
//!
//! - **Host Header Injection** (medium): the response uses the made-up host as the host of a
//!   URL it gives the browser (a redirect, a link, a form action, a `<base>`, a script or
//!   stylesheet URL; see [`canary::reflected_in_link_context`]), and the baseline doesn't.
//!   Whoever can get that response cached, or the page's links clicked, sends users to a host
//!   of their choosing.
//! - With the OOB listener running in DNS mode (`oob start --domain`), the made-up host is an
//!   OOB host, and a callback raises **Routing-Based SSRF via Host Header** (high: the server
//!   or something behind it connected to the host it was told), or on a form that sends email
//!   **Password Reset Poisoning** (high: a reset link carrying the host was opened, by the user
//!   or a mail scanner, or the server fetched it). Without one (or in host mode, whose payloads
//!   carry their token in the path, not the host) the host is a random `.invalid` name.
//!
//! A form that may send email (a path naming a password reset, forgotten password or account
//! recovery, or a parameter naming an email address) gets only `X-Forwarded-Host` below
//! strength high: each request may email a real user. Every request carries a cache buster
//! ([`canary::bust`]), so a cache in front can only keep the poisoned answer under a URL
//! nobody else asks for.
//!
//! The made-up host isn't in the scope, so through MCP this rule runs only with
//! `scan active --host-header-test` (see [`ActiveRule::tests_host_header`]).

use crate::http::RawRequest;
use crate::scan::active::canary;
use crate::scan::active::{points, ActiveRule, BoxFuture, Cx, PointOptions, RuleScope, Strength};
use crate::scan::{AlertDef, Confidence, Risk};

const TAGS: &[&str] = &["OWASP_2025_A05", "OWASP_2021_A05", "OWASP_2017_A06", "WSTG-v42-INPV-17"];
const REFS: &[&str] = &[
    "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/17-Testing_for_Host_Header_Injection",
    "https://cheatsheetseries.owasp.org/cheatsheets/Forgot_Password_Cheat_Sheet.html",
    "https://www.rfc-editor.org/rfc/rfc7239",
];

static INJECTION: AlertDef = AlertDef {
    alert_ref: "100010-1",
    name: "Host Header Injection",
    risk: Risk::Medium,
    confidence: Confidence::Medium,
    cwe: 644,
    wasc: 0,
    description: "The application builds URLs from a host named in the request (the Host header, a forwarding \
        header such as X-Forwarded-Host, or the request line) instead of a host it knows is its own: a host the \
        scan made up came back in a redirect, a link, a form action, a base URL or a script URL. Where that \
        response is cached, or the host goes into an email such as a password reset link, an attacker sends \
        users, and their tokens, to a host of their choosing.",
    solution: "Build absolute URLs from a configured canonical host, never from request headers. Accept forwarding \
        headers only from your own proxies, and have the front end reject or overwrite Host values it doesn't \
        serve.",
    references: REFS,
    tags: TAGS,
};

static ROUTING: AlertDef = AlertDef {
    alert_ref: "100010-2",
    name: "Routing-Based SSRF via Host Header",
    risk: Risk::High,
    confidence: Confidence::High,
    cwe: 918,
    wasc: 0,
    description: "A request naming an out-of-band host in a Host-related header made something connect to that \
        host: the server, a proxy or load balancer in front of it, or a service behind it routes or fetches by \
        a host the client names. An attacker can make it reach internal hosts.",
    solution: "Route only to the hosts the front end is configured for, and ignore or reject Host and forwarding \
        header values that name any other.",
    references: REFS,
    tags: TAGS,
};

static RESET: AlertDef = AlertDef {
    alert_ref: "100010-3",
    name: "Password Reset Poisoning",
    risk: Risk::High,
    confidence: Confidence::Medium,
    cwe: 640,
    wasc: 0,
    description: "A form that sends email was sent an out-of-band host in a Host-related header, and that host \
        was contacted: most likely the emailed link (a password reset link, say) was built from it and opened, \
        by the user or a mail scanner. An attacker who asks for a reset for someone else's account gets the \
        reset token when the link is opened. It may also be the server itself fetching the host (see \
        Routing-Based SSRF via Host Header).",
    solution: "Build links in emails from a configured canonical host, never from request headers, and accept \
        forwarding headers only from your own proxies.",
    references: REFS,
    tags: TAGS,
};

static ALERTS: [&AlertDef; 3] = [&INJECTION, &ROUTING, &RESET];

/// Where the made-up host goes.
#[derive(Clone, Copy)]
enum Place {
    /// A header set to the host (replacing one the request has).
    Header(&'static str),
    /// `Forwarded: host=...`.
    Forwarded,
    /// The request line's target in absolute form with the host, the Host header kept.
    AbsoluteUri,
    /// A second Host header after the real one.
    SecondHost,
}

/// In the order tried; the first is the only one a form that may send email gets below
/// strength high.
const PLACES: &[Place] = &[
    Place::Header("X-Forwarded-Host"),
    Place::Header("X-Host"),
    Place::Header("X-Forwarded-Server"),
    Place::Header("X-Original-Host"),
    Place::Forwarded,
    Place::AbsoluteUri,
    Place::SecondHost,
];

impl Place {
    /// What a finding names as its parameter.
    fn param(self) -> &'static str {
        match self {
            Place::Header(h) => h,
            Place::Forwarded => "Forwarded",
            Place::AbsoluteUri => "request line (absolute URI)",
            Place::SecondHost => "Host (a second one)",
        }
    }

    /// Whether it can be said over HTTP/2 or HTTP/3.
    fn over_h2(self) -> bool {
        !matches!(self, Place::AbsoluteUri | Place::SecondHost)
    }

    /// `request` with `host` put in this place, and what was put there (the attack); None when
    /// the request can't carry it (a request target that isn't a path).
    fn apply(self, request: &[u8], scheme: &str, host: &str) -> Option<(Vec<u8>, String)> {
        match self {
            Place::Header(name) => Some((
                RawRequest::from_bytes(request.to_vec()).set_header(name, host).into_bytes(),
                format!("{name}: {host}"),
            )),
            Place::Forwarded => {
                // RFC 7239: a value with a `:` (a port) is a quoted string.
                let value = if host.contains(':') { format!("host=\"{host}\"") } else { format!("host={host}") };
                let attack = format!("Forwarded: {value}");
                Some((RawRequest::from_bytes(request.to_vec()).set_header("Forwarded", &value).into_bytes(), attack))
            }
            Place::AbsoluteUri => {
                let end = request.iter().position(|&b| b == b'\n')?;
                let line = std::str::from_utf8(&request[..end]).ok()?;
                let mut parts = line.splitn(3, ' ');
                let (method, target, rest) = (parts.next()?, parts.next()?, parts.next()?);
                if !target.starts_with('/') {
                    return None;
                }
                let mut out = format!("{method} {scheme}://{host}{target} {rest}").into_bytes();
                out.extend_from_slice(&request[end..]);
                Some((out, format!("{method} {scheme}://{host}{target}")))
            }
            Place::SecondHost => {
                let (head, body) = crate::http::request::split_head_body(request);
                let head = std::str::from_utf8(head).ok()?.trim_end_matches("\r\n");
                let mut lines: Vec<&str> = head.split("\r\n").collect();
                let line = format!("Host: {host}");
                let at = lines.iter().rposition(|l| l.get(..5).is_some_and(|n| n.eq_ignore_ascii_case("host:")));
                lines.insert(at.map_or(lines.len(), |i| i + 1), &line);
                let mut out = lines.join("\r\n").into_bytes();
                out.extend_from_slice(b"\r\n\r\n");
                out.extend_from_slice(body);
                Some((out, line.clone()))
            }
        }
    }
}

/// Words in a path that name a form that sends email to reset or recover an account.
const MAIL_PATHS: &[&str] = &["reset", "forgot", "recover", "lostpassword", "lost-password", "lost_password"];
/// Words in a parameter's name that say the request carries an email address or a reset.
const MAIL_PARAMS: &[&str] = &["mail", "reset", "forgot"];

/// Whether the base request looks like a form that sends email (a password reset): a path
/// naming a reset, a forgotten password or account recovery, or a parameter naming an email
/// address. Saying yes too often only sends fewer requests.
fn sends_email(path: &str, request: &[u8]) -> bool {
    let path = path.to_ascii_lowercase();
    if MAIL_PATHS.iter().any(|w| path.contains(w)) {
        return true;
    }
    let opts = PointOptions { names: false, ..PointOptions::default() };
    points::points(request, &opts).iter().any(|p| {
        let name = p.name.to_ascii_lowercase();
        MAIL_PARAMS.iter().any(|w| name.contains(w))
    })
}

/// Responses no link is built in.
fn media(content_type: &str) -> bool {
    ["image/", "font/", "audio/", "video/"].iter().any(|t| content_type.starts_with(t))
}

/// The `host[:port]` of an OOB payload's URL.
fn authority(url: &str) -> Option<&str> {
    let rest = url.split_once("://")?.1;
    Some(rest.split(['/', '?', '#']).next().unwrap_or(rest)).filter(|a| !a.is_empty())
}

pub struct HostHeaderInjection;

impl ActiveRule for HostHeaderInjection {
    fn id(&self) -> u32 {
        100010
    }

    fn name(&self) -> &'static str {
        "Host Header Injection"
    }

    fn alerts(&self) -> &'static [&'static AlertDef] {
        &ALERTS
    }

    fn scope(&self) -> RuleScope {
        RuleScope::Page
    }

    fn tests_host_header(&self) -> bool {
        true
    }

    fn scan<'a>(&'a self, cx: &'a Cx) -> BoxFuture<'a> {
        Box::pin(async move {
            let base = cx.base();
            if media(&cx.base_response().content_type())
                || !cx.once(&format!("100010:{} {}{}", base.method, cx.target().origin(), base.path))
            {
                return;
            }
            let mail = sends_email(&base.path, cx.base_request());
            let all = !mail || cx.strength() >= Strength::High;
            let note = if mail && !all {
                "The request looks like a form that sends email (a password reset, say), so below strength high \
                 only X-Forwarded-Host was tried: each request may email a real user."
            } else if mail {
                "The request looks like a form that sends email (a password reset, say): each request may have \
                 emailed a real user."
            } else {
                ""
            };
            let h2 = cx.sends_over_h2();
            let mut reflected = false;
            for &place in PLACES.iter().take(if all { PLACES.len() } else { 1 }) {
                if cx.stopped() {
                    return;
                }
                if h2 && !place.over_h2() {
                    continue;
                }
                // An OOB host only where its token is in the host name (DNS mode).
                let payload = cx.oob_payload().filter(|p| p.dns);
                let host = match payload.as_ref().and_then(|p| authority(&p.url)) {
                    Some(a) => a.to_string(),
                    None => canary::canary(),
                };
                let Some((request, attack)) = place.apply(cx.base_request(), &cx.target().scheme, &host) else {
                    continue;
                };
                let request = canary::bust(&request);
                let resp = cx.send(request.clone()).await;
                if let Some(p) = &payload {
                    let def = if mail { &RESET } else { &ROUTING };
                    let finding = def.raise(place.param(), "").attack(attack.clone()).other_info(note);
                    cx.oob_register(p, finding, &request, resp.as_ref().ok());
                }
                let Ok(resp) = resp else { continue };
                if reflected || canary::reflected_in_link_context(cx.base_response(), &host).is_some() {
                    continue;
                }
                if let Some(evidence) = canary::reflected_in_link_context(&resp, &host) {
                    reflected = true;
                    let mut info = format!("The host {host} sent as {} came back as a URL's host.", place.param());
                    if matches!(place, Place::AbsoluteUri) {
                        info.push_str(
                            " HTTP/1.1 tells a server to prefer an absolute request target over Host, so this one \
                             matters where a front end routes by Host and passes the request line on as it is.",
                        );
                    }
                    if !note.is_empty() {
                        info.push(' ');
                        info.push_str(note);
                    }
                    cx.report(INJECTION.raise(place.param(), evidence).attack(attack).other_info(info), &resp);
                }
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const REQ: &[u8] = b"POST /forgot?x=1 HTTP/1.1\r\nHost: app.test\r\nContent-Length: 3\r\n\r\na=b";

    #[test]
    fn each_place_carries_the_host() {
        let text = |p: Place| String::from_utf8(p.apply(REQ, "https", "h.invalid").unwrap().0).unwrap();
        assert!(text(Place::Header("X-Host")).contains("\r\nX-Host: h.invalid\r\n"));
        assert!(text(Place::Forwarded).contains("\r\nForwarded: host=h.invalid\r\n"));
        let (fwd, _) = Place::Forwarded.apply(REQ, "http", "o.test:8080").unwrap();
        assert!(String::from_utf8(fwd).unwrap().contains("Forwarded: host=\"o.test:8080\""));
        assert_eq!(
            text(Place::AbsoluteUri),
            "POST https://h.invalid/forgot?x=1 HTTP/1.1\r\nHost: app.test\r\nContent-Length: 3\r\n\r\na=b"
        );
        assert_eq!(
            text(Place::SecondHost),
            "POST /forgot?x=1 HTTP/1.1\r\nHost: app.test\r\nHost: h.invalid\r\nContent-Length: 3\r\n\r\na=b"
        );
        assert!(Place::AbsoluteUri.apply(b"OPTIONS * HTTP/1.1\r\n\r\n", "http", "h").is_none());
    }

    #[test]
    fn forms_that_may_send_email_are_told() {
        assert!(sends_email("/account/Forgot-Password", b"GET /account/Forgot-Password HTTP/1.1\r\n\r\n"));
        let post = b"POST /api/users HTTP/1.1\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\nuserEmail=a";
        assert!(sends_email("/api/users", post));
        assert!(!sends_email("/products", b"GET /products?id=1 HTTP/1.1\r\n\r\n"));
        assert_eq!(authority("http://bpx.oob.test:8053/"), Some("bpx.oob.test:8053"));
    }
}
