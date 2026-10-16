//! Ported from ZAP HttpOnlySiteScanRule (ascanrules, Apache License 2.0).

use std::time::Duration;

use super::common::{base_path, no_response, with_request_line};
use crate::error::Error;
use crate::http::{RawRequest, Target};
use crate::scan::active::{ActiveRule, BoxFuture, Cx, Response, RuleScope};
use crate::scan::{AlertDef, Confidence, Risk};

static ALERT: AlertDef = AlertDef {
    alert_ref: "10106",
    name: "HTTP Only Site",
    risk: Risk::Medium,
    confidence: Confidence::Medium,
    cwe: 311,
    wasc: 4,
    description: "The site is only served under HTTP and not HTTPS.",
    solution: "Configure your web or application server to use SSL (https).",
    references: &[
        "https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Protection_Cheat_Sheet.html",
        "https://letsencrypt.org/",
    ],
    tags: &["OWASP_2025_A04", "OWASP_2021_A05", "OWASP_2017_A06", "WSTG-v42-CRYP-03"],
};

static ALERTS: [&AlertDef; 1] = [&ALERT];

const REDIR_LIMIT: usize = 10;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Reason {
    ConnectionFail,
    DifferentHosts,
    NoRedirection,
    NoSsl,
    RedirectionLimit,
    RedirectToHttp,
    UriNotEncoded,
}

impl Reason {
    fn text(self) -> &'static str {
        match self {
            Reason::ConnectionFail => "Failed to connect.",
            Reason::DifferentHosts => "Different Hosts.",
            Reason::NoRedirection => "There was no automatic redirection.",
            Reason::NoSsl => "Site has no SSL/TLS support.",
            Reason::RedirectionLimit => "Redirection limit reached.",
            Reason::RedirectToHttp => "Redirected to HTTP.",
            Reason::UriNotEncoded => "Redirection URI couldn't be encoded.",
        }
    }
}

fn other_info(reason: Reason, url: &str) -> String {
    format!("{}\nZAP attempted to connect via: {url}", reason.text())
}

/// The https URL for an http base: ports 80 and 443 become the https default.
fn https_url(host: &str, port: u16, path: &str) -> String {
    let host = if host.contains(':') { format!("[{host}]") } else { host.to_string() };
    if port == 80 || port == 443 {
        format!("https://{host}{path}")
    } else {
        format!("https://{host}:{port}{path}")
    }
}

/// How a failed https attempt is reported: connection errors are "connection
/// failed", a TLS failure caused by a plaintext answer is "no SSL"; anything else
/// (including out-of-scope refusals) raises nothing.
fn classify_error(e: &Error) -> Option<Reason> {
    match e {
        Error::Connect(_) | Error::Timeout(_) | Error::Io(_) => Some(Reason::ConnectionFail),
        Error::Tls(m) => {
            let m = m.to_ascii_lowercase();
            (m.contains("plaintext") || m.contains("invalidcontenttype") || m.contains("corrupt message"))
                .then_some(Reason::NoSsl)
        }
        _ => None,
    }
}

fn path_and_query(url: &url::Url) -> String {
    match url.query() {
        Some(q) => format!("{}?{q}", url.path()),
        None => url.path().to_string(),
    }
}

pub struct HttpOnlySite;

impl HttpOnlySite {
    fn raise(cx: &Cx, reason: Reason, url: &str, resp: &Response) {
        let finding = ALERT.raise("", "").other_info(other_info(reason, url));
        cx.report(finding, resp);
    }
}

impl ActiveRule for HttpOnlySite {
    fn id(&self) -> u32 {
        10106
    }

    fn name(&self) -> &'static str {
        "HTTP Only Site"
    }

    fn alerts(&self) -> &'static [&'static AlertDef] {
        &ALERTS
    }

    fn scope(&self) -> RuleScope {
        RuleScope::Host
    }

    fn scan<'a>(&'a self, cx: &'a Cx) -> BoxFuture<'a> {
        Box::pin(async move {
            if cx.target().is_tls() || cx.stopped() {
                return;
            }
            let Ok(mut url) = url::Url::parse(&https_url(&cx.target().host, cx.target().port, &base_path(cx))) else {
                return;
            };
            let method = cx.base().method.clone();
            let mut count = 0;
            let mut last: Option<Response> = None;
            while count < REDIR_LIMIT {
                if cx.stopped() {
                    return;
                }
                let Ok(target) = Target::from_url(url.as_str()) else { return };
                let raw = with_request_line(cx.base_request(), &method, &path_and_query(&url));
                let raw = RawRequest::from_bytes(raw).set_header("Host", &target.host_header()).into_bytes();
                let resp = match cx.send_to(&target, raw.clone()).await {
                    Ok(r) => r,
                    Err(e) => {
                        if let Some(reason) = classify_error(&e) {
                            Self::raise(cx, reason, url.as_str(), &no_response(cx, raw, Duration::ZERO));
                        }
                        return;
                    }
                };
                if !(300..400).contains(&resp.status) {
                    last = None;
                    break;
                }
                let location = resp.header("location").unwrap_or("").to_string();
                if location.is_empty() {
                    Self::raise(cx, Reason::NoRedirection, url.as_str(), &resp);
                    return;
                }
                let Ok(next) = url.join(&location) else {
                    Self::raise(cx, Reason::UriNotEncoded, url.as_str(), &resp);
                    return;
                };
                let same_host = url.host_str() == next.host_str();
                url = next;
                if !same_host {
                    Self::raise(cx, Reason::DifferentHosts, url.as_str(), &resp);
                    return;
                }
                if url.scheme() != "https" {
                    Self::raise(cx, Reason::RedirectToHttp, url.as_str(), &resp);
                    return;
                }
                count += 1;
                last = Some(resp);
            }
            if count == REDIR_LIMIT {
                if let Some(resp) = last {
                    Self::raise(cx, Reason::RedirectionLimit, url.as_str(), &resp);
                }
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn https_urls() {
        assert_eq!(https_url("example.com", 80, "/a"), "https://example.com/a");
        assert_eq!(https_url("example.com", 8080, "/"), "https://example.com:8080/");
        assert_eq!(https_url("::1", 80, "/"), "https://[::1]/");
    }

    #[test]
    fn errors() {
        assert_eq!(classify_error(&Error::Connect("refused".into())), Some(Reason::ConnectionFail));
        assert_eq!(classify_error(&Error::Timeout(Duration::from_secs(1))), Some(Reason::ConnectionFail));
        assert_eq!(
            classify_error(&Error::Tls("received corrupt message of type InvalidContentType".into())),
            Some(Reason::NoSsl)
        );
        assert_eq!(classify_error(&Error::Tls("invalid peer certificate".into())), None);
        assert_eq!(classify_error(&Error::OutOfScope("x".into())), None);
    }

    #[test]
    fn texts() {
        assert_eq!(
            other_info(Reason::NoSsl, "https://a/"),
            "Site has no SSL/TLS support.\nZAP attempted to connect via: https://a/"
        );
    }
}
