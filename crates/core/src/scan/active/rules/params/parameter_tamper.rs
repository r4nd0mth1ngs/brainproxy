//! Ported from ZAP ParameterTamperScanRule (ascanrules, Apache License 2.0).
//!
//! ZAP's first attack removes the parameter (`setParameter(msg, null, null)`). The
//! insertion point API cannot remove values, so [`remove_point`] builds that request
//! locally: a marker is injected, then the pair carrying it is dropped.

use std::sync::LazyLock;

use regex::Regex;

use crate::http::request::split_head_body;
use crate::http::RawRequest;
use crate::scan::active::{points, ActiveRule, BoxFuture, Cx, InsertionPoint, PointKind, Response, RuleScope};
use crate::scan::{AlertDef, Confidence, Risk};

static ALERT: AlertDef = AlertDef {
    alert_ref: "40008",
    name: "Parameter Tampering",
    risk: Risk::Medium,
    confidence: Confidence::Medium,
    cwe: 472,
    wasc: 20,
    description:
        "Parameter manipulation caused an error page or Java stack trace to be displayed. This indicated lack of \
        exception handling and potential areas for further exploit.",
    solution:
        "Identify the cause of the error and fix it. Do not trust client side input and enforce a tight check in the \
        server side. Besides, catch the exception properly. Use a generic 500 error page for internal server error.",
    references: &[],
    tags: &["API_2023_API1", "OWASP_2025_A06", "OWASP_2021_A04", "OWASP_2017_A01"],
};

static ALERTS: [&AlertDef; 1] = [&ALERT];

/// None = remove the parameter.
const PARAM_LIST: [Option<&str>; 6] = [None, Some(""), Some("@"), Some("+"), Some("\0"), Some("|")];

const MARKER: &str = "brainproxyRemoveMe7f3a";

fn re(p: &str) -> Regex {
    // PATTERN_PARAM: CASE_INSENSITIVE | MULTILINE.
    Regex::new(&format!("(?im){p}")).unwrap()
}

static JAVA1: LazyLock<Regex> = LazyLock::new(|| re(r"javax\.servlet\.\S+"));
static JAVA2: LazyLock<Regex> = LazyLock::new(|| re(r"invoke.+exception|exception.+invoke"));
/// Checked in order; any of these is LOW confidence.
static OTHERS: LazyLock<[Regex; 6]> = LazyLock::new(|| {
    [
        re(r"Microsoft(?:\s|&nbsp)+VBScript(?:\s|&nbsp)+error"),
        re(r"Microsoft OLE DB Provider for ODBC Drivers.*error"),
        re(r"ODBC.*Drivers.*error"),
        re(r"Microsoft JET Database Engine.*error"),
        re(r"(Apache Tomcat).*(Caused by:|HTTP Status 500 - Internal Server Error)"),
        re(r" on line <b>"),
    ]
});

/// checkResult's pattern part: (evidence, confidence).
pub(crate) fn error_evidence(body: &str) -> Option<(String, Confidence)> {
    if let Some(m) = JAVA1.find(body) {
        if JAVA2.is_match(body) {
            return Some((m.as_str().to_string(), Confidence::Medium));
        }
    }
    OTHERS.iter().find_map(|r| r.find(body)).map(|m| (m.as_str().to_string(), Confidence::Low))
}

fn drop_pair(pairs: &str) -> String {
    pairs.split('&').filter(|p| p.split_once('=').map(|(_, v)| v) != Some(MARKER)).collect::<Vec<_>>().join("&")
}

fn remove_json(v: &mut serde_json::Value) -> bool {
    match v {
        serde_json::Value::Object(m) => {
            if let Some(k) = m.iter().find(|(_, x)| x.as_str() == Some(MARKER)).map(|(k, _)| k.clone()) {
                m.shift_remove(&k);
                return true;
            }
            m.values_mut().any(remove_json)
        }
        serde_json::Value::Array(a) => {
            if let Some(i) = a.iter().position(|x| x.as_str() == Some(MARKER)) {
                a.remove(i);
                return true;
            }
            a.iter_mut().any(remove_json)
        }
        _ => false,
    }
}

/// The request without the parameter at `point`.
pub(crate) fn remove_point(raw: &[u8], point: &InsertionPoint) -> Vec<u8> {
    if point.kind == PointKind::Header {
        return RawRequest::from_bytes(raw.to_vec()).remove_header(&point.name).into_bytes();
    }
    let marked = points::inject(raw, point, MARKER, false);
    let (head, body) = split_head_body(&marked);
    let mut head = String::from_utf8_lossy(head).into_owned();
    let mut body = body.to_vec();
    match point.kind {
        PointKind::Query => {
            let line_end = head.find("\r\n").unwrap_or(head.len());
            let line = head[..line_end].to_string();
            let mut parts = line.splitn(3, ' ');
            let (m, t, v) = (parts.next().unwrap_or(""), parts.next().unwrap_or(""), parts.next().unwrap_or(""));
            let new_target = match t.split_once('?') {
                Some((p, q)) => {
                    let q = drop_pair(q);
                    if q.is_empty() {
                        p.to_string()
                    } else {
                        format!("{p}?{q}")
                    }
                }
                None => t.to_string(),
            };
            head.replace_range(..line_end, &format!("{m} {new_target} {v}"));
        }
        PointKind::Form => body = drop_pair(&String::from_utf8_lossy(&body)).into_bytes(),
        PointKind::Json => {
            if let Ok(mut v) = serde_json::from_slice::<serde_json::Value>(&body) {
                remove_json(&mut v);
                body = serde_json::to_vec(&v).unwrap_or(body);
            }
        }
        PointKind::Cookie => {
            let lines: Vec<String> = head
                .trim_end_matches("\r\n")
                .split("\r\n")
                .map(|l| match l.split_once(':') {
                    Some((k, v)) if k.trim().eq_ignore_ascii_case("cookie") => {
                        let kept: Vec<&str> = v
                            .split(';')
                            .map(str::trim)
                            .filter(|c| c.split_once('=').map(|(_, x)| x) != Some(MARKER))
                            .collect();
                        format!("{k}: {}", kept.join("; "))
                    }
                    _ => l.to_string(),
                })
                .collect();
            head = format!("{}\r\n\r\n", lines.join("\r\n"));
        }
        PointKind::Header => {}
    }
    RawRequest::from_bytes([head.as_bytes(), &body].concat()).update_content_length().into_bytes()
}

pub struct ParameterTamper;

impl ActiveRule for ParameterTamper {
    fn id(&self) -> u32 {
        40008
    }

    fn name(&self) -> &'static str {
        "Parameter Tampering"
    }

    fn alerts(&self) -> &'static [&'static AlertDef] {
        &ALERTS
    }

    fn scope(&self) -> RuleScope {
        RuleScope::Param
    }

    fn scan<'a>(&'a self, cx: &'a Cx) -> BoxFuture<'a> {
        Box::pin(async move {
            // Always try the normal request first.
            let Ok(normal) = cx.send_following(cx.base_request().to_vec()).await else { return };
            if normal.status != 200 {
                return;
            }
            for attack in PARAM_LIST {
                if cx.stopped() {
                    return;
                }
                let req = match attack {
                    None => remove_point(cx.base_request(), cx.point()),
                    Some(v) => points::inject(cx.base_request(), cx.point(), v, true),
                };
                let Ok(resp) = cx.send_following(req).await else { continue };
                if check_result(cx, &resp, attack.unwrap_or(""), normal.body_str()) {
                    return;
                }
            }
        })
    }
}

fn check_result(cx: &Cx, resp: &Response, attack: &str, normal: &str) -> bool {
    if resp.status != 200 && resp.status != 500 {
        return false;
    }
    // The parameter has no effect on the output.
    if resp.body_str() == normal {
        return false;
    }
    let Some((evidence, confidence)) = error_evidence(resp.body_str()) else { return false };
    cx.report(ALERT.raise(cx.point().name.clone(), evidence).attack(attack).confidence(confidence), resp);
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scan::active::PointOptions;

    #[test]
    fn error_patterns() {
        let java = "javax.servlet.ServletException: x\n at Method.invoke(..) threw exception";
        assert_eq!(error_evidence(java), Some(("javax.servlet.ServletException:".into(), Confidence::Medium)));
        assert_eq!(error_evidence("Parse error in <b>x.php</b> on line <b>3</b>").unwrap().1, Confidence::Low);
        assert!(error_evidence("javax.servlet.Foo only").is_none());
        assert!(error_evidence("all fine").is_none());
    }

    #[test]
    fn removes_parameters() {
        let raw = b"POST /p?a=1&b=2 HTTP/1.1\r\nHost: h\r\nCookie: s=1; t=2\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 7\r\n\r\nc=3&d=4";
        let opts = PointOptions { cookies: true, ..Default::default() };
        let pts = points::points(raw, &opts);
        let s = |p: usize| String::from_utf8(remove_point(raw, &pts[p])).unwrap();
        assert!(s(0).starts_with("POST /p?b=2 HTTP/1.1\r\n"), "{}", s(0));
        assert!(s(3).ends_with("\r\n\r\nc=3") && s(3).contains("Content-Length: 3\r\n"), "{}", s(3));
        assert!(s(4).contains("Cookie: t=2\r\n"), "{}", s(4));
        let json = b"POST /j HTTP/1.1\r\nHost: h\r\nContent-Type: application/json\r\nContent-Length: 15\r\n\r\n{\"a\":1,\"b\":[2]}";
        let pts = points::points(json, &PointOptions::default());
        assert!(String::from_utf8(remove_point(json, &pts[0])).unwrap().ends_with("{\"b\":[2]}"));
    }
}
