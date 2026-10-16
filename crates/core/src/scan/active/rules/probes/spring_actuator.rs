//! Ported from ZAP SpringActuatorScanRule (ascanrules, Apache License 2.0).

use std::sync::LazyLock;

use regex::Regex;

use super::common::{base_path, is_page_200};
use crate::http::RawRequest;
use crate::scan::active::{ActiveRule, BoxFuture, Cx, RuleScope};
use crate::scan::{AlertDef, Confidence, Risk};

static ALERT: AlertDef = AlertDef {
    alert_ref: "40042",
    name: "Spring Actuator Information Leak",
    risk: Risk::Medium,
    confidence: Confidence::Medium,
    cwe: 215,
    wasc: 13,
    description: "Spring Actuator for Health is enabled and may reveal sensitive information about this application. \
        Spring Actuators can be used for real monitoring purposes, but should be used with caution as to not expose \
        too much information about the application or the infrastructure running it.",
    solution: "Disable the Health Actuators and other actuators, or restrict them to administrative users.",
    references: &["https://docs.spring.io/spring-boot/api/rest/actuator/index.html#overview"],
    tags: &["OWASP_2025_A02", "OWASP_2021_A01", "OWASP_2017_A05", "WSTG-v42-CONF-05"],
};

static ALERTS: [&AlertDef; 1] = [&ALERT];

const ENDPOINTS: [&str; 1] = ["actuator/health"];

static CONTENT_TYPE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"application/vnd\.spring-boot\.actuator\.v[0-9]\+json|application/json").unwrap());
static JSON_PAYLOAD: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?s)\{.*:.*\}").unwrap());

/// ZAP's actuator generatePath: cuts at the *last* '/' of a non-directory base.
fn generate_path(base_path: &str, endpoint: &str) -> String {
    if base_path.contains('/') {
        if base_path.ends_with('/') {
            format!("{base_path}{endpoint}")
        } else {
            format!("{}/{endpoint}", &base_path[..base_path.rfind('/').unwrap_or(0)])
        }
    } else {
        format!("{base_path}/{endpoint}")
    }
}

fn matches(content_type: &str, body: &str) -> bool {
    CONTENT_TYPE.is_match(content_type) && JSON_PAYLOAD.is_match(body)
}

pub struct SpringActuator;

impl ActiveRule for SpringActuator {
    fn id(&self) -> u32 {
        40042
    }

    fn name(&self) -> &'static str {
        "Spring Actuator Information Leak"
    }

    fn alerts(&self) -> &'static [&'static AlertDef] {
        &ALERTS
    }

    fn scope(&self) -> RuleScope {
        RuleScope::Host
    }

    fn scan<'a>(&'a self, cx: &'a Cx) -> BoxFuture<'a> {
        Box::pin(async move {
            let base = base_path(cx);
            for endpoint in ENDPOINTS {
                let path = generate_path(&base, endpoint);
                // ZAP sends the same path twice with different Accept-Encoding values.
                for encoding in [None, Some("application/json")] {
                    if cx.stopped() {
                        return;
                    }
                    let mut req = RawRequest::from_bytes(cx.request_for("GET", &path));
                    if let Some(enc) = encoding {
                        req = req.set_header("Accept-Encoding", enc);
                    }
                    let Ok(resp) = cx.send(req.into_bytes()).await else { continue };
                    let ct = resp.content_type();
                    if !ct.is_empty() && is_page_200(cx, &resp).await && matches(&ct, resp.body_str()) {
                        let evidence: String = resp.body_str().chars().take(100).collect();
                        cx.report(ALERT.raise("", evidence), &resp);
                        break;
                    }
                }
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn paths() {
        assert_eq!(generate_path("/", "actuator/health"), "/actuator/health");
        assert_eq!(generate_path("/app/x", "actuator/health"), "/app/actuator/health");
        assert_eq!(generate_path("/app/", "actuator/health"), "/app/actuator/health");
    }

    #[test]
    fn detection() {
        assert!(matches("application/vnd.spring-boot.actuator.v3+json", r#"{"status":"UP"}"#));
        assert!(matches("application/json;charset=utf-8", r#"{ "status" : "UP" }"#));
        assert!(!matches("text/html", r#"{"status":"UP"}"#));
        assert!(!matches("application/json", "not json"));
    }
}
