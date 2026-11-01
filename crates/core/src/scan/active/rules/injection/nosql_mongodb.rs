//! Ported from ZAP MongoDbInjectionScanRule (ascanrulesBeta, Apache License 2.0).
//!
//! Differences:
//! - JSON attacks replace the value with an operator object (`{"$ne":"0"}`). ZAP sets
//!   the value to a JSON document held in a string, which a query never sees as an
//!   operator. The counter-proof is `{"$eq":<original>}`, which must answer like the
//!   original, where ZAP sends an unknown operator that a real server would reject. It
//!   runs at every strength: ZAP skips it at LOW, where any changed answer raises an alert.
//! - The not-handled error check stops at the first alert. ZAP raises one per payload.
//! - No check for an authentication page bypass: scans don't know of a login page.
//! - No technology filter: ZAP only runs this against targets it knows use MongoDB,
//!   and by default assumes all do.

use serde_json::{json, Value};

use super::common::point;
use crate::scan::active::points::{self, PointKind};
use crate::scan::active::{ActiveRule, BoxFuture, Cx, Response, RuleScope, Strength};
use crate::scan::{AlertDef, Confidence, Risk};

static ALERT: AlertDef = AlertDef {
    alert_ref: "40033",
    name: "NoSQL Injection - MongoDB",
    risk: Risk::High,
    confidence: Confidence::High,
    cwe: 943,
    wasc: 19,
    description: "MongoDB query injection may be possible.",
    solution: "Do not trust client side input and escape all data on the server side.\nAvoid to use the query input \
        directly into the where and group clauses and upgrade all drivers at the latest available version.",
    references: &[
        "https://arxiv.org/pdf/1506.04082",
        "https://owasp.org/www-project-web-security-testing-guide/v41/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05.6-Testing_for_NoSQL_Injection.html",
    ],
    tags: &[
        "API_2023_API10",
        "OWASP_2025_A05",
        "OWASP_2021_A03",
        "OWASP_2017_A01",
        "WSTG-v42-INPV-05",
        "HIPAA",
        "PCI_DSS",
    ],
};

static ALERTS: [&AlertDef; 1] = [&ALERT];

const ALL_DATA_INFO: &str = "In some PHP or NodeJS based back end implementations, in order to obtain sensitive data \
    it is possible to inject the \"[$ne]\" string (or other similar ones) that is processed as an associative array \
    rather than a simple text.\nThrough this, the queries made to MongoDB will always be true.";
const CRASH_INFO: &str = "A MongoDB exception hasn't been properly handled.";
const JSON_INFO: &str = "In some NodeJS based back end implementations, messages having the JSON format as \
    content-type are expected. In order to obtain sensitive data it is possible to attack these applications \
    injecting the \"{$ne:}\" string (or other similar ones) that is processed as an associative array rather than a \
    simple text.\nThrough this, the queries made to MongoDB will always be true.";

/// Parameter name suffix and value.
const ALL_DATA: [(&str, &str); 4] = [("[$ne]", ""), ("[$regex]", ".*"), ("[$gt]", "0"), ("[$eq]", "")];
const CRASH: [&str; 5] = ["\"", "'", "//", "});", ");"];
const JSON_OPERATORS: [(&str, &str); 3] = [("$ne", "0"), ("$gt", ""), ("$regex", ".*")];
/// Lower case: ZAP matches them case-insensitively.
const ERRORS: [&str; 2] = ["runtimeexception: syntaxerror: unterminated string literal", "mongoresultexception"];

fn same_answer(a: &Response, b: &Response) -> bool {
    a.body_str() == b.body_str()
}

/// What an error in the response proves: the ones the original page shows prove nothing.
fn new_error(base: &str, attacked: &str) -> bool {
    let (base, attacked) = (base.to_lowercase(), attacked.to_lowercase());
    ERRORS.iter().any(|e| !base.contains(e) && attacked.contains(e))
}

enum Step {
    /// Nothing found: try the next step.
    Next,
    /// Found, or a request failed.
    Done,
}

/// `name[$ne]=` and friends, which PHP and qs parse into an operator.
async fn all_data(cx: &Cx, param: &str, value: &str) -> Step {
    let base = cx.base_response();
    for (suffix, injected) in ALL_DATA {
        if cx.stopped() {
            return Step::Done;
        }
        let name = format!("{param}{suffix}");
        let Some(request) = points::inject_named(cx.base_request(), cx.point(), &name, injected) else {
            return Step::Next;
        };
        let Ok(resp) = cx.send(request).await else { return Step::Done };
        if resp.status != base.status || same_answer(&resp, base) {
            continue;
        }
        let eq = format!("{param}[$eq]");
        let Some(proof) = points::inject_named(cx.base_request(), cx.point(), &eq, value) else {
            return Step::Next;
        };
        let Ok(proof) = cx.send(proof).await else { return Step::Done };
        if same_answer(&proof, base) {
            let attack = format!("{name}{injected}");
            cx.report(ALERT.raise(param, "").attack(attack).other_info(ALL_DATA_INFO), &resp);
            return Step::Done;
        }
    }
    Step::Next
}

async fn crash(cx: &Cx, param: &str) -> Step {
    let base = cx.base_response().body_str();
    for injected in CRASH {
        if cx.stopped() {
            return Step::Done;
        }
        let Ok(resp) = cx.send_payload(injected).await else { return Step::Done };
        if new_error(base, resp.body_str()) {
            let finding = ALERT.raise(param, "").attack(injected).other_info(CRASH_INFO).confidence(Confidence::Medium);
            cx.report(finding, &resp);
            return Step::Done;
        }
    }
    Step::Next
}

/// A JSON value replaced by an operator object.
async fn json_query(cx: &Cx, param: &str) {
    let base = cx.base_response();
    for (operator, operand) in JSON_OPERATORS {
        if cx.stopped() {
            return;
        }
        let attack = points::inject_json(cx.base_request(), cx.point(), |_| json!({ operator: operand }));
        let Some(attack) = attack else { return };
        let Ok(resp) = cx.send_following(attack).await else { return };
        if resp.status != base.status || same_answer(&resp, base) {
            continue;
        }
        let name = format!("{operator}{operand}");
        let proof = points::inject_json(cx.base_request(), cx.point(), |original: Value| json!({ "$eq": original }));
        let Some(proof) = proof else { return };
        let Ok(proof) = cx.send(proof).await else { return };
        if same_answer(&proof, base) {
            cx.report(ALERT.raise(param, "").attack(name).other_info(JSON_INFO), &resp);
            return;
        }
    }
}

pub struct MongoDbInjection;

impl ActiveRule for MongoDbInjection {
    fn id(&self) -> u32 {
        40033
    }

    fn name(&self) -> &'static str {
        "NoSQL Injection - MongoDB"
    }

    fn alerts(&self) -> &'static [&'static AlertDef] {
        &ALERTS
    }

    fn scope(&self) -> RuleScope {
        RuleScope::Param
    }

    fn scan<'a>(&'a self, cx: &'a Cx) -> BoxFuture<'a> {
        Box::pin(async move {
            let (param, value) = point(cx);
            let is_json = cx.point().kind == PointKind::Json;
            if !is_json {
                if let Step::Done = all_data(cx, &param, &value).await {
                    return;
                }
            }
            if cx.strength() != Strength::Low {
                if let Step::Done = crash(cx, &param).await {
                    return;
                }
            }
            if is_json {
                json_query(cx, &param).await;
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_new_errors_count() {
        assert!(new_error("<p>ok</p>", "com.mongodb.MongoResultException: bad"));
        assert!(new_error("<p>ok</p>", "RuntimeException: SyntaxError: unterminated string literal"));
        assert!(!new_error("MongoResultException in the docs", "MongoResultException in the docs"));
        assert!(!new_error("<p>ok</p>", "<p>no error</p>"));
    }
}
