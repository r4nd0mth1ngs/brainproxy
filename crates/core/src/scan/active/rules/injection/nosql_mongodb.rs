//! Ported from ZAP MongoDbInjectionScanRule (ascanrulesBeta, Apache License 2.0).
//!
//! Differences:
//! - JSON attacks replace the value with an operator object (`{"$ne":"0"}`). ZAP sets
//!   the value to a JSON document held in a string, which a query never sees as an
//!   operator. The counter-proof is `{"$eq":<original>}`, which must answer like the
//!   original, where ZAP sends an unknown operator that a real server would reject. It
//!   runs at every strength: ZAP skips it at LOW, where any changed answer raises an alert.
//! - An operator's answer may have another status than the original's, if not a 5xx
//!   or 429: a login that refuses the original password with a 401 and lets
//!   `{"$ne":"0"}` in is the textbook case. ZAP needs the same status. The
//!   counter-proof must then give the original's status and body.
//! - `name[$eq]=` is only the counter-proof. ZAP also attacks with an empty value, which
//!   shows no more than the plain parameter can.
//! - The not-handled error check stops at the first alert. ZAP raises one per payload.
//! - No check for an authentication page bypass: scans don't know of a login page.
//! - No technology filter: ZAP only runs this against targets it knows use MongoDB,
//!   and by default assumes all do.
//! - A MongoDB error for a quote or bracket counts only when the same characters
//!   after a random value bring it too (a search page may quote the error).

use serde_json::{json, Value};

use super::common::{control_token, point};
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
const BYPASS_INFO: &str = "The original request was refused and the operator's was not: this may bypass \
    authentication or authorisation.";
const JSON_INFO: &str = "In some NodeJS based back end implementations, messages having the JSON format as \
    content-type are expected. In order to obtain sensitive data it is possible to attack these applications \
    injecting the \"{$ne:}\" string (or other similar ones) that is processed as an associative array rather than a \
    simple text.\nThrough this, the queries made to MongoDB will always be true.";

/// Parameter name suffix and value.
const ALL_DATA: [(&str, &str); 3] = [("[$ne]", ""), ("[$regex]", ".*"), ("[$gt]", "0")];
const CRASH: [&str; 5] = ["\"", "'", "//", "});", ");"];
const JSON_OPERATORS: [(&str, &str); 3] = [("$ne", "0"), ("$gt", ""), ("$regex", ".*")];
/// Lower case: ZAP matches them case-insensitively.
const ERRORS: [&str; 2] = ["runtimeexception: syntaxerror: unterminated string literal", "mongoresultexception"];

fn same_answer(a: &Response, b: &Response) -> bool {
    a.status == b.status && a.body_str() == b.body_str()
}

/// An operator's answer that may show it matched more: anything but a server failure
/// or a rate limit. The status may differ from the original's (a refused login that
/// lets the operator in); the counter-proof, which must answer like the original,
/// tells a query that read the operator from a server that rejects any object.
fn changed(attack: &Response, base: &Response) -> bool {
    attack.status < 500 && attack.status != 429 && !same_answer(attack, base)
}

/// Other info for a finding: what the operator did to a refused request.
fn info(text: &str, attack: &Response, base: &Response) -> String {
    let refused = matches!(base.status, 401 | 403);
    if refused && (200..400).contains(&attack.status) {
        format!("{text}\n{BYPASS_INFO}")
    } else {
        text.to_string()
    }
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
        if !changed(&resp, base) {
            continue;
        }
        let eq = format!("{param}[$eq]");
        let Some(proof) = points::inject_named(cx.base_request(), cx.point(), &eq, value) else {
            return Step::Next;
        };
        let Ok(proof) = cx.send(proof).await else { return Step::Done };
        if same_answer(&proof, base) {
            let attack = format!("{name}{injected}");
            cx.report(ALERT.raise(param, "").attack(attack).other_info(info(ALL_DATA_INFO, &resp, base)), &resp);
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
            // Not in ZAP: the error must come back after a random value too, or it was
            // content the attack value found (a search page quoting the error).
            let control = format!("{}{injected}", control_token(false));
            let Ok(again) = cx.send_payload(&control).await else { return Step::Done };
            if !new_error(base, again.body_str()) {
                continue;
            }
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
        if !changed(&resp, base) {
            continue;
        }
        let name = format!("{operator}{operand}");
        let proof = points::inject_json(cx.base_request(), cx.point(), |original: Value| json!({ "$eq": original }));
        let Some(proof) = proof else { return };
        let Ok(proof) = cx.send(proof).await else { return };
        if same_answer(&proof, base) {
            cx.report(ALERT.raise(param, "").attack(name).other_info(info(JSON_INFO, &resp, base)), &resp);
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
