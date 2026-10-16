//! Ported from ZAP SqlInjectionMsSqlTimingScanRule (ascanrules, Apache License 2.0).

use super::common::{SQL_DESC, SQL_REFS, SQL_SOLN, SQL_TIMING_TAGS};
use super::timing::{scan_sql_timing, SqlTiming};
use crate::scan::active::{ActiveRule, BoxFuture, Cx, RuleScope};
use crate::scan::{AlertDef, Confidence, Risk};

static ALERT: AlertDef = AlertDef {
    alert_ref: "40027",
    name: "SQL Injection - MsSQL (Time Based)",
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

/// WAITFOR DELAY payloads for a parameter in a WHERE clause, in ZAP's order.
pub(super) const TEMPLATES: [&str; 15] = [
    concat!(orig_value!(), " WAITFOR DELAY '", sleep_token!(), "' -- "),
    concat!(orig_value!(), "' WAITFOR DELAY '", sleep_token!(), "' -- "),
    concat!(orig_value!(), "\" WAITFOR DELAY '", sleep_token!(), "' -- "),
    concat!(orig_value!(), ") WAITFOR DELAY '", sleep_token!(), "' -- "),
    concat!(orig_value!(), ") ' WAITFOR DELAY '", sleep_token!(), "' -- "),
    concat!(orig_value!(), ") \" WAITFOR DELAY '", sleep_token!(), "' -- "),
    concat!(orig_value!(), ")) WAITFOR DELAY '", sleep_token!(), "' -- "),
    concat!(orig_value!(), ")) ' WAITFOR DELAY '", sleep_token!(), "' -- "),
    concat!(orig_value!(), ")) \" WAITFOR DELAY '", sleep_token!(), "' -- "),
    concat!(orig_value!(), ") WAITFOR DELAY '", sleep_token!(), "' ("),
    concat!(orig_value!(), ") ' WAITFOR DELAY '", sleep_token!(), "' ("),
    concat!(orig_value!(), ") \" WAITFOR DELAY '", sleep_token!(), "' ("),
    concat!(orig_value!(), ")) WAITFOR DELAY '", sleep_token!(), "' (("),
    concat!(orig_value!(), ")) ' WAITFOR DELAY '", sleep_token!(), "' (("),
    concat!(orig_value!(), ")) \" WAITFOR DELAY '", sleep_token!(), "' (("),
];

/// `getSleepToken`: `h:m:s` without padding.
fn sleep_token(x: f64) -> String {
    let total = x as i64;
    format!("{}:{}:{}", total / 3600, (total % 3600) / 60, total % 60)
}

static SPEC: SqlTiming = SqlTiming {
    alert: &ALERT,
    templates: &TEMPLATES,
    limits: [6, 10, 12, TEMPLATES.len()],
    sleep_token,
    attack_sleep: None,
};

pub struct SqlInjectionMsSqlTiming;

impl ActiveRule for SqlInjectionMsSqlTiming {
    fn id(&self) -> u32 {
        40027
    }

    fn name(&self) -> &'static str {
        "SQL Injection - MsSQL (Time Based)"
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
        assert_eq!(sleep_token(5.0), "0:0:5");
        assert_eq!(sleep_token(3725.0), "1:2:5");
        assert_eq!(assemble(TEMPLATES[4], "test", &sleep_token(5.0)), "test) ' WAITFOR DELAY '0:0:5' -- ");
        assert_eq!(assemble(TEMPLATES[14], "1", &sleep_token(1.0)), "1)) \" WAITFOR DELAY '0:0:1' ((");
        assert_eq!(SPEC.limits, [6, 10, 12, 15]);
    }
}
