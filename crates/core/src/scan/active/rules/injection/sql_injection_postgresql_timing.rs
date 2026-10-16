//! Ported from ZAP SqlInjectionPostgreSqlTimingScanRule (ascanrules, Apache License 2.0).

use super::common::{java_double, SQL_DESC, SQL_REFS, SQL_SOLN, SQL_TIMING_TAGS};
use super::timing::{scan_sql_timing, SqlTiming, LIMITS_3_5_10_100};
use crate::scan::active::{ActiveRule, BoxFuture, Cx, RuleScope};
use crate::scan::{AlertDef, Confidence, Risk};

static ALERT: AlertDef = AlertDef {
    alert_ref: "40022",
    name: "SQL Injection - PostgreSQL (Time Based)",
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

macro_rules! sleep_fn {
    () => {
        concat!("case when cast(pg_sleep(", sleep_token!(), ") as varchar) > '' then 0 else 1 end")
    };
}

/// pg_sleep payloads, in ZAP's order.
pub(super) const TEMPLATES: [&str; 16] = [
    sleep_fn!(),
    concat!(sleep_fn!(), " -- "),
    concat!("'", sleep_fn!(), " -- "),
    concat!("\"", sleep_fn!(), " -- "),
    // Without a comment: the field in the SELECT clause, but also in WHERE clauses.
    concat!(orig_value!(), " / ", sleep_fn!(), " "),
    concat!(orig_value!(), "' / ", sleep_fn!(), " / '"),
    concat!(orig_value!(), "\" / ", sleep_fn!(), " / \""),
    // Param in SELECT/UPDATE/DELETE clause.
    concat!(orig_value!(), " where 0 in (select ", sleep_fn!(), " ) -- "),
    concat!(orig_value!(), "' where 0 in (select ", sleep_fn!(), " ) -- "),
    concat!(orig_value!(), "\" where 0 in (select ", sleep_fn!(), " ) -- "),
    // Param in WHERE clause.
    concat!(orig_value!(), " and 0 in (select ", sleep_fn!(), " ) -- "),
    concat!(orig_value!(), "' and 0 in (select ", sleep_fn!(), " ) -- "),
    concat!(orig_value!(), "\" and 0 in (select ", sleep_fn!(), " ) -- "),
    concat!(orig_value!(), " or 0 in (select ", sleep_fn!(), " ) -- "),
    concat!(orig_value!(), "' or 0 in (select ", sleep_fn!(), " ) -- "),
    concat!(orig_value!(), "\" or 0 in (select ", sleep_fn!(), " ) -- "),
];

/// ZAP passes the requested delay through as a double (`pg_sleep(5.0)`).
fn sleep_token(x: f64) -> String {
    java_double(x)
}

/// The reported attack uses the configured (integer) sleep.
fn attack_sleep(s: u32) -> String {
    s.to_string()
}

static SPEC: SqlTiming = SqlTiming {
    alert: &ALERT,
    templates: &TEMPLATES,
    limits: LIMITS_3_5_10_100,
    sleep_token,
    attack_sleep: Some(attack_sleep),
};

pub struct SqlInjectionPostgreSqlTiming;

impl ActiveRule for SqlInjectionPostgreSqlTiming {
    fn id(&self) -> u32 {
        40022
    }

    fn name(&self) -> &'static str {
        "SQL Injection - PostgreSQL (Time Based)"
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
        assert_eq!(
            assemble(TEMPLATES[11], "test", &attack_sleep(5)),
            "test' and 0 in (select case when cast(pg_sleep(5) as varchar) > '' then 0 else 1 end ) -- "
        );
        assert_eq!(
            assemble(TEMPLATES[0], "test", &sleep_token(5.0)),
            "case when cast(pg_sleep(5.0) as varchar) > '' then 0 else 1 end"
        );
        assert_eq!(SPEC.limits, [3, 5, 10, 100]);
    }
}
