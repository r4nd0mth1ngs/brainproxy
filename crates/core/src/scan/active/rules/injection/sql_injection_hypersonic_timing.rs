//! Ported from ZAP SqlInjectionHypersonicTimingScanRule (ascanrules, Apache License 2.0).

use super::common::{SQL_DESC, SQL_REFS, SQL_SOLN, SQL_TIMING_TAGS};
use super::timing::{scan_sql_timing, SqlTiming};
use crate::scan::active::{ActiveRule, BoxFuture, Cx, RuleScope};
use crate::scan::{AlertDef, Confidence, Risk};

static ALERT: AlertDef = AlertDef {
    alert_ref: "40020",
    name: "SQL Injection - Hypersonic SQL (Time Based)",
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
        concat!("\"java.lang.Thread.sleep\"(", sleep_token!(), ")")
    };
}

macro_rules! from_where {
    () => {
        " from INFORMATION_SCHEMA.SYSTEM_COLUMNS where TABLE_NAME = 'SYSTEM_COLUMNS' and COLUMN_NAME = 'TABLE_NAME'"
    };
}

/// Hypersonic payloads calling `java.lang.Thread.sleep`, in ZAP's order. ('+'
/// is avoided: it would reach the database as a space.)
pub(super) const TEMPLATES: [&str; 16] = [
    concat!("; select ", sleep_fn!(), from_where!(), " -- "),
    concat!("'; select ", sleep_fn!(), from_where!(), " -- "),
    concat!("\"; select ", sleep_fn!(), from_where!(), " -- "),
    concat!("); select ", sleep_fn!(), from_where!(), " -- "),
    sleep_fn!(),
    concat!(orig_value!(), " / ", sleep_fn!(), " "),
    concat!(orig_value!(), "' / ", sleep_fn!(), " / '"),
    concat!(orig_value!(), "\" / ", sleep_fn!(), " / \""),
    // Param in WHERE clause somewhere.
    concat!(orig_value!(), " and exists ( select ", sleep_fn!(), from_where!(), ") -- "),
    concat!(orig_value!(), "' and exists ( select ", sleep_fn!(), from_where!(), ") -- "),
    concat!(orig_value!(), "\" and exists ( select ", sleep_fn!(), from_where!(), ") -- "),
    concat!(orig_value!(), ") and exists ( select ", sleep_fn!(), from_where!(), ") -- "),
    concat!(orig_value!(), " or exists ( select ", sleep_fn!(), from_where!(), ") -- "),
    concat!(orig_value!(), "' or exists ( select ", sleep_fn!(), from_where!(), ") -- "),
    concat!(orig_value!(), "\" or exists ( select ", sleep_fn!(), from_where!(), ") -- "),
    concat!(orig_value!(), ") or exists ( select ", sleep_fn!(), from_where!(), ") -- "),
];

/// `TimeUnit.SECONDS.toMillis((long) x)`: Thread.sleep takes milliseconds.
fn sleep_token(x: f64) -> String {
    (x as i64 * 1000).to_string()
}

static SPEC: SqlTiming = SqlTiming {
    alert: &ALERT,
    templates: &TEMPLATES,
    limits: [6, 10, 12, TEMPLATES.len()],
    sleep_token,
    attack_sleep: None,
};

pub struct SqlInjectionHypersonicTiming;

impl ActiveRule for SqlInjectionHypersonicTiming {
    fn id(&self) -> u32 {
        40020
    }

    fn name(&self) -> &'static str {
        "SQL Injection - Hypersonic SQL (Time Based)"
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
            assemble(TEMPLATES[3], "test", &sleep_token(5.0)),
            "); select \"java.lang.Thread.sleep\"(5000) from INFORMATION_SCHEMA.SYSTEM_COLUMNS where TABLE_NAME = \
             'SYSTEM_COLUMNS' and COLUMN_NAME = 'TABLE_NAME' -- "
        );
        assert_eq!(assemble(TEMPLATES[6], "x", &sleep_token(1.0)), "x' / \"java.lang.Thread.sleep\"(1000) / '");
        assert_eq!(SPEC.limits, [6, 10, 12, 16]);
    }
}
