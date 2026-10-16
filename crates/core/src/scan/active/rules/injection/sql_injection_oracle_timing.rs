//! Ported from ZAP SqlInjectionOracleTimingScanRule (ascanrules, Apache License 2.0).

use super::common::{SQL_DESC, SQL_REFS, SQL_SOLN, SQL_TIMING_TAGS};
use super::timing::{scan_sql_timing, SqlTiming, LIMITS_3_5_10_100};
use crate::scan::active::{ActiveRule, BoxFuture, Cx, RuleScope};
use crate::scan::{AlertDef, Confidence, Risk};

static ALERT: AlertDef = AlertDef {
    alert_ref: "40021",
    name: "SQL Injection - Oracle (Time Based)",
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
        concat!("DBMS_SESSION.SLEEP(", sleep_token!(), ")")
    };
}

/// DBMS_SESSION.SLEEP payloads, in ZAP's order.
pub(super) const TEMPLATES: [&str; 12] = [
    concat!("(", sleep_fn!(), ")"),
    concat!(orig_value!(), " / (", sleep_fn!(), ") "),
    concat!(orig_value!(), "' / (", sleep_fn!(), ") / '"),
    concat!(orig_value!(), "\" / (", sleep_fn!(), ") / \""),
    // Param in WHERE clause somewhere.
    concat!(orig_value!(), " and exists (", sleep_fn!(), ") -- "),
    concat!(orig_value!(), "' and exists (", sleep_fn!(), ") -- "),
    concat!(orig_value!(), "\" and exists (", sleep_fn!(), ") -- "),
    concat!(orig_value!(), ") and exists (", sleep_fn!(), ") -- "),
    concat!(orig_value!(), " or exists (", sleep_fn!(), ") -- "),
    concat!(orig_value!(), "' or exists (", sleep_fn!(), ") -- "),
    concat!(orig_value!(), "\" or exists (", sleep_fn!(), ") -- "),
    concat!(orig_value!(), ") or exists (", sleep_fn!(), ") -- "),
];

/// `(int) x`: whole seconds.
fn sleep_token(x: f64) -> String {
    (x as i64).to_string()
}

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

pub struct SqlInjectionOracleTiming;

impl ActiveRule for SqlInjectionOracleTiming {
    fn id(&self) -> u32 {
        40021
    }

    fn name(&self) -> &'static str {
        "SQL Injection - Oracle (Time Based)"
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
        assert_eq!(assemble(TEMPLATES[1], "test", &attack_sleep(5)), "test / (DBMS_SESSION.SLEEP(5)) ");
        assert_eq!(assemble(TEMPLATES[0], "test", &sleep_token(1.0)), "(DBMS_SESSION.SLEEP(1))");
        assert_eq!(assemble(TEMPLATES[11], "7", "5"), "7) or exists (DBMS_SESSION.SLEEP(5)) -- ");
    }
}
