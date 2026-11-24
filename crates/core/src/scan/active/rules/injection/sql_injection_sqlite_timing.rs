//! Ported from ZAP SqlInjectionSqLiteTimingScanRule (ascanrulesAlpha, Apache License 2.0).
//!
//! SQLite has no `sleep()`. ZAP makes it slow with `randomblob(N)` for N from 100 KB up to
//! 1 GB, and reports when the time keeps rising with N. Allocating a gigabyte on someone's
//! database server is a load test, so this port keeps ZAP's injection contexts but makes
//! the work a counting loop that holds no memory (a recursive CTE of N rows), and it reuses
//! the timing check the other time based rules share ([`check_timing`]):
//!
//! 1. Calibrate: with N = 1, then 100,000 and ten times more each step (to 100 million at
//!    most), until the answer takes 0.4 s longer than with N = 1. That gives the rows a
//!    second; a step only goes ten times past one that was too fast to see, so no request
//!    asks for more than a few seconds of work.
//! 2. Ask for whole seconds of it, high and low, twice over, as the sleep based rules do.
//!
//! A SQLite syntax error the payload provokes (`near "...": syntax error`) is reported too,
//! as in ZAP. ZAP sends nothing at LOW strength; here LOW tries one template.

use std::sync::LazyLock;
use std::time::Duration;

use regex::Regex;

use super::common::{by_strength, point, SQL_DESC, SQL_REFS, SQL_SOLN, SQL_TIMING_TAGS};
use super::timing::{assemble, check_timing, fractional_seconds, sleep_seconds, TimingOutcome};
use crate::scan::active::{ActiveRule, BoxFuture, Cx, RuleScope};
use crate::scan::{AlertDef, Confidence, Risk};

static ALERT: AlertDef = AlertDef {
    alert_ref: "40024",
    name: "SQL Injection - SQLite (Time Based)",
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

/// Work of `<<<<SLEEP>>>>` rows, as a number (ZAP's `case randomblob(..) when not null then
/// 1 else 1 end`) and as a string (`then "" else "" end`).
macro_rules! rows {
    () => {
        concat!(
            "(with recursive bp(i) as (select 1 union all select i+1 from bp limit ",
            sleep_token!(),
            ") select count(*) from bp)"
        )
    };
}
macro_rules! work_int {
    () => {
        concat!("case ", rows!(), " when 0 then 1 else 1 end ")
    };
}
macro_rules! work_str {
    () => {
        concat!("case ", rows!(), " when 0 then \"\" else \"\" end")
    };
}

/// ZAP's injection contexts, in its order: replacing the value, then after it; integer,
/// single and double quoted; with and without a trailing comment.
const TEMPLATES: [&str; 12] = [
    work_int!(),
    concat!("' | ", work_str!(), " | '"),
    concat!("\" | ", work_str!(), " | \""),
    concat!(work_int!(), "--"),
    concat!("' | ", work_str!(), " --"),
    concat!("\" | ", work_str!(), " --"),
    concat!(orig_value!(), " * ", work_int!()),
    concat!(orig_value!(), "' | ", work_str!(), " | '"),
    concat!(orig_value!(), "\" | ", work_str!(), " | \""),
    concat!(orig_value!(), " * ", work_int!(), "--"),
    concat!(orig_value!(), "' | ", work_str!(), " --"),
    concat!(orig_value!(), "\" | ", work_str!(), " --"),
];

/// Templates tried at LOW, MEDIUM, HIGH and INSANE.
const LIMITS: [usize; 4] = [1, 3, 6, TEMPLATES.len()];

/// The extra time that counts as the loop being run.
const SEEN: f64 = 0.4;
/// How much more work than the requested seconds is asked for.
const WORK_MARGIN: f64 = 1.1;
/// The most rows asked for while calibrating.
const MAX_ROWS: u64 = 100_000_000;

static SYNTAX_ERROR: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"(?i)near ".+": syntax error"#).expect("static regex compiles"));

enum Calibration {
    /// Rows a second.
    Rate(f64),
    /// The payload provoked a SQLite error (already reported).
    Error,
    NotSlowed,
}

/// How long the payload asking for `rows` took. A SQLite error it provoked is reported
/// (`Err(Error)`); a request that failed is `Err(NotSlowed)`.
async fn timed(cx: &Cx, template: &str, value: &str, param: &str, rows: u64) -> Result<Duration, Calibration> {
    let payload = assemble(template, value, &rows.to_string());
    let Ok(resp) = cx.send_payload(&payload).await else { return Err(Calibration::NotSlowed) };
    if let Some(m) = SYNTAX_ERROR.find(resp.body_str()) {
        if !SYNTAX_ERROR.is_match(cx.base_response().body_str()) {
            let info = format!("The following known SQLite error message was provoked: [{}].", SYNTAX_ERROR.as_str());
            cx.report(ALERT.raise(param, m.as_str()).attack(payload).other_info(info), &resp);
            return Err(Calibration::Error);
        }
    }
    Ok(resp.duration)
}

/// Finds how many rows a second the loop runs at for `template`, if it runs at all.
async fn calibrate(cx: &Cx, template: &str, value: &str, param: &str) -> Calibration {
    let quick = match timed(cx, template, value, param, 1).await {
        Ok(d) => d,
        Err(c) => return c,
    };
    let mut rows = 100_000;
    while rows <= MAX_ROWS && !cx.stopped() {
        let took = match timed(cx, template, value, param, rows).await {
            Ok(d) => d,
            Err(c) => return c,
        };
        let extra = took.as_secs_f64() - quick.as_secs_f64();
        if extra >= SEEN {
            return Calibration::Rate(rows as f64 / extra);
        }
        rows *= 10;
    }
    Calibration::NotSlowed
}

pub struct SqlInjectionSqLiteTiming;

impl ActiveRule for SqlInjectionSqLiteTiming {
    fn id(&self) -> u32 {
        40024
    }

    fn name(&self) -> &'static str {
        "SQL Injection - SQLite (Time Based)"
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
            let sleep = sleep_seconds();
            for template in TEMPLATES.iter().take(by_strength(cx.strength(), LIMITS)) {
                if cx.stopped() {
                    return;
                }
                let rate = match calibrate(cx, template, &value, &param).await {
                    Calibration::Rate(r) => r,
                    Calibration::Error => return,
                    Calibration::NotSlowed => continue,
                };
                // A tenth more than the calibration says: the check needs each answer to take at least
                // as long as asked, and a rate measured once can be a little high. The slope stays near 1.
                let rows = |seconds: f64| ((rate * seconds * WORK_MARGIN).round() as u64).max(1).to_string();
                let outcome =
                    check_timing(cx, sleep, |x| assemble(template, &value, &rows(x)), fractional_seconds).await;
                if let TimingOutcome::Injectable(t) = outcome {
                    let low = assemble(template, &value, &rows(1.0));
                    let info = format!(
                        "The query time is controllable using parameter value [{}], which caused the request to take \
                         [{}] milliseconds, parameter value [{low}], which caused the request to take [{}] \
                         milliseconds, when the original unmodified query with value [{value}] took [{}] \
                         milliseconds.",
                        t.first_payload,
                        t.first.duration.as_millis(),
                        t.last.duration.as_millis(),
                        cx.base_response().duration.as_millis()
                    );
                    let finding = ALERT.raise(param, "").attack(t.first_payload.clone()).other_info(info);
                    cx.report(finding, &t.first);
                    return;
                }
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scan::active::rules::test_app::{get, html, scan, serve, Opts};
    use crate::scan::active::Strength;

    #[test]
    fn templates() {
        assert_eq!(
            assemble(TEMPLATES[7], "7", "500"),
            "7' | case (with recursive bp(i) as (select 1 union all select i+1 from bp limit 500) select count(*) from \
             bp) when 0 then \"\" else \"\" end | '"
        );
        assert!(TEMPLATES.iter().all(|t| t.contains(sleep_token!())));
    }

    /// The rows a payload asks a vulnerable SQLite to count.
    fn rows(id: &str) -> Option<u64> {
        id.split("limit ").nth(1)?.split(')').next()?.parse().ok()
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_counting_loop_slows_the_query_and_a_safe_page_does_not() {
        // A million rows a second; an identifier-safe endpoint answers at once.
        let port = serve(|r| {
            let id = r.param("id").unwrap_or_default();
            if r.path == "/sqlite" {
                if let Some(n) = rows(&id) {
                    std::thread::sleep(Duration::from_secs_f64(n as f64 / 1e6));
                }
            }
            html("<p>item</p>")
        });
        let (s, found) =
            scan(40024, vec![get(port, "/sqlite?id=1")], Opts { strength: Some(Strength::Low), ..Default::default() })
                .await;
        assert_eq!(found.len(), 1, "{s:?}");
        // The first timed request asks for two seconds and a tenth more: some 2.2 million rows.
        let asked = rows(&found[0].attack).unwrap();
        assert!((2_000_000..2_400_000).contains(&asked), "{found:?}");
        // Calibration: 1, 100,000 and 1,000,000 rows; then two sequences of four.
        assert_eq!(s.requests, 3 + 8, "{s:?}");

        let (s, found) = scan(40024, vec![get(port, "/safe?id=1")], Opts::default()).await;
        assert!(found.is_empty());
        // Three templates, each 1 + 4 calibration requests up to 100 million rows.
        assert_eq!(s.requests, 15);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_sqlite_syntax_error() {
        let port = serve(|r| {
            let id = r.param("id").unwrap_or_default();
            if id.contains("with recursive") {
                html("<b>Error</b>: near \"with\": syntax error")
            } else {
                html("<p>item</p>")
            }
        });
        let (s, found) = scan(40024, vec![get(port, "/old?id=1")], Opts::default()).await;
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].evidence, "near \"with\": syntax error");
        assert_eq!(s.requests, 1);
    }
}
