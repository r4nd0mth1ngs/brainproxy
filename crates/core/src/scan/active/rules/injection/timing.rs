//! Time based detection, ported from ZAP commonlib `TimingUtils` and
//! `OnlineSimpleLinearRegression` (Apache License 2.0), plus the request loop
//! shared by the RDBMS-specific time based SQL injection rules.

use std::time::Duration;

use super::common::{by_strength, grouped, point};
use crate::scan::active::{Cx, Response};
use crate::scan::AlertDef;

/// ZAP's default for `rules.common.sleep`, in seconds. Tests use a shorter delay
/// so the end-to-end timing checks stay fast.
pub(super) const DEFAULT_SLEEP_TIME: u32 = 5;
/// The most requests one timing check sends (sent as high/low pairs).
pub(super) const BLIND_REQUESTS_LIMIT: u32 = 4;
/// Acceptance intervals for the final regression: correlation > 1 - 0.15 and
/// |slope - 1| < 0.30.
pub(super) const TIME_CORRELATION_ERROR_RANGE: f64 = 0.15;
pub(super) const TIME_SLOPE_ERROR_RANGE: f64 = 0.30;
/// `TimingUtils.MINIMUM_REQUESTS`.
const MINIMUM_REQUESTS: u32 = 2;

pub(super) fn sleep_seconds() -> u32 {
    if cfg!(test) {
        2
    } else {
        DEFAULT_SLEEP_TIME
    }
}

/// Simple linear regression updated one point at a time (modified Welford's
/// method). Correlation and slope are 1 and the intercept 0 until two points
/// are in; the "correlation" is r squared, as in ZAP.
#[derive(Debug, Clone)]
pub(super) struct Regression {
    count: f64,
    independent_sum: f64,
    dependent_sum: f64,
    independent_variance_n: f64,
    dependent_variance_n: f64,
    sample_covariance_n: f64,
    slope: f64,
    intercept: f64,
    correlation: f64,
}

impl Default for Regression {
    fn default() -> Self {
        Self {
            count: 0.0,
            independent_sum: 0.0,
            dependent_sum: 0.0,
            independent_variance_n: 0.0,
            dependent_variance_n: 0.0,
            sample_covariance_n: 0.0,
            slope: 1.0,
            intercept: 0.0,
            correlation: 1.0,
        }
    }
}

impl Regression {
    pub(super) fn add_point(&mut self, x: f64, y: f64) {
        // New values against the old means (NaN for the first point: 0/0).
        let independent_adjustment = x - self.independent_sum / self.count;
        let dependent_adjustment = y - self.dependent_sum / self.count;
        self.count += 1.0;
        self.independent_sum += x;
        self.dependent_sum += y;
        if independent_adjustment.is_nan() {
            return;
        }
        let independent_residual = x - self.independent_sum / self.count;
        let dependent_residual = y - self.dependent_sum / self.count;
        self.independent_variance_n += independent_residual * independent_adjustment;
        self.dependent_variance_n += dependent_residual * dependent_adjustment;
        self.sample_covariance_n += independent_residual * dependent_adjustment;

        self.slope = self.sample_covariance_n / self.independent_variance_n;
        self.correlation = self.slope * (self.independent_variance_n / self.dependent_variance_n).sqrt();
        self.correlation *= self.correlation;
        // As in ZAP (the formula is ZAP's, including its mix of means).
        self.intercept = self.independent_sum / self.count - (self.dependent_sum / self.count) * self.slope;
        // A flat line gives NaN; it is still a line.
        if self.correlation.is_nan() {
            self.correlation = 1.0;
        }
    }

    #[cfg(test)]
    pub(super) fn slope(&self) -> f64 {
        self.slope
    }

    #[cfg(test)]
    pub(super) fn correlation(&self) -> f64 {
        self.correlation
    }

    #[cfg(test)]
    pub(super) fn intercept(&self) -> f64 {
        self.intercept
    }

    pub(super) fn is_within_confidence(&self, correlation_error: f64, expected_slope: f64, slope_error: f64) -> bool {
        self.correlation > 1.0 - correlation_error && (expected_slope - self.slope).abs() < slope_error
    }
}

/// `TimingUtils.checkTimingDependence` as a state machine, so the caller can do
/// the (async) sending: ask `next_delay`, send a request asking for that delay,
/// `record` the observed delay, until `verdict` is set.
///
/// Delays alternate high/low (high, 1, high, 1, ...); the check gives up as soon
/// as an observed delay is below the requested one or the regression is clearly
/// off (correlation <= 0.7 or |slope - 1| >= 0.5). After `requests_limit`
/// requests (rounded up to a pair) the regression must be within the given
/// ranges.
#[derive(Debug, Clone)]
pub(super) struct TimingCheck {
    regression: Regression,
    requests_left: i64,
    high: f64,
    correlation_error: f64,
    slope_error: f64,
    low_next: bool,
    verdict: Option<bool>,
}

impl TimingCheck {
    pub(super) fn new(requests_limit: u32, high_sleep: u32, correlation_error: f64, slope_error: f64) -> Self {
        assert!(requests_limit >= MINIMUM_REQUESTS, "requires at least {MINIMUM_REQUESTS} requests to get results");
        Self {
            regression: Regression::default(),
            requests_left: requests_limit as i64,
            high: high_sleep as f64,
            correlation_error,
            slope_error,
            low_next: false,
            verdict: None,
        }
    }

    /// The delay (seconds) the next request should ask for, or None once decided.
    pub(super) fn next_delay(&self) -> Option<f64> {
        match self.verdict {
            Some(_) => None,
            None if self.low_next => Some(1.0),
            None => Some(self.high),
        }
    }

    /// Records the observed delay (seconds) of the request for `next_delay`.
    pub(super) fn record(&mut self, observed: f64) {
        let Some(delay) = self.next_delay() else { return };
        if observed < delay {
            self.verdict = Some(false);
            return;
        }
        self.regression.add_point(delay, observed);
        if !self.regression.is_within_confidence(0.3, 1.0, 0.5) {
            self.verdict = Some(false);
            return;
        }
        if self.low_next {
            self.requests_left -= 2;
            if self.requests_left <= 0 {
                self.verdict =
                    Some(self.regression.is_within_confidence(self.correlation_error, 1.0, self.slope_error));
            }
        }
        self.low_next = !self.low_next;
    }

    pub(super) fn verdict(&self) -> Option<bool> {
        self.verdict
    }

    #[cfg(test)]
    pub(super) fn regression(&self) -> &Regression {
        &self.regression
    }
}

/// Synchronous `checkTimingDependence` (for tests and pure use): `sender` gets the
/// requested delay and returns the observed one.
#[cfg(test)]
pub(super) fn check_timing_dependence(
    requests_limit: u32,
    high_sleep: u32,
    mut sender: impl FnMut(f64) -> f64,
    correlation_error: f64,
    slope_error: f64,
) -> bool {
    let mut check = TimingCheck::new(requests_limit, high_sleep, correlation_error, slope_error);
    while let Some(d) = check.next_delay() {
        check.record(sender(d));
    }
    check.verdict() == Some(true)
}

/// ZAP `TimeUnit.MILLISECONDS.toSeconds(msg.getTimeElapsedMillis())`: whole seconds.
pub(super) fn whole_seconds(d: Duration) -> f64 {
    (d.as_millis() / 1000) as f64
}

/// `msg.getTimeElapsedMillis() / 1000.0`.
pub(super) fn fractional_seconds(d: Duration) -> f64 {
    d.as_millis() as f64 / 1000.0
}

pub(super) struct Timed {
    /// The first request sent (asking for the high delay) and its value.
    pub first: Response,
    pub first_payload: String,
    /// The last request sent.
    pub last: Response,
}

pub(super) enum TimingOutcome {
    NotInjectable,
    Injectable(Box<Timed>),
    /// A request failed (ZAP's IOException): move on to the next payload.
    Failed,
}

/// Runs one timing check against the insertion point: `payload(delay)` is the
/// value for a request asking for `delay` seconds (escaped for its context, like
/// ZAP's `setParameter`); `seconds` converts the elapsed time.
pub(super) async fn check_timing(
    cx: &Cx,
    high_sleep: u32,
    payload: impl Fn(f64) -> String,
    seconds: fn(Duration) -> f64,
) -> TimingOutcome {
    let mut check =
        TimingCheck::new(BLIND_REQUESTS_LIMIT, high_sleep, TIME_CORRELATION_ERROR_RANGE, TIME_SLOPE_ERROR_RANGE);
    let mut first: Option<(Response, String)> = None;
    let mut last = None;
    while let Some(delay) = check.next_delay() {
        let value = payload(delay);
        let Ok(resp) = cx.send_payload(&value).await else { return TimingOutcome::Failed };
        check.record(seconds(resp.duration));
        if first.is_none() {
            first = Some((resp.clone(), value));
        }
        last = Some(resp);
    }
    match (check.verdict(), first, last) {
        (Some(true), Some((first, first_payload)), Some(last)) => {
            TimingOutcome::Injectable(Box::new(Timed { first, first_payload, last }))
        }
        _ => TimingOutcome::NotInjectable,
    }
}

const ORIG_VALUE_TOKEN: &str = "<<<<ORIGINALVALUE>>>>";
const SLEEP_TOKEN: &str = "<<<<SLEEP>>>>";

/// `assembleTimingPayload` of the SQL timing rules.
pub(super) fn assemble(template: &str, value: &str, sleep: &str) -> String {
    template.replace(ORIG_VALUE_TOKEN, value).replace(SLEEP_TOKEN, sleep)
}

/// `ascanrules.sqlinjection.alert.timebased.extrainfo` (the MsSQL variant has the same text).
pub(super) fn sql_timing_other_info(attack: &str, attack_ms: u128, value: &str, original_ms: u128) -> String {
    format!(
        "The query time is controllable using parameter value [{attack}], which caused the request to take [{}] \
         milliseconds, when the original unmodified query with value [{value}] took [{}] milliseconds.",
        grouped(attack_ms as i64),
        grouped(original_ms as i64)
    )
}

/// One RDBMS-specific time based SQL injection rule.
pub(super) struct SqlTiming {
    pub alert: &'static AlertDef,
    /// Templates with `<<<<ORIGINALVALUE>>>>` and `<<<<SLEEP>>>>` tokens.
    pub templates: &'static [&'static str],
    /// How many templates to try at LOW, MEDIUM, HIGH, INSANE.
    pub limits: [usize; 4],
    /// How a requested delay (seconds) is written in the payload.
    pub sleep_token: fn(f64) -> String,
    /// The reported attack: None for the first value sent, or the template with
    /// the configured sleep written by this function.
    pub attack_sleep: Option<fn(u32) -> String>,
}

/// The scan loop shared by ZAP's SqlInjection{MySql,MsSql,Hypersonic,PostgreSql,Oracle}TimingScanRule.
pub(super) async fn scan_sql_timing(cx: &Cx, spec: &SqlTiming) {
    let (param, value) = point(cx);
    let sleep = sleep_seconds();
    let max = by_strength(cx.strength(), spec.limits);
    for template in spec.templates.iter().take(max) {
        if cx.stopped() {
            return;
        }
        let outcome =
            check_timing(cx, sleep, |x| assemble(template, &value, &(spec.sleep_token)(x)), whole_seconds).await;
        if let TimingOutcome::Injectable(t) = outcome {
            let attack = match spec.attack_sleep {
                Some(f) => assemble(template, &value, &f(sleep)),
                None => t.first_payload.clone(),
            };
            let info = sql_timing_other_info(
                &attack,
                t.first.duration.as_millis(),
                &value,
                cx.base_response().duration.as_millis(),
            );
            let finding = spec.alert.raise(param, "").attack(attack).other_info(info);
            cx.report(finding, &t.first);
            return;
        }
    }
}

/// Strength limits of SqlInjection{PostgreSql,Oracle}TimingScanRule (the MySQL,
/// MsSQL and Hypersonic rules use 6, 10, 12 and all).
pub(super) const LIMITS_3_5_10_100: [usize; 4] = [3, 5, 10, 100];

#[cfg(test)]
mod tests {
    use super::*;

    const CORR: f64 = 0.1;
    const SLOPE: f64 = 0.2;

    fn close(a: f64, b: f64) -> bool {
        (a - b).abs() < 1e-8
    }

    fn regression(points: &[(f64, f64)]) -> Regression {
        let mut r = Regression::default();
        for &(x, y) in points {
            r.add_point(x, y);
        }
        r
    }

    #[test]
    fn regression_is_numerically_stable() {
        let r = regression(&[(1., 1.), (2., 2.), (3., 3.), (4., 4.), (5., 5.), (1., 1.), (2., 2.), (2., 2.), (2., 2.)]);
        assert!(close(r.slope(), 1.0) && close(r.correlation(), 1.0));
    }

    #[test]
    fn regression_exact_and_known() {
        let r = regression(&[(1., 1.), (2., 3.)]);
        assert!(close(r.slope(), 2.0) && close(r.correlation(), 1.0));
        // Values checked by ZAP against Excel.
        let r = regression(&[
            (1., 1.348520581),
            (2., 2.524046187),
            (3., 3.276944688),
            (4., 4.735374498),
            (5., 5.150291657),
        ]);
        assert!(close(r.slope(), 0.981487046), "{}", r.slope());
        assert!(close(r.correlation(), 0.979228906), "{}", r.correlation());
        let r = regression(&[(1., 2.), (2., 4.), (3., 8.), (4., 16.), (5., 32.)]);
        assert!(r.correlation() < 0.9);
        // Defaults before two points; a flat line counts as a line.
        let r = regression(&[(3., 3.)]);
        assert_eq!((r.slope(), r.correlation(), r.intercept()), (1.0, 1.0, 0.0));
        let r = regression(&[(1., 5.), (2., 5.)]);
        assert_eq!((r.slope(), r.correlation()), (0.0, 1.0));
    }

    #[test]
    fn alternates_high_and_low() {
        let mut asked = Vec::new();
        let ok = check_timing_dependence(
            4,
            15,
            |x| {
                asked.push(x);
                x
            },
            CORR,
            SLOPE,
        );
        assert!(ok);
        assert_eq!(asked, [15.0, 1.0, 15.0, 1.0]);
    }

    #[test]
    fn gives_up_quickly_when_not_injectable() {
        let mut n = 0;
        let ok = check_timing_dependence(
            4,
            15,
            |_| {
                n += 1;
                0.5
            },
            CORR,
            SLOPE,
        );
        assert!(!ok);
        assert_eq!(n, 1);
    }

    #[test]
    fn gives_up_quickly_when_slow_but_not_injectable() {
        let mut n = 0;
        let mut jitter = [0.1, 0.4, 0.2, 0.3].into_iter().cycle();
        let ok = check_timing_dependence(
            4,
            15,
            |_| {
                n += 1;
                10.0 + jitter.next().unwrap()
            },
            CORR,
            SLOPE,
        );
        assert!(!ok);
        assert!(n <= 3, "{n}");
    }

    #[test]
    fn detects_dependence_with_small_error() {
        let mut jitter = [0.31, 0.05, 0.47, 0.2].into_iter();
        assert!(check_timing_dependence(4, 15, |x| x + jitter.next().unwrap(), CORR, SLOPE));
    }

    #[test]
    fn rule_ranges_on_recorded_series() {
        // ZAP's own regression cases with the rules' ranges (0.15, 0.30).
        let mut uncorrelated = vec![15.377, 12.093, 16.588, 10.752].into_iter();
        assert!(!check_timing_dependence(4, 15, |_| uncorrelated.next().unwrap(), 0.15, 0.30));
        let mut correlated = vec![16.0, 2.0, 17.0, 3.0].into_iter();
        assert!(check_timing_dependence(4, 15, |_| correlated.next().unwrap(), 0.15, 0.30));
    }

    #[test]
    fn request_budget() {
        // An odd limit still finishes the last pair (ZAP: "1 more request than the limit").
        let mut n = 0;
        assert!(check_timing_dependence(
            3,
            5,
            |x| {
                n += 1;
                x
            },
            0.15,
            0.3
        ));
        assert_eq!(n, 4);
        let mut c = TimingCheck::new(2, 5, 0.15, 0.3);
        c.record(5.0);
        c.record(1.0);
        assert_eq!(c.verdict(), Some(true));
        assert_eq!(c.next_delay(), None);
        assert_eq!(c.regression().slope(), 1.0);
    }

    #[test]
    #[should_panic]
    fn requires_two_requests() {
        TimingCheck::new(1, 5, 0.15, 0.3);
    }

    #[test]
    fn seconds_conversions() {
        assert_eq!(whole_seconds(Duration::from_millis(5999)), 5.0);
        assert_eq!(fractional_seconds(Duration::from_millis(5250)), 5.25);
    }

    #[test]
    fn sql_timing_texts() {
        assert_eq!(assemble("<<<<ORIGINALVALUE>>>>' / sleep(<<<<SLEEP>>>>) / '", "test", "5"), "test' / sleep(5) / '");
        assert_eq!(
            sql_timing_other_info("x", 5012, "test", 100),
            "The query time is controllable using parameter value [x], which caused the request to take [5,012] \
             milliseconds, when the original unmodified query with value [test] took [100] milliseconds."
        );
    }
}
