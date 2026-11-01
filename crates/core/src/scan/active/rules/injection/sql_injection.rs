//! Ported from ZAP SqlInjectionScanRule (ascanrules, Apache License 2.0), with the
//! response comparison of commonlib ComparableResponse that it uses.
//!
//! Behaviour is ZAP's at the default MEDIUM alert threshold: RDBMS-specific
//! error based checks on, generic error messages off. The checks run in ZAP's
//! order (error, expression, boolean, boolean "no data", UNION, ORDER BY) with
//! the attack strength's request budgets, and stop at the first finding for the
//! parameter. Not ported: the "SQL Injection - Authentication Bypass" alert,
//! which needs ZAP's authentication contexts to know the login URL.

use std::sync::{LazyLock, OnceLock};

use regex::Regex;

use super::common::{java_len, java_regex, point, strip_off, strip_off_both, SQL_DESC, SQL_REFS, SQL_SOLN};
use crate::scan::active::{ActiveRule, BoxFuture, Cx, Response, RuleScope, Strength};
use crate::scan::{AlertDef, Confidence, Risk};

const TAGS: &[&str] =
    &["OWASP_2025_A05", "OWASP_2021_A03", "OWASP_2017_A01", "WSTG-v42-INPV-05", "API_2023_API10", "HIPAA", "PCI_DSS"];

macro_rules! sqli_alert {
    ($name:expr) => {
        AlertDef {
            alert_ref: "40018",
            name: $name,
            risk: Risk::High,
            confidence: Confidence::Medium,
            cwe: 89,
            wasc: 19,
            description: SQL_DESC,
            solution: SQL_SOLN,
            references: SQL_REFS,
            tags: TAGS,
        }
    };
}

static ALERT: AlertDef = sqli_alert!("SQL Injection");
static ALERTS: [&AlertDef; 1] = [&ALERT];

/// ZAP names error and UNION based alerts after the RDBMS ("SQL Injection - MySQL")
/// under the same alert ref; these definitions carry those names.
static A_MYSQL: AlertDef = sqli_alert!("SQL Injection - MySQL");
static A_MSSQL: AlertDef = sqli_alert!("SQL Injection - Microsoft SQL Server");
static A_ORACLE: AlertDef = sqli_alert!("SQL Injection - Oracle");
static A_DB2: AlertDef = sqli_alert!("SQL Injection - IBM DB2");
static A_POSTGRESQL: AlertDef = sqli_alert!("SQL Injection - PostgreSQL");
static A_SYBASE: AlertDef = sqli_alert!("SQL Injection - Sybase");
static A_INFORMIX: AlertDef = sqli_alert!("SQL Injection - Informix");
static A_FIREBIRD: AlertDef = sqli_alert!("SQL Injection - Firebird");
static A_IDSSERVER: AlertDef = sqli_alert!("SQL Injection - IDS Server");
static A_INSTANTDB: AlertDef = sqli_alert!("SQL Injection - InstantDB");
static A_INTERBASE: AlertDef = sqli_alert!("SQL Injection - Interbase");
static A_HYPERSONIC: AlertDef = sqli_alert!("SQL Injection - Hypersonic SQL");
static A_SYBASE_ANY: AlertDef = sqli_alert!("SQL Injection - Sybase SQL Anywhere");
static A_POINTBASE: AlertDef = sqli_alert!("SQL Injection - Pointbase");
static A_CLOUDSCAPE: AlertDef = sqli_alert!("SQL Injection - Cloudscape");
static A_INGRES: AlertDef = sqli_alert!("SQL Injection - Ingres");
static A_SQLITE: AlertDef = sqli_alert!("SQL Injection - SQLite");

/// One RDBMS with its (driver level) error message patterns, as Java regex
/// sources (shown in the alert), most common first.
struct Rdbms {
    name: &'static str,
    alert: &'static AlertDef,
    errors: &'static [&'static str],
    union_errors: &'static [&'static str],
}

/// ZAP's RDBMS enum without GENERIC, whose patterns are only used by the generic
/// error check that the MEDIUM threshold turns off.
static RDBMS: [Rdbms; 17] = [
    Rdbms {
        name: "MySQL",
        alert: &A_MYSQL,
        errors: &[
            r"\QYou have an error in your SQL syntax\E",
            r"\Qcom.mysql.jdbc.exceptions\E",
            r"\Qorg.gjt.mm.mysql\E",
            r"\QODBC driver does not support\E",
            r"\QThe used SELECT statements have a different number of columns\E",
        ],
        union_errors: &[
            r"\QYou have an error in your SQL syntax\E",
            r"\QThe used SELECT statements have a different number of columns\E",
        ],
    },
    Rdbms {
        name: "Microsoft SQL Server",
        alert: &A_MSSQL,
        errors: &[
            r"\Qcom.microsoft.sqlserver.jdbc\E",
            r"\Qcom.microsoft.jdbc\E",
            r"\Qcom.inet.tds\E",
            r"\Qcom.ashna.jturbo\E",
            r"\Qweblogic.jdbc.mssqlserver\E",
            r"\Q[Microsoft]\E",
            r"\Q[SQLServer]\E",
            r"\Q[SQLServer 2000 Driver for JDBC]\E",
            r"\Qnet.sourceforge.jtds.jdbc\E",
            r"\Q80040e14\E",
            r"\Q800a0bcd\E",
            r"\Q80040e57\E",
            r"\QODBC driver does not support\E",
            r"\QAll queries in an SQL statement containing a UNION operator must have an equal number of expressions in their target lists\E",
            r"\QAll queries combined using a UNION, INTERSECT or EXCEPT operator must have an equal number of expressions in their target lists\E",
        ],
        union_errors: &[
            r"\QAll queries in an SQL statement containing a UNION operator must have an equal number of expressions in their target lists\E",
            r"\QAll queries combined using a UNION, INTERSECT or EXCEPT operator must have an equal number of expressions in their target lists\E",
        ],
    },
    Rdbms {
        name: "Oracle",
        alert: &A_ORACLE,
        errors: &[
            r"\Qoracle.jdbc\E",
            r"\QSQLSTATE[HY\E",
            r"\QORA-00933\E",
            r"\QORA-06512\E",
            r"\QSQL command not properly ended\E",
            r"\QORA-00942\E",
            r"\QORA-29257\E",
            r"\QORA-00932\E",
            r"\Qquery block has incorrect number of result columns\E",
            r"\QORA-01789\E",
        ],
        union_errors: &[r"\Qquery block has incorrect number of result columns\E", r"\QORA-01789\E"],
    },
    Rdbms {
        name: "IBM DB2",
        alert: &A_DB2,
        errors: &[r"\Qcom.ibm.db2.jcc\E", r"\QCOM.ibm.db2.jdbc\E"],
        union_errors: &[],
    },
    Rdbms {
        name: "PostgreSQL",
        alert: &A_POSTGRESQL,
        errors: &[
            r"\Qorg.postgresql.util.PSQLException\E",
            r"\Qorg.postgresql\E",
            r"\Qeach UNION query must have the same number of columns\E",
            r"\Qunterminated quoted string at or near\E",
            r"\Qsyntax error at or near\E",
        ],
        union_errors: &[r"\Qeach UNION query must have the same number of columns\E"],
    },
    Rdbms {
        name: "Sybase",
        alert: &A_SYBASE,
        errors: &[r"\Qcom.sybase.jdbc\E", r"\Qnet.sourceforge.jtds.jdbc\E"],
        union_errors: &[],
    },
    Rdbms { name: "Informix", alert: &A_INFORMIX, errors: &[r"\Qcom.informix.jdbc\E"], union_errors: &[] },
    Rdbms { name: "Firebird", alert: &A_FIREBIRD, errors: &[r"\Qorg.firebirdsql.jdbc\E"], union_errors: &[] },
    Rdbms { name: "IDS Server", alert: &A_IDSSERVER, errors: &[r"\Qids.sql\E"], union_errors: &[] },
    Rdbms {
        name: "InstantDB",
        alert: &A_INSTANTDB,
        errors: &[r"\Qorg.enhydra.instantdb.jdbc\E", r"\Qjdbc.idb\E"],
        union_errors: &[],
    },
    Rdbms { name: "Interbase", alert: &A_INTERBASE, errors: &[r"\Qinterbase.interclient\E"], union_errors: &[] },
    Rdbms {
        name: "Hypersonic SQL",
        alert: &A_HYPERSONIC,
        errors: &[
            r"\Qorg.hsql\E",
            r"\QhSql.\E",
            r"\QUnexpected token , requires FROM in statement\E",
            r"\QUnexpected end of command in statement\E",
            r"\QColumn count does not match in statement\E",
            r"\QTable not found in statement\E",
            r"\QUnexpected token:\E",
        ],
        union_errors: &[r"\QUnexpected end of command in statement\E", r"\QColumn count does not match in statement\E"],
    },
    Rdbms {
        name: "Sybase SQL Anywhere",
        alert: &A_SYBASE_ANY,
        errors: &[r"\Qsybase.jdbc.sqlanywhere\E"],
        union_errors: &[],
    },
    Rdbms { name: "Pointbase", alert: &A_POINTBASE, errors: &[r"\Qcom.pointbase.jdbc\E"], union_errors: &[] },
    Rdbms {
        name: "Cloudscape",
        alert: &A_CLOUDSCAPE,
        errors: &[r"\Qdb2j.\E", r"\QCOM.cloudscape\E", r"\QRmiJdbc.RJDriver\E"],
        union_errors: &[],
    },
    Rdbms { name: "Ingres", alert: &A_INGRES, errors: &[r"\Qcom.ingres.jdbc\E"], union_errors: &[] },
    Rdbms {
        name: "SQLite",
        alert: &A_SQLITE,
        errors: &[
            r#"near ".+": syntax error"#,
            r"SQLITE_ERROR",
            r"\QSELECTs to the left and right of UNION do not have the same number of result columns\E",
        ],
        union_errors: &[r"\QSELECTs to the left and right of UNION do not have the same number of result columns\E"],
    },
];

/// The patterns compiled once, case-insensitive and multi-line (ZAP's PATTERN_PARAM).
struct Compiled {
    errors: Vec<Regex>,
    union_errors: Vec<Regex>,
}

static COMPILED: LazyLock<Vec<Compiled>> = LazyLock::new(|| {
    let compile = |src: &&str| Regex::new(&format!("(?im){}", java_regex(src))).expect("RDBMS pattern");
    RDBMS
        .iter()
        .map(|r| Compiled {
            errors: r.errors.iter().map(compile).collect(),
            union_errors: r.union_errors.iter().map(compile).collect(),
        })
        .collect()
});

const SQL_ONE_LINE_COMMENT: &str = " -- ";

/// Metacharacters to cause SQL errors, one family per request.
const SQL_CHECK_ERR: [&str; 8] = ["'", "\"", ";", "'(", ")", "(", "NULL", "'\""];

/// Always true conditions, commented versions first; the last three are for LIKE.
const SQL_LOGIC_AND_TRUE: [&str; 9] = [
    " AND 1=1 -- ",
    "' AND '1'='1' -- ",
    "\" AND \"1\"=\"1\" -- ",
    " AND 1=1",
    "' AND '1'='1",
    "\" AND \"1\"=\"1",
    "%",
    "%'  -- ",
    "%\"  -- ",
];

const SQL_LOGIC_AND_FALSE: [&str; 9] = [
    " AND 1=2 -- ",
    "' AND '1'='2' -- ",
    "\" AND \"1\"=\"2\" -- ",
    " AND 1=2",
    "' AND '1'='2",
    "\" AND \"1\"=\"2",
    "XYZABCDEFGHIJ",
    "XYZABCDEFGHIJ'  -- ",
    "XYZABCDEFGHIJ\"  -- ",
];

const SQL_LOGIC_OR_TRUE: [&str; 9] = [
    " OR 1=1 -- ",
    "' OR '1'='1' -- ",
    "\" OR \"1\"=\"1\" -- ",
    " OR 1=1",
    "' OR '1'='1",
    "\" OR \"1\"=\"1",
    "%",
    "%'  -- ",
    "%\"  -- ",
];

/// UNION statements hoping for a recognisable column count error.
const SQL_UNION_APPENDAGES: [&str; 6] = [
    " UNION ALL select NULL -- ",
    "' UNION ALL select NULL -- ",
    "\" UNION ALL select NULL -- ",
    ") UNION ALL select NULL -- ",
    "') UNION ALL select NULL -- ",
    "\") UNION ALL select NULL -- ",
];

/// Request budgets per check; `None` turns a check off.
#[derive(Debug, Clone, Copy, PartialEq)]
struct Limits {
    error: usize,
    expression: usize,
    boolean: Option<usize>,
    union: Option<usize>,
    order_by: Option<usize>,
}

fn limits(s: Strength) -> Limits {
    match s {
        Strength::Low => Limits { error: 4, expression: 4, boolean: None, union: None, order_by: None },
        // Boolean: will not run all the LIKE attacks (done at HIGH).
        Strength::Medium => Limits { error: 8, expression: 8, boolean: Some(6), union: Some(5), order_by: None },
        Strength::High => Limits { error: 16, expression: 16, boolean: Some(20), union: Some(10), order_by: Some(5) },
        Strength::Insane => {
            Limits { error: 100, expression: 100, boolean: Some(100), union: Some(100), order_by: Some(100) }
        }
    }
}

// Alert texts (`ascanrules.sqlinjection.alert.*`), formatted as MessageFormat would.

fn error_based_info(rdbms: &str, pattern: &str) -> String {
    format!(
        "RDBMS [{rdbms}] likely, given error message regular expression [{pattern}] matched by the HTML results.\n\
         The vulnerability was detected by manipulating the parameter to cause a database error message to be \
         returned and recognised."
    )
}

fn union_based_info(rdbms: &str, pattern: &str) -> String {
    // MessageFormat drops the single quotes ZAP's text has around UNION.
    format!(
        "RDBMS [{rdbms}] likely, given UNION-specific error message regular expression [{pattern}] matched by the \
         HTML results\nThe vulnerability was detected by manipulating the parameter with an SQL UNION clause to cause \
         a database error message to be returned and recognised."
    )
}

fn boolean_based_info(a: &str, b: &str, not: &str) -> String {
    format!(
        "The page results were successfully manipulated using the boolean conditions [{a}] and [{b}]\n\
         The parameter value being modified was {not}stripped from the HTML output for the purposes of the comparison."
    )
}

const DATA_EXISTS: &str = "Data was returned for the original parameter.\n\
    The vulnerability was detected by successfully restricting the data originally returned, by manipulating the \
    parameter.";
const DATA_NOT_EXISTS: &str = "Data was NOT returned for the original parameter.\n\
    The vulnerability was detected by successfully retrieving more data than originally returned, by manipulating \
    the parameter.";

fn expression_based_info(value: &str, not: &str) -> String {
    format!(
        "The original page results were successfully replicated using the expression [{value}] as the parameter \
         value\nThe parameter value being modified was {not}stripped from the HTML output for the purposes of the \
         comparison."
    )
}

fn order_by_based_info(value: &str, not: &str) -> String {
    format!(
        "The original page results were successfully replicated using the \"ORDER BY\" expression [{value}] as the \
         parameter value\nThe parameter value being modified was {not}stripped from the HTML output for the purposes \
         of the comparison."
    )
}

/// The parts of commonlib's ComparableResponse that this rule compares.
struct Comparable<'a> {
    status: u16,
    body: &'a str,
    location: Option<&'a str>,
    value_sent: &'a str,
}

impl<'a> Comparable<'a> {
    fn new(resp: &'a Response, value_sent: &'a str) -> Self {
        // A case-insensitive map: the last Location header wins.
        let location =
            resp.headers.iter().rev().find(|(k, _)| k.eq_ignore_ascii_case("location")).map(|(_, v)| v.as_str());
        Self { status: resp.status, body: resp.body_str(), location, value_sent }
    }
}

const HEURISTIC_WEIGHT: f32 = 0.99;

/// 1 for "the same" (equal bodies once both sent values are stripped, and equal
/// Location headers on redirects of the same status), less otherwise.
fn compare_responses(one: &Comparable, two: &Comparable) -> f32 {
    let mut total = 1f32;
    total *= location_header_heuristic(one, two) * HEURISTIC_WEIGHT + (1.0 - HEURISTIC_WEIGHT);
    total *= response_body_heuristic(one, two) * HEURISTIC_WEIGHT + (1.0 - HEURISTIC_WEIGHT);
    total
}

fn response_body_heuristic(one: &Comparable, two: &Comparable) -> f32 {
    let stripped1 = strip_off_both(one.body, one.value_sent, two.value_sent);
    let stripped2 = strip_off_both(two.body, one.value_sent, two.value_sent);
    if stripped1 == stripped2 {
        1.0
    } else {
        0.0
    }
}

fn location_header_heuristic(one: &Comparable, two: &Comparable) -> f32 {
    if one.status == two.status && (300..400).contains(&one.status) && one.location != two.location {
        return 0.0;
    }
    1.0
}

pub struct SqlInjection;

impl ActiveRule for SqlInjection {
    fn id(&self) -> u32 {
        40018
    }

    fn name(&self) -> &'static str {
        "SQL Injection"
    }

    fn alerts(&self) -> &'static [&'static AlertDef] {
        &ALERTS
    }

    fn scope(&self) -> RuleScope {
        RuleScope::Param
    }

    fn scan<'a>(&'a self, cx: &'a Cx) -> BoxFuture<'a> {
        Box::pin(async move {
            let (param, orig) = point(cx);
            let mut s = Scan {
                cx,
                param,
                orig,
                lim: limits(cx.strength()),
                found: false,
                refreshed: None,
                base_hits: OnceLock::new(),
                n_error: 0,
                n_expression: 0,
                n_boolean: 0,
                n_order_by: 0,
            };
            for step in 0..6 {
                if cx.stopped() || s.found {
                    break;
                }
                match step {
                    0 => s.error_based().await,
                    1 => s.expression_based().await,
                    2 => s.boolean_based().await,
                    3 => s.boolean_based_no_data().await,
                    4 => s.union_based().await,
                    _ => s.order_by_based().await,
                }
            }
        })
    }
}

/// State of one parameter's scan (ZAP's per-parameter fields).
struct Scan<'a> {
    cx: &'a Cx,
    param: String,
    orig: String,
    lim: Limits,
    found: bool,
    /// The original request re-sent before the comparison checks.
    refreshed: Option<Response>,
    /// Per RDBMS, which error patterns match the original response.
    base_hits: OnceLock<Vec<Vec<bool>>>,
    n_error: usize,
    n_expression: usize,
    n_boolean: usize,
    n_order_by: usize,
}

impl Scan<'_> {
    async fn send(&self, value: &str) -> Option<Response> {
        self.cx.send_payload(value).await.ok()
    }

    /// Re-sends the original request: earlier attacks may have changed the data.
    async fn refresh(&mut self) -> bool {
        self.refreshed = self.cx.send(self.cx.base_request().to_vec()).await.ok();
        self.refreshed.is_some()
    }

    fn base_hits(&self) -> &Vec<Vec<bool>> {
        self.base_hits.get_or_init(|| {
            let body = self.cx.base_response().body_str();
            COMPILED.iter().map(|c| c.errors.iter().map(|p| p.is_match(body)).collect()).collect()
        })
    }

    fn report(&mut self, def: &'static AlertDef, evidence: &str, attack: &str, info: String, resp: &Response) {
        let finding = def.raise(self.param.clone(), evidence).attack(attack).other_info(info);
        self.cx.report(finding, resp);
        self.found = true;
    }

    /// Check 1: database error messages.
    async fn error_based(&mut self) {
        let base_status = self.cx.base_response().status;
        let orig = self.orig.clone();
        for err in SQL_CHECK_ERR {
            if self.found || self.n_error >= self.lim.error {
                break;
            }
            // Both with and without the original value in front (ZAP sends both even
            // when the original value is empty).
            for prefix in ["", orig.as_str()] {
                if self.found {
                    break;
                }
                if self.cx.stopped() {
                    return;
                }
                let value = format!("{prefix}{err}");
                let Some(resp) = self.send(&value).await else { continue };
                self.n_error += 1;

                if resp.status == 500 && base_status != 500 {
                    // Make sure the service doesn't answer 500 for any invalid value.
                    let safe = self.send("S4feV4lu3").await;
                    if safe.is_some_and(|s| s.status != 500) {
                        let finding = ALERT
                            .raise(self.param.clone(), resp.status_line.clone())
                            .attack(value.clone())
                            .confidence(Confidence::Low);
                        self.cx.report(finding, &resp);
                        self.found = true;
                        continue;
                    }
                }

                for i in 0..RDBMS.len() {
                    if self.cx.stopped() {
                        return;
                    }
                    if self.check_specific_errors(i, &resp, &value) {
                        break;
                    }
                }
            }
        }
    }

    /// An error message of RDBMS `i` in the attack response that the original lacked.
    fn check_specific_errors(&mut self, i: usize, resp: &Response, attack: &str) -> bool {
        let body = resp.body_str();
        for (j, pattern) in COMPILED[i].errors.iter().enumerate() {
            if self.base_hits()[i][j] {
                continue;
            }
            if let Some(m) = pattern.find(body) {
                let rdbms = &RDBMS[i];
                self.report(rdbms.alert, m.as_str(), attack, error_based_info(rdbms.name, rdbms.errors[j]), resp);
                return true;
            }
        }
        false
    }

    /// Check 4: an integer value replaced by an expression with the same value
    /// gives the same page, and one with another value doesn't.
    async fn expression_based(&mut self) {
        if !self.refresh().await {
            return;
        }
        if self.found || self.n_expression >= self.lim.expression {
            return;
        }
        let Ok(n) = self.orig.parse::<i32>() else { return };
        // Like Math.addExact/multiplyExact: an overflow ends the check.
        let (Some(plus2), Some(plus3)) = (n.checked_add(2), n.checked_add(3)) else { return };
        self.expression_attack(&format!("{plus2}-2"), &format!("{plus3}-2")).await;
        if self.cx.stopped() {
            return;
        }
        if !self.found && self.n_expression < self.lim.expression {
            let (Some(mul2), Some(mul4)) = (n.checked_mul(2), n.checked_mul(4)) else { return };
            self.expression_attack(&format!("{mul2}/2"), &format!("{mul4}/2")).await;
        }
    }

    async fn expression_attack(&mut self, value: &str, confirm: &str) {
        let Some(resp) = self.send(value).await else { return };
        self.n_expression += 1;
        if self.found || self.n_expression >= self.lim.expression {
            return;
        }
        let Some(refreshed) = self.refreshed.clone() else { return };
        let normal = Comparable::new(&refreshed, &self.orig);
        if compare_responses(&normal, &Comparable::new(&resp, value)) == 1.0 {
            let Some(confirm_resp) = self.send(confirm).await else { return };
            self.n_expression += 1;
            if compare_responses(&normal, &Comparable::new(&confirm_resp, confirm)) < 1.0 {
                self.report(&ALERT, "", value, expression_based_info(value, ""), &resp);
            }
        }
    }

    /// Check 2: "AND true" keeps the original page and "AND false" changes it, or,
    /// when "AND false" keeps it too (no data originally), "OR true" changes it.
    async fn boolean_based(&mut self) {
        if !self.refresh().await {
            return;
        }
        let Some(max) = self.lim.boolean else { return };
        let Some(refreshed) = self.refreshed.clone() else { return };
        let orig = self.orig.clone();
        let normal = Comparable::new(&refreshed, &orig);
        for i in 0..SQL_LOGIC_AND_TRUE.len() {
            if self.found || self.n_boolean >= max {
                break;
            }
            if self.cx.stopped() {
                return;
            }
            let and_true = format!("{orig}{}", SQL_LOGIC_AND_TRUE[i]);
            let and_false = format!("{orig}{}", SQL_LOGIC_AND_FALSE[i]);
            let Some(resp) = self.send(&and_true).await else { continue };
            self.n_boolean += 1;
            if self.cx.stopped() {
                return;
            }
            if compare_responses(&normal, &Comparable::new(&resp, &and_true)) != 1.0 {
                continue;
            }
            let Some(false_resp) = self.send(&and_false).await else { continue };
            self.n_boolean += 1;
            if compare_responses(&normal, &Comparable::new(&false_resp, &and_false)) < 1.0 {
                let info = format!("{}\n{DATA_EXISTS}", boolean_based_info(&and_true, &and_false, ""));
                self.report(&ALERT, "", &and_true, info, &resp);
                break;
            }
            let or_true = format!("{orig}{}", SQL_LOGIC_OR_TRUE[i]);
            let Some(or_resp) = self.send(&or_true).await else { continue };
            self.n_boolean += 1;
            if compare_responses(&normal, &Comparable::new(&or_resp, &or_true)) < 1.0 {
                // As ZAP: the evidence message is the "AND true" one.
                let info = format!("{}\n{DATA_NOT_EXISTS}", boolean_based_info(&and_true, &or_true, ""));
                self.report(&ALERT, "", &or_true, info, &resp);
                break;
            }
        }
    }

    /// Check 2a: the original returned no data; "OR true" returns clearly more (by
    /// size) and "AND false" brings back the original page.
    async fn boolean_based_no_data(&mut self) {
        let Some(max) = self.lim.boolean else { return };
        let Some(refreshed) = self.refreshed.clone() else { return };
        let orig = self.orig.clone();
        let normal_unstripped = refreshed.body_str();
        let normal_stripped = strip_off(normal_unstripped, &orig);
        for i in 0..SQL_LOGIC_OR_TRUE.len() {
            if self.found || self.n_boolean >= max {
                break;
            }
            if self.cx.stopped() {
                return;
            }
            let or_true = format!("{orig}{}", SQL_LOGIC_OR_TRUE[i]);
            let and_false = format!("{orig}{}", SQL_LOGIC_AND_FALSE[i]);
            let Some(resp) = self.send(&or_true).await else { continue };
            self.n_boolean += 1;
            // Unlike ZAP, without the values sent: a small page that echoes its input or
            // path would otherwise look like it returned more data.
            let or_stripped = strip_off_both(resp.body_str(), &orig, &or_true);
            if (java_len(&or_stripped) as f64) <= java_len(&normal_stripped) as f64 * 1.2 {
                continue;
            }
            let Some(false_resp) = self.send(&and_false).await else { continue };
            self.n_boolean += 1;
            let false_unstripped = false_resp.body_str();
            let false_stripped = strip_off_both(false_unstripped, &orig, &and_false);
            let by_unstripped = false_unstripped == normal_unstripped;
            let by_stripped = false_stripped == normal_stripped;
            if by_unstripped || by_stripped {
                let not = if by_stripped { "" } else { "NOT " };
                let info = format!("{}\n{DATA_NOT_EXISTS}", boolean_based_info(&or_true, &and_false, not));
                self.report(&ALERT, "", &or_true, info, &resp);
                break;
            }
        }
    }

    /// Check 3: UNION-specific error messages.
    async fn union_based(&mut self) {
        let Some(max) = self.lim.union else { return };
        let Some(refreshed) = self.refreshed.clone() else { return };
        let orig = self.orig.clone();
        let normal_stripped = strip_off(refreshed.body_str(), &orig);
        for (i, appendage) in SQL_UNION_APPENDAGES.iter().enumerate() {
            if self.found || i >= max {
                break;
            }
            if self.cx.stopped() {
                return;
            }
            let value = format!("{orig}{appendage}");
            let Some(resp) = self.send(&value).await else { continue };
            let union_stripped = strip_off_both(resp.body_str(), &orig, &value);
            for r in 0..RDBMS.len() {
                if self.cx.stopped() {
                    return;
                }
                if self.check_union_errors(r, &resp, &normal_stripped, &union_stripped, &value) {
                    break;
                }
            }
        }
    }

    fn check_union_errors(&mut self, r: usize, resp: &Response, normal: &str, union: &str, attack: &str) -> bool {
        for (j, pattern) in COMPILED[r].union_errors.iter().enumerate() {
            if pattern.is_match(normal) {
                continue;
            }
            if let Some(m) = pattern.find(union) {
                let rdbms = &RDBMS[r];
                let info = union_based_info(rdbms.name, rdbms.union_errors[j]);
                self.report(rdbms.alert, m.as_str(), attack, info, resp);
                return true;
            }
        }
        false
    }

    /// A column in an ORDER BY clause: " ASC -- " keeps the page, " DESC -- " changes it.
    async fn order_by_based(&mut self) {
        if !self.refresh().await {
            return;
        }
        let Some(max) = self.lim.order_by else { return };
        if self.found || self.n_order_by >= max {
            return;
        }
        let Some(refreshed) = self.refreshed.clone() else { return };
        let orig = self.orig.clone();
        let normal = [refreshed.body_str().to_string(), strip_off(refreshed.body_str(), &orig)];
        let value = format!("{orig} ASC {SQL_ONE_LINE_COMMENT}");
        let Some(resp) = self.send(&value).await else { return };
        self.n_order_by += 1;
        let ascending = [resp.body_str().to_string(), strip_off_both(resp.body_str(), &orig, &value)];
        for idx in 0..2 {
            if self.cx.stopped() {
                return;
            }
            if ascending[idx] != normal[idx] {
                continue;
            }
            let confirm = format!("{orig} DESC {SQL_ONE_LINE_COMMENT}");
            let Some(confirm_resp) = self.send(&confirm).await else { continue };
            self.n_order_by += 1;
            let confirm_body = match idx {
                0 => confirm_resp.body_str().to_string(),
                _ => strip_off_both(confirm_resp.body_str(), &orig, &confirm),
            };
            if confirm_body != normal[idx] {
                let not = if idx == 1 { "" } else { "NOT " };
                self.report(&ALERT, "", &value, order_by_based_info(&value, not), &resp);
                break;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn resp(status: u16, headers: &[(&str, &str)], body: &str) -> Response {
        let mut raw = format!("HTTP/1.1 {status} X\r\n");
        for (k, v) in headers {
            raw.push_str(&format!("{k}: {v}\r\n"));
        }
        raw.push_str(&format!("Content-Length: {}\r\n\r\n{body}", body.len()));
        Response::parse(Vec::new(), raw.into_bytes(), std::time::Duration::ZERO).unwrap()
    }

    #[test]
    fn rdbms_patterns_compile_and_match() {
        assert_eq!(COMPILED.len(), RDBMS.len());
        let find = |body: &str| -> Option<(&str, &str)> {
            for (i, c) in COMPILED.iter().enumerate() {
                for (j, p) in c.errors.iter().enumerate() {
                    if p.is_match(body) {
                        return Some((RDBMS[i].name, RDBMS[i].errors[j]));
                    }
                }
            }
            None
        };
        assert_eq!(
            find("Warning: you have an ERROR in your SQL syntax; check the manual"),
            Some(("MySQL", r"\QYou have an error in your SQL syntax\E"))
        );
        assert_eq!(find("ORA-00933: SQL command not properly ended").map(|f| f.0), Some("Oracle"));
        assert_eq!(find("[Microsoft][ODBC SQL Server Driver]").map(|f| f.0), Some("Microsoft SQL Server"));
        assert_eq!(find("SQLSTATE[HY000]").map(|f| f.0), Some("Oracle"));
        assert_eq!(find("Error: near \"'\": syntax error").map(|f| f.0), Some("SQLite"));
        assert_eq!(find("ERROR: syntax error at or near \"'\"").map(|f| f.0), Some("PostgreSQL"));
        // Literal dots and brackets are not regex syntax.
        assert_eq!(find("hSqlX"), None);
        assert_eq!(find("SQLServer"), None);
        assert_eq!(find("all good"), None);
        assert!(COMPILED[0].union_errors[1].is_match("The used SELECT statements have a different number of columns"));
    }

    #[test]
    fn payload_lists() {
        assert_eq!(SQL_LOGIC_AND_TRUE[7], "%'  -- ");
        assert_eq!(SQL_LOGIC_AND_FALSE[8], "XYZABCDEFGHIJ\"  -- ");
        assert_eq!(SQL_UNION_APPENDAGES[4], "') UNION ALL select NULL -- ");
        assert_eq!(format!("1 ASC {SQL_ONE_LINE_COMMENT}"), "1 ASC  -- ");
        assert_eq!(
            limits(Strength::Medium),
            Limits { error: 8, expression: 8, boolean: Some(6), union: Some(5), order_by: None }
        );
        assert_eq!(limits(Strength::Low).boolean, None);
        assert_eq!(limits(Strength::High).order_by, Some(5));
    }

    #[test]
    fn comparison() {
        // The weights give exactly 1 for equal responses.
        let a = resp(200, &[], "Results for 1: apple, pear");
        let b = resp(200, &[], "Results for 1 AND 1=1 -- : apple, pear");
        let c = resp(200, &[], "Results for 1 AND 1=2 -- : none");
        let normal = Comparable::new(&a, "1");
        assert_eq!(compare_responses(&normal, &Comparable::new(&b, "1 AND 1=1 -- ")), 1.0);
        assert!(compare_responses(&normal, &Comparable::new(&c, "1 AND 1=2 -- ")) < 1.0);
        // Redirects to different places differ even with equal bodies.
        let r1 = resp(302, &[("Location", "/a")], "");
        let r2 = resp(302, &[("location", "/b")], "");
        let r3 = resp(302, &[("Location", "/x"), ("Location", "/a")], "");
        assert!(compare_responses(&Comparable::new(&r1, "1"), &Comparable::new(&r2, "2")) < 1.0);
        assert_eq!(compare_responses(&Comparable::new(&r1, "1"), &Comparable::new(&r3, "2")), 1.0);
        assert_eq!(location_header_heuristic(&Comparable::new(&a, ""), &Comparable::new(&r1, "")), 1.0);
    }

    #[test]
    fn texts() {
        assert_eq!(
            union_based_info("MySQL", "p"),
            "RDBMS [MySQL] likely, given UNION-specific error message regular expression [p] matched by the HTML \
             results\nThe vulnerability was detected by manipulating the parameter with an SQL UNION clause to cause \
             a database error message to be returned and recognised."
        );
        assert_eq!(
            boolean_based_info("a", "b", "NOT "),
            "The page results were successfully manipulated using the boolean conditions [a] and [b]\nThe parameter \
             value being modified was NOT stripped from the HTML output for the purposes of the comparison."
        );
        assert!(expression_based_info("3-2", "").starts_with("The original page results were successfully replicated using the expression [3-2] as the parameter value\nThe parameter value being modified was stripped"));
        assert!(order_by_based_info("1 ASC  -- ", "").contains("the \"ORDER BY\" expression [1 ASC  -- ]"));
        assert!(
            error_based_info("Oracle", "x").ends_with("cause a database error message to be returned and recognised.")
        );
        assert!(DATA_EXISTS.starts_with("Data was returned for the original parameter.\nThe vulnerability"));
        assert_eq!(A_SQLITE.name, "SQL Injection - SQLite");
        assert_eq!(A_SQLITE.alert_ref, ALERT.alert_ref);
    }
}
