//! HQL/JPQL injection: user input concatenated into a Hibernate, EclipseLink or OpenJPA
//! query. brainproxy's own rule, not a ZAP port. ZAP's SQL injection rule (40018) finds
//! some of these through its boolean checks, but names them after an RDBMS at best.
//!
//! Two checks per parameter, both needing the query error to reach the page:
//! - Unknown path: the value is closed and followed by a comparison on a random dotted
//!   path (`x' and bp9d8e.bp1a2b=1 and '1'='1`). Only an ORM query parser answers
//!   "could not resolve property: bp9d8e of: com.app.User"; an SQL database names a
//!   table or column instead. The names are random, so the page can't have had them
//!   before, and an echo of the input doesn't match: the ORM's phrasing must be around
//!   them. High confidence; the entity class goes into the finding where it's named.
//! - Parser errors: quotes and brackets that break the query, with an error of the ORM's
//!   query parser in the answer that the original page didn't show. Medium confidence.
//!
//! Blind HQL injection (no error shown) is left to 40018's boolean checks, which work on
//! HQL as they do on SQL, and report "SQL Injection".

use std::sync::LazyLock;

use regex::Regex;

use super::common::point;
use crate::scan::active::{rand_u64, ActiveRule, BoxFuture, Cx, RuleScope, Strength};
use crate::scan::{AlertDef, Confidence, Risk};

static ALERT: AlertDef = AlertDef {
    alert_ref: "100003",
    name: "HQL Injection",
    risk: Risk::High,
    confidence: Confidence::Medium,
    cwe: 564,
    wasc: 19,
    description: "User input reaches an object query (Hibernate HQL, or JPQL with EclipseLink or OpenJPA) without \
        being bound as a parameter, so it can change the query. An attacker can read entities and fields the query \
        was not meant to return, bypass conditions such as ownership checks or a login's password comparison, and \
        through the ORM's SQL translation often reach the database further, depending on the ORM and its version.",
    solution: "Bind every value as a query parameter (setParameter with named or positional parameters, or the \
        Criteria API) instead of building the query string by concatenation. Do not pass user input as an entity, \
        property or ORDER BY name; map it from a fixed list instead. Do not show query or stack trace errors to \
        users.",
    references: &[
        "https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05.7-Testing_for_ORM_Injection",
        "https://cheatsheetseries.owasp.org/cheatsheets/Query_Parameterization_Cheat_Sheet.html",
        "https://cwe.mitre.org/data/definitions/564.html",
    ],
    tags: &["OWASP_2025_A05", "OWASP_2021_A03", "OWASP_2017_A01", "WSTG-v42-INPV-05", "API_2023_API10", "PCI_DSS"],
};

static ALERTS: [&AlertDef; 1] = [&ALERT];

/// Query parser errors, per ORM. Case-insensitive.
const PARSER_ERRORS: [(&str, &str); 13] = [
    ("Hibernate 4/5", r"org\.hibernate\.hql\.internal\.ast\.QuerySyntaxException"),
    ("Hibernate 4/5", r"org\.hibernate\.hql\.internal\.ast\.ErrorCounter"),
    ("Hibernate 3", r"org\.hibernate\.hql\.ast\.QuerySyntaxException"),
    ("Hibernate", r"unexpected (?:token|char): .{0,200}?near line \d+, column \d+"),
    ("Hibernate", r"unexpected end of subtree \["),
    ("Hibernate", r"expecting .{1,40}?, found .{1,40}? near line \d+, column \d+"),
    ("Hibernate", r"org\.hibernate\.QueryException"),
    ("Hibernate 6", r"org\.hibernate\.query\.(?:SyntaxException|SemanticException|sqm\.ParsingException)"),
    (
        "Hibernate 6",
        r"At \d+:\d+ and token '.{0,80}?', (?:mismatched input|no viable alternative|extraneous input|missing|token recognition error)",
    ),
    ("EclipseLink", r"org\.eclipse\.persistence\.exceptions\.JPQLException"),
    // 8000s are JPQL parsing; others wrap database errors (4002) and more.
    ("EclipseLink", r"Exception \[EclipseLink-80\d\d\]"),
    ("OpenJPA", r"org\.apache\.openjpa\.persistence\.ArgumentException"),
    ("OpenJPA", r"An error occurred while parsing the query filter"),
];

static PARSER: LazyLock<Vec<(&str, Regex)>> = LazyLock::new(|| {
    PARSER_ERRORS.iter().map(|(orm, p)| (*orm, Regex::new(&format!("(?i){p}")).expect("HQL pattern"))).collect()
});

/// Unknown path errors, with `{P}` for either random name of the path and a group for
/// the entity where the message names it.
const PROPERTY_ERRORS: [(&str, &str); 7] = [
    ("Hibernate 3 to 5", r"could not resolve property: (?:\w+\.)?{P} of: ([\w.$]+)"),
    ("Hibernate 3 to 5", r"Invalid path: '(?:\w+\.)?{P}'()"),
    ("Hibernate 6", r"Could not resolve attribute '(?:\w+\.)?{P}' of '([\w.$]+)'"),
    ("Hibernate 6", r"Could not interpret path expression '(?:\w+\.)?{P}'()"),
    ("Hibernate", r"unable to resolve path \[(?:\w+\.)?{P}\]()"),
    ("EclipseLink", r"(?:state field path|identification variable) '(?:\w+\.)?{P}'()"),
    ("OpenJPA", r#"No field named "{P}" in "?([\w.$]+)"#),
];

/// Values that break a query at a string or a numeric value; the original value is
/// put in front where `{V}` is.
const BREAKERS: [&str; 6] = ["'", "\"", "{V}'", "{V}\"", "{V}')", "{V})"];

/// The unknown path comparison, for a single quoted, double quoted and numeric value.
/// A dotted path (`{A}.{P}`) fails in every ORM's parser, also in queries with an alias,
/// where Hibernate 5 would pass an unknown plain name on to the database as a column.
const PROPERTY_ATTACKS: [&str; 3] =
    ["{V}' and {A}.{P}=1 and '1'='1", "{V}\" and {A}.{P}=1 and \"1\"=\"1", "{V} and {A}.{P}=1"];

/// Requests per check: (unknown property, parser error).
fn budget(s: Strength) -> (usize, usize) {
    match s {
        Strength::Low => (2, 1),
        Strength::Medium => (3, 3),
        Strength::High | Strength::Insane => (3, BREAKERS.len()),
    }
}

/// The body with the escapes a page puts around an error message undone: HTML entities
/// and JSON string escapes.
fn unescaped(body: &str) -> String {
    let mut s = body.replace("\\\"", "\"").replace("\\u0027", "'").replace("\\u0022", "\"").replace("\\/", "/");
    for (from, to) in [
        ("&#39;", "'"),
        ("&#x27;", "'"),
        ("&apos;", "'"),
        ("&quot;", "\""),
        ("&#34;", "\""),
        ("&lt;", "<"),
        ("&gt;", ">"),
    ] {
        s = s.replace(from, to);
    }
    s.replace("&amp;", "&")
}

/// The first parser error in `body`: (ORM, matched text).
fn parser_error(body: &str) -> Option<(&'static str, String)> {
    let body = unescaped(body);
    PARSER.iter().find_map(|(orm, re)| re.find(&body).map(|m| (*orm, m.as_str().to_string())))
}

/// An unknown path error naming one of `names`: (ORM, matched text, entity if named).
fn property_error(body: &str, names: &[&str]) -> Option<(&'static str, String, Option<String>)> {
    let body = unescaped(body);
    let names = names.iter().map(|n| regex::escape(n)).collect::<Vec<_>>().join("|");
    PROPERTY_ERRORS.iter().find_map(|(orm, p)| {
        let re = Regex::new(&format!("(?i){}", p.replace("{P}", &format!("(?:{names})")))).ok()?;
        let c = re.captures(&body)?;
        let entity = c.get(1).map(|m| m.as_str().to_string()).filter(|e| !e.is_empty());
        Some((*orm, c[0].to_string(), entity))
    })
}

async fn unknown_property(cx: &Cx, param: &str, value: &str, budget: usize) -> bool {
    for template in PROPERTY_ATTACKS.iter().take(budget) {
        if cx.stopped() {
            return true;
        }
        let alias = format!("bp{:x}", rand_u64() & 0xff_ffff);
        let property = format!("bp{:x}", rand_u64() & 0xff_ffff);
        let attack = template.replace("{V}", value).replace("{A}", &alias).replace("{P}", &property);
        let Ok(resp) = cx.send_payload(&attack).await else { return true };
        if let Some((orm, evidence, entity)) = property_error(resp.body_str(), &[&alias, &property]) {
            let entity = entity.map_or(String::new(), |e| format!(" It names the entity {e}."));
            let info = format!(
                "The query parser ({orm}) reports the random path {alias}.{property} as unknown, so the value was \
                 parsed as part of an object query rather than bound as a parameter.{entity}"
            );
            let finding = ALERT.raise(param, evidence).attack(attack).other_info(info).confidence(Confidence::High);
            cx.report(finding, &resp);
            return true;
        }
    }
    false
}

async fn parser_errors(cx: &Cx, param: &str, value: &str, budget: usize) {
    let base = unescaped(cx.base_response().body_str());
    let in_base = |re: &Regex| re.is_match(&base);
    if PARSER.iter().any(|(_, re)| in_base(re)) {
        // The page shows such an error anyway; a new one proves nothing.
        return;
    }
    for template in BREAKERS.iter().take(budget) {
        if cx.stopped() {
            return;
        }
        let attack = template.replace("{V}", value);
        let Ok(resp) = cx.send_payload(&attack).await else { return };
        if let Some((orm, evidence)) = parser_error(resp.body_str()) {
            let info = format!(
                "The value broke the query, and the answer has an error of the {orm} query parser, which the \
                 original page doesn't. The unknown property check didn't confirm it, so the query may only be \
                 reached in part, or its error not shown in full."
            );
            cx.report(ALERT.raise(param, evidence).attack(attack).other_info(info), &resp);
            return;
        }
    }
}

pub struct HqlInjection;

impl ActiveRule for HqlInjection {
    fn id(&self) -> u32 {
        100003
    }

    fn name(&self) -> &'static str {
        "HQL Injection"
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
            let (properties, breakers) = budget(cx.strength());
            if !unknown_property(cx, &param, &value, properties).await {
                parser_errors(cx, &param, &value, breakers).await;
            }
        })
    }
}

/// Hibernate's query parser errors, which never reach a database.
static HIBERNATE_PARSER: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)QuerySyntaxException|org\.hibernate\.query\.(?:SyntaxException|sqm\.ParsingException)|near line \d+, column \d+")
        .expect("Hibernate pattern")
});

/// Whether `body` has a Hibernate query parser error. 40018 then doesn't take its
/// "unexpected token:" for Hypersonic SQL's; driver errors on the page still count.
pub(super) fn is_hibernate_parser_error(body: &str) -> bool {
    HIBERNATE_PARSER.is_match(&unescaped(body))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parser_errors_of_each_orm() {
        for (body, orm) in [
            (
                "org.hibernate.hql.internal.ast.QuerySyntaxException: unexpected token: ' near line 1, column 42 \
                 [from com.shop.Product where name = '']",
                "Hibernate 4/5",
            ),
            ("unexpected char: ''' near line 1, column 40", "Hibernate"),
            ("expecting ''', found '<EOF>' near line 1, column 41", "Hibernate"),
            ("unexpected end of subtree [from com.shop.Product where id = ]", "Hibernate"),
            (
                "org.hibernate.query.SyntaxException: At 1:41 and token ''', token recognition error at: '''",
                "Hibernate 6",
            ),
            ("At 1:33 and token 'x', mismatched input 'x', expecting {&lt;EOF&gt;}", "Hibernate 6"),
            ("Exception [EclipseLink-8025] (Eclipse Persistence Services)", "EclipseLink"),
            ("org.apache.openjpa.persistence.ArgumentException: An error occurred while parsing", "OpenJPA"),
        ] {
            assert_eq!(parser_error(body).map(|e| e.0), Some(orm), "{body}");
        }
        // HTML-escaped, as an error page shows it.
        assert!(parser_error("unexpected token: &#39; near line 1, column 9").is_some());
        // Database errors aren't the ORM parser's, also when an ORM wraps them.
        for body in [
            "You have an error in your SQL syntax",
            "org.hibernate.exception.SQLGrammarException: could not extract ResultSet",
            "Unexpected token: , requires FROM in statement",
            "Exception [EclipseLink-4002]: org.postgresql.util.PSQLException: syntax error at or near",
            "javax.persistence.PersistenceException: org.hibernate.exception.SQLGrammarException: could not execute query",
        ] {
            assert!(parser_error(body).is_none(), "{body}");
        }
        // 40018's guard: Hibernate's parser, not HSQLDB's own error.
        assert!(is_hibernate_parser_error("QuerySyntaxException: unexpected token: ' near line 1, column 9"));
        assert!(!is_hibernate_parser_error("Unexpected token: , requires FROM in statement [SELECT]"));
    }

    #[test]
    fn unknown_path_names_a_random_name_and_the_entity() {
        let (a, p) = ("bp9d8e7f", "bp1a2b3c");
        let found = |body: String| property_error(&body, &[a, p]);
        let e = found(format!("could not resolve property: {a} of: com.shop.User")).unwrap();
        assert_eq!((e.0, e.2.as_deref()), ("Hibernate 3 to 5", Some("com.shop.User")));
        let e = found(format!("Could not resolve attribute '{p}' of 'com.shop.User'")).unwrap();
        assert_eq!((e.0, e.2.as_deref()), ("Hibernate 6", Some("com.shop.User")));
        let e = found(format!(r#"{{"error":"Invalid path: '{a}.{p}'"}}"#)).unwrap();
        assert_eq!((e.0, e.2), ("Hibernate 3 to 5", None));
        assert!(found(format!("Could not interpret path expression '{a}.{p}'")).is_some());
        assert!(found(format!("The identification variable '{a}' is not defined in the FROM clause")).is_some());
        // Another name, an echo, or a database's unknown column or table error don't count.
        assert!(found("could not resolve property: bpffffff of: com.shop.User".into()).is_none());
        assert!(found(format!("<p>No results for x' and {a}.{p}=1 and '1'='1</p>")).is_none());
        assert!(found(format!("ERROR: missing FROM-clause entry for table \"{a}\"")).is_none());
    }
}
