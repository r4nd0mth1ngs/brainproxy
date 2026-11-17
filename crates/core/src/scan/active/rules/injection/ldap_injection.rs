//! Ported from ZAP LdapInjectionScanRule (ascanrulesAlpha, Apache License 2.0): its id,
//! alerts, texts and its error attack. The checks are brainproxy's own.
//!
//! Differences from ZAP, against false positives and for search pages that return data:
//! - Error based: ZAP's error list (hundreds of LDAP result texts such as "Invalid string",
//!   "out of memory" or "Timed out") is replaced by messages only an LDAP client library or
//!   server writes: JNDI, Spring LDAP, UnboundID, Apache Directory, libldap (PHP,
//!   python-ldap), ldap3, ldapjs, .NET System.DirectoryServices, Active Directory, go-ldap
//!   and Ruby net-ldap. As in ZAP, a placebo of the same length must not bring the message;
//!   unlike ZAP, an unbalanced filter after a random value must bring one too (a search whose
//!   results quote an LDAP error finds nothing for a random value), and the finding is high
//!   confidence.
//! - Boolean based: ZAP compares "value)(objectClass=*" with the original page alone, and a
//!   wildcard in the middle of the value, so any app that ignores the input raises. Here
//!   the always-true clause is paired with the same clause made false (`objectClass=` a
//!   random word): read as data the two are unknown values and give the same page; read as
//!   a filter, the one ANDed or ORed with the original condition keeps the original page and
//!   the other changes it (`differential`). Pairs start from the original value (data
//!   originally) and from `*` (none), closed one parenthesis deep, and at HIGH and INSANE
//!   also two and three deep.
//! - ZAP skips pages whose original answer is a 4xx or 5xx, and URL path segments; so does
//!   this rule.

use regex::Regex;
use std::sync::LazyLock;

use super::common::{by_strength, control_token, point};
use crate::scan::active::points::PointKind;
use crate::scan::active::rules::differential::{Differential, Kept};
use crate::scan::active::{ActiveRule, BoxFuture, Cx, RuleScope};
use crate::scan::{AlertDef, Confidence, Risk};

const DESC: &str = "LDAP Injection may be possible. It may be possible for an attacker to bypass authentication \
    controls, and to view and modify arbitrary data in the LDAP directory.";
const SOLN: &str = "Validate and/or escape all user input before using it to create an LDAP query.  In particular, \
    the following characters (or combinations) should be deny listed:\n&\n|\n!\n<\n>\n=\n~=\n>=\n<=\n*\n(\n)\n,\n+\n\
    -\n\"\n'\n;\n\\\n/\nNUL character\n";
const REFS: &[&str] = &[
    "https://owasp.org/www-community/attacks/LDAP_Injection",
    "https://cheatsheetseries.owasp.org/cheatsheets/LDAP_Injection_Prevention_Cheat_Sheet.html",
];
const TAGS: &[&str] =
    &["API_2023_API4", "OWASP_2025_A05", "OWASP_2021_A03", "OWASP_2017_A01", "WSTG-v42-INPV-06", "HIPAA", "PCI_DSS"];

static ERROR_ALERT: AlertDef = AlertDef {
    alert_ref: "40015-1",
    name: "LDAP Injection",
    risk: Risk::High,
    confidence: Confidence::High,
    cwe: 90,
    wasc: 29,
    description: DESC,
    solution: SOLN,
    references: REFS,
    tags: TAGS,
};

static BOOLEAN_ALERT: AlertDef = AlertDef {
    alert_ref: "40015-2",
    name: "LDAP Injection",
    risk: Risk::High,
    confidence: Confidence::Medium,
    cwe: 90,
    wasc: 29,
    description: DESC,
    solution: SOLN,
    references: REFS,
    tags: TAGS,
};

static ALERTS: [&AlertDef; 2] = [&ERROR_ALERT, &BOOLEAN_ALERT];

/// ZAP's error attack: every LDAP filter metacharacter.
const ERROR_ATTACK: &str = "|!<>=~=>=<=*(),+-\"'\\/";

/// Messages only LDAP client libraries and servers write, by implementation.
const ERRORS: &[(&str, &str)] = &[
    ("JNDI", r"javax\.naming\.(?:directory\.InvalidSearchFilterException|NamingException|InvalidNameException)"),
    ("JNDI", r"\[LDAP: error code \d+"),
    ("Spring LDAP", r"org\.springframework\.ldap\.[A-Za-z.]*Exception"),
    ("UnboundID LDAP SDK", r"com\.unboundid\.ldap\.sdk\.LDAPException"),
    ("Apache Directory", r"org\.apache\.directory\.api\.ldap\.[A-Za-z.]*Exception"),
    // PHP prints the function name, as a link with html_errors on.
    ("PHP", r"ldap_(?:search|list|read)\(\)(?: \[<a [^\]]*\])?: Search: "),
    // ldap_err2string(LDAP_FILTER_ERROR), which PHP and python-ldap pass on.
    ("libldap", r"Bad search filter"),
    ("python-ldap", r"ldap\.FILTER_ERROR"),
    ("ldap3", r"LDAPInvalidFilterError"),
    ("ldapjs", r"node_modules[/\\]@?ldapjs"),
    (".NET", r"System\.DirectoryServices(?:\.Protocols)?\.[A-Za-z]*Exception"),
    (".NET", r"The search filter (?:is invalid|cannot be recognized)"),
    ("Active Directory", r"LdapErr: DSID-[0-9A-Fa-f]+"),
    ("go-ldap", r#"LDAP Result Code \d+ "[A-Za-z ]+""#),
    ("Ruby net-ldap", r"Net::LDAP::[A-Za-z]*Error"),
];

static COMPILED: LazyLock<Vec<Regex>> = LazyLock::new(|| {
    ERRORS.iter().map(|(_, p)| Regex::new(p).expect("the LDAP error patterns are valid regexes")).collect()
});

/// The first LDAP error in `body` that `base` lacks: its index in `ERRORS` and the matched text.
fn new_error(body: &str, base: &str) -> Option<(usize, String)> {
    COMPILED.iter().enumerate().find_map(|(i, re)| {
        if re.is_match(base) {
            return None;
        }
        re.find(body).map(|m| (i, m.as_str().to_string()))
    })
}

/// A value of `len` random letters and digits (ZAP's placebo attack).
fn placebo(len: usize) -> String {
    let mut s = String::new();
    while s.len() < len {
        s.push_str(&control_token(false));
        s.push_str(&control_token(true));
    }
    s.truncate(len);
    s
}

/// The always-true and always-false values for `start` closed `depth` parentheses deep: the
/// added clause is ANDed onto whatever the value's own filter was nested in, and the
/// template's own closing parentheses close it. `(&(a=b)(|(uid=V)(mail=c)))` with
/// `V))(&(objectClass=*` reads `(&(a=b)(|(uid=V))(&(objectClass=*)(mail=c)))`.
fn pair(start: &str, depth: usize, word: &str) -> (String, String) {
    let head = format!("{start}{}{}", ")".repeat(depth), "(&".repeat(depth.saturating_sub(1)));
    (format!("{head}(objectClass=*"), format!("{head}(objectClass={word}"))
}

fn error_info(param: &str, implementation: &str, pattern: &str) -> String {
    format!(
        "parameter [{param}] may be vulnerable to LDAP injection, using an attack with LDAP meta-characters \
         [{ERROR_ATTACK}], yielding known [{implementation}] error message [{pattern}], which was not present in the \
         original response."
    )
}

fn boolean_info(param: &str, t: &str, f: &str, kept: Kept) -> String {
    let how = match kept {
        Kept::ByTrue => "kept the original results and the FALSE expression changed them",
        Kept::ByFalse => "changed the original results and the FALSE expression kept them",
    };
    format!(
        "parameter [{param}] may be vulnerable to LDAP injection: the logically TRUE expression [{t}] {how} \
         [{f}]. Taken as plain values, the two would give the same page."
    )
}

pub struct LdapInjection;

impl ActiveRule for LdapInjection {
    fn id(&self) -> u32 {
        40015
    }

    fn name(&self) -> &'static str {
        "LDAP Injection"
    }

    fn alerts(&self) -> &'static [&'static AlertDef] {
        &ALERTS
    }

    fn scope(&self) -> RuleScope {
        RuleScope::Param
    }

    fn scan<'a>(&'a self, cx: &'a Cx) -> BoxFuture<'a> {
        Box::pin(async move {
            if cx.base_response().status >= 400 || cx.point().kind == PointKind::Path {
                return;
            }
            if error_based(cx).await || cx.stopped() {
                return;
            }
            boolean_based(cx).await;
        })
    }
}

/// An LDAP error for the metacharacters, absent for a placebo and present for an unbalanced
/// filter after a random value.
async fn error_based(cx: &Cx) -> bool {
    let (param, orig) = point(cx);
    let base = cx.base_response().body_str();
    let attacks = [ERROR_ATTACK.to_string(), format!("{orig})")];
    let n = by_strength(cx.strength(), [1, 2, 2, 2]);
    for attack in attacks.iter().take(n) {
        let Ok(resp) = cx.send_payload(attack).await else { continue };
        let Some((i, evidence)) = new_error(resp.body_str(), base) else { continue };
        if cx.stopped() {
            return false;
        }
        let Ok(placebo_resp) = cx.send_payload(&placebo(attack.chars().count())).await else { return false };
        if new_error(placebo_resp.body_str(), base).is_some() {
            return false;
        }
        let control = format!("{})(", control_token(orig.parse::<f64>().is_ok()));
        let Ok(control_resp) = cx.send_payload(&control).await else { return false };
        if new_error(control_resp.body_str(), base).is_none() {
            return false;
        }
        let (implementation, pattern) = ERRORS[i];
        let f = ERROR_ALERT.raise(param.clone(), evidence).attack(attack.clone()).other_info(error_info(
            &param,
            implementation,
            pattern,
        ));
        cx.report(f, &resp);
        return true;
    }
    false
}

async fn boolean_based(cx: &Cx) {
    let (param, orig) = point(cx);
    let Some(diff) = Differential::new(cx).await else { return };
    let depths = by_strength(cx.strength(), [1, 1, 2, 3]);
    // A random word, so no directory has it as an object class.
    let word = control_token(false);
    for depth in 1..=depths {
        // The original value first: with data originally, `*` changes the page both ways.
        for start in [orig.as_str(), "*"] {
            if cx.stopped() {
                return;
            }
            let (t, f) = pair(start, depth, &word);
            if let Some((kept, resp)) = diff.test(&t, &f).await {
                let finding = BOOLEAN_ALERT
                    .raise(param.clone(), "")
                    .attack(t.clone())
                    .other_info(boolean_info(&param, &t, &f, kept));
                cx.report(finding, &resp);
                return;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn error_patterns() {
        let cases = [
            ("javax.naming.directory.InvalidSearchFilterException: Unbalanced parenthesis", "JNDI"),
            ("javax.naming.NamingException: [LDAP: error code 1 - Operations Error]", "JNDI"),
            ("org.springframework.ldap.BadLdapGrammarException: Failed to parse", "Spring LDAP"),
            ("com.unboundid.ldap.sdk.LDAPException: Unable to parse", "UnboundID LDAP SDK"),
            (
                "<b>Warning</b>:  ldap_search() [<a href='function.ldap-search'>function.ldap-search</a>]: Search: Bad",
                "PHP",
            ),
            ("Warning: ldap_search(): Search: Bad search filter in /var/www/x.php", "PHP"),
            ("ldap.FILTER_ERROR: {'result': -7, 'desc': 'Bad search filter'}", "libldap"),
            ("ldap3.core.exceptions.LDAPInvalidFilterError: malformed filter", "ldap3"),
            ("at parse (/app/node_modules/@ldapjs/filter/lib/parse.js:12:9)", "ldapjs"),
            ("System.DirectoryServices.DirectoryServicesCOMException (0x80072020)", ".NET"),
            ("The search filter is invalid.", ".NET"),
            ("00002077: LdapErr: DSID-0C0907E9, comment: Error in attribute conversion", "Active Directory"),
            (r#"LDAP Result Code 201 "Filter Compile Error": ldap: filter does not start with an '('"#, "go-ldap"),
            ("Net::LDAP::FilterSyntaxInvalidError", "Ruby net-ldap"),
        ];
        for (text, name) in cases {
            assert_eq!(new_error(text, "").map(|e| ERRORS[e.0].0), Some(name), "{text}");
        }
        // Plain words that ZAP's list had are not LDAP errors.
        for text in ["out of memory", "Invalid string", "Timed out", "Not Supported", "Protocol error"] {
            assert_eq!(new_error(text, ""), None, "{text}");
        }
        // Already on the original page: not the attack's doing.
        assert_eq!(new_error("Bad search filter", "FAQ: Bad search filter"), None);
    }

    #[test]
    fn pairs_balance_the_template() {
        assert_eq!(pair("alice", 1, "zz"), ("alice)(objectClass=*".into(), "alice)(objectClass=zz".into()));
        assert_eq!(pair("*", 2, "zz"), ("*))(&(objectClass=*".into(), "*))(&(objectClass=zz".into()));
        // Put into a nested filter, both close every parenthesis they open.
        for depth in 1..=3 {
            let (t, f) = pair("v", depth, "zz");
            let close = ")".repeat(depth + 1);
            for v in [t, f] {
                let filter = format!("(&(a=b){}(uid={v}{close}", "(|".repeat(depth - 1));
                let opens = filter.matches('(').count();
                assert_eq!(opens, filter.matches(')').count(), "{filter}");
            }
        }
    }

    #[test]
    fn placebo_is_alphanumeric_of_the_length() {
        let p = placebo(ERROR_ATTACK.len());
        assert_eq!(p.len(), ERROR_ATTACK.len());
        assert!(p.chars().all(|c| c.is_ascii_alphanumeric()), "{p}");
    }
}
