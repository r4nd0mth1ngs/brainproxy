//! Passive rules, ported from ZAP's pscanrules add-on (Apache License 2.0).

pub(crate) mod content;
mod cookie_http_only;
mod headers;
pub(crate) mod params;

use crate::scan::PassiveRule;

pub fn all() -> Vec<Box<dyn PassiveRule>> {
    let mut rules: Vec<Box<dyn PassiveRule>> = vec![Box::new(cookie_http_only::CookieHttpOnly)];
    rules.extend(headers::all());
    rules.extend(params::all());
    rules.extend(content::all());
    rules
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    #[test]
    fn rule_ids_and_alert_refs_are_unique() {
        let rules = super::all();
        let mut ids = HashSet::new();
        for r in &rules {
            assert!(ids.insert(r.id()), "duplicate rule id {}", r.id());
            assert!(!r.alerts().is_empty(), "rule {} has no alerts", r.id());
            for a in r.alerts() {
                assert!(
                    a.alert_ref == r.id().to_string() || a.alert_ref.starts_with(&format!("{}-", r.id())),
                    "alert {} doesn't belong to rule {}",
                    a.alert_ref,
                    r.id()
                );
                assert!(!a.description.is_empty() && !a.solution.is_empty(), "alert {} lacks texts", a.alert_ref);
                for t in a.tags {
                    assert!(!["PENTEST", "DEV_STD", "QA_STD", "DEV-STD", "QA-STD"].contains(t), "policy tag {t}");
                }
            }
        }
        assert!(rules.len() >= 49, "expected all ported rules, got {}", rules.len());
    }
}
