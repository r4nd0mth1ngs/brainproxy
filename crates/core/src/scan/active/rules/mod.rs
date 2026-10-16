//! Active rules, ported from ZAP's ascanrules add-on (Apache License 2.0).

mod crlf_injection;
pub(crate) mod env_file;
mod injection;
mod params;
mod probes;

use crate::scan::active::ActiveRule;

pub fn all() -> Vec<Box<dyn ActiveRule>> {
    let mut rules: Vec<Box<dyn ActiveRule>> =
        vec![Box::new(crlf_injection::CrlfInjection), Box::new(env_file::EnvFile)];
    rules.extend(injection::all());
    rules.extend(params::all());
    rules.extend(probes::all());
    rules
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    #[test]
    fn rule_ids_unique_and_complete() {
        let rules = super::all();
        let mut ids = HashSet::new();
        for r in &rules {
            assert!(ids.insert(r.id()), "duplicate active rule id {}", r.id());
            assert!(!r.alerts().is_empty(), "rule {} lists no alerts", r.id());
            for a in r.alerts() {
                assert!(!a.description.is_empty(), "alert {} lacks a description", a.alert_ref);
                // ZAP leaves the solution empty only for informational alerts (e.g. 10104).
                assert!(
                    !a.solution.is_empty() || a.risk == crate::scan::Risk::Info,
                    "alert {} lacks a solution",
                    a.alert_ref
                );
                for t in a.tags {
                    assert!(
                        !["PENTEST", "QA_STD", "QA_FULL", "DEV_STD", "DEV_FULL", "SEQUENCE"].contains(t),
                        "policy tag {t}"
                    );
                }
            }
        }
        assert!(rules.len() >= 42, "expected all ported active rules, got {}", rules.len());
        // No active rule id collides with a passive rule id.
        let passive: HashSet<u32> = crate::scan::passive::all_rules().iter().map(|r| r.id()).collect();
        for id in &ids {
            assert!(!passive.contains(id), "active rule {id} reuses a passive rule id");
        }
    }
}
