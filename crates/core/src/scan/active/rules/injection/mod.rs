//! Injection rules, including the time based ones, ported from ZAP's
//! ascanrules add-on (Apache License 2.0). Each file names its ZAP class;
//! `timing` is ZAP commonlib's TimingUtils, `common` the ZAP core and
//! commons-text behaviour the rules depend on.

/// Placeholders of the SQL timing templates (ZAP's tokens).
macro_rules! orig_value {
    () => {
        "<<<<ORIGINALVALUE>>>>"
    };
}

macro_rules! sleep_token {
    () => {
        "<<<<SLEEP>>>>"
    };
}

mod code_injection;
mod command_injection;
mod command_injection_timing;
mod common;
mod sql_injection;
mod sql_injection_hypersonic_timing;
mod sql_injection_mssql_timing;
mod sql_injection_mysql_timing;
mod sql_injection_oracle_timing;
mod sql_injection_postgresql_timing;
mod ssti_blind;
mod timing;

#[cfg(test)]
mod e2e;

use crate::scan::active::ActiveRule;

pub fn all() -> Vec<Box<dyn ActiveRule>> {
    vec![
        Box::new(sql_injection::SqlInjection),
        Box::new(sql_injection_mysql_timing::SqlInjectionMySqlTiming),
        Box::new(sql_injection_hypersonic_timing::SqlInjectionHypersonicTiming),
        Box::new(sql_injection_oracle_timing::SqlInjectionOracleTiming),
        Box::new(sql_injection_postgresql_timing::SqlInjectionPostgreSqlTiming),
        Box::new(sql_injection_mssql_timing::SqlInjectionMsSqlTiming),
        Box::new(code_injection::CodeInjection),
        Box::new(command_injection::CommandInjection),
        Box::new(ssti_blind::SstiBlind),
        Box::new(command_injection_timing::CommandInjectionTiming),
    ]
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use super::*;

    #[test]
    fn ids_alerts_and_tags() {
        let rules = all();
        let ids: HashSet<u32> = rules.iter().map(|r| r.id()).collect();
        assert_eq!(ids, HashSet::from([40018, 40019, 40020, 40021, 40022, 40027, 90019, 90020, 90036, 90037]));
        let mut refs = HashSet::new();
        for r in &rules {
            assert!(!r.name().is_empty());
            for a in r.alerts() {
                assert!(a.alert_ref == r.id().to_string() || a.alert_ref.starts_with(&format!("{}-", r.id())));
                assert!(refs.insert(a.alert_ref), "duplicate {}", a.alert_ref);
                assert!(!a.description.is_empty() && !a.solution.is_empty() && !a.references.is_empty());
                for t in a.tags {
                    assert!(
                        t.starts_with("OWASP_")
                            || t.starts_with("WSTG-")
                            || t.starts_with("API_")
                            || ["HIPAA", "PCI_DSS", "TEST_TIMING"].contains(t),
                        "unexpected tag {t} on {}",
                        a.alert_ref
                    );
                }
            }
        }
    }
}
