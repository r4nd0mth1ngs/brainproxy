//! Passive checks (`passive: true`): the matchers and extractors of a check run
//! on recorded exchanges in the passive scanner, like a built-in passive rule.
//! Nothing is sent, so they read the response only (no baseline, no numbered
//! parts, no out-of-band interactions).

use std::collections::HashMap;
use std::path::Path;

use super::rule::{alert_def, run_extractors, run_matchers, subst, verdict, Ambient};
use super::{feed_dir, load, local_dir, Check, LoadOptions};
use crate::scan::active::Response;
use crate::scan::{AlertDef, Finding, Message, PassiveRule};

pub struct CheckPassiveRule {
    check: Check,
    name: &'static str,
    alerts: &'static [&'static AlertDef],
}

impl CheckPassiveRule {
    pub fn new(check: Check) -> Self {
        let def = alert_def(&check);
        CheckPassiveRule { name: def.name, alerts: Box::leak(Box::new([def])), check }
    }

    pub fn check(&self) -> &Check {
        &self.check
    }
}

/// The passive checks of the brainproxy feed and of `checks/local/`, for the
/// passive scanner. Only feed checks may replace a built-in rule. Checks that
/// don't load (or need `--check-var` inputs) are left out.
pub fn passive_rules(home: &Path) -> Vec<CheckPassiveRule> {
    let feed = feed_dir(home);
    let dirs: Vec<_> = [feed.clone(), local_dir(home)].into_iter().filter(|d| d.is_dir()).collect();
    let Ok(loaded) = load(&dirs, &LoadOptions::default()) else { return vec![] };
    loaded
        .checks
        .into_iter()
        .filter(|c| c.passive)
        .map(|mut c| {
            if !c.file.starts_with(&feed) {
                c.replaces = None;
            }
            CheckPassiveRule::new(c)
        })
        .collect()
}

/// Nuclei's input-derived variables for a recorded request, then the check's own.
fn variables(check: &Check, msg: &Message) -> HashMap<String, String> {
    let origin = url::Url::parse(&msg.url).map(|u| u.origin().ascii_serialization()).unwrap_or_default();
    let default_port = matches!((msg.scheme.as_str(), msg.port), ("https", 443) | ("http", 80));
    let hostname = if default_port { msg.host.clone() } else { format!("{}:{}", msg.host, msg.port) };
    let mut vars = HashMap::from([
        ("BaseURL".to_string(), origin.clone()),
        ("RootURL".to_string(), origin),
        ("Hostname".to_string(), hostname),
        ("Host".to_string(), msg.host.clone()),
        ("Port".to_string(), msg.port.to_string()),
        ("Path".to_string(), msg.path.clone()),
        ("File".to_string(), msg.path.rsplit('/').next().unwrap_or("").to_string()),
        ("Scheme".to_string(), msg.scheme.clone()),
    ]);
    vars.extend(check.inputs.iter().cloned());
    for (k, v) in &check.variables {
        if check.inputs.iter().any(|(i, _)| i == k) {
            continue;
        }
        if let Some(v) = subst(v, &vars) {
            vars.insert(k.clone(), v);
        }
    }
    vars
}

impl PassiveRule for CheckPassiveRule {
    /// 0, or the built-in rule this check replaces (`info.replaces`).
    fn id(&self) -> u32 {
        self.check.replaces.unwrap_or(0)
    }

    fn name(&self) -> &'static str {
        self.name
    }

    fn alerts(&self) -> &'static [&'static AlertDef] {
        self.alerts
    }

    fn scan(&self, msg: &Message, out: &mut Vec<Finding>) {
        let resp = Response::recorded(msg.status, msg.resp_headers.clone(), msg.resp_body.clone());
        let seen = std::slice::from_ref(&resp);
        let amb = Ambient { baseline: None, host: &msg.host };
        let mut vars = variables(&self.check, msg);
        for block in &self.check.blocks {
            let (extracted, mvars) = run_extractors(&amb, block, seen, &mut vars);
            let results = run_matchers(&amb, block, seen, &mvars);
            if let Some(Some((evidence, info))) = verdict(&self.check, block, results, &extracted) {
                out.push(self.alerts[0].raise("", evidence).other_info(info));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scan::passive::util::testing::msg;
    use crate::scan::passive::{all_rules, scan_with};

    /// The feed's passive checks, from the repository's checks/ folder.
    fn feed_rule(id: &str) -> CheckPassiveRule {
        let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../checks/passive");
        let loaded = load(&[dir], &LoadOptions::default()).unwrap();
        assert!(loaded.skipped.is_empty(), "{:?}", loaded.skipped);
        CheckPassiveRule::new(loaded.checks.into_iter().find(|c| c.id == id).unwrap())
    }

    #[test]
    fn feed_php2shell_matches_rule_100001() {
        let feed = feed_rule("CVE-2026-109618-php-version");
        assert_eq!((feed.id(), feed.alerts()[0].alert_ref), (100001, "100001"));
        let builtin = all_rules().iter().find(|r| r.id() == 100001).unwrap();
        let mut cases: Vec<(&str, String)> = [
            "5.3.29",
            "5.4.0",
            "7.4.33",
            "8.0.30",
            "8.1.2-1ubuntu2.14",
            "8.2.34",
            "8.2.35",
            "8.2.35-1+deb12u1",
            "8.2.35beta2",
            "8.3.35",
            "8.3.36",
            "8.4.26",
            "8.4.27",
            "8.4.27RC1",
            "8.5.11",
            "8.5.12",
            "8.5.12-dev",
            "8.5.13",
            "8.5.13-dev",
            "8.6.0",
            "9.0.0",
            "8",
        ]
        .iter()
        .map(|v| ("X-Powered-By", format!("PHP/{v}")))
        .collect();
        cases.extend([
            ("Server", "Apache/2.4.57 (Ubuntu) PHP/8.1.2-1ubuntu2.14".to_string()),
            ("Server", "Apache/2.4.62 PHP/8.4.27".to_string()),
            ("X-Lib", "PHP/8.2.1".to_string()),
            ("X-Powered-By", "Express".to_string()),
        ]);
        for (k, v) in &cases {
            let m = msg("https://a.test/").header(k, v).build();
            let (mut a, mut b) = (Vec::new(), Vec::new());
            builtin.scan(&m, &mut a);
            feed.scan(&m, &mut b);
            let ev = |f: &[Finding]| f.iter().map(|x| x.evidence.clone()).collect::<Vec<_>>();
            assert_eq!(ev(&a), ev(&b), "{k}: {v}");
        }
        // Both headers: the first one reported decides, as for the rule.
        let m = msg("https://a.test/").header("Server", "nginx PHP/8.4.27").header("X-Powered-By", "PHP/8.4.1").build();
        let mut b = Vec::new();
        feed.scan(&m, &mut b);
        assert!(b.is_empty(), "{b:?}");
    }

    #[test]
    fn a_feed_check_runs_in_place_of_the_rule_it_replaces() {
        let feed = [feed_rule("CVE-2026-109618-php-version")];
        let m = msg("https://a.test/").header("X-Powered-By", "PHP/8.2.34").build();
        let found: Vec<_> = scan_with(&m, &[], &feed).into_iter().filter(|f| f.def.alert_ref == "100001").collect();
        assert_eq!(found.len(), 1);
        assert!(found[0].other_info.starts_with("Check CVE-2026-109618-php-version"), "{}", found[0].other_info);
        // Switching the rule off switches the check off.
        assert!(scan_with(&m, &[100001], &feed).iter().all(|f| f.def.alert_ref != "100001"));
    }
}
