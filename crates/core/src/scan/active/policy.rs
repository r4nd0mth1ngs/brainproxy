//! Scan policies: named, saved choices of which active rules run, how hard each attacks
//! (strength) and how sure each must be before it raises a finding (threshold), as ZAP's scan
//! policies hold them. `scan active --policy NAME` uses one.
//!
//! A threshold is ZAP's alert threshold, read against the confidence the rules give their
//! findings: at `low` every finding is raised (as before policies), at `medium` only findings of
//! medium or high confidence, at `high` only high-confidence ones. A finding below its rule's
//! threshold isn't raised; the scan counts it in `below_threshold`. It doesn't change which
//! attacks a rule sends: the rules keep ZAP's checks at its default MEDIUM threshold. A rule is
//! turned off with `enabled: false`, ZAP's OFF threshold.
//!
//! Policies are kept in the project's settings (`setting.scan_policies`), all in one value: a
//! map from name to policy.

use std::collections::{BTreeMap, HashMap};

use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};
use crate::scan::active::{all_rules, Strength};
use crate::scan::Confidence;
use crate::store::Store;

/// The settings key the policies are kept under.
pub const SETTINGS_KEY: &str = "scan_policies";

/// How sure a rule must be before it raises a finding (ZAP's alert threshold, without OFF).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Threshold {
    /// Every finding.
    #[default]
    Low,
    /// Findings of medium or high confidence.
    Medium,
    /// High-confidence findings only.
    High,
}

impl Threshold {
    /// Whether a finding of this confidence is raised.
    pub fn passes(self, c: Confidence) -> bool {
        c.level() >= self as i64
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Threshold::Low => "low",
            Threshold::Medium => "medium",
            Threshold::High => "high",
        }
    }
}

/// One rule's own settings in a policy; what it leaves out comes from the policy.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct RuleSetting {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub enabled: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub strength: Option<Strength>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub threshold: Option<Threshold>,
}

impl RuleSetting {
    pub fn is_empty(&self) -> bool {
        self == &RuleSetting::default()
    }
}

/// A saved scan policy.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Policy {
    /// Whether rules the policy doesn't turn on or off run.
    pub enabled: bool,
    pub strength: Strength,
    pub threshold: Threshold,
    /// Per rule id.
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    pub rules: BTreeMap<u32, RuleSetting>,
}

impl Default for Policy {
    fn default() -> Self {
        Self { enabled: true, strength: Strength::Medium, threshold: Threshold::Low, rules: BTreeMap::new() }
    }
}

/// One rule as a policy runs it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct Effective {
    pub enabled: bool,
    pub strength: Strength,
    pub threshold: Threshold,
}

impl Policy {
    /// Refuses rule ids that aren't active rules, and drops rule entries that set nothing.
    pub fn validate(mut self) -> Result<Self> {
        if let Some(bad) = self.rules.keys().find(|id| !all_rules().iter().any(|r| r.id() == **id)) {
            return Err(Error::NotFound(format!("active rule {bad}")));
        }
        self.rules.retain(|_, s| !s.is_empty());
        Ok(self)
    }

    pub fn effective(&self, rule: u32) -> Effective {
        let s = self.rules.get(&rule);
        Effective {
            enabled: s.and_then(|s| s.enabled).unwrap_or(self.enabled),
            strength: s.and_then(|s| s.strength).unwrap_or(self.strength),
            threshold: s.and_then(|s| s.threshold).unwrap_or(self.threshold),
        }
    }

    /// The active rules it turns off (by id, in id order).
    pub fn disabled(&self) -> Vec<u32> {
        let mut ids: Vec<u32> = all_rules().iter().map(|r| r.id()).filter(|&id| !self.effective(id).enabled).collect();
        ids.sort_unstable();
        ids
    }

    /// The active rules it runs (by id, in id order).
    pub fn enabled_rules(&self) -> Vec<u32> {
        let mut ids: Vec<u32> = all_rules().iter().map(|r| r.id()).filter(|&id| self.effective(id).enabled).collect();
        ids.sort_unstable();
        ids
    }

    /// Its threshold, and the rules whose strength or threshold differ from its own.
    pub fn tuning(&self) -> Tuning {
        let rules = self
            .rules
            .iter()
            .filter(|(_, s)| s.strength.is_some() || s.threshold.is_some())
            .map(|(&id, s)| (id, RuleTuning { strength: s.strength, threshold: s.threshold }))
            .collect();
        Tuning { threshold: self.threshold, rules }
    }
}

/// A rule's own strength or threshold in a scan.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct RuleTuning {
    pub strength: Option<Strength>,
    pub threshold: Option<Threshold>,
}

/// A scan's thresholds, and the rules' own strengths and thresholds (`ActiveConfig::tuning`);
/// the default raises every finding and gives each rule the scan's strength.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Tuning {
    /// For every rule or check without one of its own.
    pub threshold: Threshold,
    pub rules: HashMap<u32, RuleTuning>,
}

impl Tuning {
    pub fn strength(&self, rule: u32, default: Strength) -> Strength {
        self.rules.get(&rule).and_then(|t| t.strength).unwrap_or(default)
    }

    pub fn threshold(&self, rule: u32) -> Threshold {
        self.rules.get(&rule).and_then(|t| t.threshold).unwrap_or(self.threshold)
    }
}

/// Checks a policy name: 1 to 64 characters, not starting with `-`, no control characters.
pub fn check_name(name: &str) -> Result<()> {
    if name.is_empty() || name.chars().count() > 64 {
        return Err(Error::InvalidInput("a policy name has 1 to 64 characters".into()));
    }
    if name.starts_with('-') || name.chars().any(char::is_control) {
        return Err(Error::InvalidInput("a policy name can't start with - or hold control characters".into()));
    }
    Ok(())
}

const META_KEY: &str = "setting.scan_policies";

fn parse(v: Option<String>) -> Result<BTreeMap<String, Policy>> {
    match v {
        Some(v) => serde_json::from_str(&v).map_err(|e| Error::InvalidInput(format!("setting {SETTINGS_KEY}: {e}"))),
        None => Ok(BTreeMap::new()),
    }
}

impl Store {
    /// Every saved policy, by name.
    pub fn scan_policies(&self) -> Result<BTreeMap<String, Policy>> {
        parse(self.meta_get(META_KEY)?)
    }

    pub fn scan_policy(&self, name: &str) -> Result<Policy> {
        self.scan_policies()?.remove(name).ok_or_else(|| Error::NotFound(format!("scan policy {name:?}")))
    }

    /// Saves `policy` as `name`; one of that name is replaced only with `replace`
    /// (otherwise `Conflict`).
    pub fn scan_policy_save(&mut self, name: &str, policy: &Policy, replace: bool) -> Result<()> {
        check_name(name)?;
        let policy = policy.clone().validate()?;
        self.meta_update(META_KEY, |old| {
            let mut all = parse(old)?;
            if !replace && all.contains_key(name) {
                return Err(Error::Conflict(format!("scan policy {name:?} exists")));
            }
            all.insert(name.to_string(), policy);
            Ok((Some(serde_json::to_string(&all).map_err(|e| Error::InvalidInput(e.to_string()))?), ()))
        })?;
        self.setting_saved(SETTINGS_KEY)
    }

    pub fn scan_policy_remove(&mut self, name: &str) -> Result<()> {
        self.meta_update(META_KEY, |old| {
            let mut all = parse(old)?;
            if all.remove(name).is_none() {
                return Err(Error::NotFound(format!("scan policy {name:?}")));
            }
            let v = if all.is_empty() { None } else { Some(serde_json::to_string(&all).unwrap_or_default()) };
            Ok((v, ()))
        })?;
        self.setting_saved(SETTINGS_KEY)
    }

    /// Logs who saved setting `key` and bumps the settings version, as `set_setting` does.
    fn setting_saved(&self, key: &str) -> Result<()> {
        crate::store::log_setting_change(&self.conn, key)?;
        self.bump_settings_version()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_threshold_raises_findings_at_or_above_it() {
        use Confidence::*;
        assert!([Low, Medium, High].iter().all(|&c| Threshold::Low.passes(c)));
        assert!(!Threshold::Medium.passes(Low) && Threshold::Medium.passes(Medium) && Threshold::Medium.passes(High));
        assert!(!Threshold::High.passes(Medium) && Threshold::High.passes(High));
    }

    #[test]
    fn a_rule_takes_what_it_sets_and_the_policy_the_rest() {
        let mut p = Policy { strength: Strength::High, threshold: Threshold::Medium, ..Default::default() };
        p.rules.insert(40018, RuleSetting { strength: Some(Strength::Insane), ..Default::default() });
        p.rules.insert(40012, RuleSetting { enabled: Some(false), ..Default::default() });
        assert_eq!(
            p.effective(40018),
            Effective { enabled: true, strength: Strength::Insane, threshold: Threshold::Medium }
        );
        assert!(!p.effective(40012).enabled);
        assert_eq!(
            p.effective(40014),
            Effective { enabled: true, strength: Strength::High, threshold: Threshold::Medium }
        );
        assert_eq!(p.disabled(), [40012]);
        assert_eq!(p.enabled_rules().len(), all_rules().len() - 1);
        let t = p.tuning();
        assert_eq!(t.rules[&40018], RuleTuning { strength: Some(Strength::Insane), threshold: None });
        assert!(!t.rules.contains_key(&40012));
        assert_eq!(
            (t.strength(40018, Strength::Low), t.strength(40014, Strength::Low)),
            (Strength::Insane, Strength::Low)
        );
        assert_eq!(t.threshold(40018), Threshold::Medium);

        // Off by default: only the rules it turns on run.
        let only = Policy {
            enabled: false,
            rules: [(40018, RuleSetting { enabled: Some(true), ..Default::default() })].into(),
            ..Default::default()
        };
        assert_eq!(only.enabled_rules(), [40018]);
    }

    #[test]
    fn policies_are_saved_by_name() {
        let mut s = Store::open_in_memory().unwrap();
        assert!(s.scan_policies().unwrap().is_empty());
        let mut p = Policy::default();
        p.rules.insert(40018, RuleSetting { threshold: Some(Threshold::High), ..Default::default() });
        p.rules.insert(40012, RuleSetting::default());
        s.scan_policy_save("deep", &p, true).unwrap();
        // An entry that sets nothing isn't kept.
        let saved = s.scan_policy("deep").unwrap();
        assert_eq!(saved.rules.keys().collect::<Vec<_>>(), [&40018]);
        assert!(matches!(s.scan_policy_save("deep", &Policy::default(), false), Err(Error::Conflict(_))));
        assert_eq!(s.scan_policy("deep").unwrap(), saved);
        s.scan_policy_save("deep", &Policy::default(), true).unwrap();
        assert_eq!(s.scan_policy("deep").unwrap(), Policy::default());

        let bad = Policy {
            rules: [(1, RuleSetting { enabled: Some(false), ..Default::default() })].into(),
            ..Default::default()
        };
        assert!(matches!(s.scan_policy_save("bad", &bad, true), Err(Error::NotFound(_))));
        assert!(s.scan_policy_save("-x", &Policy::default(), true).is_err());
        assert!(s.scan_policy_save("", &Policy::default(), true).is_err());

        s.scan_policy_remove("deep").unwrap();
        assert!(matches!(s.scan_policy("deep"), Err(Error::NotFound(_))));
        assert!(matches!(s.scan_policy_remove("deep"), Err(Error::NotFound(_))));
        let logged: i64 = s
            .conn
            .query_row("SELECT count(*) FROM setting_changes WHERE key = 'scan_policies'", [], |r| r.get(0))
            .unwrap();
        assert_eq!(logged, 3);
    }

    #[test]
    fn a_policy_reads_from_json() {
        let p: Policy =
            serde_json::from_str(r#"{"strength": "high", "rules": {"40018": {"threshold": "high"}}}"#).unwrap();
        assert!(p.enabled && p.strength == Strength::High && p.threshold == Threshold::Low);
        assert_eq!(p.rules[&40018].threshold, Some(Threshold::High));
        assert!(serde_json::from_str::<Policy>(r#"{"strenght": "high"}"#).is_err());
        assert!(serde_json::from_str::<Policy>(r#"{"threshold": "off"}"#).is_err());
    }
}
