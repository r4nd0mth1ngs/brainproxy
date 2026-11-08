//! `scan policy`: saved scan policies (which active rules run, at what strength and
//! threshold), used with `scan active --policy NAME`.

use std::io::Read;
use std::path::Path;

use brainproxy_core::scan::active::policy::Policy;
use brainproxy_core::scan::active::{self, Strength, Threshold};
use brainproxy_core::store::Store;
use brainproxy_core::Error;
use clap::ValueEnum;
use serde_json::{json, Value};

use crate::active_cmd::StrengthArg;
use crate::output::Out;

#[derive(clap::Subcommand)]
pub enum PolicyCmd {
    /// Every saved scan policy.
    List,
    /// One policy, with every active rule as it runs it.
    Show { name: String },
    /// Save a policy under NAME (replacing one of that name; through MCP only a new name), from
    /// these flags, on top of --from's or --json's when given.
    #[command(after_help = "A threshold is how sure a rule must be to raise a finding, against the confidence \
        the rule gives it: low raises every finding, medium those of medium or high confidence, high only \
        high-confidence ones. A finding below it isn't raised (the scan counts it in below_threshold); the \
        attacks sent are the same. A rule's own --rule-strength or --rule-threshold wins over the policy's. \
        JSON: {\"enabled\": true, \"strength\": \"medium\", \"threshold\": \"low\", \"rules\": {\"40018\": \
        {\"enabled\": true, \"strength\": \"high\", \"threshold\": \"medium\"}}}, every field optional.")]
    Save {
        name: String,
        #[command(flatten)]
        flags: PolicyFlags,
    },
    /// Remove a saved policy; a person does this, not through MCP.
    Remove { name: String },
}

#[derive(clap::Args)]
pub struct PolicyFlags {
    /// Start from this saved policy (default: every rule on, strength medium, threshold low).
    #[arg(long, value_name = "POLICY", conflicts_with = "json")]
    from: Option<String>,
    /// Start from this policy, as JSON (see below), or - to read it from stdin.
    #[arg(long, value_name = "JSON")]
    json: Option<String>,
    /// Strength of the rules without one of their own.
    #[arg(long, value_enum)]
    strength: Option<StrengthArg>,
    /// Threshold of the rules without one of their own.
    #[arg(long, value_enum)]
    threshold: Option<ThresholdArg>,
    /// Whether the rules the policy doesn't turn on or off run [default: on]; off runs only
    /// those --enable names.
    #[arg(long, value_parser = ["on", "off"])]
    others: Option<String>,
    /// Turn these rule ids on (comma-separated).
    #[arg(long, value_delimiter = ',', value_name = "IDS")]
    enable: Vec<u32>,
    /// Turn these rule ids off (comma-separated).
    #[arg(long, value_delimiter = ',', value_name = "IDS")]
    disable: Vec<u32>,
    /// A rule's own strength, ID=STRENGTH (e.g. 40018=insane). Repeatable or comma-separated.
    #[arg(long, value_delimiter = ',', value_name = "ID=STRENGTH")]
    rule_strength: Vec<String>,
    /// A rule's own threshold, ID=THRESHOLD (e.g. 40012=high). Repeatable or comma-separated.
    #[arg(long, value_delimiter = ',', value_name = "ID=THRESHOLD")]
    rule_threshold: Vec<String>,
    /// Drop these rules' own settings, so they take the policy's (applied before the flags above).
    #[arg(long, value_delimiter = ',', value_name = "IDS")]
    reset: Vec<u32>,
}

#[derive(Clone, Copy, ValueEnum, Debug, PartialEq)]
pub enum ThresholdArg {
    Low,
    Medium,
    High,
}

impl ThresholdArg {
    pub fn get(self) -> Threshold {
        match self {
            ThresholdArg::Low => Threshold::Low,
            ThresholdArg::Medium => Threshold::Medium,
            ThresholdArg::High => Threshold::High,
        }
    }
}

impl StrengthArg {
    pub fn get(self) -> Strength {
        match self {
            StrengthArg::Low => Strength::Low,
            StrengthArg::Medium => Strength::Medium,
            StrengthArg::High => Strength::High,
            StrengthArg::Insane => Strength::Insane,
        }
    }
}

/// `ID=VALUE` pairs, the value one of a ValueEnum's.
fn pairs<T: ValueEnum>(flag: &str, given: &[String]) -> Result<Vec<(u32, T)>, Error> {
    given
        .iter()
        .map(|p| {
            let bad = || Error::InvalidInput(format!("{flag} {p:?}: expected ID=VALUE, e.g. 40018=high"));
            let (id, v) = p.split_once('=').ok_or_else(bad)?;
            let id: u32 = id.trim().parse().map_err(|_| bad())?;
            let v = T::from_str(v.trim(), true).map_err(|_| bad())?;
            Ok((id, v))
        })
        .collect()
}

impl PolicyFlags {
    /// The policy these flags make, from `base`.
    fn apply(&self, mut p: Policy) -> Result<Policy, Error> {
        for id in &self.reset {
            p.rules.remove(id);
        }
        if let Some(s) = self.strength {
            p.strength = s.get();
        }
        if let Some(t) = self.threshold {
            p.threshold = t.get();
        }
        if let Some(o) = &self.others {
            p.enabled = o == "on";
        }
        if let Some(id) = self.enable.iter().find(|id| self.disable.contains(id)) {
            return Err(Error::InvalidInput(format!("rule {id} is both in --enable and --disable")));
        }
        for &id in &self.enable {
            p.rules.entry(id).or_default().enabled = Some(true);
        }
        for &id in &self.disable {
            p.rules.entry(id).or_default().enabled = Some(false);
        }
        for (id, s) in pairs::<StrengthArg>("--rule-strength", &self.rule_strength)? {
            p.rules.entry(id).or_default().strength = Some(s.get());
        }
        for (id, t) in pairs::<ThresholdArg>("--rule-threshold", &self.rule_threshold)? {
            p.rules.entry(id).or_default().threshold = Some(t.get());
        }
        p.validate()
    }
}

/// Reads `--json`: inline, or `-` for stdin.
fn read_json(given: &str) -> Result<Policy, Error> {
    let text = if given == "-" {
        let mut s = String::new();
        std::io::stdin().take(1 << 20).read_to_string(&mut s)?;
        s
    } else {
        given.to_string()
    };
    serde_json::from_str(&text).map_err(|e| Error::InvalidInput(format!("--json: {e}")))
}

/// A policy as shown: its settings, and how many rules it turns off.
fn summary(name: &str, p: &Policy) -> Value {
    json!({
        "name": name,
        "enabled": p.enabled,
        "strength": p.strength,
        "threshold": p.threshold,
        "rules": p.rules,
        "rules_enabled": p.enabled_rules().len(),
        "rules_disabled": p.disabled().len(),
    })
}

/// Every active rule as the policy runs it.
fn rule_table(p: &Policy) -> Vec<Value> {
    let mut rules: Vec<_> = active::all_rules().iter().collect();
    rules.sort_by_key(|r| r.id());
    rules
        .iter()
        .map(|r| {
            let e = p.effective(r.id());
            json!({"id": r.id(), "name": r.name(), "enabled": e.enabled, "strength": e.strength,
                "threshold": e.threshold, "own": p.rules.contains_key(&r.id())})
        })
        .collect()
}

fn text_line(v: &Value) -> String {
    format!(
        "{}  {} rules on, {} off; strength {}, threshold {}{}",
        v["name"].as_str().unwrap_or(""),
        v["rules_enabled"],
        v["rules_disabled"],
        v["strength"].as_str().unwrap_or(""),
        v["threshold"].as_str().unwrap_or(""),
        match v["rules"].as_object().map(|m| m.len()).unwrap_or(0) {
            0 => String::new(),
            n => format!("; {n} rule(s) with their own settings"),
        }
    )
}

pub fn policy(project: &Path, cmd: PolicyCmd, out: &Out) -> Result<(), Error> {
    let mut store = Store::open(project)?;
    match cmd {
        PolicyCmd::List => {
            let list: Vec<Value> = store.scan_policies()?.iter().map(|(n, p)| summary(n, p)).collect();
            out.ok(json!({"policies": list}), || {
                if list.is_empty() {
                    "no saved scan policies (scan policy save NAME)".into()
                } else {
                    list.iter().map(text_line).collect::<Vec<_>>().join("\n")
                }
            });
        }
        PolicyCmd::Show { name } => {
            let p = store.scan_policy(&name)?;
            let mut v = summary(&name, &p);
            v["rule_table"] = json!(rule_table(&p));
            out.ok(v.clone(), || {
                let mut lines = vec![text_line(&v)];
                for r in v["rule_table"].as_array().into_iter().flatten() {
                    lines.push(format!(
                        "{:>6}  {:<3} {:<7} {:<6} {}{}",
                        r["id"],
                        if r["enabled"] == true { "on" } else { "off" },
                        r["strength"].as_str().unwrap_or(""),
                        r["threshold"].as_str().unwrap_or(""),
                        r["name"].as_str().unwrap_or(""),
                        if r["own"] == true { "  *" } else { "" }
                    ));
                }
                lines.join("\n")
            });
        }
        PolicyCmd::Save { name, flags } => {
            let base = match (&flags.from, &flags.json) {
                (Some(from), _) => store.scan_policy(from)?,
                (None, Some(j)) => read_json(j)?,
                (None, None) => Policy::default(),
            };
            let p = flags.apply(base)?;
            // A saved policy may be a person's: an agent adds new ones only.
            let replace = !crate::mcp::in_tool_call();
            store.scan_policy_save(&name, &p, replace).map_err(|e| match e {
                Error::Conflict(_) if !replace => Error::Conflict(format!(
                    "scan policy {name:?} exists; through MCP a policy is saved under a new name, and a person \
                     replaces or removes one in the app or a terminal"
                )),
                e => e,
            })?;
            let v = summary(&name, &p);
            out.ok(v.clone(), || format!("saved scan policy {}", text_line(&v)));
        }
        PolicyCmd::Remove { name } => {
            if crate::mcp::in_tool_call() {
                return Err(Error::InvalidInput(
                    "scan policy remove is refused through MCP: a saved policy may be a person's; save a new name \
                     instead"
                        .into(),
                ));
            }
            store.scan_policy_remove(&name)?;
            out.ok(json!({"name": name, "removed": true}), || format!("removed scan policy {name}"));
        }
    }
    Ok(())
}

/// How `scan active` runs with --policy and its flags: which rules (for `ActiveConfig::rules`
/// and `exclude_rules`), at what strength and thresholds, and what the result says about it.
pub struct Applied {
    pub strength: Strength,
    pub tuning: active::Tuning,
    pub rules: Option<Vec<u32>>,
    pub exclude_rules: Vec<u32>,
    /// The result's `policy`; None without --policy.
    pub shown: Option<Value>,
}

/// Explicit flags win over the policy: --strength and --threshold apply to every rule (their
/// own settings in the policy too), --rules picks the rules the policy would have, and
/// --exclude-rules adds to the ones it turns off. `preset` is --preset's strength, which the
/// policy's wins over.
pub fn apply(
    policy: Option<(&str, &Policy)>,
    strength: Option<StrengthArg>,
    preset: Option<StrengthArg>,
    threshold: Option<ThresholdArg>,
    rules: &[u32],
    exclude_rules: &[u32],
) -> Applied {
    let flag_rules = (!rules.is_empty()).then(|| rules.to_vec());
    let Some((name, p)) = policy else {
        return Applied {
            strength: strength.or(preset).unwrap_or(StrengthArg::Medium).get(),
            tuning: active::Tuning {
                threshold: threshold.map_or(Threshold::Low, ThresholdArg::get),
                ..Default::default()
            },
            rules: flag_rules,
            exclude_rules: exclude_rules.to_vec(),
            shown: None,
        };
    };
    let mut tuning = p.tuning();
    if strength.is_some() {
        tuning.rules.values_mut().for_each(|t| t.strength = None);
    }
    if let Some(t) = threshold {
        tuning.threshold = t.get();
        tuning.rules.values_mut().for_each(|r| r.threshold = None);
    }
    tuning.rules.retain(|_, t| t.strength.is_some() || t.threshold.is_some());
    // The rules it turns off by name are excluded; with others off, the ones it turns on are the
    // rules (so the rules they depend on still run, as with --rules).
    let turned_off: Vec<u32> = p.rules.iter().filter(|(_, s)| s.enabled == Some(false)).map(|(&id, _)| id).collect();
    let (sel, mut exclude) = match flag_rules {
        Some(r) => (Some(r), vec![]),
        None if p.enabled => (None, turned_off),
        None => (Some(p.enabled_rules()), turned_off),
    };
    for id in exclude_rules {
        if !exclude.contains(id) {
            exclude.push(*id);
        }
    }
    let overridden: Vec<&str> = [
        ("--strength", strength.is_some()),
        ("--threshold", threshold.is_some()),
        ("--rules", !rules.is_empty()),
        ("--exclude-rules", !exclude_rules.is_empty()),
    ]
    .into_iter()
    .filter_map(|(flag, given)| given.then_some(flag))
    .collect();
    let strength = strength.map(StrengthArg::get).unwrap_or(p.strength);
    // What ran differently from the default: for comparing findings with the scan.
    let rule_strengths: serde_json::Map<String, Value> =
        tuning.rules.iter().filter_map(|(id, t)| t.strength.map(|s| (id.to_string(), json!(s)))).collect();
    let rule_thresholds: serde_json::Map<String, Value> =
        tuning.rules.iter().filter_map(|(id, t)| t.threshold.map(|s| (id.to_string(), json!(s)))).collect();
    let mut shown = json!({
        "name": name,
        "strength": strength,
        "threshold": tuning.threshold,
        "rule_strengths": rule_strengths,
        "rule_thresholds": rule_thresholds,
        "flags_over_policy": overridden,
    });
    if let Some(r) = &sel {
        shown["rules"] = json!(r);
    }
    shown["exclude_rules"] = json!(exclude);
    Applied { strength, tuning, rules: sel, exclude_rules: exclude, shown: Some(shown) }
}

#[cfg(test)]
mod tests {
    use super::*;
    use brainproxy_core::scan::active::policy::RuleSetting;

    fn policy() -> Policy {
        let mut p = Policy { strength: Strength::High, threshold: Threshold::Medium, ..Default::default() };
        p.rules.insert(
            40018,
            RuleSetting { strength: Some(Strength::Insane), threshold: Some(Threshold::High), ..Default::default() },
        );
        p.rules.insert(40012, RuleSetting { enabled: Some(false), ..Default::default() });
        p
    }

    #[test]
    fn a_policy_sets_the_rules_strength_and_thresholds() {
        let p = policy();
        let a = apply(Some(("deep", &p)), None, Some(StrengthArg::Low), None, &[], &[]);
        assert_eq!(a.strength, Strength::High, "the policy's strength wins over --preset's");
        assert_eq!((a.rules, a.exclude_rules.as_slice()), (None, &[40012][..]));
        assert_eq!(a.tuning.threshold, Threshold::Medium);
        assert_eq!(a.tuning.strength(40018, a.strength), Strength::Insane);
        assert_eq!(a.tuning.threshold(40018), Threshold::High);
        let shown = a.shown.unwrap();
        assert_eq!(shown["name"], "deep");
        assert_eq!(shown["rule_thresholds"]["40018"], "high");
        assert_eq!(shown["flags_over_policy"], json!([]));
    }

    #[test]
    fn flags_win_over_the_policy() {
        let p = policy();
        let a = apply(Some(("deep", &p)), Some(StrengthArg::Low), None, Some(ThresholdArg::Low), &[40012], &[40014]);
        assert_eq!(a.strength, Strength::Low);
        assert!(a.tuning.rules.is_empty(), "{:?}", a.tuning);
        assert_eq!(a.tuning.threshold, Threshold::Low);
        assert_eq!(a.rules, Some(vec![40012]), "--rules runs a rule the policy turns off");
        assert_eq!(a.exclude_rules, [40014]);
        let shown = a.shown.unwrap();
        assert_eq!(shown["flags_over_policy"], json!(["--strength", "--threshold", "--rules", "--exclude-rules"]));
    }

    #[test]
    fn a_policy_with_others_off_runs_the_rules_it_turns_on() {
        let p = Policy {
            enabled: false,
            rules: [(40014, RuleSetting { enabled: Some(true), ..Default::default() })].into(),
            ..Default::default()
        };
        let a = apply(Some(("xss", &p)), None, None, None, &[], &[40016]);
        assert_eq!(a.rules, Some(vec![40014]));
        assert_eq!(a.exclude_rules, [40016]);
    }

    #[test]
    fn without_a_policy_the_flags_are_as_before() {
        let a = apply(None, None, Some(StrengthArg::Insane), None, &[1], &[]);
        assert_eq!((a.strength, a.rules, a.tuning), (Strength::Insane, Some(vec![1]), active::Tuning::default()));
        assert!(a.shown.is_none());
        assert_eq!(apply(None, None, None, None, &[], &[]).strength, Strength::Medium);
    }

    #[test]
    fn save_flags_build_a_policy() {
        use clap::Parser;
        #[derive(Parser)]
        struct T {
            #[command(flatten)]
            f: PolicyFlags,
        }
        let t = T::parse_from([
            "t",
            "--strength=high",
            "--threshold=medium",
            "--disable=40012,40014",
            "--rule-strength=40018=insane,40014=high",
            "--rule-threshold=40018=medium",
        ]);
        let p = t.f.apply(Policy::default()).unwrap();
        assert_eq!((p.strength, p.threshold), (Strength::High, Threshold::Medium));
        assert_eq!(p.rules[&40012], RuleSetting { enabled: Some(false), ..Default::default() });
        let own =
            RuleSetting { strength: Some(Strength::Insane), threshold: Some(Threshold::Medium), ..Default::default() };
        assert_eq!(p.rules[&40018], own);
        assert_eq!(
            p.rules[&40014],
            RuleSetting { enabled: Some(false), strength: Some(Strength::High), ..Default::default() }
        );
        let t = T::parse_from(["t", "--reset=40014", "--others=off", "--enable=40018"]);
        let p = t.f.apply(p).unwrap();
        assert!(!p.enabled && !p.rules.contains_key(&40014));
        assert_eq!(p.rules[&40018].enabled, Some(true));
        assert_eq!(p.rules[&40012].enabled, Some(false));
        assert_eq!(p.enabled_rules(), [40018]);
        assert!(T::parse_from(["t", "--rule-strength=40018"]).f.apply(Policy::default()).is_err());
        assert!(T::parse_from(["t", "--enable=1"]).f.apply(Policy::default()).is_err());
        assert!(T::parse_from(["t", "--enable=40018", "--disable=40018"]).f.apply(Policy::default()).is_err());
    }
}
