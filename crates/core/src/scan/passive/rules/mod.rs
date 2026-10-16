//! Passive rules, ported from ZAP's pscanrules add-on (Apache License 2.0).

use crate::scan::PassiveRule;

pub fn all() -> Vec<Box<dyn PassiveRule>> {
    vec![]
}
