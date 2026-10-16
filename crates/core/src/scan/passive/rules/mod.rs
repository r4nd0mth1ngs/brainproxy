//! Passive rules, ported from ZAP's pscanrules add-on (Apache License 2.0).

mod cookie_http_only;
mod params;

use crate::scan::PassiveRule;

pub fn all() -> Vec<Box<dyn PassiveRule>> {
    let mut rules: Vec<Box<dyn PassiveRule>> = vec![Box::new(cookie_http_only::CookieHttpOnly)];
    rules.extend(params::all());
    rules
}
