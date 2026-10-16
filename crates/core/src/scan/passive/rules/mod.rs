//! Passive rules, ported from ZAP's pscanrules add-on (Apache License 2.0).

mod content;
mod cookie_http_only;

use crate::scan::PassiveRule;

pub fn all() -> Vec<Box<dyn PassiveRule>> {
    let mut rules: Vec<Box<dyn PassiveRule>> = vec![Box::new(cookie_http_only::CookieHttpOnly)];
    rules.extend(content::all());
    rules
}
