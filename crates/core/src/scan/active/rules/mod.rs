//! Active rules, ported from ZAP's ascanrules add-on (Apache License 2.0).

mod crlf_injection;
pub(crate) mod env_file;
mod probes;

use crate::scan::active::ActiveRule;

pub fn all() -> Vec<Box<dyn ActiveRule>> {
    let mut rules: Vec<Box<dyn ActiveRule>> =
        vec![Box::new(crlf_injection::CrlfInjection), Box::new(env_file::EnvFile)];
    rules.extend(probes::all());
    rules
}
