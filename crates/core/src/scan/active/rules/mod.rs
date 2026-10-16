//! Active rules, ported from ZAP's ascanrules add-on (Apache License 2.0).

mod crlf_injection;
mod env_file;

use crate::scan::active::ActiveRule;

pub fn all() -> Vec<Box<dyn ActiveRule>> {
    vec![Box::new(crlf_injection::CrlfInjection), Box::new(env_file::EnvFile)]
}
