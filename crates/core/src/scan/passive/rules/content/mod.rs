//! Response body content rules, ported from ZAP's pscanrules add-on (Apache License 2.0).

mod application_error;
mod common;
mod cross_domain_script;
mod debug_errors;
mod directory_browsing;
mod hash_disclosure;
mod in_page_banner;
mod jso;
mod link_target;
mod modern_app;
mod pii;
mod polyfill_cdn;
mod private_address;
mod sri_missing;
mod suspicious_comments;
mod timestamp;

use crate::scan::PassiveRule;

pub fn all() -> Vec<Box<dyn PassiveRule>> {
    vec![
        Box::new(private_address::PrivateAddress),
        Box::new(in_page_banner::InPageBanner),
        Box::new(cross_domain_script::CrossDomainScript),
        Box::new(debug_errors::DebugErrors),
        Box::new(suspicious_comments::SuspiciousComments),
        Box::new(directory_browsing::DirectoryBrowsing),
        Box::new(pii::Pii),
        Box::new(timestamp::Timestamp),
        Box::new(hash_disclosure::HashDisclosure),
        Box::new(link_target::LinkTarget),
        Box::new(modern_app::ModernApp),
        Box::new(polyfill_cdn::PolyfillCdn),
        Box::new(jso::Jso),
        Box::new(sri_missing::SriMissing),
        Box::new(application_error::ApplicationError),
    ]
}
