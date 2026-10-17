//! Response body content rules, ported from ZAP's pscanrules add-on (Apache License 2.0).

pub(crate) mod application_error;
mod charset_mismatch;
mod common;
mod cross_domain_script;
pub(crate) mod debug_errors;
mod directory_browsing;
mod hash_disclosure;
mod in_page_banner;
mod jsf_viewstate;
mod jso;
mod link_target;
mod modern_app;
mod pii;
mod polyfill_cdn;
mod private_address;
mod sri_missing;
mod suspicious_comments;
mod timestamp;
mod viewstate;

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
        Box::new(charset_mismatch::CharsetMismatch),
        Box::new(viewstate::Viewstate),
        Box::new(jsf_viewstate::InsecureJsfViewState),
    ]
}
