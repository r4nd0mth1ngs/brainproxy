//! HTTP header rules, ported from ZAP's pscanrules add-on (Apache License 2.0).

mod anti_clickjacking;
mod big_redirects;
mod cache_control;
pub(crate) mod common;
mod content_security_policy;
mod content_type_missing;
mod cross_domain_misconfiguration;
mod csp_missing;
mod heartbleed;
mod insecure_authentication;
mod retrieved_from_cache;
mod server_header;
mod strict_transport_security;
mod x_aspnet_version;
mod x_backend_server;
mod x_chrome_logger_data;
mod x_content_type_options;
mod x_debug_token;
mod x_powered_by;

use crate::scan::PassiveRule;

pub fn all() -> Vec<Box<dyn PassiveRule>> {
    vec![
        Box::new(x_backend_server::XBackendServer),
        Box::new(x_aspnet_version::XAspNetVersion),
        Box::new(content_type_missing::ContentTypeMissing),
        Box::new(cache_control::CacheControl),
        Box::new(x_content_type_options::XContentTypeOptions),
        Box::new(server_header::ServerHeader),
        Box::new(x_chrome_logger_data::XChromeLoggerData),
        Box::new(x_powered_by::XPoweredBy),
        Box::new(x_debug_token::XDebugToken),
        Box::new(anti_clickjacking::AntiClickjacking),
        Box::new(strict_transport_security::StrictTransportSecurity),
        Box::new(csp_missing::CspMissing),
        Box::new(content_security_policy::ContentSecurityPolicy),
        Box::new(cross_domain_misconfiguration::CrossDomainMisconfiguration),
        Box::new(retrieved_from_cache::RetrievedFromCache),
        Box::new(big_redirects::BigRedirects),
        Box::new(heartbleed::HeartBleed),
        Box::new(insecure_authentication::InsecureAuthentication),
    ]
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    #[test]
    fn rule_ids_and_alert_refs_are_unique() {
        let rules = super::all();
        let ids: HashSet<u32> = rules.iter().map(|r| r.id()).collect();
        assert_eq!(ids.len(), 18);
        let mut seen = HashSet::new();
        for r in &rules {
            for a in r.alerts() {
                assert!(a.alert_ref.starts_with(&r.id().to_string()), "{}", a.alert_ref);
                assert!(seen.insert(a.alert_ref), "duplicate {}", a.alert_ref);
                assert!(!a.tags.iter().any(|t| ["PENTEST", "DEV-STD", "QA-STD"].contains(t)));
            }
        }
    }
}
