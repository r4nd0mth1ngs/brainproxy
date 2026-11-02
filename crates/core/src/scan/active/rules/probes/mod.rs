//! Page- and host-level probe rules, ported from ZAP's ascanrules and ascanrulesBeta
//! add-ons (Apache License 2.0). These send extra requests to fixed paths or forge
//! headers rather than fuzzing the base request's parameters.

mod cloud_metadata;
mod common;
mod cors;
mod directory_browsing;
mod elmah;
mod entity_expansion;
mod get_for_post;
mod heartbleed;
pub(crate) mod hidden_files;
mod htaccess;
mod http_only_site;
mod https_as_http;
mod php2shell;
mod rce_cve_2012_1823;
mod react2shell;
mod shellshock;
mod source_disclosure_cve_2012_1823;
mod source_disclosure_webinf;
mod spring4shell;
mod spring_actuator;
mod trace_axd;
mod user_agent;

use crate::scan::active::ActiveRule;

pub fn all() -> Vec<Box<dyn ActiveRule>> {
    vec![
        Box::new(cloud_metadata::CloudMetadata),
        Box::new(cors::Cors),
        Box::new(directory_browsing::DirectoryBrowsing),
        Box::new(elmah::Elmah),
        Box::new(entity_expansion::EntityExpansion),
        Box::new(get_for_post::GetForPost),
        Box::new(heartbleed::HeartBleed),
        Box::new(hidden_files::HiddenFilesRule),
        Box::new(htaccess::HtAccess),
        Box::new(http_only_site::HttpOnlySite),
        Box::new(https_as_http::HttpsAsHttp),
        Box::new(rce_cve_2012_1823::RceCve20121823),
        Box::new(php2shell::Php2Shell),
        Box::new(react2shell::React2Shell),
        Box::new(shellshock::ShellShock),
        Box::new(source_disclosure_cve_2012_1823::SourceDisclosureCve20121823),
        Box::new(source_disclosure_webinf::SourceDisclosureWebInf),
        Box::new(spring4shell::Spring4Shell),
        Box::new(spring_actuator::SpringActuator),
        Box::new(trace_axd::TraceAxd),
        Box::new(user_agent::UserAgent),
    ]
}
