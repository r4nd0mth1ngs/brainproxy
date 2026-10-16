//! Cookie, parameter, reflection and form rules ported from ZAP's pscanrules
//! add-on (Apache License 2.0).

mod common;
mod cookie_loosely_scoped;
mod cookie_poisoning;
mod cookie_same_site;
mod cookie_secure_flag;
mod csrf_countermeasures;
mod html_attributes;
mod info_disclosure_referrer;
mod info_disclosure_url;
mod insecure_form_load;
mod insecure_form_post;
mod javascript_event;
mod mixed_content;
mod open_redirect;
mod session_id_url;
mod user_controlled_charset;

use crate::scan::PassiveRule;

pub fn all() -> Vec<Box<dyn PassiveRule>> {
    vec![
        Box::new(session_id_url::InfoSessionIdUrl),
        Box::new(cookie_secure_flag::CookieSecureFlag),
        Box::new(info_disclosure_url::InformationDisclosureInUrl),
        Box::new(info_disclosure_referrer::InformationDisclosureReferrer),
        Box::new(open_redirect::UserControlledOpenRedirect),
        Box::new(cookie_poisoning::UserControlledCookie),
        Box::new(user_controlled_charset::UserControlledCharset),
        Box::new(html_attributes::UserControlledHtmlAttributes),
        Box::new(mixed_content::MixedContent),
        Box::new(insecure_form_load::InsecureFormLoad),
        Box::new(insecure_form_post::InsecureFormPost),
        Box::new(javascript_event::UserControlledJavascriptEvent),
        Box::new(cookie_same_site::CookieSameSite),
        Box::new(csrf_countermeasures::CsrfCountermeasures),
        Box::new(cookie_loosely_scoped::CookieLooselyScoped),
    ]
}
