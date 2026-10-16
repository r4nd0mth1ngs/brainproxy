//! Ported from ZAP ContentSecurityPolicyScanRule (pscanrules, Apache License 2.0).
//!
//! ZAP delegates parsing and policy evaluation to the htmlunit-csp library; this
//! is a self-contained, simplified equivalent: serialized CSP lists are parsed
//! into directives, enforced policies (headers and `<meta>`) are intersected the
//! way browsers do, and fetch directives are resolved through the CSP fallback
//! chains. Parser notices mimic the library's messages where they are known.

use super::common::{header_name_as_spelled, header_values, meta_tags};
use crate::scan::{AlertDef, Confidence, Finding, Message, PassiveRule, Risk};

const TAGS: &[&str] = &["OWASP_2025_A02", "OWASP_2021_A05", "OWASP_2017_A06", "SYSTEMIC"];
const DESC: &str = "Content Security Policy (CSP) is an added layer of security that helps to detect and mitigate \
    certain types of attacks. Including (but not limited to) Cross Site Scripting (XSS), and data injection attacks. \
    These attacks are used for everything from data theft to site defacement or distribution of malware. CSP \
    provides a set of standard HTTP headers that allow website owners to declare approved sources of content that \
    browsers should be allowed to load on that page \u{2014} covered types are JavaScript, CSS, HTML frames, fonts, \
    images and embeddable objects such as Java applets, ActiveX, audio and video files.";
const SOLN: &str = "Ensure that your web server, application server, load balancer, etc. is properly configured to \
    set the Content-Security-Policy header.";
const REFS: &[&str] = &[
    "https://www.w3.org/TR/CSP/",
    "https://caniuse.com/#search=content+security+policy",
    "https://content-security-policy.com/",
    "https://github.com/HtmlUnit/htmlunit-csp",
    "https://web.dev/articles/csp#resource-options",
];

macro_rules! csp_alert {
    ($ref:literal, $name:literal, $risk:expr) => {
        csp_alert!($ref, $name, $risk, DESC, REFS)
    };
    ($ref:literal, $name:literal, $risk:expr, $desc:expr, $refs:expr) => {
        AlertDef {
            alert_ref: $ref,
            name: $name,
            risk: $risk,
            confidence: Confidence::High,
            cwe: 693,
            wasc: 15,
            description: $desc,
            solution: SOLN,
            references: $refs,
            tags: TAGS,
        }
    };
}

static XCSP: AlertDef = csp_alert!("10055-1", "CSP: X-Content-Security-Policy", Risk::Low);
static XWKCSP: AlertDef = csp_alert!("10055-2", "CSP: X-WebKit-CSP", Risk::Low);
static NOTICES: AlertDef = csp_alert!("10055-3", "CSP: Notices", Risk::Low);
static WILDCARD: AlertDef = csp_alert!("10055-4", "CSP: Wildcard Directive", Risk::Medium);
static SCRIPT_UNSAFE_INLINE: AlertDef = csp_alert!("10055-5", "CSP: script-src unsafe-inline", Risk::Medium);
static STYLE_UNSAFE_INLINE: AlertDef = csp_alert!("10055-6", "CSP: style-src unsafe-inline", Risk::Medium);
static SCRIPT_UNSAFE_HASHES: AlertDef = csp_alert!(
    "10055-7",
    "CSP: script-src unsafe-hashes",
    Risk::Medium,
    DESC,
    &[
        "https://www.w3.org/TR/CSP3/#unsafe-hashes-usage",
        "https://content-security-policy.com/examples/allow-inline-script/",
    ]
);
static STYLE_UNSAFE_HASHES: AlertDef = csp_alert!(
    "10055-8",
    "CSP: style-src unsafe-hashes",
    Risk::Medium,
    DESC,
    &[
        "https://www.w3.org/TR/CSP3/#unsafe-hashes-usage",
        "https://content-security-policy.com/examples/allow-inline-style/"
    ]
);
static MALFORMED: AlertDef = csp_alert!("10055-9", "CSP: Malformed Policy (Non-ASCII)", Risk::Medium);
static SCRIPT_UNSAFE_EVAL: AlertDef = csp_alert!("10055-10", "CSP: script-src unsafe-eval", Risk::Medium);
static META_BAD_DIRECTIVE: AlertDef = csp_alert!(
    "10055-11",
    "CSP: Meta Policy Invalid Directive",
    Risk::Medium,
    "The policy specified via meta element contains either or both the sandbox or frame-ancestors directive, which \
        are not permitted inside meta CSP definitions.",
    REFS
);
static NO_FALLBACK: AlertDef = csp_alert!(
    "10055-13",
    "CSP: Failure to Define Directive with No Fallback",
    Risk::Medium,
    "The Content Security Policy fails to define one of the directives that has no fallback. Missing/excluding them \
        is the same as allowing anything.",
    REFS
);

static ALERTS: [&AlertDef; 12] = [
    &XCSP,
    &XWKCSP,
    &NOTICES,
    &WILDCARD,
    &SCRIPT_UNSAFE_INLINE,
    &STYLE_UNSAFE_INLINE,
    &SCRIPT_UNSAFE_HASHES,
    &STYLE_UNSAFE_HASHES,
    &MALFORMED,
    &SCRIPT_UNSAFE_EVAL,
    &META_BAD_DIRECTIVE,
    &NO_FALLBACK,
];

const CSP: &str = "Content-Security-Policy";
const XCSP_HEADER: &str = "X-Content-Security-Policy";
const XWKCSP_HEADER: &str = "X-WebKit-CSP";
const DIRECTIVES_WITHOUT_FALLBACK: [&str; 2] = ["form-action", "frame-ancestors"];
/// Directives that have no effect when the policy is delivered via `<meta>`.
const META_IGNORED: [&str; 3] = ["frame-ancestors", "report-uri", "sandbox"];

const KNOWN_DIRECTIVES: &[&str] = &[
    "base-uri",
    "block-all-mixed-content",
    "child-src",
    "connect-src",
    "default-src",
    "fenced-frame-src",
    "font-src",
    "form-action",
    "frame-ancestors",
    "frame-src",
    "img-src",
    "manifest-src",
    "media-src",
    "navigate-to",
    "object-src",
    "plugin-types",
    "prefetch-src",
    "report-to",
    "report-uri",
    "require-sri-for",
    "require-trusted-types-for",
    "sandbox",
    "script-src",
    "script-src-attr",
    "script-src-elem",
    "style-src",
    "style-src-attr",
    "style-src-elem",
    "trusted-types",
    "upgrade-insecure-requests",
    "webrtc",
    "worker-src",
];

/// Directives whose value is a source list.
fn is_source_list_directive(name: &str) -> bool {
    name.ends_with("-src")
        || name.ends_with("-src-elem")
        || name.ends_with("-src-attr")
        || matches!(name, "base-uri" | "form-action" | "frame-ancestors" | "navigate-to")
}

const UNQUOTED_KEYWORDS: &[&str] = &[
    "none",
    "self",
    "unsafe-inline",
    "unsafe-eval",
    "strict-dynamic",
    "unsafe-hashes",
    "report-sample",
    "unsafe-allow-redirects",
    "wasm-unsafe-eval",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Severity {
    Error,
    Warning,
    Info,
}

#[derive(Debug)]
struct Directive {
    name: String,
    values: Vec<String>,
}

impl Directive {
    fn has_keyword(&self, kw: &str) -> bool {
        self.values.iter().any(|v| v.eq_ignore_ascii_case(kw))
    }

    fn has_nonce(&self) -> bool {
        self.values.iter().any(|v| is_quoted_with_prefix(v, &["'nonce-"]))
    }

    fn hashes(&self) -> Vec<(String, &str)> {
        self.values
            .iter()
            .filter(|v| is_quoted_with_prefix(v, &["'sha256-", "'sha384-", "'sha512-"]))
            .map(|v| (v[1..7].to_ascii_lowercase(), &v[8..v.len() - 1]))
            .collect()
    }
}

fn is_quoted_with_prefix(v: &str, prefixes: &[&str]) -> bool {
    v.len() > 9
        && v.ends_with('\'')
        && prefixes.iter().any(|p| v.as_bytes()[..p.len()].eq_ignore_ascii_case(p.as_bytes()))
}

#[derive(Debug)]
struct Policy {
    directives: Vec<Directive>,
    meta: bool,
}

impl Policy {
    fn get(&self, name: &str) -> Option<&Directive> {
        if self.meta && META_IGNORED.contains(&name) {
            return None;
        }
        self.directives.iter().find(|d| d.name == name)
    }

    /// The first directive of the fallback chain that the policy defines.
    fn governing(&self, chain: &[&str]) -> Option<&Directive> {
        chain.iter().find_map(|n| self.get(n))
    }

    fn declares(&self, name: &str) -> bool {
        self.directives.iter().any(|d| d.name == name)
    }
}

fn is_csp_whitespace(c: char) -> bool {
    matches!(c, ' ' | '\t' | '\n' | '\x0c' | '\r')
}

/// Parses one serialized policy, collecting parser notices.
fn parse_policy(text: &str, meta: bool, notices: &mut Vec<(Severity, String)>) -> Policy {
    let mut directives: Vec<Directive> = Vec::new();
    for raw in text.split(';') {
        let token = raw.trim_matches(is_csp_whitespace);
        if token.is_empty() {
            continue;
        }
        let mut parts = token.split(is_csp_whitespace).filter(|s| !s.is_empty());
        let name = parts.next().unwrap_or_default().to_ascii_lowercase();
        let values: Vec<String> = parts.map(str::to_string).collect();
        if !name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-') {
            notices.push((
                Severity::Error,
                format!("Directive name {name} contains characters outside the range ALPHA / DIGIT / \"-\""),
            ));
            continue;
        }
        if directives.iter().any(|d| d.name == name) {
            notices.push((Severity::Warning, format!("Duplicate directive {name}")));
            continue;
        }
        check_directive(&name, &values, meta, notices);
        directives.push(Directive { name, values });
    }
    Policy { directives, meta }
}

fn check_directive(name: &str, values: &[String], meta: bool, notices: &mut Vec<(Severity, String)>) {
    if !KNOWN_DIRECTIVES.contains(&name) {
        notices.push((Severity::Warning, format!("Unrecognized directive {name}")));
        return;
    }
    if meta && META_IGNORED.contains(&name) {
        notices.push((Severity::Warning, format!("The {name} directive is not supported inside a <meta> element")));
    }
    match name {
        "prefetch-src" => {
            notices.push((Severity::Warning, "The prefetch-src directive has been deprecated".into()));
        }
        "report-uri" => notices.push((
            Severity::Info,
            "A draft of the next version of CSP deprecates report-uri in favour of a new report-to directive".into(),
        )),
        "trusted-types" => {
            if values.is_empty() {
                notices.push((Severity::Warning, "Empty trusted-types directive allows all policy names".into()));
            } else if values.iter().any(|v| v == "*") {
                notices.push((Severity::Warning, "Wildcard policy names (*) permit any policy name".into()));
            }
        }
        "require-trusted-types-for" if values.is_empty() => {
            notices.push((Severity::Error, "The require-trusted-types-for directive requires a value".into()));
        }
        _ => {}
    }
    if is_source_list_directive(name) {
        for v in values {
            let lv = v.to_ascii_lowercase();
            if UNQUOTED_KEYWORDS.contains(&lv.as_str()) {
                notices.push((
                    Severity::Warning,
                    format!(
                        "This host name is unusual, and likely meant to be a keyword that is missing the required \
                         quotes: '{lv}'."
                    ),
                ));
            }
        }
        if values.len() > 1 && values.iter().any(|v| v.eq_ignore_ascii_case("'none'")) {
            notices.push((Severity::Error, "'none' must not be combined with any other source-expression".into()));
        }
    }
}

/// Parses a serialized CSP list (header value): comma separated policies, empty ones dropped.
fn parse_list(text: &str, notices: &mut Vec<(Severity, String)>) -> Vec<Policy> {
    text.split(',').map(|p| parse_policy(p, false, notices)).filter(|p| !p.directives.is_empty()).collect()
}

fn notices_string(notices: &[(Severity, String)]) -> String {
    let mut s = String::new();
    for (sev, title) in
        [(Severity::Error, "Errors:"), (Severity::Warning, "Warnings:"), (Severity::Info, "Info Items:")]
    {
        let mut first = true;
        for (_, m) in notices.iter().filter(|(s, _)| *s == sev) {
            if first {
                s.push_str(title);
                s.push('\n');
                first = false;
            }
            s.push_str(m);
            s.push('\n');
        }
    }
    s
}

fn notices_finding(notices: &[(Severity, String)], param: String, evidence: &str) -> Option<Finding> {
    if notices.is_empty() {
        return None;
    }
    let risk = if notices.iter().any(|(s, _)| *s != Severity::Info) { Risk::Low } else { Risk::Info };
    Some(NOTICES.raise(param, evidence).risk(risk).other_info(notices_string(notices)))
}

fn malformed_finding(msg: &Message, text: &str) -> Finding {
    let bad: String = text.chars().filter(|&c| !(' '..'\x7f').contains(&c)).collect();
    let param = header_name_as_spelled(msg, CSP).unwrap_or_else(|| CSP.to_string());
    MALFORMED.raise(param, text).other_info(format!(
        "A non-ASCII character was encountered while attempting to parse the policy, thus rendering it invalid (no \
         further evaluation occurred). The following invalid characters were collected: {bad}"
    ))
}

// ---- Policy evaluation against an arbitrary third-party URL --------------------

/// The host ZAP checks every policy against (a random, never-whitelisted FQDN).
const RAND_FQDN: &str = "7963124546083337415.owasp.org";

#[derive(Clone, Copy, PartialEq, Eq)]
enum Scheme {
    Http,
    Https,
}

fn scheme_allows(source_scheme: &str, url: Scheme) -> bool {
    match source_scheme.to_ascii_lowercase().as_str() {
        "http" => true,
        "https" => url == Scheme::Https,
        _ => false,
    }
}

/// CSP3 "does url match expression" for `http(s)://RAND_FQDN` with no origin.
fn source_matches(expr: &str, url: Scheme) -> bool {
    if expr.starts_with('\'') {
        // Keywords, nonces and hashes never match a URL; 'self' needs an origin.
        return false;
    }
    if expr == "*" {
        return true;
    }
    let b = expr.as_bytes();
    if b.len() > 1
        && b[b.len() - 1] == b':'
        && b[0].is_ascii_alphabetic()
        && b[..b.len() - 1].iter().all(|c| c.is_ascii_alphanumeric() || b"+-.".contains(c))
    {
        return scheme_allows(&expr[..expr.len() - 1], url);
    }
    // host-source: [scheme "://"] host [":" port] [path]
    let rest = match expr.split_once("://") {
        Some((scheme, rest)) => {
            if !scheme_allows(scheme, url) {
                return false;
            }
            rest
        }
        None => expr,
    };
    let host_end = rest.find([':', '/']).unwrap_or(rest.len());
    let host = &rest[..host_end];
    let mut tail = &rest[host_end..];
    let mut port = None;
    if let Some(t) = tail.strip_prefix(':') {
        let pe = t.find('/').unwrap_or(t.len());
        port = Some(&t[..pe]);
        tail = &t[pe..];
    }
    let host_ok = if host == "*" {
        true
    } else if let Some(suffix) = host.strip_prefix("*.") {
        let fq = RAND_FQDN.as_bytes();
        let sfx = suffix.as_bytes();
        fq.len() > sfx.len() + 1
            && fq[fq.len() - sfx.len()..].eq_ignore_ascii_case(sfx)
            && fq[fq.len() - sfx.len() - 1] == b'.'
    } else {
        host.eq_ignore_ascii_case(RAND_FQDN)
    };
    let default_port = if url == Scheme::Https { "443" } else { "80" };
    let port_ok = match port {
        None | Some("*") => true,
        Some(p) => p == default_port || (p == "80" && url == Scheme::Https),
    };
    let path_ok = tail.is_empty() || tail == "/";
    host_ok && port_ok && path_ok
}

fn directive_allows_url(d: &Directive, url: Scheme, external_script: bool) -> bool {
    if external_script && d.has_keyword("'strict-dynamic'") {
        return false;
    }
    d.values.iter().any(|v| source_matches(v, url))
}

/// Every policy allows a request to http://RAND_FQDN, or every policy allows https://RAND_FQDN.
fn all_allow_url(policies: &[Policy], chain: &[&str], external_script: bool) -> bool {
    [Scheme::Http, Scheme::Https].into_iter().any(|url| {
        policies.iter().all(|p| p.governing(chain).is_none_or(|d| directive_allows_url(d, url, external_script)))
    })
}

const URL_CHECKS: [(&str, &[&str]); 12] = [
    ("script-src", &["script-src-elem", "script-src", "default-src"]),
    ("style-src", &["style-src-elem", "style-src", "default-src"]),
    ("img-src", &["img-src", "default-src"]),
    ("connect-src", &["connect-src", "default-src"]),
    ("frame-src", &["frame-src", "child-src", "default-src"]),
    ("frame-ancestors", &["frame-ancestors"]),
    ("font-src", &["font-src", "default-src"]),
    ("media-src", &["media-src", "default-src"]),
    ("object-src", &["object-src", "default-src"]),
    ("manifest-src", &["manifest-src", "default-src"]),
    ("worker-src", &["worker-src", "child-src", "script-src", "default-src"]),
    ("form-action", &["form-action"]),
];

fn allows_inline(policies: &[Policy], chain: &[&str], script: bool) -> bool {
    policies.iter().all(|p| {
        p.governing(chain).is_none_or(|d| {
            d.has_keyword("'unsafe-inline'")
                && !d.has_nonce()
                && d.hashes().is_empty()
                && !(script && d.has_keyword("'strict-dynamic'"))
        })
    })
}

fn unsafe_hashes_allowed(policies: &[Policy], chain: &[&str]) -> bool {
    let mut common: Option<Vec<(String, &str)>> = None;
    for p in policies {
        let Some(d) = p.governing(chain) else { continue };
        let hashes = d.hashes();
        if !d.has_keyword("'unsafe-hashes'") || hashes.is_empty() {
            return false;
        }
        let next = match common {
            None => hashes,
            Some(c) => c.into_iter().filter(|h| hashes.contains(h)).collect(),
        };
        if next.is_empty() {
            return false;
        }
        common = Some(next);
    }
    common.is_some()
}

fn keyword_allowed(policies: &[Policy], chain: &[&str], kw: &str) -> bool {
    let governing: Vec<Option<&Directive>> = policies.iter().map(|p| p.governing(chain)).collect();
    governing.iter().any(|d| d.is_some_and(|d| d.has_keyword(kw)))
        && governing.iter().all(|d| d.is_none_or(|d| d.has_keyword(kw)))
}

fn with_multi(base: String, multi: &str) -> String {
    if multi.trim().is_empty() {
        base
    } else if base.trim().is_empty() {
        multi.to_string()
    } else {
        format!("{base}\n{multi}")
    }
}

fn check_effective(policies: &[Policy], texts: &[&str], param: &str, out: &mut Vec<Finding>) {
    let evidence = texts[0];
    let multi = if policies.len() <= 1 {
        String::new()
    } else {
        format!(
            "The response contained {} Content-Security-Policy policies (header and/or meta). They were analyzed \
             together using browser-style intersection (a resource is allowed only if every policy allows it):\n{}",
            policies.len(),
            texts.join("\n")
        )
    };
    let raise = |def: &'static AlertDef, info: String| def.raise(param, evidence).other_info(with_multi(info, &multi));

    let allowed: Vec<&str> = URL_CHECKS
        .iter()
        .filter(|(name, chain)| all_allow_url(policies, chain, *name == "script-src"))
        .map(|(name, _)| *name)
        .collect();
    let (no_fallback, rest): (Vec<&str>, Vec<&str>) =
        allowed.into_iter().partition(|n| DIRECTIVES_WITHOUT_FALLBACK.contains(n));
    if !no_fallback.is_empty() {
        out.push(raise(
            &NO_FALLBACK,
            format!(
                "The directive(s): {} is/are among the directives that do not fallback to default-src.",
                no_fallback.join(", ")
            ),
        ));
    }
    if !rest.is_empty() {
        out.push(raise(
            &WILDCARD,
            format!(
                "The following directives either allow wildcard sources (or ancestors), are not defined, or are \
                 overly broadly defined:\n{}",
                rest.join(", ")
            ),
        ));
    }
    if allows_inline(policies, &["script-src-elem", "script-src", "default-src"], true) {
        out.push(raise(&SCRIPT_UNSAFE_INLINE, "script-src includes unsafe-inline.".into()));
    }
    if allows_inline(policies, &["style-src-elem", "style-src", "default-src"], false) {
        out.push(raise(&STYLE_UNSAFE_INLINE, "style-src includes unsafe-inline.".into()));
    }
    if unsafe_hashes_allowed(policies, &["script-src", "default-src"]) {
        out.push(raise(
            &SCRIPT_UNSAFE_HASHES,
            "script-src includes unsafe-hashes, an attacker will be able to use any of the code covered by such \
             hashes."
                .into(),
        ));
    }
    if unsafe_hashes_allowed(policies, &["style-src", "default-src"]) {
        out.push(raise(
            &STYLE_UNSAFE_HASHES,
            "style-src includes unsafe-hashes, an attacker will be able to use any of the code covered by such \
             hashes."
                .into(),
        ));
    }
    if keyword_allowed(policies, &["script-src", "default-src"], "'unsafe-eval'") {
        out.push(raise(&SCRIPT_UNSAFE_EVAL, "script-src includes unsafe-eval.".into()));
    }
}

const XCSP_OTHER_INFO: &str = "The header X-Content-Security-Policy was found on this response. While it is a good \
    sign that CSP is implemented to some degree the policy specified in this header has not been analyzed by ZAP. To \
    ensure full support by modern browsers ensure that the Content-Security-Policy header is defined and attached to \
    responses.";
const XWKCSP_OTHER_INFO: &str = "The header X-WebKit-CSP was found on this response. While it is a good sign that \
    CSP is implemented to some degree the policy specified in this header has not been analyzed by ZAP. To ensure \
    full support by modern browsers ensure that the Content-Security-Policy header is defined and attached to \
    responses.";

pub struct ContentSecurityPolicy;

impl PassiveRule for ContentSecurityPolicy {
    fn id(&self) -> u32 {
        10055
    }

    fn name(&self) -> &'static str {
        "CSP"
    }

    fn alerts(&self) -> &'static [&'static AlertDef] {
        &ALERTS
    }

    fn scan(&self, msg: &Message, out: &mut Vec<Finding>) {
        if !msg.is_html() {
            return;
        }
        let csp_values: Vec<&str> = header_values(msg, CSP).collect();
        let legacy_risk = if csp_values.is_empty() { Risk::Low } else { Risk::Info };
        for (def, header, info) in [(&XCSP, XCSP_HEADER, XCSP_OTHER_INFO), (&XWKCSP, XWKCSP_HEADER, XWKCSP_OTHER_INFO)]
        {
            if let Some(v) = header_values(msg, header).next() {
                let param = header_name_as_spelled(msg, header).unwrap_or_default();
                out.push(def.raise(param, v).risk(legacy_risk).other_info(info));
            }
        }

        let mut policies: Vec<Policy> = Vec::new();
        let mut texts: Vec<&str> = Vec::new();
        let mut header_contributed = false;
        for csp in &csp_values {
            if !csp.is_ascii() {
                out.push(malformed_finding(msg, csp));
                continue;
            }
            let mut notices = Vec::new();
            let parsed = parse_list(csp, &mut notices);
            if !notices.is_empty() {
                let param = header_name_as_spelled(msg, CSP).unwrap_or_default();
                out.extend(notices_finding(&notices, param, csp));
            }
            if !parsed.is_empty() {
                policies.extend(parsed);
                texts.push(csp);
                header_contributed = true;
            }
        }

        let body = msg.body();
        let metas = meta_tags(body);
        for t in &metas {
            let Some(field) = t.attr("http-equiv").filter(|f| !f.trim().is_empty()) else { continue };
            let Some(content) = t.attr("content").filter(|c| !c.trim().is_empty()) else { continue };
            if !field.eq_ignore_ascii_case(CSP) {
                continue;
            }
            if !content.is_ascii() {
                out.push(malformed_finding(msg, content));
                continue;
            }
            if content.contains(',') {
                // A single (meta) policy cannot contain a comma: the library rejects it.
                continue;
            }
            let mut notices = Vec::new();
            let policy = parse_policy(content, true, &mut notices);
            out.extend(notices_finding(&notices, CSP.to_string(), content));
            if META_IGNORED.iter().any(|d| policy.declares(d)) {
                out.push(META_BAD_DIRECTIVE.raise(field, content));
            }
            policies.push(policy);
            texts.push(content);
        }

        if !policies.is_empty() {
            let param =
                if header_contributed { header_name_as_spelled(msg, CSP).unwrap_or_default() } else { String::new() };
            check_effective(&policies, &texts, &param, out);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scan::passive::util::testing::{msg, M};

    const REASONABLE: &str = "default-src 'self'; script-src 'self' storage.googleapis.com cdn.temasys.io \
        cdn.tiny.cloud *.google-analytics.com; style-src 'self' *.googleapis.com; font-src 'self' data: \
        *.googleapis.com fonts.gstatic.com; frame-ancestors 'none'; worker-src 'self'; form-action 'none'";
    const REASONABLE_META: &str = "default-src 'self'; script-src 'self' storage.googleapis.com cdn.temasys.io \
        cdn.tiny.cloud *.google-analytics.com; style-src 'self' *.googleapis.com; font-src 'self' data: \
        *.googleapis.com fonts.gstatic.com; worker-src 'self'; form-action 'none'";

    fn page() -> M {
        msg("https://www.example.com/test/").html("<html></html>").header("Server", "Apache-Coyote/1.1")
    }

    fn with_csp(policy: &str) -> M {
        page().header(CSP, policy)
    }

    fn with_meta(m: M, policy: &str) -> M {
        m.body(&format!("<html><head><meta http-equiv=\"{CSP}\" content=\"{policy}\"></head></html>"))
    }

    fn refs(f: &[Finding]) -> Vec<&str> {
        f.iter().map(|f| f.def.alert_ref).collect()
    }

    fn scan(m: M) -> Vec<Finding> {
        m.scan(&ContentSecurityPolicy)
    }

    #[test]
    fn skips_non_html() {
        let m = msg("https://a.test/").header("Content-Type", "image/png").header(CSP, "report-uri /__cspreport__");
        assert!(scan(m).is_empty());
    }

    #[test]
    fn report_uri_only_policy() {
        let f = scan(with_csp("report-uri /__cspreport__"));
        assert_eq!(refs(&f), ["10055-3", "10055-13", "10055-4", "10055-5", "10055-6"]);
        assert_eq!(f[0].risk, Risk::Info);
        assert!(f[0].other_info.starts_with("Info Items:\n"));
    }

    #[test]
    fn warning_notices() {
        let f = scan(with_csp("default-src none; report-to csp-endpoint "));
        assert_eq!(refs(&f), ["10055-3", "10055-13"]);
        assert_eq!(
            f[0].other_info,
            "Warnings:\nThis host name is unusual, and likely meant to be a keyword that is missing the required \
             quotes: 'none'.\n"
        );
        assert_eq!(f[0].evidence, "default-src none; report-to csp-endpoint");
        assert_eq!((f[0].risk, f[0].confidence, f[0].param.as_str()), (Risk::Low, Confidence::High, CSP));
    }

    #[test]
    fn no_fallback_frame_ancestors() {
        let f = scan(with_csp("frame-ancestors *; default-src 'self'; form-action 'none'"));
        assert_eq!(refs(&f), ["10055-13"]);
        assert_eq!(
            f[0].other_info,
            "The directive(s): frame-ancestors is/are among the directives that do not fallback to default-src."
        );
        assert_eq!(f[0].evidence, "frame-ancestors *; default-src 'self'; form-action 'none'");
        assert_eq!(f[0].risk, Risk::Medium);
    }

    #[test]
    fn wildcard_connect_src() {
        let p = "connect-src *; default-src 'self'; form-action 'none'; frame-ancestors 'self'";
        let f = scan(with_csp(p));
        assert_eq!(refs(&f), ["10055-4"]);
        assert_eq!(
            f[0].other_info,
            "The following directives either allow wildcard sources (or ancestors), are not defined, or are overly \
             broadly defined:\nconnect-src"
        );
        assert_eq!((f[0].evidence.as_str(), f[0].param.as_str()), (p, CSP));
    }

    #[test]
    fn reasonable_policies() {
        assert!(scan(with_csp(REASONABLE)).is_empty());
        assert!(scan(with_meta(with_csp(REASONABLE), REASONABLE_META)).is_empty());
        assert!(scan(with_csp(&format!("{REASONABLE}, script-src 'unsafe-inline'"))).is_empty());
        assert!(scan(with_csp(REASONABLE).header(CSP, "style-src 'unsafe-inline'")).is_empty());
        for add in ["; require-trusted-types-for 'script'", "; trusted-types 'none'"] {
            assert!(scan(with_csp(&format!("{REASONABLE}{add}"))).is_empty());
        }
    }

    #[test]
    fn meta_policies() {
        let f = scan(with_meta(page(), REASONABLE_META));
        assert_eq!(refs(&f), ["10055-13"]);
        assert!(f[0].other_info.contains("frame-ancestors"));
        assert_eq!(f[0].param, "");
        // A comma makes the meta policy unparseable: ignored.
        assert!(scan(with_meta(page(), &format!("{REASONABLE_META},"))).is_empty());
        let f = scan(with_meta(with_csp(REASONABLE), &format!("{REASONABLE_META}; frame-ancestors *")));
        assert_eq!(refs(&f), ["10055-3", "10055-11"]);
        assert_eq!(
            (f[1].param.as_str(), f[1].evidence.as_str()),
            (CSP, &*format!("{REASONABLE_META}; frame-ancestors *"))
        );
        // <meta /> without attributes is fine.
        let m =
            with_csp(REASONABLE).body(&format!("<meta http-equiv=\"{CSP}\" content=\"{REASONABLE_META}\"><meta />"));
        assert!(scan(m).is_empty());
    }

    #[test]
    fn multiple_policies() {
        let first = "script-src 'unsafe-inline'; form-action 'none'; frame-ancestors 'none'";
        let second = "default-src 'unsafe-inline'; form-action 'none'; frame-ancestors 'none'";
        let f = scan(with_csp(first).header(CSP, second));
        let ui = f.iter().find(|f| f.def.alert_ref == "10055-5").unwrap();
        assert_eq!(ui.evidence, first);
        assert!(ui.other_info.starts_with("script-src includes unsafe-inline.\nThe response contained 2"));
        assert!(ui.other_info.contains(first) && ui.other_info.contains(second));
        let f = scan(with_csp(&format!("{first}, {second}")));
        let ui = f.iter().find(|f| f.def.alert_ref == "10055-5").unwrap();
        assert!(ui.other_info.contains("The response contained 2 Content-Security-Policy policies"));

        let permissive = "connect-src *; default-src 'self'; form-action 'none'; frame-ancestors 'self'";
        let restrictive = "connect-src 'self'; default-src 'self'; form-action 'none'; frame-ancestors 'self'";
        assert!(scan(with_csp(permissive).header(CSP, restrictive)).is_empty());
        let f = scan(with_csp(permissive).header(CSP, permissive));
        assert_eq!(refs(&f), ["10055-4"]);
        assert!(f[0].other_info.contains("The response contained 2 Content-Security-Policy policies"));

        let hashes = "default-src 'self'; script-src 'unsafe-hashes' \
            'sha256-jzgBGA4UWFFmpOBq0JpdsySukE1FrEN5bUpoK8Z29fY='; form-action 'none'; frame-ancestors 'none'";
        let plain = "default-src 'self'; script-src 'self'; form-action 'none'; frame-ancestors 'none'";
        assert!(scan(with_csp(hashes).header(CSP, plain)).is_empty());
        assert_eq!(refs(&scan(with_csp(hashes))), ["10055-7"]);
    }

    #[test]
    fn notices_for_noisy_header_only() {
        let noisy = "default-src none; form-action 'none'; frame-ancestors 'none'";
        let f = scan(with_csp(REASONABLE).header(CSP, noisy));
        assert_eq!(refs(&f), ["10055-3"]);
        assert_eq!(f[0].evidence, noisy);
        assert!(f[0].other_info.contains("missing the required quotes: 'none'"));
    }

    #[test]
    fn trusted_types_notices() {
        let base = "default-src 'self'; frame-ancestors 'none'; form-action 'none'";
        for (add, expected) in [
            ("; trusted-types", "Empty trusted-types directive allows all policy names"),
            ("; require-trusted-types-for", "The require-trusted-types-for directive requires a value"),
            ("; trusted-types *", "Wildcard policy names (*) permit any policy name"),
            ("; trusted-types * 'allow-duplicates'", "Wildcard policy names (*) permit any policy name"),
        ] {
            let p = format!("{base}{add}");
            let f = scan(with_csp(&p));
            assert_eq!(refs(&f), ["10055-3"], "{p}");
            assert!(f[0].other_info.contains(expected));
            assert_eq!((f[0].evidence.as_str(), f[0].risk), (p.as_str(), Risk::Low));
        }
        let f = scan(with_csp(&format!("{REASONABLE}; prefetch-src *")));
        assert_eq!(refs(&f), ["10055-3"]);
        assert_eq!(f[0].other_info, "Warnings:\nThe prefetch-src directive has been deprecated\n");
    }

    #[test]
    fn legacy_headers() {
        for (h, r) in [(XCSP_HEADER, "10055-1"), (XWKCSP_HEADER, "10055-2")] {
            let f = scan(page().header(h, REASONABLE));
            assert_eq!(refs(&f), [r]);
            assert_eq!((f[0].risk, f[0].param.as_str(), f[0].evidence.as_str()), (Risk::Low, h, REASONABLE));
            let f = scan(with_csp(REASONABLE).header(h, REASONABLE));
            assert_eq!((refs(&f), f[0].risk), (vec![r], Risk::Info));
        }
    }

    #[test]
    fn unsafe_inline_eval_and_hashes() {
        let f = scan(with_csp("script-src 'unsafe-inline'"));
        assert_eq!(refs(&f), ["10055-13", "10055-4", "10055-5", "10055-6"]);
        assert_eq!(f[0].other_info, "The directive(s): frame-ancestors, form-action is/are among the directives that do not fallback to default-src.");
        assert_eq!(f[2].other_info, "script-src includes unsafe-inline.");
        let f =
            scan(with_csp("script-src 'strict-dynamic' 'unsafe-inline'; form-action 'none'; frame-ancestors 'none'"));
        assert!(!refs(&f).contains(&"10055-5"));
        let f = scan(with_csp("script-src 'unsafe-eval'"));
        assert_eq!(refs(&f), ["10055-13", "10055-4", "10055-6", "10055-10"]);
        let p = "default-src 'self'; script-src 'unsafe-hashes' 'sha256-jzgBGA4UWFFmpOBq0JpdsySukE1FrEN5bUpoK8Z29fY='";
        let f = scan(with_csp(p));
        assert_eq!(refs(&f), ["10055-13", "10055-7"]);
        assert_eq!((f[1].evidence.as_str(), f[1].def.references.len()), (p, 2));
        let p = "default-src 'self'; style-src 'unsafe-hashes' 'sha256-xyz4zkCjuC3lZcD2UmnqDG0vurmq12W/XKM5Vd0+MlQ='";
        assert_eq!(refs(&scan(with_csp(p))), ["10055-13", "10055-8"]);
    }

    #[test]
    fn missing_no_fallback_directive() {
        let no_form_action = REASONABLE.replace("; form-action 'none'", "");
        let no_frame_ancestors = REASONABLE.replace(" frame-ancestors 'none';", "");
        for p in [no_form_action, no_frame_ancestors] {
            let f = scan(with_csp(&p));
            assert_eq!(refs(&f), ["10055-13"], "{p}");
        }
    }

    #[test]
    fn malformed_header_falls_back_to_meta() {
        let m = page().header(CSP, "default-src \u{2018}self\u{2019} \u{201c}");
        let f = scan(with_meta(m, "script-src 'unsafe-inline'"));
        assert_eq!(f[0].def.alert_ref, "10055-9");
        assert!(f[0].other_info.ends_with("collected: \u{2018}\u{2019}\u{201c}"));
        let ui = f.iter().find(|f| f.def.alert_ref == "10055-5").unwrap();
        assert_eq!((ui.param.as_str(), ui.evidence.as_str()), ("", "script-src 'unsafe-inline'"));
    }

    #[test]
    fn source_matching() {
        assert!(source_matches("*.owasp.org", Scheme::Http));
        assert!(source_matches("https:", Scheme::Https));
        assert!(!source_matches("https:", Scheme::Http));
        assert!(source_matches("http:", Scheme::Https));
        assert!(!source_matches("data:", Scheme::Https));
        assert!(source_matches("https://*:443", Scheme::Https));
        assert!(!source_matches("*.google-analytics.com", Scheme::Https));
        assert!(!source_matches("'self'", Scheme::Https));
        assert!(!source_matches("*.owasp.org/path", Scheme::Https));
    }
}
