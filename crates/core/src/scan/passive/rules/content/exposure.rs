//! brainproxy's own rules (100022 to 100025): what a response says about the application's
//! insides, beyond an error. An API description (OpenAPI or Swagger) lists every endpoint
//! and parameter, internal ones too; Prometheus metrics show the runtime, the routes and
//! the load; a source map hands out the original source; a JSONP endpoint lets any site
//! read the answer. Each is a lead for testing more than a flaw by itself, so they are
//! informational or low, and they point the active scan at the right places.

use std::sync::LazyLock;

use regex::Regex;
use serde::Deserialize;

use super::common::{cut_chars, is_css, is_javascript, is_source_map};
use crate::scan::{AlertDef, Confidence, Finding, Message, PassiveRule, Risk};

const TAGS: &[&str] = &["OWASP_2025_A02", "OWASP_2021_A05", "OWASP_2017_A06", "WSTG-v42-INFO-05"];

static API_SPEC: AlertDef = AlertDef {
    alert_ref: "100022-1",
    name: "API Description Exposed",
    risk: Risk::Low,
    confidence: Confidence::High,
    cwe: 200,
    wasc: 13,
    description: "The response is an OpenAPI (Swagger) description of the application's API: every endpoint, \
        its parameters and its data types, including endpoints the user interface never calls.",
    solution: "If the API isn't meant to be public, serve its description only to those who need it (behind \
        authentication, or not in production). Either way, make sure every endpoint it lists checks who may \
        call it.",
    references: &["https://owasp.org/API-Security/editions/2023/en/0xa9-improper-inventory-management/"],
    tags: TAGS,
};

static API_UI: AlertDef = AlertDef {
    alert_ref: "100022-2",
    name: "API Documentation Page Exposed",
    risk: Risk::Info,
    confidence: Confidence::High,
    cwe: 200,
    wasc: 13,
    description: "The page is an interactive API documentation page (Swagger UI or ReDoc), which loads the API's \
        description and lets anyone send requests to it.",
    solution: "If the API isn't meant to be public, don't serve its documentation in production, or put it \
        behind authentication.",
    references: &["https://owasp.org/API-Security/editions/2023/en/0xa9-improper-inventory-management/"],
    tags: TAGS,
};

static METRICS: AlertDef = AlertDef {
    alert_ref: "100023",
    name: "Prometheus Metrics Exposed",
    risk: Risk::Low,
    confidence: Confidence::High,
    cwe: 200,
    wasc: 13,
    description: "The response is a Prometheus metrics page. Metrics name the runtime and its versions, the \
        application's routes and counters, and show its load, which helps an attacker plan.",
    solution: "Serve metrics on a separate port or path that only the monitoring system can reach, or require \
        authentication for them.",
    references: &["https://prometheus.io/docs/instrumenting/exposition_formats/"],
    tags: TAGS,
};

static SOURCE_MAP: AlertDef = AlertDef {
    alert_ref: "100024",
    name: "Source Map Exposed",
    risk: Risk::Low,
    confidence: Confidence::High,
    cwe: 540,
    wasc: 13,
    description: "The response is a JavaScript source map. With it, the minified scripts read as their original \
        source, with file names, comments and, when it carries `sourcesContent`, the source code itself.",
    solution: "Don't deploy source maps to production, or serve them only to the developers who need them.",
    references: &["https://developer.mozilla.org/en-US/docs/Glossary/Source_map"],
    tags: TAGS,
};

static JSONP: AlertDef = AlertDef {
    alert_ref: "100025",
    name: "JSONP Endpoint",
    risk: Risk::Low,
    confidence: Confidence::Medium,
    cwe: 346,
    wasc: 0,
    description: "The response wraps its data in a call to the function the request names (JSONP). Any site can \
        load it with a script tag and read the data, with the visitor's cookies sent along, so data that depends \
        on the user can be stolen cross-site, and a callback name the server doesn't restrict can run script.",
    solution: "Replace JSONP with CORS for the origins that need the data. If JSONP has to stay, return only \
        public data from it and allow only plain identifiers as the callback name.",
    references: &["https://cwe.mitre.org/data/definitions/346.html"],
    tags: &["OWASP_2025_A01", "OWASP_2021_A01", "WSTG-v42-CLNT-07"],
};

static SPEC_JSON: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"\A\s*\{[\s\S]{0,2000}?("(?:openapi"\s*:\s*"3\.\d+(?:\.\d+)?|swagger"\s*:\s*"2\.0)")"#)
        .expect("static pattern")
});
static SPEC_YAML: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r#"(?m)\A(?:\s*#[^\n]*\n|\s*---\s*\n)*\s*((?:openapi:\s*["']?3\.\d+(?:\.\d+)?|swagger:\s*["']?2\.0)["']?)[ \t]*\r?$"#,
    )
    .expect("static pattern")
});
static SPEC_PATHS: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"(?m)"paths"\s*:\s*\{|^paths:\s*$"#).expect("static pattern"));
/// swagger-ui-express writes the description into its init script.
static SPEC_IN_SCRIPT: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#""swaggerDoc"\s*:\s*\{\s*"(?:openapi|swagger)"\s*:\s*"[23]\.[\d.]+""#).expect("static pattern")
});
static DOCS_UI: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"<div id=["']swagger-ui["']|SwaggerUIBundle\(|<redoc\b|Redoc\.init\("#).expect("static pattern")
});

pub struct ApiDocs;

impl PassiveRule for ApiDocs {
    fn id(&self) -> u32 {
        100022
    }

    fn name(&self) -> &'static str {
        "API Description Exposed"
    }

    fn alerts(&self) -> &'static [&'static AlertDef] {
        static ALERTS: [&AlertDef; 2] = [&API_SPEC, &API_UI];
        &ALERTS
    }

    fn scan(&self, msg: &Message, out: &mut Vec<Finding>) {
        if !msg.is_success() || msg.resp_body.is_empty() {
            return;
        }
        let body = msg.body();
        if is_javascript(msg) {
            if let Some(m) = SPEC_IN_SCRIPT.find(body) {
                out.push(API_SPEC.raise("", m.as_str()).other_info("The documentation page's script embeds it."));
            }
            return;
        }
        if msg.is_html() {
            if let Some(m) = DOCS_UI.find(body) {
                out.push(API_UI.raise("", m.as_str()));
            }
            return;
        }
        let spec = SPEC_JSON.captures(body).or_else(|| SPEC_YAML.captures(body)).and_then(|c| c.get(1));
        if let Some(m) = spec.filter(|_| SPEC_PATHS.is_match(body)) {
            out.push(API_SPEC.raise("", m.as_str()));
        }
    }
}

static METRIC_TYPE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"(?m)^# TYPE [a-zA-Z_:][a-zA-Z0-9_:]* (?:counter|gauge|histogram|summary|untyped|unknown|info|stateset|gaugehistogram)[ \t]*\r?$",
    )
    .expect("static pattern")
});

pub struct PrometheusMetrics;

impl PassiveRule for PrometheusMetrics {
    fn id(&self) -> u32 {
        100023
    }

    fn name(&self) -> &'static str {
        "Prometheus Metrics Exposed"
    }

    fn alerts(&self) -> &'static [&'static AlertDef] {
        static ALERTS: [&AlertDef; 1] = [&METRICS];
        &ALERTS
    }

    fn scan(&self, msg: &Message, out: &mut Vec<Finding>) {
        // A page or a script about Prometheus shows the format as an example.
        let ct = msg.content_type();
        let exposition = ct.is_empty() || ct.starts_with("text/plain") || ct.contains("openmetrics");
        if !msg.is_success() || !exposition || is_javascript(msg) {
            return;
        }
        let body = msg.body();
        let mut types = METRIC_TYPE.find_iter(body);
        let Some(first) = types.next() else { return };
        if !body.contains("# HELP ") {
            return;
        }
        let n = types.count() + 1;
        out.push(METRICS.raise("", first.as_str().trim_end()).other_info(format!("It describes {n} metrics.")));
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Map {
    #[serde(default)]
    sources: Vec<Option<String>>,
    #[serde(default)]
    sources_content: Vec<Option<serde::de::IgnoredAny>>,
}

pub struct SourceMap;

impl PassiveRule for SourceMap {
    fn id(&self) -> u32 {
        100024
    }

    fn name(&self) -> &'static str {
        "Source Map Exposed"
    }

    fn alerts(&self) -> &'static [&'static AlertDef] {
        static ALERTS: [&AlertDef; 1] = [&SOURCE_MAP];
        &ALERTS
    }

    fn scan(&self, msg: &Message, out: &mut Vec<Finding>) {
        // A single-page app answers a missing .map with its index page, which isn't one.
        if !msg.is_success() || msg.is_html() || !is_source_map(msg) {
            return;
        }
        let body = msg.body();
        if !body.contains("\"mappings\"") {
            return;
        }
        let Ok(map) = serde_json::from_slice::<Map>(&msg.resp_body) else { return };
        let sources: Vec<&str> = map.sources.iter().flatten().map(String::as_str).collect();
        let with_code = map.sources_content.iter().flatten().count();
        let mut other = format!("It names {} source files", sources.len());
        if !sources.is_empty() {
            let shown: Vec<&str> = sources.iter().take(5).map(|s| cut_chars(s, 120)).collect();
            other.push_str(&format!(" ({}{})", shown.join(", "), if sources.len() > 5 { ", ..." } else { "" }));
        }
        let (evidence, risk) = if with_code > 0 {
            other.push_str(&format!(" and carries the source code of {with_code}."));
            ("\"sourcesContent\"", Risk::Low)
        } else {
            other.push('.');
            ("\"mappings\"", Risk::Info)
        };
        out.push(SOURCE_MAP.raise("", evidence).risk(risk).other_info(other));
    }
}

/// Query parameters that name a JSONP callback.
const CALLBACK_PARAMS: &[&str] =
    &["callback", "cb", "jsonp", "jsonpcallback", "jsoncallback", "jsonp_callback", "_callback"];

fn identifier(s: &str) -> bool {
    let mut b = s.bytes();
    b.next().is_some_and(|c| c.is_ascii_alphabetic() || c == b'_' || c == b'$')
        && b.all(|c| c.is_ascii_alphanumeric() || c == b'_' || c == b'$' || c == b'.')
        && s.len() <= 100
}

/// The body's start after JSONP's usual guards: `/**/` and `typeof cb === 'function' &&`.
fn call_start(body: &str) -> &str {
    let mut rest = body.trim_start();
    if let Some(r) = rest.strip_prefix("/**/") {
        rest = r.trim_start();
    }
    if let Some(i) = rest.strip_prefix("typeof ").and_then(|r| r.find("&&")) {
        rest = rest.get(7 + i + 2..).unwrap_or("").trim_start();
    }
    rest
}

pub struct JsonpEndpoint;

impl PassiveRule for JsonpEndpoint {
    fn id(&self) -> u32 {
        100025
    }

    fn name(&self) -> &'static str {
        "JSONP Endpoint"
    }

    fn alerts(&self) -> &'static [&'static AlertDef] {
        static ALERTS: [&AlertDef; 1] = [&JSONP];
        &ALERTS
    }

    fn scan(&self, msg: &Message, out: &mut Vec<Finding>) {
        if !msg.is_success() || msg.is_html() || is_css(msg) || msg.resp_body.is_empty() {
            return;
        }
        let params = msg.query_params();
        let Some((name, callback)) =
            params.iter().find(|(k, v)| CALLBACK_PARAMS.contains(&k.to_ascii_lowercase().as_str()) && identifier(v))
        else {
            return;
        };
        let start = call_start(msg.body());
        let Some(rest) = start.strip_prefix(callback.as_str()) else { return };
        if !rest.trim_start().starts_with('(') {
            return;
        }
        // Data a cross-site page can read is the user's only when the request carried credentials.
        let credentials = msg.req_header("cookie").is_some() || msg.req_header("authorization").is_some();
        let f = JSONP.raise(name.as_str(), format!("{callback}("));
        out.push(if credentials {
            f.other_info("The request carried the user's credentials, so the data may be the user's.")
        } else {
            f.risk(Risk::Info).other_info("The request carried no credentials; the data is likely public.")
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scan::passive::util::testing::msg;

    #[test]
    fn flags_api_descriptions_and_documentation_pages() {
        let json = r#"{"openapi":"3.0.1","info":{"title":"Shop","version":"1"},"paths":{"/orders":{}}}"#;
        let f = msg("https://a.test/v3/api-docs").header("Content-Type", "application/json").body(json).scan(&ApiDocs);
        assert_eq!((f[0].def.alert_ref, f[0].evidence.as_str()), ("100022-1", r#""openapi":"3.0.1""#));
        let yaml = "# generated\nswagger: '2.0'\ninfo:\n  title: Shop\npaths:\n  /orders:\n";
        let f = msg("https://a.test/swagger.yaml").header("Content-Type", "text/yaml").body(yaml).scan(&ApiDocs);
        assert_eq!(f[0].evidence, "swagger: '2.0'");
        // Juice Shop's /api-docs/ (swagger-ui-express): the page, and the description in its script.
        let page = "<title>Swagger UI</title></head><body><div id=\"swagger-ui\"></div>\
            <script src=\"./swagger-ui-bundle.js\"> </script>";
        let f = msg("http://a.test/api-docs/").html(page).scan(&ApiDocs);
        assert_eq!((f[0].def.alert_ref, f[0].risk), ("100022-2", Risk::Info));
        let init = "var options = {\n  \"swaggerDoc\": {\n    \"openapi\": \"3.0.0\",\n    \"servers\": []";
        let js = msg("http://a.test/api-docs/swagger-ui-init.js").header("Content-Type", "application/javascript");
        assert_eq!(js.body(init).scan(&ApiDocs)[0].def.alert_ref, "100022-1");
    }

    /// Swagger UI's own bundle, an API's ordinary JSON and the SPA's fallback page aren't descriptions.
    #[test]
    fn ignores_bundles_data_and_fallback_pages() {
        let bundle = r#"!function(){var SwaggerUIBundle=function(){};var d={"swagger":"2.0","paths":{}}}();"#;
        let js = msg("https://a.test/swagger-ui-bundle.js").header("Content-Type", "application/javascript");
        assert!(js.body(bundle).scan(&ApiDocs).is_empty());
        let data = r#"{"data":[{"name":"openapi","description":"\"swagger\":\"2.0\" docs"}],"paths":{}}"#;
        let f = msg("https://a.test/api/x").header("Content-Type", "application/json").body(data);
        assert!(f.scan(&ApiDocs).is_empty());
        let spa = "<!doctype html><title>OWASP Juice Shop</title><app-root></app-root>";
        assert!(msg("https://a.test/swagger.json").html(spa).scan(&ApiDocs).is_empty());
    }

    #[test]
    fn flags_prometheus_metrics() {
        let metrics = "# HELP juiceshop_llm_input_tokens_total Number of total input tokens processed\n\
            # TYPE juiceshop_llm_input_tokens_total counter\njuiceshop_llm_input_tokens_total{app=\"juiceshop\"} 0\n\n\
            # HELP process_cpu_seconds_total Total user and system CPU time\n# TYPE process_cpu_seconds_total counter\n";
        let f = msg("http://a.test/metrics").header("Content-Type", "text/plain; version=0.0.4; charset=utf-8");
        let f = f.body(metrics).scan(&PrometheusMetrics);
        assert_eq!(f[0].evidence, "# TYPE juiceshop_llm_input_tokens_total counter");
        assert_eq!(f[0].other_info, "It describes 2 metrics.");
    }

    #[test]
    fn ignores_metrics_shown_as_examples() {
        let doc = "<pre># HELP http_requests_total The total\n# TYPE http_requests_total counter\n</pre>";
        assert!(msg("https://a.test/docs/metrics").html(doc).scan(&PrometheusMetrics).is_empty());
        let readme = "Run it and see:\n# TYPE x counter\n"; // no HELP lines
        let f = msg("https://a.test/README.txt").header("Content-Type", "text/plain").body(readme);
        assert!(f.scan(&PrometheusMetrics).is_empty());
        let js = msg("https://a.test/prom.js").header("Content-Type", "text/plain");
        assert!(js.body("// # HELP a b\n# TYPE a counter\n").scan(&PrometheusMetrics).is_empty());
    }

    #[test]
    fn flags_source_maps() {
        let map = r#"{"version":3,"file":"main.js","sources":["webpack:///src/app/login.component.ts","webpack:///src/environments/environment.ts"],"sourcesContent":["export class Login {}",null],"mappings":"AAAA"}"#;
        let f = msg("https://a.test/main.js.map").header("Content-Type", "application/json").body(map);
        let f = f.scan(&SourceMap);
        assert_eq!((f[0].evidence.as_str(), f[0].risk), ("\"sourcesContent\"", Risk::Low));
        assert!(
            f[0].other_info.contains("names 2 source files (webpack:///src/app/login.component.ts"),
            "{}",
            f[0].other_info
        );
        assert!(f[0].other_info.ends_with("source code of 1."), "{}", f[0].other_info);
        let bare = r#"{"version":3,"sources":["a.ts"],"names":[],"mappings":"AAAA"}"#;
        let f = msg("https://a.test/a.js.map").body(bare).scan(&SourceMap);
        assert_eq!((f[0].evidence.as_str(), f[0].risk), ("\"mappings\"", Risk::Info));
    }

    #[test]
    fn ignores_what_only_mentions_source_maps() {
        let js = "console.log(1);\n//# sourceMappingURL=main.js.map";
        let f = msg("https://a.test/main.js").header("Content-Type", "application/javascript").body(js);
        assert!(f.scan(&SourceMap).is_empty());
        // Juice Shop answers an unknown path, a missing map too, with its index page.
        let spa = "<!doctype html><title>OWASP Juice Shop</title>";
        assert!(msg("https://a.test/main.js.map").html(spa).scan(&SourceMap).is_empty());
        let other = r#"{"version":3,"name":"config"}"#;
        let f = msg("https://a.test/api/config").header("Content-Type", "application/json").body(other);
        assert!(f.scan(&SourceMap).is_empty());
    }

    #[test]
    fn flags_jsonp_callbacks() {
        let f = msg("https://a.test/api/user?callback=jQuery1124_1700&_=1")
            .req_header("Cookie", "sid=1")
            .header("Content-Type", "application/javascript")
            .body(r#"/**/ typeof jQuery1124_1700 === 'function' && jQuery1124_1700({"email":"a@a.test"});"#)
            .scan(&JsonpEndpoint);
        assert_eq!(
            (f[0].param.as_str(), f[0].evidence.as_str(), f[0].risk),
            ("callback", "jQuery1124_1700(", Risk::Low)
        );
        let f = msg("https://a.test/api/stats?jsonp=cb.done")
            .header("Content-Type", "text/javascript")
            .body(r#"cb.done({"n":3})"#)
            .scan(&JsonpEndpoint);
        assert_eq!(f[0].risk, Risk::Info);
    }

    #[test]
    fn ignores_callbacks_not_called() {
        let json = msg("https://a.test/api/hooks?callback=notify")
            .header("Content-Type", "application/json")
            .body(r#"{"callback":"notify","status":"ok"}"#);
        assert!(json.scan(&JsonpEndpoint).is_empty());
        let page = msg("https://a.test/oauth?callback=done").html("done(1)");
        assert!(page.scan(&JsonpEndpoint).is_empty());
        let odd = msg("https://a.test/x?callback=alert(1)//").header("Content-Type", "application/javascript");
        assert!(odd.body("alert(1)//({})").scan(&JsonpEndpoint).is_empty());
    }
}
