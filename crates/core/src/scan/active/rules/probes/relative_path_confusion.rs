//! Ported from ZAP RelativePathConfusionScanRule (ascanrulesBeta, Apache License 2.0).
//!
//! Asks for the page with two made-up folders after its file name (`/page.php/ab12c/de34f`).
//! A server that still serves the page there, with relative links, a single `<base>` missing,
//! and either no Content-Type or a way past it (Quirks Mode, or a page that may be framed),
//! lets a browser load the page's relative resources from the wrong place.
//!
//! Less noise than ZAP: the answer must be a 200 (ZAP also judges an error page), and an empty
//! link or one with a scheme of its own (`javascript:`, `mailto:`, `data:`) isn't relative.
//! HTML is read by brainproxy's lenient tokenizer instead of jsoup, so `<base>` and
//! `<meta http-equiv>` count anywhere in the page, not only in its head.

use std::sync::LazyLock;

use regex::Regex;

use super::common::base_path;
use crate::scan::active::{rand_u64, ActiveRule, BoxFuture, Cx, RuleScope};
use crate::scan::passive::rules::content::common::{element_content, element_source};
use crate::scan::passive::util::{tags, Tag};
use crate::scan::{AlertDef, Confidence, Risk};

static ALERT: AlertDef = AlertDef {
    alert_ref: "10051",
    name: "Relative Path Confusion",
    risk: Risk::Medium,
    confidence: Confidence::Medium,
    cwe: 20,
    wasc: 20,
    description: "The web server is configured to serve responses to ambiguous URLs in a manner that is likely to \
        lead to confusion about the correct \"relative path\" for the URL. Resources (CSS, images, etc.) are also \
        specified in the page response using relative, rather than absolute URLs. In an attack, if the web browser \
        parses the \"cross-content\" response in a permissive manner, or can be tricked into permissively parsing the \
        \"cross-content\" response, using techniques such as framing, then the web browser may be fooled into \
        interpreting HTML as CSS (or other content types), leading to an XSS vulnerability.",
    solution: "Web servers and frameworks should be updated to be configured to not serve responses to ambiguous URLs \
        in such a way that the relative path of such URLs could be mis-interpreted by components on either the client \
        side, or server side.\nWithin the application, the correct use of the \"<base>\" HTML tag in the HTTP \
        response will unambiguously specify the base URL for all relative URLs in the document.\nUse the \
        \"Content-Type\" HTTP response header to make it harder for the attacker to force the web browser to \
        mis-interpret the content type of the response.\nUse the \"X-Content-Type-Options: nosniff\" HTTP response \
        header to prevent the web browser from \"sniffing\" the content type of the response.\nUse a modern DOCTYPE \
        such as \"<!doctype html>\" to prevent the page from being rendered in the web browser using \"Quirks \
        Mode\", since this results in the content type being ignored by the web browser.\nSpecify the \
        \"X-Frame-Options\" HTTP response header to prevent Quirks Mode from being enabled in the web browser using \
        framing attacks.",
    references: &[
        "https://arxiv.org/abs/1811.00917",
        "https://hsivonen.fi/doctype/",
        "https://www.w3schools.com/tags/tag_base.asp",
    ],
    tags: &["OWASP_2025_A02", "OWASP_2021_A05", "OWASP_2017_A06"],
};

static ALERTS: [&AlertDef; 1] = [&ALERT];

/// ZAP's attributes that load a URL, with the elements that carry them. An empty element
/// name is any element; an empty attribute is the element's content (a `<style>`).
const LOADING: &[(&str, &[&str])] = &[
    ("href", &["link", "a", "area"]),
    ("src", &["img", "iframe", "frame", "embed", "script", "input", "audio", "video", "source"]),
    ("lowersrc", &["img", "iframe", "frame", "embed", "script", "input", "audio", "video", "source"]),
    ("dynsrc", &["img", "iframe", "frame", "embed", "script", "input", "audio", "video", "source"]),
    ("action", &["form"]),
    ("data", &["object"]),
    ("codebase", &["applet", "object"]),
    ("cite", &["blockquote", "del", "ins", "q"]),
    ("background", &["body"]),
    ("longdesc", &["frame", "iframe", "img"]),
    ("profile", &["head"]),
    ("usemap", &["img", "input", "object"]),
    ("classid", &["object"]),
    ("formaction", &["button"]),
    ("icon", &["command", "input"]),
    ("manifest", &["html"]),
    ("poster", &["video"]),
    ("archive", &["object", "applet"]),
    ("style", &[""]),
    ("", &["style"]),
];

/// Doctype public ids that put browsers in Quirks Mode.
const QUIRKS_DOCTYPES: &[&str] = &[
    "-//W3C//DTD HTML 3.2 Final//EN",
    "-//W3C//DTD HTML 4.01//EN",
    "-//W3C//DTD HTML 4.0 Transitional//EN",
    "-//W3C//DTD HTML 4.01 Transitional//EN",
    "-//W3C//DTD XHTML 1.0 Transitional//EN",
    "-//W3C//DTD XHTML 1.1//EN",
    "-//W3C//DTD XHTML Basic 1.0//EN",
    "-//W3C//DTD XHTML 1.0 Strict//EN",
    "ISO/IEC 15445:2000//DTD HTML//EN",
    "ISO/IEC 15445:2000//DTD HyperText Markup Language//EN",
    "ISO/IEC 15445:1999//DTD HTML//EN",
    "ISO/IEC 15445:1999//DTD HyperText Markup Language//EN",
];

/// A CSS property loading a URL (`background: url(img.png)`).
static STYLE_URL: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?is)[a-zA-Z_-]*\s*:\s*url\s*\(([^)]*)\)").expect("static regex compiles"));

/// A relative `url(...)` in CSS (not from the root, not http or https), quotes taken out as
/// ZAP does.
fn style_url(css: &str) -> Option<String> {
    let css = css.replace(['\'', '"'], "");
    STYLE_URL
        .captures_iter(&css)
        .find(|c| {
            let url = c[1].to_ascii_lowercase();
            !url.is_empty() && !url.starts_with('/') && !url.starts_with("http:") && !url.starts_with("https:")
        })
        .map(|c| c[0].to_string())
}

/// The doctype at the start of the page: Some(public id, "" without one), None when absent.
static DOCTYPE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?is)\A(?:\s|<!--.*?-->|<\?.*?\?>)*<!doctype\s+[^\s>]+(?:\s+public\s+["']([^"']*)["'])?"#)
        .expect("static regex compiles")
});

/// Whether a URL is relative to the page's path: not absolute, not from the root, not a
/// fragment, not empty and without a scheme of its own.
fn relative(url: &str) -> bool {
    let u = url.trim();
    let scheme = u.split_once(':').is_some_and(|(s, _)| {
        s.chars().next().is_some_and(|c| c.is_ascii_alphabetic())
            && s.chars().all(|c| c.is_ascii_alphanumeric() || "+-.".contains(c))
    });
    !u.is_empty() && !u.starts_with('/') && !u.starts_with('#') && !scheme
}

/// The first relative reference in `html`, as ZAP's order of attributes finds it.
fn relative_reference(html: &str, all: &[Tag]) -> Option<String> {
    for (attr, names) in LOADING {
        for name in names.iter() {
            for t in all.iter().filter(|t| name.is_empty() || t.name == *name) {
                if attr.is_empty() {
                    if let Some(m) = style_url(element_content(html, t)) {
                        return Some(m);
                    }
                    continue;
                }
                let Some(value) = t.attr(attr) else { continue };
                if *attr == "style" {
                    if style_url(value).is_some() {
                        return Some(value.to_string());
                    }
                } else if relative(value) {
                    return Some(element_source(html, t).to_string());
                }
            }
        }
    }
    None
}

fn random(len: usize) -> String {
    const CHARS: &[u8] = b"abcdefghijklmnopqrstuvwxyz0123456789";
    (0..len).map(|_| CHARS[(rand_u64() % CHARS.len() as u64) as usize] as char).collect()
}

pub struct RelativePathConfusion;

impl ActiveRule for RelativePathConfusion {
    fn id(&self) -> u32 {
        10051
    }

    fn name(&self) -> &'static str {
        "Relative Path Confusion"
    }

    fn alerts(&self) -> &'static [&'static AlertDef] {
        &ALERTS
    }

    fn scope(&self) -> RuleScope {
        RuleScope::Page
    }

    fn scan<'a>(&'a self, cx: &'a Cx) -> BoxFuture<'a> {
        Box::pin(async move {
            let path = base_path(cx);
            let name = path.rsplit('/').next().unwrap_or("");
            if !name.rsplit_once('.').is_some_and(|(_, ext)| !ext.is_empty()) {
                return;
            }
            let query = cx.base().query.clone().unwrap_or_default();
            let attack = format!("{path}/{}/{}?{query}", random(5), random(5));
            let Ok(resp) = cx.send_following(cx.request_for("GET", &attack)).await else { return };
            if resp.status != 200 {
                return;
            }
            let html = resp.body_str();
            let all = tags(html);
            let mut info: Vec<String> = Vec::new();
            match all.iter().filter(|t| t.name == "base" && t.has("href")).count() {
                1 => return,
                0 => info.push("No <base> tag was specified in the HTML <head> tag to define the location for relative URLs.".into()),
                _ => info.push(
                    "More than one <base> tag was specified in the HTML <head> tag to define the location for relative \
                     URLs, which is not valid."
                        .into(),
                ),
            }
            let Some(evidence) = relative_reference(html, &all) else { return };
            match resp.header("content-type") {
                None => info.push(
                    "No Content Type was specified, so Quirks Mode is not required to exploit the vulnerability in the \
                     web browser."
                        .into(),
                ),
                Some(ct) => {
                    info.push(format!(
                        "A Content Type of \"{ct}\" was specified. If the web browser is employing strict parsing \
                         rules, this will prevent cross-content attacks from succeeding. Quirks Mode in the web \
                         browser would disable strict parsing."
                    ));
                    let mut quirks = false;
                    for m in all.iter().filter(|t| t.name == "meta") {
                        let equiv = m.attr("http-equiv").unwrap_or("");
                        let content = m.attr("content").unwrap_or("");
                        if equiv.trim().eq_ignore_ascii_case("x-ua-compatible") && !content.trim().eq_ignore_ascii_case("ie=edge") {
                            quirks = true;
                            info.push(format!(
                                "Quirks Mode is explicitly enabled via <meta http-equiv=\"{equiv}\", allowing the \
                                 specified Content Type to be bypassed."
                            ));
                        }
                    }
                    if !quirks {
                        match DOCTYPE.captures(html) {
                            None => {
                                quirks = true;
                                info.push(
                                    "Quirks Mode is implicitly enabled via the absence of a DOCTYPE, allowing the \
                                     specified Content Type to be bypassed."
                                        .into(),
                                );
                            }
                            Some(c) => {
                                let id = c.get(1).map_or("", |m| m.as_str());
                                if QUIRKS_DOCTYPES.iter().any(|q| q.eq_ignore_ascii_case(id)) {
                                    quirks = true;
                                    info.push(format!(
                                        "Quirks Mode is implicitly enabled via the use of an old DOCTYPE with PUBLIC \
                                         id \"{id}\", allowing the specified Content Type to be bypassed in some web \
                                         browsers."
                                    ));
                                }
                            }
                        }
                    }
                    if !quirks {
                        let framable = match resp.header("x-frame-options") {
                            Some(v) => {
                                let v = v.trim().to_ascii_uppercase();
                                !(v == "DENY" || v == "SAMEORIGIN" || v.starts_with("ALLOW-FROM"))
                            }
                            None => true,
                        };
                        if !framable {
                            return;
                        }
                        if resp.header("x-frame-options").is_none() {
                            info.push(
                                "No X-Frame-Options header was specified, so the page can be framed, and this can be \
                                 used to enable Quirks Mode, allowing the specified Content Type to be bypassed."
                                    .into(),
                            );
                        }
                    }
                }
            }
            let url = format!("{}{attack}", cx.target().origin());
            cx.report(ALERT.raise("", evidence).attack(url).other_info(info.join("\n")), &resp);
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scan::active::rules::test_app::{get, html, not_found, resp, scan, serve, Opts};

    const PAGE: &str =
        "<!doctype html><html><head><link rel=stylesheet href=\"css/site.css\"></head><body>Hi</body></html>";

    #[test]
    fn relative_references() {
        let page = "<html><body><a href=\"#top\">t</a><a href=\"/abs\">a</a><a href=\"mailto:x@y\">m</a><img src=\"img/logo.png\"></body></html>";
        assert_eq!(relative_reference(page, &tags(page)).unwrap(), "<img src=\"img/logo.png\">");
        let css = "<html><head><style>body { background: url('img/bg.png') }</style></head></html>";
        assert_eq!(relative_reference(css, &tags(css)).unwrap(), "background: url(img/bg.png)");
        let abs = "<html><head><style>body { background: url(https://cdn.test/bg.png) }</style></head></html>";
        assert!(relative_reference(abs, &tags(abs)).is_none());
        assert!(DOCTYPE.captures(PAGE).is_some());
        let old = "<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 4.01 Transitional//EN\"><html>";
        assert_eq!(DOCTYPE.captures(old).unwrap().get(1).unwrap().as_str(), "-//W3C//DTD HTML 4.01 Transitional//EN");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn path_info_served_page_that_can_be_framed() {
        // PATH_INFO: /index.php/anything serves the page.
        let port = serve(|r| if r.path.starts_with("/index.php") { html(PAGE) } else { not_found() });
        let (s, found) = scan(10051, vec![get(port, "/index.php")], Opts::default()).await;
        assert_eq!(found.len(), 1, "{s:?}");
        assert_eq!(found[0].evidence, "<link rel=stylesheet href=\"css/site.css\">");
        assert!(found[0].other_info.contains("can be framed"));
        assert_eq!(s.requests, 1);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn fixed_pages_raise_nothing() {
        // A 404 for the made-up path; a page that can't be framed; a page with a <base>.
        let strict = serve(|r| match r.path.as_str() {
            "/a.php" => html(PAGE),
            p if p.starts_with("/b.php") => resp(200, "text/html", &[("X-Frame-Options", "DENY")], PAGE),
            p if p.starts_with("/c.php") => html(&PAGE.replace("<head>", "<head><base href=\"/\">")),
            _ => not_found(),
        });
        for page in ["/a.php", "/b.php", "/c.php"] {
            let (_, found) = scan(10051, vec![get(strict, page)], Opts::default()).await;
            assert!(found.is_empty(), "{page}: {found:?}");
        }
    }
}
