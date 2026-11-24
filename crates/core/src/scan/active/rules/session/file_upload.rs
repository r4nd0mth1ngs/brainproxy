//! File upload (40041). Not a zap-extensions port: rule 40041 is the id of SasanLabs'
//! owasp-zap-fileupload-addon (Apache License 2.0), whose attack list informed this one.
//!
//! On a recorded multipart request with a file part, uploads harmless marker files in its
//! place: an HTML page and an SVG image whose only content is a marker text, a plain text file,
//! and at high strength an HTML file with a double extension (`.jpg.html`). None holds script.
//! It then looks for each file where the site serves it: a link or `Location` in the upload's
//! response naming it, then the upload's own directory and common upload folders. An HTML or
//! SVG file served back from the site as `text/html` or `image/svg+xml`, inline, is active
//! content an attacker could put there (stored cross-site scripting): risk high.
//!
//! Opt-in ([`ActiveRule::opt_in`]): every file it uploads stays on the server. Each alert lists
//! the files it left, and an informational alert lists them whenever an upload was accepted,
//! so they can be removed. It runs only when named with `--rules` or turned on in a policy.
//! Requests: per file one upload and up to seven fetches; one file at low strength, three at
//! medium, four at high and insane. Each upload endpoint (method and path) is tested once.

use crate::http::RawRequest;
use crate::scan::active::points::multipart_parts;
use crate::scan::active::{rand_u64, ActiveRule, BoxFuture, Cx, Response, RuleScope, Strength};
use crate::scan::{AlertDef, Confidence, Risk};

static SERVED: AlertDef = AlertDef {
    alert_ref: "40041-1",
    name: "File Upload: Active Content Served Back",
    risk: Risk::High,
    confidence: Confidence::Medium,
    cwe: 434,
    wasc: 42,
    description: "The application accepted an uploaded HTML or SVG file and serves it back from its own origin as \
        a type the browser renders. An attacker can upload a page with script in it and send victims a link to it: \
        the script runs as the site (stored cross-site scripting), with the victim's session.",
    solution: "Accept only the file types the feature needs, checked by content as well as by name. Store uploads \
        outside the web root or on a separate domain, give them random names, serve them with a fixed safe \
        Content-Type and `Content-Disposition: attachment`, and send `X-Content-Type-Options: nosniff`.",
    references: &[
        "https://owasp.org/www-community/vulnerabilities/Unrestricted_File_Upload",
        "https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html",
        "https://cwe.mitre.org/data/definitions/434.html",
    ],
    tags: &["OWASP_2025_A06", "OWASP_2021_A04", "WSTG-v42-BUSL-09"],
};

static LEFT: AlertDef = AlertDef {
    alert_ref: "40041-2",
    name: "File Upload: Test Files Left on the Server",
    risk: Risk::Info,
    confidence: Confidence::Medium,
    cwe: 434,
    wasc: 42,
    description: "The scan uploaded harmless marker files and the upload was accepted. They may still be on the \
        server: other info lists each file and, where it was found, the URL it is served from.",
    solution: "Remove the files listed once testing is done.",
    references: &["https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html"],
    tags: &["WSTG-v42-BUSL-08"],
};

static ALERTS: [&AlertDef; 2] = [&SERVED, &LEFT];

/// A marker file: extension, the Content-Type it is uploaded as, and whether a browser
/// rendering it as served would run script in it.
struct Marker {
    ext: &'static str,
    content_type: &'static str,
    active: bool,
}

const MARKERS: [Marker; 4] = [
    Marker { ext: "html", content_type: "text/html", active: true },
    Marker { ext: "svg", content_type: "image/svg+xml", active: true },
    Marker { ext: "txt", content_type: "text/plain", active: false },
    Marker { ext: "jpg.html", content_type: "image/jpeg", active: true },
];

/// Folders uploads are commonly served from, besides the upload's own.
const FOLDERS: [&str; 6] = ["/uploads/", "/upload/", "/files/", "/images/", "/media/", "/static/uploads/"];

pub struct FileUpload;

impl ActiveRule for FileUpload {
    fn id(&self) -> u32 {
        40041
    }

    fn name(&self) -> &'static str {
        "File Upload"
    }

    fn alerts(&self) -> &'static [&'static AlertDef] {
        &ALERTS
    }

    fn scope(&self) -> RuleScope {
        RuleScope::Page
    }

    fn opt_in(&self) -> bool {
        true
    }

    fn scan<'a>(&'a self, cx: &'a Cx) -> BoxFuture<'a> {
        Box::pin(async move {
            let request = cx.base_request();
            let Some(part) = multipart_parts(request).into_iter().find(|p| p.filename.is_some()) else { return };
            let (method, path) = (&cx.base().method, cx.base().url.split(['?', '#']).next().unwrap_or_default());
            if !cx.once(&format!("40041 {method} {path}")) {
                return;
            }
            let count = match cx.strength() {
                Strength::Low => 1,
                Strength::Medium => 3,
                _ => MARKERS.len(),
            };
            let mut left: Vec<String> = Vec::new();
            let mut proof: Option<(String, Response)> = None;
            let mut accepted: Option<Response> = None;
            for m in &MARKERS[..count] {
                if cx.stopped() {
                    break;
                }
                let marker = format!("brainproxy-upload-{:016x}", rand_u64());
                let name = format!("{marker}.{}", m.ext);
                let Some(upload) = with_file(request, &part, &name, m.content_type, &content(m, &marker)) else {
                    return;
                };
                let Ok(resp) = cx.send(upload).await else { continue };
                if !(200..400).contains(&resp.status) {
                    continue;
                }
                accepted.get_or_insert_with(|| resp.clone());
                let found = find_served(cx, &resp, &name, &marker).await;
                match &found {
                    Some((url, served)) => {
                        left.push(format!("{name} (served at {url} as {})", served.content_type()));
                        if m.active && proof.is_none() && renders_active(served) {
                            proof = Some((url.clone(), served.clone()));
                        }
                    }
                    None => left.push(format!("{name} (not found where it would be served)")),
                }
            }
            let Some(accepted) = accepted else { return };
            let listed = format!("Files this rule uploaded, which may still be on the server:\n{}", left.join("\n"));
            if let Some((url, served)) = proof {
                let mut f = SERVED.raise(part.name.clone(), served.content_type());
                f.attack = format!("an HTML or SVG marker file uploaded as [{}]", part.name);
                f.other_info =
                    format!("The uploaded file is served at {url} as {}.\n\n{listed}", served.content_type());
                cx.report(f, &served);
            }
            let mut f = LEFT.raise(part.name.clone(), "");
            f.other_info = listed;
            cx.report(f, &accepted);
        })
    }
}

/// The marker file's content: the marker text and nothing that runs.
fn content(m: &Marker, marker: &str) -> String {
    match m.ext {
        "svg" => format!(
            "<svg xmlns=\"http://www.w3.org/2000/svg\" width=\"300\" height=\"20\"><text x=\"0\" y=\"15\">{marker}</text></svg>"
        ),
        "txt" => format!("{marker}\n"),
        _ => format!("<!DOCTYPE html><html><head><title>{marker}</title></head><body><p>{marker}</p></body></html>"),
    }
}

/// The request with `part`, a file part, replaced by `name` of type `content_type` holding
/// `body`; its other parts as they were.
fn with_file(
    request: &[u8],
    part: &crate::scan::active::points::MultipartPart,
    name: &str,
    content_type: &str,
    body: &str,
) -> Option<Vec<u8>> {
    let span = &request[part.span.clone()];
    let delimiter = &span[..span.iter().position(|&b| b == b'\r')?];
    let field = part.name.replace(['"', '\r', '\n'], "");
    let mut out = request[..part.span.start].to_vec();
    out.extend_from_slice(delimiter);
    out.extend_from_slice(
        format!(
            "\r\nContent-Disposition: form-data; name=\"{field}\"; filename=\"{name}\"\r\nContent-Type: {content_type}\r\n\r\n{body}\r\n"
        )
        .as_bytes(),
    );
    out.extend_from_slice(&request[part.span.end..]);
    Some(RawRequest::from_bytes(out).update_content_length().into_bytes())
}

/// Looks for the uploaded file where it would be served: URLs naming it in the upload's
/// response, then the upload's folder and common upload folders. The URL and the response
/// that has the marker.
async fn find_served(cx: &Cx, upload: &Response, name: &str, marker: &str) -> Option<(String, Response)> {
    let base = url::Url::parse(&cx.base().url).ok()?;
    let mut candidates: Vec<url::Url> = Vec::new();
    let mut add = |u: Option<url::Url>| {
        if let Some(u) = u.filter(|u| u.origin() == base.origin()) {
            if !candidates.contains(&u) {
                candidates.push(u);
            }
        }
    };
    for text in upload.headers_named("location").chain([upload.body_str()]) {
        for (at, _) in text.match_indices(name) {
            let start = text[..at].rfind(['"', '\'', '(', '=', ' ', '>', '\n']).map_or(0, |i| i + 1);
            add(base.join(&text[start..at + name.len()]).ok());
        }
    }
    add(base.join(name).ok());
    for folder in FOLDERS {
        add(base.join(&format!("{folder}{name}")).ok());
    }
    for u in candidates.into_iter().take(7) {
        let path = &u[url::Position::BeforePath..url::Position::AfterQuery];
        let Ok(resp) = cx.send(cx.request_for("GET", path)).await else { continue };
        if resp.status == 200 && resp.body_str().contains(marker) {
            return Some((u.to_string(), resp));
        }
    }
    None
}

/// Whether a browser shows `resp` as a page or SVG of the site's own: served as HTML or SVG,
/// and not as a download.
fn renders_active(resp: &Response) -> bool {
    let ct = resp.content_type();
    let active = ct.starts_with("text/html") || ct.starts_with("image/svg+xml") || ct.starts_with("application/xhtml");
    let download =
        resp.header("content-disposition").is_some_and(|d| d.trim().to_ascii_lowercase().starts_with("attachment"));
    active && !download
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_file_part_is_replaced_and_the_rest_kept() {
        let body =
            "--b\r\nContent-Disposition: form-data; name=\"a\"\r\n\r\none\r\n--b\r\nContent-Disposition: form-data; \
                    name=\"up\"; filename=\"x.png\"\r\nContent-Type: image/png\r\n\r\nDATA\r\n--b--\r\n";
        let raw = format!(
            "POST /u HTTP/1.1\r\nHost: h\r\nContent-Type: multipart/form-data; boundary=b\r\nContent-Length: {}\r\n\r\n{body}",
            body.len()
        );
        let parts = multipart_parts(raw.as_bytes());
        let part = parts.iter().find(|p| p.filename.is_some()).unwrap();
        let out =
            String::from_utf8(with_file(raw.as_bytes(), part, "m.svg", "image/svg+xml", "<svg/>").unwrap()).unwrap();
        let want =
            "--b\r\nContent-Disposition: form-data; name=\"a\"\r\n\r\none\r\n--b\r\nContent-Disposition: form-data; \
                    name=\"up\"; filename=\"m.svg\"\r\nContent-Type: image/svg+xml\r\n\r\n<svg/>\r\n--b--\r\n";
        assert!(out.ends_with(want), "{out}");
        assert!(out.contains(&format!("Content-Length: {}\r\n", want.len())));
        let names: Vec<(String, bool)> =
            multipart_parts(out.as_bytes()).into_iter().map(|p| (p.name, p.filename.is_some())).collect();
        assert_eq!(names, [("a".to_string(), false), ("up".to_string(), true)]);
    }

    #[test]
    fn active_content_is_html_or_svg_shown_inline() {
        let r = |head: &str| {
            Response::parse(vec![], format!("HTTP/1.1 200 OK\r\n{head}\r\n\r\n").into_bytes(), Default::default())
                .unwrap()
        };
        assert!(renders_active(&r("Content-Type: text/html; charset=utf-8")));
        assert!(renders_active(&r("Content-Type: image/svg+xml")));
        assert!(!renders_active(&r("Content-Type: text/html\r\nContent-Disposition: attachment; filename=x")));
        assert!(!renders_active(&r("Content-Type: text/plain")));
        assert!(!content(&MARKERS[1], "m").contains("script") && !content(&MARKERS[0], "m").contains("script"));
    }
}
