//! The parsed request/response pair that scan rules inspect.

use std::sync::OnceLock;

/// A captured exchange with everything parsed up front.
#[derive(Debug, Clone, Default)]
pub struct Message {
    pub history_id: i64,
    pub method: String,
    pub url: String,
    pub scheme: String,
    pub host: String,
    pub port: u16,
    pub path: String,
    pub query: Option<String>,
    pub req_headers: Vec<(String, String)>,
    pub req_body: Vec<u8>,
    pub status: u16,
    pub resp_headers: Vec<(String, String)>,
    /// Decoded (de-chunked, decompressed) response body.
    pub resp_body: Vec<u8>,
    text: OnceLock<String>,
}

impl Message {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        history_id: i64,
        method: String,
        url: String,
        scheme: String,
        host: String,
        port: u16,
        path: String,
        query: Option<String>,
        req_headers: Vec<(String, String)>,
        req_body: Vec<u8>,
        status: u16,
        resp_headers: Vec<(String, String)>,
        resp_body: Vec<u8>,
    ) -> Self {
        Self {
            history_id,
            method,
            url,
            scheme,
            host,
            port,
            path,
            query,
            req_headers,
            req_body,
            status,
            resp_headers,
            resp_body,
            text: OnceLock::new(),
        }
    }

    /// Parses a raw exchange (as sent/received) into a message.
    pub fn from_exchange(history_id: i64, target: &crate::http::Target, request: &[u8], response: &[u8]) -> Self {
        let c = crate::capture::Capture::new("", target, request, Some(response), None, None);
        let headers = |s: Option<&str>| -> Vec<(String, String)> {
            s.and_then(|s| serde_json::from_str(s).ok()).unwrap_or_default()
        };
        Self::new(
            history_id,
            c.method.clone(),
            c.url.clone(),
            c.scheme.clone(),
            c.host.clone(),
            c.port,
            c.path.clone(),
            c.query.clone(),
            headers(Some(&c.req_headers)),
            c.req_body.clone(),
            c.status.unwrap_or(0),
            headers(c.resp_headers.as_deref()),
            c.resp_body.clone().unwrap_or_default(),
        )
    }

    /// Response body as text (lossy UTF-8).
    pub fn body(&self) -> &str {
        self.text.get_or_init(|| String::from_utf8_lossy(&self.resp_body).into_owned())
    }

    pub fn req_body_str(&self) -> String {
        String::from_utf8_lossy(&self.req_body).into_owned()
    }

    pub fn resp_header(&self, name: &str) -> Option<&str> {
        header(&self.resp_headers, name)
    }

    pub fn resp_headers_named<'a>(&'a self, name: &'a str) -> impl Iterator<Item = &'a str> + 'a {
        self.resp_headers.iter().filter(move |(k, _)| k.eq_ignore_ascii_case(name)).map(|(_, v)| v.as_str())
    }

    pub fn req_header(&self, name: &str) -> Option<&str> {
        header(&self.req_headers, name)
    }

    pub fn req_headers_named<'a>(&'a self, name: &'a str) -> impl Iterator<Item = &'a str> + 'a {
        self.req_headers.iter().filter(move |(k, _)| k.eq_ignore_ascii_case(name)).map(|(_, v)| v.as_str())
    }

    pub fn content_type(&self) -> String {
        self.resp_header("content-type").unwrap_or("").to_ascii_lowercase()
    }

    pub fn is_https(&self) -> bool {
        self.scheme.eq_ignore_ascii_case("https")
    }

    /// ZAP's isHtml: Content-Type mentions html.
    pub fn is_html(&self) -> bool {
        self.content_type().contains("html")
    }

    pub fn is_javascript(&self) -> bool {
        let ct = self.content_type();
        ct.contains("javascript") || ct.contains("ecmascript")
    }

    pub fn is_json(&self) -> bool {
        self.content_type().contains("json")
    }

    pub fn is_xml(&self) -> bool {
        self.content_type().contains("xml")
    }

    pub fn is_css(&self) -> bool {
        self.content_type().contains("css")
    }

    /// Text-like content (html, js, json, xml, css, text/*).
    pub fn is_text(&self) -> bool {
        let ct = self.content_type();
        ct.starts_with("text/")
            || ct.contains("javascript")
            || ct.contains("json")
            || ct.contains("xml")
            || ct.contains("html")
    }

    pub fn is_image(&self) -> bool {
        self.content_type().starts_with("image/")
    }

    pub fn is_redirect(&self) -> bool {
        (300..400).contains(&self.status)
    }

    pub fn is_success(&self) -> bool {
        (200..300).contains(&self.status)
    }

    pub fn is_client_error(&self) -> bool {
        (400..500).contains(&self.status)
    }

    pub fn is_server_error(&self) -> bool {
        (500..600).contains(&self.status)
    }

    /// URL-decoded query parameters, in order.
    pub fn query_params(&self) -> Vec<(String, String)> {
        self.query.as_deref().map(parse_form).unwrap_or_default()
    }

    /// URL-decoded form parameters from an application/x-www-form-urlencoded body.
    pub fn form_params(&self) -> Vec<(String, String)> {
        let ct = self.req_header("content-type").unwrap_or("").to_ascii_lowercase();
        if ct.contains("application/x-www-form-urlencoded") {
            parse_form(&self.req_body_str())
        } else {
            Vec::new()
        }
    }

    /// Query and form parameters together (ZAP's url + form params).
    pub fn params(&self) -> Vec<(String, String)> {
        let mut p = self.query_params();
        p.extend(self.form_params());
        p
    }

    /// Cookies sent with the request.
    pub fn request_cookies(&self) -> Vec<(String, String)> {
        self.req_headers_named("cookie")
            .flat_map(|v| v.split(';'))
            .filter_map(|c| {
                let (k, v) = c.split_once('=').unwrap_or((c, ""));
                let k = k.trim();
                (!k.is_empty()).then(|| (k.to_string(), v.trim().to_string()))
            })
            .collect()
    }

    /// Set-Cookie headers in the response.
    pub fn set_cookies(&self) -> Vec<SetCookie> {
        self.resp_headers_named("set-cookie").map(SetCookie::parse).collect()
    }
}

fn header<'a>(headers: &'a [(String, String)], name: &str) -> Option<&'a str> {
    headers.iter().find(|(k, _)| k.eq_ignore_ascii_case(name)).map(|(_, v)| v.as_str())
}

pub fn parse_form(s: &str) -> Vec<(String, String)> {
    s.split('&')
        .filter(|p| !p.is_empty())
        .map(|p| {
            let (k, v) = p.split_once('=').unwrap_or((p, ""));
            (url_decode(k), url_decode(v))
        })
        .collect()
}

pub fn url_decode(s: &str) -> String {
    let plus: String = s.replace('+', " ");
    percent_encoding::percent_decode_str(&plus).decode_utf8_lossy().into_owned()
}

/// A parsed Set-Cookie header.
#[derive(Debug, Clone)]
pub struct SetCookie {
    pub raw: String,
    pub name: String,
    pub value: String,
    /// Attribute names (lower-case) with their values.
    pub attrs: Vec<(String, String)>,
}

impl SetCookie {
    pub fn parse(raw: &str) -> Self {
        let mut parts = raw.split(';');
        let first = parts.next().unwrap_or("");
        let (name, value) = first.split_once('=').unwrap_or((first, ""));
        let attrs = parts
            .map(|a| {
                let (k, v) = a.split_once('=').unwrap_or((a, ""));
                (k.trim().to_ascii_lowercase(), v.trim().to_string())
            })
            .filter(|(k, _)| !k.is_empty())
            .collect();
        Self { raw: raw.to_string(), name: name.trim().to_string(), value: value.trim().to_string(), attrs }
    }

    pub fn has(&self, attr: &str) -> bool {
        self.attrs.iter().any(|(k, _)| k == attr)
    }

    pub fn attr(&self, attr: &str) -> Option<&str> {
        self.attrs.iter().find(|(k, _)| k == attr).map(|(_, v)| v.as_str())
    }

    /// Cookies being deleted (expired or empty) are usually ignored by rules.
    pub fn is_expired(&self) -> bool {
        if self.value.is_empty() {
            return true;
        }
        if let Some(age) = self.attr("max-age") {
            if age.trim().parse::<i64>().map(|a| a <= 0).unwrap_or(false) {
                return true;
            }
        }
        if let Some(exp) = self.attr("expires") {
            // Dates in the past: a cheap check for the common "Thu, 01 Jan 1970" form.
            if exp.contains("1970") {
                return true;
            }
        }
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_params_and_cookies() {
        let m = Message::new(
            1,
            "POST".into(),
            "https://a.test/x?a=1&b=two+words".into(),
            "https".into(),
            "a.test".into(),
            443,
            "/x".into(),
            Some("a=1&b=two+words".into()),
            vec![
                ("Content-Type".into(), "application/x-www-form-urlencoded".into()),
                ("Cookie".into(), "s=1; t=2".into()),
            ],
            b"c=%3Cx%3E".to_vec(),
            200,
            vec![("Set-Cookie".into(), "sid=abc; Path=/; HttpOnly; SameSite=Lax".into())],
            Vec::new(),
        );
        assert_eq!(
            m.params(),
            vec![("a".into(), "1".into()), ("b".into(), "two words".into()), ("c".into(), "<x>".into())]
        );
        assert_eq!(m.request_cookies().len(), 2);
        let c = &m.set_cookies()[0];
        assert_eq!((c.name.as_str(), c.has("httponly"), c.attr("samesite")), ("sid", true, Some("Lax")));
    }
}
