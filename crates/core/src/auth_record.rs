//! Builds an auth profile from a login recorded through the proxy (`auth record`). The
//! user logs in in a browser as usual; the recorded exchanges show the login request,
//! a CSRF token it carried and the page that handed it out, a bearer token and the
//! header it travels in, and a page that tells logged-in from logged-out. Every
//! extraction pattern is checked against the recorded response it has to work on.
//!
//! A login that can't be replayed (single sign-on on another host, a second factor, a
//! token from a later step) gives a session profile instead: the recorded cookies and
//! token as static headers, valid until the site expires them.

use regex::Regex;
use serde::Serialize;
use serde_json::Value;

use crate::auth::{AuthProfile, Secret};
use crate::capture::decode_body;
use crate::http::request::split_head_body;
use crate::http::{parse_response_head, RawRequest, Target};
use crate::scan::message::{parse_form, SetCookie};
use crate::scan::passive::util::decode_entities;

/// One recorded exchange, in recording order.
pub struct Recorded {
    pub id: i64,
    pub target: Target,
    pub request: Vec<u8>,
    pub response: Vec<u8>,
}

#[derive(Debug, Serialize, PartialEq, Clone, Copy)]
#[serde(rename_all = "snake_case")]
pub enum Mode {
    /// brainproxy logs in by itself, and again when the session ends.
    Replay,
    /// The recorded session only; record again once it expires.
    Session,
}

#[derive(Debug, Serialize, Default)]
pub struct Evidence {
    pub login: Option<i64>,
    pub csrf: Option<i64>,
    pub token: Option<i64>,
    pub check: Option<i64>,
}

#[derive(Debug, Serialize)]
pub struct Proposal {
    pub mode: Mode,
    /// With the recorded password; redact before showing.
    pub profile: AuthProfile,
    /// History ids each part was taken from.
    pub evidence: Evidence,
    /// What was found, in plain words.
    pub found: Vec<String>,
    pub warnings: Vec<String>,
}

struct Ex {
    id: i64,
    url: url::Url,
    method: String,
    headers: Vec<(String, String)>,
    body: String,
    status: u16,
    set_cookies: Vec<SetCookie>,
    content_type: String,
    /// Response head plus decoded body: what the login code's patterns run on.
    text: String,
}

impl Ex {
    fn parse(r: &Recorded) -> Option<Self> {
        let req = RawRequest::from_bytes(r.request.clone());
        let head = req.head().ok()?;
        let url = if head.target.starts_with("http://") || head.target.starts_with("https://") {
            url::Url::parse(&head.target).ok()?
        } else {
            url::Url::parse(&format!("{}{}", r.target.origin(), head.target)).ok()?
        };
        let resp = parse_response_head(&r.response).ok()?;
        let (h, b) = split_head_body(&r.response);
        let mut text = String::from_utf8_lossy(h).into_owned();
        text.push_str(&String::from_utf8_lossy(&decode_body(&resp.headers, b)));
        Some(Ex {
            id: r.id,
            url,
            method: head.method.to_ascii_uppercase(),
            body: String::from_utf8_lossy(req.body()).into_owned(),
            set_cookies: resp
                .headers
                .iter()
                .filter(|(k, _)| k.eq_ignore_ascii_case("set-cookie"))
                .map(|(_, v)| SetCookie::parse(v))
                .collect(),
            content_type: resp.header("content-type").unwrap_or("").to_ascii_lowercase(),
            status: resp.status,
            headers: head.headers,
            text,
        })
    }

    fn header(&self, name: &str) -> Option<&str> {
        self.headers.iter().find(|(k, _)| k.eq_ignore_ascii_case(name)).map(|(_, v)| v.as_str())
    }

    fn origin(&self) -> String {
        self.url.origin().ascii_serialization()
    }

    fn json(&self) -> bool {
        self.header("content-type").is_some_and(|c| c.to_ascii_lowercase().contains("json"))
            || self.body.trim_start().starts_with('{')
    }

    fn form(&self) -> bool {
        self.header("content-type").is_some_and(|c| c.to_ascii_lowercase().contains("x-www-form-urlencoded"))
    }

    /// Request body fields: form pairs, or JSON string values by dotted path.
    fn fields(&self) -> Vec<(String, String)> {
        if self.json() {
            let mut out = Vec::new();
            if let Ok(v) = serde_json::from_str::<Value>(&self.body) {
                json_strings(&v, "", &mut out);
            }
            out
        } else if self.form() || self.body.contains('=') {
            parse_form(&self.body)
        } else {
            vec![]
        }
    }

    fn has_password_input(&self) -> bool {
        PASSWORD_INPUT.is_match(&self.text)
    }

    fn is_page(&self) -> bool {
        let path = self.url.path().to_ascii_lowercase();
        let asset =
            [".js", ".css", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".woff", ".woff2", ".map", ".webp"]
                .iter()
                .any(|e| path.ends_with(e));
        !asset && (self.content_type.contains("html") || self.content_type.contains("json"))
    }
}

fn json_strings(v: &Value, path: &str, out: &mut Vec<(String, String)>) {
    match v {
        Value::Object(m) => {
            for (k, x) in m {
                let p = if path.is_empty() { k.clone() } else { format!("{path}.{k}") };
                json_strings(x, &p, out);
            }
        }
        Value::String(s) => out.push((path.to_string(), s.clone())),
        _ => {}
    }
}

fn set_json(v: &mut Value, path: &str, to: &str) {
    let mut cur = v;
    for part in path.split('.') {
        match cur.get_mut(part) {
            Some(next) => cur = next,
            None => return,
        }
    }
    *cur = Value::String(to.into());
}

static PASSWORD_INPUT: std::sync::LazyLock<Regex> =
    std::sync::LazyLock::new(|| Regex::new(r#"(?i)<input[^>]*type=["']?password"#).unwrap());

/// Names of password inputs on recorded pages.
fn password_names(exs: &[Ex]) -> Vec<String> {
    let re = Regex::new(r#"(?i)<input\b[^>]*>"#).unwrap();
    let name = Regex::new(r#"(?i)\bname=["']?([^"'\s>]+)"#).unwrap();
    let mut out = Vec::new();
    for e in exs {
        for m in re.find_iter(&e.text) {
            if PASSWORD_INPUT.is_match(m.as_str()) {
                if let Some(c) = name.captures(m.as_str()) {
                    out.push(decode_entities(&c[1]));
                }
            }
        }
    }
    out
}

fn last_segment(key: &str) -> String {
    key.rsplit(['.', '[']).next().unwrap_or(key).trim_end_matches(']').to_ascii_lowercase()
}

fn is_password_key(key: &str, known: &[String]) -> bool {
    let k = last_segment(key);
    known.iter().any(|n| n == key)
        || k.contains("password")
        || k.contains("passwd")
        || ["pass", "pwd", "pw"].contains(&k.as_str())
}

fn is_user_key(key: &str) -> bool {
    let k = last_segment(key);
    ["user", "login", "email", "mail", "account", "ident", "name", "uid"].iter().any(|w| k.contains(w))
}

/// A value that looks generated (a token), not typed.
fn tokenish(v: &str) -> bool {
    v.len() >= 8
        && v.len() <= 4096
        && !v.contains(' ')
        && v.chars().any(|c| c.is_ascii_digit())
        && v.chars().any(|c| c.is_ascii_alphabetic())
}

/// The first pattern (group 1) that extracts `value` from `text`, as the login code reads it.
fn pattern_for(text: &str, value: &str, candidates: Vec<String>) -> Option<String> {
    candidates.into_iter().find(|p| {
        Regex::new(p)
            .ok()
            .and_then(|re| re.captures(text))
            .and_then(|c| c.get(1))
            .is_some_and(|m| decode_entities(m.as_str()) == value)
    })
}

/// Patterns for a value found in `text`: by cookie, input name, JSON key, then by the
/// text just before it.
fn extraction_candidates(text: &str, value: &str, field: Option<&str>) -> Vec<String> {
    let mut out = Vec::new();
    let esc_field = field.map(|f| regex::escape(&last_segment_raw(f)));
    if let Some(f) = &esc_field {
        out.push(format!(r#"(?i)set-cookie:\s*{f}=([^;\r\n]+)"#));
        out.push(format!(r#"name=["']?{f}["']?[^>]*?value=["']([^"']*)["']"#));
        out.push(format!(r#"value=["']([^"']*)["'][^>]*?name=["']?{f}["']?"#));
        out.push(format!(r#""{f}"\s*:\s*"([^"]+)""#));
    }
    // Context: up to 40 characters before the value, from a tag or line start.
    let encoded = value.replace('&', "&amp;");
    if let Some(at) = text.find(value).or_else(|| text.find(&encoded)) {
        let mut start = at.saturating_sub(40);
        while !text.is_char_boundary(start) {
            start += 1;
        }
        let before = &text[start..at];
        let cut = before.rfind(['<', '\n', '{', ',', ';']).map(|i| i + 1).unwrap_or(0);
        let ctx = before[cut..].trim_start();
        if ctx.len() >= 4 {
            out.push(format!("{}([^\"'<>\\s;,]+)", regex::escape(ctx)));
        }
    }
    out
}

/// A JSON key path's last part, or a form key as written (`user[token]` stays whole).
fn last_segment_raw(key: &str) -> String {
    if key.contains('[') {
        key.to_string()
    } else {
        key.rsplit('.').next().unwrap_or(key).to_string()
    }
}

/// Analyzes a recording. `site` is the address the recording started at, if known.
pub fn analyze(recorded: &[Recorded], name: &str, site: Option<&str>) -> Proposal {
    let exs: Vec<Ex> = recorded.iter().filter_map(Ex::parse).collect();
    let mut found = Vec::new();
    let mut warnings = Vec::new();
    let mut evidence = Evidence::default();
    let known = password_names(&exs);

    // The login: the last request that posted a password and wasn't answered with the form again.
    let candidates: Vec<(usize, String)> = exs
        .iter()
        .enumerate()
        .filter(|(_, e)| matches!(e.method.as_str(), "POST" | "PUT" | "PATCH"))
        .filter_map(|(i, e)| {
            e.fields().into_iter().find(|(k, v)| !v.is_empty() && is_password_key(k, &known)).map(|(k, _)| (i, k))
        })
        .collect();
    let ok = |e: &Ex| (200..400).contains(&e.status) && !(e.content_type.contains("html") && e.has_password_input());
    let login = candidates.iter().rev().find(|(i, _)| ok(&exs[*i])).or_else(|| {
        let last = candidates.last();
        if last.is_some() {
            warnings
                .push("The login response looked like a failed login (the form came back). Check the password.".into());
        }
        last
    });
    let app_origin = site
        .and_then(|s| url::Url::parse(s).ok())
        .map(|u| u.origin().ascii_serialization())
        .or_else(|| login.map(|(i, _)| exs[*i].origin()))
        .or_else(|| exs.first().map(Ex::origin));

    let session = |why: String, warnings: &mut Vec<String>, found: &mut Vec<String>, evidence: &mut Evidence| {
        warnings.push(why);
        session_profile(&exs, name, app_origin.as_deref(), found, evidence)
    };

    let Some(&(li, ref pass_key)) = login else {
        let profile = session(
            "No login request with a password was recorded, so brainproxy can't log in by itself.".into(),
            &mut warnings,
            &mut found,
            &mut evidence,
        );
        return Proposal { mode: Mode::Session, profile, evidence, found, warnings };
    };
    let le = &exs[li];
    evidence.login = Some(le.id);
    found.push(format!("Login: {} {} (history #{})", le.method, le.url, le.id));

    if app_origin.as_deref().is_some_and(|o| o != le.origin()) {
        let why = format!(
            "The password went to {} (single sign-on on another site); the profile uses the recorded session instead.",
            le.origin()
        );
        let profile = session(why, &mut warnings, &mut found, &mut evidence);
        return Proposal { mode: Mode::Session, profile, evidence, found, warnings };
    }
    // A second factor right after the login can't be replayed.
    let second = exs[li + 1..].iter().find(|e| {
        e.method == "POST"
            && e.fields().iter().any(|(k, v)| {
                let k = last_segment(k);
                ["otp", "totp", "mfa", "2fa", "code", "verification"].iter().any(|w| k.contains(w))
                    && v.len() <= 10
                    && v.chars().all(|c| c.is_ascii_digit())
            })
    });
    if let Some(s) = second {
        let why = format!(
            "A one-time code was entered after the login (history #{}); the profile uses the recorded session instead.",
            s.id
        );
        let profile = session(why, &mut warnings, &mut found, &mut evidence);
        return Proposal { mode: Mode::Session, profile, evidence, found, warnings };
    }

    let fields = le.fields();
    let password = fields.iter().find(|(k, _)| k == pass_key).map(|(_, v)| v.clone()).unwrap_or_default();
    let user = fields
        .iter()
        .filter(|(k, v)| k != pass_key && !v.is_empty() && !tokenish(v))
        .find(|(k, _)| is_user_key(k))
        .or_else(|| fields.iter().find(|(k, v)| k != pass_key && !v.is_empty() && !tokenish(v)))
        .cloned();
    if let Some((k, v)) = &user {
        found.push(format!("Username field {k} ({v})"));
    } else {
        warnings.push("No username field was recognised; the request is replayed as recorded.".into());
    }
    found.push(format!("Password field {pass_key}"));

    // CSRF: a generated value the login sent that an earlier response handed out.
    let mut csrf: Option<(String, String, String, i64)> = None; // (value, url, pattern, id)
    let header_candidates: Vec<(String, String)> = le
        .headers
        .iter()
        .filter(|(k, _)| {
            let k = k.to_ascii_lowercase();
            k.contains("csrf") || k.contains("xsrf")
        })
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect();
    for (key, value) in fields.iter().filter(|(k, v)| k != pass_key && tokenish(v)).chain(&header_candidates) {
        let source = exs[..li].iter().rev().find(|e| {
            e.method == "GET" && (e.text.contains(value.as_str()) || e.text.contains(&value.replace('&', "&amp;")))
        });
        let Some(src) = source else { continue };
        // A header value usually comes from a cookie of a similar name, else the page.
        let cookie = src.set_cookies.iter().find(|c| &c.value == value).map(|c| c.name.clone());
        let field = cookie.as_deref().or(Some(key.as_str()));
        if let Some(p) = pattern_for(&src.text, value, extraction_candidates(&src.text, value, field)) {
            if csrf.as_ref().is_some_and(|(v, ..)| v != value) {
                warnings.push(format!("More than one token was sent ({key} too); only the first is refreshed."));
                continue;
            }
            found.push(format!("CSRF token {key}, from {} (history #{})", src.url, src.id));
            csrf = Some((value.clone(), src.url.to_string(), p, src.id));
        }
    }
    evidence.csrf = csrf.as_ref().map(|c| c.3);

    // The login request as a template: values become placeholders, stale cookies go.
    let mut body = le.body.clone();
    let user_value = user.as_ref().map(|(_, v)| v.clone());
    let csrf_value = csrf.as_ref().map(|c| c.0.clone());
    if le.json() {
        if let Ok(mut v) = serde_json::from_str::<Value>(&le.body) {
            for (k, val) in &fields {
                if k == pass_key {
                    set_json(&mut v, k, "{{password}}");
                } else if Some(val) == user_value.as_ref() && user.as_ref().is_some_and(|(uk, _)| uk == k) {
                    set_json(&mut v, k, "{{username}}");
                } else if Some(val) == csrf_value.as_ref() {
                    set_json(&mut v, k, "{{csrf}}");
                }
            }
            body = v.to_string();
        }
    } else if le.form() || body.contains('=') {
        body = body
            .split('&')
            .map(|pair| {
                let (rk, _) = pair.split_once('=').unwrap_or((pair, ""));
                let k = crate::scan::message::url_decode(rk);
                let v = fields.iter().find(|(fk, _)| *fk == k).map(|(_, v)| v.clone()).unwrap_or_default();
                if &k == pass_key {
                    format!("{rk}={{{{password}}}}")
                } else if user.as_ref().is_some_and(|(uk, _)| *uk == k) {
                    format!("{rk}={{{{username}}}}")
                } else if Some(&v) == csrf_value.as_ref() {
                    format!("{rk}={{{{csrf}}}}")
                } else {
                    pair.to_string()
                }
            })
            .collect::<Vec<_>>()
            .join("&");
    } else {
        body = body.replace(&password, "{{password}}");
        if let Some(u) = &user_value {
            body = body.replace(u.as_str(), "{{username}}");
        }
    }
    let skip = [
        "cookie",
        "content-length",
        "connection",
        "if-none-match",
        "if-modified-since",
        "priority",
        "proxy-connection",
    ];
    let mut head = format!("{} {} HTTP/1.1\r\n", le.method, &le.url[url::Position::BeforePath..]);
    if le.header("host").is_none() {
        head.push_str(&format!("Host: {}\r\n", le.url.host_str().unwrap_or_default()));
    }
    for (k, v) in &le.headers {
        if skip.contains(&k.to_ascii_lowercase().as_str()) {
            continue;
        }
        let v = if csrf_value.as_deref() == Some(v.as_str()) { "{{csrf}}" } else { v.as_str() };
        head.push_str(&format!("{k}: {v}\r\n"));
    }
    let login_request = format!("{head}\r\n{body}");

    let mut profile = AuthProfile {
        name: name.to_string(),
        login_url: Some(le.url.to_string()),
        login_method: le.method.clone(),
        login_request: Some(login_request),
        username: user_value.clone(),
        password: Some(Secret::Literal(password)),
        relogin_interval_secs: 5,
        max_relogins: 20,
        ..Default::default()
    };
    if let Some((_, url, pattern, _)) = &csrf {
        profile.csrf_url = Some(url.clone());
        profile.csrf_regex = Some(pattern.clone());
    }

    // A token the browser sent after the login, and where it came from.
    for e in &exs[li + 1..] {
        let sent = e.headers.iter().find_map(|(k, v)| {
            let lk = k.to_ascii_lowercase();
            if lk == "authorization" {
                let (scheme, tok) =
                    v.split_once(' ').map(|(s, t)| (format!("{s} "), t)).unwrap_or((String::new(), v.as_str()));
                Some((k.clone(), scheme, tok.trim().to_string()))
            } else if (lk.contains("token") || lk.contains("api-key") || lk.contains("apikey"))
                && !lk.contains("csrf")
                && !lk.contains("xsrf")
                && v.len() >= 16
            {
                Some((k.clone(), String::new(), v.clone()))
            } else {
                None
            }
        });
        let Some((header, scheme, token)) = sent else { continue };
        let key = serde_json::from_str::<Value>(le.text.split_once("\r\n\r\n").map(|x| x.1).unwrap_or(""))
            .ok()
            .and_then(|v| {
                let mut all = Vec::new();
                json_strings(&v, "", &mut all);
                all.into_iter().find(|(_, x)| *x == token).map(|(k, _)| k)
            });
        match pattern_for(&le.text, &token, extraction_candidates(&le.text, &token, key.as_deref())) {
            Some(p) => {
                found.push(format!("Token in the login response, sent as {header}"));
                profile.token_regex = Some(p);
                profile.token_header = Some(format!("{header}: {scheme}{{{{token}}}}"));
                evidence.token = Some(le.id);
            }
            None => {
                warnings.push(format!(
                    "The {header} token (sent from history #{}) didn't come from the login response; it is added as recorded \
                     and stops working when it expires.",
                    e.id
                ));
                profile.headers.push((header, format!("{scheme}{token}")));
            }
        }
        break;
    }

    // A page only a logged-in user gets, and what tells the two apart.
    let login_page = exs[..li].iter().rev().find(|e| e.has_password_input());
    let after: Vec<&Ex> = exs[li + 1..]
        .iter()
        .filter(|e| e.method == "GET" && e.status == 200 && e.is_page() && Some(e.origin()) == app_origin)
        .collect();
    // What says the login form is showing: on the login page, and on none of the pages after
    // the login. Any password field is the plainest, but a logged-in page may have one too (a
    // change-password form), so the login form's own field, by name, or the form that posts
    // to the login are tried next.
    let logged_out = login_page.and_then(|l| {
        let names = password_names(std::slice::from_ref(l));
        let action = regex::escape(le.url.path());
        let candidates = std::iter::once(PASSWORD_INPUT.as_str().to_string())
            .chain(names.iter().map(|n| format!(r#"(?i)<input[^>]*\bname=["']?{}["'\s/>]"#, regex::escape(n))))
            .chain([format!(r#"(?i)<form[^>]*action=["']?[^"'\s>]*{action}["'\s>?]"#)]);
        candidates.into_iter().find(|p| {
            let re = Regex::new(p).unwrap();
            re.is_match(&l.text) && !after.iter().any(|e| re.is_match(&e.text))
        })
    });
    let looks_logged_out = |e: &Ex| match &logged_out {
        Some(p) => Regex::new(p).unwrap().is_match(&e.text),
        None => e.has_password_input(),
    };
    let check = after.iter().rev().copied().find(|e| !looks_logged_out(e));
    match check {
        Some(c) => {
            let not_on_login = |p: &str| {
                let re = Regex::new(p).unwrap();
                re.is_match(&c.text) && !login_page.is_some_and(|l| re.is_match(&l.text))
            };
            let by_user = user_value.as_ref().filter(|u| u.len() >= 3).map(|u| regex::escape(u));
            let pattern =
                by_user.into_iter().chain([r"(?i)\b(log ?out|sign ?out)\b".to_string()]).find(|p| not_on_login(p));
            profile.check_url = Some(c.url.to_string());
            evidence.check = Some(c.id);
            match &pattern {
                Some(p) => found.push(format!("Logged-in check: {} matches {p} (history #{})", c.url, c.id)),
                None => warnings.push(format!(
                    "Nothing on {} tells a logged-in page apart; the login is judged by its cookies or token.",
                    c.url
                )),
            }
            profile.logged_in = pattern;
        }
        None => warnings.push(
            "No page was opened after logging in, so there is no logged-in check. Record again and open a page only a \
             logged-in user can see."
                .into(),
        ),
    }
    match logged_out {
        Some(p) => {
            found.push(format!("Logged-out pattern: {p}, which the login page matches and the pages after it don't"));
            profile.logged_out = Some(p);
        }
        None if login_page.is_some() => warnings.push(
            "Nothing on the login page tells it apart from the pages after the login (they have a password field \
             too), so there is no logged-out pattern."
                .into(),
        ),
        None => {}
    }
    Proposal { mode: Mode::Replay, profile, evidence, found, warnings }
}

/// The recorded session: the last cookies and auth header the browser sent to the site.
fn session_profile(
    exs: &[Ex],
    name: &str,
    origin: Option<&str>,
    found: &mut Vec<String>,
    evidence: &mut Evidence,
) -> AuthProfile {
    let mut profile =
        AuthProfile { name: name.into(), relogin_interval_secs: 5, max_relogins: 20, ..Default::default() };
    let last = exs.iter().rev().find(|e| origin.is_none_or(|o| e.origin() == o) && e.status < 400);
    if let Some(e) = last {
        for h in ["cookie", "authorization"] {
            if let Some(v) = e.header(h) {
                let k = e
                    .headers
                    .iter()
                    .find(|(k, _)| k.eq_ignore_ascii_case(h))
                    .map(|(k, _)| k.clone())
                    .unwrap_or_default();
                profile.headers.push((k, v.to_string()));
            }
        }
        evidence.check = Some(e.id);
        found.push(format!("Session from history #{} ({} header(s))", e.id, profile.headers.len()));
    }
    profile
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rec(id: i64, request: &str, response: &str) -> Recorded {
        let t = Target::from_url("https://app.test/").unwrap();
        Recorded {
            id,
            target: t,
            request: request.replace('\n', "\r\n").into_bytes(),
            response: response.replace('\n', "\r\n").into_bytes(),
        }
    }

    fn html(body: &str, extra: &str) -> String {
        format!("HTTP/1.1 200 OK\nContent-Type: text/html\n{extra}Content-Length: {}\n\n{body}", body.len())
    }

    #[test]
    fn form_login_with_csrf_and_check_page() {
        let form = r#"<form method=post action=/login><input type="hidden" name="authenticity_token" value="tok3n-a1b2c3d4"><input name=user[email]><input type="password" name="user[password]"></form>"#;
        let body = "authenticity_token=tok3n-a1b2c3d4&user%5Bemail%5D=alice%40corp.test&user%5Bpassword%5D=s3cret%21";
        let recs = vec![
            rec(1, "GET /login HTTP/1.1\nHost: app.test\n\n", &html(form, "Set-Cookie: sid=anon; Path=/\n")),
            rec(
                2,
                &format!("POST /login HTTP/1.1\nHost: app.test\nCookie: sid=anon\nOrigin: https://app.test\nContent-Type: application/x-www-form-urlencoded\nContent-Length: {}\n\n{body}", body.len()),
                "HTTP/1.1 302 Found\nLocation: /home\nSet-Cookie: sid=live; Path=/\nContent-Length: 0\n\n",
            ),
            rec(3, "GET /home HTTP/1.1\nHost: app.test\nCookie: sid=live\n\n", &html("<p>Hi alice@corp.test</p><a href=/logout>Log out</a>", "")),
        ];
        let p = analyze(&recs, "app", Some("https://app.test/"));
        assert_eq!(p.mode, Mode::Replay, "{p:?}");
        let pr = &p.profile;
        assert_eq!(pr.login_url.as_deref(), Some("https://app.test/login"));
        let req = pr.login_request.as_deref().unwrap();
        assert!(
            req.ends_with("authenticity_token={{csrf}}&user%5Bemail%5D={{username}}&user%5Bpassword%5D={{password}}"),
            "{req}"
        );
        assert!(req.contains("Origin: https://app.test") && !req.to_ascii_lowercase().contains("cookie:"), "{req}");
        assert_eq!(pr.username.as_deref(), Some("alice@corp.test"));
        assert_eq!(pr.password, Some(Secret::Literal("s3cret!".into())));
        assert_eq!(pr.csrf_url.as_deref(), Some("https://app.test/login"));
        let csrf = Regex::new(pr.csrf_regex.as_deref().unwrap()).unwrap();
        assert_eq!(&csrf.captures(form).unwrap()[1], "tok3n-a1b2c3d4");
        assert_eq!(pr.check_url.as_deref(), Some("https://app.test/home"));
        assert_eq!(pr.logged_in.as_deref(), Some(r"alice@corp\.test"));
        assert!(pr.logged_out.is_some());
        assert_eq!((p.evidence.login, p.evidence.csrf, p.evidence.check), (Some(2), Some(1), Some(3)));
        pr.validate().unwrap();
    }

    #[test]
    fn a_change_password_form_after_login_isnt_taken_for_the_login_form() {
        let form = r#"<form method=post action="/wdp/login"><input name=username><input type="password" name="password"></form>"#;
        let home = r#"<h1>Driver portal</h1><a href=/wdp/logout>Logout</a>
            <label>Current password</label><input type="password" class="form-control" id="currentpwd">
            <label>New password</label><input type="password" class="form-control" id="pwd">"#;
        let body = "username=ross%40corp.test&password=s3cret";
        let recs = vec![
            rec(1, "GET /wdp/login HTTP/1.1\nHost: app.test\n\n", &html(form, "Set-Cookie: SESSION=anon; Path=/\n")),
            rec(
                2,
                &format!("POST /wdp/login HTTP/1.1\nHost: app.test\nCookie: SESSION=anon\nContent-Type: application/x-www-form-urlencoded\nContent-Length: {}\n\n{body}", body.len()),
                "HTTP/1.1 302 Found\nLocation: /wdp/user/driverdetails\nSet-Cookie: SESSION=live; Path=/\nContent-Length: 0\n\n",
            ),
            rec(3, "GET /wdp/user/driverdetails HTTP/1.1\nHost: app.test\nCookie: SESSION=live\n\n", &html(home, "")),
        ];
        let p = analyze(&recs, "wdp", Some("https://app.test/"));
        assert_eq!(p.mode, Mode::Replay, "{p:?}");
        let pr = &p.profile;
        // The logged-in page is still the check, though it has password fields.
        assert_eq!(pr.check_url.as_deref(), Some("https://app.test/wdp/user/driverdetails"), "{p:?}");
        assert_eq!(pr.logged_in.as_deref(), Some(r"(?i)\b(log ?out|sign ?out)\b"));
        // The logged-out pattern is the login form's own field, which the logged-in page lacks.
        let out = Regex::new(pr.logged_out.as_deref().unwrap()).unwrap();
        assert!(out.is_match(form) && !out.is_match(home), "{:?}", pr.logged_out);
        // With nothing that tells them apart, no logged-out pattern rather than a wrong one.
        let same = r#"<form method=post action="/wdp/login"><input type="password" name="password"></form>"#;
        let mut recs = recs;
        recs[2] = rec(
            3,
            "GET /wdp/user/driverdetails HTTP/1.1\nHost: app.test\nCookie: SESSION=live\n\n",
            &html(&format!("{same}<a href=/wdp/logout>Logout</a>"), ""),
        );
        let p = analyze(&recs, "wdp", Some("https://app.test/"));
        assert!(p.profile.logged_out.is_none(), "{p:?}");
        assert!(p.warnings.iter().any(|w| w.contains("no logged-out pattern")), "{:?}", p.warnings);
    }

    #[test]
    fn json_login_with_bearer_token() {
        let body = r#"{"email":"bob@corp.test","password":"pw-123"}"#;
        let token = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJib2IifQ.abc123";
        let resp =
            format!("HTTP/1.1 200 OK\nContent-Type: application/json\n\n{{\"data\":{{\"accessToken\":\"{token}\"}}}}");
        let recs = vec![
            rec(
                5,
                &format!("POST /api/login HTTP/1.1\nHost: app.test\nContent-Type: application/json\n\n{body}"),
                &resp,
            ),
            rec(
                6,
                &format!("GET /api/me HTTP/1.1\nHost: app.test\nAuthorization: Bearer {token}\n\n"),
                "HTTP/1.1 200 OK\nContent-Type: application/json\n\n{\"email\":\"bob@corp.test\"}",
            ),
        ];
        let p = analyze(&recs, "api", None);
        assert_eq!(p.mode, Mode::Replay, "{p:?}");
        let pr = &p.profile;
        assert!(pr
            .login_request
            .as_deref()
            .unwrap()
            .ends_with(r#"{"email":"{{username}}","password":"{{password}}"}"#));
        assert_eq!(pr.token_header.as_deref(), Some("Authorization: Bearer {{token}}"));
        let re = Regex::new(pr.token_regex.as_deref().unwrap()).unwrap();
        assert_eq!(&re.captures(&resp).unwrap()[1], token);
        assert_eq!(pr.check_url.as_deref(), Some("https://app.test/api/me"));
        assert_eq!(pr.logged_in.as_deref(), Some(r"bob@corp\.test"));
        pr.validate().unwrap();
    }

    #[test]
    fn second_factor_and_single_sign_on_fall_back_to_the_session() {
        let login = "POST /login HTTP/1.1\nHost: app.test\nContent-Type: application/x-www-form-urlencoded\n\nuser=al&password=pw";
        let otp =
            "POST /verify HTTP/1.1\nHost: app.test\nContent-Type: application/x-www-form-urlencoded\n\notp=123456";
        let ok = "HTTP/1.1 200 OK\nContent-Type: text/html\n\n<p>ok</p>";
        let recs = vec![
            rec(1, login, ok),
            rec(2, otp, ok),
            rec(3, "GET /home HTTP/1.1\nHost: app.test\nCookie: sid=after-mfa\n\n", ok),
        ];
        let p = analyze(&recs, "mfa", Some("https://app.test/"));
        assert_eq!(p.mode, Mode::Session);
        assert_eq!(p.profile.headers, vec![("Cookie".to_string(), "sid=after-mfa".to_string())]);
        assert!(p.warnings[0].contains("one-time code"), "{:?}", p.warnings);
        p.profile.validate().unwrap();

        let sso = vec![
            rec(1, &login.replace("Host: app.test", "Host: idp.test"), ok),
            rec(3, "GET /home HTTP/1.1\nHost: app.test\nCookie: sid=s\n\n", ok),
        ];
        let mut sso = sso;
        sso[0].target = Target::from_url("https://idp.test/").unwrap();
        let p = analyze(&sso, "sso", Some("https://app.test/"));
        assert_eq!(p.mode, Mode::Session);
        assert!(p.warnings[0].contains("single sign-on"), "{:?}", p.warnings);
    }
}
