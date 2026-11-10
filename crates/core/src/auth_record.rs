//! Builds an auth profile from a login recorded through the proxy (`auth record`). The
//! user logs in in a browser as usual; the recorded exchanges show the login request,
//! a CSRF token it carried and the page that handed it out, a bearer token and the
//! header it travels in, and a page that tells logged-in from logged-out. Every
//! extraction pattern is checked against the recorded response it has to work on.
//!
//! A one-time code is replayed too when the profile has the TOTP secret: `{{totp}}` in the
//! login request, or in the request after it that posts the code. A login plain requests
//! can't repeat (single sign-on on another host, a page that builds the login itself, a
//! passkey) is replayed in a browser when its steps were recorded (see
//! [`crate::browser_login`]). Failing both, the profile carries the session instead: the
//! recorded cookies and token as static headers, valid until the site expires them.

use regex::Regex;
use serde::Serialize;
use serde_json::Value;

use crate::auth::{AuthProfile, LoginStep, Secret};
use crate::browser_login::record::{is_code, names_a_one_time_code, Derived};
use crate::browser_login::{BrowserLogin, Do};
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
    /// brainproxy logs in by itself by replaying the recorded steps in a headless browser.
    Browser,
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
    /// The one-time code the login sent, and the history row it went in.
    #[serde(skip)]
    pub code: Option<(String, i64)>,
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

/// What else `auth record finish` knows when it analyzes a recording.
#[derive(Default)]
pub struct Options<'a> {
    /// The profile has a TOTP secret, so a login that sends a one-time code can be replayed.
    pub totp: bool,
    /// What the person did in the login browser, when it was recorded.
    pub steps: Option<&'a Derived>,
    /// Replay the steps in a browser even if plain requests could repeat the login.
    pub in_browser: bool,
}

/// A value a second factor posts: a short number in a field named for one, as the login
/// recorder decides it for a field typed in (a `company_code` or an `invite_code` is not one).
fn is_otp_field(key: &str, value: &str) -> bool {
    let name = key.rsplit(['.', '[']).next().unwrap_or(key).trim_end_matches(']');
    is_code(value) && names_a_one_time_code(&[name])
}

/// A header that carries a token, with its scheme ("Bearer ") and the token.
fn sent_token(e: &Ex) -> Option<(String, String, String)> {
    e.headers.iter().find_map(|(k, v)| {
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
    })
}

/// A recorded request as a template: the body fields named in `by_key` (key, value,
/// placeholder) and every field or header whose value is in `by_value` get their
/// placeholders; stale cookies and framing headers go.
fn template(e: &Ex, by_key: &[(&str, &str, &str)], by_value: &[(&str, &str)]) -> String {
    let fields = e.fields();
    let key = |k: &str| by_key.iter().find(|(key, ..)| *key == k).map(|(.., to)| *to);
    let value = |v: &str| by_value.iter().find(|(val, _)| *val == v).map(|(_, to)| *to);
    let mut body = e.body.clone();
    if e.json() {
        if let Ok(mut v) = serde_json::from_str::<Value>(&e.body) {
            for (k, val) in &fields {
                if let Some(to) = key(k).or_else(|| value(val)) {
                    set_json(&mut v, k, to);
                }
            }
            body = v.to_string();
        }
    } else if e.form() || body.contains('=') {
        body = body
            .split('&')
            .map(|pair| {
                let (rk, _) = pair.split_once('=').unwrap_or((pair, ""));
                let k = crate::scan::message::url_decode(rk);
                let v = fields.iter().find(|(fk, _)| *fk == k).map(|(_, v)| v.clone()).unwrap_or_default();
                match key(&k).or_else(|| value(&v)) {
                    Some(to) => format!("{rk}={to}"),
                    None => pair.to_string(),
                }
            })
            .collect::<Vec<_>>()
            .join("&");
    } else {
        for (_, v, to) in by_key.iter().filter(|(_, v, _)| !v.is_empty()) {
            body = body.replace(v, to);
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
    let mut head = format!("{} {} HTTP/1.1\r\n", e.method, &e.url[url::Position::BeforePath..]);
    if e.header("host").is_none() {
        head.push_str(&format!("Host: {}\r\n", e.url.host_str().unwrap_or_default()));
    }
    for (k, v) in &e.headers {
        if skip.contains(&k.to_ascii_lowercase().as_str()) {
            continue;
        }
        // The whole value, or the part after a scheme word ("Bearer TOKEN").
        let filled = match (value(v), v.split_once(' ')) {
            (Some(to), _) => to.to_string(),
            (None, Some((scheme, rest))) if value(rest.trim()).is_some() => {
                format!("{scheme} {}", value(rest.trim()).unwrap_or_default())
            }
            _ => v.clone(),
        };
        head.push_str(&format!("{k}: {filled}\r\n"));
    }
    format!("{head}\r\n{body}")
}

/// Analyzes a recording. `site` is the address the recording started at, if known.
pub fn analyze(recorded: &[Recorded], name: &str, site: Option<&str>) -> Proposal {
    analyze_with(recorded, name, site, &Options::default())
}

/// [`analyze`], knowing whether the profile can make one-time codes and what was done in the
/// login browser. Plain requests are tried first; a login they can't repeat is replayed in a
/// browser when its steps were recorded; else the profile carries the recorded session.
pub fn analyze_with(recorded: &[Recorded], name: &str, site: Option<&str>, opts: &Options) -> Proposal {
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

    // Why plain requests can't repeat the login, if they can't: the reason, and what to say
    // when the profile then carries the recorded session.
    let mut why_not: Option<(String, String)> = None;
    // A one-time code: the field of the login request it went in, or the request after it.
    let (mut code_in_login, mut code_step): (Option<String>, Option<usize>) = (None, None);
    match login {
        None => {
            why_not = Some((
                "No login request with a password was recorded".into(),
                ", so brainproxy can't log in by itself.".into(),
            ))
        }
        Some(&(li, _)) => {
            let le = &exs[li];
            evidence.login = Some(le.id);
            found.push(format!("Login: {} {} (history #{})", le.method, le.url, le.id));
            if app_origin.as_deref().is_some_and(|o| o != le.origin()) {
                let why = format!("The password went to {} (single sign-on on another site)", le.origin());
                why_not = Some((why, "; the profile uses the recorded session instead.".into()));
            } else {
                code_in_login = le.fields().into_iter().find(|(k, v)| is_otp_field(k, v)).map(|(k, _)| k);
                // A second factor: the first code posted after the login, or, if it was mistyped and
                // sent again, the last time it went to the same place. A later form elsewhere with
                // a number in a field named like a code isn't it.
                let posts_code = |e: &Ex| e.method == "POST" && e.fields().iter().any(|(k, v)| is_otp_field(k, v));
                code_step = exs.iter().enumerate().skip(li + 1).find(|(_, e)| posts_code(e)).map(|(first, fe)| {
                    exs.iter()
                        .enumerate()
                        .skip(first + 1)
                        .rfind(|(_, e)| posts_code(e) && e.url == fe.url)
                        .map_or(first, |(i, _)| i)
                });
                if !opts.totp {
                    if let Some(s) = code_step {
                        let why = format!("A one-time code was entered after the login (history #{})", exs[s].id);
                        why_not = Some((why, "; the profile uses the recorded session instead.".into()));
                    } else if code_in_login.is_some() {
                        let why = format!("A one-time code was sent with the login (history #{})", le.id);
                        why_not = Some((why, "; the profile uses the recorded session instead.".into()));
                    }
                }
            }
        }
    }

    let code = code_step
        .map(|s| &exs[s])
        .or(login.filter(|_| code_in_login.is_some()).map(|(i, _)| &exs[*i]))
        .and_then(|e| e.fields().into_iter().find(|(k, v)| is_otp_field(k, v)).map(|(_, v)| (v, e.id)));

    // The steps recorded in the browser, if they can be replayed.
    let acts = |d: &&Derived| d.steps.iter().any(|s| matches!(s.action, Do::Fill | Do::Click | Do::Press));
    let steps = opts.steps.filter(acts);
    let steps_type_code = steps.is_some_and(|d| d.steps.iter().any(|s| s.value.contains("{{totp")));
    let browser = steps.filter(|_| !steps_type_code || opts.totp);
    if opts.in_browser && browser.is_none() {
        warnings
            .push("No steps to replay in a browser were recorded, so plain requests are used if they can be.".into());
    }
    let plain = login.filter(|_| why_not.is_none() && !(opts.in_browser && browser.is_some()));

    let Some(&(li, ref pass_key)) = plain else {
        let recorded_password =
            login.and_then(|(i, k)| exs[*i].fields().into_iter().find(|(fk, _)| fk == k)).map(|(_, v)| v);
        if let Some(d) = browser {
            match &why_not {
                Some((why, _)) => found.push(format!("{why}: the recorded steps are replayed in a browser instead.")),
                None => found.push("The recorded steps are replayed in a browser, as asked.".into()),
            }
            let site = site.map(str::to_string).or_else(|| exs.first().map(|e| e.url.to_string())).unwrap_or_default();
            let mut profile = AuthProfile {
                name: name.into(),
                username: d.username.clone(),
                password: d.password.clone().or(recorded_password).map(Secret::Literal),
                browser: Some(BrowserLogin { start_url: site, steps: d.steps.clone() }),
                relogin_interval_secs: 5,
                max_relogins: 20,
                ..Default::default()
            };
            found.push(format!("{} browser steps", d.steps.len()));
            warnings.extend(d.warnings.iter().cloned());
            // What the proxy recorded after the last step is the logged-in site: after the row
            // that was the last one then, and after the load of the page the step was taken on
            // (the proxy may write its rows a moment late).
            let by_row = exs.iter().rposition(|e| e.id <= d.last_history).map_or(0, |i| i + 1);
            let by_page =
                exs.iter().rposition(|e| e.method == "GET" && e.url.as_str() == d.last_page).map_or(0, |i| i + 1);
            let (before, after) = exs.split_at(by_row.max(by_page));
            let (before, after): (Vec<&Ex>, Vec<&Ex>) = (before.iter().collect(), after.iter().collect());
            let on_site = |e: &Ex| app_origin.as_deref().is_none_or(|o| e.origin() == o);
            let sent = after.iter().copied().filter(|e| on_site(e)).find_map(|e| Some((e, sent_token(e)?)));
            if let Some((e, (header, scheme, _))) = sent {
                found.push(format!(
                    "Token sent as {header} (history #{}), read off the browser's requests at each login",
                    e.id
                ));
                profile.token_header = Some(format!("{header}: {scheme}{{{{token}}}}"));
                evidence.token = Some(e.id);
            }
            let login_page = before.iter().rev().copied().find(|e| e.has_password_input());
            let pages: Vec<&Ex> = after
                .iter()
                .copied()
                .filter(|e| e.method == "GET" && e.status == 200 && e.is_page() && Some(e.origin()) == app_origin)
                .collect();
            let user = d.username.clone();
            find_checks(
                &mut profile,
                login_page,
                &pages,
                None,
                user.as_ref(),
                &mut found,
                &mut warnings,
                &mut evidence,
            );
            return Proposal { mode: Mode::Browser, profile, evidence, found, warnings, code };
        }
        let (why, then) = why_not.unwrap_or_default();
        warnings.push(format!("{why}{then}"));
        if code_in_login.is_some() || code_step.is_some() {
            warnings.push(
                "With the TOTP secret (auth record finish --totp-secret-env VAR, or in the app) brainproxy makes \
                 the code itself and logs in again when the session ends."
                    .into(),
            );
        } else if steps_type_code {
            warnings.push(
                "The recorded steps type a one-time code: with the TOTP secret (--totp-secret-env VAR, or in the \
                 app) they are replayed in a browser."
                    .into(),
            );
        }
        if let Some(d) = opts.steps {
            warnings.extend(d.warnings.iter().cloned());
        }
        let profile = session_profile(&exs, name, app_origin.as_deref(), &mut found, &mut evidence);
        return Proposal { mode: Mode::Session, profile, evidence, found, warnings, code };
    };
    let le = &exs[li];

    let fields = le.fields();
    let password = fields.iter().find(|(k, _)| k == pass_key).map(|(_, v)| v.clone()).unwrap_or_default();
    let typed =
        |k: &String, v: &String| k != pass_key && Some(k) != code_in_login.as_ref() && !v.is_empty() && !tokenish(v);
    let user = fields
        .iter()
        .filter(|(k, v)| typed(k, v))
        .find(|(k, _)| is_user_key(k))
        .or_else(|| fields.iter().find(|(k, v)| typed(k, v)))
        .cloned();
    if let Some((k, v)) = &user {
        found.push(format!("Username field {k} ({v})"));
    } else {
        warnings.push("No username field was recognised; the request is replayed as recorded.".into());
    }
    found.push(format!("Password field {pass_key}"));
    if let Some(k) = &code_in_login {
        found.push(format!("One-time code field {k}, filled from the TOTP secret"));
    }

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
    let user_value = user.as_ref().map(|(_, v)| v.clone());
    let mut by_key: Vec<(&str, &str, &str)> = vec![(pass_key.as_str(), password.as_str(), "{{password}}")];
    if let Some((k, v)) = &user {
        by_key.push((k.as_str(), v.as_str(), "{{username}}"));
    }
    if let Some(k) = &code_in_login {
        by_key.push((k.as_str(), "", "{{totp}}"));
    }
    let by_value: Vec<(&str, &str)> = csrf.iter().map(|c| (c.0.as_str(), "{{csrf}}")).collect();
    let login_request = template(le, &by_key, &by_value);

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

    // The request that posts the one-time code, as a step after the login request. A
    // generated value it carries comes from a page fetched for it, or from what the login
    // (or its redirects) answered.
    if let Some(si) = code_step {
        let se = &exs[si];
        let step_fields = se.fields();
        let code_key = step_fields.iter().find(|(k, v)| is_otp_field(k, v)).map(|(k, _)| k.clone()).unwrap_or_default();
        let mut token: Option<(String, Option<String>, String)> = None; // (value, page, pattern)
                                                                        // A token may travel in a header instead (X-CSRF-Token, or Authorization with the
                                                                        // ticket the login answered with): the value after any scheme word.
        let in_headers: Vec<(String, String)> = se
            .headers
            .iter()
            .filter_map(|(k, v)| {
                let lk = k.to_ascii_lowercase();
                let value = match lk.as_str() {
                    "authorization" => v.split_once(' ').map_or(v.as_str(), |(_, t)| t).trim(),
                    _ if lk.contains("csrf") || lk.contains("xsrf") || lk.contains("token") => v.trim(),
                    _ => return None,
                };
                Some((k.clone(), value.to_string()))
            })
            .collect();
        let in_body = step_fields.iter().filter(|(k, v)| *k != code_key && tokenish(v));
        for (key, value) in in_body.chain(&in_headers) {
            if token.as_ref().is_some_and(|t| &t.0 == value) {
                continue;
            }
            let header = in_headers.iter().any(|(k, _)| k == key);
            let holds = |e: &&Ex| e.text.contains(value.as_str()) || e.text.contains(&value.replace('&', "&amp;"));
            // A page that can be fetched again, if one handed it out (the form may also have
            // come back with a mistyped code); else what the request before answered.
            let earlier = || exs[li..si].iter().rev();
            let src = earlier().filter(|e| e.method == "GET").find(holds).or_else(|| earlier().find(holds));
            let cookie = src.and_then(|s| s.set_cookies.iter().find(|c| &c.value == value)).map(|c| c.name.clone());
            let field = cookie.as_deref().or((!header).then_some(key.as_str()));
            let read =
                src.and_then(|s| Some((s, pattern_for(&s.text, value, extraction_candidates(&s.text, value, field))?)));
            let Some((src, p)) = read else {
                // Sent again as it was recorded, which a site that hands out a new one each
                // time refuses: said, so a failing login has its reason.
                if header {
                    warnings.push(format!(
                        "The one-time code request's {key} header didn't come from an earlier response; it is sent as \
                         recorded, and the login stops working when it expires."
                    ));
                }
                continue;
            };
            if token.is_some() {
                warnings.push(format!(
                    "The one-time code request sent more than one token ({key} too); only the first is refreshed."
                ));
                continue;
            }
            found.push(format!("Token {key} of the one-time code request, from {} (history #{})", src.url, src.id));
            token = Some((value.clone(), (src.method == "GET").then(|| src.url.to_string()), p));
        }
        let by_value: Vec<(&str, &str)> = token.iter().map(|t| (t.0.as_str(), "{{csrf}}")).collect();
        found.push(format!(
            "One-time code: {} {} (history #{}), field {code_key} filled from the TOTP secret",
            se.method, se.url, se.id
        ));
        profile.login_steps.push(LoginStep {
            url: se.url.to_string(),
            request: template(se, &[(code_key.as_str(), "", "{{totp}}")], &by_value),
            csrf_url: token.as_ref().and_then(|t| t.1.clone()),
            csrf_regex: token.map(|t| t.2),
        });
    }
    // Everything after the last request of the login is the logged-in site.
    let last = code_step.unwrap_or(li);

    // A token the browser sent after the login, and where it came from.
    for e in &exs[last + 1..] {
        let Some((header, scheme, token)) = sent_token(e) else { continue };
        // The answer that handed it out: the last request of the login, else the login request.
        let source = [last, li].into_iter().map(|i| &exs[i]).find_map(|src| {
            let key = serde_json::from_str::<Value>(src.text.split_once("\r\n\r\n").map(|x| x.1).unwrap_or(""))
                .ok()
                .and_then(|v| {
                    let mut all = Vec::new();
                    json_strings(&v, "", &mut all);
                    all.into_iter().find(|(_, x)| *x == token).map(|(k, _)| k)
                });
            pattern_for(&src.text, &token, extraction_candidates(&src.text, &token, key.as_deref())).map(|p| (src, p))
        });
        match source {
            Some((src, p)) => {
                found.push(format!("Token in the login response, sent as {header}"));
                profile.token_regex = Some(p);
                profile.token_header = Some(format!("{header}: {scheme}{{{{token}}}}"));
                evidence.token = Some(src.id);
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
    let after: Vec<&Ex> = exs[last + 1..]
        .iter()
        .filter(|e| e.method == "GET" && e.status == 200 && e.is_page() && Some(e.origin()) == app_origin)
        .collect();
    let action = le.url.path().to_string();
    find_checks(
        &mut profile,
        login_page,
        &after,
        Some(&action),
        user_value.as_ref(),
        &mut found,
        &mut warnings,
        &mut evidence,
    );
    Proposal { mode: Mode::Replay, profile, evidence, found, warnings, code }
}

/// Finds the page that shows a login worked and what tells logged in from logged out:
/// `login_page` is the page with the login form, `after` the site's pages opened after the
/// login, `action` the path the login form posts to.
#[allow(clippy::too_many_arguments)]
fn find_checks(
    profile: &mut AuthProfile,
    login_page: Option<&Ex>,
    after: &[&Ex],
    action: Option<&str>,
    user_value: Option<&String>,
    found: &mut Vec<String>,
    warnings: &mut Vec<String>,
    evidence: &mut Evidence,
) {
    // What says the login form is showing: on the login page, and on none of the pages after
    // the login. Any password field is the plainest, but a logged-in page may have one too (a
    // change-password form), so the login form's own field, by name, or the form that posts
    // to the login are tried next.
    let logged_out = login_page.and_then(|l| {
        let names = password_names(std::slice::from_ref(l));
        let action = action.map(|a| format!(r#"(?i)<form[^>]*action=["']?[^"'\s>]*{}["'\s>?]"#, regex::escape(a)));
        let candidates = std::iter::once(PASSWORD_INPUT.as_str().to_string())
            .chain(names.iter().map(|n| format!(r#"(?i)<input[^>]*\bname=["']?{}["'\s/>]"#, regex::escape(n))))
            .chain(action);
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
            let by_user = user_value.filter(|u| u.len() >= 3).map(|u| regex::escape(u));
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
    fn a_one_time_code_is_replayed_when_the_profile_can_make_it() {
        let form = r#"<form method=post action=/login><input name=user><input type="password" name="password"></form>"#;
        let code_form = r#"<form method=post action=/verify><input type=hidden name=ticket value="t1ck3t-9f8e7d"><input name=otp></form>"#;
        let post = |path: &str, body: &str| {
            format!("POST {path} HTTP/1.1\nHost: app.test\nCookie: pre=1\nContent-Type: application/x-www-form-urlencoded\n\n{body}")
        };
        let found = "HTTP/1.1 302 Found\nLocation: /next\nContent-Length: 0\n\n";
        let recs = vec![
            rec(1, "GET /login HTTP/1.1\nHost: app.test\n\n", &html(form, "Set-Cookie: pre=1; Path=/\n")),
            rec(2, &post("/login", "user=al&password=pw-1"), found),
            rec(3, "GET /verify HTTP/1.1\nHost: app.test\nCookie: pre=1\n\n", &html(code_form, "")),
            // A mistyped code first: the last one sent is the step.
            rec(4, &post("/verify", "ticket=t1ck3t-9f8e7d&otp=111111"), &html(code_form, "")),
            rec(5, &post("/verify", "ticket=t1ck3t-9f8e7d&otp=654321"), found),
            rec(
                6,
                "GET /home HTTP/1.1\nHost: app.test\nCookie: sid=live\n\n",
                &html("<p>Hi al</p><a href=/logout>Log out</a>", ""),
            ),
        ];
        // Without a secret, as before: the session, and the code that was typed for the caller to check.
        let p = analyze(&recs, "mfa", Some("https://app.test/"));
        assert_eq!((p.mode, p.code.clone()), (Mode::Session, Some(("654321".to_string(), 5))), "{p:?}");
        assert!(p.warnings[1].contains("--totp-secret-env"), "{:?}", p.warnings);

        let p = analyze_with(&recs, "mfa", Some("https://app.test/"), &Options { totp: true, ..Default::default() });
        assert_eq!(p.mode, Mode::Replay, "{p:?}");
        let pr = &p.profile;
        assert!(pr.login_request.as_deref().unwrap().ends_with("user={{username}}&password={{password}}"), "{pr:?}");
        let [step] = pr.login_steps.as_slice() else { panic!("{pr:?}") };
        assert_eq!(step.url, "https://app.test/verify");
        assert!(step.request.ends_with("ticket={{csrf}}&otp={{totp}}") && !step.request.contains("Cookie"), "{step:?}");
        assert_eq!(step.csrf_url.as_deref(), Some("https://app.test/verify"));
        let re = Regex::new(step.csrf_regex.as_deref().unwrap()).unwrap();
        assert_eq!(&re.captures(code_form).unwrap()[1], "t1ck3t-9f8e7d");
        // The pages after the code, not the code form, show the login worked.
        assert_eq!(pr.check_url.as_deref(), Some("https://app.test/home"));
        assert!(pr.login_uses_totp());
        // The profile is whole only with the secret it was analyzed for.
        let mut pr = pr.clone();
        pr.totp = Some(crate::totp::Totp::from_input("GEZDGNBVGY3TQOJQ", None, None, None).unwrap());
        pr.validate().unwrap();

        // The ticket the login answers with, sent on in a header: read again at each login,
        // not kept as recorded.
        let api = vec![
            rec(1, "POST /api/login HTTP/1.1\nHost: app.test\nContent-Type: application/json\n\n{\"user\":\"al\",\"password\":\"pw-1\"}", "HTTP/1.1 200 OK\nContent-Type: application/json\n\n{\"mfa\":\"required\",\"ticket\":\"t1ck3t-0a1b2c3d\"}"),
            rec(2, "POST /api/mfa HTTP/1.1\nHost: app.test\nAuthorization: Bearer t1ck3t-0a1b2c3d\nX-Device: stale-7f3a9c1d2e\nContent-Type: application/json\n\n{\"otp\":\"654321\"}", "HTTP/1.1 200 OK\nContent-Type: application/json\n\n{\"ok\":true}"),
            rec(3, "GET /api/me HTTP/1.1\nHost: app.test\nCookie: sid=live\n\n", "HTTP/1.1 200 OK\nContent-Type: application/json\n\n{\"user\":\"al\"}"),
        ];
        let p = analyze_with(&api, "api", None, &Options { totp: true, ..Default::default() });
        let [step] = p.profile.login_steps.as_slice() else { panic!("{p:?}") };
        assert!(step.request.contains("Authorization: Bearer {{csrf}}\r\n"), "{step:?}");
        assert!(step.request.ends_with(r#"{"otp":"{{totp}}"}"#) && !step.request.contains("t1ck3t"), "{step:?}");
        assert_eq!(step.csrf_url, None, "the login's own answer has it: {step:?}");
        let re = Regex::new(step.csrf_regex.as_deref().unwrap()).unwrap();
        assert_eq!(&re.captures(r#"{"mfa":"required","ticket":"n3w-t1ck3t"}"#).unwrap()[1], "n3w-t1ck3t");

        // A code in the login form itself.
        let one = vec![
            rec(1, "GET /login HTTP/1.1\nHost: app.test\n\n", &html(form, "")),
            rec(2, &post("/login", "user=al&password=pw-1&mfa_code=654321"), found),
            rec(3, "GET /home HTTP/1.1\nHost: app.test\nCookie: sid=live\n\n", &html("<p>Hi al</p>", "")),
        ];
        let p = analyze_with(&one, "one", None, &Options { totp: true, ..Default::default() });
        assert_eq!(p.mode, Mode::Replay, "{p:?}");
        let req = p.profile.login_request.as_deref().unwrap();
        assert!(req.ends_with("user={{username}}&password={{password}}&mfa_code={{totp}}"), "{req}");
        assert!(p.profile.login_steps.is_empty());
        assert_eq!(analyze(&one, "one", None).mode, Mode::Session);
    }

    #[test]
    fn a_number_in_a_field_named_for_another_code_is_no_one_time_code() {
        // As the login recorder decides it for a field typed in.
        for key in ["otp", "mfa_code", "code", "verification-code", "smsCode", "user[otp]", "login.totp"] {
            assert!(is_otp_field(key, "482913"), "{key}");
        }
        for key in ["company_code", "invite_code", "zip_code", "postcode", "customerCode", "coupon", "account_code"] {
            assert!(!is_otp_field(key, "0042"), "{key}");
        }
        assert!(!is_otp_field("otp", "12ab56") && !is_otp_field("otp", "123"));

        let form = r#"<form method=post action=/login><input name=user><input type="password" name="password"></form>"#;
        let post = |path: &str, body: &str| {
            format!("POST {path} HTTP/1.1\nHost: app.test\nContent-Type: application/x-www-form-urlencoded\n\n{body}")
        };
        let found = "HTTP/1.1 302 Found\nLocation: /home\nContent-Length: 0\n\n";
        // A plain login with a company code and an invite code: repeatable without a TOTP secret.
        let recs = vec![
            rec(1, "GET /login HTTP/1.1\nHost: app.test\n\n", &html(form, "")),
            rec(2, &post("/login", "user=al&password=pw-1&company_code=0042&invite_code=123456"), found),
            rec(3, "GET /home HTTP/1.1\nHost: app.test\nCookie: sid=live\n\n", &html("<p>Hi al</p>", "")),
        ];
        let p = analyze(&recs, "plain", None);
        assert_eq!((p.mode, p.code.clone()), (Mode::Replay, None), "{p:?}");
        let req = p.profile.login_request.as_deref().unwrap();
        assert!(req.ends_with("company_code=0042&invite_code=123456"), "{req}");
        assert!(p.profile.login_steps.is_empty());
    }

    #[test]
    fn the_code_step_is_the_first_code_posted_after_the_login_or_its_retries() {
        let form = r#"<form method=post action=/login><input name=user><input type="password" name="password"></form>"#;
        let code_form = r#"<form method=post action=/verify><input name=otp></form>"#;
        let post = |path: &str, body: &str| {
            format!("POST {path} HTTP/1.1\nHost: app.test\nContent-Type: application/x-www-form-urlencoded\n\n{body}")
        };
        let found = "HTTP/1.1 302 Found\nLocation: /home\nContent-Length: 0\n\n";
        let recs = vec![
            rec(1, "GET /login HTTP/1.1\nHost: app.test\n\n", &html(form, "")),
            rec(2, &post("/login", "user=al&password=pw-1"), found),
            rec(3, "GET /verify HTTP/1.1\nHost: app.test\n\n", &html(code_form, "")),
            rec(4, &post("/verify", "otp=111111"), &html(code_form, "")),
            rec(5, &post("/verify", "otp=654321"), found),
            rec(6, "GET /home HTTP/1.1\nHost: app.test\nCookie: sid=live\n\n", &html("<p>Hi al</p>", "")),
            // Later, another form that posts a number in a field named like a code.
            rec(7, &post("/devices/pair", "pairing_code=424242"), found),
        ];
        let p = analyze(&recs, "mfa", Some("https://app.test/"));
        assert_eq!((p.mode, p.code.clone()), (Mode::Session, Some(("654321".to_string(), 5))), "{p:?}");
        let p = analyze_with(&recs, "mfa", Some("https://app.test/"), &Options { totp: true, ..Default::default() });
        let [step] = p.profile.login_steps.as_slice() else { panic!("{p:?}") };
        assert_eq!(step.url, "https://app.test/verify");
    }

    #[test]
    fn a_login_requests_cant_repeat_replays_the_recorded_steps() {
        use crate::browser_login::Step;
        let page =
            r#"<form id=f><input name=user><input type="password" name="pass"><button id=go>Sign in</button></form>"#;
        let recs = vec![
            rec(1, "GET /login HTTP/1.1\nHost: app.test\n\n", &html(page, "")),
            // The page hashed the password: no request holds it.
            rec(2, "POST /api/login HTTP/1.1\nHost: app.test\nContent-Type: application/json\n\n{\"user\":\"al\",\"proof\":\"9f86d081884c7d65\"}", "HTTP/1.1 200 OK\nContent-Type: application/json\n\n{\"ok\":true}"),
            rec(3, "GET /home HTTP/1.1\nHost: app.test\nCookie: sid=live\n\n", &html("<p id=who></p>", "")),
            rec(4, "GET /api/me HTTP/1.1\nHost: app.test\nAuthorization: Bearer abc.def.ghi-123456\nCookie: sid=live\n\n", "HTTP/1.1 200 OK\nContent-Type: application/json\n\n{\"user\":\"alice\"}"),
        ];
        let step = |action, css: &str, value: &str| Step {
            action,
            css: css.into(),
            text: None,
            value: value.into(),
            masked: false,
            page: "https://app.test/login".into(),
        };
        let steps = Derived {
            steps: vec![
                step(Do::Fill, "input[name=\"user\"]", "{{username}}"),
                step(Do::Fill, "input[name=\"pass\"]", "{{password}}"),
                step(Do::Click, "#go", ""),
            ],
            username: Some("alice".into()),
            password: Some("pw-1".into()),
            // The proxy was a row behind when the button was clicked: the page tells.
            last_history: 0,
            last_page: "https://app.test/login".into(),
            ..Default::default()
        };
        // Without the steps: the session, as before.
        assert_eq!(analyze(&recs, "js", Some("https://app.test/login")).mode, Mode::Session);
        let opts = Options { steps: Some(&steps), ..Default::default() };
        let p = analyze_with(&recs, "js", Some("https://app.test/login"), &opts);
        assert_eq!(p.mode, Mode::Browser, "{p:?}");
        let pr = &p.profile;
        let login = pr.browser.as_ref().unwrap();
        assert_eq!((login.start_url.as_str(), login.steps.len()), ("https://app.test/login", 3));
        assert_eq!((pr.username.as_deref(), &pr.password), (Some("alice"), &Some(Secret::Literal("pw-1".into()))));
        // The token is read off the page's requests: a header to carry it, no pattern.
        assert_eq!((pr.token_header.as_deref(), &pr.token_regex), (Some("Authorization: Bearer {{token}}"), &None));
        assert_eq!(
            (pr.check_url.as_deref(), pr.logged_in.as_deref()),
            (Some("https://app.test/api/me"), Some("alice"))
        );
        assert!(pr.logged_out.is_some() && pr.login_url.is_none());
        pr.validate().unwrap();
        // Steps that type a code need the secret; with plain requests enough, the steps aren't used unless asked for.
        let mut typed = Derived { steps: steps.steps.clone(), ..Default::default() };
        typed.steps.insert(2, step(Do::Fill, "input[name=\"otp\"]", "{{totp}}"));
        let p = analyze_with(&recs, "js", None, &Options { steps: Some(&typed), ..Default::default() });
        assert_eq!(p.mode, Mode::Session, "{p:?}");
        assert!(p.warnings.iter().any(|w| w.contains("type a one-time code")), "{:?}", p.warnings);
        let p = analyze_with(&recs, "js", None, &Options { steps: Some(&typed), totp: true, ..Default::default() });
        assert_eq!(p.mode, Mode::Browser);
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
