//! OAuth 2.0 token requests for an auth profile: the client credentials, password, refresh
//! token and authorization code (PKCE) grants, and renewing a token before it runs out.
//!
//! A token goes where a login's token goes: session state, and on requests as the vault's
//! placeholder. Token requests carry the client secret and the responses hold tokens, so
//! they are never recorded in history, and they get none of the profile's other credentials.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine;
use ring::rand::SecureRandom;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::auth::{AuthSession, LoginResult, Secret};
use crate::error::{Error, Result};
use crate::http::{parse_response_head, RawRequest, Target};

/// Renew a token this long before it expires.
const EARLY_SECS: u64 = 30;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum Flow {
    ClientCredentials,
    /// The profile's username and password.
    Password,
    /// Only a refresh token obtained elsewhere.
    RefreshToken,
    /// A browser sign-in (`auth oauth authorize`), with PKCE.
    AuthorizationCode,
}

impl Flow {
    pub fn parse(s: &str) -> Result<Flow> {
        Ok(match s.trim().to_ascii_lowercase().replace('-', "_").as_str() {
            "client_credentials" => Flow::ClientCredentials,
            "password" => Flow::Password,
            "refresh_token" => Flow::RefreshToken,
            "authorization_code" => Flow::AuthorizationCode,
            _ => {
                return Err(Error::InvalidInput(format!(
                    "unknown OAuth flow {s:?}; one of client_credentials, password, refresh_token, authorization_code"
                )))
            }
        })
    }
}

/// How the client proves itself at the token endpoint.
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum ClientAuth {
    /// `client_id` and `client_secret` form fields.
    #[default]
    Body,
    /// HTTP Basic.
    Basic,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct OAuth {
    pub flow: Flow,
    pub token_url: String,
    pub client_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_secret: Option<Secret>,
    #[serde(default)]
    pub client_auth: ClientAuth,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub audience: Option<String>,
    /// Extra token request fields.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub params: Vec<(String, String)>,
    /// The refresh token a `refresh_token` flow starts from.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub refresh_token: Option<Secret>,
    /// The sign-in page of the authorization code flow.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authorize_url: Option<String>,
    /// The loopback port the sign-in redirects to; 0 or none picks a free one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub redirect_port: Option<u16>,
}

impl OAuth {
    pub(crate) fn validate(&self, username: Option<&str>, password: Option<&Secret>) -> Result<()> {
        let bad = |e: String| Err(Error::InvalidInput(format!("OAuth: {e}")));
        Target::from_url(&self.token_url).map_err(|e| Error::InvalidInput(format!("OAuth token URL: {e}")))?;
        let u = url::Url::parse(&self.token_url).map_err(|e| Error::InvalidInput(format!("OAuth token URL: {e}")))?;
        if !u.username().is_empty() || u.password().is_some() {
            return bad("the token URL can't hold a username or password".into());
        }
        if self.client_id.trim().is_empty() {
            return bad("needs a client id".into());
        }
        if self.client_auth == ClientAuth::Basic && self.client_secret.is_none() {
            return bad("HTTP Basic client authentication needs a client secret".into());
        }
        for (k, _) in &self.params {
            if matches!(k.as_str(), "grant_type" | "client_id" | "client_secret" | "refresh_token" | "code") {
                return bad(format!("--oauth-param can't set {k}"));
            }
        }
        match self.flow {
            Flow::ClientCredentials if self.client_secret.is_none() => {
                return bad("the client credentials flow needs a client secret".into())
            }
            Flow::Password if username.is_none() || password.is_none() => {
                return bad("the password flow needs --username and a password".into())
            }
            Flow::RefreshToken if self.refresh_token.is_none() => {
                return bad("the refresh token flow needs a refresh token".into())
            }
            Flow::AuthorizationCode => {
                let Some(a) = &self.authorize_url else {
                    return bad("the authorization code flow needs --oauth-authorize-url".into());
                };
                let u = url::Url::parse(a).map_err(|e| Error::InvalidInput(format!("OAuth authorize URL: {e}")))?;
                if !matches!(u.scheme(), "http" | "https") {
                    return bad("the authorize URL must be http or https".into());
                }
            }
            _ => {}
        }
        Ok(())
    }

    pub(crate) fn redacted(&self) -> OAuth {
        let hide = |s: &Option<Secret>| match s {
            Some(Secret::Literal(_)) => Some(Secret::Literal("********".into())),
            other => other.clone(),
        };
        OAuth { client_secret: hide(&self.client_secret), refresh_token: hide(&self.refresh_token), ..self.clone() }
    }

    fn origin(&self) -> String {
        Target::from_url(&self.token_url).map(|t| t.origin()).unwrap_or_default()
    }
}

fn now_secs() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs()
}

fn form(fields: &[(&str, &str)]) -> String {
    let mut f = url::form_urlencoded::Serializer::new(String::new());
    for (k, v) in fields {
        f.append_pair(k, v);
    }
    f.finish()
}

/// What a token endpoint answered.
struct Answer {
    access_token: String,
    refresh_token: Option<String>,
    expires_at: Option<u64>,
}

impl AuthSession {
    fn oauth(&self) -> Result<&OAuth> {
        self.profile.oauth.as_ref().ok_or_else(|| Error::InvalidInput("the profile has no OAuth flow".into()))
    }

    /// Sends one token request, with `grant` and the client's fields. Secrets in it appear
    /// in no message; what the server said comes back only as its `error` code.
    async fn token_request(&self, grant: &[(&str, &str)]) -> Result<Answer> {
        let o = self.oauth()?;
        let secret = o.client_secret.as_ref().map(Secret::resolve).transpose()?;
        let mut fields: Vec<(&str, &str)> = grant.to_vec();
        let mut headers = vec![
            ("Content-Type".to_string(), "application/x-www-form-urlencoded".to_string()),
            ("Accept".to_string(), "application/json".to_string()),
        ];
        match (o.client_auth, &secret) {
            (ClientAuth::Basic, Some(s)) => {
                // RFC 6749 2.3.1: each part form-encoded first.
                let enc = |v: &str| url::form_urlencoded::byte_serialize(v.as_bytes()).collect::<String>();
                let pair = format!("{}:{}", enc(&o.client_id), enc(s));
                headers.push(("Authorization".into(), format!("Basic {}", STANDARD.encode(pair))));
            }
            (_, Some(s)) => {
                fields.push(("client_id", &o.client_id));
                fields.push(("client_secret", s));
            }
            (_, None) => fields.push(("client_id", &o.client_id)),
        }
        if let Some(s) = o.scope.as_deref().filter(|s| !s.is_empty()) {
            fields.push(("scope", s));
        }
        if let Some(a) = o.audience.as_deref().filter(|a| !a.is_empty()) {
            fields.push(("audience", a));
        }
        fields.extend(o.params.iter().map(|(k, v)| (k.as_str(), v.as_str())));
        let (req, target) = RawRequest::build("POST", &o.token_url, &headers, form(&fields).as_bytes())?;
        let ex = self.client.send(&req, &target).await?;
        parse_answer(&ex.response, &o.origin())
    }

    fn keep_answer(&self, a: Answer) {
        let mut st = self.state.lock().unwrap();
        st.token = Some(a.access_token);
        st.token_expires = a.expires_at;
        // A server that doesn't rotate its refresh token sends none: the old one still works.
        if a.refresh_token.is_some() {
            st.refresh_token = a.refresh_token;
        }
    }

    fn finish_login(&self, reason: std::result::Result<&str, String>) -> Result<LoginResult> {
        let (success, reason) = match reason {
            Ok(r) => (true, r.to_string()),
            Err(e) => (false, e),
        };
        {
            let mut st = self.state.lock().unwrap();
            st.logged_in = success;
            st.last_login = Some(crate::auth::now_iso());
            st.last_error = (!success).then(|| reason.clone());
        }
        self.bump_generation();
        let _ = self.save();
        Ok(LoginResult {
            success,
            status: None,
            cookies: vec![],
            token: self.state().token.is_some(),
            reason,
            history_ids: vec![],
        })
    }

    /// Gets a token: with the refresh token when there is one, else by the profile's flow.
    /// A token still in use stays in place until a new one arrives.
    pub(crate) async fn oauth_login(&self) -> Result<LoginResult> {
        let o = self.oauth()?;
        self.mark_login_time();
        let held = self.state().refresh_token;
        let start = match (held, o.flow, &o.refresh_token) {
            (Some(t), ..) => Some(t),
            (None, Flow::RefreshToken, Some(s)) => Some(s.resolve()?),
            _ => None,
        };
        let mut failure = None;
        if let Some(t) = start {
            match self.token_request(&[("grant_type", "refresh_token"), ("refresh_token", &t)]).await {
                Ok(a) => {
                    self.keep_answer(a);
                    return self.finish_login(Ok("token refreshed"));
                }
                Err(e @ Error::OutOfScope(_)) => return Err(e),
                Err(e) => {
                    self.state.lock().unwrap().refresh_token = None;
                    failure = Some(e.to_string());
                }
            }
        }
        let answer = match o.flow {
            Flow::ClientCredentials => self.token_request(&[("grant_type", "client_credentials")]).await,
            Flow::Password => {
                let user = self.profile.username.clone().unwrap_or_default();
                let pass = self.profile.password.as_ref().map(Secret::resolve).transpose()?.unwrap_or_default();
                self.token_request(&[("grant_type", "password"), ("username", &user), ("password", &pass)]).await
            }
            Flow::RefreshToken => {
                return self.finish_login(Err(failure.unwrap_or_else(|| "no refresh token".to_string())))
            }
            Flow::AuthorizationCode => {
                let why = failure.map_or_else(|| "no token yet".to_string(), |f| format!("the refresh failed: {f}"));
                return self.finish_login(Err(format!(
                    "{why}; sign in again with `auth oauth authorize {}`",
                    self.profile.name
                )));
            }
        };
        match answer {
            Ok(a) => {
                self.keep_answer(a);
                self.finish_login(Ok("token obtained"))
            }
            Err(e @ Error::OutOfScope(_)) => Err(e),
            Err(e) => self.finish_login(Err(e.to_string())),
        }
    }

    /// Renews a token about to run out, once however many requests notice at once.
    pub(crate) async fn oauth_renew_if_due(&self) {
        let due = |st: &crate::auth::SessionState| st.token_expires.is_some_and(|at| at <= now_secs() + EARLY_SECS);
        if self.profile.oauth.is_none() || !due(&self.state.lock().unwrap()) {
            return;
        }
        let _guard = self.login_lock.lock().await;
        if due(&self.state.lock().unwrap()) {
            let _ = self.oauth_login().await;
        }
    }

    /// Runs the browser sign-in. `open` gets the URL to show; the call waits for the redirect
    /// on a loopback port, up to `timeout`, then swaps the code for tokens.
    pub async fn oauth_authorize(&self, timeout: Duration, open: impl FnOnce(&str)) -> Result<LoginResult> {
        let o = self.oauth()?;
        let authorize = o
            .authorize_url
            .as_deref()
            .filter(|_| o.flow == Flow::AuthorizationCode)
            .ok_or_else(|| Error::InvalidInput("the profile's OAuth flow isn't authorization_code".into()))?;
        let listener = tokio::net::TcpListener::bind(("127.0.0.1", o.redirect_port.unwrap_or(0))).await?;
        let port = listener.local_addr()?.port();
        let redirect = format!("http://127.0.0.1:{port}/callback");
        let (verifier, state) = (random_token()?, random_token()?);
        let challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()));
        let mut url =
            url::Url::parse(authorize).map_err(|e| Error::InvalidInput(format!("OAuth authorize URL: {e}")))?;
        {
            let mut q = url.query_pairs_mut();
            q.append_pair("response_type", "code")
                .append_pair("client_id", &o.client_id)
                .append_pair("redirect_uri", &redirect)
                .append_pair("state", &state)
                .append_pair("code_challenge", &challenge)
                .append_pair("code_challenge_method", "S256");
            if let Some(s) = o.scope.as_deref().filter(|s| !s.is_empty()) {
                q.append_pair("scope", s);
            }
            if let Some(a) = o.audience.as_deref().filter(|a| !a.is_empty()) {
                q.append_pair("audience", a);
            }
        }
        open(url.as_str());
        let code = tokio::time::timeout(timeout, wait_for_code(&listener, &state))
            .await
            .map_err(|_| Error::InvalidInput("no sign-in came back in time".into()))??;
        let _guard = self.login_lock.lock().await;
        self.mark_login_time();
        let grant = [
            ("grant_type", "authorization_code"),
            ("code", code.as_str()),
            ("redirect_uri", redirect.as_str()),
            ("code_verifier", verifier.as_str()),
        ];
        match self.token_request(&grant).await {
            Ok(a) => {
                self.keep_answer(a);
                self.finish_login(Ok("signed in"))
            }
            Err(e @ Error::OutOfScope(_)) => Err(e),
            Err(e) => self.finish_login(Err(e.to_string())),
        }
    }
}

fn random_token() -> Result<String> {
    let mut b = [0u8; 32];
    ring::rand::SystemRandom::new().fill(&mut b).map_err(|_| Error::InvalidInput("no random bytes".into()))?;
    Ok(URL_SAFE_NO_PAD.encode(b))
}

fn parse_answer(response: &[u8], origin: &str) -> Result<Answer> {
    let head = parse_response_head(response)?;
    let raw = crate::capture::decode_body(&head.headers, crate::http::request::split_head_body(response).1);
    let body: Value = serde_json::from_slice(&raw).unwrap_or(Value::Null);
    let word = |k: &str| {
        body.get(k).and_then(Value::as_str).filter(|v| {
            v.len() <= 64 && v.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.'))
        })
    };
    if !(200..300).contains(&head.status) {
        let said = word("error").map_or(String::new(), |e| format!(": {e}"));
        return Err(Error::InvalidInput(format!("the token endpoint {origin} answered {}{said}", head.status)));
    }
    let Some(access_token) = body.get("access_token").and_then(Value::as_str).filter(|t| !t.is_empty()) else {
        return Err(Error::InvalidInput(format!("the token endpoint {origin} sent no access_token")));
    };
    if access_token.contains(['\r', '\n']) {
        return Err(Error::InvalidInput(format!("the token endpoint {origin} sent a bad access_token")));
    }
    if let Some(ty) = body.get("token_type").and_then(Value::as_str) {
        if !ty.eq_ignore_ascii_case("bearer") {
            return Err(Error::InvalidInput(format!(
                "the token endpoint {origin} sent a token of type {:?}; only bearer tokens are supported",
                word("token_type").unwrap_or("other")
            )));
        }
    }
    // Some servers send it as a string.
    let expires_in = body.get("expires_in").and_then(|v| v.as_u64().or_else(|| v.as_str()?.trim().parse().ok()));
    Ok(Answer {
        access_token: access_token.to_string(),
        refresh_token: body.get("refresh_token").and_then(Value::as_str).filter(|t| !t.is_empty()).map(str::to_string),
        expires_at: expires_in.map(|s| now_secs().saturating_add(s)),
    })
}

/// Waits for the redirect carrying `state`. Anything else gets a 400 and the wait goes on,
/// so a stray connection or a guessed URL can't end the sign-in.
async fn wait_for_code(listener: &tokio::net::TcpListener, state: &str) -> Result<String> {
    loop {
        let (mut socket, _) = listener.accept().await?;
        let mut buf = vec![0u8; 16384];
        let mut len = 0;
        // A client that sends nothing mustn't hold up the real redirect.
        let _ = tokio::time::timeout(Duration::from_secs(5), async {
            while len < buf.len() {
                match socket.read(&mut buf[len..]).await {
                    Ok(0) | Err(_) => break,
                    Ok(n) => {
                        len += n;
                        if buf[..len].windows(4).any(|w| w == b"\r\n\r\n") {
                            break;
                        }
                    }
                }
            }
        })
        .await;
        let text = String::from_utf8_lossy(&buf[..len]);
        let uri = text.lines().next().and_then(|l| l.split(' ').nth(1)).unwrap_or_default();
        let parsed = url::Url::parse(&format!("http://127.0.0.1{uri}")).ok();
        let params: Vec<(String, String)> = parsed
            .as_ref()
            .filter(|u| u.path() == "/callback")
            .map(|u| u.query_pairs().into_owned().collect())
            .unwrap_or_default();
        let get = |k: &str| params.iter().find(|(n, _)| n == k).map(|(_, v)| v.as_str());
        let matches = get("state").is_some_and(|s| ct_eq(s.as_bytes(), state.as_bytes()));
        let (status, page) = if !matches {
            ("400 Bad Request", "This isn't the sign-in brainproxy is waiting for.")
        } else if get("code").is_some() {
            ("200 OK", "Signed in. You can close this window and go back to brainproxy.")
        } else {
            ("200 OK", "The sign-in was refused. You can close this window.")
        };
        let reply = format!(
            "HTTP/1.1 {status}\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{page}",
            page.len()
        );
        let _ = socket.write_all(reply.as_bytes()).await;
        let _ = socket.shutdown().await;
        if !matches {
            continue;
        }
        return match (get("code"), get("error")) {
            (Some(code), _) if !code.is_empty() => Ok(code.to_string()),
            (_, Some(e)) => {
                let word = e.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_') && e.len() <= 64;
                Err(Error::InvalidInput(format!(
                    "the sign-in was refused: {}",
                    if word { e } else { "see the browser" }
                )))
            }
            _ => Err(Error::InvalidInput("the sign-in came back with no code".into())),
        };
    }
}

fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |d, (x, y)| d | (x ^ y)) == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    fn answer(status: &str, body: &str) -> Result<Answer> {
        let raw = format!("HTTP/1.1 {status}\r\nContent-Length: {}\r\n\r\n{body}", body.len());
        parse_answer(raw.as_bytes(), "https://id.test")
    }

    #[test]
    fn a_token_answer_is_read_and_errors_keep_secrets_out() {
        let a = answer("200 OK", r#"{"access_token":"A","token_type":"Bearer","expires_in":"60","refresh_token":"R"}"#);
        let a = a.ok().unwrap();
        assert_eq!((a.access_token.as_str(), a.refresh_token.as_deref()), ("A", Some("R")));
        assert!(a.expires_at.unwrap() >= now_secs() + 59);
        let e = answer("400 Bad", r#"{"error":"invalid_client","error_description":"bad secret HUNTER2"}"#);
        let e = e.err().unwrap().to_string();
        assert!(e.contains("invalid_client") && e.contains("400") && !e.contains("HUNTER2"), "{e}");
        let e = answer("400 Bad", r#"{"error":"echo HUNTER2 back"}"#).err().unwrap().to_string();
        assert!(!e.contains("HUNTER2"), "{e}");
        assert!(answer("200 OK", r#"{"token":"x"}"#).is_err());
        assert!(answer("200 OK", r#"{"access_token":"x","token_type":"mac"}"#).is_err());
        assert!(answer("200 OK", "{\"access_token\":\"x\\r\\nHost: b\"}").is_err());
    }

    #[test]
    fn a_config_needs_what_its_flow_uses() {
        let base = OAuth {
            flow: Flow::ClientCredentials,
            token_url: "https://id.test/token".into(),
            client_id: "c".into(),
            client_secret: Some(Secret::Env("S".into())),
            client_auth: ClientAuth::Body,
            scope: None,
            audience: None,
            params: vec![],
            refresh_token: None,
            authorize_url: None,
            redirect_port: None,
        };
        let check = |o: OAuth| o.validate(None, None).is_ok();
        assert!(check(base.clone()));
        assert!(!check(OAuth { client_secret: None, ..base.clone() }));
        assert!(!check(OAuth { token_url: "https://u:p@id.test/token".into(), ..base.clone() }));
        assert!(!check(OAuth { flow: Flow::Password, ..base.clone() }));
        assert!(!check(OAuth { flow: Flow::RefreshToken, ..base.clone() }));
        assert!(!check(OAuth { flow: Flow::AuthorizationCode, ..base.clone() }));
        assert!(!check(OAuth {
            flow: Flow::AuthorizationCode,
            authorize_url: Some("javascript:alert(1)".into()),
            ..base.clone()
        }));
        assert!(!check(OAuth { params: vec![("grant_type".into(), "x".into())], ..base.clone() }));
        let shown = OAuth { client_secret: Some(Secret::Literal("HUNTER2".into())), ..base }.redacted();
        assert!(!format!("{shown:?}").contains("HUNTER2"));
    }

    #[tokio::test]
    async fn only_the_redirect_with_the_right_state_ends_the_wait() {
        let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let hit = |path: &'static str| async move {
            let mut s = tokio::net::TcpStream::connect(("127.0.0.1", port)).await.unwrap();
            s.write_all(format!("GET {path} HTTP/1.1\r\nHost: x\r\n\r\n").as_bytes()).await.unwrap();
            let mut out = String::new();
            s.read_to_string(&mut out).await.unwrap();
            out
        };
        let waiting = tokio::spawn(async move { wait_for_code(&listener, "GOOD").await });
        assert!(hit("/callback?code=EVIL&state=BAD").await.starts_with("HTTP/1.1 400"));
        assert!(hit("/other?code=EVIL&state=GOOD").await.starts_with("HTTP/1.1 400"));
        assert!(hit("/callback?code=REAL&state=GOOD").await.starts_with("HTTP/1.1 200"));
        assert_eq!(waiting.await.unwrap().unwrap(), "REAL");
    }
}
