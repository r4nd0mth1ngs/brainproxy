//! Authentication profiles: how to log in, and the live session that other
//! commands use with `--auth NAME`.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use brainproxy_core::auth::{AuthProfile, AuthSession, QueryKey, Secret, SessionState};
use brainproxy_core::auth_record::{Mode, Recorded};
use brainproxy_core::browser_login::record::{ask, Ask, RecordOptions, Recording};
use brainproxy_core::browser_login::Passkey;
use brainproxy_core::http::{Client, RawRequest, SendOptions, Target};
use brainproxy_core::oauth::{Flow, OAuth};
use brainproxy_core::session::{Action, ExtractFrom, Extractor, Macro, MacroStep, SessionRule, Tool, SESSION_RULE_IDS};
use brainproxy_core::sign::{HmacAlg, JwtAlg, KeySource, Place, SignKind, Signer};
use brainproxy_core::store::Store;
use brainproxy_core::totp::Totp;
use brainproxy_core::Error;
use clap::{Args, Subcommand};
use serde_json::json;

use crate::output::Out;

#[derive(Subcommand)]
pub enum AuthCmd {
    /// Add or replace a profile. Use it with `--auth NAME` on send, fuzz, crawl,
    /// scan active, and proxy start. For a session with no login, start with `auth macro add`.
    #[command(after_help = "Form login: --login-url URL --login-body 'user={{username}}&pass={{password}}' \
        --username alice --password-env APP_PW. JSON bodies (starting with '{') are sent as application/json.\n\
        CSRF: --csrf-url PAGE --csrf-regex 'name=\"csrf\" value=\"([^\"]+)\"' fills {{csrf}}.\n\
        Bearer token: --token-regex '\"token\":\"([^\"]+)\"' --token-header 'Authorization: Bearer {{token}}'.\n\
        Static API key only: --header 'X-Api-Key: ...', or --header-env 'X-Api-Key=ENV_VAR' to keep it off the \
        command line (no --login-url). A bearer token is --header-env 'Authorization=ENV_VAR' with the value \
        'Bearer abc' in the variable. In the query string: --query-key 'api_key=ENV_VAR' --key-origin https://api.test; \
        history keeps a placeholder, and the key goes only to the origins given.\n\
        Platform auth (HTTP Basic, Digest, NTLM): --platform ntlm --platform-host '*.corp.test' --username 'CORP\\bob' \
        --password-env BOB_PW. It answers those hosts' 401 challenges on every command, no --auth needed, and is added \
        on the wire only (history keeps the request without it).\n\
        Logout detection: a 401, a redirect to the login path, or --logged-out REGEX triggers an automatic re-login.")]
    Add(Box<AddArgs>),
    /// Log in now and store the session.
    Login {
        name: String,
        #[command(flatten)]
        net: NetArgs,
    },
    /// Stored session state; with a check URL, also fetch it to see if the session is still valid.
    Status {
        name: String,
        /// Don't contact the check URL; only report the stored state.
        #[arg(long)]
        offline: bool,
        #[command(flatten)]
        net: NetArgs,
    },
    /// The Cookie and auth headers the session adds (for external tools such as sqlmap or ffuf).
    Headers {
        name: String,
        /// Print "Name: value" lines with no envelope.
        #[arg(long)]
        raw: bool,
        /// Log in first if there is no session yet.
        #[arg(long)]
        login: bool,
        #[command(flatten)]
        net: NetArgs,
    },
    /// All profiles with their session state.
    List,
    /// One profile (password and header values redacted).
    Show { name: String },
    /// Delete a profile and its session.
    Remove { name: String },
    /// Build a profile by logging in once in a browser: `record start URL`, log in and
    /// open a page only a logged-in user sees, then `record finish NAME --save`.
    #[command(subcommand)]
    Record(RecordCmd),
    /// A profile's macros: requests run in order that extract values (a CSRF token, a
    /// one-time code) for later steps and for session rules.
    #[command(subcommand)]
    Macro(MacroCmd),
    /// A profile's session rules: what to do before requests of some tools to some URLs
    /// go out with `--auth NAME` (check the session, run a macro, update the request, log in).
    #[command(subcommand)]
    Rule(RuleCmd),
    /// A profile's request signers: HMAC and private-key signatures, JWTs and AWS SigV4 computed
    /// as requests go out, for a session rule's `sign:NAME` action. Keys stay in the environment or a file.
    #[command(subcommand)]
    Sign(SignCmd),
    /// OAuth 2.0 sign-ins for a profile added with --oauth-flow.
    #[command(subcommand)]
    Oauth(OauthCmd),
}

#[derive(Subcommand)]
pub enum OauthCmd {
    /// Sign in with a browser (authorization code with PKCE) and store the tokens. Register
    /// http://127.0.0.1:PORT/callback with the provider (see --oauth-redirect-port).
    Authorize {
        name: String,
        /// Only print the sign-in URL; don't open a browser.
        #[arg(long)]
        no_open: bool,
        /// Seconds to wait for the sign-in.
        #[arg(long, default_value_t = 300)]
        wait: u64,
        #[command(flatten)]
        net: NetArgs,
    },
    /// Read an OpenID Connect discovery document (fetched in scope): where tokens and sign-ins go.
    Discover {
        url: String,
        #[command(flatten)]
        net: NetArgs,
    },
}

#[derive(Subcommand)]
pub enum MacroCmd {
    /// Add or replace a macro. A profile that doesn't exist yet is made, with no login.
    #[command(after_help = "Steps run in the order given, with the profile's session; cookies carry \
        through. --step takes a history id, a raw request FILE (sent to its Host over --scheme), or \
        ORIGIN=FILE (e.g. https://app.test:8443=req.txt).\n\
        --extract STEP:VAR=KIND:EXPR takes a value from step STEP's response into VAR. KIND is regex \
        (group 1), json (a path like data.token or items.0.id), header, cookie (a Set-Cookie), or input \
        (an HTML <input name=EXPR>, or <meta name=EXPR content=...>).\n\
        Later steps use a value as {{VAR}} (also {{username}} and {{password}}), and their parameters \
        named VAR get it too. Example:\n  \
        brainproxy auth macro add app csrf --step 12 --extract '1:csrf=input:csrf'")]
    Add {
        profile: String,
        /// Macro name.
        name: String,
        /// A step: history id, FILE, or ORIGIN=FILE. Repeatable, in order. Through MCP only a file in the project's folder.
        #[arg(long = "step", required = true)]
        steps: Vec<String>,
        /// STEP:VAR=KIND:EXPR. Repeatable.
        #[arg(long = "extract")]
        extract: Vec<String>,
        /// Scheme for FILE steps whose request line has no absolute URL.
        #[arg(long, default_value = "https")]
        scheme: String,
        /// A step's Host header deliberately names a host the scope doesn't list, for a
        /// Host-header test. Through MCP such a macro is refused without it.
        #[arg(long)]
        host_header_test: bool,
    },
    /// The profile's macros.
    List { profile: String },
    /// One macro with its requests and extractors.
    Show { profile: String, name: String },
    /// Run a macro now: each step's request, status, history id, and the values it
    /// extracted (masked). The values become the session's latest.
    Run {
        profile: String,
        name: String,
        #[command(flatten)]
        net: NetArgs,
    },
    /// Delete a macro (refused while a session rule runs it).
    Remove { profile: String, name: String },
}

#[derive(Subcommand)]
pub enum RuleCmd {
    /// Add a session rule; its actions run in order before each matching request.
    #[command(after_help = "Actions (--action, repeatable, in order):\n  \
        check[:N]               fetch the profile's check URL (every Nth request); valid skips the rest\n  \
        macro:NAME[:each|:N]    run a macro: once and again when its values go stale (default), on \
        every request, or every Nth\n  \
        update[:P[=VAR],...]    put macro values into the request: each query, form, JSON or multipart \
        parameter, header or cookie P gets VAR (default: the variables of this rule's macros, into \
        parameters of their names)\n  \
        login                   log in again with the profile if the session is not logged in\n  \
        sign:NAME               sign the request as it goes out, with a signer of `auth sign add`\n\
        A response that looks logged out, or matches --invalid, refreshes the rule's macros (and \
        logs in again) and the request is sent once more.\n\
        Fresh CSRF token per request during a scan or fuzz run:\n  \
        brainproxy auth rule add app --tool scan,fuzz --action macro:csrf:each --action update:csrf\n\
        Re-login when a check every 20 requests fails:\n  \
        brainproxy auth rule add app --action check:20 --action login")]
    Add {
        profile: String,
        /// check[:N], macro:NAME[:each|:N], update[:PARAM[=VAR],...], login, or sign:NAME. Repeatable, in order.
        #[arg(long = "action", required = true)]
        actions: Vec<String>,
        /// Only for these tools: proxy, send, fuzz, crawl (also import), scan, checks (default: all).
        #[arg(long = "tool", value_delimiter = ',')]
        tools: Vec<String>,
        /// Only for requests to this host pattern (*.example.com) or URL prefix (https://example.com/api/).
        /// Without it, macro values only go to the origins of the macro that extracted them.
        #[arg(long)]
        url: Option<String>,
        /// Regex marking a response rejected for stale values (e.g. "invalid csrf"): refresh and resend.
        #[arg(long)]
        invalid: Option<String>,
        #[arg(long)]
        description: Option<String>,
    },
    /// The profile's session rules, in the order they run.
    List { profile: String },
    /// Delete a session rule by id.
    Remove { profile: String, id: u32 },
}

#[derive(Subcommand)]
pub enum SignCmd {
    /// Add or replace a signer. A profile that doesn't exist yet is made, with no login.
    /// Add a rule with `--action sign:NAME` to use it.
    #[command(after_help = "Templates (--canonical, --claims, --set-header) can use {{method}}, {{host}}, \
        {{path}}, {{query}}, {{body}}, {{body_sha256}}, {{body_sha256_base64}}, {{timestamp}}, \
        {{timestamp_ms}}, {{nonce}} and {{header:NAME}}. In --canonical, \\n \\r \\t and \\\\ are read \
        as escapes. The value is computed last, over the request as it is sent; history keeps a placeholder.\n\
        An HMAC of the request, with the time it covers in its own header:\n  \
        brainproxy auth sign add api hm --secret-env API_SECRET --origin https://api.test \\\n    \
        --to header:X-Signature --set-header 'X-Timestamp: {{timestamp}}' \\\n    \
        --canonical '{{method}}\\n{{path}}\\n{{query}}\\n{{header:X-Timestamp}}\\n{{body_sha256}}'\n  \
        brainproxy auth rule add api --action sign:hm\n\
        A JWT with chosen claims, good for five minutes:\n  \
        brainproxy auth sign add api tok --jwt HS256 --secret-env JWT_KEY --origin https://api.test \\\n    \
        --to header:Authorization --wrap 'Bearer {{signature}}' --claims '{\"sub\":\"admin\"}' --ttl 300\n\
        A signature with a private key:\n  \
        brainproxy auth sign add api ed --key-alg EdDSA --secret-file ed25519.pem --origin https://api.test \\\n    \
        --to header:X-Signature --output base64 --canonical '{{method}} {{path}}\\n{{body_sha256}}'\n\
        AWS Signature Version 4:\n  \
        brainproxy auth sign add aws v4 --sigv4-region eu-west-1 --sigv4-service execute-api \\\n    \
        --access-key-env AWS_ACCESS_KEY_ID --secret-env AWS_SECRET_ACCESS_KEY \\\n    \
        --session-token-env AWS_SESSION_TOKEN --origin https://abc.execute-api.eu-west-1.amazonaws.com\n\
        A Postman collection's pre-request script (this runs its code, cut off from files and the network):\n  \
        brainproxy auth sign add api postman --script collection.json --environment prod.postman_environment.json \\\n    \
        --origin https://api.test")]
    Add(Box<SignAddArgs>),
    /// The profile's signers (they hold where a key is, not the key).
    List { profile: String },
    /// Delete a signer (refused while a session rule uses it).
    Remove { profile: String, name: String },
}

#[derive(Args)]
pub struct SignAddArgs {
    pub profile: String,
    /// Signer name.
    pub name: String,
    /// Environment variable holding the key (never stored).
    #[arg(long, conflicts_with = "secret_file", required_unless_present_any = ["secret_file", "script"])]
    pub secret_env: Option<String>,
    /// File holding the key (never stored), e.g. a PEM private key for RS256.
    #[arg(long)]
    pub secret_file: Option<PathBuf>,
    /// How the key is written: raw, hex, or base64.
    #[arg(long, default_value = "raw")]
    pub secret_encoding: String,
    /// Origin it may sign for (scheme://host[:port]). Repeatable.
    #[arg(long = "origin", required = true)]
    pub origins: Vec<String>,
    /// Where the value goes: header:NAME or query:NAME. SigV4 always uses Authorization.
    #[arg(long, required_unless_present_any = ["sigv4_region", "script"])]
    pub to: Option<String>,
    /// A header's value around the signature, e.g. 'Bearer {{signature}}'.
    #[arg(long)]
    pub wrap: Option<String>,
    /// 'NAME: TEMPLATE' header set before signing. Repeatable.
    #[arg(long = "set-header")]
    pub set_headers: Vec<String>,
    /// The string to HMAC.
    #[arg(long, conflicts_with = "jwt", required_unless_present_any = ["jwt", "sigv4_region", "script"])]
    pub canonical: Option<String>,
    /// HMAC hash: sha1, sha256, sha384, or sha512.
    #[arg(long, default_value = "sha256", conflicts_with = "jwt")]
    pub hash: String,
    /// HMAC output: hex, base64, or base64url.
    #[arg(long, default_value = "hex", conflicts_with = "jwt")]
    pub output: String,
    /// Sign --canonical with a PEM private key: RS256/384/512, PS256/384/512, ES256/384, or EdDSA.
    /// ES and Ed25519 keys are PKCS#8. --output says how the signature is written.
    #[arg(long, requires = "canonical", conflicts_with = "jwt")]
    pub key_alg: Option<String>,
    /// Make a JWT with this algorithm: HS256/384/512, RS256/384/512, PS256/384/512, ES256/384, or EdDSA.
    #[arg(long)]
    pub jwt: Option<String>,
    /// JWT claims, a JSON object template.
    #[arg(long, requires = "jwt", default_value = "{}")]
    pub claims: String,
    /// Seconds a JWT is valid: sets iat and exp unless the claims do.
    #[arg(long, requires = "jwt")]
    pub ttl: Option<u64>,
    /// JWT kid header.
    #[arg(long, requires = "jwt")]
    pub kid: Option<String>,
    /// Start from the JWT already in the request (its header and claims, --claims on top).
    #[arg(long, requires = "jwt")]
    pub resign: bool,
    /// AWS SigV4 for this region; --secret-env or --secret-file is the secret access key.
    #[arg(long, requires = "sigv4_service", conflicts_with_all = ["jwt", "canonical", "key_alg", "to", "wrap"])]
    pub sigv4_region: Option<String>,
    /// The AWS service to sign for, e.g. execute-api or s3.
    #[arg(long, requires = "sigv4_region")]
    pub sigv4_service: Option<String>,
    /// Environment variable holding the AWS access key id (never stored).
    #[arg(long, conflicts_with = "access_key_file")]
    pub access_key_env: Option<String>,
    /// File holding the AWS access key id (never stored).
    #[arg(long)]
    pub access_key_file: Option<PathBuf>,
    /// Environment variable holding an AWS session token (never stored).
    #[arg(long, conflicts_with = "session_token_file")]
    pub session_token_env: Option<String>,
    /// File holding an AWS session token (never stored).
    #[arg(long)]
    pub session_token_file: Option<PathBuf>,
    /// Run a Postman pre-request script for every request: a collection or a .js file. This runs
    /// code from that file, with no file or network access; read it first (`import api --show-scripts`).
    /// A collection's variables, then --environment, then --script-var are what it sees.
    #[arg(long, value_name = "FILE", conflicts_with_all = ["jwt", "canonical", "key_alg", "sigv4_region", "to", "wrap", "set_headers"])]
    pub script: Option<PathBuf>,
    /// Which script of the collection, by the sha256 the preview lists. Also pins a .js file.
    #[arg(long, value_name = "HEX", requires = "script")]
    pub script_sha256: Option<String>,
    /// A Postman environment file holding what the script reads (never stored).
    #[arg(long, value_name = "FILE", requires = "script", conflicts_with_all = ["secret_env", "secret_file"])]
    pub environment: Option<PathBuf>,
    /// Another variable for the script, NAME=VALUE. Stored, so not for secrets. Repeatable.
    #[arg(long = "script-var", value_name = "NAME=VALUE", requires = "script")]
    pub script_vars: Vec<String>,
    /// Replacing a signer, keep its place in the order instead of running it last.
    #[arg(long)]
    pub keep_place: bool,
}

#[derive(Subcommand)]
pub enum RecordCmd {
    /// Open a fresh browser profile at URL through the running proxy and start recording. In a
    /// Chromium-based browser (on Linux and macOS) what you do in the page is recorded too:
    /// fields filled, buttons clicked, Enter pressed.
    #[command(after_help = "The steps are for a login plain requests can't repeat (single sign-on on another site, \
        a page that builds the login in JavaScript, a passkey): `auth record finish` then makes a profile that \
        replays them in a headless browser. They are recorded in the tab the browser opens with; the browser is \
        held by a brainproxy process until `auth record finish` or until you close it.\n\
        Passkeys: --passkey puts a virtual authenticator in the browser. Log in as usual, register a passkey in \
        the account's security settings (it is made here, and kept with the profile), and finish. To record the \
        passkey sign-in itself, start again with --passkeys-from PROFILE and sign in with the passkey.")]
    Start {
        /// Login page (or the site's start page).
        url: String,
        /// Browser id from `browser list` (default: the first one found).
        #[arg(long)]
        browser: Option<String>,
        /// Only record the traffic, as for Firefox: the browser isn't held, and no steps are kept.
        #[arg(long, conflicts_with_all = ["passkey", "passkeys_from"])]
        no_steps: bool,
        /// Put a virtual authenticator in the browser, so a passkey registered while recording
        /// is kept with the profile. The machine's own authenticators and security keys aren't
        /// offered in this browser.
        #[arg(long)]
        passkey: bool,
        /// Start the virtual authenticator with this profile's passkeys, to record a sign-in
        /// with one (implies --passkey).
        #[arg(long, value_name = "PROFILE")]
        passkeys_from: Option<String>,
        /// Hold the browser and record until asked to stop (what `start` runs in the background).
        #[arg(long, hide = true)]
        hold: bool,
    },
    /// Turn what the proxy recorded since `start` into a profile: the login request with
    /// placeholders, its CSRF token and where it comes from, a bearer token, and logged-in
    /// and logged-out checks. A one-time code is replayed with the TOTP secret; single sign-on
    /// and other logins plain requests can't repeat replay the recorded browser steps; without
    /// either, the profile carries the recorded session.
    Finish {
        /// Profile name.
        name: String,
        /// Save the profile (else only show what was found).
        #[arg(long)]
        save: bool,
        /// Read the password from this environment variable at login instead of storing
        /// the recorded one in the project.
        #[arg(long)]
        password_env: Option<String>,
        /// Analyze history after this id instead of since `record start`.
        #[arg(long)]
        since: Option<i64>,
        #[command(flatten)]
        totp: TotpArgs,
        /// Replay the recorded steps in a headless browser even if plain requests could
        /// repeat the login (for a login the plain replay gets wrong).
        #[arg(long)]
        in_browser: bool,
        /// Keep the recorded steps from this one on (as numbered in the output): for a
        /// recording that did more than log in, such as registering a passkey first.
        #[arg(long, value_name = "N")]
        steps_from: Option<usize>,
    },
}

/// A profile's TOTP secret, for the one-time code a login asks for.
#[derive(clap::Args)]
pub struct TotpArgs {
    /// TOTP secret (base32, or the otpauth:// URI a QR code holds), stored in the project file.
    /// Prefer --totp-secret-env. Also read from BRAINPROXY_SECRET_TOTP, which keeps it off the
    /// command line (the desktop app uses it).
    #[arg(long, conflicts_with = "totp_secret_env", env = "BRAINPROXY_SECRET_TOTP", hide_env_values = true)]
    totp_secret: Option<String>,
    /// Environment variable holding the TOTP secret, read at each login; never stored.
    #[arg(long, value_name = "VAR")]
    totp_secret_env: Option<String>,
    /// TOTP hash: sha1, sha256 or sha512 (default sha1, or what an otpauth:// URI says).
    #[arg(long, value_name = "HASH")]
    totp_algorithm: Option<String>,
    /// Digits of a code (default 6, or what an otpauth:// URI says).
    #[arg(long, value_name = "N")]
    totp_digits: Option<u32>,
    /// Seconds a code is valid (default 30, or what an otpauth:// URI says).
    #[arg(long, value_name = "SECONDS")]
    totp_period: Option<u64>,
}

impl TotpArgs {
    /// The setup the flags give, if they give a secret.
    fn totp(&self) -> Result<Option<Totp>, Error> {
        let algorithm = self.totp_algorithm.as_deref().map(brainproxy_core::totp::Algorithm::parse).transpose()?;
        let (digits, period) = (self.totp_digits, self.totp_period);
        match (&self.totp_secret, &self.totp_secret_env) {
            (Some(secret), _) => Ok(Some(Totp::from_input(secret, algorithm, digits, period)?)),
            (None, Some(var)) => {
                crate::mcp::check_secret_env("--totp-secret-env", var)?;
                Ok(Some(Totp::from_env(var, algorithm, digits, period)?))
            }
            (None, None) if algorithm.is_some() || digits.is_some() || period.is_some() => Err(Error::InvalidInput(
                "--totp-algorithm, --totp-digits and --totp-period go with --totp-secret-env (or --totp-secret)".into(),
            )),
            (None, None) => Ok(None),
        }
    }
}

#[derive(clap::Args)]
pub struct AddArgs {
    /// Profile name.
    name: String,
    /// Login endpoint. Without it the profile only adds --header values.
    #[arg(long)]
    login_url: Option<String>,
    /// Login method.
    #[arg(long, default_value = "POST")]
    login_method: String,
    /// Login body with {{username}}, {{password}}, and {{csrf}} placeholders (encoded for the body type).
    #[arg(long)]
    login_body: Option<String>,
    /// Raw login request file used instead of --login-method/--login-body (placeholders allowed);
    /// sent to the --login-url origin. Through MCP only a file in the project's folder.
    #[arg(long, value_name = "FILE")]
    login_request: Option<String>,
    /// Header for the login request only ("Name: value"). Repeatable.
    #[arg(long)]
    login_header: Vec<String>,
    #[arg(long)]
    username: Option<String>,
    /// Password stored in the project file. Prefer --password-env. Also read from
    /// BRAINPROXY_SECRET_PASSWORD, which keeps it off the command line (the desktop app uses it).
    #[arg(long, conflicts_with = "password_env", env = "BRAINPROXY_SECRET_PASSWORD", hide_env_values = true)]
    password: Option<String>,
    /// Environment variable holding the password, read at each login; never stored.
    #[arg(long)]
    password_env: Option<String>,
    /// Page fetched before login to extract a CSRF token.
    #[arg(long)]
    csrf_url: Option<String>,
    /// Regex extracting the CSRF token from --csrf-url (group 1).
    #[arg(long)]
    csrf_regex: Option<String>,
    /// Regex extracting a token from the login response (group 1).
    #[arg(long)]
    token_regex: Option<String>,
    /// Header carrying the token, e.g. "Authorization: Bearer {{token}}".
    #[arg(long)]
    token_header: Option<String>,
    /// Regex that only matches logged-in pages (verifies the login).
    #[arg(long)]
    logged_in: Option<String>,
    /// Regex that matches a logged-out response (login form, "session expired").
    #[arg(long)]
    logged_out: Option<String>,
    /// URL fetched to verify the session after login and by `auth status`.
    #[arg(long)]
    check_url: Option<String>,
    /// Header added to every request (API key, static bearer token). Repeatable.
    #[arg(short = 'H', long = "header")]
    headers: Vec<String>,
    /// NAME=ENV_VAR: a header like --header, its value read once from the environment
    /// variable and stored in the project. Repeatable.
    #[arg(long = "header-env", value_name = "NAME=ENV_VAR")]
    header_env: Vec<String>,
    /// NAME=ENV_VAR: an API key sent as this query parameter, read once from the environment
    /// variable and stored in the project. Needs --key-origin. Repeatable.
    #[arg(long = "query-key", value_name = "NAME=ENV_VAR", requires = "key_origins")]
    query_keys: Vec<String>,
    /// An origin (scheme://host[:port]) the --query-key values may go to. Repeatable.
    #[arg(long = "key-origin", value_name = "ORIGIN", requires = "query_keys")]
    key_origins: Vec<String>,
    /// When replacing a profile, keep its --query-key values. For an edit that can't see them.
    #[arg(long, conflicts_with = "query_keys")]
    keep_query_keys: bool,
    /// OAuth 2.0 in place of a login: client_credentials, password, refresh_token, or
    /// authorization_code (then sign in with `auth oauth authorize NAME`).
    #[arg(long, value_name = "FLOW", requires_all = ["oauth_token_url", "oauth_client_id"], conflicts_with_all = ["login_url", "token_regex"])]
    oauth_flow: Option<String>,
    /// Where tokens are requested; its host must be in scope.
    #[arg(long, value_name = "URL", requires = "oauth_flow")]
    oauth_token_url: Option<String>,
    #[arg(long, value_name = "ID", requires = "oauth_flow")]
    oauth_client_id: Option<String>,
    /// Environment variable holding the client secret, read at each token request; never stored.
    #[arg(long, value_name = "VAR", requires = "oauth_flow")]
    oauth_client_secret_env: Option<String>,
    /// Environment variable holding the refresh token the refresh_token flow starts from.
    #[arg(long, value_name = "VAR", requires = "oauth_flow")]
    oauth_refresh_token_env: Option<String>,
    /// Read those variables once now and store the values in the project, for background
    /// scans that won't have them. The desktop app uses this.
    #[arg(long, requires = "oauth_flow")]
    oauth_store_secrets: bool,
    /// How the client authenticates: body (form fields) or basic.
    #[arg(long, value_name = "HOW", default_value = "body", requires = "oauth_flow")]
    oauth_client_auth: String,
    #[arg(long, value_name = "SCOPES", requires = "oauth_flow")]
    oauth_scope: Option<String>,
    #[arg(long, value_name = "AUDIENCE", requires = "oauth_flow")]
    oauth_audience: Option<String>,
    /// Extra token request field, NAME=VALUE. Repeatable.
    #[arg(long = "oauth-param", value_name = "NAME=VALUE", requires = "oauth_flow")]
    oauth_params: Vec<String>,
    /// The sign-in page, for authorization_code.
    #[arg(long, value_name = "URL", requires = "oauth_flow")]
    oauth_authorize_url: Option<String>,
    /// Loopback port the sign-in redirects to, when the client registered a fixed one.
    #[arg(long, value_name = "PORT", requires = "oauth_flow")]
    oauth_redirect_port: Option<u16>,
    /// When replacing a profile, keep its OAuth setup. For an edit that can't see it.
    #[arg(long, conflicts_with = "oauth_flow")]
    keep_oauth: bool,
    #[command(flatten)]
    totp: TotpArgs,
    /// When replacing a profile, keep its TOTP secret. For an edit that can't see it.
    #[arg(long, conflicts_with_all = ["totp_secret", "totp_secret_env"])]
    keep_totp: bool,
    /// When replacing a profile `auth record` made, keep what only a recording gives: its
    /// login request (unless --login-request gives one), the requests after it, and its
    /// browser steps. For an edit that can't see them.
    #[arg(long)]
    keep_recorded: bool,
    /// A Host header the profile sets (with --header or in the login request) deliberately
    /// names a host the scope doesn't list, for a Host-header test. Through MCP such a profile
    /// is refused without it.
    #[arg(long)]
    host_header_test: bool,
    /// Minimum seconds between automatic re-logins.
    #[arg(long, default_value_t = 5)]
    relogin_interval: u64,
    /// Maximum automatic re-logins per command run.
    #[arg(long, default_value_t = 20)]
    max_relogins: u32,
    /// Platform authentication with --username and the password: answer this scheme's 401
    /// challenges from --platform-host hosts on every command.
    #[arg(long, value_parser = ["basic", "digest", "ntlm"], requires = "platform_host")]
    platform: Option<String>,
    /// Host pattern platform auth is offered to (host, *.domain, *, optional :port). Repeatable.
    #[arg(long, requires = "platform")]
    platform_host: Vec<String>,
    /// NTLM domain (else taken from a DOMAIN\user username).
    #[arg(long, requires = "platform")]
    domain: Option<String>,
}

/// Network options for commands that log in.
#[derive(clap::Args)]
pub struct NetArgs {
    /// Per-request timeout in seconds.
    #[arg(long, default_value_t = 30.0)]
    timeout: f64,
    #[arg(long)]
    verify_tls: bool,
    /// The profile's login or macro requests deliberately name a host the scope doesn't list in
    /// their Host header, for a Host-header test. Through MCP such a request is refused without it.
    #[arg(long)]
    host_header_test: bool,
}

impl NetArgs {
    fn send_options(&self, project: &Path) -> Result<SendOptions, Error> {
        Ok(SendOptions {
            timeout: Duration::from_secs_f64(self.timeout.max(0.1)),
            verify_tls: self.verify_tls,
            sni: None,
            guard: Some(crate::project_guard(project)?),
            http2: false,
            host: brainproxy_core::http::client::HostPolicy::for_process(self.host_header_test),
            stream: Default::default(),
        })
    }
}

fn runtime() -> Result<tokio::runtime::Runtime, Error> {
    Ok(tokio::runtime::Builder::new_current_thread().enable_all().build()?)
}

/// Loads a profile's session on a guarded client, logging in if it has no
/// session yet. Commands call `save()` on it when they finish.
pub fn load_session(project: &Path, name: &str, send: SendOptions) -> Result<Arc<AuthSession>, Error> {
    let session = AuthSession::load(project, name, Client::new(send))?;
    runtime()?.block_on(session.ensure())?;
    Ok(Arc::new(session))
}

/// `load_session` for an optional `--auth NAME`.
pub fn maybe_session(
    project: &Path,
    name: Option<&str>,
    send: &SendOptions,
) -> Result<Option<Arc<AuthSession>>, Error> {
    name.map(|n| load_session(project, n, send.clone())).transpose()
}

/// `NAME=ENV_VAR` with the variable read. Errors name the variable, never a value.
fn env_pair(flag: &str, spec: &str) -> Result<(String, String), Error> {
    let bad = || Error::InvalidInput(format!("{flag}: expected NAME=ENV_VAR"));
    let (name, var) = spec.split_once('=').ok_or_else(bad)?;
    let (name, var) = (name.trim(), var.trim());
    if name.is_empty() || var.is_empty() {
        return Err(bad());
    }
    crate::mcp::check_secret_env(flag, var)?;
    // Only a name that looks like one is repeated: a key given here by mistake must not be.
    let shown = if var.bytes().all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || b == b'_') {
        var
    } else {
        "the variable after NAME="
    };
    let value = std::env::var(var).map_err(|_| Error::InvalidInput(format!("{flag}: {shown} is not set")))?;
    let value = value.trim();
    if value.is_empty() {
        return Err(Error::InvalidInput(format!("{flag}: {shown} is empty")));
    }
    if value.contains(['\r', '\n', '\0']) {
        return Err(Error::InvalidInput(format!("{flag}: {shown} holds a line break")));
    }
    Ok((name.to_string(), value.to_string()))
}

fn state_json(state: &SessionState) -> serde_json::Value {
    json!({
        "logged_in": state.logged_in,
        "cookies": state.cookies.iter().map(|(k, _)| k).collect::<Vec<_>>(),
        "token": state.token.is_some(),
        "last_login": state.last_login,
        "last_error": state.last_error,
        "refresh_token": state.refresh_token.is_some(),
        "token_expires": state.token_expires,
        "vars": state.vars.iter().map(|v| &v.name).collect::<Vec<_>>(),
    })
}

/// The profile's OAuth setup from `auth add` flags. With --oauth-store-secrets the values
/// are read now and go in the project; else only the variable names do.
fn oauth_from_args(a: &AddArgs) -> Result<Option<OAuth>, Error> {
    let Some(flow) = &a.oauth_flow else { return Ok(None) };
    let secret = |flag: &str, var: &Option<String>| -> Result<Option<Secret>, Error> {
        let Some(var) = var else { return Ok(None) };
        crate::mcp::check_secret_env(flag, var)?;
        if !a.oauth_store_secrets {
            return Ok(Some(Secret::Env(var.clone())));
        }
        let (_, value) = env_pair(flag, &format!("x={var}"))?;
        Ok(Some(Secret::Literal(value)))
    };
    let params = a
        .oauth_params
        .iter()
        .map(|p| {
            let (k, v) = p
                .split_once('=')
                .map(|(k, v)| (k.trim().to_string(), v.to_string()))
                .ok_or_else(|| Error::InvalidInput("--oauth-param: expected NAME=VALUE".into()))?;
            if secret_param(&k) {
                return Err(Error::InvalidInput(format!(
                    "--oauth-param {k} looks like a credential and would be stored as given; use \
                     --oauth-client-secret-env or --oauth-refresh-token-env"
                )));
            }
            Ok((k, v))
        })
        .collect::<Result<_, Error>>()?;
    Ok(Some(OAuth {
        flow: Flow::parse(flow)?,
        token_url: a.oauth_token_url.clone().unwrap_or_default(),
        client_id: a.oauth_client_id.clone().unwrap_or_default(),
        client_secret: secret("--oauth-client-secret-env", &a.oauth_client_secret_env)?,
        client_auth: parse_choice("client authentication", &a.oauth_client_auth, "body, basic")?,
        scope: a.oauth_scope.clone(),
        audience: a.oauth_audience.clone(),
        params,
        refresh_token: secret("--oauth-refresh-token-env", &a.oauth_refresh_token_env)?,
        authorize_url: a.oauth_authorize_url.clone(),
        redirect_port: a.oauth_redirect_port,
        store_secrets: a.oauth_store_secrets,
    }))
}

/// A token request field that holds a credential: refused by --oauth-param, masked by `auth show`.
fn secret_param(name: &str) -> bool {
    let n = name.to_ascii_lowercase();
    brainproxy_core::apiimport::looks_secret(&n) || n.contains("assertion") || n.contains("credential")
}

/// Opens `url` in the system browser, passed as one argument with no shell between.
fn open_browser(url: &str) -> std::io::Result<()> {
    #[cfg(target_os = "macos")]
    let mut c = std::process::Command::new("open");
    #[cfg(target_os = "windows")]
    let mut c = {
        let mut c = std::process::Command::new("rundll32");
        c.arg("url.dll,FileProtocolHandler");
        c
    };
    #[cfg(not(any(target_os = "macos", target_os = "windows")))]
    let mut c = std::process::Command::new("xdg-open");
    c.arg(url)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null());
    c.spawn().map(|_| ())
}

fn oauth_cmd(project: &Path, cmd: OauthCmd, out: &Out) -> Result<(), Error> {
    match cmd {
        OauthCmd::Authorize { name, no_open, wait, net } => {
            let session = AuthSession::load(project, &name, Client::new(net.send_options(project)?))?;
            let result = runtime()?.block_on(session.oauth_authorize(Duration::from_secs(wait), |url| {
                // On stderr: the JSON on stdout comes when the sign-in is done.
                eprintln!("Sign in at: {url}");
                // An agent mustn't open the user's browser at a page it chose.
                if !no_open && !crate::mcp::in_tool_call() && open_browser(url).is_err() {
                    eprintln!("Could not open a browser; open the URL above yourself.");
                }
            }))?;
            if !result.success {
                return Err(Error::InvalidInput(format!("OAuth sign-in failed: {}", result.reason)));
            }
            out.ok(json!({"name": name, "signed_in": true, "session": state_json(&session.state())}), || {
                format!("{name} is signed in")
            });
        }
        OauthCmd::Discover { url, net } => {
            let (req, target) = RawRequest::build("GET", &url, &[("Accept".into(), "application/json".into())], b"")?;
            let opts = net.send_options(project)?;
            // Refused before a row is written: nothing goes out.
            if let Some(guard) = &opts.guard {
                crate::require_in_scope(guard, &target)?;
            }
            let client = Client::new(opts);
            // On record before it goes out, like any request brainproxy sends.
            let mut log = crate::sent::SentLog::open(project, "auth", false)?;
            let id = log.pending(&target, &client.recorded_request(&req, &target)?)?;
            let ex = match runtime()?.block_on(client.send(&req, &target)) {
                Ok(ex) => {
                    log.answered(id, &ex)?;
                    ex
                }
                Err(e) => {
                    log.failed(id, &target, &client.recorded_request(&req, &target)?, &e.to_string())?;
                    return Err(e);
                }
            };
            let head = brainproxy_core::http::parse_response_head(&ex.response)?;
            let body = brainproxy_core::http::request::split_head_body(&ex.response).1;
            let doc: serde_json::Value =
                serde_json::from_slice(&brainproxy_core::capture::decode_body(&head.headers, body))
                    .ok()
                    .filter(|_| (200..300).contains(&head.status))
                    .ok_or_else(|| {
                        Error::InvalidInput(format!("{url} isn't a discovery document ({})", head.status))
                    })?;
            let text = |k: &str| doc.get(k).and_then(serde_json::Value::as_str).map(str::to_string);
            let (token_url, authorize_url) = (text("token_endpoint"), text("authorization_endpoint"));
            out.ok(json!({"token_url": token_url, "authorize_url": authorize_url}), || {
                format!(
                    "token: {}\nsign-in: {}",
                    token_url.as_deref().unwrap_or("-"),
                    authorize_url.as_deref().unwrap_or("-")
                )
            });
        }
    }
    Ok(())
}

pub fn auth(project: &Path, home: &Path, cmd: AuthCmd, out: &Out) -> Result<(), Error> {
    match cmd {
        AuthCmd::Record(cmd) => record(project, home, cmd, out)?,
        AuthCmd::Macro(cmd) => macro_cmd(project, cmd, out)?,
        AuthCmd::Rule(cmd) => rule_cmd(project, cmd, out)?,
        AuthCmd::Sign(cmd) => sign_cmd(project, cmd, out)?,
        AuthCmd::Oauth(cmd) => oauth_cmd(project, cmd, out)?,
        AuthCmd::Add(a) => {
            let parse = |list: &[String]| {
                list.iter().map(|h| crate::request_args::parse_header(h)).collect::<Result<Vec<_>, _>>()
            };
            let login_request = a
                .login_request
                .as_deref()
                .map(|f| {
                    // Sent and stored as it is: through MCP only a file in the project's folder.
                    let path = crate::mcp::local_document(
                        project,
                        "--login-request",
                        f,
                        "describe the login with --login-method, --login-body and --login-header",
                    )?;
                    std::fs::read_to_string(path)
                        .map_err(|e| Error::InvalidInput(format!("cannot read login request {f:?}: {e}")))
                })
                .transpose()?;
            if login_request.is_some() && a.login_url.is_none() {
                return Err(Error::InvalidInput("--login-request needs --login-url (where to send it)".into()));
            }
            if let Some(var) = &a.password_env {
                crate::mcp::check_secret_env("--password-env", var)?;
            }
            let mut headers = parse(&a.headers)?;
            for spec in &a.header_env {
                let (name, value) = env_pair("--header-env", spec)?;
                if name.is_empty() || name.contains([':', ' ', '\r', '\n']) {
                    return Err(Error::InvalidInput(format!("--header-env: bad header name {name:?}")));
                }
                headers.push((name, value));
            }
            let origins =
                a.key_origins.iter().map(|o| Target::from_url(o).map(|t| t.origin())).collect::<Result<Vec<_>, _>>()?;
            let query_keys = a
                .query_keys
                .iter()
                .map(|spec| {
                    let (name, value) = env_pair("--query-key", spec)?;
                    Ok(QueryKey { name, value, origins: origins.clone() })
                })
                .collect::<Result<Vec<_>, Error>>()?;
            let oauth = oauth_from_args(&a)?;
            let mut profile = AuthProfile {
                oauth,
                name: a.name,
                login_url: a.login_url,
                login_method: a.login_method.to_ascii_uppercase(),
                login_body: a.login_body,
                login_request,
                login_headers: parse(&a.login_header)?,
                username: a.username,
                password: a.password.map(Secret::Literal).or(a.password_env.map(Secret::Env)),
                csrf_url: a.csrf_url,
                csrf_regex: a.csrf_regex,
                token_regex: a.token_regex,
                token_header: a
                    .token_header
                    .or_else(|| a.oauth_flow.as_ref().map(|_| "Authorization: Bearer {{token}}".to_string())),
                logged_in: a.logged_in,
                logged_out: a.logged_out,
                check_url: a.check_url,
                headers,
                query_keys,
                relogin_interval_secs: a.relogin_interval,
                max_relogins: a.max_relogins,
                platform: a
                    .platform
                    .as_deref()
                    .map(|scheme| -> Result<_, Error> {
                        Ok(brainproxy_core::connection::PlatformAuth {
                            scheme: brainproxy_core::connection::PlatformScheme::parse(scheme)?,
                            hosts: a.platform_host.clone(),
                            domain: a.domain.clone(),
                        })
                    })
                    .transpose()?,
                totp: a.totp.totp()?,
                login_steps: vec![],
                browser: None,
                passkeys: vec![],
                // Set when it is saved.
                origin: None,
            };
            let store = Store::open(project)?;
            // `auth show` redacts header values; re-saving one unchanged (the GUI's edit form does)
            // keeps the stored value instead of storing the mask.
            // The tokens of an OAuth setup kept as it was: saving the profile clears its session,
            // and a browser sign-in can't be got back without the user.
            let mut kept_tokens = None;
            if let Ok((old, old_state)) = store.auth_profile(&profile.name) {
                for (k, v) in &mut profile.headers {
                    if let Some((_, stored)) =
                        old.headers.iter().find(|(o, _)| v == "********" && o.eq_ignore_ascii_case(k))
                    {
                        *v = stored.clone();
                    }
                }
                if a.keep_query_keys {
                    profile.query_keys = old.query_keys;
                }
                if a.keep_totp {
                    profile.totp = old.totp;
                }
                // No flag gives a passkey: the profile keeps those a recording gave it.
                profile.passkeys = old.passkeys;
                if a.keep_recorded {
                    // The browser steps stand in for a login request: one given now replaces them.
                    if profile.login_url.is_none() && profile.oauth.is_none() {
                        profile.browser = old.browser;
                    }
                    if profile.login_request.is_none()
                        && profile.login_body.is_none()
                        && profile.login_url == old.login_url
                    {
                        profile.login_request = old.login_request;
                        profile.login_steps = old.login_steps;
                    }
                }
                if a.keep_oauth && old.oauth.is_some() {
                    profile.oauth = old.oauth;
                    profile.token_header = old.token_header;
                    let by = store.auth_state_origin(&profile.name)?;
                    kept_tokens = Some((
                        SessionState {
                            token: old_state.token,
                            refresh_token: old_state.refresh_token,
                            token_expires: old_state.token_expires,
                            logged_in: old_state.logged_in,
                            last_login: old_state.last_login,
                            ..Default::default()
                        },
                        by,
                    ));
                }
            }
            // A Host the profile puts on its requests, unless it put the same one there already.
            let guard = store.guard()?;
            let old = store.auth_profile(&profile.name).ok().and_then(|(old, _)| profile_host(&guard, &old));
            let host = profile_host(&guard, &profile).filter(|h| old.as_ref() != Some(h));
            let host_warning = match host {
                Some((place, host)) => {
                    let what = format!("auth profile {}: {place}", profile.name);
                    crate::mcp::check_host_setting(&what, Some(host), a.host_header_test, out)?
                }
                None => None,
            };
            store.auth_save_profile(&profile)?;
            if let Some((state, by)) = kept_tokens {
                store.auth_keep_state(&profile.name, &state, by)?;
            }
            let shown = profile.redacted();
            let mut data = json!({"profile": shown, "next": format!("brainproxy auth login {}", shown.name)});
            if let Some(w) = host_warning {
                data["host_warning"] = json!(w);
            }
            out.ok(data, || format!("profile {:?} saved; run: brainproxy auth login {}", shown.name, shown.name));
        }
        AuthCmd::Login { name, net } => {
            let session = AuthSession::load(project, &name, Client::new(net.send_options(project)?))?;
            let r = runtime()?.block_on(session.login())?;
            let data = json!({"name": name, "login": r, "session": state_json(&session.state())});
            if !r.success {
                // Report the details, then fail with a stable exit code.
                return Err(Error::InvalidInput(format!(
                    "login failed: {} (requests: {:?}; inspect with history show ID)",
                    r.reason, r.history_ids
                )));
            }
            out.ok(data, || format!("logged in as {name}: {} (cookies: {})", r.reason, r.cookies.join(", ")));
        }
        AuthCmd::Status { name, offline, net } => {
            let (profile, state) = Store::open(project)?.auth_profile(&name)?;
            let mut data = json!({"name": name, "has_login": profile.has_login(), "session": state_json(&state)});
            if !offline && profile.check_url.is_some() {
                let session = AuthSession::new(project, profile, state, Client::new(net.send_options(project)?))?;
                let check = runtime()?.block_on(session.check())?;
                session.save()?;
                data["check"] = json!(check);
                data["session"] = state_json(&session.state());
            }
            out.ok(data.clone(), || {
                let live = data["check"]["logged_in"].as_bool();
                let stored = data["session"]["logged_in"].as_bool().unwrap_or(false);
                format!(
                    "{name}: {}{}",
                    if stored { "logged in" } else { "not logged in" },
                    live.map(|l| format!(" (check URL: {})", if l { "valid" } else { "logged out" }))
                        .unwrap_or_default()
                )
            });
        }
        AuthCmd::Headers { name, raw, login, net } => {
            let send = net.send_options(project)?;
            let session = if login {
                load_session(project, &name, send)?
            } else {
                Arc::new(AuthSession::load(project, &name, Client::new(send))?)
            };
            let headers = session.headers();
            if raw {
                let text: String = headers.iter().map(|(k, v)| format!("{k}: {v}\n")).collect();
                out.raw(text.as_bytes());
                return Ok(());
            }
            let data = json!({
                "name": name,
                "logged_in": session.state().logged_in,
                "headers": headers.iter().map(|(k, v)| format!("{k}: {v}")).collect::<Vec<_>>(),
            });
            out.ok(data, || headers.iter().map(|(k, v)| format!("{k}: {v}")).collect::<Vec<_>>().join("\n"));
        }
        AuthCmd::List => {
            let items: Vec<_> = Store::open(project)?
                .auth_list()?
                .into_iter()
                .map(|(p, s)| {
                    json!({
                        "name": p.name,
                        "login_url": p.login_url,
                        "browser_login": p.browser.as_ref().map(|b| &b.start_url),
                        "username": p.username,
                        "session": state_json(&s),
                    })
                })
                .collect();
            out.ok(json!({"profiles": items}), || {
                items
                    .iter()
                    .map(|i| {
                        format!(
                            "{:<20} {:<14} {}",
                            i["name"].as_str().unwrap_or(""),
                            if i["session"]["logged_in"] == true { "logged in" } else { "not logged in" },
                            match (i["login_url"].as_str(), i["browser_login"].as_str()) {
                                (Some(url), _) => url.to_string(),
                                (None, Some(url)) => format!("{url} (in a browser)"),
                                (None, None) => "(headers only)".to_string(),
                            }
                        )
                    })
                    .collect::<Vec<_>>()
                    .join("\n")
            });
        }
        AuthCmd::Show { name } => {
            let store = Store::open(project)?;
            let (profile, state) = store.auth_profile(&name)?;
            let handling = store.auth_handling(&name)?;
            let mut profile = profile.redacted();
            for (k, v) in profile.oauth.iter_mut().flat_map(|o| o.params.iter_mut()) {
                if secret_param(k) {
                    *v = "********".into();
                }
            }
            let (session_origin, session_changed_at) = store.auth_state_origin(&name)?;
            let steps: Vec<String> = profile.browser.iter().flat_map(|b| b.steps.iter().map(|s| s.line())).collect();
            let data = json!({
                // What a browser login does, a step a line; and its passkeys, never their keys.
                "browser_steps": steps,
                "passkeys": profile.passkeys.iter().map(Passkey::summary).collect::<Vec<_>>(),
                "profile": profile,
                "session": state_json(&state),
                "session_origin": session_origin,
                "session_changed_at": session_changed_at,
                "macros": handling.macros.iter().map(macro_summary).collect::<Vec<_>>(),
                "rules": handling.rules,
                "signers": handling.signers,
            });
            out.ok(data.clone(), || serde_json::to_string_pretty(&data).unwrap_or_default());
        }
        AuthCmd::Remove { name } => {
            Store::open(project)?.auth_remove(&name)?;
            out.ok(json!({"name": name, "removed": true}), || format!("profile {name:?} removed"));
        }
    }
    Ok(())
}

const RECORD_KEY: &str = "auth.record";

/// The recording of the login browser's steps, if there is one: its recorder is asked to stop
/// recording (the browser closes) and hands it over. It keeps holding it, for a later `auth
/// record finish --save`. Also whether a recording was lost: its recorder is gone, and what
/// it held with it.
fn take_recording(store: &Store) -> Result<(Option<Recording>, bool), Error> {
    let Some(status) = store.auth_recording_status()? else { return Ok((None, false)) };
    if !matches!(status.state.as_str(), "recording" | "done") {
        return Ok((None, false));
    }
    if !crate::process::alive(status.pid) {
        return Ok((None, true));
    }
    match ask(&status.socket, Ask::Stop) {
        Ok(rec) => Ok((rec, false)),
        Err(Error::NotFound(_)) => Ok((None, true)),
        Err(e) => Err(e),
    }
}

/// Lets go of the recording: its recorder forgets it and exits.
fn drop_recording(store: &Store) -> Result<(), Error> {
    if let Some(status) = store.auth_recording_status()? {
        if crate::process::alive(status.pid) {
            let _ = ask(&status.socket, Ask::Done);
        }
        store.auth_set_recording_status(None)?;
    }
    Ok(())
}

/// What `auth record start --hold` does: opens the login browser with the DevTools protocol
/// attached and records what is done in it, until `auth record finish` asks it to stop or the
/// person closes the browser.
fn hold_recording(
    project: &Path,
    home: &Path,
    url: String,
    browser: Option<String>,
    passkey: bool,
    passkeys_from: Option<String>,
) -> Result<(), Error> {
    let store = Store::open(project)?;
    let state = crate::proxy_cmd::running_here(&store)?.ok_or_else(|| {
        Error::Conflict("the proxy isn't running for this project; start it with `brainproxy proxy start`".into())
    })?;
    let listen = crate::proxy_cmd::connect_addr(&state.listen);
    let proxy = listen
        .parse()
        .map_err(|_| Error::InvalidInput(format!("can't record steps through a proxy listening on {listen}")))?;
    let (ca, _) = crate::proxy_cmd::load_ca(home)?;
    let passkeys = match &passkeys_from {
        Some(name) => store.auth_profile(name)?.0.passkeys,
        None => vec![],
    };
    drop(store);
    let path = crate::browser_cmd::chromium(browser.as_deref())?;
    let opts = RecordOptions {
        passkeys_from,
        browser: &path,
        proxy,
        ca_spki: ca.spki_sha256_base64(),
        url,
        passkey,
        passkeys,
        unattended: std::env::var("BRAINPROXY_RECORD_UNATTENDED").is_ok_and(|v| !v.is_empty() && v != "0"),
    };
    runtime()?.block_on(brainproxy_core::browser_login::record::record(project, opts))
}

/// Seconds since 1970 of a history row's time (`2026-11-09T21:59:03.123Z`).
fn unix_time(iso: &str) -> Option<u64> {
    let num = |r: std::ops::Range<usize>| iso.get(r)?.parse::<i64>().ok();
    let (y, m, d) = (num(0..4)?, num(5..7)?, num(8..10)?);
    let (h, min, s) = (num(11..13)?, num(14..16)?, num(17..19)?);
    // Days from 1970-01-01 (the civil-from-days arithmetic, the other way round).
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y.rem_euclid(400);
    let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + d - 1;
    let days = era * 146_097 + yoe * 365 + yoe / 4 - yoe / 100 + doy - 719_468;
    u64::try_from(days * 86_400 + h * 3600 + min * 60 + s).ok()
}

fn record(project: &Path, home: &Path, cmd: RecordCmd, out: &Out) -> Result<(), Error> {
    let store = Store::open(project)?;
    match cmd {
        RecordCmd::Start { url, browser, no_steps, passkey, passkeys_from, hold } => {
            let guard = crate::project_guard(project)?;
            crate::require_in_scope(&guard, &brainproxy_core::http::Target::from_url(&url)?)?;
            crate::browser_cmd::check_url(&url)?;
            let passkey = passkey || passkeys_from.is_some();
            if hold {
                return hold_recording(project, home, url, browser, passkey, passkeys_from);
            }
            if let Some(name) = &passkeys_from {
                if store.auth_profile(name)?.0.passkeys.is_empty() {
                    return Err(Error::NotFound(format!(
                        "passkeys of profile {name:?}; register one first: auth record start URL --passkey"
                    )));
                }
            }
            let found = crate::browser_cmd::find();
            let steps = !no_steps && crate::browser_cmd::records_steps(&found, browser.as_deref());
            if passkey && !steps {
                return Err(Error::InvalidInput(
                    "--passkey needs a Chromium-based browser on Linux or macOS: the passkey is made by the browser's \
                     virtual authenticator (see `brainproxy browser list`)"
                        .into(),
                ));
            }
            if let Some(id) = browser.as_deref().filter(|id| !crate::browser_cmd::known(&found, id)) {
                return Err(Error::NotFound(format!("browser {id:?}; see `brainproxy browser list`")));
            }
            if crate::proxy_cmd::running_here(&store)?.is_none() {
                return Err(Error::Conflict(
                    "the proxy isn't running for this project; start it with `brainproxy proxy start`".into(),
                ));
            }
            // Only now, with nothing left to refuse this one for: an earlier recording's browser
            // is closed, and what it recorded let go of.
            drop_recording(&store)?;
            let since = store.last_history_id()?;
            let mut data = if steps {
                // Refused here, with the reason, if it isn't one that can be held.
                let path = crate::browser_cmd::chromium(browser.as_deref())?;
                // The browser is held by a process of its own, which outlives this command.
                let project = std::fs::canonicalize(project)?;
                let log = project.with_extension("record.log");
                let log_file = crate::process::private_file(&log, false)?;
                let mut cmd = std::process::Command::new(std::env::current_exe()?);
                cmd.arg("--project").arg(&project).arg("--home").arg(home).args(["--format", "json"]);
                cmd.args(["auth", "record", "start", "--hold"]);
                if let Some(b) = &browser {
                    cmd.arg(format!("--browser={b}"));
                }
                if passkey {
                    cmd.arg("--passkey");
                }
                if let Some(name) = &passkeys_from {
                    cmd.arg(format!("--passkeys-from={name}"));
                }
                cmd.arg("--").arg(&url);
                brainproxy_core::provenance::pass_on(&mut cmd);
                crate::process::detach(&mut cmd);
                cmd.stdin(std::process::Stdio::null())
                    .stdout(std::process::Stdio::null())
                    .stderr(std::process::Stdio::from(log_file));
                let mut child = cmd.spawn()?;
                let deadline = std::time::Instant::now() + Duration::from_secs(45);
                loop {
                    let status = store.auth_recording_status()?.filter(|r| r.pid == child.id());
                    match status.as_ref().map(|r| r.state.as_str()) {
                        Some("recording") => break,
                        Some("failed") => {
                            let why = status.and_then(|r| r.error).unwrap_or_default();
                            store.auth_set_recording_status(None)?;
                            return Err(Error::InvalidInput(format!("the login browser didn't start: {why}")));
                        }
                        _ => {}
                    }
                    if let Some(status) = child.try_wait()? {
                        let msg = std::fs::read_to_string(&log).unwrap_or_default();
                        return Err(crate::jobs_cmd::child_failure("the login browser", status, &msg));
                    }
                    if std::time::Instant::now() >= deadline {
                        let _ = child.kill();
                        return Err(Error::InvalidInput("the login browser didn't open the page in 45s".into()));
                    }
                    std::thread::sleep(Duration::from_millis(100));
                }
                json!({
                    "since": since,
                    "url": url,
                    "browser": {"path": path, "pid": null, "held_by": child.id()},
                    "steps": true,
                    "passkey": passkey,
                })
            } else {
                let (browser, _) =
                    crate::browser_cmd::open(project, home, &found, browser, url.clone(), Some("login"))?;
                json!({"since": since, "url": url, "browser": browser, "steps": false, "passkey": false})
            };
            store.meta_set(RECORD_KEY, Some(&json!({"since": since, "url": url}).to_string()))?;
            data["next"] = json!("brainproxy auth record finish NAME --save");
            out.ok(data, || {
                format!(
                    "Recording from history #{since}{}. Log in in the browser, open a page only a logged-in user sees, then: \
                     brainproxy auth record finish NAME --save",
                    match (steps, passkey) {
                        (true, true) => " (with your steps, and a virtual authenticator for passkeys)",
                        (true, false) => " (with your steps in the page)",
                        _ => "",
                    }
                )
            });
        }
        RecordCmd::Finish { name, save, password_env, since, totp, in_browser, steps_from } => {
            let started: serde_json::Value =
                store.meta_get(RECORD_KEY)?.and_then(|s| serde_json::from_str(&s).ok()).unwrap_or_default();
            let since = since.or_else(|| started["since"].as_i64()).ok_or_else(|| {
                Error::InvalidInput(
                    "no recording started; run `auth record start URL` first (or pass --since ID)".into(),
                )
            })?;
            if let Some(var) = &password_env {
                crate::mcp::check_secret_env("--password-env", var)?;
            }
            // Given now, else the one the profile this replaces has.
            let old = store.auth_profile(&name).ok().map(|(p, _)| p);
            let totp = match totp.totp()? {
                Some(t) => Some(t),
                None => old.as_ref().and_then(|p| p.totp.clone()),
            };
            // The login browser closes here: its steps are complete.
            let (recording, lost) = take_recording(&store)?;
            let recording = recording.filter(|r| !r.events.is_empty() || r.passkey);
            let entries = store.list(&brainproxy_core::store::HistoryFilter {
                after_id: Some(since),
                source: Some("proxy".into()),
                limit: Some(5000),
                ..Default::default()
            })?;
            if entries.is_empty() {
                return Err(Error::NotFound(format!(
                    "no proxied requests after history #{since}; was the browser opened with `auth record start`?"
                )));
            }
            let recorded: Vec<Recorded> = entries
                .iter()
                .filter_map(|e| store.get(e.id).ok())
                .map(|h| Recorded { id: h.entry.id, target: h.target, request: h.request, response: h.response })
                .collect();
            let from = steps_from.unwrap_or(1);
            let derived = recording.as_ref().map(|r| brainproxy_core::browser_login::record::derive(r, from));
            if steps_from.is_some() && derived.as_ref().is_none_or(|d| d.steps.is_empty()) {
                return Err(Error::InvalidInput(format!("--steps-from {from}: the recording has no step {from}")));
            }
            let opts =
                brainproxy_core::auth_record::Options { totp: totp.is_some(), steps: derived.as_ref(), in_browser };
            let mut p = brainproxy_core::auth_record::analyze_with(&recorded, &name, started["url"].as_str(), &opts);
            if let Some(var) = &password_env {
                if p.profile.password.is_some() {
                    p.profile.password = Some(Secret::Env(var.clone()));
                }
            }
            if lost {
                p.warnings.push(
                    "The steps recorded in the browser are gone (the process that held them isn't running any more), \
                     so only the recorded traffic was looked at. Record again to have the steps."
                        .into(),
                );
            }
            // The code typed while recording, and when: the login's, else the one typed in the page.
            let typed_code = match (&p.code, p.mode) {
                (Some((code, id)), Mode::Replay | Mode::Session) => {
                    entries.iter().find(|e| e.id == *id).and_then(|e| unix_time(&e.time)).map(|at| (code.clone(), at))
                }
                _ => derived.as_ref().and_then(|d| d.code.clone()),
            };
            let needs_totp = totp.is_none() && typed_code.is_some();
            // The secret must make the code the person typed, or every login will be refused.
            let mut code_step = None;
            if let (Some(t), Some((code, at))) = (&totp, &typed_code) {
                match t.generator() {
                    // A history row's time is when the proxy wrote it, which can be a while after.
                    Ok(g) => match g.step_of(code, *at, (90 / g.period).max(2)) {
                        Some(step) => {
                            p.found.push("The TOTP secret makes the code that was typed while recording".into());
                            code_step = Some(step);
                        }
                        None => p.warnings.push(
                            "The TOTP secret doesn't make the code that was typed while recording: another account's \
                             secret, or other digits, period or algorithm? The site will refuse the login."
                                .into(),
                        ),
                    },
                    // A variable that isn't set here (the app's, a job's) is read when it logs in.
                    Err(e) => p.warnings.push(format!("The TOTP secret couldn't be read to check it: {e}")),
                }
            }
            // Kept though this login sends no code: a macro or a rule of the profile may.
            p.profile.totp = totp;
            // The passkeys the browser ended with; without an authenticator in it, those the
            // profile this replaces has.
            p.profile.passkeys = match &recording {
                Some(r) if r.passkey => r.passkeys.clone(),
                _ => old.map(|p| p.passkeys).unwrap_or_default(),
            };
            if let Some(r) = recording.as_ref().filter(|r| r.passkey) {
                for k in &r.passkeys {
                    p.found.push(format!(
                        "Passkey for {} (signed {} times), kept with the profile",
                        k.rp_id, k.sign_count
                    ));
                }
                if r.passkeys.is_empty() {
                    p.warnings.push(
                        "No passkey was registered in the browser: add one in the account's security settings while \
                         recording (auth record start URL --passkey)."
                            .into(),
                    );
                } else if p.mode == Mode::Browser && !r.passkey_used {
                    p.warnings.push(
                        "The passkey was registered but didn't sign in during this recording: the steps replay the \
                         login as you did it. To record the passkey sign-in: auth record start URL --passkeys-from \
                         PROFILE, sign in with the passkey, and finish."
                            .into(),
                    );
                } else if p.mode != Mode::Browser {
                    p.warnings.push(
                        "The passkey is kept, but this profile doesn't log in with a browser, so it isn't used: record \
                         the passkey sign-in with auth record start URL --passkeys-from PROFILE."
                            .into(),
                    );
                }
            }
            // Where the steps go must be in the engagement scope, or the replay refuses them.
            let guard = crate::project_guard(project)?;
            let steps: Vec<String> = p.profile.browser.iter().flat_map(|b| b.steps.iter().map(|s| s.line())).collect();
            if let Some(b) = &p.profile.browser {
                let mut refused: Vec<String> = Vec::new();
                for url in
                    b.steps.iter().flat_map(|s| [s.page.as_str(), if s.css.is_empty() { s.value.as_str() } else { "" }])
                {
                    if let Ok(t) = Target::from_url(url) {
                        if !guard.may_allow(&t.host, t.port) && !refused.contains(&t.host) {
                            refused.push(t.host);
                        }
                    }
                }
                if !refused.is_empty() {
                    p.warnings.push(format!(
                        "The login went through {}, outside the engagement scope: the replay refuses steps there. \
                         Add it to the scope if the login needs it.",
                        refused.join(", ")
                    ));
                }
            }
            if save {
                p.profile.validate()?;
                store.auth_save_profile(&p.profile)?;
                // The site may take a code once: the one typed while recording isn't sent again.
                if let Some(step) = code_step {
                    store.auth_note_code_used(&name, step)?;
                }
                store.meta_set(RECORD_KEY, None)?;
                // The recording holds what was typed: let go of once the profile has it.
                drop_recording(&store)?;
            }
            let data = json!({
                "saved": save,
                "recorded": recorded.len(),
                "mode": p.mode,
                "profile": p.profile.redacted(),
                "evidence": p.evidence,
                "found": p.found,
                "warnings": p.warnings,
                "steps": steps,
                "passkeys": p.profile.passkeys.iter().map(Passkey::summary).collect::<Vec<_>>(),
                "needs_totp": needs_totp,
            });
            out.ok(data, || {
                let mut lines = vec![format!(
                    "{} profile {name} from {} recorded requests{}",
                    match p.mode {
                        Mode::Replay => "Login",
                        Mode::Browser => "Browser login",
                        Mode::Session => "Session-only",
                    },
                    recorded.len(),
                    if save { " (saved)" } else { " (not saved; add --save)" }
                )];
                lines.extend(p.found.iter().map(|f| format!("  found: {f}")));
                lines.extend(steps.iter().enumerate().map(|(i, s)| format!("  step {}: {s}", i + from)));
                lines.extend(p.warnings.iter().map(|w| format!("  note:  {w}")));
                lines.join("\n")
            });
        }
    }
    Ok(())
}

fn macro_summary(m: &Macro) -> serde_json::Value {
    json!({
        "name": m.name,
        "steps": m.steps.len(),
        "vars": m.vars(),
        "requests": m.steps.iter().map(step_line).collect::<Vec<_>>(),
        "origin": m.origin,
    })
}

/// "METHOD URL" of a macro step.
fn step_line(s: &MacroStep) -> String {
    let line = s.request.lines().next().unwrap_or("");
    let mut parts = line.split(' ');
    let (method, path) = (parts.next().unwrap_or(""), parts.next().unwrap_or(""));
    if path.starts_with("http://") || path.starts_with("https://") {
        format!("{method} {path}")
    } else {
        format!("{method} {}{path}", s.target.trim_end_matches('/'))
    }
}

/// A macro step from `--step`: a history id, FILE, or ORIGIN=FILE.
/// The values of the Host headers among `headers`.
fn host_values<'a>(headers: impl IntoIterator<Item = (&'a str, &'a str)>) -> impl Iterator<Item = &'a str> {
    headers.into_iter().filter(|(k, _)| k.trim().eq_ignore_ascii_case("host")).map(|(_, v)| v)
}

/// Where a profile puts a Host the scope doesn't list on its requests, and that host: its
/// headers (the token header too) go to every target, so any such host counts; its login
/// request and login headers go to the login URL, whose own host is fine.
fn profile_host(guard: &Arc<brainproxy_core::guard::Guard>, p: &AuthProfile) -> Option<(&'static str, String)> {
    let token = p.token_header.as_deref().and_then(|h| h.split_once(':'));
    let headers = p.headers.iter().map(|(k, v)| (k.as_str(), v.as_str())).chain(token);
    let unlisted = |v: &str| brainproxy_core::http::client::unlisted_host(Some(guard), v);
    if let Some(host) = host_values(headers).find_map(unlisted) {
        return Some(("header", host));
    }
    let login = p.login_url.as_deref().and_then(|u| Target::from_url(u).ok())?;
    let own = |h: &String| h.eq_ignore_ascii_case(&login.host);
    let login_headers = p.login_headers.iter().map(|(k, v)| (k.as_str(), v.as_str()));
    if let Some(host) = host_values(login_headers).filter_map(unlisted).find(|h| !own(h)) {
        return Some(("login header", host));
    }
    let opts = SendOptions { guard: Some(guard.clone()), ..Default::default() };
    let request = p.login_request.as_deref()?;
    opts.foreign_host(request.as_bytes(), &login).map(|host| ("login request", host))
}

/// The first macro step whose request names a Host the scope doesn't list in place of its
/// own target's, and that host.
fn macro_host(guard: &Arc<brainproxy_core::guard::Guard>, m: &Macro) -> Option<(usize, String)> {
    let opts = SendOptions { guard: Some(guard.clone()), ..Default::default() };
    m.steps.iter().enumerate().find_map(|(i, s)| {
        let target = Target::from_url(&s.target).ok()?;
        opts.foreign_host(s.request.as_bytes(), &target).map(|host| (i + 1, host))
    })
}

fn read_step(project: &Path, store: &Store, spec: &str, scheme: &str) -> Result<MacroStep, Error> {
    if let Ok(id) = spec.trim().parse::<i64>() {
        let h = store.get(id)?;
        return Ok(MacroStep {
            target: h.target.origin(),
            request: String::from_utf8_lossy(&h.request).into_owned(),
            history_id: Some(id),
            extract: vec![],
        });
    }
    let (origin, file) = match spec.split_once('=') {
        Some((o, f)) if o.starts_with("http://") || o.starts_with("https://") => (Some(o), f),
        _ => (None, spec),
    };
    // The step is sent as it is, and stored: through MCP only a file in the project's folder.
    let path = crate::mcp::local_document(
        project,
        "--step",
        file,
        "give the step as a history id (send the request first, or find it with `query`)",
    )?;
    let text = std::fs::read_to_string(path)
        .map_err(|e| Error::InvalidInput(format!("cannot read macro step {file:?}: {e}")))?;
    let target = match origin {
        Some(o) => Target::from_url(o)?,
        None => RawRequest::from_bytes(text.clone().into_bytes()).infer_target(scheme)?,
    };
    Ok(MacroStep { target: target.origin(), request: text, history_id: None, extract: vec![] })
}

/// `STEP:VAR=KIND:EXPR`.
fn parse_extract(spec: &str) -> Result<(usize, Extractor), Error> {
    let bad =
        || Error::InvalidInput(format!("--extract {spec:?}: expected STEP:VAR=KIND:EXPR, e.g. 1:csrf=input:csrf"));
    let (step, rest) = spec.split_once(':').ok_or_else(bad)?;
    let (var, rest) = rest.split_once('=').ok_or_else(bad)?;
    let (kind, expr) = rest.split_once(':').ok_or_else(bad)?;
    let step = step.trim().parse::<usize>().map_err(|_| bad())?;
    let x = Extractor { var: var.trim().to_string(), from: ExtractFrom::parse(kind)?, expr: expr.to_string() };
    Ok((step, x))
}

fn macro_cmd(project: &Path, cmd: MacroCmd, out: &Out) -> Result<(), Error> {
    let store = Store::open(project)?;
    match cmd {
        MacroCmd::Add { profile, name, steps, extract, scheme, host_header_test } => {
            let mut h = store.auth_handling(&profile)?;
            let mut m = Macro {
                name: name.clone(),
                steps: steps.iter().map(|s| read_step(project, &store, s, &scheme)).collect::<Result<_, _>>()?,
                origin: Some(brainproxy_core::provenance::origin().to_string()),
            };
            for spec in &extract {
                let (step, x) = parse_extract(spec)?;
                let n = m.steps.len();
                let s = step
                    .checked_sub(1)
                    .and_then(|i| m.steps.get_mut(i))
                    .ok_or_else(|| Error::InvalidInput(format!("--extract {spec:?}: the macro has steps 1 to {n}")))?;
                s.extract.push(x);
            }
            // Its steps go out as a session rule's, so a Host the scope doesn't list is checked as
            // `send` checks one, unless the macro it replaces sent the same one.
            let guard = store.guard()?;
            let old = h.macros.iter().find(|o| o.name == name).and_then(|o| macro_host(&guard, o));
            let host_warning = match macro_host(&guard, &m).filter(|(_, h)| old.as_ref().map(|o| &o.1) != Some(h)) {
                Some((step, host)) => {
                    let what = format!("macro {name} step {step}");
                    crate::mcp::check_host_setting(&what, Some(host), host_header_test, out)?
                }
                None => None,
            };
            let replaced = h.macros.iter().any(|o| o.name == name);
            h.macros.retain(|o| o.name != name);
            h.macros.push(m.clone());
            // A macro can start a profile with no login; `auth add` can set its options after.
            let created = matches!(store.auth_profile(&profile), Err(Error::NotFound(_)));
            if created {
                store.auth_create_for_macros(&profile, &h)?;
            } else {
                store.auth_save_handling(&profile, &h)?;
            }
            let summary = macro_summary(&m);
            let mut data =
                json!({"profile": profile, "profile_created": created, "macro": summary, "replaced": replaced});
            if let Some(w) = host_warning {
                data["host_warning"] = json!(w);
            }
            out.ok(data, || {
                format!(
                    "macro {name:?} {} for {}{profile} ({} steps); try it: brainproxy auth macro run {profile} {name}",
                    if replaced { "replaced" } else { "saved" },
                    if created { "new profile " } else { "" },
                    m.steps.len()
                )
            });
        }
        MacroCmd::List { profile } => {
            store.auth_profile(&profile)?;
            let items: Vec<_> = store.auth_handling(&profile)?.macros.iter().map(macro_summary).collect();
            out.ok(json!({"profile": profile, "macros": items}), || {
                items
                    .iter()
                    .map(|m| {
                        format!("{:<20} {} steps  vars: {}", m["name"].as_str().unwrap_or(""), m["steps"], m["vars"])
                    })
                    .collect::<Vec<_>>()
                    .join("\n")
            });
        }
        MacroCmd::Show { profile, name } => {
            let h = store.auth_handling(&profile)?;
            let m = h
                .macros
                .iter()
                .find(|m| m.name == name)
                .ok_or_else(|| Error::NotFound(format!("macro {name:?} of profile {profile:?}")))?;
            let data = json!({"profile": profile, "macro": m});
            out.ok(data.clone(), || serde_json::to_string_pretty(&data).unwrap_or_default());
        }
        MacroCmd::Run { profile, name, net } => {
            let session = AuthSession::load(project, &profile, Client::new(net.send_options(project)?))?;
            let run = runtime()?.block_on(session.run_macro(&name))?;
            session.save()?;
            let lines: Vec<String> = run
                .steps
                .iter()
                .map(|s| {
                    let mut line = format!(
                        "{}. {} {} -> {}{}",
                        s.step,
                        s.method,
                        s.url,
                        s.status.map_or("no response".to_string(), |c| c.to_string()),
                        s.history_id.map(|id| format!(" (history #{id})")).unwrap_or_default()
                    );
                    if let Some(e) = &s.error {
                        line.push_str(&format!(" error: {e}"));
                    }
                    for x in &s.extracted {
                        line.push_str(&format!("\n     {} = {}", x.var, x.value.as_deref().unwrap_or("(not found)")));
                    }
                    line
                })
                .collect();
            if !run.complete() {
                return Err(Error::InvalidInput(format!(
                    "macro {name:?} did not complete (missing: {}):\n{}",
                    run.missing.join(", "),
                    lines.join("\n")
                )));
            }
            out.ok(json!({"profile": profile, "run": run}), || lines.join("\n"));
        }
        MacroCmd::Remove { profile, name } => {
            let mut h = store.auth_handling(&profile)?;
            if !h.macros.iter().any(|m| m.name == name) {
                return Err(Error::NotFound(format!("macro {name:?} of profile {profile:?}")));
            }
            let users: Vec<u32> = h
                .rules
                .iter()
                .filter(|r| r.actions.iter().any(|a| matches!(a, Action::RunMacro { name: n, .. } if n == &name)))
                .map(|r| r.id)
                .collect();
            if !users.is_empty() {
                return Err(Error::InvalidInput(format!(
                    "session rules {users:?} run macro {name:?}; remove them first (auth rule remove {profile} ID)"
                )));
            }
            h.macros.retain(|m| m.name != name);
            store.auth_save_handling(&profile, &h)?;
            out.ok(json!({"profile": profile, "name": name, "removed": true}), || format!("macro {name:?} removed"));
        }
    }
    Ok(())
}

fn rule_line(r: &SessionRule) -> String {
    let tools = if r.tools.is_empty() {
        "all tools".to_string()
    } else {
        r.tools.iter().map(|t| t.name()).collect::<Vec<_>>().join(",")
    };
    let actions: Vec<String> = r
        .actions
        .iter()
        .map(|a| match a {
            Action::Check { every } if *every > 1 => format!("check every {every}"),
            Action::Check { .. } => "check".into(),
            Action::RunMacro { name, every: 0 } => format!("macro {name}"),
            Action::RunMacro { name, every: 1 } => format!("macro {name} each request"),
            Action::RunMacro { name, every } => format!("macro {name} every {every}"),
            Action::Update { params } if params.is_empty() => "update all".into(),
            Action::Update { params } => format!(
                "update {}",
                params
                    .iter()
                    .map(|(p, v)| if p == v { p.clone() } else { format!("{p}={v}") })
                    .collect::<Vec<_>>()
                    .join(",")
            ),
            Action::Login => "login".into(),
            Action::Sign { signer } => format!("sign {signer}"),
        })
        .collect();
    format!("#{:<3} {:<28} {:<24} {}", r.id, tools, r.url.as_deref().unwrap_or("any URL"), actions.join(" -> "))
}

fn rule_cmd(project: &Path, cmd: RuleCmd, out: &Out) -> Result<(), Error> {
    let mut store = Store::open(project)?;
    match cmd {
        RuleCmd::Add { profile, actions, tools, url, invalid, description } => {
            let mut h = store.auth_handling(&profile)?;
            let mut tools = tools.iter().map(|t| Tool::parse(t)).collect::<Result<Vec<_>, _>>()?;
            tools.dedup();
            let actions = actions.iter().map(|a| Action::parse(a)).collect::<Result<_, _>>()?;
            // Never one a removed rule had, of this profile or another: an old history row's
            // `edited_by` names it. The profiles share the counter, so the floor is theirs all.
            let floor = store.session_rule_ids_in_use()?;
            let id = store.next_id(SESSION_RULE_IDS, floor)?;
            let rule = SessionRule {
                id,
                description: description.unwrap_or_default(),
                tools,
                url,
                actions,
                invalid,
                origin: Some(brainproxy_core::provenance::origin().to_string()),
            };
            h.rules.push(rule.clone());
            store.auth_save_handling(&profile, &h)?;
            out.ok(json!({"profile": profile, "rule": rule}), || format!("session rule added: {}", rule_line(&rule)));
        }
        RuleCmd::List { profile } => {
            store.auth_profile(&profile)?;
            let rules = store.auth_handling(&profile)?.rules;
            out.ok(json!({"profile": profile, "rules": rules}), || {
                if rules.is_empty() {
                    format!("{profile} has no session rules")
                } else {
                    rules.iter().map(rule_line).collect::<Vec<_>>().join("\n")
                }
            });
        }
        RuleCmd::Remove { profile, id } => {
            let mut h = store.auth_handling(&profile)?;
            let before = h.rules.len();
            h.rules.retain(|r| r.id != id);
            if h.rules.len() == before {
                return Err(Error::NotFound(format!("session rule {id} of profile {profile:?}")));
            }
            store.auth_save_handling(&profile, &h)?;
            out.ok(json!({"profile": profile, "id": id, "removed": true}), || format!("session rule {id} removed"));
        }
    }
    Ok(())
}

fn parse_choice<T: serde::de::DeserializeOwned>(what: &str, s: &str, valid: &str) -> Result<T, Error> {
    serde_json::from_value(json!(s.trim().to_ascii_lowercase()))
        .map_err(|_| Error::InvalidInput(format!("unknown {what} {s:?}; one of {valid}")))
}

fn sign_cmd(project: &Path, cmd: SignCmd, out: &Out) -> Result<(), Error> {
    let store = Store::open(project)?;
    match cmd {
        SignCmd::Add(args) => {
            let SignAddArgs {
                profile,
                name,
                secret_env,
                secret_file,
                secret_encoding,
                origins,
                to,
                wrap,
                set_headers,
                canonical,
                hash,
                output,
                jwt,
                claims,
                ttl,
                kid,
                resign,
                key_alg,
                sigv4_region,
                sigv4_service,
                access_key_env,
                access_key_file,
                session_token_env,
                session_token_file,
                script,
                script_sha256,
                environment,
                script_vars,
                keep_place,
            } = *args;
            if script.is_some() && crate::mcp::in_tool_call() {
                return Err(Error::InvalidInput(
                    "--script runs code from a collection, so it isn't offered through MCP: a person must read the \
                     script (`import api --show-scripts`) and add the signer in the app or a terminal"
                        .into(),
                ));
            }
            // These two go on the wire as they are, so an agent could send any readable file to
            // the target; key files only ever produce a signature.
            if crate::mcp::in_tool_call() && (access_key_file.is_some() || session_token_file.is_some()) {
                return Err(Error::InvalidInput(
                    "--access-key-file and --session-token-file aren't offered through MCP (their contents are sent \
                     as they are): use --access-key-env and --session-token-env with BRAINPROXY_SECRET_* variables, \
                     or add the signer in the app or a terminal"
                        .into(),
                ));
            }
            for (flag, var) in [
                ("--secret-env", &secret_env),
                ("--access-key-env", &access_key_env),
                ("--session-token-env", &session_token_env),
            ] {
                if let Some(var) = var {
                    crate::mcp::check_secret_env(flag, var)?;
                }
            }
            let key = match (secret_env, secret_file.or(environment)) {
                (Some(var), _) => KeySource::Env(var),
                (_, Some(path)) => KeySource::File(path),
                _ if script.is_some() => KeySource::None,
                _ => return Err(Error::InvalidInput("give --secret-env or --secret-file".into())),
            };
            let script_kind = script
                .map(|file| {
                    let file = std::fs::canonicalize(&file).unwrap_or(file);
                    let (text, _) = brainproxy_core::sign::read_script(&file, script_sha256.as_deref())
                        .map_err(Error::InvalidInput)?;
                    brainproxy_core::sign_script::check_syntax(&text).map_err(Error::InvalidInput)?;
                    let vars = crate::import_cmd::parse_vars(&script_vars)?;
                    if let Some((k, _)) = vars.iter().find(|(k, _)| brainproxy_core::apiimport::looks_secret(k)) {
                        return Err(Error::InvalidInput(format!(
                            "--script-var {k} looks like a credential and would be stored; put it in --environment"
                        )));
                    }
                    let sha256 = brainproxy_core::fetch::sha256_hex(text.as_bytes());
                    Ok::<_, Error>(SignKind::Script { file, sha256, vars })
                })
                .transpose()?;
            let is_script = script_kind.is_some();
            let source =
                |env: Option<String>, file: Option<PathBuf>| env.map(KeySource::Env).or(file.map(KeySource::File));
            let kind = match (jwt, key_alg, sigv4_region) {
                _ if script_kind.is_some() => script_kind.unwrap_or_else(|| unreachable!("checked")),
                (Some(alg), ..) => SignKind::Jwt { alg: JwtAlg::parse(&alg)?, claims, ttl, kid, resign },
                (_, Some(alg), _) => SignKind::Key {
                    alg: JwtAlg::parse(&alg)?,
                    canonical: canonical.unwrap_or_default(),
                    output: parse_choice("output", &output, "hex, base64, base64url")?,
                },
                (_, _, Some(region)) => SignKind::Sigv4 {
                    access_key: source(access_key_env, access_key_file).ok_or_else(|| {
                        Error::InvalidInput("--sigv4-region needs --access-key-env or --access-key-file".into())
                    })?,
                    session_token: source(session_token_env, session_token_file),
                    region,
                    service: sigv4_service.unwrap_or_default(),
                },
                _ => SignKind::Hmac {
                    alg: HmacAlg::parse(&hash)?,
                    canonical: canonical.unwrap_or_default(),
                    output: parse_choice("output", &output, "hex, base64, base64url")?,
                },
            };
            let headers = set_headers
                .iter()
                .map(|h| {
                    h.split_once(':')
                        .map(|(k, v)| (k.trim().to_string(), v.trim().to_string()))
                        .ok_or_else(|| Error::InvalidInput(format!("--set-header {h:?}: use 'NAME: TEMPLATE'")))
                })
                .collect::<Result<_, _>>()?;
            let origins =
                origins.iter().map(|o| Target::from_url(o).map(|t| t.origin())).collect::<Result<Vec<_>, _>>()?;
            let signer = Signer {
                name: name.clone(),
                key,
                key_encoding: parse_choice("key encoding", &secret_encoding, "raw, hex, base64")?,
                origins,
                to: match to {
                    Some(to) => Place::parse(&to)?,
                    None if is_script => Place::Header(brainproxy_core::sign::SCRIPT_MARK_HEADER.into()),
                    None => Place::Header("Authorization".into()),
                },
                format: wrap,
                headers,
                kind,
            };
            let mut h = store.auth_handling(&profile)?;
            let place = h.signers.iter().position(|s| s.name == name);
            let replaced = place.is_some();
            h.signers.retain(|s| s.name != name);
            match place.filter(|_| keep_place) {
                Some(i) => h.signers.insert(i, signer.clone()),
                None => h.signers.push(signer.clone()),
            }
            let created = matches!(store.auth_profile(&profile), Err(Error::NotFound(_)));
            if created {
                store.auth_create_for_macros(&profile, &h)?;
            } else {
                store.auth_save_handling(&profile, &h)?;
            }
            out.ok(
                json!({"profile": profile, "profile_created": created, "signer": signer, "replaced": replaced}),
                || {
                    format!(
                        "signer {name:?} {}; use it: brainproxy auth rule add {profile} --action sign:{name}",
                        if replaced { "replaced" } else { "saved" }
                    )
                },
            );
        }
        SignCmd::List { profile } => {
            store.auth_profile(&profile)?;
            let signers = store.auth_handling(&profile)?.signers;
            out.ok(json!({"profile": profile, "signers": signers}), || {
                if signers.is_empty() {
                    format!("{profile} has no signers")
                } else {
                    signers
                        .iter()
                        .map(|s| format!("{} -> {} for {}", s.name, s.to, s.origins.join(", ")))
                        .collect::<Vec<_>>()
                        .join("\n")
                }
            });
        }
        SignCmd::Remove { profile, name } => {
            let mut h = store.auth_handling(&profile)?;
            if h.rules.iter().any(|r| r.actions.iter().any(|a| matches!(a, Action::Sign { signer } if signer == &name)))
            {
                return Err(Error::InvalidInput(format!("a session rule uses signer {name:?}; remove the rule first")));
            }
            let before = h.signers.len();
            h.signers.retain(|s| s.name != name);
            if h.signers.len() == before {
                return Err(Error::NotFound(format!("signer {name:?} of profile {profile:?}")));
            }
            store.auth_save_handling(&profile, &h)?;
            out.ok(json!({"profile": profile, "name": name, "removed": true}), || format!("signer {name:?} removed"));
        }
    }
    Ok(())
}
