# Passive rules

brainproxy's passive scanner runs 52 rules ported from OWASP ZAP's `pscanrules` add-on and
one (10003) from its `retire` add-on (https://github.com/zaproxy/zap-extensions, Apache
License 2.0). Each rule file names the ZAP class it came from, and alert names, descriptions,
solutions, and references are ZAP's.

Rules run automatically on proxy traffic and `send` results (sources are configurable with
`brainproxy scan sources`), and before every `findings` command. `brainproxy scan rules`
lists them; `scan disable ID` / `scan enable ID` switch them.

brainproxy's own rules use IDs from 100000 so they never clash with ZAP's:
**100001 PHP2Shell** (CVE-2026-109618, CVE-2026-109619) flags a PHP version from
`X-Powered-By` or `Server` that has no fix (5.4 to 8.1, and 8.2 to 8.5 before 8.2.35,
8.3.36, 8.4.27, 8.5.12, including their -dev, beta and RC builds). It only reads the reported version: distributions back-port fixes
without changing it, and a server that hides its version isn't flagged.
**100008 JWT Issues** reads JSON Web Tokens in traffic: a token in the query string
(100008-1, low), and for tokens the server hands out (in a response's headers, such as
`Set-Cookie` or `Location`, or its body, unless the body is a script or a source map, whose
tokens are samples in the code) one with `alg: none` (100008-2, high), one with no
`exp` (100008-3, low), and one with a claim named like a secret, such as `password`,
`client_secret`, `ssn` or `card_number` (100008-4, low). Tokens only the client sends are
left to the active rule 100007, so a token isn't reported again on every request.
**100020 Password Hash in Response** reports a hex digest (MD5, SHA-1, SHA-2) in a field
named like a password (`password`, `passwordHash`, `pwd`, `hash`; not a reset token, salt
or policy), once per field name (100020-1, high), and an Argon2 or Django PBKDF2 hash
anywhere (100020-2, high). It reads text responses but not scripts, stylesheets or source
maps, whose values are samples.
**100021 Secrets in Response** reads scripts (also one served as `text/plain` or
`application/octet-stream`, by its `.js` path), JSON, HTML and other text for credentials:
a PEM private key with its body (high), and AWS access key IDs (medium), Stripe live secret
keys, Slack tokens, GitHub tokens (high), Slack webhooks (medium) and Google API keys (low,
as browser keys are often public on purpose) (100021-1, evidence the key, or a private key's
header line). Keys whose random part is a placeholder (`EXAMPLE`, `xxxx`, little variety)
don't count. 100021-2 (medium, low confidence) reports a literal assigned to a name like
`password`, `secret`, `apiKey` or `auth_token` (``testingPassword=`IamUsedForTesting` ``),
once per name; labels, messages, field names, constants, templates and placeholders (values
with spaces, `password`, `changeme`, `currentPassword`, `SECRET_KEY`, `${pw}`) don't count.
Source maps are skipped: their sources hold test fixtures.

## Rules

| ID | Rule | Max risk | Alert refs |
|---|---|---|---|
| 2 | Private IP Disclosure | low | 2 |
| 3 | Session ID in URL Rewrite | medium | 3-1, 3-2, 3-3 |
| 10003 | Vulnerable JS Library (Powered by Retire.js) | medium | 10003 |
| 10009 | In Page Banner Information Leak | low | 10009 |
| 10010 | Cookie No HttpOnly Flag | low | 10010 |
| 10011 | Cookie Without Secure Flag | low | 10011 |
| 10015 | Re-examine Cache-control Directives | info | 10015 |
| 10017 | Cross-Domain JavaScript Source File Inclusion | low | 10017 |
| 10019 | Content-Type Header Missing | info | 10019-1, 10019-2 |
| 10020 | Anti-clickjacking Header | medium | 10020-1, 10020-2, 10020-3, 10020-4 |
| 10021 | X-Content-Type-Options Header Missing | low | 10021 |
| 10023 | Information Disclosure - Debug Error Messages | low | 10023 |
| 10024 | Information Disclosure - Sensitive Information in URL | info | 10024 |
| 10025 | Information Disclosure - Sensitive Information in HTTP Referrer Header | info | 10025 |
| 10027 | Information Disclosure - Suspicious Comments | info | 10027 |
| 10028 | Off-site Redirect | medium | 10028 |
| 10029 | Cookie Poisoning | info | 10029 |
| 10030 | User Controllable Charset | info | 10030 |
| 10031 | User Controllable HTML Element Attribute (Potential XSS) | info | 10031 |
| 10032 | Viewstate | high | 10032-1, 10032-2, 10032-3, 10032-5, 10032-6 |
| 10033 | Directory Browsing | medium | 10033 |
| 10034 | Heartbleed OpenSSL Vulnerability (Indicative) | high | 10034 |
| 10035 | Strict-Transport-Security Header | low | 10035-1, 10035-2, 10035-3, 10035-5, 10035-6, 10035-7, 10035-8 |
| 10036 | HTTP Server Response Header | low | 10036-2 |
| 10037 | Server Leaks Information via "X-Powered-By" HTTP Response Header Field(s) | low | 10037 |
| 10038 | Content Security Policy (CSP) Header Not Set | medium | 10038-1, 10038-2, 10038-3 |
| 10039 | X-Backend-Server Header Information Leak | low | 10039 |
| 10040 | Secure Pages Include Mixed Content | medium | 10040, 10040 |
| 10041 | HTTP to HTTPS Insecure Transition in Form Post | medium | 10041 |
| 10042 | HTTPS to HTTP Insecure Transition in Form Post | medium | 10042 |
| 10043 | User Controllable JavaScript Event (XSS) | info | 10043 |
| 10044 | Big Redirect Detected (Potential Sensitive Information Leak) | low | 10044-1, 10044-2 |
| 10050 | Retrieved from Cache | info | 10050-1, 10050-2 |
| 10052 | X-ChromeLogger-Data (XCOLD) Header Information Leak | medium | 10052 |
| 10054 | Cookie without SameSite Attribute | low | 10054-1, 10054-2, 10054-3 |
| 10055 | CSP | medium | 10055-1, 10055-2, 10055-3, 10055-4, 10055-5, 10055-6, 10055-7, 10055-8, 10055-9, 10055-10, 10055-11, 10055-13 |
| 10056 | X-Debug-Token Information Leak | low | 10056 |
| 10061 | X-AspNet-Version Response Header | low | 10061 |
| 10062 | PII Disclosure | high | 10062 |
| 10096 | Timestamp Disclosure | low | 10096 |
| 10097 | Hash Disclosure | high | 10097-1, 10097-2, 10097-3, 10097-4, 10097-5, 10097-6, 10097-7, 10097-8 |
| 10098 | Cross-Domain Misconfiguration | medium | 10098 |
| 10105 | Weak Authentication Method | medium | 10105-1, 10105-2 |
| 10108 | Reverse Tabnabbing | medium | 10108 |
| 10109 | Modern Web Application | info | 10109 |
| 10115 | Script Served From Malicious Domain (polyfill) | high | 10115-1, 10115-2 |
| 10202 | Absence of Anti-CSRF Tokens | medium | 10202 |
| 90001 | Insecure JSF ViewState | medium | 90001 |
| 90002 | Java Serialization Object | medium | 90002 |
| 90003 | Sub Resource Integrity Attribute Missing | medium | 90003 |
| 90011 | Charset Mismatch | info | 90011-1, 90011-2, 90011-4 |
| 90022 | Application Error Disclosure | medium | 90022 |
| 90033 | Loosely Scoped Cookie | info | 90033 |
| 100001 | PHP2Shell PHP Remote Code Execution (Indicative) | high | 100001 |
| 100005 | HTTP/3 Offered (Alt-Svc) | info | 100005 |
| 100008 | JWT Issues | high | 100008-1, 100008-2, 100008-3, 100008-4 |
| 100020 | Password Hash in Response | high | 100020-1, 100020-2 |
| 100021 | Secrets in Response | high | 100021-1, 100021-2 |

Not ported: ZapVersion (ZAP-specific), UsernameIdor (needs configured usernames).

## Differences from ZAP

Behaviour follows ZAP's default (MEDIUM) alert threshold. The main differences:

- **Thresholds:** alerts ZAP raises only at LOW threshold are not raised (e.g. 10036-1,
  10035-4, 10032-4, 90011-3, the low-confidence SHA/MD5 patterns of 10097). There is no threshold setting yet.
- **ZAP configuration and contexts** (trusted domains, cookie/CSRF ignore lists, scope
  checks, custom error pages, BIN list lookups) are not used; lists are empty and PII
  findings stay at Medium confidence at most.
- **Content Security Policy (10055)** uses brainproxy's own CSP parser and evaluator, not
  the htmlunit-csp library. It reproduces nearly all of ZAP's own CSP unit-test
  expectations; some parser notice texts are brainproxy's wording.
- **HTML parsing** uses a lenient tokenizer instead of Jericho. Attribute names are reported
  lower-case, and element extents are approximated.
- **JavaScript comments (10027)** are found with a hand-written scanner instead of ZAP's
  ANTLR lexer.
- **Defaults from ZAP core** that are not in the add-on source (anti-CSRF token names,
  session-id parameter names, and the CSRF alert texts from `vulnerabilities.xml`) were
  reconstructed and may differ slightly from current ZAP.
- **Crash paths** in the Java (malformed cookie escapes, valueless attributes, missing
  cookie domains) are handled gracefully instead of aborting the scan of that message.
- **Accidental bugs** are not copied: Timestamp Disclosure (10096) uses the intended
  64-bit range check, and the never-matching LanMan hash pattern is omitted.
- **Evidence formatting:** raw header blocks are rebuilt as `Name: value` lines.
- **Charset Mismatch (90011)** doesn't alert on an XML declaration without `encoding` (ZAP
  reports `null`; such documents are UTF-8 by default), and only looks at a leading XML
  declaration instead of Jericho's XML detection.
- **Viewstate (10032)** lists analyzer matches sorted; malformed split viewstates raise
  nothing instead of aborting the scan.
- **Findings are de-duplicated:** the same alert, method, URL (without its query) and
  parameter is one finding with a `hits` count; the first evidence is kept. ZAP lists each
  differing evidence separately (for example two `Server` headers in one response).

### Less noise

Some rules are deliberately stricter or rated lower than ZAP's, where ZAP's output is mostly
noise on modern applications:

- **Cross-Domain Misconfiguration (10098)** rates `Access-Control-Allow-Origin: *` Low (ZAP:
  Medium), since a wildcard can't carry credentials, and skips fonts, images, stylesheets,
  audio and video. It also raises Medium (low confidence) when a response allows the
  request's `Origin` of another site, or `null`, with `Access-Control-Allow-Credentials: true`,
  which ZAP's passive rule doesn't look at; the active CORS rule (40040) confirms it.
- **Strict-Transport-Security Header (10035-1)** isn't raised on a `304 Not Modified`,
  which ZAP counts as a redirect: a revalidation needn't repeat the full response's headers.
- **Sub Resource Integrity Attribute Missing (90003)** reads only HTML pages (ZAP: any
  body, so a tag inside a JS bundle's string counted), and leaves a script from another
  host without `integrity` to Cross-Domain JavaScript Source File Inclusion (10017), which
  reports the same element; 90003 keeps stylesheets, preloads and the scripts 10017
  doesn't count.
- **Obsolete CSP Header (10038-2)** isn't raised: the CSP rule's 10055-1 and 10055-2 report
  `X-Content-Security-Policy` and `X-WebKit-CSP` with their values.
- **Timestamp Disclosure (10096)** raises one finding per header and one for the body, with
  the first timestamp as evidence and the others in the other info (ZAP: one per match, so
  a single response could add hundreds of hits). It skips numbers inside URLs (`?id=…`,
  `/items/…`) and the bodies of scripts and stylesheets, whose numbers are ids and constants.
- **Session ID in URL Rewrite (3-1)** ignores `sid` in an Engine.IO (socket.io) URL, one
  with `EIO` and `transport` parameters: it identifies the transport, not a login.
- **Application Error Disclosure (90022)** and **Debug Error Messages (10023)** skip source
  maps, and in JSON data (a 2xx JSON body: hints, translations) ignore generic phrases such
  as "Internal Server Error", "internal error" or "is not allowed to access"; a driver's
  message or another specific signature still counts there. 90022 raises nothing for a 500
  with an empty body.
- **Off-site Redirect (10028)** is Medium (ZAP: High), since one sighting can't tell a
  parameter that redirects anywhere from an allow-list, and gives the `Location` value as
  evidence (ZAP: none).
- **Anti-clickjacking (10020-1)** and **CSP Header Not Set (10038-1)** skip a text/html body
  without any markup (socket.io answers a POST with `ok`): there is no page to frame or
  script to restrict.
- **PII Disclosure (10062)** is Medium at low confidence (ZAP: High, Medium) for a card
  number with no label such as `card`, `credit`, `cc` or `pan` in the 40 characters before
  it: one number in ten passes the Luhn check, so ids and order numbers did.

### More coverage

Some ported rules also look for what today's stacks produce, which ZAP's lists (from the
PHP, ASP and JDBC era) don't have. The patterns are brainproxy's own, kept out of ZAP's
data files:

- **Application Error Disclosure (90022)** also knows Node.js, Python, Java and .NET stack
  traces, Go panics, PHP fatal errors, SQLite, MySQL (Node driver), Sequelize and MongoDB
  errors, and the ASP.NET, Django debug and Spring Boot (Whitelabel, Low) error pages, and
  reports the first of them as the evidence, at Medium. It reads a 500's body too (ZAP
  stops at the status): a stack trace or a specific message there is the evidence, and
  `HTTP/1.1 500 Internal Server Error` (Low) is left for a 500 with only generic text. A
  stack trace in a 2xx HTML page doesn't count, as it is usually an example in
  documentation; a Node.js trace needs two frames.
- **In Page Banner Information Leak (10009)** also reports an Express version in an error
  page (`Express ^4.22.1`).
- **Directory Browsing (10033)** also knows the listings of Express `serve-index`, Python's
  `http.server`, Tomcat and Go's `http.FileServer`, and names nginx's autoindex (ZAP: Apache,
  and not at all for `/`). A listing's title counts only with the listing's own markup, so
  an article titled "Directory listing for ..." doesn't.
- **Hash Disclosure (10097)** reports BCrypt hashes written `$2b$` and `$2y$` at any cost
  (ZAP: only `$2y$05$`), as Node's and Python's bcrypt and PHP's `password_hash` write them.
