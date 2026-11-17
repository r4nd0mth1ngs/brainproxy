# Active rules

`brainproxy scan active` runs 53 rules ported from OWASP ZAP's `ascanrules`, `ascanrulesBeta` and `ascanrulesAlpha` add-ons (and
helpers from `commonlib`), https://github.com/zaproxy/zap-extensions, Apache License 2.0.
Each rule file names the ZAP class it came from; alert names, descriptions, solutions,
and references are ZAP's.

Every request a rule sends goes through the engagement scope guard (see the README):
rules can only reach targets the engagement allows, including when following redirects.

## brainproxy's own rules

These use IDs from 100000, so they never clash with ZAP's.

- **100002 PHP2Shell (Suspected)** (CVE-2026-109618, CVE-2026-109619), once per site. It
  looks for PHP: an `X-Powered-By` or `Server` header, a `PHPSESSID` cookie, a `.php` page,
  `/index.php` answering 200, or the PHP-FPM error ("File not found.", "No input file
  specified.") for a random `.php` path. When PHP reports a fixed version it stays quiet;
  when the version is affected or hidden it raises a finding (high risk, low confidence).
  It then sends one small multipart form to the page and notes whether multipart requests
  get through or look filtered (the suggested stop-gap). Nothing it sends triggers the bug.
  The passive rule 100001 flags affected versions seen in any traffic. In the app:
  **Scans › New scan › PHP2Shell check**.
- **100003 HQL Injection**, per parameter: input built into a Hibernate HQL or JPQL
  (EclipseLink, OpenJPA) query. It closes the value and compares a random dotted path
  (`apple' and bp9d8e7f.bp1a2b3c=1 and '1'='1`, also double quoted and numeric). Only an
  ORM's query parser answers "could not resolve property: bp9d8e7f of: com.shop.Product"
  or "Could not interpret path expression", so that confirms it (high confidence), and the
  finding names the entity where the message does; a database would name a table or
  column instead. Failing that, it looks for a query parser error (Hibernate 3 to 6,
  EclipseLink, OpenJPA) that quotes and brackets cause and the original page lacks, and that
  the same attack with a random value in place of the original causes too (medium
  confidence). Both need the error to reach the page, also HTML or JSON escaped. Spring
  Boot 2.3 and later leave the message out of error responses by default, so there, and
  wherever errors are hidden, HQL injection is left to 40018's boolean checks, which
  report it as "SQL Injection". Input used as an ORDER BY or entity name isn't covered.
  Requests per parameter: 3 at LOW, 6 at MEDIUM, 9 at HIGH and INSANE. 40018 no longer
  takes Hibernate's "unexpected token:" for Hypersonic SQL's error.
- **100007 JWT Weaknesses**, per page that sends a JSON Web Token (in a header such as
  `Authorization: Bearer`, a cookie, or a query or body parameter). An HMAC token (HS256,
  HS384, HS512) is first cracked offline against a list of common and default secrets plus
  the host's own name, sending nothing (100007-4, high confidence). The rule then checks the
  page depends on the token: the token as recorded is sent again, and the same request with
  the token taken out (an empty value). The real token has to get a success (below 400) and
  a different answer; otherwise the page is left (2 pages per origin and token place are
  tried at LOW, 3 at MEDIUM, 5 at HIGH, 10 at INSANE), so a page that ignores the token
  costs two requests. (A malformed token is no control: a middleware may fail on one in
  front of a page that never reads the token.) On the first page that depends on it, forged
  tokens follow, each counted as accepted when it gets the real token's answer and not the
  answer without a token:
  - a changed signature (100007-1, *Signature Not Verified*; nothing else is sent after it);
  - the signature removed (100007-3), then `alg: none` without a signature (100007-2; at
    MEDIUM and above also `None`, `NONE`, `nOnE`), which is skipped when the first was
    accepted, as it says nothing more;
  - with the secret cracked and an `exp` in the token: the same token, expired a day ago and
    signed again (100007-5, *Expiry Not Enforced*);
  - MEDIUM and above: a `kid` of `../../../../../../../../dev/null` signed with an empty key
    (100007-6, when the token has a `kid`); for an RS or PS token, HS256 signed with the
    origin's RSA public key as the secret (100007-7, *Algorithm Confusion*). Keys are
    looked for, up to four: PEM public keys in responses recorded from the origin (found
    through history's full-text index, no request); then, with at most 8 requests, the
    `.pem` and `.pub` files history requested from the origin or links to (up to 3, such as a
    directory listing's `jwt.pub`), `/.well-known/jwks.json`, `/jwks.json`,
    `/.well-known/openid-configuration` (and its same-origin `jwks_uri`), `/jwt.pub`,
    `/public.pem` and `/publickey.pem`. A JWKS key is tried in four PEM forms, a key file as
    it was found, with and without a final newline; and with `oob start`, a `jku`
    and an `x5u` naming the listener (100007-8 when the server calls it).

  The payload is never changed except `exp` in the expiry test, so a forged token claims
  the same user as the real one. The attacks run once per origin, token place, algorithm
  and `kid`. With `--auth`, the session leaves the token's header, cookie or parameter as
  the rule set it. A request recorded with `--auth` carries an auth placeholder
  (`«auth:NAME:token»`, or a cookie's or header's) instead of the token; the rule reads the
  token behind it from the project's session values, as sending does, and keeps the
  placeholder in every request on record. Such a token's signature stays a secret: the
  changed-signature and `jku`/`x5u` tests use a made-up signature instead of the real one,
  and a weak-secret finding doesn't quote the token. A cookie the server sets to a token in
  answer to a forged one (an accepted token handed back) is kept off the rule's later
  requests, so the session doesn't send it with every forged token after. The passive rule
  100008 reports what traffic shows without sending anything.

## Rules

| ID | Rule | Scope | Max risk | Alert refs |
|---|---|---|---|---|
| 0 | Directory Browsing | page | medium | 0 |
| 6 | Path Traversal | param | high | 6-1, 6-2, 6-3 |
| 7 | Remote File Inclusion | param | high | 7 |
| 10045 | Source Code Disclosure - /WEB-INF Folder | host | high | 10045-1 |
| 10047 | HTTPS Content Available via HTTP | page | low | 10047 |
| 10048 | Remote Code Execution - Shell Shock | param | high | 10048-1, 10048-2 |
| 10058 | GET for POST | page | info | 10058 |
| 10104 | User Agent Fuzzer | page | info | 10104 |
| 10106 | HTTP Only Site | host | medium | 10106 |
| 20015 | Heartbleed OpenSSL Vulnerability | host | high | 20015 |
| 20017 | Source Code Disclosure - CVE-2012-1823 | page | high | 20017 |
| 20018 | Remote Code Execution - CVE-2012-1823 | page | high | 20018 |
| 20019 | External Redirect | param | high | 20019-1, 20019-2, 20019-3, 20019-4 |
| 30001 | Buffer Overflow | param | medium | 30001 |
| 30002 | Format String Error | param | medium | 30002 |
| 40003 | CRLF Injection | param | medium | 40003 |
| 40008 | Parameter Tampering | param | medium | 40008 |
| 40009 | Server Side Include | param | high | 40009 |
| 40012 | Cross Site Scripting (Reflected) | param | high | 40012 |
| 40014 | Cross Site Scripting (Persistent) | param | high | 40014-1, 40014-2, 40014-3 |
| 40015 | LDAP Injection | param | high | 40015-1, 40015-2 |
| 40016 | Cross Site Scripting (Persistent) - Prime | param | (none) | |
| 40017 | Cross Site Scripting (Persistent) - Spider | page | (none) | |
| 40018 | SQL Injection | param | high | 40018 |
| 40019 | SQL Injection - MySQL (Time Based) | param | high | 40019 |
| 40020 | SQL Injection - Hypersonic SQL (Time Based) | param | high | 40020 |
| 40021 | SQL Injection - Oracle (Time Based) | param | high | 40021 |
| 40022 | SQL Injection - PostgreSQL (Time Based) | param | high | 40022 |
| 40027 | SQL Injection - MsSQL (Time Based) | param | high | 40027 |
| 40028 | ELMAH Information Leak | host | medium | 40028-1 |
| 40029 | Trace.axd Information Leak | page | medium | 40029-1 |
| 40032 | .htaccess Information Leak | page | medium | 40032-1 |
| 40033 | NoSQL Injection - MongoDB | param | high | 40033 |
| 40034 | .env Information Leak | page | medium | 40034-1 |
| 40035 | Hidden File Finder | host | medium | 40035 |
| 40040 | CORS Header / CORS Misconfiguration | page | high | 40040-1, 40040-2, 40040-3 |
| 40042 | Spring Actuator Information Leak | host | medium | 40042 |
| 40043 | Log4Shell (needs `oob start`) | param | high | 40043-1, 40043-2 |
| 40044 | Exponential Entity Expansion (Billion Laughs Attack) | page | medium | 40044 |
| 40045 | Spring4Shell | page | high | 40045 |
| 40046 | Server Side Request Forgery (needs `oob start`) | param | high | 40046 |
| 40048 | Remote Code Execution (React2Shell) | host | high | 40048 |
| 90017 | XSLT Injection | param | medium | 90017 |
| 90019 | Server Side Code Injection | param | high | 90019-1, 90019-2 |
| 90020 | Remote OS Command Injection | param | high | 90020 |
| 90021 | XPath Injection | param | high | 90021 |
| 90023 | XML External Entity Attack | page | high | 90023 |
| 90024 | Generic Padding Oracle | param | high | 90024 |
| 90034 | Cloud Metadata Potentially Exposed | host | high | 90034 |
| 90035 | Server Side Template Injection | param | high | 90035 |
| 90036 | Server Side Template Injection (Blind) | param | high | 90036 |
| 90037 | Remote OS Command Injection (Time Based) | param | high | 90037 |
| 90039 | NoSQL Injection - MongoDB (Time Based) | param | high | 90039 |
| 100002 | PHP2Shell PHP Remote Code Execution (Suspected) | host | high | 100002 |
| 100003 | HQL Injection | param | high | 100003 |
| 100006 | Response Differs over HTTP/3 | page | medium | 100006-1, 100006-2 |
| 100007 | JWT Weaknesses | page | high | 100007-1, 100007-2, 100007-3, 100007-4, 100007-5, 100007-6, 100007-7, 100007-8 |

Scopes: `param` runs once per insertion point (query, form, JSON, XML, multipart; cookies,
headers and URL path segments when enabled), `page` once per target request, `host` once per scheme://host:port.

Every rule in ZAP's `ascanrules` add-on is ported (`zap-sync.json` lists the two
`pscanrules` rules that aren't). From `ascanrulesBeta` so far: CORS (40040), Server Side
Request Forgery (40046), and the two MongoDB rules (40033, 90039). From `ascanrulesAlpha`:
LDAP Injection (40015), with its own checks (see below). Each file's header
lists where it differs from ZAP; for example, JSON attacks send a real operator object.
The time based MongoDB rule keeps ZAP's small delay, because `sleep()` runs per document:
the stall stays small, but it only fires on collections of roughly 1,000 documents.

Persistent XSS is three rules, as in ZAP: Prime (40016) stores a unique marker through
every parameter, Spider (40017) re-requests every target and records which pages show
which markers, and 40014 stores XSS payloads through each parameter that has such a sink
page and looks for them there. Rules run in phases (each phase finishes before the next
starts), and selecting 40014 with `--rules` pulls in 40016 and 40017; excluding one of
those skips 40014. Prime and Spider never raise alerts themselves.

## Differences from ZAP

- **Threshold and strength:** each rule's checks follow ZAP's default MEDIUM alert
  threshold; `--strength low|medium|high|insane` maps to ZAP's attack strength and keeps
  ZAP's per-strength request budgets. A scan policy (`scan policy save`, `scan active
  --policy`) gives each rule its own strength, and its own threshold; that threshold is
  applied to the confidence of the findings a rule raises (low: all, medium: medium and high,
  high: high only) rather than changing which checks it runs. See
  [Scan policies](MANUAL.md#scan-policies).
- **No technology filtering:** ZAP can skip checks for technologies a site doesn't use;
  brainproxy runs every check (ZAP's default with all technologies in scope).
- **Out-of-band checks** use brainproxy's own listener (`brainproxy oob start`, see
  [OOB.md](OOB.md)) instead of ZAP's OAST add-on; without a running listener they are
  skipped. Interactions are correlated after the last check (`--oob-wait`) and by
  `oob poll`; the alert has no evidence (repeat callbacks count as hits) and the
  interaction goes to other info. Log4Shell puts the token in the JNDI path instead of
  `abc`, skips the DNS-only patterns in host mode, and has no Java technology filter. XXE's
  check #1 (ZAP's own callback service) is covered by check #2 and not run separately.
- **No third-party hosts in payloads.** The scope guard covers brainproxy's own connections,
  not what a target does with a URL it is sent, so no payload names a host outside the
  engagement for the target to fetch:
  - **Remote File Inclusion (7)** sends the OOB listener's URL instead of ZAP's
    `www.google.com`, and the target fetching it raises the alert; without a listener it
    sends nothing. The listener answers with an empty body, so it shows the URL was fetched,
    not that its content was included, and the same fetch is also SSRF (40046).
  - **External Redirect (20019)** redirects to a random host under `.invalid` (which never
    resolves) instead of ZAP's under `owasp.org`. A browser only has to be sent there, so
    redirects are found as before; an app that checks the host resolves before redirecting
    isn't.
- **Timing rules** port ZAP's TimingUtils regression; the sleep time is fixed at ZAP's
  default of 5 seconds. A passing high/low sequence is run a second time and must pass
  again (all time based rules: SQL 40019-40027, command injection 90037, MongoDB 90039,
  blind SSTI 90036, Shellshock 10048), so jittery latency doesn't line up by chance.
- **SQL Injection (40018)** confirms before it reports, against false positives:
  - a comparison that finds SQL (expression, boolean, ORDER BY) is repeated: the
    original, the value that keeps the original page and the one that changes it are
    sent again, so transient errors, rate limits, clocks and live data that changes
    between requests don't pass (the changed page must not be a 5xx or 429 then);
  - values echoed with the quote escapes frameworks use (`&#39;`, `&#x27;`) or JSON
    escaped are stripped before comparing, as ZAP strips URL and its own HTML encoding;
  - "OR 1=1" findings need "OR 1=2" to keep the original page (free-text searches
    match words of both);
  - the bare LIKE pair (`%` against `XYZABCDEFGHIJ`) isn't sent: a parameterised
    `LIKE` with unescaped wildcards answers it the same way. The quoted LIKE pairs
    (`%'  -- `) still find concatenated LIKE clauses;
  - an SQL error message must come back for the same error characters after a random
    value too, so a search whose results quote an SQL error isn't reported;
  - (HQL Injection 100003 and NoSQL Injection - MongoDB 40033 do the same for their error
    messages;)
  - the HTTP 500 check runs for quotes only, and the 500 must repeat and go away when
    each quote is doubled inside a value (`x''y`, an escaped quote in an SQL string):
    input validation and type errors (`true'` in a JSON boolean) reject both. The
    doubled quotes are never sent alone, because `""` is a valid quoted cookie value
    that a server rejecting `"` in a cookie accepts;
  - a bare 500 is the last resort: a database error message in the 500 page is matched
    first and names the database (Medium confidence), and the bare 500 (Low confidence)
    is reported only when no other check (error message, expression, boolean, UNION,
    ORDER BY) found the parameter.
- **Remote OS Command Injection (90020)** sends a control before it reports: the same
  attack with its command commented out (`;#cat /etc/passwd;`, `&rem type …`,
  `;#get-help`). The output must not come back for it, so a search or help page that
  shows matching text for the command's words isn't reported. PowerShell output is
  recognised by the description `get-help` prints, not by the words "cmdlet",
  "Get-Help" or "Get-Alias" (ZAP), which any PowerShell documentation page has.
- **Format String Error (30002)** runs without ZAP's C technology filter, so a 500 counts
  only when the format conversions cause it: the 500 must repeat, and neither a plain
  value of the same length nor the same length of `%%` (a literal `%` to printf) may give
  one. A `URIError` from decoding `%` twice, a validator that rejects `%`, or a page that
  failed for another reason isn't reported. The `%x` follow-up is compared with a plain
  value of the same length, so a page that echoes or stores the value doesn't pass it.
- **LDAP Injection (40015)** keeps ZAP's id, alert texts and error attack (every filter
  metacharacter), and checks differently:
  - *Error based* (40015-1, high confidence): only messages an LDAP library or server
    writes count (JNDI, Spring LDAP, UnboundID, Apache Directory, libldap as PHP and
    python-ldap show it, ldap3, ldapjs, .NET `System.DirectoryServices`, Active Directory's
    `LdapErr: DSID-`, go-ldap, Ruby net-ldap), not ZAP's list of generic texts such as
    "out of memory". A random value of the same length must not bring the message, and an
    unbalanced filter after a random value (`k3jd8a)(`) must bring one too. At MEDIUM and
    above the original value with a closing parenthesis is tried as well.
  - *Boolean based* (40015-2, medium confidence): ZAP compares `value)(objectClass=*` with
    the original page alone, which any page that ignores the input passes. Here it is paired
    with the same clause made false (`value)(objectClass=` and a random word). Read as plain
    data, both are unknown values and give the same page; read as a filter, the one ANDed or
    ORed with the original condition (`(&(uid=alice)(objectClass=*))`) keeps the original
    page and the other changes it. The pair is also tried from `*`, for a value that found
    nothing at first, and at HIGH and INSANE two and three parentheses deep. See *Boolean
    differential* below.
  - Like ZAP, it skips pages whose original answer is a 4xx or 5xx, and URL path segments.
- **XPath Injection (90021)** also has a boolean check, not in ZAP, for apps that hide
  XPath errors (medium confidence; the error check stays high). It closes the value and
  adds an always-true and an always-false comparison, ANDed and then ORed:
  `2' and '1'='1` / `2' and '1'='2`, then `or`. Single quotes at LOW; double quotes, and
  numbers (`2 and 1=1`) for a numeric value, from MEDIUM; numbers for any value from HIGH.
  SQL reads that pair the same way, so a pair that passes is confirmed with one only XPath
  can evaluate, which must give the same answer: the root element counted,
  `2' and count(/*)=1 and '1'='1` / `2' and count(/*)=0 and '1'='1` (and the same with
  `or`, double quotes or numbers). In SQL `/*` opens a comment, so both are the same syntax
  error and an SQL injection isn't reported as XPath injection. The finding's attack is the
  XPath-only value.
- **Boolean differential** (40015 and 90021): pages are compared by the words they contain,
  with the values sent stripped out, also escaped or entity-encoded (a page that echoes the
  whole query, encoded, echoes the attack too). The original page is requested twice first:
  how much it changes by itself is the noise (when the two differ less with every word that
  has a digit in it counted as one word, as a clock, counter or CSRF token makes them, pages
  are compared that way), a page that changes too much isn't tested,
  "the same page" may differ by little more than the noise and "a different page" must
  differ by more than twice it. One of the pair must keep the original page and the other
  change it; neither may be a 5xx or 429. A pair that passes is sent again with the
  original, and must give the same answer.
- **HTML parsing and response comparison** use ports of ZAP's HtmlContextAnalyser and
  commonlib ComparableResponse on top of brainproxy's own lenient HTML parser (instead of
  Jericho); results can differ slightly on badly broken markup.
- **Path Traversal (6)** doesn't run ZAP's check 5 (alert 6-5), which sends the URL's own
  file name and reports a 200 where a random value got none: the status alone, which any
  parameter that takes a name from a list gives, and a probe that would overwrite the app's
  own script where the path is written to. It found nothing real on the OWASP Benchmark and
  raised 15 false reports. The other checks report file contents only.
- **Path Traversal (6) reads only files nothing can overwrite.** A parameter that names a
  file the app *writes* (an upload saved under the name sent) truncates whatever it is given:
  ZAP's `/etc/passwd` emptied the OWASP Benchmark container's. So the *nix check reads
  `/proc/version` (made up by the kernel on every read; writing it fails, even as root,
  evidence `Linux version …`), and the Windows check `Windows\System32\kernel32.dll` (owned by
  TrustedInstaller and in use by every process, so not even SYSTEM may open it for writing;
  evidence the PE header's `This program cannot be run in DOS mode`). The directory listings
  can't be written to. ZAP's J2EE check (6-4, the app's own `WEB-INF/web.xml`, which a write
  could replace) isn't run. What this gives up: *nix servers without a Linux `/proc` (BSDs,
  macOS) are found only by a directory listing, and `web.xml` read through a parameter that
  can't leave the web app's folder isn't found.
- **Redirects followed:** a rule that follows redirects (as ZAP does) still files its
  finding under the request it attacked, with that request's own response, not under the
  page the redirect led to. When that response doesn't show the evidence itself (a POST
  answered with a redirect to a page that shows what was saved), the finding is low
  confidence and its other info names the page where the evidence was.
- **"Not found" detection** uses 404 plus a soft-404 signature per host instead of ZAP's
  custom page configuration.
- **WEB-INF source disclosure (10045)** detects served class files but does not decompile
  them, so the follow-up "Properties File Disclosure" alert (10045-2) isn't raised.
- **Cloud metadata (90034)** sets the metadata host only in the Host header; the
  connection always goes to the in-scope target.
- **SSTI (90035)** checks reflected output only (ZAP also checks pages found by its
  persistent-XSS spider).
- **Persistent XSS (40014)** follows ZAP's MEDIUM threshold (attacks are looked for anywhere
  on the sink page; PUT requests are skipped) and stops at the first alert per parameter.
  Sinks are the target requests themselves, re-sent, rather than ZAP's temporary history.
- **XSS and the response type.** Reflected XSS (40012) reports an attack only in a response
  a browser renders as markup: an HTML or SVG Content-Type, or none without
  `X-Content-Type-Options: nosniff`. A reflection in JSON, plain text or any other type is
  not reported, whichever attack found it (ZAP checks the type on some paths only). For
  Persistent XSS (40014) the sink page's type picks the alert on every path: 40014-1 (High)
  for HTML, 40014-2 (Low, JSON weakness) for JSON, and 40014-3 (Low risk, High in ZAP) for
  other types, which a browser shows as text.
- **Heartbleed (20015)** opens its raw TCP connection through the guarded client
  (`Cx::connect_raw`), so the engagement scope applies; the heartbeat response is only
  measured (more than 3 bytes back means vulnerable), never stored. Port 80 is tested on
  443 as in ZAP; other ports are tested as given.
- **XSLT Injection (90017)** applies ZAP's per-strength request limit per insertion point
  (ZAP counts it across all parameters of a page).
- **Per-file references** for Hidden Files (40035) are added to the finding's other-info.
- **Low-threshold-only alerts** (e.g. the 401/403 "may be protected" informational
  alerts of the file probes, the JSON XSS weakness alert) are not raised.
- Smaller per-rule differences are documented in comments in each rule file.
