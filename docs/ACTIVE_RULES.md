# Active rules

`brainproxy scan active` runs 48 rules ported from OWASP ZAP's `ascanrules` add-on (and
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
  The brainproxy checks feed carries a simpler version of this check
  (`CVE-2026-109619-php2shell-multipart`), which steps aside whenever this rule runs
  ([CHECKS.md](CHECKS.md#feed-checks-and-built-in-rules)).

## Rules

| ID | Rule | Scope | Max risk | Alert refs |
|---|---|---|---|---|
| 0 | Directory Browsing | page | medium | 0 |
| 6 | Path Traversal | param | high | 6-1, 6-2, 6-3, 6-4, 6-5 |
| 7 | Remote File Inclusion | param | high | 7 |
| 10045 | Source Code Disclosure - /WEB-INF Folder | host | high | 10045-1 |
| 10047 | HTTPS Content Available via HTTP | page | low | 10047 |
| 10048 | Remote Code Execution - Shell Shock | param | high | 10048-1, 10048-2 |
| 10058 | GET for POST | page | info | 10058 |
| 10104 | User Agent Fuzzer | page | info | 10104 |
| 10106 | HTTP Only Site | host | medium | 10106 |
| 20015 | Heartbleed OpenSSL Vulnerability | host | high | 20015 |
| 20017 | Source Code Disclosure - CVE-2012-1823 | page | high | 20015 | Heartbleed OpenSSL Vulnerability | host | high | 20015 |
| 20017 |
| 20018 | Remote Code Execution - CVE-2012-1823 | page | high | 20018 |
| 20019 | External Redirect | param | high | 20019-1, 20019-2, 20019-3, 20019-4 |
| 30001 | Buffer Overflow | param | medium | 30001 |
| 30002 | Format String Error | param | medium | 30002 |
| 40003 | CRLF Injection | param | medium | 40003 |
| 40008 | Parameter Tampering | param | medium | 40008 |
| 40009 | Server Side Include | param | high | 40009 |
| 40012 | Cross Site Scripting (Reflected) | param | high | 40012 |
| 40014 | Cross Site Scripting (Persistent) | param | high | 40014-1, 40014-2, 40014-3 |
| 40016 | Cross Site Scripting (Persistent) - Prime | param | (none) | |
| 40017 | Cross Site Scripting (Persistent) - Spider | page | (none) | |
| 40018 | SQL Injection | param | high | 40014 | Cross Site Scripting (Persistent) | param | high | 40014-1, 40014-2, 40014-3 |
| 40016 | Cross Site Scripting (Persistent) - Prime | param | (none) | |
| 40017 | Cross Site Scripting (Persistent) - Spider | page | (none) | |
| 40018 |
| 40019 | SQL Injection - MySQL (Time Based) | param | high | 40019 |
| 40020 | SQL Injection - Hypersonic SQL (Time Based) | param | high | 40020 |
| 40021 | SQL Injection - Oracle (Time Based) | param | high | 40021 |
| 40022 | SQL Injection - PostgreSQL (Time Based) | param | high | 40022 |
| 40027 | SQL Injection - MsSQL (Time Based) | param | high | 40027 |
| 40028 | ELMAH Information Leak | host | medium | 40028-1 |
| 40029 | Trace.axd Information Leak | page | medium | 40029-1 |
| 40032 | .htaccess Information Leak | page | medium | 40032-1 |
| 40034 | .env Information Leak | page | medium | 40034-1 |
| 40035 | Hidden File Finder | host | medium | 40035 |
| 40042 | Spring Actuator Information Leak | host | medium | 40042 |
| 40043 | Log4Shell (needs `oob start`) | param | high | 40043-1, 40043-2 |
| 40044 | Exponential Entity Expansion (Billion Laughs Attack) | page | medium | 40044 |
| 40045 | Spring4Shell | page | high | 40045 |
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
| 100002 | PHP2Shell PHP Remote Code Execution (Suspected) | host | high | 100002 |

Scopes: `param` runs once per insertion point (query, form, JSON; cookies and headers when
enabled), `page` once per target request, `host` once per scheme://host:port.

Every rule in ZAP's `ascanrules` add-on is ported (`zap-sync.json` lists the two
`pscanrules` rules that aren't).

Persistent XSS is three rules, as in ZAP: Prime (40016) stores a unique marker through
every parameter, Spider (40017) re-requests every target and records which pages show
which markers, and 40014 stores XSS payloads through each parameter that has such a sink
page and looks for them there. Rules run in phases (each phase finishes before the next
starts), and selecting 40014 with `--rules` pulls in 40016 and 40017; excluding one of
those skips 40014. Prime and Spider never raise alerts themselves.

## Differences from ZAP

- **Threshold and strength:** behaviour follows ZAP's default MEDIUM alert threshold;
  `--strength low|medium|high|insane` maps to ZAP's attack strength and keeps ZAP's
  per-strength request budgets.
- **No technology filtering:** ZAP can skip checks for technologies a site doesn't use;
  brainproxy runs every check (ZAP's default with all technologies in scope).
- **Out-of-band checks** use brainproxy's own listener (`brainproxy oob start`, see
  [OOB.md](OOB.md)) instead of ZAP's OAST add-on; without a running listener they are
  skipped. Interactions are correlated after the last check (`--oob-wait`) and by
  `oob poll`; the alert has no evidence (repeat callbacks count as hits) and the
  interaction goes to other info. Log4Shell puts the token in the JNDI path instead of
  `abc`, skips the DNS-only patterns in host mode, and has no Java technology filter. XXE's
  check #1 (ZAP's own callback service) is covered by check #2 and not run separately.
- **Timing rules** port ZAP's TimingUtils regression; the sleep time is fixed at ZAP's
  default of 5 seconds.
- **HTML parsing and response comparison** use ports of ZAP's HtmlContextAnalyser and
  commonlib ComparableResponse on top of brainproxy's own lenient HTML parser (instead of
  Jericho); results can differ slightly on badly broken markup.
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
