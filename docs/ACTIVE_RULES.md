# Active rules

`brainproxy scan active` runs 43 rules ported from OWASP ZAP's `ascanrules` add-on (and
helpers from `commonlib`), https://github.com/zaproxy/zap-extensions, Apache License 2.0.
Each rule file names the ZAP class it came from; alert names, descriptions, solutions,
and references are ZAP's.

Every request a rule sends goes through the engagement scope guard (see the README):
rules can only reach targets the engagement allows, including when following redirects.

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
| 20017 | Source Code Disclosure - CVE-2012-1823 | page | high | 20017 |
| 20018 | Remote Code Execution - CVE-2012-1823 | page | high | 20018 |
| 20019 | External Redirect | param | high | 20019-1, 20019-2, 20019-3, 20019-4 |
| 30001 | Buffer Overflow | param | medium | 30001 |
| 30002 | Format String Error | param | medium | 30002 |
| 40003 | CRLF Injection | param | medium | 40003 |
| 40008 | Parameter Tampering | param | medium | 40008 |
| 40009 | Server Side Include | param | high | 40009 |
| 40012 | Cross Site Scripting (Reflected) | param | high | 40012 |
| 40018 | SQL Injection | param | high | 40018 |
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
| 90019 | Server Side Code Injection | param | high | 90019-1, 90019-2 |
| 90020 | Remote OS Command Injection | param | high | 90020 |
| 90021 | XPath Injection | param | high | 90021 |
| 90023 | XML External Entity Attack | page | high | 90023 |
| 90024 | Generic Padding Oracle | param | high | 90024 |
| 90034 | Cloud Metadata Potentially Exposed | host | high | 90034 |
| 90035 | Server Side Template Injection | param | high | 90035 |
| 90036 | Server Side Template Injection (Blind) | param | high | 90036 |
| 90037 | Remote OS Command Injection (Time Based) | param | high | 90037 |

Scopes: `param` runs once per insertion point (query, form, JSON; cookies and headers when
enabled), `page` once per target request, `host` once per scheme://host:port.

Not ported yet (listed in `zap-sync.json`): XSLT Injection, Persistent XSS (needs
cross-request state), Heartbleed (raw TLS).

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
- **Per-file references** for Hidden Files (40035) are added to the finding's other-info.
- **Low-threshold-only alerts** (e.g. the 401/403 "may be protected" informational
  alerts of the file probes, the JSON XSS weakness alert) are not raised.
- Smaller per-rule differences are documented in comments in each rule file.
