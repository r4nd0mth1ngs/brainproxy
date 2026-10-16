# BrainProxy: research on Burp Suite and OWASP ZAP, and a CLI design

Status: research and design draft, written 2026-10-16. No code yet.

Goal: a lightweight, CLI-first web security testing tool (a GUI comes later) that covers
the core workflow of Burp Suite and OWASP ZAP: intercept, replay, fuzz, crawl, scan, report.

---

## 1. What we can take from each tool, and how

| | OWASP ZAP | Burp Suite (Pro / Community) |
|---|---|---|
| License | Apache 2.0 (core `zaproxy` and `zap-extensions`) | Proprietary, closed source |
| What we may reuse | Code, scan-rule logic, payload lists, alert IDs and descriptions, docs text. We must keep the Apache 2.0 license text and a `NOTICE` file, mark files we changed, and credit the original authors. | **Ideas and workflows only.** We rebuild features from public documentation, clean-room. We copy no code, decompiled bytecode, UI assets, text, or the BCheck/Bambda language verbatim. We don't use the "Burp" name in our product. |
| Language | Java | Java |

ZAP's rules are Java, so we port their **logic** (the payloads, detection regexes, and
comparison heuristics) into our own language, keeping the attribution. Porting counts as a
derivative work, which Apache 2.0 allows.

Other permissively licensed sources worth taking from:
- **SecLists** (MIT): wordlists for discovery, fuzzing, and usernames.
- **FuzzDB** (BSD/CC-BY, also bundled as a ZAP add-on): attack payloads.
- **Nuclei templates** (MIT): a model for a declarative check format, and a huge library of
  known-CVE checks. A later phase could support a compatible subset.

---

## 2. Feature inventory

### 2.1 Burp Suite features to reproduce (clean-room)

| Burp feature | What it does | Priority for us |
|---|---|---|
| **Proxy** | MITM HTTP/1.1, HTTP/2, and WebSocket traffic. Uses a per-install CA, intercept/forward/drop, match-and-replace rules, scope filtering. | P0 |
| **HTTP history** | A searchable log of every request and response, with filters, notes, and highlights. | P0 |
| **Repeater** | Edits a request and resends it. Can send a group of requests in parallel or as a single-packet attack (race conditions). | P0 |
| **Intruder** | Marks payload positions with `§…§`. Attack types are **Sniper** (one position at a time), **Battering ram** (one payload in every position), **Pitchfork** (lists advance together), and **Cluster bomb** (every combination). Supports payload processing (encode, hash, prefix), grep-match and grep-extract, and resource pools. | P0 |
| **Decoder** | URL, HTML, Base64, hex, and gzip encode/decode. Hashes. Smart decode. | P1 |
| **Comparer** | Word-level and byte-level diff of two requests or responses. | P1 |
| **Sequencer** | Statistical randomness analysis of session tokens (FIPS 140-2 tests, entropy per character/bit). | P2 |
| **Scanner** (Pro) | Crawl, then passive and active audit. Insertion points include params, headers, cookies, JSON/XML bodies, and nested encodings. | P0 (via the ZAP rule port) |
| **BChecks** (Pro) | A small declarative language for custom scan checks: metadata, `given … then`, `send payload`, `if … then report issue`, and Collaborator interactions. | P1. We build **our own YAML check format** with the same capabilities (see section 4). |
| **Bambdas** | Java snippets used as filters and custom columns over history. | P1. Use a filter DSL or an embedded expression language (e.g. CEL or expr). |
| **Collaborator** | An out-of-band interaction server (DNS, HTTP, SMTP) for blind SSRF, blind XXE, blind SQLi, and blind XSS. | P1. Self-hosted OAST server, or an interactsh client (MIT). |
| **Organizer** | Saves and annotates interesting requests. Newer versions can share collections. | P2 |
| **Logger** | Shows all traffic from every tool, not only the proxy. | Free if our store records every source |
| **Session handling rules / macros** | Re-login, refresh CSRF tokens, update cookies before each request. | P1 (needed to scan authenticated apps) |
| **Turbo Intruder** (BApp) | Very fast scripted sending, race conditions, HTTP pipelining. | P1 (Go makes this cheap) |
| **Extensions (Montoya API)** | A plugin API. | P2. Plugins as external processes or WASM. |
| **Burp AI / Burp AT** (2026.7) | An agentic AI that drives Burp's deterministic tools toward a testing goal. | P2. Expose our engine over MCP so any LLM agent can drive it. |

### 2.2 ZAP features to port (Apache 2.0)

Inventoried from `zaproxy/zap-extensions@main` (`addOns/*/src/main/java`).

**Active scan rules, release (`ascanrules`, 48 rule classes):** BufferOverflow, CloudMetadata,
CodeInjection, CommandInjection (+Timing), CrlfInjection, CrossSiteScripting (reflected),
PersistentXss (+Prime/Spider), DirectoryBrowsing, Elmah, EnvFile, ExponentialEntityExpansion,
ExternalRedirect, FormatString, GetForPost, HeartBleed, HiddenFiles, HtAccess, HttpOnlySite,
HttpsAsHttp, Log4Shell, PaddingOracle, ParameterTamper, PathTraversal, RemoteFileInclude,
ServerSideInclude, ShellShock, SourceCodeDisclosure (WEB-INF, CVE-2012-1823), Spring4Shell,
SpringActuator, React2Shell, SqlInjection (error/boolean/union) plus timing variants for
MySQL, PostgreSQL, MSSQL, Oracle, and Hypersonic, Ssti and SstiBlind, TraceAxd, UserAgent,
XpathInjection, XsltInjection, Xxe.

**Active scan rules, beta (`ascanrulesBeta`, 23):** BackupFileDisclosure, Cors, CrossDomain,
CsrfToken, ExpressionLanguageInjection, ForbiddenBypass (403 bypass), HttPoxy,
HttpParameterPollution, InsecureHttpMethod, IntegerOverflow, MongoDbInjection (+Timing),
OutOfBandXss, ProxyDisclosure, RelativePathConfusion, SessionFixation, SourceCodeDisclosure
(Git, SVN, file inclusion), Ssrf, Text4Shell, UsernameEnumeration.

**Passive scan rules (`pscanrules` 54 + `pscanrulesBeta` 6):** security headers
(CSP, HSTS, X-Content-Type-Options, anti-clickjacking, Permissions-Policy, site isolation),
cookie flags (HttpOnly, Secure, SameSite, scope), cache control, information leaks (Server,
X-Powered-By, X-AspNet-Version, debug errors, stack traces, private IPs, hashes, timestamps,
PII, suspicious comments, session IDs in URLs), mixed content, insecure forms, CSRF
countermeasures, user-controlled charset, cookie, attribute, JS event, and open redirect,
ViewState, SRI, the polyfill.io CDN check, and modern-app detection.

**Other ZAP capabilities worth copying in design:**
- **Automation Framework**: a YAML "plan" with `env` (contexts, URLs, auth, users) and
  ordered `jobs` (`spider`, `spiderAjax`/`clientSpider`, `passiveScan-wait`, `activeScan`,
  `activeScan-policy`, `openapi`/`graphql`/`soap` import, `requestor`, `report`,
  `exitStatus`, `delay`). This is the right model for a CI-friendly CLI.
- **Scan policies**: per-rule strength (attack count) and threshold (false-positive
  tolerance). Since early 2026 you can also select rules by **alert tags** (OWASP Top 10,
  CWE, and so on).
- **Contexts and authentication**: form-based, JSON, HTTP/NTLM, script-based, and
  browser-based auth. Logged-in/logged-out indicators. Session management. Multiple users
  for access-control testing.
- **API importers**: OpenAPI, GraphQL (with introspection), SOAP/WSDL, Postman, HAR.
  The 2026 addition of **MCP server scanning** is also relevant.
- **Alert de-duplication** (2.17): group identical alerts across URLs.
- **Reports**: HTML, JSON, XML, Markdown, and SARIF (SARIF matters for GitHub code scanning).
- **Client Spider**: a crawler that drives a real browser, built for SPAs.

---

## 3. Recommended stack: Go

| Need | Why Go fits |
|---|---|
| Lightweight distribution | One static binary, cross-compiled for Linux, macOS, and Windows with no JVM. |
| MITM proxy | `net/http`, `crypto/tls`, `crypto/x509` for on-the-fly leaf certificates, `golang.org/x/net/http2`. |
| Raw, malformed requests (smuggling, CRLF) | We need our own raw HTTP/1.x writer next to `net/http`. That's straightforward in Go. |
| Intruder, Turbo Intruder, race conditions | Goroutines with rate limiting. Single-packet attack via HTTP/2 frame batching. |
| Headless browser crawling | `chromedp` (MIT) or `go-rod` (MIT). |
| Future GUI | Wails (Go + web UI) or a web UI served by the same binary. The CLI engine becomes the backend. |
| Ecosystem precedent | Nuclei, httpx, katana, ffuf, and interactsh are all Go, so tooling and libraries are mature. |

Rust would be the alternative: faster and smaller, but slower to build in, especially for
the TLS-interception and browser-automation parts. Go is the pragmatic choice.

Storage: **SQLite** (`modernc.org/sqlite`, pure Go, no cgo). One `.bpdb` project file holds
history, findings, and config. This mirrors Burp's project file and makes the later GUI simple.

---

## 4. Architecture

```
                 +----------------------------------------------+
  CLI / TUI  --> |            core engine (Go library)          | <-- later: GUI, MCP server, REST API
                 +----------------------------------------------+
                 | proxy (MITM, CA, HTTP/1/2, WS, intercept)    |
                 | sender (net/http + raw socket client)        |
                 | store (SQLite: history, findings, notes)     |
                 | scope + contexts + auth/session handling     |
                 | crawler (HTTP spider + headless browser)     |
                 | scanner (passive + active, insertion points) |
                 | fuzzer (Intruder modes, payload processors)  |
                 | checks (ported ZAP rules + YAML checks)      |
                 | oast (Collaborator-like client/server)       |
                 | report (HTML, JSON, MD, SARIF)               |
                 +----------------------------------------------+
```

The engine is a library. The CLI is a thin layer over it. That keeps "GUI later" cheap.

### Custom check format (our BCheck equivalent)

Our own YAML, not a copy of BCheck syntax:

```yaml
id: bp-ssti-basic
name: Server-side template injection (basic arithmetic)
severity: high
confidence: firm
tags: [injection, ssti, cwe-1336, owasp-a03]
scope: per-insertion-point        # per-host | per-request | per-insertion-point
payloads: ["{{7*191}}", "${7*191}", "<%= 7*191 %>"]
match:
  all:
    - body_contains: "1337"
    - not: { baseline_body_contains: "1337" }
oast: false
```

Ported ZAP rules live in Go (`checks/zap/...`) with a header that credits the original file.
Simple ones can be written as YAML checks.

---

## 5. CLI design (draft)

```
bp init <project.bpdb>                       create a project and generate a CA
bp ca export --format pem|der                export the CA for browser or OS install
bp proxy  [-l 127.0.0.1:8080] [--intercept] [--scope scope.yaml]
          [--match-replace rules.yaml]       run the MITM proxy and log to the project
bp history [--filter 'status==500 && host~"api"'] [--json]
bp show <id> [--raw|--req|--resp]
bp repeat <id|file.http> [--set-header k:v] [--parallel N] [--single-packet]
bp fuzz  <file.http> --mode sniper|ram|pitchfork|cluster
         -p 1=wordlist.txt -p 2=ids.txt [--proc urlencode,b64] [--grep 'error'] [--rate 50]
bp crawl <url> [--depth 5] [--browser] [--auth auth.yaml]
bp scan  <url|--from-history> [--policy default|quick|full|tags:owasp-a03] [--checks dir/]
bp import openapi|graphql|har|postman <file|url>
bp findings [--severity high] [--json]
bp report --format html|json|md|sarif -o out.html
bp decode|encode <b64|url|html|hex|jwt> [input]
bp diff <id1> <id2> [--words|--bytes]
bp sequencer <id> --token 'cookie:session' [--samples 10000]
bp oast serve | poll                         Collaborator-like server or client
bp run plan.yaml                             ZAP-style automation plan for CI, exits non-zero on findings
```

Request files (`.http`) use the raw HTTP format, with optional `§…§` markers for fuzzing,
so you can copy one from the history and edit it in `$EDITOR`.

---

## 6. Phased roadmap

| Phase | Deliverable | Burp/ZAP parity reached |
|---|---|---|
| **0: Skeleton** | Go module, `bp` CLI (cobra), SQLite store, request/response model, `.http` parser, CI | none |
| **1: Proxy and history** | MITM proxy (HTTP/1.1, then HTTP/2), CA generation and export, scope, match-and-replace, history and show commands, HAR import/export | Burp Proxy, ZAP proxy |
| **2: Manual tools** | `repeat` (with race and single-packet modes), `fuzz` (all 4 Intruder modes, payload processors, grep), `decode`, `diff` | Repeater, Intruder, Decoder, Comparer |
| **3: Passive scanner** | Port the ZAP passive rules. Run them inline in the proxy and over history. | ZAP passive scan |
| **4: Crawl and active scan** | HTTP spider, insertion-point engine, scan policies, port of the ZAP release active rules, YAML checks, reports (HTML/JSON/SARIF) | Burp Scanner (core), ZAP active scan |
| **5: Auth and automation** | Contexts, login flows, session macros, `bp run plan.yaml`, OpenAPI/GraphQL import | ZAP Automation Framework, Burp session rules |
| **6: Advanced** | OAST server/client, headless browser crawler, Sequencer, WebSocket fuzzing, ZAP beta rules, MCP server for AI agents, plugins | Collaborator, Sequencer, Burp AT/ZAP MCP |
| **7: GUI** | Wails or embedded web UI on the same engine | Burp/ZAP desktop |

---

## 7. Legal and ethical guardrails

- Keep `LICENSE` (our choice; Apache 2.0 is the simplest fit with ZAP) and a `NOTICE`
  file that credits ZAP and the payload sources.
- Burp: clean-room only. Never use decompiled code, text copied from PortSwigger docs, or
  their trademarks.
- The tool should require an explicit scope for active scanning and fuzzing, warn when the
  target is out of scope, and support rate limits by default. It's for authorized testing.

---

## 8. Open decisions

1. Language: Go (recommended) or Rust?
2. Project license: Apache 2.0 (recommended for easy ZAP reuse), MIT, or GPL?
3. Binary name: `bp`, `brainproxy`, or `braintruder`?
4. Interactive intercept in the CLI: a TUI (bubbletea) or an `$EDITOR` round-trip?

---

## Sources

- ZAP source inventory: `github.com/zaproxy/zap-extensions` (main branch, Apache-2.0),
  `addOns/ascanrules`, `ascanrulesBeta`, `pscanrules`, `pscanrulesBeta`, `automation`.
- ZAP 2026 updates: https://www.zaproxy.org/blog/2026-02-02-zap-updates-2025-highlights-2026-plans/ ,
  https://www.zaproxy.org/blog/2026-06-02-zap-updates-may-2026/
- ZAP scanner rules: https://www.zaproxy.org/docs/desktop/start/checks/
- Burp releases: https://portswigger.net/burp/releases/professional-community-2026-7-1 ,
  https://portswigger.net/burp/releases/professional-community-2026-4 ,
  https://portswigger.net/burp/releases/professional-community-2026-1
- Burp overview: https://en.wikipedia.org/wiki/Burp_Suite
