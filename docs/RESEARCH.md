# Braintruder: research on Burp Suite and OWASP ZAP, and a CLI design

Status: design, updated 2026-10-16. Phase 0 is implemented (see the README).

Goal: a fast, lightweight, **AI-first** web security testing tool. It covers the core
workflow of Burp Suite and OWASP ZAP (intercept, replay, fuzz, crawl, scan, report).
Every feature is a non-interactive CLI command, so an AI agent can drive all of it. A GUI
comes later on the same engine.

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
| **Turbo Intruder** (BApp) | Very fast scripted sending, race conditions, HTTP pipelining. | P1 (cheap with tokio) |
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

## 3. Stack: Rust

Chosen for speed and efficiency: no garbage collector, predictable latency under heavy
fuzzing, small static binaries, and low memory when a proxy holds thousands of connections.

| Need | Rust choice |
|---|---|
| Async networking | `tokio` |
| TLS client and MITM | `rustls` (ring backend, no C toolchain), `rcgen` for the CA and per-host leaf certificates |
| Raw, malformed requests (smuggling, CRLF) | Our own raw HTTP/1.x writer and reader (done in Phase 0), with `httparse` |
| HTTP/2, single-packet race attacks | `h2` for normal traffic, plus a small hand-written frame writer for single-packet attacks |
| Storage | SQLite via `rusqlite` (bundled), one `.btdb` file per project |
| CLI | `clap` (derive). Its command tree also generates the `capabilities` JSON. |
| Headless crawling | `chromiumoxide` (Chrome DevTools Protocol) |
| Custom checks / filters | YAML via `serde`, filter expressions via an embedded expression engine (e.g. `cel-interpreter` or `evalexpr`) |
| Plugins (later) | WASM via `wasmtime`, so plugins are sandboxed and language-agnostic |
| GUI (later) | Tauri, on the same engine crate |

Workspace layout: `crates/core` (engine library) and `crates/cli` (the `braintruder`
binary). Later: `crates/mcp` (MCP server) and `crates/gui`.

## 4. Architecture

```
                 +----------------------------------------------+
  CLI        --> |           core engine (Rust crate)           | <-- later: GUI, MCP server, REST API
                 +----------------------------------------------+
                 | proxy (MITM, CA, HTTP/1/2, WS, intercept)    |
                 | sender (raw HTTP/1.x client, h2 later)       |
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

Our own YAML, not a copy of BCheck syntax. Agents can write new checks as plain files:

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

Ported ZAP rules live in Rust (`crates/core/src/checks/zap/...`) with a header that credits the original file.
Simple ones can be written as YAML checks.

---

## 5. AI-first CLI contract

These rules apply to every command, current and future:

1. **No interactive prompts, ever.** Every choice is a flag, an env var, or a file. Missing
   state, like the project file, is created automatically. Dangerous actions are gated by
   explicit flags (for example `--scope`), not by confirmations.
2. **One JSON envelope per command.** `--format json` is the default when stdout isn't a
   terminal: `{"ok":true,"command":"send","data":{...}}` or
   `{"ok":false,"command":"send","error":{"kind":"connect","message":"..."}}`.
3. **Stable exit codes:** 0 success, 1 internal/storage error, 2 invalid input or usage,
   3 network error, 4 not found. Later: 5 findings at or above a `--fail-on` severity.
4. **Self-description.** `braintruder capabilities` returns every command, flag, default,
   allowed value, env var, exit code, and codec as JSON. An agent learns the whole tool in
   one call.
5. **Bounded output.** Bodies are capped (`--max-body`) and marked `truncated`. Binary data
   comes back as base64 with `"encoding":"base64"`. Lists take `--limit` and `--after <id>`
   for incremental polling.
6. **Pipes everywhere.** Inputs accept `-`/stdin. `--raw` prints bare bytes, so
   `history show 7 --part request --raw | braintruder send --target ...` works.
7. **Long-running work becomes jobs.** Proxy, crawl, scan, and fuzz will run as background
   jobs with IDs (`job start|status|stop|results`) that stream NDJSON. An agent never has
   to hold a terminal open.
8. **Intercept without a human.** Instead of a modal "forward/drop" prompt, interception
   is either rules (match-and-replace, auto-drop) or a queue an agent polls and resolves:
   `intercept list`, `intercept edit <id> --file`, `intercept forward|drop <id>`.
9. **MCP server.** `braintruder mcp` will expose the same commands as MCP tools, generated
   from the same command tree, so CLI and MCP never drift.

### Command map

Implemented commands are marked with a check.

```
braintruder capabilities                                   ✔ machine-readable command list
braintruder project init|info                              ✔
braintruder send [FILE|-] [--url U -X M -H h -d body]      ✔ Repeater
                 [--target T] [--verbatim] [--raw]
braintruder history list [--host --status --contains --after --limit]   ✔
braintruder history show <id> [--part request|response|response-body --raw]   ✔
braintruder history note <id> [TEXT]                       ✔
braintruder encode|decode|hash <chain> [INPUT|-]           ✔ Decoder (base64, url, hex, html, jwt, md5/sha*)
braintruder ca init|export                                 Phase 1
braintruder proxy start|stop|status [--listen] [--scope] [--rules]   Phase 1
braintruder intercept list|show|edit|forward|drop          Phase 1
braintruder send --parallel N | --single-packet             Phase 2 (race conditions)
braintruder fuzz <file> --mode sniper|ram|pitchfork|cluster -p 1=list ... [--grep] [--rate]   Phase 2
braintruder diff <id1> <id2> [--words|--bytes]             Phase 2
braintruder crawl <url> [--browser] [--auth auth.yaml]     Phase 4
braintruder scan <url|--history> [--policy] [--checks dir] Phase 3-4
braintruder findings list|show                             Phase 3
braintruder report --format html|json|md|sarif             Phase 4
braintruder import openapi|graphql|har|postman             Phase 5
braintruder run plan.yaml                                  Phase 5 (ZAP-style automation)
braintruder sequencer <id> --token ...                     Phase 6
braintruder oast serve|poll                                Phase 6
braintruder job list|status|stop|results                   Phase 1+
braintruder mcp                                            Phase 6
```

## 6. Phased roadmap

| Phase | Deliverable | Burp/ZAP parity reached |
|---|---|---|
| **0: Skeleton (done)** | Rust workspace, `braintruder` CLI, JSON envelope and exit codes, `capabilities`, SQLite store, raw HTTP/1.x client (HTTP and HTTPS), `send`, `history`, codecs | Repeater (single request), Decoder |
| **1: Proxy and history** | MITM proxy (HTTP/1.1, then HTTP/2), CA generation and export, scope, match-and-replace, history and show commands, HAR import/export | Burp Proxy, ZAP proxy |
| **2: Manual tools** | `repeat` (with race and single-packet modes), `fuzz` (all 4 Intruder modes, payload processors, grep), `decode`, `diff` | Repeater, Intruder, Decoder, Comparer |
| **3: Passive scanner** | Port the ZAP passive rules. Run them inline in the proxy and over history. | ZAP passive scan |
| **4: Crawl and active scan** | HTTP spider, insertion-point engine, scan policies, port of the ZAP release active rules, YAML checks, reports (HTML/JSON/SARIF) | Burp Scanner (core), ZAP active scan |
| **5: Auth and automation** | Contexts, login flows, session macros, `braintruder run plan.yaml`, OpenAPI/GraphQL import | ZAP Automation Framework, Burp session rules |
| **6: Advanced** | OAST server/client, headless browser crawler, Sequencer, WebSocket fuzzing, ZAP beta rules, MCP server for AI agents, plugins | Collaborator, Sequencer, Burp AT/ZAP MCP |
| **7: GUI** | Tauri on the same engine | Burp/ZAP desktop |

---

## 7. Legal and ethical guardrails

- Keep `LICENSE` (our choice; Apache 2.0 is the simplest fit with ZAP) and a `NOTICE`
  file that credits ZAP and the payload sources.
- Burp: clean-room only. Never use decompiled code, text copied from PortSwigger docs, or
  their trademarks.
- The tool should require an explicit scope for active scanning and fuzzing, warn when the
  target is out of scope, and support rate limits by default. It's for authorized testing.

---

## 8. Decisions

| Decision | Choice |
|---|---|
| Language | Rust |
| Interface | AI-first, non-interactive CLI. GUI later. |
| Binary name | `braintruder` |
| Project license | Apache 2.0, proposed for easy ZAP reuse. Not yet confirmed. |

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
