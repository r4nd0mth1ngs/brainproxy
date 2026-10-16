# brainproxy: research on Burp Suite and OWASP ZAP, and a CLI design

Status: design, updated 2026-10-16. Phase 0 is implemented (see the README).

Goal: a fast, lightweight, **AI-first** web security testing tool. It covers the core
workflow of Burp Suite and OWASP ZAP (intercept, replay, fuzz, crawl, scan, report).
**Braintruder** runs it through a Kali runner (CLI-only Kali first, other platforms later),
so its main operator is an LLM. Every feature is a non-interactive CLI command. A GUI comes
later on the same engine.

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
| Storage | SQLite via `rusqlite` (bundled), one `.bpdb` file per project |
| CLI | `clap` (derive). Its command tree also generates the `capabilities` JSON. |
| Headless crawling | `chromiumoxide` (Chrome DevTools Protocol) |
| Custom checks / filters | YAML via `serde`, filter expressions via an embedded expression engine (e.g. `cel-interpreter` or `evalexpr`) |
| Plugins (later) | WASM via `wasmtime`, so plugins are sandboxed and language-agnostic |
| GUI (later) | Tauri, on the same engine crate |

Workspace layout: `crates/core` (engine library) and `crates/cli` (the `brainproxy`
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
4. **Self-description.** `brainproxy capabilities` returns every command, flag, default,
   allowed value, env var, exit code, and codec as JSON. An agent learns the whole tool in
   one call.
5. **Bounded output.** Bodies are capped (`--max-body`) and marked `truncated`. Binary data
   comes back as base64 with `"encoding":"base64"`. Lists take `--limit` and `--after <id>`
   for incremental polling.
6. **Pipes everywhere.** Inputs accept `-`/stdin. `--raw` prints bare bytes, so
   `history show 7 --part request --raw | brainproxy send --target ...` works.
7. **Long-running work becomes jobs.** Proxy, crawl, scan, and fuzz will run as background
   jobs with IDs (`job start|status|stop|results`) that stream NDJSON. An agent never has
   to hold a terminal open.
8. **Intercept without a human.** Instead of a modal "forward/drop" prompt, interception
   is either rules (match-and-replace, auto-drop) or a queue an agent polls and resolves:
   `intercept list`, `intercept edit <id> --file`, `intercept forward|drop <id>`.
9. **MCP server.** `brainproxy mcp` will expose the same commands as MCP tools, generated
   from the same command tree, so CLI and MCP never drift.
10. **Captures are a SQL database.** Every request any tool sends or proxies goes into one
    SQLite table, stored raw *and* pre-parsed (see below). `brainproxy query` runs
    read-only SQL against it.

### Designing for an LLM operator

Choices made from the point of view of the model that will run brainproxy:

- **SQL rather than a custom filter language.** LLMs already write SQL well. Learning a new
  filter DSL costs tokens and causes mistakes; SQL needs no learning. The database is opened
  read-only for `query`, so there is no risk in letting the model write any SQL.
- **Pre-parsed columns.** `url`, `path`, `query`, `status`, `*_content_type`, `title`, and
  headers as JSON are filled in when a capture is recorded. Bodies are stored decoded
  (chunking, gzip, deflate, and br removed) in `*_body`, plus a `*_body_text` copy when
  they're UTF-8. The model filters with plain `WHERE` clauses instead of parsing raw HTTP.
- **Helper SQL functions** for the things models otherwise get wrong:
  `header(resp_headers, 'set-cookie')` (case-insensitive), `REGEXP` and
  `regexp_extract(text, pattern, group)` (Rust regex syntax), plus SQLite's built-in
  `json_extract`/`json_each` for JSON bodies.
- **Full-text search** (`history_fts`, FTS5) for "find anything mentioning X" across URLs,
  headers, and bodies of large captures.
- **`schema` is self-documenting.** It returns every column with a description, the helper
  functions, and worked example queries, so the model writes correct SQL first time.
- **Token-frugal output.** Query results default to `{columns, rows:[[...]]}`. Column
  names aren't repeated per row. Cells are capped (`--max-cell`), rows are capped
  (`--limit`) with a `truncated` flag, and `--format text` gives TSV. `send` omits the
  echoed request unless `--show-request`, and prints headers as `"Name: value"` strings.
- **Parameter binding** (`-p value` maps to `?1`) so payloads with quotes never break the SQL.
- **Tags and notes** (`history tag`, `history note`) give the model a place to record its
  working state ("idor-candidate", "tested") and query it later
  (`EXISTS (SELECT 1 FROM json_each(tags) WHERE value='idor-candidate')`).
- **Fuzz results are pre-triaged.** A fuzz run ends with a summary instead of thousands
  of rows: the baseline response shape (status + word count), outliers whose shape is rare,
  grep matches with extracted values, the slowest responses, and grouped errors. Everything
  is still in `fuzz_results` for SQL.
- **Targeted help.** `capabilities send` describes just one command, so the model doesn't
  reload the whole CLI description each time.

### Command map

Implemented commands are marked with a check.

```
brainproxy capabilities [COMMAND...]                      ✔ machine-readable command list
brainproxy schema                                         ✔ capture DB columns, functions, examples
brainproxy query <SQL|-> [-p v]... [--limit --max-cell --shape rows|objects]   ✔ read-only SQL
brainproxy project init|info                              ✔
brainproxy send [FILE|-] [--url U -X M -H h -d body]      ✔ Repeater
                 [--target T] [--verbatim] [--raw]
brainproxy history list [--host --status --tag --contains --after --limit]   ✔
brainproxy history show <id> [--part request|response|response-body --raw]   ✔
brainproxy history note <id> [TEXT]                       ✔
brainproxy history tag <id> [--add t] [--remove t]        ✔
brainproxy encode|decode|hash <chain> [INPUT|-]           ✔ Decoder (base64, url, hex, html, jwt, md5/sha*)
brainproxy ca init|export|install-system                  ✔
brainproxy proxy start|run|stop|status [--listen]         ✔ background proxy, captures to the DB
brainproxy scope show|set|add|clear|check                 ✔ host regexes
brainproxy rules list|add|remove|enable|disable|clear     ✔ match-and-replace
brainproxy intercept enable|disable|status|list|show|forward|drop   ✔ agent-driven queue
brainproxy send --race N                                  ✔ last-byte sync (HTTP/2 single-packet: later)
brainproxy fuzz run|status|results|list|stop              ✔ 4 modes, -p list:|file:|range:, --process, --grep, --extract
brainproxy diff <id1> <id2> [--part] [--mode lines|words|bytes]   ✔
brainproxy crawl <url> [--browser] [--auth auth.yaml]     Phase 4
brainproxy scan active <url|--history> [--policy] [--checks dir]   Phase 4
brainproxy findings list|show|mark                        ✔ grouped by alert type, de-duplicated
brainproxy scan passive|rules|enable|disable|sources       ✔ 49 passive rules from ZAP
brainproxy report --format html|json|md|sarif             Phase 4
brainproxy import openapi|graphql|har|postman             Phase 5
brainproxy run plan.yaml                                  Phase 5 (ZAP-style automation)
brainproxy sequencer <id> --token ...                     Phase 6
brainproxy oast serve|poll                                Phase 6
brainproxy job list|status|stop|results                   Phase 1+
brainproxy mcp                                            Phase 6
```

## 6. Phased roadmap

| Phase | Deliverable | Burp/ZAP parity reached |
|---|---|---|
| **0: Skeleton (done)** | Rust workspace, `brainproxy` CLI, JSON envelope and exit codes, `capabilities`, SQLite capture DB with `query`/`schema`, FTS, and SQL helpers, raw HTTP/1.x client (HTTP and HTTPS), `send`, `history`, codecs, static Linux build | Repeater (single request), Decoder, Logger |
| **1: Proxy (done)** | MITM proxy (HTTP/1.x, CONNECT, TLS interception, WebSocket pass-through), CA generation/export/system install, scope, match-and-replace, intercept queue in the project DB, background lifecycle. Still to do: HTTP/2 to clients, upstream connection pooling, upstream proxy chaining, HAR import/export | Burp Proxy, ZAP proxy |
| **2: Manual tools (done)** | `send --race` (last-byte sync), `fuzz` (4 Intruder modes, payload sources and processors, grep/extract, match-status, stop-on-match, rate limit, keep-alive workers, background runs, outlier summary), `diff`. Still to do: HTTP/2 single-packet attack, streaming very large wordlists | Repeater, Intruder, Comparer |
| **3: Passive scanner (done)** | 49 ZAP passive rules ported (see docs/PASSIVE_RULES.md), run automatically on proxy and send traffic, de-duplicated findings with triage states, `findings`/`scan` commands. Still to do: ViewState rules, a threshold setting | ZAP passive scan |
| **4: Crawl and active scan** | HTTP spider, insertion-point engine, scan policies, port of the ZAP release active rules, YAML checks, reports (HTML/JSON/SARIF) | Burp Scanner (core), ZAP active scan |
| **5: Auth and automation** | Contexts, login flows, session macros, `brainproxy run plan.yaml`, OpenAPI/GraphQL import | ZAP Automation Framework, Burp session rules |
| **6: Advanced** | OAST server/client, headless browser crawler, Sequencer, WebSocket fuzzing, ZAP beta rules, MCP server for AI agents, plugins | Collaborator, Sequencer, Burp AT/ZAP MCP |
| **7: GUI** | Tauri on the same engine | Burp/ZAP desktop |

---

## 7. Legal and ethical guardrails

- Keep `LICENSE` (Apache 2.0 for now) and a `NOTICE` file that credits ZAP and the
  payload sources. These obligations stay even if brainproxy later goes closed source.
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
| Binary name | `brainproxy` (driven by Braintruder through a Kali runner) |
| First platform | CLI-only Kali Linux, as a fully static x86_64 binary (musl). arm64 is next. |
| Capture storage | SQLite, one `.bpdb` file per project, queried with read-only SQL |
| Project license | Apache 2.0 for now. Closed source may come later. Apache 2.0 allows ZAP-derived code in a closed product, as long as the NOTICE and license text for that code are kept. |

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
