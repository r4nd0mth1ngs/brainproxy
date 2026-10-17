# brainproxy handover

State as of branch `feat/mcp` (2026-10-17). `feat/auth-wiring`, `feat/reports`, `feat/api-import`,
`feat/oob`, `feat/rule-updates`, `feat/checks-dsl`, `feat/zap-rules`, `feat/perf`, `feat/checks-inputs`, and `feat/mcp`
(each branched from the previous one) are pushed to origin (no PRs yet); `main` is pushed.

brainproxy is an AI-first, non-interactive web security testing CLI in Rust, built for
Braintruder to drive on a CLI-only Kali runner (arm64 first). It reproduces the core of
Burp Suite and OWASP ZAP: proxy, repeater, intruder, crawler, passive and active scanning,
with a SQLite capture database the agent queries with SQL.

## Get going locally

```sh
git clone https://github.com/r4nd0mth1ngs/brainproxy && cd brainproxy
cargo build                      # dev build
scripts/check.sh                 # fmt + clippy -D warnings + tests (what CI runs); ~1 min
make static                      # static x86_64 musl (needs: apt install musl-tools)
make static-arm64                # static arm64 musl (needs: pip install ziglang; cargo install cargo-zigbuild;
                                 #                    rustup target add aarch64-unknown-linux-musl)
```

Smoke test (every outbound request needs a scope first):

```sh
export BRAINPROXY_PROJECT=/tmp/t.bpdb BRAINPROXY_FORMAT=json
./target/debug/brainproxy engagement start --target 127.0.0.1
./target/debug/brainproxy send --url http://127.0.0.1:8000/
./target/debug/brainproxy findings list
./target/debug/brainproxy capabilities      # full machine-readable command list
```

Toolchain used: Rust 1.97 (edition 2021). Tests: 424 (`cargo test`), including end-to-end
tests that run the real binary against in-process HTTP/HTTPS servers and curl.

**Rule:** run `scripts/check.sh` before every commit. CI (`.github/workflows/ci.yml`) runs
the same checks, then builds static x86_64 and arm64 binaries (arm64 smoke-tested under
QEMU) and attaches them with `.sha256` files to `v*` tags. No tag has been created yet; CI
status couldn't be checked from the cloud session, so look at the Actions tab first.

## Repository map

```
crates/core/src/            engine library (everything testable lives here)
  http/                     raw HTTP/1.x: request/response parsing, WireReader, client (rustls, pool),
                            h2.rs (HTTP/2 over the guarded client)
  guard.rs                  engagement + system scope; enforced in Client::connect
  store.rs                  SQLite project store (schema v9, migrations in Store::migrate)
  capture.rs                raw exchange -> parsed columns (url, headers JSON, decoded bodies)
  proxy/                    MITM proxy: CA (rcgen), server, scope/rules/intercept settings
  fuzz/                     Intruder: templates, 4 modes, payloads, engine, results summary
  race.rs, diff.rs          last-byte sync and HTTP/2 single-packet races; comparer
  crawl.rs                  spider (links, forms, robots, sitemap, JS paths)
  jobs.rs                   background jobs table + JobControl (stop/progress)
  scan/passive/             52 rules ported from ZAP pscanrules (+ data/ files from ZAP)
  scan/active/              engine (mod.rs: Cx API, phased run), points.rs (insertion points),
                            source_sink.rs (stored-input tracking), rules/ with 48 rules
                            ported from ZAP ascanrules (all of them)
  scan/findings_db.rs       de-duplicated findings (hits), finding_types texts
  scan/report.rs            report model (findings + types + history evidence), JSON/MD/HTML/SARIF
  auth.rs                   auth sessions (profiles, login, relogin)
  apiimport/                OpenAPI/Swagger, Postman, GraphQL -> requests; send + record (source "import")
  oob/                      out-of-band: tokens, payload/interaction tables, correlate; server.rs listener
  data.rs                   runtime-updatable ZAP data files (embedded or <home>/rules copy)
  fetch.rs                  GitHub-only guarded downloads (resolve ref, raw file, tarball) + tar.gz reader
  checks/                   declarative checks: Nuclei HTTP subset parser (mod.rs), DSL parser +
                            evaluator (dsl.rs), runner as an active rule (rule.rs), template
                            stores + `checks update` (store.rs)
crates/cli/src/             thin CLI over core (clap). One *_cmd.rs per command group; mcp.rs = MCP server.
crates/cli/tests/           end-to-end tests (cli.rs, proxy.rs, scope.rs, auth.rs, report.rs, import.rs, oob.rs, checks.rs, mcp.rs)
docs/RESEARCH.md            original research, design, roadmap, AI-first CLI contract
docs/PASSIVE_RULES.md       passive rules + differences from ZAP
docs/ACTIVE_RULES.md        active rules + differences from ZAP
docs/OOB.md                 out-of-band listener design (tokens, NAT, correlation, boundary)
docs/RULE_UPDATES.md        how ZAP rule changes are tracked; data sync and declarative checks
docs/CHECKS.md              check format (Nuclei subset + extensions), stores, security boundary
docs/MCP.md                 MCP server: protocol, tool derivation, bounds
zap-sync.json               pinned zap-extensions commit, copied data files, skipped rules
scripts/zap_drift.py        reports upstream ZAP changes vs. our ports (weekly workflow)
scripts/check.sh            pre-commit checks
```

## Design rules to keep

- **AI-first CLI:** no interactive prompts ever; one JSON envelope per command when stdout
  isn't a TTY (`{ok, command, data}` / `{ok:false, error:{kind, message}}`); stable exit
  codes (0 ok, 1 internal, 2 invalid/usage, 3 network, 4 not found, 6 out of scope);
  bounded output (`--limit`, `--max-body`, `--max-cell`, `truncated` flags);
  `capabilities` must describe every command.
- **Scope is the security boundary:** `engagement start` is write-once per project;
  `/etc/brainproxy/scope.json` (root-owned, written by the runner) is always enforced on
  top and can't be overridden. Every network path must use `Client` with a guard
  (`SendOptions.guard`); `Client::connect` resolves, checks, and connects only to checked
  addresses. Never add a code path that opens sockets around `Client`.
- **Long work runs as jobs:** `--background` + `job status|wait|stop`
  (`jobs_cmd::spawn_background` / `run_job`).
- **ZAP ports:** every ported file starts with `//! Ported from ZAP <Class> (<addon>, Apache
  License 2.0).` (the drift script relies on it); alert texts are ZAP's; NOTICE lists
  ZAP-derived code. Deviations go in docs/PASSIVE_RULES.md / ACTIVE_RULES.md.

## What's done (phases)

0. Rust workspace, JSON envelope, capture DB with read-only SQL `query` + `schema`, codecs.
1. Intercepting proxy (CONNECT, TLS interception, WebSocket pass-through), CA, scope/rules,
   agent-driven intercept queue.
2. Fuzzer (sniper, battering-ram, pitchfork, cluster-bomb), `send --race`, `diff`.
3. Passive scanner: 49 ZAP rules (52 now), automatic incremental scanning, findings triage.
4. Crawler, background jobs, immutable engagement scope, active scanner with 42 ZAP rules (48 now),
   ZAP drift detection, arm64 static builds.

## Authenticated testing (done)

`crates/core/src/auth.rs` (profiles, `AuthSession`) and `crates/cli/src/auth_cmd.rs`
(`auth add|login|status|headers|list|show|remove`, plus `load_session` / `maybe_session`,
which build the session on the guarded client and log in if needed). `--auth NAME` is wired
into `send` (and `--race`, applied once), `fuzz run`, `crawl`, `scan active` (including the
URL baselines), and `proxy start|run`. Each site applies the session, observes responses,
and on `is_logged_out` calls `relogin(generation)` and retries once. Fuzzed cookies (marker
in the value) and the cookie being attacked by an active rule keep their payload. Commands
call `session.save()` when they finish. E2E tests: `crates/cli/tests/auth.rs` (local app
with CSRF form login, expiring sessions, JSON bearer login, crawl/fuzz/active/proxy).

Known limits / ideas:
- `auth_profiles.state` (session cookies) and literal passwords are readable through
  `query`; `--password-env` avoids storing the password.
- The proxy observes browser responses too, so a browser logout clears the shared jar.
- Relogin is bounded by `--relogin-interval` (default 5 s) and `--max-relogins` (20 per
  command run); attacking the session cookie itself can use these up.
- No multi-user profiles for access-control testing yet (e.g. replay as user B).

## Reports (done)

`crates/core/src/scan/report.rs` builds a `Report` (summary by risk, alert groups with
ZAP description/solution/references/CWE, instances with the history request/response cut
to `--max-evidence`) and renders it; `crates/cli/src/report_cmd.rs` is the `report [json|
markdown|html|sarif]` command with `--output`, `--risk`, `--confidence`, `--source`,
`--state`, `--host`, `--alert`, `--limit`, `--no-evidence`, `--title`. Without `--output`,
JSON mode puts the JSON report in `data` (other formats as `data.content`); text mode prints
the rendered report. HTML escapes all target data and sets a CSP that blocks scripts;
Markdown puts target data in code spans/blocks whose fences outgrow any backtick run.
SARIF uses `webRequest`/`webResponse`, `security-severity`, CWE tags, and a
`partialFingerprints` key per finding. `findings list` also gained `--confidence`.

## API import (done)

`crates/core/src/apiimport/`: `parse_document` (JSON, or YAML via serde-saphyr with its
alias budget; non-string keys like `200:` become strings), `openapi.rs` (3.x + Swagger 2.0:
servers with variables, operation > path > document servers, relative servers against the
spec URL, `$ref`/allOf/oneOf, path/query/header/cookie params, JSON/form/multipart/XML/text
bodies), `postman.rs` (v2.0/v2.1: folders, `{{vars}}`, `:path` vars, raw/urlencoded/formdata/
graphql bodies, bearer/basic/apikey auth inherited from folders), `graphql.rs` (introspection
query, one operation per query/mutation field with arguments as variables, selection depth
3), `values.rs` (schema -> example value, encoders), and `run` (send in scope, record, passive
scan). `crates/cli/src/import_cmd.rs` is `import openapi|postman|graphql` with `--base-url`,
`--var`, `-H`, `--auth`, `--include-destructive`, `--dry-run`, `--max-requests`, `--limit`,
`--background`. Spec URLs and introspection go through the guarded client and are recorded.
`scan active` without targets now includes source `import`. `build_raw` rejects non-token
methods and CR/LF in headers from documents.

Known limits / ideas:
- Remote `$ref`s aren't fetched; security schemes aren't applied for OpenAPI (pass `-H`/`--auth`).
- No request chaining (e.g. use the id returned by a create call in later paths).
- GraphQL: no fragments on unions/interfaces (they select `__typename`), no batching/aliases.
- SOAP/WSDL import isn't covered.

## Out-of-band callbacks (done)

Design in docs/OOB.md. `crates/core/src/oob/mod.rs`: tokens (`bp` + 18 base32), `Endpoint`
(DNS mode `<token>.<domain>`, host mode `<host>:<port>/<token>`; `auto_host` + `for_target`
picks the local address routing to each target when the public host was guessed),
`oob_payloads`/`oob_interactions` tables (schema v8), `correlate` (interaction -> finding
backed by the attack exchange, recorded in history on first hit). `oob/server.rs`: TCP
listener (HTTP 200, LDAP bind success then search, TLS ClientHello recorded) and UDP DNS
(A/AAAA with `--public-ip` under `--domain`, REFUSED otherwise); bounded, receive-only.
`crates/cli/src/oob_cmd.rs`: `oob start|run|stop|status|payload|poll`. Scanner: `Cx::oob_payload`,
`payload_request`, `oob_register`; `run` correlates for `--oob-wait` after the last unit
(`--no-oob` skips). Rules: Log4Shell 40043 (new port), XXE 90023 check #2, blind SSTI 90036
callbacks (HIGH/INSANE). E2E: `crates/cli/tests/oob.rs` (fake Log4j over LDAP + XXE over HTTP).

Smoke-tested against the user's lab target (10.0.1.244:8100, "Cargolink TMS"): 231 payloads,
no callbacks (the app showed no Log4j/XML/SSTI surface; the listener was reachable on the LAN).
That run found the default-route bug fixed by `for_target` (VPN default route vs. LAN target).

Known limits / ideas:
- No interactsh client / remote listener; the listener must write to the project file.
- No SMTP; HTTPS callbacks are only recorded as a ClientHello (no TLS handshake).
- Findings are only raised when a scan finishes or on `oob poll` (the listener doesn't raise them).
- More rules could use it: blind command injection (ZAP doesn't), SSRF-style params, RFI.

## Rule updates and declarative checks (done)

Layer 2: `crates/core/src/data.rs` + `scan data status|update|reset`. The four ZAP data
files are read through `data::get(name)`; the CLI calls `data::set_home` at startup, so a
copy in `<home>/rules/` is used when the manifest lists it, its sha256 matches, and it
validates (rules' own parser, at least half the embedded entries). `update` resolves a
zap-extensions ref to a commit and fetches each file at it (or `--from DIR`).

Layer 3: `crates/core/src/checks/` (see docs/CHECKS.md). Templates are parsed from
`serde_json::Value` (via `apiimport::parse_document`) into `Check`/`Block`/`Matcher`; any
unknown key, interactsh, payload file, unknown DSL function, etc. makes the template
"unsupported" with a reason. `into_rules` leaks one `AlertDef` per check (`check:<id>`)
and wraps it as an `ActiveRule` (id 0, scope host/page/param); `ActiveConfig.checks` and
`no_rules` add them to `active::run`. Requests go through `Cx` (`request_for` keeps the
base headers; other origins are skipped). `checks update` (store.rs) downloads the
nuclei-templates tarball at a resolved commit via `fetch::GitHub` (scope = GitHub hosts,
system scope still applies, TLS verified), stores only the `http/` templates that load,
and swaps the store directory. CLI: `crates/cli/src/checks_cmd.rs` (`checks list|validate|
update|status`), `scan active --checks nuclei|local|all|PATH`, `--check-tags`,
`--check-exclude-tags` (default dos,fuzz,intrusive), `--check-ids`, `--check-severity`,
`--no-rules`. Tests: `checks/tests.rs`, `crates/core/tests/checks.rs` (engine against an
in-test server: path, raw + clusterbomb + stop-at-first-match, internal extractor chain,
param inject with baseline_body), `crates/cli/tests/checks.rs`.

Measured on nuclei-templates 17f5725 (before the DSL subset): 5,856 of 11,690 HTTP
templates loaded. Live run on the lab target: 1,493 exposure/config/misconfig/flask
templates, 2,647 requests, no false positives; a local check written for its `/console`
config dump found the leaked secrets.

## Checks DSL subset (done)

`crates/core/src/checks/dsl.rs`: lexer + recursive-descent parser (govaluate precedence:
`||`, `&&`, comparisons, `+ -`, `* / %`, unary `! -`, parentheses) into `Expr`, and a pure
evaluator over `Value` (string/number/bool) with ~40 Nuclei helper functions (contains*,
regex, case, trim, substr, hashes, base64/base64_py/mmh3, url/hex codecs, compare_versions
with go-version constraints, rand_*, unix_time). Parsed at load time; unknown functions or
operators (`?:`, `=~`) make the template unsupported. Limits: 16 KiB per expression,
nesting 32, 512 binary operators (bounds eval recursion), 32 MiB values. Literal regex
arguments are syntax-checked at load and compiled lazily.

Wired in `mod.rs`/`rule.rs`: `type: dsl` matchers (`condition`, `negative`, `name`) and
extractors; DSL in `{{...}}` placeholders and variables (`subst` evaluates expressions over
template values); `json` extractors with a jq path subset (`compile_json_path`);
numbered parts (`body_2`, `status_code_1`) and `req-condition` (all requests of a block
run, internal extractors feed the next, matchers run once over `seen: &[Response]`);
`flow` as `&&`/`||`/`!` over `http(N)` (`run_flow`, short-circuit); matcher `internal: true`
(no finding when all matchers are internal); matched matcher names go into other info.
DSL variables: `dsl_value` (template values, response parts, then any response header).

Coverage on 17f5725: 9,139 of 11,690 load (real `checks update`, ~1 s to load all). Top
remaining reasons: self-contained 938 (correctly skipped), template inputs 556 (`{{username}}`
etc. from `-var`), interactsh 535, payload files 258, lookaround regexes 43, JavaScript
flows 26. Live run on the lab target with the 2,506 stored templates that use DSL/flow/json/
numbered parts (cves, misconfiguration, exposures, panels, technologies, default-logins;
osint and credential-stuffing left out): 3,998 requests, one finding,
`http-missing-security-headers` (true positive: the app sends none of them), no false positives.

`scripts/check.sh` didn't fail on test failures (`! grep` under `set -e`); fixed.

Known limits / ideas (inputs, payload files, and interactsh are done, see below):
- `date_time`, `wait_for`, `generate_jwt`, `hmac`, xpath extractors, and `select()` in json
  queries are unsupported (each < 25 templates).
- In flows, only internal extractor values carry to later blocks (Nuclei shares all named ones).
- `checks list` parses every template; an index in the store would make it instant.
- Data files apply to commands started after the update (a running proxy keeps the old ones).

## Checks inputs, payload files, interactsh (done, branch `feat/checks-inputs`)

`checks::LoadOptions` (`vars`, `any_inputs`, `oob`) is passed to `checks::load`.

- Template inputs: `--check-var NAME=VALUE` on `scan active`, `checks list`, `checks
  validate` (`checks::parse_var`). Unknown placeholder/DSL names that are given become
  `Check.inputs` (also when they override a template variable); missing ones make the
  template unsupported with the names in the reason. `checks update` loads with
  `any_inputs` so they are stored.
- Payload files: `payload_file` in mod.rs resolves `payloads: {x: helpers/...txt}` from
  the template's directory up to the load root (`load` now pairs each file with the path
  it was found under), plain components only, canonicalised and confined to the root,
  4 MiB max. `checks update` keeps `helpers/` (`store_path` accepts `helpers/...`; 64 MiB
  cap; `Manifest.helpers` counts them).
- Interactsh: `Part::Oob`, `Matcher.oob`/`src`, `Block.oob`, `Check.oob_url`. Without
  `LoadOptions.oob` (no running listener, or `--no-oob`) such templates are unsupported;
  `checks list`/`validate` detect a listener in the project. At run time (rule.rs) each
  request gets `cx.oob_payload()` as `{{interactsh-url}}` (`set_oob`; host mode is
  `host:port/token`), and `evaluate` defers when interactsh matchers decide: `defer_oob`
  registers the payload via `Cx::oob_register_check` with `check_json` (alert definition,
  interactsh matcher sources, a snapshot of vars and the response values their DSL uses).
  `oob::correlate` runs `checks::interaction_matches` on each interaction and builds the
  alert from the JSON (`alert_from_json`) when the active rules don't know it, so `oob
  poll` in a later process raises check findings too. Schema v9 adds
  `oob_payloads.check_json`.
- Fixed on the way: `Capture::new` treated an origin-form target with a URL in its query
  (`/fetch?url=http://x/y`) as absolute-form and recorded the wrong URL.

Coverage on 17f5725 (stored templates): 9,392 load without inputs or listener (payload
files +253), 9,870 with a listener, 10,411 with a listener and username/password;
`checks update` stores 10,434 of 11,690 (938 self-contained, 51 JavaScript flows, 43
lookaround regexes, ...). Tests: `checks/tests.rs` (inputs, payload files incl. traversal
and symlink escape, interactsh parsing and matching), `oob` unit test (check payload
correlation without the rule), `crates/core/tests/checks.rs` (inputs end to end),
`crates/cli/tests/checks.rs` (stored input template + `--check-var`), `crates/cli/tests/oob.rs`
(`interactsh_templates_use_the_listener`: real listener, SSRF app, four templates).

Live on the lab target with the listener (auto host 10.0.1.108:8880 via `for_target`):
290 `oast`-tagged templates, 337 requests, 148 payloads registered, no callbacks, no
findings (the app has no such surface; nothing it serves needed them).

Limits: interactions are matched one at a time (an `and` over a DNS and an HTTP
interaction can't combine them); an interactsh block returns false to `flow` until
correlation, so `http(1) && http(2)` doesn't continue after an OOB-only block; nested
placeholders (`{{len('... {{interactsh-url}}')}}`) only get the inner one; DNS-only
templates need `oob start --domain`.

## Remaining ZAP rules (done)

Branch `feat/zap-rules`. Passive: CharsetMismatch 90011, Viewstate 10032, InsecureJsfViewState
90001 (`scan/passive/rules/content/`). Active: XSLT Injection 90017, persistent XSS (Prime
40016, Spider 40017, attack 40014), Heartbleed 20015. Only ZapVersion and UsernameIdor
(pscanrules) remain unported, on purpose.

Engine changes: `ActiveRule::phase` (units run phase by phase; each finishes before the
next starts) and `ActiveRule::depends_on` (ZAP `getDependency`: `--rules 40014` pulls in
40016/40017, excluding one drops the dependents). `source_sink.rs` ports commonlib
SourceSinkUtils (markers `zApPX<n>sS`, sinks = target requests re-sent); Cx gained
`source_value`, `test_for_sink`, `sinks`, `send_following_to`. `Cx::connect_raw(host, port)`
returns a raw TCP stream from the guarded client (Heartbleed speaks TLS records over it;
the scope still applies). Deviations are in docs/ACTIVE_RULES.md / PASSIVE_RULES.md.

Tests: unit tests per rule, params e2e (XSLT vendor + false-positive trap, guestbook
persistent XSS raw/escaped), `crates/core/tests/probes.rs` (Heartbleed against a TLS stub).
Live on the lab target: no findings from the new rules (it isn't ASP.NET/JSF/XSLT; stored
input is behind a login we have no credentials for; it serves plain HTTP).

Ideas: ZAP's SSTI rule also checks persistent-XSS sink pages (SSTI 90035 here only checks
reflected output); `source_sink` could feed it.

## Performance (done except the HTTP/2 proxy, branch `feat/perf`)

Connection pooling: `http/client.rs` keeps idle connections in a pool owned by the `Client`
(shared by its clones; key = tokio runtime id, scheme, host, port; 64 per key, 30 s idle).
Connections only come from `Client::connect`, and a `Client`'s options (guard included)
never change, so reuse never skips a scope decision; a new `Client` starts with an empty
pool. `Client::exchange` checks out, sends, and retries once on a *new* connection when a
reused one fails before any response byte (server closed it while idle); `close_after`
decides whether to `checkin` (request/response `Connection: close`, HTTP/1.0 without
keep-alive, read-until-close bodies, 101, or unread bytes left in the reader). `send`
uses it; the proxy's upstream side uses `exchange` + `checkin` (101 upgrades keep the
stream). The fuzzer's own per-worker keep-alive code was replaced by the pool. Crawl and
import build requests with `Connection: keep-alive`, and the active scanner rewrites a
base request's `Connection: close` to keep-alive (`keep_alive` in scan/active/mod.rs).
The runtime id is in the key because `AuthSession` logs in on a short-lived runtime.
`JobControl::watch` now parks instead of sleeping, so commands no longer wait up to
500 ms for the watcher thread on exit.

Measured (release builds, crawl of 34 pages + active scan of one URL with all non-time-based
rules, local Python HTTPS server with keep-alive): 415 -> 24 connections for the scan;
with a simulated 20 ms per-connection cost, scan 2.0-2.7 s -> 0.53 s and crawl
0.9-1.1 s -> 0.6 s. The lab target (Werkzeug) answers `Connection: close`, so there is no
reuse there (scan times unchanged within noise; crawl ~0.6 s faster from the watcher fix).

HTTP/2 client: `http/h2.rs` (h2 crate). `H2Request::from_raw` turns the HTTP/1.x text
request into an h2 request (Host -> `:authority`, connection-specific headers dropped,
chunked bodies de-chunked; header values that h2 can't carry are an error) and keeps the
text form that is recorded: `METHOD path HTTP/2`, `host:`, sent headers, body. Responses
are recorded as `HTTP/2 <status>` + headers + body; `parse_response_head` accepts that
(version "HTTP/2"), so passive rules, history, and diff work unchanged. `SendOptions.http2`
(CLI `--http2` on send/fuzz/crawl/scan active) or a request line ending in `HTTP/2` routes
`Client::send` over HTTP/2. `Client::connect_h2` = guarded TCP (`connect_tcp`, the only
place sockets to targets are opened) + TLS with ALPN `h2` only (error if not negotiated)
or prior knowledge for http. One multiplexed connection per pool key, created under a
lock so concurrent workers share it; a dead pooled connection is detected by `ready()`
before anything is sent. Errors on a new connection are reworded by `setup_error` (with
an h2c hint for http://). Not done: HTTP/2 in the proxy (browser side needs an h2 server
behind the MITM TLS with ALPN, and upstream h2 per request; the client pieces are ready
for the upstream half), `import`/auth login over h2 (they use HTTP/1.1), and h2-specific
attacks (pseudo-header or CRLF-in-header smuggling: `from_raw` rejects invalid values, and
the h2 crate normalises framing).

Single-packet race: `race::single_packet` (`send --race N --http2`, N <= 100). All requests
on one connection through a `Gate` stream under the h2 connection: send every request but
its final DATA frame (an empty END_STREAM frame for bodiless requests), PING round trip,
then hold writes, queue the final frames, wait until the held bytes contain N END_STREAM
DATA frames (`end_streams` parses frame headers; 2 s cap), and release them in one write.
`synced` in the output = final frames in that write (should equal N). Live-tested only
against in-test h2/h2c servers: the lab target doesn't speak HTTP/2 (h2c refused with a
clear error, exit 3).

## MCP server (done)

Branch `feat/mcp`. `crates/cli/src/mcp.rs`: `brainproxy mcp serve` reads newline-delimited
JSON-RPC 2.0 from stdin (initialize, ping, tools/list, tools/call; notifications ignored).
No MCP crate: the protocol surface is small and a hand-written loop needed no new
dependency. Tools = visible leaf commands of `Cli::command()` (same tree `capabilities`
walks), minus `mcp serve`, `proxy run`, `oob run`; input schemas come from the clap args
(id as property name; value parser type -> integer/number/boolean/string; Append -> array;
possible values -> enum), plus `stdin` where the command's help mentions stdin. A call runs
`current_exe --format json --project P [--home H] path --flag=value ... -- positionals` as a
child process (like `jobs_cmd::spawn_background`), so the scope, envelope, and exit codes
are the CLI's own and process-global state (stdout, exit) needs no refactor. Child stdin is
the `stdin` argument or null. Bounds: `--max-output` (stdout cap, cut-off marker),
`--timeout` (kill, `timeout` envelope), stderr up to 4 KB on failure. Calls run concurrently
(thread + child each, max 16, replies written under a stdout lock); `notifications/cancelled`
sets the call's flag, the wait loop kills the child, and the reply is dropped; stdin EOF
cancels everything and joins.
Tests: unit tests in mcp.rs (argv building, schema types), `crates/cli/tests/mcp.rs`
(protocol errors, tool list, scope refusal, send via url and stdin, history/query, timeout,
output cap, concurrent calls, cancellation closing the target connection). Live: initialize/engagement_start/send/findings_list against the lab target.

Ideas: progress notifications for `job_wait`; `readOnlyHint`/`destructiveHint` tool annotations; MCP resources for `schema` and
reports.

## Backlog (suggested order)

1. Tag `v0.1.0` once CI is green (publishes arm64 + x86_64 binaries).
2. Checks: done (see "Checks inputs, payload files, interactsh").
3. Performance: done except HTTP/2 in the proxy (see "Performance").
4. MCP server: done (see "MCP server"). Next: the GUI (Tauri) on the same core.

## Notes from the cloud session

- Parallel work used git worktrees under `.claude/worktrees/` (ignored by git); all were
  merged and removed.
- Several turns in the cloud session were cut off by an automated safety filter while
  working on the active rules and on auth wiring; the XSLT injection port was abandoned for
  that reason (it was finished later on `feat/zap-rules`). Nothing partial was committed (each interrupted step was reverted), and
  `scripts/check.sh` passes on `main`.
- `/tmp`-style test projects: tests create their own temp dirs; no external services are
  needed, but `curl` must be installed for `crates/cli/tests/proxy.rs`.
