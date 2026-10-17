# brainproxy handover

State as of commit `311e871` on `main` (2026-10-17). Everything below is pushed.

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

Toolchain used: Rust 1.97 (edition 2021). Tests: 327 (`cargo test`), including end-to-end
tests that run the real binary against in-process HTTP/HTTPS servers and curl.

**Rule:** run `scripts/check.sh` before every commit. CI (`.github/workflows/ci.yml`) runs
the same checks, then builds static x86_64 and arm64 binaries (arm64 smoke-tested under
QEMU) and attaches them with `.sha256` files to `v*` tags. No tag has been created yet; CI
status couldn't be checked from the cloud session, so look at the Actions tab first.

## Repository map

```
crates/core/src/            engine library (everything testable lives here)
  http/                     raw HTTP/1.x: request/response parsing, WireReader, client (rustls)
  guard.rs                  engagement + system scope; enforced in Client::connect
  store.rs                  SQLite project store (schema v7, migrations in Store::migrate)
  capture.rs                raw exchange -> parsed columns (url, headers JSON, decoded bodies)
  proxy/                    MITM proxy: CA (rcgen), server, scope/rules/intercept settings
  fuzz/                     Intruder: templates, 4 modes, payloads, engine, results summary
  race.rs, diff.rs          last-byte-sync race sending; comparer
  crawl.rs                  spider (links, forms, robots, sitemap, JS paths)
  jobs.rs                   background jobs table + JobControl (stop/progress)
  scan/passive/             49 rules ported from ZAP pscanrules (+ data/ files from ZAP)
  scan/active/              engine (mod.rs: Cx API), points.rs (insertion points),
                            rules/ with 42 rules ported from ZAP ascanrules
  scan/findings_db.rs       de-duplicated findings (hits), finding_types texts
  auth.rs                   auth sessions (core only, see "In progress")
crates/cli/src/             thin CLI over core (clap). One *_cmd.rs per command group.
crates/cli/tests/           end-to-end tests (cli.rs, proxy.rs, scope.rs)
docs/RESEARCH.md            original research, design, roadmap, AI-first CLI contract
docs/PASSIVE_RULES.md       passive rules + differences from ZAP
docs/ACTIVE_RULES.md        active rules + differences from ZAP
docs/RULE_UPDATES.md        how ZAP rule changes are tracked / auto-update design
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
3. Passive scanner: 49 ZAP rules, automatic incremental scanning, findings triage.
4. Crawler, background jobs, immutable engagement scope, active scanner with 42 ZAP rules,
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

## Backlog (suggested order)

1. Tag `v0.1.0` once CI is green (publishes arm64 + x86_64 binaries).
2. Reports: JSON, Markdown, HTML, SARIF from findings.
3. API import: OpenAPI/Swagger, GraphQL introspection, Postman as scan targets.
4. Out-of-band callback server (Collaborator-like) to enable Log4Shell, blind SSRF/XXE.
5. Rule updates layers 2–3 (docs/RULE_UPDATES.md): `rules update` for ZAP data files;
   declarative checks incl. a Nuclei template subset.
6. Remaining ZAP rules (see `zap-sync.json` "skipped"): XSLT injection, persistent XSS,
   ViewState rules, CharsetMismatch, Heartbleed.
7. Performance: upstream connection pooling, HTTP/2 client/proxy, single-packet race.
8. MCP server exposing the CLI as tools; later the GUI (Tauri) on the same core.

## Notes from the cloud session

- Parallel work used git worktrees under `.claude/worktrees/` (ignored by git); all were
  merged and removed.
- Several turns in the cloud session were cut off by an automated safety filter while
  working on the active rules and on auth wiring; the XSLT injection port was abandoned for
  that reason. Nothing partial was committed (each interrupted step was reverted), and
  `scripts/check.sh` passes on `main`.
- `/tmp`-style test projects: tests create their own temp dirs; no external services are
  needed, but `curl` must be installed for `crates/cli/tests/proxy.rs`.
