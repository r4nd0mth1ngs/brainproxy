# brainproxy

A fast, AI-first web security testing toolkit written in Rust. It takes its features from
Burp Suite (rebuilt clean-room) and OWASP ZAP (ported under Apache 2.0). Its main operator
is an LLM: **Braintruder** drives it through a Kali runner. Every feature is a
non-interactive CLI command with structured JSON output. A GUI comes later on the same engine.

Only use it against systems you are authorized to test.

See [docs/RESEARCH.md](docs/RESEARCH.md) for the feature research, design, and roadmap.

## Install on Kali (CLI only)

brainproxy builds into one static binary with no runtime dependencies, for **arm64**
(Braintruder's Kali target) and x86_64. Tagged releases attach both
(`brainproxy-linux-arm64`, `brainproxy-linux-x86_64`) with `.sha256` files:

```sh
curl -LO https://github.com/r4nd0mth1ngs/brainproxy/releases/latest/download/brainproxy-linux-arm64
sha256sum -c <(curl -sL https://github.com/r4nd0mth1ngs/brainproxy/releases/latest/download/brainproxy-linux-arm64.sha256)
sudo install -m755 brainproxy-linux-arm64 /usr/local/bin/brainproxy
```

Build an arm64 binary from any Linux machine:

```sh
rustup target add aarch64-unknown-linux-musl
pip install ziglang && cargo install cargo-zigbuild
make static-arm64              # -> target/aarch64-unknown-linux-musl/release/brainproxy
```

Or build x86_64:

```sh
# Build once (on Kali or any Linux box with Rust installed)
sudo apt install -y musl-tools
rustup target add x86_64-unknown-linux-musl
make static                    # -> target/x86_64-unknown-linux-musl/release/brainproxy
sudo make install              # -> /usr/local/bin/brainproxy
```

Or copy the `brainproxy-linux-x86_64` artifact from CI (or a tagged release) onto the runner.

## Engagement scope (required)

brainproxy sends nothing until a scope exists, and every outbound request (send, race,
fuzz, crawl, proxy upstream, scans) must match it. The check happens at connect time,
after DNS resolution, and the connection goes to the checked address. Link-local
addresses such as cloud metadata (169.254.169.254) are refused unless listed by address.

```sh
brainproxy engagement start --target app.example.com --target '*.api.example.com' \
    --target 10.0.0.0/24 --exclude 10.0.0.1 --name "ACME pentest"
brainproxy engagement show
brainproxy engagement check 10.0.0.7:8443
```

`engagement start` is write-once: the scope can't be changed or removed afterwards.

**Runner setup (Braintruder / Kali).** The engagement scope protects a project, but an
agent could start a new project. For a hard lock, the runner writes the scope to
`/etc/brainproxy/scope.json` (root-owned, not writable by the agent) before handing over:

```json
{"name": "ACME pentest", "include": ["app.example.com", "*.api.example.com", "10.0.0.0/24"], "exclude": ["10.0.0.1"]}
```

While that file exists it is always enforced (on top of any engagement scope), and no flag
or environment variable can override it; an unreadable or invalid file blocks all traffic.
Run the agent as a non-root user. For defence in depth, also restrict the runner's egress
with a firewall, since other tools on the box (curl, sqlmap, ...) aren't bound by brainproxy.

## Usage

```sh
export BRAINPROXY_PROJECT=/work/engagement.bpdb   # capture DB, created on first use

# Send requests (Repeater). Each one is recorded in the capture DB.
brainproxy send --url 'https://target.test/api?id=1' -X POST -H 'Content-Type: application/json' -d '{"a":1}'
brainproxy send request.http                      # raw request; target from the Host header
cat request.http | brainproxy send --target http://10.0.0.5:8080

# Query captures with read-only SQL
brainproxy schema                                 # columns, helper functions, example queries
brainproxy query "SELECT id, status, url, title FROM history WHERE status >= 500"
brainproxy query "SELECT id, url FROM history WHERE resp_body_text REGEXP '(?i)sql syntax|ORA-[0-9]{5}'"
brainproxy query "SELECT id, header(resp_headers, 'server') FROM history"
brainproxy query "SELECT rowid FROM history_fts WHERE history_fts MATCH 'password'"
brainproxy query "SELECT id FROM history WHERE host = ?1 AND path LIKE ?2" -p target.test -p '/api/%'

# Intercepting proxy (runs in the background; captures go to the same DB)
brainproxy proxy start --listen 127.0.0.1:8080    # prints proxy URL, CA path, curl/env hints
curl --noproxy '' -x http://127.0.0.1:8080 --cacert ~/.local/share/brainproxy/ca/ca.pem https://target.test/
sudo brainproxy ca install-system                 # or trust the CA system-wide (Kali/Debian)
brainproxy scope set --include '(^|\.)target\.test$' # only intercept/record these hosts
brainproxy rules add --location request-header --replace 'X-Forwarded-For: 127.0.0.1'
brainproxy rules add --location response-body --match 'disabled' --replace ''
brainproxy proxy status
brainproxy proxy stop

# Intercept without a human in the loop: held messages wait in a queue
brainproxy intercept enable --method 'POST|PUT' --host 'target\.test' --timeout 120
brainproxy intercept list --wait 30               # block until something is held
brainproxy intercept show 4 --raw > msg.http      # edit it...
brainproxy intercept forward 4 --file msg.http    # ...and release it (or: intercept drop 4)
brainproxy intercept disable

# Fuzzing (Intruder): mark positions with §value§
brainproxy fuzz run --url 'https://target.test/api/user?id=§1§' -p range:1-500 --grep 'api_key'
brainproxy fuzz run req.http --mode cluster-bomb -p file:users.txt -p file:pass.txt \
    --grep '"ok": ?true' --extract '"token": "([^"]+)"' --stop-on-match --store matches
brainproxy fuzz run req.http -p file:big.txt --rate 50 --background    # returns a run id
brainproxy fuzz status 3          # baseline, outliers, matches, errors
brainproxy fuzz results 3 --matched
brainproxy fuzz stop 3

# Race conditions: N requests, last byte released together
brainproxy send req.http --race 20

# Compare two captures
brainproxy diff 12 15 --part response-body --mode words

# Passive scanning (49 rules ported from ZAP) runs automatically on proxy and send traffic
brainproxy findings list                          # grouped by alert type, highest risk first
brainproxy findings list --risk medium --all      # one row per instance
brainproxy findings show 7                        # description, solution, references, evidence
brainproxy findings mark 7 --state false-positive --note "test cookie"
brainproxy scan rules                             # list rules; scan disable 10021 to switch one off
brainproxy scan passive --rescan                  # rescan all history

# Crawl, then actively scan (42 rules ported from ZAP); everything stays inside the engagement scope
brainproxy crawl https://app.example.com/ --background         # job id; brainproxy job wait ID
brainproxy scan active                                         # all crawled/proxied/sent endpoints
brainproxy scan active https://app.example.com/item?id=1 --strength high
brainproxy scan active --where "path LIKE '/api/%'" --rules 40018,40012 --background
brainproxy scan rules --active
brainproxy findings list --source active

# API import: one request per operation with example/typed values, sent in scope and recorded as
# history source 'import', which `scan active` attacks by default. DELETE and GraphQL mutations
# only with --include-destructive; --dry-run lists the requests without sending them.
brainproxy import openapi https://app.example.com/openapi.json      # OpenAPI 3.x / Swagger 2.0, JSON or YAML
brainproxy import openapi spec.yaml --base-url https://staging.example.com -H 'Authorization: Bearer ...'
brainproxy import postman collection.json --var baseUrl=https://app.example.com
brainproxy import graphql https://app.example.com/graphql           # introspection; or --schema result.json
brainproxy scan active --where "source = 'import'" --auth api

# Authenticated testing: a login profile, then --auth NAME on send, fuzz, crawl, scan active, proxy start.
# Cookies/tokens are applied to every request, rotated cookies are learned, and a 401, a redirect to the
# login path, or --logged-out triggers one automatic re-login and a retry.
export APP_PW='...'                                # read at each login, never stored
brainproxy auth add app --login-url https://app.example.com/login \
    --login-body 'user={{username}}&pass={{password}}&csrf={{csrf}}' --username alice --password-env APP_PW \
    --csrf-url https://app.example.com/login --csrf-regex 'name="csrf" value="([^"]+)"' \
    --logged-in 'Sign out' --check-url https://app.example.com/account
brainproxy auth add api --login-url https://app.example.com/api/login \
    --login-body '{"username":"{{username}}","password":"{{password}}"}' --username alice --password-env APP_PW \
    --token-regex '"token":"([^"]+)"' --token-header 'Authorization: Bearer {{token}}'
brainproxy auth add key -H 'X-Api-Key: ...'       # static headers only
brainproxy auth login app                         # verify; failures list the history ids to inspect
brainproxy crawl https://app.example.com/ --auth app
brainproxy scan active --auth app --background
brainproxy auth status app                        # live check against --check-url
brainproxy auth headers app --raw                 # Cookie/Authorization lines for sqlmap, ffuf, ...

# Reports: findings grouped by alert type with description, solution, references, and the
# request/response from history as evidence. False positives are left out by default.
brainproxy report html -o report.html             # self-contained, no external assets
brainproxy report sarif -o brainproxy.sarif       # SARIF 2.1.0 (GitHub code scanning, DefectDojo, ...)
brainproxy report markdown --risk medium --confidence medium -o report.md
brainproxy report json --source active --limit 100 --max-evidence 2048

# Out-of-band callbacks (Collaborator-like) for blind issues. While the listener runs, Log4Shell
# (40043), XXE (90023), and blind SSTI (90036, --strength high|insane) send callback payloads and the
# scan waits --oob-wait seconds (default 5) for interactions. Behind NAT, pass the address targets
# can reach (--public-host/--public-port); for DNS callbacks delegate a domain to the runner.
brainproxy oob start                                # TCP 0.0.0.0:8880 (HTTP, LDAP, TLS ClientHello)
brainproxy oob start --listen 0.0.0.0:80 --dns-listen 0.0.0.0:53 --domain oob.example.com --public-ip 203.0.113.5
brainproxy scan active --rules 40043,90023
brainproxy oob payload --note 'ssrf in ?url=' --target https://app.example.com   # for manual tests
brainproxy oob poll --token bp... --wait 30         # interactions; also raises late scan callbacks
brainproxy oob stop

# Declarative checks: Nuclei HTTP templates (pinned to a commit) and your own YAML checks in
# <home>/checks/local, run by the active scanner inside the scope (see docs/CHECKS.md)
brainproxy checks update                             # or --from DIR with a nuclei-templates checkout
brainproxy checks list nuclei --tags exposure --severity medium
brainproxy scan active https://app.example.com/ --checks nuclei --check-tags exposure,misconfig
brainproxy checks validate my-check.yaml             # loads, or why not
brainproxy scan data update                          # newer ZAP pattern lists (error messages, hidden files)

# Triage state
brainproxy history tag 12 --add idor-candidate
brainproxy history note 12 "user id in path, try other ids"
brainproxy history show 12 --part request --raw > req.http    # edit, then send again

# Decoder: chains apply left to right
brainproxy encode url,base64 'a b'
brainproxy decode jwt eyJhbGciOi...
```

## LLM conventions

- No interactive prompts. Every option is a flag, env var (`BRAINPROXY_PROJECT`,
  `BRAINPROXY_FORMAT`), or file.
- When stdout isn't a terminal, every command prints one JSON envelope:
  `{"ok":true,"command":...,"data":...}` or `{"ok":false,"command":...,"error":{"kind","message"}}`.
- Exit codes: `0` success, `1` internal/storage, `2` invalid input or usage, `3` network,
  `4` not found, `6` out of scope.
- `brainproxy capabilities` describes the whole CLI as JSON. `brainproxy capabilities send`
  describes one command.
- Output is bounded: `--max-body`, `--limit`, and `--max-cell`, with `truncated` flags.
- Long-running work runs in the background: `proxy start` returns as soon as the proxy is
  listening. Settings (scope, rules, intercept) live in the project DB and apply to a running
  proxy within a second.
- If `NO_PROXY` covers your target (often `localhost`), pass `--noproxy ''` to curl.

## Status

- **Phase 0 (done):** raw HTTP/1.x client, `send`, the SQLite capture DB with `query` and
  `schema`, `history`, codecs, `capabilities`, and a static Linux build.
- **Phase 1 (done):** intercepting proxy (HTTP/1.x, CONNECT, TLS interception with a
  per-install CA, WebSocket pass-through), scope, match-and-replace rules, and an
  agent-driven intercept queue.
- **Phase 2 (done):** fuzzer with sniper, battering-ram, pitchfork, and cluster-bomb modes,
  payload sources and processing, grep/extract, outlier summary, background runs;
  race-condition sending (last-byte sync); diff.
- **Phase 3 (done):** passive scanner with 49 rules ported from ZAP (see
  [docs/PASSIVE_RULES.md](docs/PASSIVE_RULES.md)), de-duplicated findings, triage.
- **Phase 4 (done):** crawler, background jobs, immutable engagement scope enforced on
  every connection, active scanner with 43 rules ported from ZAP (see
  [docs/ACTIVE_RULES.md](docs/ACTIVE_RULES.md)), ZAP drift detection
  ([docs/RULE_UPDATES.md](docs/RULE_UPDATES.md)).
- **Phase 5 (in progress):** authenticated testing is done: login profiles (form, JSON,
  raw request template, CSRF prefetch, bearer tokens, static headers) and `--auth` on send,
  race, fuzz, crawl, active scan, and the proxy, with automatic re-login. Reports in JSON,
  Markdown, self-contained HTML, and SARIF 2.1.0. API import from OpenAPI/Swagger,
  Postman, and GraphQL introspection. Out-of-band callback listener (HTTP, LDAP, TLS, DNS)
  with Log4Shell, XXE, and blind SSTI callback checks (see [docs/OOB.md](docs/OOB.md)).
  Rule updates without a release: `scan data update` for ZAP's pattern lists and
  declarative checks in the Nuclei HTTP template format (`checks update`, `scan active
  --checks`; see [docs/CHECKS.md](docs/CHECKS.md) and [docs/RULE_UPDATES.md](docs/RULE_UPDATES.md)).
- **Next:** remaining ZAP rules, performance (connection pooling, HTTP/2), MCP server.

## License

Apache 2.0.
