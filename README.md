# brainproxy

A fast, AI-first web security testing toolkit written in Rust. It takes its features from
Burp Suite (rebuilt clean-room) and OWASP ZAP (ported under Apache 2.0). Its main operator
is an LLM: **Braintruder** drives it through a Kali runner. Every feature is a
non-interactive CLI command with structured JSON output. A GUI comes later on the same engine.

Only use it against systems you are authorized to test.

See [docs/RESEARCH.md](docs/RESEARCH.md) for the feature research, design, and roadmap.

## Install on Kali (CLI only)

brainproxy builds into one static binary with no runtime dependencies.

```sh
# Build once (on Kali or any Linux box with Rust installed)
sudo apt install -y musl-tools
rustup target add x86_64-unknown-linux-musl
make static                    # -> target/x86_64-unknown-linux-musl/release/brainproxy
sudo make install              # -> /usr/local/bin/brainproxy
```

Or copy the `brainproxy-linux-x86_64` artifact from CI (or a tagged release) onto the runner.

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
  `4` not found.
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
- **Next:** Phase 4, crawling and the active scanner.

## License

Apache 2.0.
