# Braintruder

A fast, AI-first web security testing toolkit written in Rust. It takes its features from
Burp Suite (rebuilt clean-room) and OWASP ZAP (ported under Apache 2.0). Everything is a
non-interactive CLI command with structured JSON output, so AI agents and scripts can drive
it end to end. A GUI comes later on the same engine.

Only use it against systems you are authorized to test.

See [docs/RESEARCH.md](docs/RESEARCH.md) for the feature research, design, and roadmap.

## Build

```sh
cargo build --release
./target/release/braintruder capabilities
```

## Usage

```sh
# Send a request built from a URL (like curl). It is recorded in braintruder.btdb.
braintruder send --url https://example.test/api?id=1 -X POST -H 'Content-Type: application/json' -d '{"a":1}'

# Send a raw request file (Repeater). Unix line endings and Content-Length are fixed up
# unless you pass --verbatim. The target defaults to the Host header over https.
braintruder send request.http
cat request.http | braintruder send --target http://127.0.0.1:8080

# History
braintruder history list --status 500 --contains 'stack trace'
braintruder history show 3
braintruder history show 3 --part request --raw | braintruder send --target https://staging.example.test

# Decoder: chains apply left to right
braintruder encode url,base64 'a b'
braintruder decode jwt eyJhbGciOi...
braintruder hash sha256 - < file.bin
```

## AI-first conventions

- No interactive prompts. Every option is a flag, env var (`BRAINTRUDER_PROJECT`,
  `BRAINTRUDER_FORMAT`), or file.
- When stdout isn't a terminal, every command prints one JSON envelope:
  `{"ok":true,"command":...,"data":...}` or `{"ok":false,"command":...,"error":{"kind","message"}}`.
- Exit codes: `0` success, `1` internal/storage, `2` invalid input or usage, `3` network,
  `4` not found.
- `braintruder capabilities` describes every command, flag, default, and exit code as JSON.

## Status

Phase 0 is done: the raw HTTP/1.x client (HTTP and HTTPS), `send`, `history`, codecs,
`capabilities`, and the project store. Next is Phase 1: the MITM proxy, CA, and
agent-driven intercept queue.

## License

Apache 2.0 (proposed).
