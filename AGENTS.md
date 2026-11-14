# AGENTS.md

Notes for coding agents working on brainproxy. Read this before changing code. The user-facing
docs are [README.md](README.md) and [docs/](docs/); this file is about working on the code.

## What this is

brainproxy is a web security testing workbench: an intercepting proxy, Replay, fuzzer, race
tester, crawler, passive and active scanner, access-control tester and report builder. One
Rust CLI does all of it. The desktop app and the MCP server are thin layers over that CLI.

| Path | What it holds |
| --- | --- |
| `crates/core` (`brainproxy-core`) | The engine: proxy, HTTP/1.1, HTTP/2 and HTTP/3 clients, scope guard, SQLite project store, scanners, auth, fuzz, race, OOB, importers, reports. |
| `crates/cli` (`brainproxy`) | The CLI (`main.rs` holds the clap tree, `*_cmd.rs` the commands) and the MCP server (`mcp.rs`). |
| `gui/` | Desktop app: React 19 + TypeScript frontend (`gui/src`), Tauri 2 shell (`gui/src-tauri`). |
| `docs/` | Manual (`MANUAL.md`), MCP (`MCP.md`), GUI (`GUI.md`), rule and check references. |
| `feed/` | The signed rule and check feed that `checks` and `scan data` download. |
| `scripts/` | `check.sh` (the pre-commit check), ZAP rule drift tools, wordlist and feed helpers. |

## How the layers fit

- **Everything goes through the CLI.** The GUI runs `brainproxy --format json --project <file> <args>`
  for every engine call (`gui/src/api.ts`: through the Tauri `cli` command, or the Vite dev bridge
  under `npm run dev`). The MCP server runs the same binary as a child process for each tool call.
  To add a feature, add a CLI command or flag first. The GUI and MCP then call it.
- **JSON envelope.** With `--format json` every command prints `{"ok":true,"command":...,"data":...}`
  or `{"ok":false,"error":{"kind":...,"message":...}}`, with the exit codes that `brainproxy capabilities`
  lists. The GUI and agents parse these, so treat the field names in `data` as API.
- **MCP tools come from clap.** `mcp.rs` makes one tool per leaf command. Its arguments are the
  command's flags and positionals, under their clap names.
  - Renaming a clap argument breaks agents. To let a scalar argument take a list, keep its name,
    make it a `Vec`, and add it to `WAS_ONE_VALUE` in `mcp.rs` so its schema still accepts a scalar.
  - Every leaf command needs an entry in `HINTS` (read-only, destructive, idempotent and open-world
    annotations). A unit test fails until it has one.
  - Commands an agent must not run go in `EXCLUDED`, and the command itself also refuses under a
    tool call (`mcp::in_tool_call()`). Exclusion alone is not enough.
  - Under a tool call, secrets come only from `BRAINPROXY_SECRET_*` variables (`check_secret_env`).
- **Scope is enforced in core.** The engagement scope is set once (`engagement start`), and
  `crates/core/src/guard.rs` checks every outbound connection against it. Never add a path that
  sends traffic without going through the guard.
- **Provenance.** `BRAINPROXY_CLIENT` (`gui`, `cli`, or `mcp` under a tool call) marks who
  recorded each row (`crates/core/src/provenance.rs`). Keep it set on new records.
- **Project schema.** `SCHEMA_VERSION` in `crates/core/src/store.rs` must be bumped with a
  migration whenever tables change. A build refuses a project from a newer schema. Don't change
  the schema unless the task needs it.

## Build and check

```bash
scripts/check.sh            # what CI runs: cargo fmt --check, clippy -D warnings, cargo test, ZAP drift test
cargo build -p brainproxy   # the CLI (target/debug/brainproxy); the GUI's dev bridge runs this binary
cargo test -p brainproxy --test mcp            # one integration suite (crates/cli/tests/*.rs)
cargo test -p brainproxy-core <filter>         # core unit tests
```

```bash
cd gui && npm ci
npm run build               # tsc --noEmit, then vite build
npm test                    # node --test 'src/**/*.test.ts' (Node 23.6+ with type stripping)
npm run dev                 # the UI in a browser; open the #bridge=<token> URL it prints
```

- `scripts/check.sh` takes about 10 to 15 minutes. CI also runs on Windows and macOS, so keep
  paths, line endings and process handling portable.
- `crates/cli/tests/browser_crawl.rs` and `login_replay.rs` start Chromium. They fail inside
  restrictive sandboxes (`socket() failed: Operation not permitted`) and under a very long
  `TMPDIR` ("Socket path too long"). Cargo stops at the first failing test binary, so a failure
  there hides every suite after it.
- GUI tests run under Node's type stripping, so use only erasable TypeScript: no `enum`,
  `namespace` or constructor parameter properties. Check with
  `gui/node_modules/.bin/tsc --noEmit -p gui --erasableSyntaxOnly`. If your Node can't strip types,
  `bun test ./gui/src` runs the same tests, but that alone doesn't prove CI will pass.
- Opening a project in the app starts its proxy (port 8080 by default) unless Settings turns that
  off. Stop it afterwards with `brainproxy --project <file> proxy stop`.

## Conventions

- **Rust:** `rustfmt.toml` sets a 120-column width. Clippy must be clean with `-D warnings` on
  every target; extra lints are set once in `[workspace.lints]` in the root `Cargo.toml`.
  - Errors are `brainproxy_core::Error`, whose kind becomes the envelope's `error.kind` and
    picks the exit code. Return the kind that says what went wrong; `Error::from_kind`
    rebuilds a child process's error from its envelope.
  - No `unwrap`/`expect` on anything from the network, a file, the user or an agent. `expect`
    is for invariants only (a lock, a static regex, state checked just before), with a message
    that says why it holds.
  - Text from outside is cut on char boundaries (`str::get`, `is_char_boundary`), never at a
    fixed byte offset. Check a value's range before an `as` cast that could truncate it, and
    turn user-given seconds into a `Duration` through the checked helpers in
    `crates/cli/src/request_args.rs`, never `Duration::from_secs_f64` directly.
  - Async code doesn't hold a `std::sync::Mutex` guard across `.await` and doesn't block (file
    or SQLite work goes on its own thread or `spawn_blocking`). A future clippy reports as large
    (`clippy::large_futures`) is boxed with `Box::pin` where it's awaited.
  - Every `unsafe` block has a `// SAFETY:` comment saying why it is sound
    (`clippy::undocumented_unsafe_blocks` is on). Remember the Windows and macOS code, which
    clippy only checks on those systems.
- **GUI:** keep logic in plain `.ts` modules with a `*.test.ts` beside them, and keep components
  (`.tsx`) thin. Actions that the command palette, shortcuts and Settings › Keyboard list are
  registered with `useActions`/`define` (`gui/src/ui/actions.ts`). Modal dialogs set
  `aria-modal="true"`, which is what pauses global shortcuts.
- **Comments** say why, not what: invariants, protocol quirks, security reasons, and anything a
  reader would get wrong. Don't add comments that restate the code. Doc comments (`///`, `/** */`)
  on items are fine when they say more than the name does. A `ponytail:` comment marks a known,
  accepted limitation (what it gives up and when to revisit it); keep it with the code it
  describes. In the CLI, `///` on clap arguments and subcommands is the `--help` text and the
  MCP tool and argument descriptions, so treat it as user-facing text.
- **Docs move with the code.** A new or changed command, flag or output field goes in
  `docs/MANUAL.md` (it also states the total command count, from `brainproxy capabilities`), MCP
  behaviour in `docs/MCP.md`, and app features in `docs/GUI.md`. GUI.md's layout table lists the
  CLI commands each view uses.
- **Tests:** CLI behaviour is tested end to end in `crates/cli/tests/*.rs`, which run the
  binary against local servers. Engine logic has unit tests beside it. A bug fix comes with a
  test that fails without it.
- **Commits:** subject is `Area: what changed, in plain words`, for example
  `GUI: the palette's recent projects are the ones Welcome would open` or
  `HTTP/3: a quiet connection is pinged so it isn't closed as idle`. Areas include GUI, Docs,
  Core, Findings, Replay, Request rules and Test.
- **Pull requests** go to `r4nd0mth1ngs/brainproxy`, base `main`.
- **Releases** bump the version in `Cargo.toml`, `gui/package.json`, `gui/src-tauri/Cargo.toml`
  and `gui/src-tauri/tauri.conf.json` (plus their lock files). A `v*` tag must match `Cargo.toml`.

## Safety

This is an offensive security tool. Tests talk only to local servers they start. Don't point
anything at hosts you don't control, and don't weaken the scope guard, the MCP exclusions, the
secret-variable rule or the dev bridge's token check to make something easier.
