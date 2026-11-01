# GUI

`gui/` is an optional desktop app (Tauri 2 + React + TypeScript) on top of the same engine.
The CLI stays the primary interface; the GUI is a workbench for a human working next to it
(or next to an agent driving the CLI or MCP server on the same project file).

## Architecture

```
React UI (gui/src)  --invoke("cli")-->  Tauri shell (gui/src-tauri)  --spawn-->  brainproxy --format json --project P ...
                    \--fetch /api/cli--> Vite dev bridge (npm run dev only) --/
```

- **Every engine call is a CLI invocation** returning the JSON envelope, exactly like
  `mcp serve` runs tools. The GUI has no second code path into the engine: scope checks,
  errors, and output are the CLI's, and anything the GUI can do an agent can do too. The
  one exception is temporary engagements (below): the shell itself creates and deletes
  their folders, because nothing reachable from the CLI or MCP may make a project that
  deletes itself.
- The shell (`src-tauri/src/main.rs`) runs the CLI with `cli(project, args, stdin, env)`.
  The binary is `$BRAINPROXY_BIN`, else a `brainproxy` next to the app executable (bundle
  the sidecar there), else `brainproxy` on PATH.
  - `stdin` is bytes (a number array, `Vec<u8>`), written to the child unchanged; `api.ts`
    sends text as UTF-8. Bodies the CLI returns as base64 are shown one char per byte
    (`bodyText`), and `textBytes(text, true)` turns them back into the same bytes, so
    Replay, intercept forwarding, the Fuzzer, the Decoder, Hex, and byte counts keep binary
    bodies exact.
  - `env` adds variables to the child, only names starting with `BRAINPROXY_SECRET_`, for
    secrets that shouldn't be in argv (visible in `ps`).
- Value flags are passed as `--flag=value` and free-text positionals after `--`, so values
  starting with `-` aren't read as flags.
- Messages the GUI edits or resends are loaded with `--max-body=2000000`. One larger than
  that arrives truncated; the GUI then refuses to send it to Replay or the Fuzzer and shows
  an intercepted one read-only (forward or drop it as is).
- `npm run dev` also serves the UI to a plain browser: `vite.config.ts` adds `POST /api/cli`
  (dev server only; localhost Host and an `X-Brainproxy: 1` header required). It runs
  `../target/debug/brainproxy` unless `BRAINPROXY_BIN` is set.
- Live data is polled (`ui/usePoll.ts`, paused while the window is hidden): history every
  1.5 s with `history list --after <last id>`, proxy status every 2 s, the intercept queue
  every second while its tab is open. The project is SQLite in WAL mode, so the GUI, the
  proxy, background jobs, and an agent share it safely.
- The GUI is built on its own (`gui/src-tauri` is its own Cargo workspace, not a member
  of the root one), so the CLI build and CI need no webview or Node.

## Welcome screen

"New engagement" creates a project and its write-once scope in one step: name, project
file location, targets (one per line; pasted URLs are reduced to host[:port]; each line is
checked and shown as a chip), optional exclusions, an explicit note that the scope can't
change later, and an "I have permission to test these targets" check. It runs
`engagement start` on the new file and opens it. Recent and existing projects are below.

### Temporary engagements

"Temporary engagement" (desktop app only) is the same form without the file step. The
project goes in a RAM-backed folder where the OS has one and is deleted when the user
discards it. Only the shell (`src-tauri/src/temp.rs`) creates or deletes these folders: the
CLI has no command for it, so a project a script or agent starts always keeps its file.

- **Where:** `$BRAINPROXY_TEMP_DIR`, else on Linux whichever of `$XDG_RUNTIME_DIR` and
  `/dev/shm` (tmpfs, not read-only) has more room, else the OS temp folder, which is on disk
  (the UI says "in the temp folder" then). Inside it, a per-user `brainproxy-temp-<uid>`
  folder (`0700`; refused if someone else owns it, others can access it, or it is a symlink),
  and one folder per project: `temp.bpdb`, the marker `temp.json` (when it was made, by
  which pid), and `owner.lock`. A project counts as temporary only by this layout, and only
  such folders are ever deleted.
- **Creating:** `temp_create` makes the folder and locks `owner.lock` for this app; the UI
  then runs `project init` and `engagement start` on `<folder>/temp.bpdb` like any project
  (discarding it if the scope is refused). Temporary projects never go in Recent.
- **While open:** the top bar shows a `temp · in memory` / `temp · on disk` badge (click:
  Save as…), and the sidebar and Settings › Project have *Save as…*: `project save --output
  FILE` (refused inside a temp folder, `temp_is_inside`), then discard, then open FILE.
- **Discarding:** Switch project or closing the window asks first (an in-app dialog,
  `ui/Confirm.tsx`, since native ones differ per OS). `temp_discard` then runs `project stop`
  (proxy, OOB listener, jobs and fuzz runs; it deletes nothing) and, once everything has
  stopped, deletes the folder. If something won't stop, the folder is kept.
- **Leftovers:** the OS releases `owner.lock` when the app exits or crashes, so a folder
  whose lock can be taken belongs to no running app. The welcome screen lists those
  (`temp_leftovers`, which keeps them locked so a second window doesn't offer them too):
  "Unsaved temporary engagement … from <date>" with *Save as…* (save, delete the temporary
  one, open the copy) and *Delete* (asks first). Nothing is deleted unless the user chooses.

## Layout

Top bar: brainproxy, the project and its engagement scope chips; on the right the intercept
and proxy pills (the proxy pill starts/stops `proxy start` on 127.0.0.1:8080) and the theme
toggle, and **Open browser**: a menu of the installed browsers (`browser list`) that starts
the proxy if needed and runs `browser open`, a separate browser instance in a per-project
profile (`<project>.browsers/<id>`) going through the proxy, loopback included; Chromium-based
browsers trust the brainproxy CA in that profile only (by its key, via
`--ignore-certificate-errors-spki-list`), Firefox gets the proxy prefs and a one-time CA import
note. Traffic hides requests refused as out of scope by default (mostly browser background
calls), and so does the Site map ("In scope only"); the proxy never holds an out-of-scope
request for interception. Tools sit in a grouped, collapsible sidebar, with the clickable
AssertiveInfosec logo above Collapse and on the welcome screen (just the mark when collapsed; links open in the system browser
via tauri-plugin-opener, limited to assertivesolutions.io); tools with several parts have sub-tabs.
Views stay mounted when hidden, so state (selection, edits, Replay tabs) survives switching.

| Group | Tool | Parts | CLI used |
| --- | --- | --- | --- |
| Recon | Overview | Guided scan (below), a new-version card when brainproxy has an update (checked daily unless turned off in Settings › Rules & data; download, open installer), rules and checks card (ZAP rule data and Nuclei templates: status and one-click download; at the top while either is missing), issue counts, recent findings, tasks, history stats | `job list`, `query`, `scan active --crawl`, `scan data status/update`, `checks status/update --background`, `update check/download --kind gui` |
| Recon | Site map | Host → path tree with issue dots (crawl/scan/replay a node), engagement and proxy scope | `query`, `history show`, `crawl`, `scan active`, `engagement *`, `scope *` |
| Capture | Proxy | Intercept (held queue incl. WebSocket messages, edit, forward/drop), Traffic (filters, request/response), WebSockets (connections, messages both ways, payload viewer, send to Replay) | `intercept *`, `history list/show/note/tag`, `ws list/messages` |
| Attack | Replay | Tabs, raw request editor, response, back/forward through sends; auto URL-encode on send (request line and form bodies: only characters invalid in a URL, structure kept); ⌘U / ⌘⇧U encode or decode the selection in any editor. WebSocket tabs (**+ WS**): handshake editor, messages separated by `---`, listen time and stop regex, the conversation with a payload viewer | `send --target T -`, `ws send --target T --input-json` (handshake and messages on stdin) |
| Attack | Fuzzer | §positions§ (manual or auto), attack types, built-in lists (`wordlist:NAME`), lists/numbers/files with processing, grep/extract/status match, Discover content preset; live results with baseline and outliers; past runs | `wordlists list/show`, `fuzz run --background`, `fuzz status/results/list/stop` |
| Attack | Scans | Tasks (live progress, stop), new scan (crawl and audit, audit everything recorded, or specific URLs; downloaded Nuclei templates included by default at high severity and up, adjustable) or crawl, either with *Run JavaScript (browser)* for single-page apps (greyed out without a Chromium-based browser), passive and active rules | `job *`, `scan active/passive/rules/enable/disable/sources`, `crawl`, `crawl --browser`, `scan active --crawl --browser`, `browser list` |
| Attack | Access | Access control across users: start a run (identities from the auth profiles plus an anonymous toggle, an optional owner, and all credentialed history, one site, a tag, or a SQL condition), or restart the proxy with live testing; a run picker; the run as a grid of requests by identities, cells coloured by verdict (bypass high/medium/low, public, different, inconclusive, enforced, error) with skipped rows marked, filterable by verdict; click a cell to see the owner's baseline and that identity's response (or requests) side by side, or open both in Diff | `auth list`, `authz run --background`, `authz list/matrix/results`, `job status/stop`, `history show`, `proxy status/stop/start --authz` |
| Results | Findings | Issues grouped by type and risk, detail, evidence, triage | `findings list/show/mark` |
| Results | Callbacks | OOB listener start/stop, payload generator, interactions with raw detail | `oob start/stop/status/payload/poll` |
| Tools | Codec | Stacked encode/decode/hash steps | `encode`, `decode`, `hash` |
| Tools | Diff | Items sent from other tools or pasted; line/word/byte diff side by side or unified | client-side diff; `diff A B` for two history entries |
| | Settings | Auth profiles (including platform auth: Basic, Digest, NTLM; with macros built from Traffic and session rules), match & replace, intercept options, proxy (status, start, setup for browsers/curl/shell), connections (upstream proxies, host overrides, client certificates, TLS pass-through, check a target's route), TLS/CA, rule data, project, open source licenses (credits and NOTICE) | `auth *` (incl. `auth macro add/run/remove`, `auth rule add/remove`, `query` for the Traffic picker), `rules *`, `intercept *`, `proxy status/start`, `connection *`, `ca init/export`, `checks *`, `scan data *`, `project info`, `project save` (temporary engagements), `engagement show` |

### Guided scan

Until a project has an active scan, the Overview opens with a four-step guided scan for
people who don't work with HTTP: the website (prefilled only from recorded traffic, and
checked with one GET before moving on, with a plain explanation if it doesn't answer or is
out of scope), login (none, or an existing auth profile, with a pointer to Settings), depth
(Quick: medium strength, crawl depth 3, 150 pages; Standard: high, 5, 500; Thorough:
insane, 8, 1500; Standard and Thorough also attack cookies (`--cookies`) and URL path segments (`--url-path`); once the Nuclei templates are downloaded, Standard adds those of high
severity and Thorough those of medium and above, both plus the end-of-life checks via
`--check-include-tags eol`; Thorough also crawls with JavaScript in a hidden browser
(`--browser`) when `browser list` finds a Chromium-based one, and says so on its card and
in the review), speed (Gentle `-c 3`, Normal, Fast `-c 30`),
and a review with warnings about replayed POST requests, attacked page addresses (at
Standard and Thorough) and real attack traffic. It runs
`scan active URL --crawl ... --background`, shows progress as "exploring" then "testing",
and ends with counts per risk level explained in plain words and a link to Findings. "I'll
set it up myself" hides it for that project.

Cross-tool actions go through `store.tsx`: `sendToRepeater`, `sendToFuzzer`,
`sendToComparer` (right-click a history row, or buttons in Intercept and Findings).

## Look

The Assertive Infosec design language (from their website's design tokens): a magenta-violet
accent and gradient (`oklch(0.58 0.24 320)` to `oklch(0.6 0.15 300)`), violet-tinted
surfaces, Geist and Geist Mono (bundled from @fontsource, OFL), rounded controls; severity
colours only for findings. Dark and light themes are CSS variables in `styles.css`. No UI framework: the
table (`ui/DataTable.tsx`, virtualized, sortable, resizable columns, keyboard), split
panes (`ui/Split.tsx`, sizes remembered), message view (`ui/HttpView.tsx`, Raw with
highlighting and an overlay editor, Pretty for JSON/forms, Hex, search), and context menu
(`ui/Menu.tsx`) are small local components. Responses also get Render (`ui/render.ts`): HTML
in a `sandbox=""` srcdoc iframe with an injected `default-src 'none'` CSP (no scripts, forms
or network requests; `data:` images and inline styles only), images from the body bytes,
anything above 5 MB only after a click.

## Develop

```sh
cargo build                      # the CLI the GUI runs
cd gui && npm install
npm run dev                      # UI in a browser at http://127.0.0.1:5173 (dev bridge)
cargo tauri dev                  # desktop window (from gui/)
npm run check                    # TypeScript
npm test                         # unit tests (node --test, e.g. ui/urlencode.test.ts)
```

## Release

CI (`.github/workflows/ci.yml`) type-checks and builds the frontend on every push
(`gui-check`). On `v*` tags, and on manual runs (`workflow_dispatch`, artifacts only), the
`gui` job bundles the app with the CLI inside as a Tauri sidecar: it builds `brainproxy`
for the target, copies it to `gui/src-tauri/binaries/brainproxy-<triple>`, and runs
`tauri build --config '{"bundle":{"externalBin":["binaries/brainproxy"]}}'` (the sidecar
is only configured there, so local dev needs no binary in place). Tauri installs it next
to the app executable as `brainproxy`, where the shell looks first. Assets:

| Asset | Platform |
| --- | --- |
| `brainproxy-gui-<version>-macos-arm64.dmg` | macOS, Apple silicon |
| `brainproxy-gui-<version>-linux-x86_64.deb`, `.AppImage` | Linux x86_64 (needs WebKitGTK 4.1) |
| `brainproxy-gui-<version>-windows-x86_64-setup.exe`, `.msi` | Windows 10 and 11, x86_64 |

`<version>` is Cargo.toml's (`brainproxy-gui-0.3.9-macos-arm64.dmg`). The updater looks for
the tag's version in the names, so the `check` job fails a tag that doesn't match Cargo.toml. Each asset has a `.sha256`, and
the `checksums` job adds one `SHA256SUMS` for the whole release. Downloads keep the asset
name, so the opener scope `$DOWNLOAD/brainproxy-gui-*` covers them. The macOS app is not signed or notarized: after copying it to
Applications, open it once, then choose System Settings → Privacy & Security → Open Anyway, or run
`xattr -dr com.apple.quarantine /Applications/brainproxy.app`.

The same bundle locally (macOS):

```sh
T=aarch64-apple-darwin
cargo build --release --target $T -p brainproxy
mkdir -p gui/src-tauri/binaries && cp target/$T/release/brainproxy gui/src-tauri/binaries/brainproxy-$T
cd gui && npx tauri build --target $T --config '{"bundle":{"externalBin":["binaries/brainproxy"]}}'
```

## Known gaps

- The Fuzzer sends the raw request on stdin (`fuzz run --background --target=... -`); the
  background run gets it through a file next to the project that it deletes once read. An
  empty `Host:` is filled from the target. List payloads go inline as `list:a,b,...`.
- `fuzz results --after IDX` pages by attack index, which can skip rows finished out of
  order; the GUI refetches everything when a run ends.
- Changing intercept filters needs `intercept enable` (there is no "set" that keeps it
  off), so Settings briefly turns intercept on and off again when it is off.
- Replay's WebSocket tabs send text messages only (binary: `ws send --binary` or `--resend ID`
  from the CLI), and show one run at a time (each run is in Proxy › WebSockets).
- Proxy › WebSockets reloads the newest 5,000 connections every 2 s (`ws list --newest`);
  older ones are reachable with `ws list` or `query`. Messages are fetched incrementally.
  Only text messages can be sent to Replay; Copy payload refuses messages over 2 MB.
- `auth add` replaces the whole profile, so editing one with a stored password needs it
  typed again; `--login-request` only takes a file.
- A literal auth password goes to `auth add` in `BRAINPROXY_SECRET_PASSWORD`, not argv. The
  login body is a template (`{{password}}` is filled at login), so it stays an argument.
- Macros are built from Traffic entries only (the 500 most recent); a step from a raw
  request file, or a step whose request should be edited (to add `{{name}}`), needs
  `auth macro add` on the command line. A macro or rule is replaced or removed, not edited
  in place. *New macro profile* starts a profile with no login from its first macro, since
  `auth add` refuses a profile with nothing to do.
- The native window was not screenshot-tested; the browser build was (`npm run dev`).
