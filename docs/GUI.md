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
  errors, and output are the CLI's, and anything the GUI can do an agent can do too.
- The shell (`src-tauri/src/main.rs`) has two commands: `cli(project, args, stdin, env)`,
  and `app_pid()`, the app's pid, which owns its temporary projects. `--project` is left
  out while no project is open (an empty `project`). The binary is `$BRAINPROXY_BIN`, else
  a `brainproxy` next to the app executable (bundle the sidecar there), else `brainproxy`
  on PATH.
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

"Temporary engagement" is the same form without the file step: it runs `project temp
--owner <app pid>`, then `engagement start` on that path (discarding it if that fails).
Temporary projects never go in Recent. The welcome screen runs `project sweep` on show,
which wipes temporary projects left by a crashed app and says whether new ones are
RAM-backed. While one is open the top bar shows a **temp** badge (click: Save as…), and
the sidebar has *Save as…*: `project save --output FILE`, then `project discard` and open
FILE. Switching project or closing the window asks first (an in-app dialog, `ui/Confirm.tsx`:
native ones differ per OS), then runs `project discard`.

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
| Capture | Proxy | Intercept (held queue, edit, forward/drop), Traffic (filters, request/response) | `intercept *`, `history list/show/note/tag` |
| Attack | Replay | Tabs, raw request editor, response, back/forward through sends; auto URL-encode on send (request line and form bodies: only characters invalid in a URL, structure kept); ⌘U / ⌘⇧U encode or decode the selection in any editor | `send --target T -` |
| Attack | Fuzzer | §positions§ (manual or auto), attack types, built-in lists (`wordlist:NAME`), lists/numbers/files with processing, grep/extract/status match, Discover content preset; live results with baseline and outliers; past runs | `wordlists list/show`, `fuzz run --background`, `fuzz status/results/list/stop` |
| Attack | Scans | Tasks (live progress, stop), new scan (crawl and audit, audit everything recorded, or specific URLs; downloaded Nuclei templates included by default at high severity and up, adjustable) or crawl, passive and active rules | `job *`, `scan active/passive/rules/enable/disable/sources`, `crawl` |
| Results | Findings | Issues grouped by type and risk, detail, evidence, triage | `findings list/show/mark` |
| Results | Callbacks | OOB listener start/stop, payload generator, interactions with raw detail | `oob start/stop/status/payload/poll` |
| Tools | Codec | Stacked encode/decode/hash steps | `encode`, `decode`, `hash` |
| Tools | Diff | Items sent from other tools or pasted; line/word/byte diff side by side or unified | client-side diff; `diff A B` for two history entries |
| | Settings | Auth profiles, match & replace, intercept options, proxy (status, start, setup for browsers/curl/shell), TLS/CA, rule data, project, open source licenses (credits and NOTICE) | `auth *`, `rules *`, `intercept *`, `proxy status/start`, `ca init/export`, `checks *`, `scan data *`, `project info`, `project save` (temporary projects), `engagement show` |

### Guided scan

Until a project has an active scan, the Overview opens with a four-step guided scan for
people who don't work with HTTP: the website (prefilled only from recorded traffic, and
checked with one GET before moving on, with a plain explanation if it doesn't answer or is
out of scope), login (none, or an existing auth profile, with a pointer to Settings), depth
(Quick: medium strength, crawl depth 3, 150 pages; Standard: high, 5, 500; Thorough:
insane, 8, 1500; Standard and Thorough also attack cookies (`--cookies`); once the Nuclei templates are downloaded, Standard adds those of high
severity and Thorough those of medium and above, both plus the end-of-life checks via
`--check-include-tags eol`), speed (Gentle `-c 3`, Normal, Fast `-c 30`),
and a review with a warning about real
attack traffic. It runs
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
| `brainproxy-gui-macos-arm64.dmg` | macOS, Apple silicon |
| `brainproxy-gui-linux-x86_64.deb`, `.AppImage` | Linux x86_64 (needs WebKitGTK 4.1) |

Each has a `.sha256`. The macOS app is not signed or notarized: after copying it to
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
- `auth add` replaces the whole profile, so editing one with a stored password needs it
  typed again; `--login-request` only takes a file.
- A literal auth password goes to `auth add` in `BRAINPROXY_SECRET_PASSWORD`, not argv. The
  login body is a template (`{{password}}` is filled at login), so it stays an argument.
- The native window was not screenshot-tested; the browser build was (`npm run dev`).
