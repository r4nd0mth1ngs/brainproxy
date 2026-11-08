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
  - Every call also gets `BRAINPROXY_CLIENT=gui` (the Vite dev bridge sets it too), so what
    the CLI records, and what the proxy and jobs it starts record, is marked as the app's
    (origin `gui`). Traffic shows it in the **By** column (app, CLI, agent); for a proxy entry
    that is who started the proxy, and hovering it shows the client's address. An agent's
    `intercept forward` or `rules add` against the app's proxy is recorded in the entry's
    `edited_by` and the intercept's `resolved_by`, not in this column.
  - `call` names the call, so `cli_cancel(call)` can stop its process (`cancelCli` in
    `api.ts`); it then fails with kind `cancelled`. For a command that waits on the user,
    such as the browser sign-in. The process gets SIGTERM, so a request it already sent
    is recorded as cancelled, and SIGKILL if it is still running 3 s later. Windows has no
    SIGTERM: the process is killed at once, and a sent request keeps the row written before
    it went out. A process that exits in time answers with its own envelope, marked
    `cancelled: true` (a failure gets kind `cancelled`, with its own in `error.cli_kind`), so
    its message still names the history rows; the dev bridge does the same.
- Value flags are passed as `--flag=value` and free-text positionals after `--`, so values
  starting with `-` aren't read as flags.
- Messages the GUI edits or resends are loaded with `--max-body=2000000`. One larger than
  that arrives truncated; the GUI then refuses to send it to Replay or the Fuzzer and shows
  an intercepted one read-only (forward or drop it as is).
- `npm run dev` also serves the UI to a plain browser: `vite.config.ts` adds `POST /api/cli`
  and `POST /api/cli-cancel` (dev server only; cancelling sends SIGTERM, then SIGKILL after
  3 s). It runs `../target/debug/brainproxy` unless `BRAINPROXY_BIN` is set.
  - The bridge runs any command, with none of the MCP limits, so it answers only a localhost
    Host whose `X-Brainproxy` header is a random token made when the dev server starts. It is
    printed under the server's URLs (`brainproxy dev bridge: open http://127.0.0.1:5173/#bridge=...`);
    open that link. `api.ts` keeps the token for the tab (sessionStorage) and takes it off the
    address bar. The fragment never reaches a server, and no page or file the dev server serves
    holds the token, so an agent that can reach the port through `send` can't learn it.
  - Requests with brainproxy's own `User-Agent` (`brainproxy/...`) are refused as well.
- Live data is polled (`ui/usePoll.ts`, paused while the window is hidden): history every
  1.5 s with `history list --after <last id>` (with a contents search or a query on, the rows each poll
  adds are then searched with `history list --contains TEXT` or `--filter QUERY` `--after <searched up to>`, so a
  new row shows only once it is known to match; `views/trafficFilter.ts`), proxy status every 2 s, the intercept queue
  every second while its tab is open. Polls can overlap; an older one that answers after a
  newer one's answer is dropped, so a slow poll never puts back a stale state (a failed poll
  changes nothing, so an older answer still lands after it). The project is SQLite in WAL mode,
  so the GUI, the proxy, background jobs, and an agent share it safely.
- The app's proxy: every place that starts the proxy (opening a project, the pill, Open
  browser, Settings, Record a login, Access's live restart) goes through `views/proxyPort.ts`,
  which records the pid `proxy start` returned in the store's `proxy` control. Closing the
  project or the window stops the proxy with
  `proxy stop --pid`, which stops it only if that pid is still the one running here, so one a
  shell, an agent or another container started is left alone, even if it started a moment ago. Settings moves the proxy to another port, and Access's
  live restart adds live testing to it, with one `proxy restart`, which holds the project's
  proxy record from the stop to the start, so a `proxy start` from a shell or an agent fails
  instead of getting in between; if the new proxy doesn't come up, the CLI starts the old one
  again where it was. The control keeps the proxy the app's at its new pid (or the pid it went
  back to, from the error's `data`, not its wording) and marks the restart: Open browser,
  Record a login and Start proxy wait for it, and the pill and Access's live restart ask to try
  again. A failed restart reports where the proxy is from a fresh `proxy status`.
- Every start also uses the rest of Settings › Proxy (`views/proxyMode.ts`): who can connect
  (`--listen=127.0.0.1:PORT`, or `0.0.0.0:PORT` after a warning that anyone on the network can
  then use the proxy, with the project's auth profiles, session rules and platform auth),
  `--invisible`, and a `--redirect=ORIGIN` that `engagement check` must allow each time it is
  saved. The port is kept for every project, in the app; the rest in the project file
  (`proxy setup show/set`, one write that replaces the whole setup), so it goes with the file
  (Save as…, a copy) and a file made at the same path starts without it. MCP calls can't save
  every interface, invisible mode or a redirect. Access's live testing, starting a proxy that is off, uses it too.
  On a wildcard address the proxy pill says "open to the network", a project that starts its
  proxy that way when it opens says so in a toast, and Settings › Proxy warns and says other
  devices use this computer's LAN address on that port.
  A running proxy that differs is restarted with them on request with one `proxy restart`, like a
  port move, keeping
  its other options (and an address that already fits, such as `[::1]`).
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
  `ui/Confirm.tsx`, since native ones differ per OS; its `ask` takes typed answers such as a
  saved filter's name, because the macOS webview has no `window.prompt`). `temp_discard` then runs `project stop`
  (proxy, OOB listener, jobs and fuzz runs; it deletes nothing) and, once everything has
  stopped, deletes the folder. If something won't stop, the folder is kept.
- **Leftovers:** the OS releases `owner.lock` when the app exits or crashes, so a folder
  whose lock can be taken belongs to no running app. The welcome screen lists those
  (`temp_leftovers`, which keeps them locked so a second window doesn't offer them too):
  "Unsaved temporary engagement … from <date>" with *Save as…* (save, delete the temporary
  one, open the copy) and *Delete* (asks first). Nothing is deleted unless the user chooses.

## Layout

Top bar: brainproxy, the project and its engagement scope chips; on the right, while an
agent's change that narrowed what the proxy records (`proxy status`'s
`recording_narrowed_by_agent`) hasn't been changed by a person since, a "Recording narrowed by
an agent" pill (when and what in its tooltip; it opens Target › Scope, which shows the same
notice, a *Keep as it is* that reads `scope show` again and, if the flagged changes are still
the ones shown (`sameFlagged`), saves each flagged setting unchanged (`views/recording.ts`
`reviewCommands`), or else reloads the tab and says so without saving, and the latest changes to the proxy scope and the pass-through list from
`scope show`, with every earlier one an agent made or that narrowed recording; the pill reloads that tab even when it is showing, keeping edits not saved yet);
likewise a "Routing changed by an agent" pill for `routing_changed_by_agent` (an agent's change
to upstream proxies, host overrides or client certificates; `reroutedNotice`), whose notice on
the Scope tab has its own *Keep as it is*, which reads `scope show` again in the same way and runs
`connection review`;
then the intercept and proxy pills (the proxy pill starts/stops `proxy start` on the address and with the options
set in Settings › Proxy, 127.0.0.1:8080 by default) and the theme toggle, and **Open browser**: a menu of the
installed browsers (`browser list`) that starts the proxy if needed and runs `browser open`,
a separate browser instance in a per-project profile (`<project>.browsers/<id>`) going through
the proxy, loopback included; Chromium-based browsers trust the brainproxy CA in that profile only (by its key, via
`--ignore-certificate-errors-spki-list`), Firefox gets the proxy prefs and a one-time CA import
note. Traffic hides requests refused as out of scope by default (mostly browser background
calls), and so does the Site map ("In scope only"); the proxy never holds an out-of-scope
request for interception. Tools sit in a grouped, collapsible sidebar, with the clickable
AssertiveInfosec logo above Collapse and on the welcome screen (just the mark when collapsed; links open in the system browser
via tauri-plugin-opener, limited to assertivesolutions.io); tools with several parts have sub-tabs.
Views stay mounted when hidden, so state (selection, edits, Replay tabs) survives switching;
Replay tabs are also kept in the project file (below).

| Group | Tool | Parts | CLI used |
| --- | --- | --- | --- |
| Recon | Overview | Guided scan (below), a new-version card when brainproxy has an update (checked daily unless turned off in Settings › Rules & data; download, open installer), rules and checks card (ZAP rule data and Nuclei templates: status and one-click download; at the top while either is missing), issue counts, recent findings, tasks, history stats | `job list`, `query`, `scan active --crawl`, `scan data status/update`, `checks status/update --background`, `update check/download --kind gui` |
| Recon | Site map | Host → path tree with issue dots (crawl/scan/replay a node, copy a request as cURL), *Import API (sends each once)…* (an API definition's operations sent live once each and recorded, below), engagement and proxy scope | `query`, `history show`, `crawl`, `scan active`, `import api` (`--dry-run`, then `--background`), `job status/stop`, `engagement *`, `scope *` |
| Capture | Proxy | Intercept (held queue incl. WebSocket messages, edit, forward/drop), Traffic (filters, a contents search inside requests and responses, a query in the filter language, saved filters kept in the project, request/response, copy as cURL; right-click to scan a request after a confirmation, test it in Access, highlight it and remove the highlight, or *Create finding…*), WebSockets (connections, messages both ways, payload viewer, send to Replay) | `intercept *`, `history list/show/note/tag`, `history list --contains`, `history list --filter`, `history filters list/save --if-revision`, `scan active --history-id [--include-methods] --background`, `checks status`, `ws list/messages`, `findings add` |
| Attack | Replay | Tabs, raw request editor, response, back/forward through sends; auto URL-encode on send (request line and form bodies: only characters invalid in a URL, structure kept); ⌘U / ⌘⇧U encode or decode the selection in any editor; **+ cURL** opens a pasted curl command as a tab and *Copy as cURL* copies the request with the tab's options (both below); Race (below); per-tab Options (`views/replayOptions.ts`): HTTP/2, send as typed (`--verbatim`, HTTP/1 only so greyed out with HTTP/2: no Content-Length update, no auto URL-encode, the head's line breaks sent as CRLF and the body as the editor holds it), CRLF body (the GUI writes a text body's line breaks as CRLF; no CLI flag), SNI, timeout, verify TLS, don't record, with the ones that aren't the default as chips on the toolbar; a step sent with other options than the tab now has says which; Stop cancels a send still waiting (`cancelCli`) and says it may have reached the server (history has its row marked cancelled, or on Windows with the pending error, and the rows the CLI names when it answered in time); a send in flight and its result stay with its tab across tab switches (`views/replayCalls.ts`), and closing the tab or the project (or quitting) stops it, after asking. WebSocket tabs (**+ WS**): handshake editor, messages separated by `---`, listen time and stop regex, the same options except HTTP/2, as typed and CRLF body, Stop, the conversation with a payload viewer. *Create finding…* for the request and its last send. Tabs are kept in the project (below) | `send --target T [--http2 \| --verbatim] [--sni] [--timeout] [--verify-tls] [--no-store] -` (with `--race N` for Race), `history show` (a raced response), `ws send --target T --input-json [--sni] [--timeout] [--verify-tls] [--no-store]` (handshake and messages on stdin), `replay tabs list/save`, `findings add` |
| Attack | Fuzzer | §positions§ (manual or auto), attack types, built-in lists (`wordlist:NAME`), lists/numbers/files with processing, grep/extract/status match, Discover content preset; live results with baseline and outliers; past runs | `wordlists list/show`, `fuzz run --background`, `fuzz status/results/list/stop` |
| Attack | Scans | Tasks (live progress, stop), new scan (crawl and audit, audit everything recorded, or specific URLs; downloaded Nuclei templates included by default at high severity and up, adjustable; *Keep only attack requests that back a finding*, a project setting) or crawl, either with *Run JavaScript (browser)* for single-page apps (greyed out without a Chromium-based browser), passive and active rules | `job *`, `scan active/passive/rules/enable/disable/sources/prune`, `crawl`, `crawl --browser`, `scan active --crawl --browser`, `browser list` |
| Attack | Access | Access control across users: start a run (identities from the auth profiles plus an anonymous toggle, an optional owner, and all credentialed history, one site, a tag, a SQL condition, or the requests sent from Traffic), or restart the proxy with live testing; a run picker; the run as a grid of requests by identities, cells coloured by verdict (bypass high/medium/low, public, different, inconclusive, enforced, error) with skipped rows marked, filterable by verdict; click a cell to see the owner's baseline and that identity's response (or requests) side by side, or open both in Diff | `auth list`, `authz run --background` (with `--history-id`, and the opt-ins asked for, for requests from Traffic), `authz list/matrix/results`, `job status/stop`, `history show`, `proxy status/start/restart --authz`, `proxy setup show` (a proxy that is off) |
| Results | Findings | Issues grouped by type and risk, detail, evidence, triage; *New finding…* for an issue found by hand (also *Create finding…* from Traffic and Replay), which can be removed again | `findings list/show/mark/add/remove` |
| Results | Callbacks | OOB listener start/stop, payload generator, interactions with raw detail | `oob start/stop/status/payload/poll` |
| Tools | Codec | Stacked encode/decode/hash steps, including gzip, zlib, and raw deflate (Brotli decodes only). **Smart decode** finds the layers (URL, Base64, hex, HTML, JWT, gzip, zlib) and puts them in as steps to check or change, stopping at JSON; its note says if the 8-layer limit or a decompression bomb stopped it | `encode`, `decode`, `hash`; Smart decode: `decode auto -` (its `steps` and `stopped`) |
| Tools | Diff | Items sent from other tools or pasted; line/word/byte diff side by side or unified | client-side diff; `diff A B` for two history entries |
| | Settings | Auth profiles (including platform auth: Basic, Digest, NTLM; with macros built from Traffic and session rules), match & replace, intercept options, proxy (status, start, the port, who can connect, invisible mode and a redirect the app uses, and restarting with them, setup for browsers/curl/shell), connections (upstream proxies, host overrides, client certificates, TLS pass-through, check a target's route), TLS/CA, rule data, project, open source licenses (credits and NOTICE) | `auth *` (incl. `auth macro add/run/remove`, `auth rule add/remove`, `query` for the Traffic picker), `rules *`, `intercept *`, `proxy status/start/stop/restart` (incl. `--invisible`, `--redirect`), `proxy setup show/set`, `engagement check` (the redirect), `connection *`, `ca init/export`, `checks *`, `scan data *`, `project info`, `project save` (temporary engagements), `engagement show` |

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

The first step also links to the API flow (`views/ApiWizard.tsx`, with its logic in
`views/apiScan.ts`), which shares the slot and `WizardProgress`. It previews with `import api
SOURCE --dry-run` (with `--graphql` for a GraphQL endpoint, and `--environment FILE` once a
Postman environment is chosen), then asks for the server (the endpoint, for a GraphQL schema file)
and Postman variables, optional authentication (API key or bearer token via `auth add
--header-env|--query-key`, with the value passed as `BRAINPROXY_SECRET_API_KEY`; OAuth 2 via
`views/ApiAuthExtras.tsx`, `auth add --oauth-* --oauth-store-secrets` with the secrets in
`BRAINPROXY_SECRET_OAUTH_*` and `BRAINPROXY_SECRET_PASSWORD`, prefilled from the definition's `oauth`,
then `auth login` or `auth oauth authorize` (which *Cancel* stops), and the profile removed again
if no token comes; entering other credentials offers to remove the profile saved before; a
query key goes only to the origins it was saved for (`--key-origin`), so a server on another
origin sets it aside (`afterServerChange`): the Authentication step and the review (`PlanFacts`,
in a scan and an import alike) say so, the scan or import can't start until it's saved again or another choice is made, either of which offers to
remove the old profile once (kept, it's there to use again with its own server), and going back
to a server it covers before then, or choosing an API key again there (`chooseMode`), brings it
back; loading another definition, *Test a website instead* and *I'll set it up myself* offer to
remove each profile saved in the wizard that nothing would use any more (`leftBehind`); an
existing profile, where one holding a query
key saved in the wizard for other origins is said to run without the key (`profileKeyText`), on
that step and in the review; optional signing via `SignerBuilder` (HMAC, private key, JWT or AWS SigV4,
prefilled from a collection's `aws`) or a collection's pre-request script, shown with
`--show-scripts` before it can be chosen, with text-direction and invisible characters flagged
and written out, and a session rule), and the operations to send
(GraphQL mutations are opt-in, as MUTATION), and offers a one-request check (`import api --only N
--auth P`, which may use a GraphQL query). It runs `scan active --api SOURCE --expect-sha256 ...
[--expect-environment-sha256 ...] --only ... --background`.

*Import API (sends each once)…* in the Site map toolbar is the same flow with `mode="import"`, for
an API to work on by hand (it is not offline: each ticked operation goes to the target once): the
same definition, server, authentication and operations steps (destructive methods and GraphQL
mutations opt-in in the same way), then a review in place of depth and speed. It runs `import api
--expect-sha256 ... [--expect-environment-sha256 ...] --only ... [--include-methods ...] [--auth P]
--background -- SOURCE`, which sends each ticked operation once, in scope, and records it as history
source `import`; nothing is attacked. Its own progress card (`job status`, *Stop*) ends with how
many requests were recorded, any rejected (401/403), unanswered or out-of-scope operations, what the
passive checks found, and links to the Site map and Proxy › Traffic (shown filtered to source
`import`, `openTraffic` in `store.tsx`; a definition fetched from a URL is there too, its rows
holding the response head only, so the GUI never reads a document from history: the wizard works
from `import api --dry-run`'s output). *Hide* shows the map while the job runs, with a *Show* link
in the toolbar. The Site map keeps the job id per project, so the card comes back after a reload; a
remembered id that is gone or names another kind of job (the project file replaced since) is
forgotten. *Stop* is disabled while the job stops. One import runs at a time. The guided API scan's
first step links to it too (`openApiImport`), with the definition typed so far and the *GraphQL
endpoint* tick; that never replaces a running import, and replaces one being set up only after
asking. While `import api` is starting, the wizard can't be cancelled or replaced, so the job it
starts is always the one shown. Since an import sends as the crawl tool, its signer check looks for
a session rule that applies to crawls rather than scans, and says so when the check goes out
unsigned.

### Race

**Race ×N** next to Send in Replay (`views/race.ts`) runs `send --target T --race N [options] -`
with the tab's request, prepared exactly as Send prepares it (auto URL-encode, as typed, CRLF
body, binary bodies), and the tab's options as Send passes them (`--http2`, `--verbatim`,
`--sni`, `--timeout`, `--verify-tls`, `--no-store`; the app passes `--no-store` only when the
person ticked Don't record, and MCP refuses it). N is 2 to 1000, or up to 100 with HTTP/2 on or
a request line ending in `HTTP/2`, since `send` then uses HTTP/2 and the single-packet attack;
otherwise it is last-byte sync over HTTP/1.1. It runs under a call id (`beginCall`), so **Stop**
and closing the tab or project cancel it like a send; the CLI wrote every copy's row, with the
race's tags, before sending, so they stay grouped and are marked cancelled (on Windows, where
the CLI is killed, they keep the pending error). The toolbar names the
technique the CLI reports (and when a single-packet race couldn't put every final frame in one
packet), the spread between the fastest and slowest response, and how many differ. The response
side lists each request's status (or error), length, time since the release and history id
(failures are recorded too); rows whose status or length differ from the most common response's
are highlighted, as is every failure (when nothing came back, the most common error is the
baseline). Selecting a row opens that response (`history show ID`); the first response is opened
when the race ends. The CLI tags every row with the race (`race:ID`, `race-sync:...`,
`race-pos:I/N`, `race-partial`) and refuses a last-byte race the open-file limit has no room
for. A race is one step in ‹ › like a send. Send history and the running send or race are kept
per tab outside the tab's view (`views/replayCalls.ts`), so a race that ends after the user
switched tabs still lands in its tab. The send, race and `history show` run against the project
they started in: closing the project stops a race still running and drops its result, and the
next project's tabs start empty. It races copies of
one request; racing different requests against each other isn't offered.

Cross-tool actions go through `store.tsx`: `sendToRepeater`, `sendToFuzzer`,
`sendToComparer` (right-click a history row, or buttons in Intercept and Findings),
`sendToAccess` (Traffic's *Test access control…*: Access opens its new-run form set to those
history ids) and `showJob` (opens Scans › Tasks on a job, e.g. from the toast after Traffic's
*Scan this request…*). The arguments, which rows can be scanned (not one with no response),
and the questions asked before a scan or before Access replays a POST, a GraphQL mutation
(read from the recorded request, as the scanner reads it; a persisted query sent without its
document counts as one, and so does a compressed body at a GraphQL endpoint, which the view
doesn't decode) or a logout-like path (authz's
default `--exclude`), are built in `views/trafficActions.ts`. So are the opt-ins the CLI refuses
a named request without (`scanOptIns`: `--include-methods` with MUTATION and the method, when the scan doesn't attack it by default;
`authzOptIns`: the same, though POST too, a mutation's method as well as MUTATION (a truncated
request is only guessed to be one), and `--exclude=^$` for a logout): `scanArgs` and `runArgs` add them
only when told the question was answered yes. The Site map's *Active scan this request* asks
the same question and adds the same opt-in (`scanConfirm`, `scanOptIns`). Also `openApiImport`, `openTraffic`, and
`newFinding`, which opens Findings with the *New finding* form prefilled with a URL, method
and history entry. The table selects one row at a
time, so these act on one request. A greyed-out menu item shows why under its label
(`MenuItem.hint`); it stays focusable, with `aria-disabled`.

### cURL

`ui/curl.ts` converts between curl commands and raw requests in the UI, with no CLI call: a
paste only opens a tab, and sending it is Replay's `send` as usual, so the scope applies. An
agent sends the same kind of request with `send --url URL -X ... -H ... -d ...`; neither
direction is a CLI command or an MCP tool.

- **Paste** (**+ cURL** in Replay): reads POSIX shell quoting (`'…'`, `"…"`, `$'…'`, `\` line
  breaks), Windows cmd as Chrome's *Copy as cURL (cmd)* writes it (`^` escapes and line
  breaks), and the `printf` forms *Copy as cURL* writes (`"$(printf '…')"` only inside double
  quotes; unquoted, a shell would split what it prints). It follows curl's rules for the method
  (POST with data, GET with `-G`, HEAD with `-I`), joins several `-d` with `&`, builds `-F`
  fields as multipart, turns `-u` into Basic auth (an `--oauth2-bearer` token wins over it, as
  in curl), and keeps curl's own `Host` and `Accept` headers unless the command replaces or
  removes them (it adds no `User-Agent`). A `-H` is read only as `Name: value` (or
  `Name:value`), `Name:` (removes curl's own header) or `Name;` (an empty one), with `Name` a
  token and nothing between it and the `:` or `;`; each replaces curl's header of that name
  and goes in as curl sends it (`Name: value` as written, spaces kept; `Name;` as `Name:`),
  and a command that sets `Host` more than once is refused. Any other form (`Name : x`,
  `Name;x: y`, a space before the name) is refused, as curl reads those by rules of its own;
  write it in one of the three forms and edit the header in the tab. `-G` and `--url-query`
  add `&` only after a query that has something in it. Long options take a value after `=`
  (`--data=x`), as curl 8.16 and later do. `--http2` on an `http://` URL stays HTTP/1.1, as curl only asks such a server to
  upgrade. A URL with a space or control character is refused, as curl refuses it. A URL that
  curl's globbing makes several requests of (`{a,b}`, `[1-3]`) is refused unless the command
  has `-g`; then the brackets are sent as they are. Options that don't change the request
  (`-k`, `-s`, `-L`, `-o`, timeouts) are ignored. A proxy, `--resolve`, `--connect-to`, a Unix
  socket and client certificates are left out: the dialog lists them before the tab opens, as
  the request may then go elsewhere than curl's would, and **Open anyway** opens it. Anything
  that reads a file (`-d @file`, `-F f=@file`, `-b file`, `-T`, `-K`), shell variables or
  command substitution, a NUL byte in an argument, challenge auth (`--digest`, `--ntlm`) and
  unknown options are refused with the reason, so nothing that changes the request is dropped
  silently.
- **Copy as cURL** (Replay, and right-click a request in Traffic or the Site map): a POSIX
  shell command with every value in single quotes. A `'` or `\` is written outside the quotes
  (`\'`, `\\`), and control, bidi and non-UTF-8 bytes as `"$(printf '\NNN')"`, so a header or
  body from the target can't run anything in sh, dash, bash, zsh or fish. So do format
  characters (`\p{Cf}`: bidi controls, zero-width characters, the soft hyphen, tag characters),
  which a terminal doesn't show. A plain-text body goes in `--data-raw` (which never reads a
  file, even for a body starting with `@`); any other body (NUL, control or non-UTF-8 bytes)
  goes through `printf '…' | curl … --data-binary @-`.
  The command goes to the tab's target, like Send: an absolute URL in the request line goes in
  `--request-target`. It adds `--http2` for an HTTP/2 request, `--http1.1` for an HTTP/1.1 one
  to an `https://` target (curl would negotiate HTTP/2 there) and `--http1.0` for HTTP/1.0,
  `--globoff` for `[]{}` in the URL, `--path-as-is` for `..` segments, `--request-target` for a
  target a URL can't hold, and empty `-H 'Name:'` to remove the headers curl would add (`Host`
  too, when the request has none). Each header line goes in `-H` as recorded, as curl sends a
  `-H` line as written: spaces after the colon and at the end stay, and so does a space before
  the colon (`Transfer-Encoding : chunked`), which curl doesn't read as its own header; that one
  gets a note, as pasting the command back is refused. An empty header goes as `-H 'Name;'`
  (curl sends `Name:`, with a note when spaces are lost). A header whose name isn't a token (an
  `@`, which curl would read as a file, `;`, a control byte) is left out with a note. Notes
  also say when curl sends something else: only the first of several `Host` headers, its own
  `Content-Length` (the body's) in place of a different one, a body chunked again under
  `Transfer-Encoding: chunked`, or, over HTTP/2, no `Connection`, `Keep-Alive`,
  `Proxy-Connection`, `Transfer-Encoding`, `Upgrade` or `TE` other than `trailers`. A request
  with a `Transfer-Encoding` or a spaced `Content-Length` and no `Content-Length` of its own is
  copied with `-H 'Content-Length:'`, so curl adds none. When the copy holds `Authorization`,
  `Cookie` or an API key header, the toast says so. Replay copies what Send would send (auto
  URL-encoding included). A `--data-raw` body over 128 KB gets a warning (Linux limits one
  argument to that size); a body over 2 MB is refused.

### Replay tabs in the project

`store.tsx` keeps Replay's tabs in the project file through `replay tabs list` and `replay
tabs save` (JSON on stdin, replacing the saved set; stored under one key of the `meta`
table with a format version `v` and a revision `rev` that every save raises), with the
logic in `views/replayTabs.ts`:

- **Opening:** the saved tabs are read when the project opens, with new keys, and the saved
  active tab is shown. Tabs sent to Replay while they load stay, after them. Nothing is saved
  until the read succeeds, so a failed read (a toast says so) never replaces the saved set.
  A project opened again waits for the save from closing it before reading, so it never
  loads the set from before and later saves over the newer one.
- **Saving:** one second after the tabs stop changing (the editors pass their text up after
  300 ms), on the CLI in the background, so typing never waits. One save runs at a time and
  an unchanged set isn't sent again. Closing the project or the window takes the editor's
  last keystrokes and saves what is waiting; so does *Save as…*, before it copies the file.
  A temporary project being discarded isn't saved.
- **Saved elsewhere:** each save passes `--if-revision` with the revision the app last read
  or wrote. If the set was saved elsewhere meanwhile (an agent, the command line), the save
  fails with a conflict; the app then reads the set, adds the tabs it didn't know (a toast
  says how many) after its own, and saves them all. Tabs the app closed stay closed. When
  the window comes back to the front the app reads the revision (`list --summary`) and,
  if it moved, takes in new tabs the same way, so an agent's tabs show up without a save.
  Checks and saves run one at a time.
- **Newer format:** a set with a higher `v` than this build writes is shown, but the app
  doesn't save it (a toast says so), and `replay tabs save` refuses to save over it, since
  the newer fields would be lost. A tab of a kind this build doesn't know isn't opened.
- **What:** per tab its kind, title, target, the request (or handshake and messages), the
  binary flag, a WebSocket tab's Listen (at most 86400 s, as `ws send --wait`) and
  Until (now kept when switching tabs too), and its send options (`options`: `http2`,
  `verbatim`, `crlfBody`, `sni`, `timeout`, `verifyTls`; `savedOptions` in
  `views/replayOptions.ts`). Never Don't record: `replay tabs save` refuses `noStore`, so a
  reopened or agent-prepared tab can't make a person's send unrecorded. The CLI checks the
  rest as the flags are: a timeout above 0 and at most a day, an SNI that is a TLS server
  name (its scope is checked when it is sent); the app leaves out an SNI or timeout that
  isn't valid yet rather than failing the save. Never responses or the send history. Text goes
  as typed, auth placeholders included, and so do live `Cookie` or `Authorization` values in
  a request sent over from history: `replay tabs list` returns them in full. Use `«auth:…»`
  placeholders in tabs that are kept.
- **Failures:** a refused save (over 500 tabs or 16 MB) is a toast, shown once per distinct
  error; the tabs stay open, and the next change or closing tries again. *Save as…* stops
  there and leaves the temporary project open (copying it would leave those tabs behind);
  switching project asks before closing without them.
- **Agents:** `replay_tabs_save` is an MCP tool that only adds tabs there (`append`; not
  destructive, sends nothing), so an agent can prepare tabs for a person to review and send
  but can't replace or clear theirs. `replay_tabs_list` is read-only and its output is
  marked untrusted, since requests often come from the target's traffic; `summary` and
  `index` page through a set larger than the server's output cap.

### New finding

The form (`views/NewFinding.tsx`, logic in `views/manualFinding.ts`) runs `findings add`: title,
risk, confidence, method and URL (or only history entries, whose first gives both), parameter,
CWE, history entries, description, solution and evidence. The method, URL, description,
solution and evidence go on stdin as JSON (`--input-json`), so a token in a URL from Traffic
or in the evidence stays out of the process list; the rest are arguments. From Replay, an unsent request's URL is its request line
on the target's scheme, host and port, with the path as written (`%2e%2e` is not resolved).
Nothing is sent. When the description or solution differs from the one findings of the same
title share, `findings add` refuses; the form then shows a checkbox to replace it
(`--replace-text`, which keeps the earlier text). A warning (outside the scope, a linked history
entry on another host or port, or a replaced description or solution) shows with the
confirmation. Risk and confidence are named groups whose picked button is pressed
(`aria-pressed`), the method and URL inputs have their own labels, and Tab stays inside the dialog (`ui/dialogFocus.ts`, shared with the confirmation
dialog), with focus going back to where it was when it closes. Findings added by hand are
grouped by title, tagged *by hand* (*via MCP* for one an agent added, by its `origin`:
`addedBy` in `views/manualFinding.ts`), show *Added by hand* (or *Added via MCP (an agent)*)
and their history entries instead of a rule, and have *Remove* (`findings remove`, after asking). A removed finding is kept with state
`removed`, which the list leaves out. The scan comparison leaves them out, since no scan looks
for them.

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
npm run dev                      # UI in a browser: open the #bridge= link it prints (dev bridge)
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
- Tabs saved from elsewhere while the project is open show up on the app's next save or
  when its window comes back to the front, not at once. Removing or changing tabs from
  elsewhere while the app has them open doesn't stick: the app keeps its open tabs and
  saves them again. In the browser build (`npm run dev`) closing the tab can lose the last
  second of edits.
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
- Traffic's Query mode runs `history list --filter` through the same paging as the contents
  search. A query the CLI refuses as invalid input isn't tried again until the text changes
  (`failPage(..., invalid)`); the toolbar shows the parser's message. Saved filters are loaded
  with `history filters list` when the project opens and saved whole with `history filters
  save --if-revision REV`, one save at a time (`saveChange`); a conflict (an agent added one, or
  another window saved) reads them again and applies the same change to what is saved now, once. Filters an
  older build kept in localStorage are merged into the project's (`mergeLocal`: an equal one is
  already there, a different one under a taken name becomes "NAME (this computer)"), then
  removed from localStorage. A note or highlight changed from Traffic runs a query that uses
  `tag` or `note` again from the start (`usesEditableFields`, `rerun`: rows it hasn't reached yet
  keep showing as before, so the table doesn't empty), since rows already searched may now match
  or not; edits made elsewhere aren't seen until the query changes.
- Traffic's contents search is case-sensitive and literal, like `history list --contains`
  (no `--ignore-case` yet), and stops at the first 10,000 matches the other filters show
  (oldest first; the toolbar says so). Only a new text or a different single source starts a
  new search, and the CLI call still running for the old one is stopped (`cancelCli`); the
  checkboxes and several sources are applied to the matches in the app, searching on only if
  the cap no longer applies. Whitespace-only text doesn't search. A failed search is tried
  again after 2 s, doubling up to a minute.
- Saved Traffic filters are kept by the app (localStorage, per project path, plain text), not
  in the owner-only project file, so the CLI and agents don't see them, they don't follow a
  copied project, and a saved search for a secret stays in the webview's storage until it is
  deleted. *Save as…* on a temporary engagement copies them to the saved file (and says so if
  it can't); discarding one leaves its (unused) entry behind.
- A finding added by hand can't be edited: mark it like any other, or remove it and add it
  again (a new finding, with a new id and an open state; the removed one stays as `removed`).
- The native window was not screenshot-tested; the browser build was (`npm run dev`).
