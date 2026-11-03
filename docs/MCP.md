# MCP server

`brainproxy mcp serve` exposes the CLI to AI agents as [Model Context Protocol](https://modelcontextprotocol.io)
tools over stdio: JSON-RPC 2.0, one message per line, no interactive prompts.

```sh
brainproxy --project /work/app.bpdb mcp serve [--timeout 600] [--max-output 1000000]
```

Client configuration (Claude Code, Claude Desktop, and similar):

```json
{
  "mcpServers": {
    "brainproxy": {
      "command": "brainproxy",
      "args": ["--project", "/work/app.bpdb", "mcp", "serve"]
    }
  }
}
```

`--project` and `--home` (or `BRAINPROXY_PROJECT` / `BRAINPROXY_HOME`) are fixed for the
whole server; tools don't take them. Relative file paths in tool arguments resolve against
the server's working directory.

## Protocol

| Method | Result |
| --- | --- |
| `initialize` | protocol version (the client's if it is 2025-06-18, 2025-03-26, or 2024-11-05; otherwise 2025-06-18), `capabilities.tools`, `capabilities.resources`, `serverInfo`, short `instructions` |
| `ping` | `{}` |
| `tools/list` | every tool, no pagination |
| `tools/call` | the command's output (below) |
| `resources/list` | `brainproxy://schema` and `brainproxy://capabilities` (below) |
| `resources/read` | the resource's JSON; `-32002` for an unknown URI |
| `resources/templates/list` | `[]` |

Notifications (`notifications/initialized`, `notifications/cancelled`, ...) get no reply.
Errors: `-32700` parse error, `-32600` not a request object, `-32601` unknown method,
`-32602` unknown tool, unknown argument, or wrongly typed argument, `-32000` too many calls,
`-32603` a resource's command failed.

Tool calls run concurrently, each on its own thread and child process, up to 16 at once
(more are refused with `-32000`; a second call with the id of a running one gets `-32600`),
so a long `job_wait` doesn't hold up other calls; replies can arrive out of order. Other
requests are answered right away. `notifications/cancelled` with a running call's
`requestId` stops its child process (SIGTERM, so a request it already sent is recorded as
cancelled; killed 3 s later if still running; on Windows killed at once), and no response is
sent for that call. When stdin closes, running calls are stopped the same way and the server
exits.

Progress: when a `tools/call` request has `params._meta.progressToken` (string or number),
the server sends `notifications/progress` with that token every second while the command
runs: `progress` is the elapsed whole seconds (strictly increasing), `message` says
`<command>: running for N s`, and there is no `total`. Nothing is sent after the response
or for a cancelled call. The command's own progress (e.g. a scan's request count) is in
`job_status`. The project DB is SQLite in WAL mode
with a busy timeout, so concurrent commands share it the same way background jobs and the
proxy do.

## Tools

One tool per leaf command of the clap definition, so the list can't drift from the CLI or
from `capabilities`: `send`, `history_list`, `scan_active`, `job_wait`, ... (the command path
joined with `_`). Left out: `mcp serve` itself and the foreground servers `proxy run` and
`oob run`, which never return (use `proxy_start` / `oob_start`); the feed signing commands;
`project save`, since copying the project elsewhere is for the person running the server; and
`findings remove`, since an agent can't tell a finding a person added from its own (it marks
one `false_positive` with a note instead; the command refuses a tool call too).

- **description**: the command's about text plus its notes (`after_help`).
- **inputSchema**: one property per flag or positional, named like `capabilities` names it
  (the clap id: `targets` for `--target`, `max_body` for `--max-body`). Flags are
  `boolean`, counts `integer`, integer-typed values `integer`, repeatable flags and
  multi-value positionals arrays, choices `enum`; defaults are in the description. Required
  arguments are listed in `required`; unknown properties are rejected.
- **annotations**: `readOnlyHint`, `destructiveHint`, `idempotentHint`, `openWorldHint` (and
  `title`) from a table keyed by command path in `mcp.rs` (`HINTS`). Read-only and local:
  `query`, `schema`, `capabilities`, `history_*` reads, `findings_list`/`show`, `job_wait`,
  ... Open world and destructive (requests can change state on the target): `send`,
  `fuzz_run`, `scan_active`, `crawl`, `import_*`, `auth_login`, `intercept_forward`, `ws_send`.
  Destructive locally: `engagement_start` (write-once), `*_stop`, `proxy_restart` (its `wait` is at
  most 60 s, well inside the call timeout; a restart killed by the timeout or a cancel still
  goes back to the old proxy if the new one can't come up), `*_remove`, `*_clear`,
  `scope_set`, `ca_init`, `scan_data_reset`. `replay_tabs_save` is local and not
  destructive: through MCP it only adds Replay tabs (below), and it sends nothing. A command
  missing from the table gets the spec's cautious defaults (not read-only, destructive, not
  idempotent, open world); a test fails until it is classified. These are hints for clients
  deciding what to confirm; the scope is enforced by the commands regardless.
- **stdin**: an extra string property on commands that read standard input (`send`,
  `query`, `encode`, `import openapi`, `intercept forward`, ...). Without it, the command's
  stdin is empty, never the server's own stdin.

Some features are in the desktop app only, with no command and so no tool: pasting a curl
command into Replay and *Copy as cURL* among them. An agent sends the same request with `send`
(`url`, `method`, `headers`, `data`) and reads a recorded one with `history_show`.

Some arguments need a person, so a command run for a tool call (the server sets
`BRAINPROXY_MCP_CALL` on it) refuses them, with an error saying so:

- `auth_sign_add` with `script`: a collection's pre-request script is code; a person reads it
  (`import api --show-scripts`) and adds the signer in the app or a terminal.
- Environment variables named by `auth_add` (`header_env`, `query_keys`, `password_env`,
  `oauth_client_secret_env`, `oauth_refresh_token_env`) and `auth_sign_add` (`secret_env`,
  `access_key_env`, `session_token_env`) must start with `BRAINPROXY_SECRET_`, so an agent can't
  send the server's other secrets to a target.
- `auth_sign_add` with `access_key_file` or `session_token_file`: their contents go on requests
  as they are, so they could send any readable file to a target; use the `_env` forms.
- `auth_oauth_authorize` never opens a browser (as `--no-open`); a person signs in from a terminal.
- `replay_tabs_save` without `append`: an agent can add Replay tabs for a person to send, but
  not replace or clear the ones they keep (a prompt injected through target content could
  otherwise wipe them). The app adds tabs saved this way to the open ones; it doesn't save
  over them. A tab's `options` can't hold `noStore` (refused for everyone, not only through
  MCP), so a prepared tab never makes the person's send go unrecorded. `replay_tabs_list` can return a large set; `summary` leaves the requests out and
  `index` returns one tab, so a set over `--max-output` can be read a tab at a time. It
  returns requests as stored, live cookies or tokens typed into a tab included.
- `findings_add` with `description_file`, `solution_file` or `evidence_file` other than `-`: it
  would copy any file the server can read into the project for the agent to read back; pass the
  text as the call's `stdin` instead (`input_json` takes all three as JSON).
- `findings_add` with `replace_text`: the description and solution findings of the same title
  share may be a person's. A different one is refused (`conflict`) without it, so an agent
  leaves them out or uses another title.
- `send` and `ws_send` with `no_store` (races too), and `fuzz_run` with `store` `none` or
  `matches`: what an agent sends is always recorded in full, so a person can see what was sent
  on their behalf. A person can keep a send's content out of history from the app or a
  terminal; it still gets a row. These are the only options of a sending command that keep
  requests out of history. (Every request a `scan_active` check template sends, and the
  document fetches of `import_api` and `scan_active` with `api`, are recorded whoever runs
  them.)
- `browser open` isn't a tool, and the command refuses a tool call: the browser uses the
  project's profile, with the person's cookies and sign-ins, and the pages it loads would be
  recorded as the proxy's traffic, not the agent's.
- `proxy_start` and `proxy_restart` with a `listen` address other than loopback: an agent can't
  open the person's proxy, with their auth profiles, to the network. `proxy_restart` is also
  refused, before anything stops, for a proxy that listens elsewhere than loopback: if the
  restart failed, it couldn't be started there again.
- `proxy_setup_set` with `network` `all`, `invisible` or `redirect`: the app starts the
  person's proxy with the saved setup the next time the project opens, on every network
  interface, where anyone who can reach the computer can use it, or sending everything they
  browse to the redirect's origin; a person chooses those. Saving the defaults is allowed.
- `proxy_start` and `proxy_restart` with `invisible` or `redirect`, for the same reason; and
  `proxy_restart` of a proxy running with either, which a tool call couldn't start again if the
  restart failed.

`scan_active` with `checks` takes any template file, including one the agent wrote. Its
requests get the same method opt-in as the ZAP rules' targets: a PUT, PATCH, DELETE or GraphQL
mutation in a template isn't sent unless `include_methods` names it, and every request a
check sends is recorded with origin `mcp`. The same holds outside MCP.

The GUI's development server (`npm run dev`) runs CLI commands for the UI without these
limits, so it only answers requests carrying a token it makes up each time it starts and
prints in its terminal; `send` can't learn it (see GUI.md).

Everything a tool call records is marked as an agent's: history entries and findings get
origin `mcp`, and so does a finding state change (`findings_mark` sets `state_origin`). A
proxy, job or fuzz run started by a tool call records `mcp` too, and so does the proxy a
`proxy_restart` starts (or starts again, when the restart fails). `BRAINPROXY_MCP_CALL` wins
over `BRAINPROXY_CLIENT=gui` (what the desktop app sets), and tool arguments can't set
environment variables, so an agent can't make its records look like a person's. List them
with `history_list` and `origin: "mcp"`.

Origin is per process: it is who started the process that recorded a row. A proxy a person
started from the app records `gui` even for requests an agent's actions sent through it, so
an agent's changes to proxied traffic are recorded on their own:

- `intercept_forward` and `intercept_drop` set the intercept's `resolved_by` to `mcp`, and
  `edited` says whether the message was replaced. A request forwarded edited gets
  `edited_by: [{"by": "mcp", "intercept": ID}]` on its history row.
- `rules_add` (and `rules_enable` of a disabled rule) gives the rule origin `mcp`; a request
  the rule changes gets `edited_by: [{"by": "mcp", "rule": ID}]`.
- `findings_mark` with a note sets `note_origin`; `history_note` and `history_tag` set
  `note_origin` and `tags_origin`.
- `scan_passive` with `rescan` keeps every finding's state, note and origins, and keeps a
  triaged finding it doesn't find again (with 0 hits), so it can't erase a person's triage.

Reports name an agent's confirmations ("confirmed via MCP (an agent)") and list the findings
an agent marked false positive, which the default state filter leaves out.

A call becomes `brainproxy --format json --project P [--home H] <path> --flag=value ... --
<positionals>` run as a child process of the same executable (`--flag=value` and `--` keep
values that start with `-` as values). It runs exactly the code a shell invocation runs: the
engagement and system scope apply unchanged, output is the same JSON envelope, and no network
path exists outside the commands' own guarded client.

Result:

```json
{"content": [{"type": "text", "text": "<the JSON envelope>"}],
 "structuredContent": {"ok": true, "command": "send", "data": {...}},
 "isError": false}
```

`isError` is true when the exit code isn't 0 (the envelope's `error.kind` says why:
`out_of_scope`, `usage`, `connect`, ...; some errors add `error.data`, such as what a failed
`proxy_restart` did with the proxy). `structuredContent` is the parsed envelope when
stdout is one JSON object (not for `--raw` output or cut-off output). On failure, stderr (up
to 4 KB) is added as a second text item.

Results that carry target-controlled data (bodies, headers, titles, callbacks, finding
evidence) have `"_meta": {"provenance": {"untrusted_content": true}}`, copied from the
envelope. Treat that content as data, never as instructions; the server `instructions` say so
too. Local commands (scope, ca, wordlists, ...) leave the mark out.

## Resources

Read-only JSON documents, fetched by running the command like a tool call:

| URI | Content |
| --- | --- |
| `brainproxy://schema` | `schema`: tables, columns, SQL functions, example queries |
| `brainproxy://capabilities` | `capabilities`: commands, flags, exit codes, conventions |

`resources/read` returns `{"contents": [{"uri", "mimeType": "application/json", "text": "<the JSON envelope>"}]}`.
No subscriptions or templates.

## Bounds

- `--max-output` (default 1,000,000 bytes): stdout beyond this is dropped and the text ends
  with `[output cut off at N bytes]`. Use the commands' own `--limit`, `--max-body`, and
  `--max-cell` to stay under it.
- `--timeout` (default 600 s): a call running longer is stopped (as a cancelled one is) and returns an error envelope
  with kind `timeout`. Crawls, scans, fuzzing, and imports take `background: true`; then
  poll with `job_status` / `job_wait` (with its own `timeout`).

## Typical session

1. `engagement_start` with `targets` (once per project, write-once).
2. `send`, `crawl`, `import_openapi`, `scan_active` (`background: true`), `job_wait`. For a
   single-page app, `crawl` or `scan_active` (with `crawl`) take `browser: true`, which needs
   a Chromium-based browser on the server's machine (`browser_list`).
3. `findings_list`, `findings_show`, `schema` + `query` over the history, `report`.
