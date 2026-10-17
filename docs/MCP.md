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
| `initialize` | protocol version (the client's if it is 2025-06-18, 2025-03-26, or 2024-11-05; otherwise 2025-06-18), `capabilities.tools`, `serverInfo`, short `instructions` |
| `ping` | `{}` |
| `tools/list` | every tool, no pagination |
| `tools/call` | the command's output (below) |

Notifications (`notifications/initialized`, `notifications/cancelled`, ...) get no reply.
Errors: `-32700` parse error, `-32600` not a request object, `-32601` unknown method,
`-32602` unknown tool, unknown argument, or wrongly typed argument. Calls are handled one at
a time in order.

## Tools

One tool per leaf command of the clap definition, so the list can't drift from the CLI or
from `capabilities`: `send`, `history_list`, `scan_active`, `job_wait`, ... (the command path
joined with `_`). Left out: `mcp serve` itself and the foreground servers `proxy run` and
`oob run`, which never return (use `proxy_start` / `oob_start`).

- **description**: the command's about text plus its notes (`after_help`).
- **inputSchema**: one property per flag or positional, named like `capabilities` names it
  (the clap id: `targets` for `--target`, `max_body` for `--max-body`). Flags are
  `boolean`, counts `integer`, integer-typed values `integer`, repeatable flags and
  multi-value positionals arrays, choices `enum`; defaults are in the description. Required
  arguments are listed in `required`; unknown properties are rejected.
- **stdin**: an extra string property on commands that read standard input (`send`,
  `query`, `encode`, `import openapi`, `intercept forward`, ...). Without it, the command's
  stdin is empty, never the server's own stdin.

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
`out_of_scope`, `usage`, `connect`, ...). `structuredContent` is the parsed envelope when
stdout is one JSON object (not for `--raw` output or cut-off output). On failure, stderr (up
to 4 KB) is added as a second text item.

## Bounds

- `--max-output` (default 1,000,000 bytes): stdout beyond this is dropped and the text ends
  with `[output cut off at N bytes]`. Use the commands' own `--limit`, `--max-body`, and
  `--max-cell` to stay under it.
- `--timeout` (default 600 s): a call running longer is killed and returns an error envelope
  with kind `timeout`. Crawls, scans, fuzzing, and imports take `background: true`; then
  poll with `job_status` / `job_wait` (with its own `timeout`).

## Typical session

1. `engagement_start` with `targets` (once per project, write-once).
2. `send`, `crawl`, `import_openapi`, `scan_active` (`background: true`), `job_wait`.
3. `findings_list`, `findings_show`, `schema` + `query` over the history, `report`.
