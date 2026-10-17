# Declarative checks

Checks are YAML files that the active scanner runs next to the ported ZAP rules. The
format is the HTTP subset of [Nuclei templates](https://docs.projectdiscovery.io/templates/introduction)
plus a few brainproxy extensions, so community templates and checks you (or an agent)
write load through the same parser and engine.

```sh
brainproxy checks update                         # Nuclei HTTP templates, pinned to a commit
brainproxy checks list nuclei --tags exposure --severity medium
brainproxy checks validate my-checks/            # per file: loads, or why not
brainproxy scan active https://app.test/ --checks nuclei --check-tags exposure,misconfig
brainproxy scan active https://app.test/ --checks local --no-rules    # only your checks
brainproxy checks status
```

## Security boundary

- Every request a check makes goes through the active scanner's `Cx`: the engagement
  and system scope guard, the `--auth` session, `--rate`, `--max-minutes`, and `job stop`
  all apply. A `path` or `raw` request whose URL points to another origin than the
  target being scanned is skipped.
- Findings are recorded like other active findings (`alert_ref` `check:<id>`, source
  `active`), with the attack exchange in history.
- `checks update` downloads only from GitHub, over verified TLS, through the guarded
  client with a scope of `api.github.com`, `raw.githubusercontent.com`, and
  `codeload.github.com`; the system scope still applies, so a locked-down runner refuses
  it (exit 6). There, the provisioner runs `checks update --from DIR` with a
  nuclei-templates checkout. The ref is resolved to a commit first; the manifest records
  the commit and the tarball's sha256, and `--sha256` makes the update fail on a mismatch.
- Templates are data: nothing in them is executed. DSL expressions are parsed when the
  template loads and evaluated by a small interpreter whose functions only compute over
  their arguments (no file, network, or process access; bounded nesting, operator count,
  and value size). Anything outside the supported subset (unknown DSL functions, code,
  JavaScript, headless, other protocols) makes the template unsupported; it is listed
  with a reason, never half-run.

## Stores and selectors

| Selector | Location |
|---|---|
| `nuclei` | `<home>/checks/nuclei/`, replaced as a whole by `checks update` (only templates that load are stored) |
| `local` | `<home>/checks/local/`, your own checks (any layout, `*.yaml`/`*.yml`) |
| `all` | both |
| a path | a template file or a directory (recursive) |

`<home>` is `--home`/`BRAINPROXY_HOME`, else `$XDG_DATA_HOME/brainproxy`, else
`~/.local/share/brainproxy`. Checks only run when `scan active --checks` names them.
`--check-tags` (any of), `--check-exclude-tags` (default `dos,fuzz,intrusive`),
`--check-ids`, and `--check-severity` narrow the set; `--no-rules` skips the ZAP rules.
Loading is parallel and cheap (about 1 s for the ~9,100 stored Nuclei templates);
regexes compile on first use.

## Supported Nuclei subset

Top level: `id`, `info` (`name`, `severity` info|low|medium|high|critical|unknown,
`description`, `remediation`, `reference`, `classification.cwe-id`, `tags`), `variables`
(strings, may use placeholders and DSL expressions), `http` (or the older `requests`),
and `flow` when it is a boolean combination of request blocks (`http(1) && (http(2) ||
http(3))`; later blocks only run when needed, JavaScript flows are unsupported).

Request blocks:

- `method` + `path` list, or `raw` requests (line endings normalized, Content-Length fixed
  unless `unsafe: true`); `headers`, `body`.
- `payloads` (inline lists only) with `attack` batteringram | pitchfork | clusterbomb, at
  most 1000 combinations per block.
- `matchers` with `matchers-condition` and|or: `word` (incl. `encoding: hex`), `regex`,
  `status`, `size`, `binary`, `dsl`; `condition`, `negative`, `case-insensitive`,
  `internal` (counts for the block and `flow`, but a block whose matchers are all
  internal reports nothing); parts `body` (default), `header`, `all`/`response`/`raw`,
  one response header (`content_type`), or a numbered part (`body_2`).
- `extractors`: `regex` (with `group`), `kval`, `dsl`, and `json` with jq paths
  (`.a.b`, `.a[0]`, `.["k"]`, `.items[]`, and pipes of these; no `select`, `..`, or
  operators); `internal: true` extractors feed later requests as `{{name}}`, and named
  extractors are visible to the same response's DSL matchers. A block with only
  extractors reports what they extract.
- Multi-request conditions: when a block's matchers use numbered parts (`body_1`,
  `status_code_2`) or set `req-condition: true`, all its requests run first (internal
  extractors feed the next one) and the matchers run once over the numbered responses;
  unnumbered names refer to the last one.
- `stop-at-first-match`, `redirects`/`host-redirects` (up to 5, in scope).
- Ignored as harmless: `max-redirects`, `cookie-reuse`, `disable-cookie`, `max-size`,
  `read-all`, `threads`, `skip-variables-check`, `id`, `name`.

Placeholders: `{{BaseURL}}`, `{{RootURL}}`, `{{Hostname}}` (host[:port]), `{{Host}}`,
`{{Port}}`, `{{Path}}`, `{{File}}`, `{{Scheme}}`, `{{randstr}}`/`{{randstr_N}}`, variables,
payload names, extractor names, and DSL expressions over these (`{{base64(user + ":" +
pass)}}`, `{{to_lower(rand_base(8))}}`). For the default host scope `BaseURL` is the origin
(`https://app.test:8443`).

Template inputs: a placeholder or DSL variable the template doesn't define (such as
`{{username}}`/`{{password}}`, which Nuclei takes from `-var`) is filled from
`--check-var NAME=VALUE` (repeatable, on `scan active`, `checks list`, and `checks
validate`). An input with the same name as a template variable overrides it. A template
using inputs that aren't given is not loaded; the reason names them (`template inputs
without a value (--check-var): password, username`). `checks update` stores such
templates anyway, so passing the inputs later enables them. Input values are sent as
given and end up in the history like any request data.

### DSL subset

Nuclei's DSL is govaluate plus helper functions. brainproxy parses it at load time:

- Literals: numbers, `'single'`/`"double"` strings (`\\`, `\"`, `\'` unescape; other
  backslashes are kept, as templates write regexes both ways), `true`, `false`.
- Operators by precedence: `||`; `&&`; `==` `!=` `<` `<=` `>` `>=`; `+` `-`; `*` `/` `%`;
  unary `!` `-`; parentheses. `+` concatenates when either side is a string; comparisons
  are numeric when both sides are numbers (or numeric strings), else string comparisons.
  `&&`/`||` short-circuit. Ternary `?:`, `=~`/`!~`, and bit operators are unsupported.
- Variables: `status_code`, `body`, `header`/`all_headers` (status line and headers),
  `response`/`raw`, `content_length`, `content_type`, `duration` (seconds), `host`,
  any other name as a response header (`set_cookie` is `Set-Cookie`, missing means no
  match), template variables, payloads, extractor values, and numbered forms (`body_2`).
- Functions: `contains`, `contains_all`, `contains_any`, `starts_with`/`startswith`,
  `ends_with`/`endswith`, `to_lower`/`tolower`, `to_upper`/`toupper`, `len`, `regex`,
  `replace`, `replace_regex`, `concat`, `trim`, `trim_space`, `trim_left`, `trim_right`,
  `trim_prefix`, `trim_suffix`, `to_string`/`tostring`, `to_number`, `substr`, `repeat`,
  `md5`, `sha1`, `sha256`, `base64`, `base64_decode`, `base64_py` and `mmh3` (favicon
  hashes), `hex_encode`, `hex_decode`, `url_encode`, `url_decode`, `compare_versions`
  (hashicorp/go-version constraints such as `'>= 8.0.0, < 8.10.2'`), `rand_base`,
  `rand_text_alpha`, `rand_text_alphanumeric`, `rand_text_numeric`, `rand_int`, `unix_time`.
- An evaluation that hits a missing value or a type error doesn't match (like Nuclei).
  A matcher must evaluate to `true`; a dsl extractor yields each non-empty value.
- Findings from DSL matchers carry no evidence string; the names of the matchers that
  fired are listed in the finding's other info (`Matched: x-frame-options, ...`).

Not supported (the template is skipped with this reason): `self-contained`, interactsh
(out-of-band), payload files, template inputs without a `--check-var`, JavaScript `flow`, `xpath`
extractors, regexes with lookaround or backreferences, DSL functions outside the list
(`date_time`, `wait_for`, `generate_jwt`, `hmac`, ...), `race`, `iterate-all`, digest
auth, `fuzzing`, and the non-HTTP protocols. On the nuclei-templates commit used during
development (17f5725, Oct 2026), 9,139 of 11,690 HTTP templates load (5,856 before the
DSL subset); the top reasons are `self-contained` (938), template inputs (554),
interactsh (535), and payload files (258). With `--check-var username=... --check-var
password=...` (523 of the 554 need just these), 9,655 load. `checks status` shows the
counts for the stored commit.

## brainproxy extensions

```yaml
id: bp-ssti-arith
info:
  name: Server-side template injection (arithmetic)
  severity: high
  confidence: high            # low | medium (default) | high
  remediation: Don't render user input as a template.
  tags: injection,ssti
scope: param                  # host (default) | request | param
http:
  - inject: ["{{7*191}}", "${7*191}", "<%= 7*191 %>"]   # literal values, no placeholders
    # inject-raw: true        # insert without escaping for the context
    matchers-condition: and
    matchers:
      - type: word
        words: ["1337"]
      - type: word
        part: baseline_body   # the original response of the attacked request
        words: ["1337"]
        negative: true
```

- `scope: host` runs once per origin (Nuclei's behaviour); `request` once per target
  request, with `{{BaseURL}}` = that request's URL without the query; `param` once per
  insertion point (query, form, JSON, and with `scan active --cookies`/`--inject-header`
  cookies and headers), sending each `inject` value.
- `path` requests reuse the attacked request's headers (cookies, auth) with the
  template's method, path, headers, and body.
- `info.confidence` sets the finding confidence (Nuclei has none; default medium).

## Ideas

- Payload files: store nuclei-templates' `helpers/` wordlists with the templates (258).
- `{{interactsh-url}}` could map to the OOB listener (`oob_payload`) with interactsh
  matchers as correlation.
- An index file in the store would let `checks list` skip parsing.
