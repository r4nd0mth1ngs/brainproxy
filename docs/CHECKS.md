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
- Templates are data: nothing in them is executed. Anything outside the supported subset
  (DSL, code, JavaScript, headless, other protocols) makes the template unsupported; it is
  listed with a reason, never half-run.

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
Loading is parallel and cheap (about 0.6 s for the ~5,900 stored Nuclei templates);
regexes compile on first use.

## Supported Nuclei subset

Top level: `id`, `info` (`name`, `severity` info|low|medium|high|critical|unknown,
`description`, `remediation`, `reference`, `classification.cwe-id`, `tags`), `variables`
(strings, may use placeholders), and `http` (or the older `requests`).

Request blocks:

- `method` + `path` list, or `raw` requests (line endings normalized, Content-Length fixed
  unless `unsafe: true`); `headers`, `body`.
- `payloads` (inline lists only) with `attack` batteringram | pitchfork | clusterbomb, at
  most 1000 combinations per block.
- `matchers` with `matchers-condition` and|or: `word` (incl. `encoding: hex`), `regex`,
  `status`, `size`, `binary`; `condition`, `negative`, `case-insensitive`; parts `body`
  (default), `header`, `all`/`response`/`raw`, or one response header (`content_type`).
- `extractors`: `regex` (with `group`) and `kval`; `internal: true` extractors feed later
  requests as `{{name}}`. A block with only extractors reports what they extract.
- `stop-at-first-match`, `redirects`/`host-redirects` (up to 5, in scope).
- Ignored as harmless: `max-redirects`, `cookie-reuse`, `disable-cookie`, `max-size`,
  `read-all`, `threads`, `skip-variables-check`, `id`, `name`.

Placeholders: `{{BaseURL}}`, `{{RootURL}}`, `{{Hostname}}` (host[:port]), `{{Host}}`,
`{{Port}}`, `{{Path}}`, `{{File}}`, `{{Scheme}}`, `{{randstr}}`/`{{randstr_N}}`, variables,
payload names, and extractor names. For the default host scope `BaseURL` is the origin
(`https://app.test:8443`).

Not supported (the template is skipped with this reason): DSL matchers/extractors and
DSL expressions in placeholders, `flow`, `self-contained`, interactsh (out-of-band), payload
files, numbered parts (`body_2`, multi-request conditions), `json`/`xpath` extractors, regexes
with lookaround or backreferences, `req-condition`, `race`, `iterate-all`, digest auth,
`fuzzing`, and the non-HTTP protocols. On the nuclei-templates commit used during
development (17f5725, Oct 2026), 5,856 of 11,690 HTTP templates load; the top reasons are
DSL matchers (2,488), `flow` (1,139), and `self-contained` (938). `checks status` shows the
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

- A small DSL subset (`status_code`, `contains()`, `len()`, `&&`/`||`) would load about
  2,500 more templates.
- `{{interactsh-url}}` could map to the OOB listener (`oob_payload`) with interactsh
  matchers as correlation.
- An index file in the store would let `checks list` skip parsing.
