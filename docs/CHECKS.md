# Declarative checks

Checks are YAML files that the active scanner runs next to the ported ZAP rules. The
format is the HTTP subset of [Nuclei templates](https://docs.projectdiscovery.io/templates/introduction)
plus a few brainproxy extensions, so community templates and checks you (or an agent)
write load through the same parser and engine.

```sh
brainproxy checks update                         # Nuclei HTTP templates, pinned to a commit
brainproxy checks update --source brainproxy     # brainproxy's own signed checks (below)
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
| `nuclei` | `<home>/checks/nuclei/`, replaced as a whole by `checks update` (only templates that load are stored, plus the repository's `helpers/` payload files) |
| `brainproxy` | `<home>/checks/brainproxy/`, the signed brainproxy feed, replaced as a whole by `checks update --source brainproxy` |
| `local` | `<home>/checks/local/`, your own checks (any layout, `*.yaml`/`*.yml`) |
| `all` | all three |
| a path | a template file or a directory (recursive) |

`<home>` is `--home`/`BRAINPROXY_HOME`, else `$XDG_DATA_HOME/brainproxy`, else
`~/.local/share/brainproxy`. Checks only run when `scan active --checks` names them.
`--check-tags` (any of), `--check-exclude-tags` (default `dos,fuzz,intrusive`),
`--check-ids`, and `--check-severity` narrow the set; `--no-rules` skips the ZAP rules.
`--check-severity` is a floor and `--check-severity-max` a cap on the template's severity
(info < low < medium < high < critical, `unknown` counts as info), so a run can be split into
bands: `--check-severity high` first (critical included), then `--check-severity-max medium`.
`--check-severity critical` is critical only; `--check-severity high --check-severity-max high`
is high without critical. A cap below the floor is refused (exit 2). `checks list --severity`
and `--severity-max` preview the same band.
`--check-include-tags` adds checks with those tags, or in a folder of that name, whatever
the other filters say (Nuclei's `-itags`). The desktop app's scans use
`--check-include-tags eol` for the end-of-life checks in nuclei-templates'
`technologies/eol` (outdated PHP, nginx, Apache httpd, WordPress, Drupal, Exchange, ...),
which are rated info; new ones arrive with `checks update`. `checks list --include-tags`
shows the same selection.
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
  unless `unsafe: true`); `headers`, `body`. A `path` is sent as written, like Nuclei:
  `..`, `%2e%2e` and `\` segments are not resolved (only spaces and other bytes a request
  line can't hold are percent-encoded). A raw request's `@timeout: 20s` line sets its
  timeout; otherwise `scan active --check-timeout` applies (default 10 s).
- `payloads` with `attack` batteringram | pitchfork | clusterbomb, at most 1000
  combinations per block. A payload is an inline list or a file (one value per non-empty
  line, at most 4 MiB), e.g. `helpers/wordlists/wp-users.txt`. File names are relative
  paths of plain components (no `..`, no absolute paths), looked up in the template's
  directory and its parents up to the load root (the directory given to `--checks` or
  `checks validate`, or a file's own directory); the resolved file, symlinks followed,
  must stay inside that root. `checks update` stores nuclei-templates' `helpers/` (about
  5 MiB, capped at 64 MiB) next to `http/`, so stored templates find them; to validate a
  checkout, pass its root rather than its `http/` directory.
- `matchers` with `matchers-condition` and|or: `word` (incl. `encoding: hex`), `regex`,
  `status`, `size`, `binary`, `dsl`; `condition`, `negative`, `case-insensitive`,
  `internal` (counts for the block and `flow`, but a block whose matchers are all
  internal reports nothing); parts `body` (default), `header`, `all`/`response`/`raw`,
  one response header (`content_type`), or a numbered part (`body_2`). Placeholders in a
  DSL expression's strings are filled before it is evaluated (`contains(body,
  '{{randstr}}')`); one without a value stays as written.
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

Out-of-band: with an OOB listener running (`brainproxy oob start`, docs/OOB.md),
`{{interactsh-url}}` is a fresh listener payload for every request (one per sequence
with req-condition): `<token>.<domain>` in DNS mode, `<host>:<port>/<token>` in host
mode, so `http://{{interactsh-url}}/...` reaches the listener either way (DNS-only uses
such as `nslookup {{interactsh-url}}` need DNS mode). Variables using it, directly or
through another variable, are evaluated again per request. Matchers on `interactsh_protocol`, `interactsh_request`,
`interactsh_response`, `interactsh_ip` (as `part:` or DSL variables) are evaluated when
an interaction with the request's token is correlated, at the end of the scan
(`--oob-wait`) or by a later `oob poll`: with `matchers-condition: and`, the request is
registered only if the other matchers held on its response, and each interaction must
then pass every interactsh matcher; with `or`, a match of the other matchers reports at
once, else any interactsh matcher passing raises the finding. DSL interactsh matchers
also see the response values they use (kept with the payload), and an attack that got no
response is still registered when the response matchers don't need to hold.
`interactsh_protocol` is `dns`, `http` (a TLS ClientHello counts, as HTTPS does for
interactsh), `ldap`, or `tcp`; `interactsh_request` is the received bytes;
`interactsh_response` is empty. Extractors over interactions are dropped (the finding
shows the interaction). Each interaction is checked on its own (Nuclei also evaluates per
interaction). Without a listener, or with `--no-oob`, these templates are not loaded
(`checks list`/`validate` look for a running listener in the project too); `checks
update` stores them.

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
  `md5`, `sha1`, `sha256`, `hmac` (`hmac('sha256', data, key)`, in hex), `generate_jwt`
  (`generate_jwt('{"sub":"1"}', 'HS256', key[, max_age_seconds])`; HS256/384/512, RS256 with
  a PEM key), `base64`, `base64_decode`, `base64_py` and `mmh3` (favicon
  hashes), `hex_encode`, `hex_decode`, `url_encode`, `url_decode`, `compare_versions`
  (hashicorp/go-version constraints such as `'>= 8.0.0, < 8.10.2'`), `rand_base`,
  `rand_text_alpha`, `rand_text_alphanumeric`, `rand_text_numeric`, `rand_int`, `unix_time`.
- An evaluation that hits a missing value or a type error doesn't match (like Nuclei).
  A matcher must evaluate to `true`; a dsl extractor yields each non-empty value.
- Findings from DSL matchers carry no evidence string; the names of the matchers that
  fired are listed in the finding's other info (`Matched: x-frame-options, ...`).

Not supported (the template is skipped with this reason): `self-contained`, interactsh
without an OOB listener, payload files that can't be found inside the root, template inputs without a `--check-var`, JavaScript `flow`, `xpath`
extractors, regexes with lookaround or backreferences, DSL functions outside the list
(`date_time`, `wait_for`, ...), `race`, `iterate-all`, digest
auth, the raw annotations `@Host` and `@tls-sni`, `fuzzing`, and the non-HTTP protocols. On the nuclei-templates commit used during
development (17f5725, Oct 2026), 9,139 of 11,690 HTTP templates load (5,856 before the
DSL subset) and 9,392 with payload files; the top remaining reasons are
`self-contained` (938), interactsh (535), and template inputs (534). With an OOB listener
9,870 load; with a listener and `--check-var username=... --check-var password=...`,
10,411 (`checks update` stores 10,434). `checks status` shows the counts for the stored
commit.

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
- `body-hex: 8f00807b7d03` (instead of `body`, on `path` requests): the body as bytes,
  sent as is, for data that isn't text, such as a compressed body. No placeholders.
- The tag `quick-check` on a brainproxy feed check makes it a one-click check under
  Scans › New scan › CVE quick checks (`scan active --no-rules --checks brainproxy
  --check-ids <id>`).

### Passive checks

```yaml
id: bp-brotli-request-body-accepted
info: {name: Brotli-compressed request body accepted, severity: info}
scope: passive
http:
  - matchers-condition: and
    matchers:
      - type: regex
        part: request_header          # the recorded request's line and headers
        regex: ['(?im)^content-encoding:[^\r\n]*\bbr\b']
      - type: dsl
        dsl: ["status_code >= 200 && status_code < 300"]
```

`scope: passive` checks send nothing. The passive scanner runs them with the built-in
passive rules on every recorded exchange (proxy, send, and crawl traffic, as configured
under Settings › Passive), and findings are recorded with source `passive`. A block has
only matchers and extractors: no `path`, `raw`, `body`, `headers`, `payloads`, or
`inject`, and nothing that needs more than one response (`flow`, numbered parts,
`baseline_body`, interactsh). Matchers and extractors see the recorded response as an
active check sees its response, plus the part (and DSL variable) `request_header`.
Passive checks come from the `brainproxy` and `local` stores; `scan active` ignores them.
`scan rules` lists them with the passive rules (by check id), and `scan disable <check
id>` / `scan enable <check id>` switch one off or on for the project, as for rules.

## The brainproxy feed

brainproxy's own checks for new CVEs ship as data, between releases: `checks update
--source brainproxy`, the Overview's **brainproxy checks** row, and, with the daily version
check on (Settings › Rules & data), once a day by itself. Guided Standard and Thorough
scans include its active checks.

- The feed is the repository's `feed/` folder: templates, `feed.json` (every file with its
  sha256), and `feed.sig`, an Ed25519 signature over `feed.json` by a key listed in
  `TRUSTED_KEYS` (`crates/core/src/checks/feed.rs`), so compiled into brainproxy.
- An update resolves the ref to a commit, fetches `feed.json` and `feed.sig` from
  raw.githubusercontent.com at that commit, and checks the signature over the exact bytes
  before parsing them. Then it fetches only the files `feed.json` lists and checks each
  hash. Anything wrong fails the update and keeps the installed store; the manifest
  records the commit, the sha256 of `feed.json`, the signing key's id, and which checks
  the update added, changed, or removed (`checks update` prints them; the app says
  what arrived). `--from DIR` (a checkout, or the `feed/` folder itself) applies the
  same checks offline.
- A compromised repository or account can't push checks to users without the private
  key, and even signed checks run through `Cx` like all others: scope guard, rate limits,
  and auth stay enforced, and the format stays declarative.

Publishing a check (maintainers):

```sh
brainproxy checks validate feed/                                  # loads?
brainproxy checks feed sign feed --key ~/.config/brainproxy-feed/signing.key
brainproxy checks feed verify feed                                # what users will check
```

`cargo test` fails while `feed/` and its signature disagree (`repository_feed_verifies`),
so CI catches a check committed without signing. Keys: `checks feed keygen --out FILE`
writes a private key (owner-only) and prints the public key for `TRUSTED_KEYS`. Keep the
private key out of the repository and backed up. To rotate, add the new public key,
release, sign with the new key, then remove the old one in a later release.

Generated checks: `feed/passive/php/` covers ZAP's server-side version rule as one passive
check per severity band (each CVE a named matcher, listed in the finding's `Matched:`
line), generated by `scripts/php_feed.py` from ZAP's PHP advisory data at the commit
pinned in `zap-sync.json`. When the drift report lists it, bump the pin, run the script,
then validate and sign as above.

## Ideas

- An index file in the store would let `checks list` skip parsing.
