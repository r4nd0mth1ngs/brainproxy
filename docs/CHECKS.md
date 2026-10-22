# Declarative checks

Checks are YAML files that the active scanner runs next to the ported ZAP rules (and,
for passive checks, the passive scanner next to its rules). The format is the HTTP subset
of [Nuclei templates](https://docs.projectdiscovery.io/templates/introduction) plus a few
brainproxy extensions, so community templates, brainproxy's own feed, and checks you (or an
agent) write load through the same parser and engine.

```sh
brainproxy checks update --source brainproxy     # brainproxy's own signed checks feed
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
| `brainproxy` | `<home>/checks/brainproxy/`, brainproxy's own signed feed, replaced as a whole by `checks update --source brainproxy` (see [The brainproxy feed](#the-brainproxy-feed)) |
| `nuclei` | `<home>/checks/nuclei/`, replaced as a whole by `checks update` (only templates that load are stored, plus the repository's `helpers/` payload files) |
| `local` | `<home>/checks/local/`, your own checks (any layout, `*.yaml`/`*.yml`) |
| `all` | all three (the feed first, so its checks win an id clash) |
| a path | a template file or a directory (recursive) |

`<home>` is `--home`/`BRAINPROXY_HOME`, else `$XDG_DATA_HOME/brainproxy`, else
`~/.local/share/brainproxy`. Checks only run when `scan active --checks` names them.
`--check-tags` (any of), `--check-exclude-tags` (default `dos,fuzz,intrusive`),
`--check-ids`, and `--check-severity` narrow the set; `--no-rules` skips the ZAP rules.
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
  unless `unsafe: true`); `headers`, `body`. A raw request's `@timeout: 20s` line sets its
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

Out-of-band: with an OOB listener running (`brainproxy oob start`, docs/OOB.md),
`{{interactsh-url}}` is a fresh listener payload for every request (one per sequence
with req-condition): `<token>.<domain>` in DNS mode, `<host>:<port>/<token>` in host
mode, so `http://{{interactsh-url}}/...` reaches the listener either way (DNS-only uses
such as `nslookup {{interactsh-url}}` need DNS mode). Variables using it are evaluated
again per request. Matchers on `interactsh_protocol`, `interactsh_request`,
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
  `md5`, `sha1`, `sha256`, `base64`, `base64_decode`, `base64_py` and `mmh3` (favicon
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
(`date_time`, `wait_for`, `generate_jwt`, `hmac`, ...), `race`, `iterate-all`, digest
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

### Passive checks

```yaml
id: CVE-2026-109618-php-version
passive: true
info:
  name: PHP2Shell PHP Remote Code Execution (Indicative)
  severity: high
http:
  - extractors:
      - type: regex
        part: header
        group: 1
        regex: ['(?im)^(?:x-powered-by|server):[^\r\n]*?\b(PHP/\d+\.\d+\.\d+\S*)']
    matchers: ...
```

- `passive: true`: the check sends nothing. Its blocks hold only `matchers`,
  `matchers-condition`, and `extractors`, which run on every recorded exchange the passive
  scanner sees (proxy, Replay, crawl, as `scan sources` sets), like a built-in passive rule.
  They see that one response: no `baseline_body`, numbered parts, `flow`, `scope`, or
  out-of-band matchers. Variables and placeholders work (`{{Host}}`, `{{Path}}`, ...
  from the recorded request).
- The passive scanner runs the passive checks of the brainproxy feed and of
  `<home>/checks/local/` (loaded once per process: restart a running proxy after an
  update). Findings have source `passive` and alert ref `check:<id>`. `scan active
  --checks` leaves passive checks out (its summary counts them as `passive`).

### Feed checks and built-in rules

- `info.replaces: <rule id>`: the check takes over a built-in rule. When it is loaded, the
  rule doesn't run; the check's findings keep the rule's id and alert ref, and `scan disable
  <id>` / `--exclude-rules <id>` switch the check off too. Only honoured for the signed
  brainproxy feed (elsewhere it is ignored), so a feed release can correct a built-in rule
  without a brainproxy release. Passive check `CVE-2026-109618-php-version` replaces passive
  rule 100001 and flags the same versions (a test runs both on the same cases).
- `info.defer-to: <rule id>`: a built-in rule does this check's job better; a scan that runs
  that rule drops the check. The feed's `CVE-2026-109619-php2shell-multipart` defers to
  active rule 100002, which also reads the scanned page's own headers and tells soft 404s
  apart, which the format can't yet.

## The brainproxy feed

brainproxy's own detections are published as checks in the `checks/` folder of the
brainproxy repository (`http/` active, `passive/` passive, `helpers/` payload files), so a
new detection for a fast-moving CVE arrives with an update, not a reinstall:

```sh
brainproxy checks update --source brainproxy           # r4nd0mth1ngs/brainproxy@main, checks/
brainproxy checks update --source brainproxy --ref v0.4.0
brainproxy checks update --source brainproxy --from ~/src/brainproxy   # offline: a checkout or its checks/
brainproxy checks status                               # serial, commit, counts, skipped
brainproxy scan active https://app.test/ --checks brainproxy
```

`checks update` prints what was added, changed, and removed (with check ids). In the
desktop app the Overview's *Rules and checks* card and *Settings › Rules & data* show the
installed feed and update it; with the daily update check on (*Settings › Rules & data*,
"Check GitHub for a new version once a day") the feed updates itself once a day, telling you
only when checks changed.
Guided scans (all depths) and active scans started from the Target tree add `--checks
brainproxy` once the feed is installed, and an active check tagged `quick-check` (and not
deferring to a built-in rule) gets its own one-click scan under *Scans › New scan*, like
*PHP2Shell check*: `scan active URL --no-rules --checks brainproxy --check-ids <id>`.

### Security

The feed decides what every install sends to its targets, so it is signed, and verified
before anything is stored:

- `feed.json` lists every file of the feed with its sha256, a format version, and a
  serial that grows with every release; `feed.sig` is an Ed25519 signature over it
  (prefixed with a fixed context string) by a key whose public half is compiled into
  brainproxy (`crates/core/src/checks/feed_keys.txt`; several may be listed for rotation).
  A pinned commit and tarball sha256 only prove what was downloaded; the signature proves
  who published it.
- An update refuses a feed that is unsigned, signed by an unknown key, or whose manifest
  doesn't match its signature, and any listed file that is missing or doesn't match its
  sha256. Files the manifest doesn't list are ignored; paths are plain relative ones under
  `http/`, `passive/`, or `helpers/`. Nothing is written until all of this checks out
  (tests tamper with files, the manifest, and the signature). An older serial than the
  installed one is refused as a rollback unless `--allow-downgrade`.
- `--from DIR` (air-gapped runners) goes through the same checks. The download itself is
  GitHub only, over verified TLS, inside the system scope, like the Nuclei templates.
- Feed checks are checks like any other: data, no code, every request through `Cx` (scope
  guard, rate limit, auth, stop), passive ones send nothing.
- A brainproxy build without a feed key (`feed_keys.txt` empty) accepts no feed.

### Signing the feed (maintainers)

```sh
brainproxy checks feed keygen --out ~/brainproxy-feed.key   # once; prints the public key
brainproxy checks feed sign checks --key ~/brainproxy-feed.key
brainproxy checks feed verify checks                        # against this build's keys
```

`keygen` writes the secret key owner-only and never overwrites one; keep it off the
repository and CI, on the maintainer's machine or in a password manager. Add the public key
to `crates/core/src/checks/feed_keys.txt` in a release before the first feed it signs, and
keep a retired key listed until every supported release knows its successor. `sign` refuses
a feed with a check that doesn't load, writes `feed.json` with a new serial, and signs it:
every change to `checks/` needs a new signature in the same pull request. Review feed pull
requests like code (two approvals): they decide what scanners send.

## Ideas

- An index file in the store would let `checks list` skip parsing.
