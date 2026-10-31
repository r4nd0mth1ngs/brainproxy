# Keeping detection rules up to date

Goal: pick up new and improved ZAP detection logic without hand-maintaining brainproxy
for every upstream change.

## The constraint

ZAP's scan rules are Java classes, not data. Their logic (how payloads are built, how
responses are compared, timing statistics, context analysis) lives in code, and ZAP
loads them as add-on JARs into a JVM. brainproxy is a single Rust binary with no JVM,
so it cannot load ZAP rules as they are. Embedding a JVM would defeat the "lightweight,
fast, static binary" goal, and auto-translating arbitrary Java at runtime isn't reliable.

What *is* data in ZAP: pattern lists the rules read (`application_errors.xml`,
`debug-error-messages.txt`, `URL-information-disclosure-messages.txt`,
`hidden_files.json`, the retire add-on's Retire.js database `jsrepository.json`) and the
alert texts in `Messages.properties`.

So "automatic" splits into three layers.

## Layer 1: drift detection (implemented)

Know exactly when upstream changes something we ported, with no manual tracking.

- Every ported file starts with `//! Ported from ZAP <Class> (<addon>, Apache License 2.0).`
- `zap-sync.json` pins the zap-extensions commit the ports are based on, lists the data
  files we copied, records rules skipped on purpose, and lists rules covered by generated
  feed checks instead of a port (`feed_rules`: the generator and the upstream data it reads).
- `scripts/zap_drift.py` maps the headers to upstream Java paths and reports:
  rules changed since the pinned commit (with upstream commit subjects), rules removed or
  renamed upstream, changed data files, feed checks to regenerate (their rule or data
  changed), and upstream rules not ported yet.
- `.github/workflows/zap-drift.yml` runs it weekly and keeps one open issue
  ("ZAP rule drift", label `zap-drift`) updated, closing it when in sync.

Porting a change then means: read the upstream diff, update the Rust rule and its tests,
bump `commit` in `zap-sync.json`. The specs-then-port workflow used for the initial ports
(agents extract an exact spec from the Java, others port it in isolated worktrees, every
rule has positive and negative tests) works for these updates too.

**Next step (optional):** run that porting loop automatically from the drift issue with a
coding agent in CI (e.g. the Claude Code GitHub Action) that opens a pull request with the
ported change and tests for human review. Detection stays deterministic; only the
translation uses an LLM, and nothing merges without review and green CI.

## Layer 2: runtime data sync (implemented)

Pattern lists update without a new brainproxy release (`crates/core/src/data.rs`):

```sh
brainproxy scan data status                  # embedded or downloaded copy per file, entry counts
brainproxy scan data update [--ref main]     # zap-extensions at a branch/tag/commit
brainproxy scan data update --from DIR       # zap-extensions checkout, or a dir with the files
brainproxy scan data reset                   # back to the embedded copies
```

- The files are the ones in `zap-sync.json`: `application_errors.xml` (90022),
  `debug-error-messages.txt` (10023), `URL-information-disclosure-messages.txt`
  (10024, 10025), `hidden_files.json` (40035), and `jsrepository.json` (10003, the
  Retire.js database of vulnerable JavaScript library versions, which ZAP refreshes from
  Retire.js regularly).
- The ref is resolved to a commit (GitHub API) and every file is fetched at that commit
  from raw.githubusercontent.com: only GitHub, verified TLS, through the guarded client
  with the system scope applied (a locked-down runner refuses; the provisioner uses
  `--from`).
- Each file is parsed by the rules' own parser (regexes must compile) and must keep at
  least half the embedded entry count; a rejected file keeps the previous copy. Accepted
  files go to `<home>/rules/` with `manifest.json` (ref, commit, sha256, entries).
- At startup a rule uses the stored copy only if the manifest lists it, its sha256 still
  matches, and it validates; otherwise the embedded copy. New data applies to commands
  started afterwards (restart a running proxy).

## Layer 3: declarative checks (implemented)

See [CHECKS.md](CHECKS.md). One format, the HTTP subset of Nuclei templates plus
brainproxy extensions (`scope: host|request|param`, `inject`, `info.confidence`, matcher
part `baseline_body`), so community templates and checks an agent writes go through the
same parser and the same engine. Checks run as active rules through `Cx` (scope guard,
auth, rate limit) and only when `scan active --checks` selects them.

`brainproxy checks update` pulls the `nuclei-templates` repository (MIT, updated daily,
thousands of CVE/exposure/misconfiguration checks) at a commit, stores the HTTP templates
that load in `<home>/checks/nuclei/`, and records the commit, tarball sha256, and skip
reasons. Templates that use unsupported features (JavaScript flows, `self-contained`, ...)
are listed, not half-run. Templates that need an out-of-band listener or inputs are kept and
load when `brainproxy oob start` is running or `--check-var` is passed; about 89% of the HTTP
templates are stored (10,434 of 11,690 at the pinned version).

ZAP itself has no declarative rule format (its scripts are JavaScript/Zest code), so
layer 3 complements the ZAP ports rather than replacing them: ZAP's generic, logic-heavy
checks (SQL injection, XSS, path traversal) stay as maintained Rust ports tracked by
layer 1; fast-moving CVE and exposure checks come in as data through layer 3.

## Summary

| Kind of change | How it reaches brainproxy |
|---|---|
| ZAP rule logic changes | Weekly drift issue, then a port (optionally an automated PR) |
| ZAP pattern list changes | `scan data update` at runtime (layer 2) |
| New CVE/exposure checks | `checks update` (Nuclei templates), `checks update --source brainproxy` (brainproxy's signed feed, also daily from the app), and your own checks (layer 3) |
| New ZAP rules | Listed under "not ported yet" in the drift report |
