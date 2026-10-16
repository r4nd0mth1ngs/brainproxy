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
`hidden_files.json`) and the alert texts in `Messages.properties`.

So "automatic" splits into three layers.

## Layer 1: drift detection (implemented)

Know exactly when upstream changes something we ported, with no manual tracking.

- Every ported file starts with `//! Ported from ZAP <Class> (<addon>, Apache License 2.0).`
- `zap-sync.json` pins the zap-extensions commit the ports are based on, lists the data
  files we copied, and records rules skipped on purpose.
- `scripts/zap_drift.py` maps the headers to upstream Java paths and reports:
  rules changed since the pinned commit (with upstream commit subjects), rules removed or
  renamed upstream, changed data files, and upstream rules not ported yet.
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

## Layer 2: runtime data sync (designed)

Pattern lists can update without a new brainproxy release:

- `brainproxy rules update` downloads the data files listed in `zap-sync.json` from
  zap-extensions at a chosen ref (default: the latest release tag of each add-on), checks
  them (parse, size limits, sha256 recorded), and stores them under
  `~/.local/share/brainproxy/rules/` with a manifest.
- Rules load the downloaded copy when present and valid, else the copy embedded at build
  time. `brainproxy rules status` shows which version each rule uses.
- Downloads are pinned to a ref and verified; a bad file is rejected and the embedded copy
  stays in use. On a locked-down runner this can be done by the provisioner instead of the
  agent.

This covers new error signatures, hidden-file paths, and sensitive-parameter names, which
are the most frequent kinds of upstream rule changes.

## Layer 3: declarative checks (recommended next feature)

For checks that should arrive as content, not code, support a declarative format:

- **brainproxy YAML checks** (our own format, sketched in `docs/RESEARCH.md`): request
  mutations plus matchers (status, regex on headers/body, timing, extract), loaded from
  `~/.local/share/brainproxy/checks/` and project directories, run by the active engine
  through the same scope guard.
- **Nuclei template subset**: the community `nuclei-templates` repository (MIT) is updated
  daily with thousands of checks, mostly for known CVEs, exposures, and misconfigurations.
  Supporting the HTTP subset of the template format (requests with `{{BaseURL}}`
  placeholders, matchers, extractors) lets `brainproxy checks update` pull those directly.
  Templates that use unsupported features are skipped and listed, not half-run.

ZAP itself has no declarative rule format (its scripts are JavaScript/Zest code), so
layer 3 complements the ZAP ports rather than replacing them: ZAP's generic, logic-heavy
checks (SQL injection, XSS, path traversal) stay as maintained Rust ports tracked by
layer 1; fast-moving CVE and exposure checks come in as data through layer 3.

## Summary

| Kind of change | How it reaches brainproxy |
|---|---|
| ZAP rule logic changes | Weekly drift issue, then a port (optionally an automated PR) |
| ZAP pattern list changes | `rules update` at runtime (layer 2) |
| New CVE/exposure checks | Declarative templates, including Nuclei's (layer 3) |
| New ZAP rules | Listed under "not ported yet" in the drift report |
