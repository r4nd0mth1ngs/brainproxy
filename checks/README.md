# brainproxy checks feed

brainproxy's own detection checks, published as data so that a new detection
reaches users with `brainproxy checks update --source brainproxy` (or the
desktop app's **Update** button) instead of a new release. The format is the
one in [docs/CHECKS.md](../docs/CHECKS.md): the Nuclei HTTP subset plus
brainproxy extensions.

| Folder | What |
|---|---|
| `http/` | Active checks: they send requests, through the scanner's scope guard, rate limit and auth |
| `passive/` | Passive checks (`passive: true`): matchers over recorded traffic, nothing is sent |
| `helpers/` | Payload files that checks refer to |

`feed.json` lists every file with its sha256 and a serial; `feed.sig` signs it
with a key built into brainproxy. Clients verify both before storing anything,
so **every change here must be re-signed** (`brainproxy checks feed sign
--key <secret key> checks`) by a maintainer, and reviewed like code: a check in
this folder decides what every brainproxy install sends to its targets.
Keep checks declarative and small; tag one `quick-check` to offer it as a
one-click scan in the desktop app.
