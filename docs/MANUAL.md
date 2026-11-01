# brainproxy manual

brainproxy is a web application security testing tool: an intercepting proxy, a request
editor, a fuzzer, a crawler, passive and active scanners, out-of-band callbacks, and
reports. Every feature is a command-line tool with JSON output, so scripts and AI agents
can drive it. The desktop app is optional and runs the same commands underneath.

Only test systems you are authorized to test.

Contents: [Install](#install) · [Concepts](#concepts) · [First engagement (desktop app)](#first-engagement-desktop-app)
· [The tools](#the-tools) · [Command line](#command-line) · [Agents and MCP](#agents-and-mcp)
· [Rules, checks, and wordlists](#rules-checks-and-wordlists) · [Troubleshooting](#troubleshooting)

---

## Install

Downloads are on the GitHub release page. Their names carry the version, written `<version>`
below (e.g. `brainproxy-gui-0.3.9-macos-arm64.dmg`; releases up to 0.3.8 leave it out). Each
file has a `.sha256` next to it, and `SHA256SUMS` lists them all: check what you downloaded
with `sha256sum -c --ignore-missing SHA256SUMS`.

| You want | Download |
| --- | --- |
| Desktop app on a Mac (Apple silicon) | `brainproxy-gui-<version>-macos-arm64.dmg` |
| Desktop app on Debian, Ubuntu, or Kali | `brainproxy-gui-<version>-linux-x86_64.deb` |
| Desktop app on another Linux, no install | `brainproxy-gui-<version>-linux-x86_64.AppImage` |
| Desktop app on Windows 10 or 11 | `brainproxy-gui-<version>-windows-x86_64-setup.exe` (or the `.msi`) |
| Command line only (servers, agents, Kali) | `brainproxy-<version>-linux-x86_64` or `brainproxy-<version>-linux-arm64` |
| Command line only on Windows | `brainproxy-<version>-windows-x86_64.exe` |

- **macOS:** open the `.dmg` and drag brainproxy to Applications. The app isn't signed
  yet: open it once, then choose System Settings → Privacy & Security → Open Anyway, or run
  `xattr -dr com.apple.quarantine /Applications/brainproxy.app`.
- **Debian/Ubuntu/Kali:** `sudo apt install ./brainproxy-gui-<version>-linux-x86_64.deb`. This installs
  WebKitGTK if it is missing and adds a menu entry.
- **AppImage:** `chmod +x brainproxy-gui-<version>-linux-x86_64.AppImage`, then run it. It needs
  WebKitGTK 4.1, which current distributions include.
- **Windows:** run the `-setup.exe` (installs for your user) or the `.msi`. The installer
  isn't signed yet, so SmartScreen shows "Windows protected your PC": choose More info →
  Run anyway. The app uses the WebView2 runtime that comes with Windows 10 and 11. The
  command-line `.exe` needs no install; rename it `brainproxy.exe` and put it on your `PATH`.
- **Command line:** the Linux binaries are static with no dependencies:
  `sudo install -m755 brainproxy-<version>-linux-x86_64 /usr/local/bin/brainproxy`.

The desktop app includes the command-line tool, so you don't need both.

**Updating.** The desktop app checks GitHub for a new version once a day and shows it on the
Overview, with a button that downloads the installer to your Downloads folder (checked
against its published sha256) and one that opens it. Close brainproxy before installing.
Settings › Rules & data turns the check off, or makes the download automatic. On the
command line, `brainproxy update check` says whether a newer release exists and
`brainproxy update download` saves the binary for this machine under its release name, e.g.
`brainproxy-0.3.9-linux-x86_64` (`--kind gui` for the app installer, `--dir` for another
folder). Neither installs anything. The AppImage is larger
than the download limit; get it from the release page.

### Container image

The `Dockerfile` packages the command-line tool for headless and CI use: a small Alpine
image (about 30 MB) that runs as a non-root user (UID 1000). No image is published, so build
it from a checkout:

```sh
docker build -t brainproxy .
docker run --rm brainproxy --version
```

Arguments go straight to `brainproxy`. It works in `/work`, so that's where to mount a
volume: the project file (`brainproxy.bpdb` unless `--project` or `BRAINPROXY_PROJECT` says
otherwise) goes there. So does the [data folder](#concepts), at `/work/.brainproxy`
(`BRAINPROXY_HOME`). It holds the CA's private key, so keep it out of anything you commit or
publish: if you mount a Git checkout, add `.brainproxy/` and `*.bpdb*` to its `.gitignore`.
Without a volume, everything is lost with the container.

```sh
# A named volume needs no setup.
docker run --rm -v brainproxy:/work brainproxy engagement start --target app.example.com
docker run --rm -v brainproxy:/work brainproxy crawl https://app.example.com/

# A host folder: run as its owner, or the user in the image may not be able to write to it.
docker run --rm --user "$(id -u):$(id -g)" -v "$PWD:/work" brainproxy report html -o report.html
```

Things that work differently in a container:

- **Addresses:** `127.0.0.1` is the container itself, not your machine. To reach a target in
  another container, put both on one Docker network (`docker run --network ...`) and scope
  the target's exact name (`engagement start --target web:8000`). A wildcard doesn't cover
  a private address, as everywhere else.
- **Servers and background jobs:** `proxy start`, `oob start`, and `--background` run in the
  background, and the container stops, taking them with it, as soon as its main command
  returns. Use the foreground `proxy run` or `oob run`, and leave `--background` off. To reach
  the proxy from outside, listen on all of the container's addresses and publish the port on
  your own machine only:

  ```sh
  docker run -d --name proxy -v brainproxy:/work -p 127.0.0.1:8080:8080 brainproxy proxy run --listen 0.0.0.0:8080
  ```

  `--init` isn't needed here: brainproxy looks at PID 1 like any other process, it just never
  sends it a signal. `docker exec proxy brainproxy proxy status` reports it, and so does a
  different container on the same volume, where the process can't be seen: the proxy holds
  `brainproxy.bpdb-proxy.lock` while it runs, and that is what `proxy status` goes by there
  (`oob run` does the same with `-oob.lock`). This needs a volume where file locks work between
  containers, as on a local disk. The address and PID shown are the ones inside the proxy's
  container, so from elsewhere connect by container name.

  Background jobs and fuzz runs do the same, each with a lock file of its own while it runs
  (`brainproxy.bpdb-job-1.lock`, `-fuzz-1.lock`), so they can be watched and stopped from a
  different container: `job status|wait|stop`, `fuzz status|stop` and `project stop` work there.
  If its container is killed, the next look from anywhere marks it failed.

  Stop it with `docker stop proxy`. `proxy stop` works too, by asking through the project file,
  and only if the proxy answers. Through `docker exec` it ends with exit code 137 and no output,
  because the container is gone as soon as its main process is.

  Two things this doesn't cover: an older brainproxy in another container on the same volume
  still clears the record of a running proxy, and on macOS and Windows hosts the lock isn't
  taken, so a proxy on the host and one in a container aren't kept apart for the same project.

- **`crawl --browser`:** needs a Chromium-based browser, which the image leaves out because it
  takes the image from about 30 MB to over 800 MB. Without one, `--browser` stops with an
  error and the plain crawler still works. To add it, build on the image (here tagged
  `brainproxy-chromium`):

  ```dockerfile
  FROM brainproxy
  USER root
  RUN apk add --no-cache chromium
  USER brainproxy
  ```

  Docker's default seccomp profile stops Chromium's sandbox from starting, so the browser
  fails with `Failed to move to new namespace`. `-e BRAINPROXY_BROWSER_NO_SANDBOX=1` runs it
  without the sandbox, which leaves the container as the only barrier around pages from the
  target, so test only sites you trust that far. Also pass `--init`, which cleans up the
  browser's exited processes:

  ```sh
  docker run --rm --init -e BRAINPROXY_BROWSER_NO_SANDBOX=1 -v brainproxy:/work brainproxy-chromium \
      crawl https://app.example.com/ --browser
  ```

---

## Concepts

**Project.** One file (`something.bpdb`) holds everything for an engagement: recorded
traffic, findings, scans, settings, and login profiles. Copy it to share or archive the
work. Several tools (the app, the CLI, an agent) can use the same project at the same time.

**Engagement scope.** Each project has a fixed list of targets that may be contacted,
such as `app.example.com`, `*.example.com`, `10.0.0.0/24`, or `api.example.com:8443`, plus
optional exclusions. It is set once, when the project is created, and **can never be
changed**. brainproxy refuses every request outside it, including redirects, links found
by the crawler, and requests from a browser using the proxy. For a different scope, start
a new engagement.

**Proxy scope.** A separate, changeable list that decides which proxied traffic is
recorded and intercepted. It is empty by default, which means everything the engagement
allows.

**Data folder.** The interception certificate (CA), downloaded rule data, and Nuclei
templates live once per user (`~/.local/share/brainproxy`, on Windows
`%APPDATA%\brainproxy`) and are shared by all projects. A project file gets the
permissions of the folder it is saved in: keep it in your own folders on a shared machine.

---

## First engagement (desktop app)

1. **Start a new engagement.** On the welcome screen choose *New engagement*:
   - Give it a name.
   - Choose where to save the project file.
   - List the targets in scope. You can paste URLs; they are reduced to host and port.
   - Optionally add hosts that must never be contacted.
   - Read the note that the scope is locked, confirm you have permission, and create it.
2. **Download rules and checks.** The Overview shows *Download the latest scan rules and
   checks* until you've done it once. Download both the ZAP rule data and the Nuclei
   templates.
3. **Explore the site.** The proxy starts automatically when a project opens (port 8080, or
   the next free one). Click **Open browser** in the top bar and pick a browser. It opens
   in its own profile, sends everything through the proxy, and trusts brainproxy's
   certificate. Your everyday browser is untouched. Log in and click through the
   application; requests appear in **Proxy › Traffic** and the **Site map**.
4. **Scan.**
   - **Guided:** the Overview's *Guided scan* asks for the website, whether to log in, and
     how thorough to be (Quick, Standard, Thorough) and how hard it may push the site
     (Gentle, Normal, Fast), then runs and explains the results.
   - **Yourself:** in **Scans › New scan**, *Crawl and audit* is the default. It crawls the
     site, then attacks every request it found, with the Nuclei templates included at high
     severity and above.
5. **Review.** **Findings** groups issues by type and risk. Each one shows a description,
   evidence, the solution, references, and the request and response. Mark false positives
   and confirmed issues; send a request to **Replay** to verify it by hand.
6. **Report.** **Findings › Report…** saves a readable HTML report, leaving out false
   positives: a summary in plain words, what to fix first, then each issue with what it
   means, how to fix it, and where it was found, with the technical evidence folded away.
   Print it from a browser to make a PDF. On the command line: `brainproxy report html -o
   report.html` (also `markdown`, `json`, `sarif`).
7. **Retest.** After fixes, scan again and use the Findings comparison: *Not found again
   by* a scan lists what that scan covered but no longer finds, likely fixed.

---

## The tools

The sidebar groups the tools by what you are doing.

### Overview
- **Guided scan:** shown until a project has a scan; after that, open it with *Guided
  scan* in the Tasks card or in **Scans › New scan**.
- **Update:** shown when a newer brainproxy is out, with Download, Open installer, and
  What's new.
- **Rules and checks:** status of the ZAP rule data, brainproxy checks (signed checks for new CVEs, updated daily when the version check is on) and Nuclei templates, with downloads.
- **Issue counts by risk, recent findings, running tasks, traffic statistics.**

### Site map
- **Map:** a tree of hosts and paths built from recorded traffic. Dots show the highest
  risk found on each node.
- **Scope:** *In scope only* (on by default) hides hosts the engagement refused, which are
  mostly browser background calls. *Include scanner and fuzzer requests* shows attack
  traffic too.
- **Actions:** right-click a node or request to send it to Replay, crawl from there, run an
  active scan of that branch or request, or copy the URL.
- **Scope tab:** shows the engagement, checks whether a host would be allowed, and edits
  the proxy scope.

### Proxy
- **Intercept:** turn it on to hold requests (and optionally responses) before they are
  sent. Edit a held message and Forward it, or Drop it. Requests outside the engagement are
  never held, because they are refused anyway. Unanswered messages are forwarded after a
  timeout (Settings › Intercept options).
- **Traffic:** everything that went through the proxy, Replay, the crawler, scanners, and
  imports.
  - **Filters:** text, source, status, static assets, and out-of-scope requests (hidden by
    default).
  - **Viewer:** select a row to see the request and response (Raw, Pretty, Hex, search).
  - **Actions:** right-click to send to Replay, Fuzzer, or Diff, add a note, or highlight.
- **WebSockets:** every WebSocket connection a browser opened through the proxy, and the
  ones Replay opened. Select a connection to see its messages in both directions (→ to the
  server, ← to the client), with pings, pongs and the close; select a message to read its
  payload. Compressed messages (permessage-deflate) are shown decompressed and fragmented
  ones joined. Right-click a connection or a message to send it to Replay.
  - **Fragmented messages** are buffered until their last fragment arrives, even with
    Intercept off, so the other side gets them all at once rather than piece by piece.
  - **Size limit:** a frame or message over 16 MB is relayed unchanged but not recorded, and
    neither is anything after it in that direction; messages that way can't be held any more
    either. The connection's note says so. A message can also be left out when the disk can't
    keep up: it still goes through, and the note counts what is missing.
  - **Intercept** holds WebSocket messages too: tick **WS to server** and/or **WS to client**.
    Edit the payload and Forward it, or Drop it (it is never delivered). Control frames are
    never held, and pings and pongs keep flowing while a message waits, so the connection's
    heartbeat doesn't time out; later messages wait behind the held one. Once a full message's
    worth (about 17 MB) is waiting, brainproxy stops reading from that side until the decision
    or the timeout, and pings and pongs from that side wait too. The other direction isn't
    affected. A message still held when its connection ends is marked dropped. The host and
    path filters apply to the request that opened the connection.

### Replay
Edit a raw request and send it as often as you like, in separate tabs.
- **Sending:** ⌘/Ctrl+Enter sends; ‹ › step back and forward through what you sent.
- **Auto URL-encode** (on by default): on send, characters that aren't valid in a URL
  (spaces, quotes, `<>`, `#`, non-ASCII) are encoded in the request line and in form bodies.
  `&`, `=`, `'` and existing `%XX` stay as typed, so `?q=x' OR 1=1--` arrives as
  `?q=x'%20OR%201=1--`.
- **Selection:** ⌘U URL-encodes the selected text completely and ⌘⇧U decodes it. This
  works in every request editor.
- **WebSocket tabs** (**+ WS**, or Send to Replay from Proxy › WebSockets): edit the
  handshake and the messages to send (text, separated by a line with `---`), then
  **Connect and send**. brainproxy opens a new connection (with a fresh key), sends the
  messages, and lists what comes back for **Listen** seconds after the last one, or until a
  reply matches **Until**. Each run is recorded like proxied traffic.

### Fuzzer
Mark payload positions with `§value§` (*Add §*, *Auto §* for every parameter), choose an
attack type, and pick payloads:
- **Attack types:**
  - **Sniper:** one list, one position at a time.
  - **Battering ram:** one list, the same payload everywhere.
  - **Pitchfork:** one list per position, in step.
  - **Cluster bomb:** every combination.
- **Payload sources:**
  - **Built-in:** 17 lists. `sqli`, `sqli-time`, `sqli-login-bypass`, `xss`,
    `path-traversal`, `command-injection`, `ssti`, `nosqli`, `naughty-strings`,
    `special-chars`, `content-discovery`, `parameters`, `headers`, `usernames`, `passwords`,
    `http-methods`, `extensions`. *Edit as list* copies one so you can change it.
  - **List:** type your own payloads.
  - **Numbers:** a range.
  - **File:** a wordlist on disk.
  - **Processing:** each set can be encoded, hashed, or prefixed.
- **Matching:** grep for text in responses, extract values, or match status codes.
- **Encoding:** payloads placed in the URL or a form body are URL-encoded where needed
  (option on by default).
- **Results:** show live, with the baseline response and *outliers* (unusual status or size)
  highlighted.
- **Discover content:** sets up `GET /§path§` with the content-discovery list to find
  files and folders such as `.git`, `.env`, backups, admin panels, and debug consoles.

### Scans
- **New scan › Active scan:**
  - **Crawl and audit** (default): crawls from the site URLs, then attacks every request
    recorded on those sites. The crawler follows links and forms, robots.txt and sitemaps,
    and URL paths mentioned in page text or scripts (error pages included); placeholder
    values such as `?key=…` or `/users/{id}` are replaced with test values. It keeps the
    cookies the site sets and sends them back, so tick *Inject into cookies* to attack them,
    and *Inject into URL paths* to attack each path segment, such as the ID in `/users/42`
    (`scan active --url-path`; it sends many more requests). The guided Standard and Thorough
    scans do both. To keep that down, `/users/1` and `/users/2` count as one route (numbers,
    UUIDs and long hex IDs; give URLs or `--history-id` to attack each), so do the script,
    style, image, font and media files of a folder, and a fixed segment such as `/api` is
    attacked once per site and method. XML and multipart bodies are attacked by default, including the file name of
    an upload but not its content. For single-page apps, tick *Run JavaScript (browser)* (see
    below).
    The crawl stays on the site URLs' origins (scheme, host and port); an `http://` site
    also covers `https://` on port 443 of the same host, since sites redirect there.
  - **Audit everything recorded:** attacks all traffic already in the project.
  - **Audit specific URLs:** only the requests you list.
  - **Options:** strength, rules, login profile, speed limits, and *Include Nuclei
    templates* (on when installed, high severity and above by default).
- **New scan › Targeted:** search the ZAP scan rules and the installed checks (Nuclei,
  brainproxy, local) by name, id, CVE, or tag, pick some, and run only those, on crawled,
  recorded, or listed requests. Checks tagged dos, fuzz, or intrusive, which other scans
  leave out, run when picked here (marked in the list).
- **New scan › Crawl:** explore only, no attacks.
- **Run JavaScript (browser)** (Crawl, and Active scan's *Crawl and audit*): also crawls
  in a hidden Chromium-based browser (Chrome, Chromium, Edge or Brave must be installed;
  the option is greyed out otherwise). Pages built by JavaScript, single-page apps, are
  explored the way a person would: it waits for each page to settle, follows links and
  client-side routes, clicks buttons, menus and other clickable elements, fills fields
  with test values and submits forms, and records the API calls (XHR, fetch) this
  triggers. Each distinct page state is explored once. It is slower than the plain crawl.
  - **What it won't do:** click elements or follow links labelled like *log out*,
    *delete*, *remove*, *reset* or *unsubscribe* (the summary lists them under
    `not_clicked`), answer *OK* to a confirmation dialog, open pop-ups or downloads,
    request logout-like URLs, load pages outside the crawl's sites or path prefix, or send
    DELETE requests (listed under `blocked_requests`). From the CLI, `--allow-destructive`
    lifts the label and DELETE rules and `--avoid REGEX` adds labels to skip.
  - **Where its traffic goes:** only through a proxy of the crawl's own, so every request
    is checked against the engagement scope and recorded in **Traffic** with source
    `crawl-browser`, and the browser's own background features (updates, sync, safe
    browsing, WebRTC) are off. It uses a fresh temporary profile, removed afterwards, so
    nothing from your normal browser is used; with a login profile, the session is added
    to every request on the site and renewed when lost.
  - **Limits:** depth, max pages (page loads, clicks and form submissions, counting the
    reloads and clicks needed to get back to a page state), rate, path
    prefix and the site's origin apply as for the plain crawl, and it stops after 30
    minutes unless you set `--max-minutes`. Linux and macOS only.
  - **Chromium's sandbox:** it stays on, because the pages it opens are the target's. As
    root, or where it is unavailable (some containers lack user namespaces), the browser
    won't start: run as a normal user, install your distribution's `chromium-sandbox`
    package, or set `BRAINPROXY_BROWSER_NO_SANDBOX=1` to run without it. The crawl's
    summary then says `"sandbox": false`.
- **New scan › PHP2Shell check:** checks the listed sites for PHP2Shell (CVE-2026-109618,
  CVE-2026-109619) with active rule 100002 only, a few requests per site. See
  [ACTIVE_RULES.md](ACTIVE_RULES.md#brainproxys-own-rules).
- **New scan › CVE quick checks:** one check for a new CVE from the brainproxy checks
  feed, run on the listed sites (for example whether a site decodes Brotli request
  bodies, CVE-2026-111497). New ones arrive with the daily feed update.
- **Tasks:** running and finished scans and crawls with progress; Stop; View findings.
- **Rules:** turn passive rules and the feed's passive checks on or off, choose which
  traffic is passively scanned, or run the passive scan again.

Passive rules run automatically on everything recorded. Active scans send real attack
requests that can change data: prefer a test environment.
By default an active scan only replays GET, HEAD, OPTIONS and POST requests from history;
DELETE, PUT, PATCH and other methods are skipped (and counted as `skipped_methods`) unless
you include them. POST stays on because a scan misses too much without it, but it isn't
safe: POST requests are replayed with attack payloads, often many times, and can change data
or trigger side effects such as email; `--crawl` also submits the forms it finds. When any
are attacked, the result says how many (`post_targets`) with a warning (`post_hint`), which
with JSON output or `--background` comes only once the scan is over. Text output warns before
the attack starts, and the scan wizard says so on its last step.

### Access
Access control across users: does the app let bob read alice's data? See
[Access control across users](#access-control-across-users-authz) for how it works.
- **New run:** tick the identities to send each request as (your auth profiles, one per
  user) and keep *anonymous* on to also send with no session. *Owner* is worked out per
  request unless you pick one. Choose which requests to test: all recorded requests that
  carry credentials, one site, a tag, or a SQL condition on history. Only GET, HEAD and
  OPTIONS requests are replayed, and logout paths never are.
- **Test live while browsing:** restarts the proxy on the same address, with the options it
  had (such as its login profile), so each in-scope request you browse is also tried as
  those identities in the background. If it doesn't start, the
  previous proxy is started again. Results fill the grid as you go; stopping the proxy ends
  the run.
- **Grid:** one row per request, one column per identity. Cells are coloured by verdict:
  red for a high-confidence bypass, orange medium, yellow low, blue public, grey different,
  a dashed outline inconclusive (a successful response with nothing to compare, so check it
  by hand), green enforced. Rows with nothing to compare (the owner didn't get a 2xx) are
  marked skipped. Click a verdict chip above the grid to show only those rows; *Worst first* puts
  bypasses at the top.
- **Compare:** click a cell to see the owner's response (the baseline) and that identity's
  side by side, with the evidence for the verdict. *Requests* shows what was sent, so you
  can check the owner's credentials were removed; *Diff* opens both in Diff.

### Findings
- **Layout:** issues grouped by type, filterable by risk, with false positives hidden by
  default.
- **Detail:** for each issue, the rule, confidence, CWE/WASC, description, solution,
  references, the evidence highlighted in the response, and the request.
- **Actions:** mark *open*, *confirmed*, or *false positive*; send the request to Replay.
- **Compare with a scan:** pick a finished active scan to show only what it found for the
  first time (*New in*), what it found again (*Still found by*), or what it covered but
  didn't find again (*Not found again by*: likely fixed). A scan covers a finding when it
  tested the finding's site (scheme, host and port) and, for active findings, its rule;
  passive findings (headers, cookies) count only when the scan crawled. The command line
  has the same comparison: [`findings compare`](#comparing-findings-and-failing-a-build-findings-compare).
- **Report…:** saves the HTML report described under [First engagement](#first-engagement-desktop-app)
  and shows it in Finder or Explorer.

### Callbacks
Out-of-band testing for blind vulnerabilities (SSRF, XXE, blind command injection,
Log4Shell-style lookups).
- **Listener:** start one, choosing the address the target can reach (and optionally a DNS
  domain).
- **Payloads:** generate payload URLs and paste them into requests.
- **Interactions:** callbacks appear as they arrive, with the raw request. Only callbacks
  carrying one of your payloads' tokens are kept (up to 100 per payload and 10,000 per
  project); other traffic to the listener, such as internet scanners, is only counted.
  The listener accepts connections on all interfaces by default so targets can reach it,
  and says so when it starts.

Active scans use the listener automatically when it runs.

### Codec
Stacked transforms: encode, decode (base64, URL, hex, HTML, JWT), or hash, each step
working on the previous output.

### Diff
Compare two requests or responses (sent from other tools or pasted) by line, word, or
byte, side by side or unified.

### Settings
- **Auth profiles:** how to log in. **Record a login** is the quick way: give the site, log
  in in the browser that opens (an empty profile, through the proxy), open one page only a
  logged-in user sees, and click *I'm logged in*. brainproxy finds the login request and
  turns the username, password, and CSRF token into placeholders, notes where a fresh CSRF
  token comes from and whether a bearer token from the login response is sent on, and picks
  a page and pattern that tell logged-in from logged-out; every pattern is checked against
  the recording. It shows what it found, then saves the profile and tests a real login.
  Single sign-on on another site or a one-time code can't be replayed: the profile then
  carries the recorded session until it expires. (CLI: `auth record start URL`,
  `auth record finish NAME --save`.) The password is kept in the project, as the proxy
  history already holds the recorded login; give an environment variable name instead to
  keep it out of the profile. Or set it up by hand: give a login URL with method and body (or a raw login
  request), the username, and the password, preferably as an environment variable name.
  Optionally add a CSRF token to fetch first, a token to extract for an Authorization
  header, and logged-in/logged-out patterns and a check URL. Scans, crawls, the fuzzer, and
  the proxy then stay logged in and log in again when the session drops.
  - **Secrets stay out of history:** values the profile adds (its headers, the session
    cookies and token, the password in the login request) are recorded as placeholders
    such as `«auth:NAME:header:X-Api-Key»` or `«auth:NAME:cookie:sid»`, so history,
    `query`, and Traffic never show them. When a stored request is sent again (Replay,
    `send`, a scan of stored requests), brainproxy fills in the profile's current values.
    A header value only goes into its own header and the password only to the login URL's
    origin. If the profile is removed or has no value yet, sending fails and names the
    placeholder; log in again or edit the request. Responses are stored as received, so
    session cookies the site sets still appear there. Projects recorded before this kept
    plaintext values in their older requests.
  - **Platform authentication:** HTTP Basic, Digest, or NTLM for some hosts, with the
    profile's username and password (for NTLM, the domain in its own field or as
    `DOMAIN\user`). brainproxy answers those hosts' 401 challenges on every command and
    through the proxy, without choosing the profile; the header is added on the wire only,
    so history keeps the request without it. A request that brings its own Authorization
    header is left alone. NTLM works over HTTP/1.1 only: the proxy sends those hosts'
    requests upstream over HTTP/1.1 even when the browser speaks HTTP/2 to it.
  - **Macros:** requests that run in order with the profile's session.
    *New macro from Traffic* lists recent requests; click them in the order they should run
    (move them up or down), then say what to take from each response into a variable: an
    HTML input by name (or a `<meta name=… content=…>`), a JSON path such as `data.token`, a
    regex (group 1), a response header, or a cookie the response sets. Later steps use a
    value as `{{name}}` (also `{{username}}` and `{{password}}`), and their parameters with
    the same name get it automatically; cookies carry through the steps into the session.
    *Run* shows each step's request, status and history entry, and the values found, masked
    (first four characters and the length). The values become the session's latest.
  - **Session rules:** what to do before a request goes out with this profile, for the
    tools you tick (proxy, send, fuzz, crawl including API import requests, scan, checks;
    none ticked means all) and a URL: a host pattern like `*.app.test` or a URL prefix like
    `https://app.test/api/`. Actions run in order: *Check session* fetches the check URL
    (every N requests); if it's still valid the rest of the rule is skipped. *Run macro*
    runs a macro on every request, every N requests, or once and again only when its values
    go stale. *Update request* puts the values of this rule's macros into the request: every query, form,
    JSON or multipart parameter, header or cookie with the variable's name (or the names you map,
    such as `X-CSRF-Token=csrf`; an `Authorization` header keeps its scheme, as in
    `Bearer …`); a parameter being fuzzed or attacked keeps its payload.
    *Log in* logs in with the profile when the session isn't logged in or a check just
    failed. A response that looks logged out, or matches the rule's *stale-values* regex
    (for example `invalid csrf token`), refreshes the rule's macros (once, however many
    requests notice at the same time), logs in again if it can, and sends the request once
    more. A profile with no login or headers of its own needs at least one macro or rule:
    start it with *New macro profile* (CLI: `auth macro add` on a new name), then edit it to
    set its options; its last macro or rule can't be removed, only the profile.
    Extracted values are stored like the session cookies and recorded as placeholders such
    as `«auth:NAME:var:csrf#7»`: each macro run has its own, so requests prepared at the
    same time each send their own token, and a request re-sent later gets the latest value.
    A value only goes to the origins of its macro's steps. To send it elsewhere (a token from
    a sign-in host used on an API host), give the rule a URL: it then also goes to the requests
    that URL matches, from then on. A rule with no URL leaves requests to other origins as they
    are. Macro requests are checked against the engagement scope like any other request.
  - **Request signers:** an HMAC signature or a JWT computed as a request goes on the wire,
    for APIs that reject a request whose signature doesn't match (see *Request signing* under
    the CLI options below). *New signer* asks for a name, the origins it may sign for, where the
    value goes, and what to make: for an HMAC the string to sign, the hash (SHA-1, SHA-256,
    SHA-384 or SHA-512) and the output, for a JWT the algorithm (HS256, HS384, HS512 or RS256)
    and the claims. There is no field for the key itself: give the name of an environment
    variable, or the full path of a file, and it is read when the signer first signs. A variable
    has to be set where the app was started, so a key file is simpler for an app started from
    a desktop launcher. *Edit* replaces the signer and keeps its place and name, since rules use
    it by name; *Run last* moves it after the others, for one that covers another's signature; a
    signer a rule uses can't be removed until the rule is. A session rule's *Sign request*
    action turns a signer on.
- **Match & replace:** rewrite requests and responses passing through the proxy.
- **Intercept options:** which methods, hosts, and paths to hold, and the timeout.
- **Proxy:** whether it runs (with a start button), its URL, and how to point a browser,
  Chromium, curl, or a shell at it.
- **Connections:** options for every request brainproxy sends (also from scans, the crawler,
  the fuzzer, logins, and the proxy's upstream side). A running proxy picks up a change
  within a second. None of them widens the engagement scope.
  - *Upstream proxies:* HTTP (CONNECT) or SOCKS5, with an optional username and a password
    read from an environment variable, by host pattern (`app.test`, `*.corp.test`, `*`, with
    an optional `:port`); the first match wins, a *direct* rule makes an exception, and no
    match connects directly. The proxy is asked for the address brainproxy resolved and
    checked, never the name, so it can't reach anything the scope doesn't allow. It
    therefore sees IP addresses, and plain-HTTP targets go through a CONNECT tunnel too.
    A proxy on this machine works as it is; any other one must be listed when the
    engagement starts (`--proxy HOST:PORT`) and, if there is a system scope file, under its
    `"proxies"`, because a proxy could read what passes through it. Proxy usernames and
    passwords go in clear to the proxy (Basic for HTTP, plain for SOCKS5), so on a proxy
    off this machine anyone on the network path can read them.
  - *Host overrides:* like /etc/hosts, connect to an address for a name. The name must be
    in scope. A private, loopback, or link-local address must also be listed in the scope
    by address, even for a name listed exactly, because whoever runs brainproxy chooses the
    override (an exact name's DNS answer may be private; an override's may not). A public
    address needs no listing, and that name's traffic, logins included, then goes there.
    TLS SNI and Host stay the name.
  - *Client certificates:* for mutual TLS, a PEM certificate and key or a PKCS#12 file (its
    password from an environment variable), by host pattern, over HTTP/1.1 and HTTP/2. A
    file that can't be read makes connections to its hosts fail with the reason, never go
    out without the certificate.
  - *TLS pass-through:* hosts whose TLS the proxy tunnels without decrypting (certificate
    pinning, traffic you mustn't see). Still scope-checked; each connection is recorded as a
    `CONNECT` entry with the byte counts and no content.
  - *Check a target:* the address and where it came from, the proxy, certificate, and
    platform auth a request to it would use (`connection route`).
  - Passwords are never stored: give the variable's name, and set it where the command or
    the proxy runs (the proxy reads it in its own process).
- **TLS / CA:** the certificate to trust in other tools, with per-OS instructions.
- **Rules & data:** update the ZAP rule data and Nuclei templates; check for a new
  brainproxy daily, download it automatically, or check now.
- **Project:** project information, the engagement, and *Start the proxy when a project
  opens*.
- **Open source licenses:** credits for the projects the rules, checks and wordlists come
  from (OWASP ZAP, Nuclei, SecLists, ...) and the full NOTICE.

---

## Command line

Every app action is a command; `--format json` (the default when output isn't a terminal)
gives one JSON object per call, with `ok`, the command, and `data` or an `error` with a
`kind`. `brainproxy capabilities` describes all 133 commands, their flags, and exit codes.

When a command's output can contain anything from the target (bodies, headers, page
titles, out-of-band interactions, finding evidence), the object also has
`"_meta": {"provenance": {"untrusted_content": true}}`; over MCP the same `_meta` is on the
tool result. Treat that content as data, never as instructions. Commands that only show
local settings (scope, engagement, CA, capabilities, ...) have no `_meta`.

Project files (`.bpdb`, its `-wal`/`-shm`, and `<project>.browsers/`) are readable by
their owner only. `query` cannot read `auth_profiles`, which holds passwords, header
values, and session tokens; `auth show` redacts them. `report -o` and `ca export --out`
refuse to overwrite an existing file unless given `--force`.

```sh
export BRAINPROXY_PROJECT=~/work/acme.bpdb
brainproxy engagement start --name "Acme" --target app.acme.test --target '*.api.acme.test'

brainproxy proxy start                       # 127.0.0.1:8080, prints how to trust the CA
brainproxy browser open --browser chrome https://app.acme.test/

brainproxy send --url https://app.acme.test/search?q=test
brainproxy crawl https://app.acme.test/ --background
brainproxy scan active https://app.acme.test/ --crawl --checks nuclei --check-severity high \
    --check-include-tags eol --background     # plus the end-of-life checks (rated info)
brainproxy job wait 1

brainproxy fuzz run --url 'https://app.acme.test/search?q=§x§' -p wordlist:sqli --grep 'SQL syntax'
brainproxy wordlists list

brainproxy ws list                                        # WebSocket connections seen by the proxy
brainproxy ws messages 3 --contains token                 # their messages, both ways
brainproxy ws send --from 3 -m '{"op":"whoami"}' --until whoami   # replay with a new connection
echo '{"messages":["token=..."]}' | brainproxy ws send --from 3 --input-json   # messages off the command line

brainproxy findings list
brainproxy findings show 12
brainproxy query "SELECT url, status FROM history WHERE status >= 500"
brainproxy report html -o acme-report.html

# Session handling: a macro that fetches a fresh CSRF token (history #42 is the form page),
# and a rule that puts one into every request of active scans and fuzz runs
brainproxy auth macro add app csrf --step 42 --extract '1:csrf=input:csrf_token'
brainproxy auth macro run app csrf
brainproxy auth rule add app --tool scan,checks,fuzz --action macro:csrf:each --action update:csrf
brainproxy scan active https://app.acme.test/account --auth app

brainproxy project save --output ~/work/acme-copy.bpdb   # consistent copy, safe while in use; never overwrites
brainproxy project stop     # stop the project's proxy, OOB listener, jobs and fuzz runs (deletes nothing)
```

Connection options (see Settings › Connections above for what each does):

```sh
brainproxy engagement start --target app.acme.test --proxy 10.0.0.1:3128   # allow a proxy off this machine
brainproxy connection upstream add --host '*' --proxy http://10.0.0.1:3128 --username me --password-env PROXY_PW
brainproxy connection upstream add --host '*.lab.acme.test' --proxy socks5://127.0.0.1:1080 --first
brainproxy connection hosts add app.acme.test 10.20.0.5
brainproxy connection cert add --host api.acme.test --pkcs12 me.p12 --password-env P12_PW
brainproxy connection passthrough add login.acme.test
brainproxy connection route https://app.acme.test/      # what a request there would use
brainproxy connection show
brainproxy auth add corp --platform ntlm --platform-host '*.acme.test' --username 'ACME\me' --password-env CORP_PW
brainproxy proxy start --listen 0.0.0.0:8080 --invisible  # also serve clients that don't know they're proxied
brainproxy proxy start --listen 127.0.0.1:8443 --redirect https://app.acme.test  # everything to one origin
```

With `--invisible`, plain requests in origin form (`GET /path`) go to their Host header's
host and port, and a TLS client that connects directly gets a certificate for its SNI and
goes to that name on port 443; ordinary proxy requests work on the same listener. A
`--redirect URL` sends every request from the listener to that origin (implies
`--invisible`). Pass-through hosts and hosts outside the proxy scope are tunnelled as with
CONNECT.

Crawl and active-scan scope and safety flags:

- `crawl --any-port` and `scan active --crawl --crawl-any-port`: follow links to any port
  and scheme on the seed hosts. Without it the crawl stays on the seeds' origins (plus
  https on 443 for an http seed), so a page can't steer it, with your cookies and auth, to
  other services on the same host.
- `crawl --rate N` and `scan active --rate N`: at most N requests per second in total,
  whatever `-c` is.
- `-c N` (default 10): requests in flight at once. More only helps when the target keeps
  up; it doesn't depend on how many CPUs you have, and the scan uses a few percent of one.
- A 429 response, or a 503 with `Retry-After`, pauses every request to that site for the
  time asked (5 s without one, at most 60 s), and the request is sent once more.
- `scan active --check-timeout S` (default 10): per-request timeout for the Nuclei
  templates, at most `--timeout`. A template's own `@timeout` line overrides it, so the
  time-based ones get the wait they need. When several templates send the same GET or HEAD
  request, it's sent once and they share the response.
- The crawler submits at most 200 forms per page.
- `crawl --max-minutes M`: stop crawling after M minutes (`scan active --max-minutes`
  bounds its crawl too, with `--browser` both crawls together).
- `crawl --browser` and `scan active --crawl --browser`: the JavaScript-aware crawl
  described under [Scans](#scans). `--browser-id ID` picks the browser from
  `brainproxy browser list`, `--headful` shows its window, `--avoid REGEX` (repeatable)
  skips more elements, `--allow-destructive` clicks destructive-looking ones and sends
  DELETE. It tries at most 40 elements per page state and chains of up to 6 clicks, and
  waits at most 10 s for a page to settle.
- `scan active --include-methods DELETE,PUT,PATCH` (or `all`): also attack requests with
  these methods. Requests picked with `--history-id` are attacked whatever their method.

Session handling (`auth macro`, `auth rule`; see Settings › Auth profiles above):

- `auth macro add PROFILE NAME --step ID|FILE|ORIGIN=FILE ... --extract STEP:VAR=KIND:EXPR ...`
  adds or replaces a macro, making the profile with no login if it doesn't exist (`auth add`
  can then set its options; `auth add` alone refuses a profile with no login, header, macro or
  rule). KIND is `regex`, `json`, `header`, `cookie` or `input`. A FILE
  step is sent to its `Host` over `--scheme` (default https) unless the request line has a
  full URL or ORIGIN is given. `auth macro list/show/run/remove`; a macro a rule runs
  can't be removed until the rule is.
- `auth macro run` fails (exit code 2) when a step gets no response or a value isn't
  found, and says which, with each step's status and history id.
- `auth rule add PROFILE --action SPEC ... [--tool T,...] [--url PATTERN] [--invalid REGEX]`,
  SPEC being `check[:N]`, `macro:NAME[:each|:N]`, `update[:PARAM[=VAR],...]` or `login`.
  `auth rule list/remove`. `auth show` lists the macros and rules too. `update` with no list
  needs a macro before it in the rule. Without `--url`, values only go to their macros' origins.
- `macro:NAME` alone runs the macro once per command and again when a response shows its
  values went stale; the cache isn't shared between commands, so each `send` runs it once.
  `:each` runs it for every request, which a scan or fuzz run with `-c 10` does ten at a
  time: use it when tokens are single-use, and lower `-c` if the site keeps only the
  latest token per session.

Request signing (`auth sign`), for APIs that reject a request whose signature doesn't match
and targets that want a JWT you choose the claims of:

- `auth sign add PROFILE NAME (--secret-env VAR | --secret-file PATH) --origin ORIGIN ...
  --to header:NAME|query:NAME [--wrap 'Bearer {{signature}}'] [--set-header 'NAME: TEMPLATE' ...]`,
  then `--canonical TEMPLATE [--hash sha1|sha256|sha384|sha512] [--output hex|base64|base64url]` for
  an HMAC, or `--jwt HS256|HS384|HS512|RS256 [--claims JSON] [--ttl SECONDS] [--kid ID] [--resign]`
  for a JWT. `--secret-encoding hex|base64` decodes the key; RS256 takes a PEM private key.
  `auth sign list/remove`. Then `auth rule add PROFILE --action sign:NAME [--tool ...] [--url ...]`
  turns it on; a rule's `check` doesn't skip its `sign`. Adding a name that exists replaces the
  signer and runs it last, or keeps its place with `--keep-place`. Settings › Auth profiles has
  all of this too.
- Templates use `{{method}}`, `{{host}}`, `{{path}}`, `{{query}}`, `{{body}}`, `{{body_sha256}}`,
  `{{body_sha256_base64}}`, `{{timestamp}}`, `{{timestamp_ms}}`, `{{nonce}}` and `{{header:NAME}}`;
  anything else is refused when the signer is saved. `--canonical` reads `\n`, `\r`, `\t` and `\\`
  as escapes. `--set-header` values are set before signing and can't hold `{{body}}`.
- The value is computed when the request goes on the wire: after insertion-point mutations, other
  session values and the Content-Length update, for every send, active scan (YAML checks included),
  fuzz, crawl, proxy and authz request a rule matches, and for history replays that carry the
  placeholder. `authz` sends through the `send` tool, so a rule limited with `--tool` must include
  `send` to sign its requests. Each send gets a
  new timestamp and nonce, shared by every signer of that send. A signer may cover a header another
  sets with `--set-header`; covering another's signature needs that signer added first, and is
  refused otherwise. A chunked body is hashed without its framing. A query signature leaves itself
  out of `{{query}}`, and `authz` removes it from its no-session requests. A body parameter isn't
  offered, since it would change what a body hash covers.
- A destination being attacked (a fuzz marker in the signature header, say) keeps the payload, so a
  bad signature can be tested. `--resign` starts from the token in the request and lays `--claims`
  over its claims; the token's own signature isn't checked, and a value that isn't a JWT fails the
  send.
- The requests a session rule makes for itself aren't signed: macro steps, logins and the session
  check URL of its `check` action.
- Signers store where a key is, never the key, so `auth show`, `query`, reports and MCP output can't
  show it; history and findings hold `«auth:PROFILE:sign:NAME»`. A value only goes to the signer's
  origins. A key is read when its signer first signs, so one no request needs is never touched. A
  missing or unreadable key fails the send, naming the variable or file and nothing more.
- Signers are data: templates name request parts and nothing is executed. A signer can read any
  file the process can as its key, but only the HMAC or signature made with it leaves the machine.

### Comparing findings and failing a build (`findings compare`)

`findings compare` reports which findings are new, unchanged, or fixed against a baseline, and
`--fail-on` turns that into an exit code for CI. The baseline can be:

- **A file** (`--baseline FILE`): `report json` output, to compare runs in different project files.
  Findings match by alert, method, URL without its query, and parameter, so the URL's
  scheme, host and port must be the same in both runs. `--current FILE` compares two reports and
  doesn't touch `--project`. "Fixed" only means not found this run, so it's as good as the run's
  coverage.
- **A scan** (`--scan JOB`): a `scan active --background` job in this project, using the same logic
  as the app's *Compare with a scan*: first found by it, found again by it, or covered by it and not
  found again. Foreground scans have no job to name.
- **Nothing**: every finding is new, which makes `--fail-on` a plain severity gate.

Write the baseline with `--state all`, so that false positives you've triaged stay triaged when a
later run finds them again, and a `--limit` above the number of findings: a report cut off at its
limit is refused, because what it left out would look new. A report written with `--risk`, `--host`
and similar filters is accepted with a warning in `warnings`, except as `--current` with `--fail-on`,
where it is refused because the gate wouldn't see what it left out. Project files are refused: run
`report json` on them.

```bash
# On the main branch: save what is known
brainproxy --project app.bpdb report json --state all --no-evidence --limit 100000 --output baseline.json

# On each pull request: scan, then fail only on new high-risk findings
brainproxy --project app.bpdb scan active https://staging.example.test/ --crawl
brainproxy --project app.bpdb findings compare --baseline baseline.json --fail-on high --new-only > compare.json
```

`--fail-on RISK` fails on findings at or above `info`, `low`, `medium`, or `high` that are still
there: new and unchanged ones, or with `--new-only` just the new ones. False positives never count,
whatever `--state` lists. With `--scan`, only what that scan found counts.

| Exit code | Meaning |
|-----------|---------|
| `0` | Compared, and the gate (if any) passed |
| `5` | Compared, and the gate found something. The output is complete: `ok` is true, and `data.gate` has `passed: false`, the `count`, and the `findings` |
| `4` | The baseline file, project, or scan job doesn't exist |
| `2` | Bad arguments; a file that isn't usable (not a report, cut off, or the baseline and the findings compared being the same file); or `--fail-on` with a filtered `--current` or a scan that didn't complete |

These don't pass a gate:

- A missing baseline file fails with `4`. With `--allow-missing-baseline` it counts as empty, for a
  first run: every finding is new, so the gate still sees them all, and `data.baseline.missing` is
  true. A file that exists but can't be read as a baseline always fails.
- A `--project` that doesn't exist fails with `4` rather than being created empty.
- A scan that failed, was stopped, or ran out of `--max-minutes` found less than it should have, so
  `--fail-on` refuses it with `2`. Without `--fail-on` the comparison runs with a warning.

Lists, including `data.gate.findings`, are cut at `--limit` per group (`summary.truncated` says so);
counts and the gate always cover every finding.

### Access control across users (`authz`)

Broken access control (IDOR, missing authorization checks) only shows up when one user's
request is tried with another user's session. `authz run` does that for the requests in
history. Make an auth profile per user, browse or send as one of them, then:

```sh
brainproxy auth add alice --login-url https://app.acme.test/login ... --username alice --password-env ALICE_PW
brainproxy auth add bob   --login-url https://app.acme.test/login ... --username bob   --password-env BOB_PW
brainproxy crawl https://app.acme.test/ --auth alice          # or browse as alice through the proxy
brainproxy authz run --as bob --where "host = 'app.acme.test'"
brainproxy authz matrix 7                  # one row per request, a cell per identity
brainproxy authz results 7 --verdict bypass
brainproxy diff 120 131 --part response-body   # the baseline and bob's response, from the row
```

For each request it:

1. works out who made it (the owner) from its auth placeholders, or a cookie, token or
   header value of a profile's session; `--owner NAME` sets it. A request whose owner
   isn't known is re-sent with the credentials it was recorded with;
2. sends it as the owner twice; whatever differs between the two (timestamps, nonces,
   CSRF tokens) is left out of every comparison. If the owner doesn't get a 2xx, there is
   nothing to compare and the request is `skipped`;
3. sends it with no credentials at all (the anonymous control; `--no-anonymous` skips it),
   then as each `--as` profile, with the owner's cookies, `Authorization` and profile
   headers removed first (`--keep-cookie NAME` keeps a cookie that isn't a credential).

Each response gets a verdict:

| Verdict | Meaning |
| --- | --- |
| `enforced` | refused: an error status, a logged-out page, or a body saying access is denied |
| `bypass` | the owner's data came back: most of the owner's private values (JSON values the anonymous response and the request don't contain), the owner's username, or a nearly identical response when there is nothing private to look for |
| `public` | the anonymous control got the same response, so the page isn't protected |
| `different` | a successful but different response, such as the identity's own data |
| `inconclusive` | a successful response with nothing to compare: an empty body, `{}`, or a HEAD or OPTIONS request. It says nothing about access, so check it by hand |

A bypass is `high` confidence when the request names an object (a number, UUID, long hex
id or email address) and the owner's values or username came back, `medium` when it names
an object but only the similarity shows it, or when the path looks privileged (admin,
users, roles, ...), and `low` otherwise: `/dashboard` may simply be the same for everyone.
Medium and high bypasses are findings (source `authz`): *Access Control Bypass* (100003)
for another profile, *Protected Content Without Authentication* (100004) for the anonymous
control. Low ones are only in the results, to review.

Safety: from history only GET, HEAD and OPTIONS requests that carry credentials are
replayed; `--include-methods POST,PUT` (or `all`) adds others, which then change data as
another user. Paths matching `--exclude` (default: logout and sign-off) are never replayed,
so the owner stays logged in. `--history-id` picks a request whatever its method. URLs on
the command line are fetched with GET and need `--owner`. Every request stays inside the
engagement scope and is recorded in history with source `authz`.

`authz run --background` returns a run id; `job wait|status|stop` work on it, and
`authz list` shows recent runs. The rows are also in the `authz_results` table for `query`.

**Live mode.** `proxy start --authz bob,anonymous` tests requests while you browse. Each
in-scope request the proxy records that carries credentials, uses GET, HEAD or OPTIONS,
doesn't match `--authz-exclude` (default: logout and sign-off) and got a 2xx response that
isn't a static asset (scripts, stylesheets, images, fonts, media) is also sent, in the
background, as each listed profile and/or with no credentials (`anonymous`), exactly as
`authz run` does. To test a request live mode leaves out, such as a private image, use
`authz run --history-id`. All of it goes
under one authz run, created when the proxy starts; `proxy start` and `proxy status` print
its id, and `authz matrix|results|list` and the desktop app's **Access** view work on it
while it fills up.

```sh
brainproxy proxy start --auth alice --authz bob,anonymous   # browse as alice
brainproxy proxy status        # authz.run_id, and counts: tested, waiting, duplicates, dropped
brainproxy authz matrix 12     # the live run's id
```

Proxied traffic never waits for the tests. Each method, URL and body is tested once; the
requests wait in a queue of `--authz-queue` (default 100), and when it is full new ones are
dropped and counted (`dropped_queue_full` in `proxy status`, next to `skipped_status`,
`skipped_static` and the other reasons a request wasn't queued). `--authz-rate` caps the
requests per second the tests send (default 5, 0 for no limit); `--authz-keep-cookie`
keeps a cookie that isn't a credential. The settings in use are stored in the project
(setting `authz`). `proxy stop` and `project stop` end the run (state `completed`), waiting
up to 30 s for it to be saved; if the proxy has to be killed, or dies, the run is `failed`
and the rows recorded so far stay;
`job stop RUN` stops testing while the proxy carries on (`stopped` once the proxy stops).

More detail: [README](../README.md), [MCP](MCP.md), [checks](CHECKS.md),
[rule updates](RULE_UPDATES.md), [out-of-band](OOB.md), [desktop app](GUI.md).

---

## Agents and MCP

`brainproxy mcp serve` exposes every command as an MCP tool over stdio. Each tool is marked
read-only, destructive, or open-world, long calls report progress, and the database schema
and capabilities are available as resources. Add it to an MCP client:

```json
{ "mcpServers": { "brainproxy": { "command": "brainproxy", "args": ["--project", "/work/acme.bpdb", "mcp", "serve"] } } }
```

The agent works under the same engagement scope; it cannot reach anything outside it.

---

## Rules, checks, and wordlists

- **ZAP rules.** The passive (53) and active (48) scan rules are ported from OWASP ZAP,
  whose code is Apache-2.0. Their pattern files (error messages, hidden files, and similar)
  are built in, and *Rules and checks › ZAP rule data* fetches the latest ones.
- **Outdated software.** *Vulnerable JS Library* (10003, from ZAP's retire add-on) checks
  every script it sees against Retire.js's database of vulnerable jQuery, Angular,
  Bootstrap, lodash, ... versions and lists the CVEs; the database comes with the ZAP rule
  data, so the same update refreshes it. The scans in the desktop app also run the Nuclei
  end-of-life checks (outdated PHP, nginx, Apache httpd, WordPress, Drupal, Exchange, ...),
  which `checks update` keeps current. Version headers (`Server`, `X-Powered-By`) are
  reported by their own rules, and many Nuclei CVE templates check versions too.
- **Nuclei templates.** brainproxy runs Nuclei's HTTP templates itself. Most templates load
  (10,434 of 11,690 at the pinned version); the rest use features it doesn't support yet,
  and `checks list --skipped` says why. Templates needing a username, password, or other
  input load when you pass `--check-var`, and those using interactsh need the callback
  listener.
- **Wordlists.** The built-in lists come from permissively licensed projects (SecLists,
  PayloadsAllTheThings, FuzzDB, Param Miner, Big List of Naughty Strings, fuzz.txt), with
  destructive payloads removed. Attributions are in NOTICE.

---

## Troubleshooting

| Problem | What to do |
| --- | --- |
| "is outside the engagement scope" | The host or port isn't in the project's scope. Use an address inside it, or start a new engagement with the right scope. |
| The site doesn't load through the proxy | Check the address (http or https? a port such as :8080?). The guided scan checks this for you. |
| HTTPS certificate warnings in your own browser | Use **Open browser**, or trust the CA from Settings › TLS / CA. |
| Firefox shows certificate errors in the opened browser | Import the CA once in that profile (the app shows how when it opens Firefox). |
| `browser open` says it can only open http(s) URLs | Give a full `http://` or `https://` address (or none for a blank page). Other schemes and anything starting with `-` are refused so they can't be read as browser options. |
| `proxy stop` / `oob stop` says it won't send SIGKILL | The saved state comes from an older version and the process ignored SIGTERM, so brainproxy can't tell it is the proxy. Check it with `ps -p PID` (Windows: Task Manager, Details tab) and stop it yourself. |
| curl or a tool skips the proxy for localhost | Pass `--noproxy ''` (curl), or unset `NO_PROXY`. |
| Container: "can't verify the proxy" (or OOB listener) | It was started in another container, and this one can't read its lock file, so brainproxy can't tell whether it still runs. If it doesn't, `brainproxy proxy stop --forget` (or `oob stop --forget`) clears the record. Nothing is signalled, and a proxy known to be running is left alone. |
| Container: "unable to open database file" | The user in the container can't write to the folder mounted at `/work`. Add `--user "$(id -u):$(id -g)"` for a host folder you own. See [Container image](#container-image). |
| "The proxy didn't start: ports … are all in use" | Another program uses ports 8080-8089. Stop it, or start the proxy on another port: `brainproxy proxy start --listen 127.0.0.1:9090`. |
| A scan finds little | Make sure it covers the site: use *Crawl and audit* (with *Run JavaScript* for single-page apps), browse the app through the proxy first, or log in with an auth profile. Download the Nuclei templates. |
| Windows says "Windows protected your PC" | The installer isn't signed yet: More info → Run anyway. |
| Windows: tools other than the opened browser reject the CA | `brainproxy ca install-system` adds it to your user's Trusted Root store (Windows asks you to confirm). Firefox keeps its own store; import it there. |
| macOS says the app can't be opened or is damaged | System Settings → Privacy & Security → Open Anyway, or run the `xattr` command in [Install](#install). |
