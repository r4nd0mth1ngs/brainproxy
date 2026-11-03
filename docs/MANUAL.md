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

**Who recorded it.** Every request in history and every finding says where it came from:
the desktop app (`gui`), the command line or a script (`cli`), or an AI agent through MCP
(`mcp`). A proxy, crawl or scan keeps the origin of whoever started it, so a proxy an agent
started records `mcp`, even for a person's browsing through it. Entries from before
brainproxy kept this show as unknown. See [Who recorded what](#who-recorded-what).

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
   the next free one, unless you chose a port in **Settings › Proxy**). Click **Open
   browser** in the top bar and pick a browser. It opens in its own profile, sends
   everything through the proxy, and trusts brainproxy's certificate. Your everyday
   browser is untouched. Log in and click through the application; requests appear in **Proxy › Traffic** and the **Site map**.
4. **Scan.**
   - **Guided:** the Overview's *Guided scan* asks for the website, whether to log in, and
     how thorough to be (Quick, Standard, Thorough) and how hard it may push the site
     (Gentle, Normal, Fast), then runs and explains the results.
   - **Guided, for an API:** from the guided scan's first step, *Testing an API?* takes an
     API definition instead of a website. See *Guided API scan* under **Scans**.
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
   report.html` (also `markdown`, `json`, `sarif`). A project collects findings across
   scans; `report html --scan JOB` lists only what that background scan found, for the
   first time or again, and leaves out older findings it didn't see again.
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
  active scan of that branch or request, or copy the URL. A request can also be copied as a
  curl command.
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
  - **Contents:** tick it to search the text inside requests and responses instead: headers
    and bodies, compressed and chunked bodies included. Unlike the plain filter, the search is
    case-sensitive and literal: it matches the bytes as stored, so `a@b.com` doesn't find
    `a%40b.com`, a JSON-escaped value has to be typed escaped, and HTTP/2 header names are
    lower-case. Text that is only spaces is ignored. The other filters still apply, and
    changing one doesn't search again. New traffic that matches shows up as it arrives. A
    search stops at the first 10,000 matches the other filters show and says so; narrow it to
    see later ones.
  - **Saved filters:** *Save…* names the current filters (text, Contents, sources and the
    checkboxes); pick one from the list to apply it again, or *Delete* it. They are kept per
    project on this computer, in the app's own storage in plain text, not in the owner-only
    project file: a saved search for a token or password stays there until you delete it.
    *Save as…* on a temporary engagement takes them along.
  - **By:** who recorded the entry: the app, the CLI, or an agent (MCP). For a proxy entry
    that is who started the proxy, not who sent the request: hover it to see the address of
    the client that sent it.
  - **Viewer:** select a row to see the request and response (Raw, Pretty, Hex, search).
  - **Actions:** right-click to send to Replay, Fuzzer, or Diff, copy the URL or the request
    as a curl command, add a note, or highlight (*Remove highlight* on a highlighted row).
  - **Scan this request…** asks first, naming the request, then runs an active scan of that
    request in the background (`scan active --history-id`, medium strength). Once the Nuclei
    templates are downloaded, those of high severity and up also run against its site, and
    some of them request paths of their own (such as `/.git/config`); the question says so. The
    request is attacked whatever its method, so a POST or a GraphQL mutation is replayed
    with attack data too, and the question names it; it also says when the path looks like a
    logout, since replaying it can end the session it was recorded with. Only your *Start
    scan* opts a DELETE, PUT, PATCH or mutation in (`--include-methods`); that lets the
    templates send requests of that kind too, and the question says so. Click the toast to
    follow it in **Scans › Tasks**. A request that got no response (a connection error, a
    timeout, or dropped in **Intercept**) has nothing to scan, so the item is greyed out,
    with the reason under it.
  - **Test access control…** opens **Access** with a new run set to test that request
    (`authz run --history-id`). Pick the identities and start it.
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
- **From cURL** (**+ cURL**): paste a curl command, for example from a browser's *Copy as
  cURL* (bash or Windows cmd), and it opens as a new tab. Nothing is sent until you press
  Send. Options that only change curl's output (`-k`, `-s`, `-L`, `-o`) are ignored. A proxy,
  `--resolve`, `--connect-to`, a Unix socket or a client certificate is left out (set those in
  Settings › Connections): the dialog lists what was left out before the tab opens, since the
  request may then go elsewhere than curl's would, and **Open anyway** opens it. A command
  that reads a file (`-d @file`, `-F field=@file`), uses shell variables, has an option
  brainproxy doesn't know, or has a URL that curl's globbing turns into several requests
  (`{a,b}`, `[1-3]`; add `-g` to send it as written) is refused with the reason. Headers are read as `-H 'Name: value'`, `-H 'Name:'` (leave out the header
  curl would add) and `-H 'Name;'` (send it empty); a header written any other way, such as
  `Name : value` or `Name;x: y`, is refused because curl reads those by its own rules: rewrite
  it in one of those forms, then edit the header in the tab after pasting. A header comes in
  as curl sends it, with its spaces.
- **Copy as cURL:** copies the request, as Send would send it, as a curl command for a POSIX
  shell (it works in fish too). It goes to the tab's target, as Send does. Every value is
  quoted, so headers or a body that came from the target can't run anything when you paste it.
  Headers are copied as recorded, spaces included (`Transfer-Encoding : chunked` stays as it
  is). The toast notes what curl will send differently (only the first of several `Host`
  headers, its own `Content-Length`, HTTP/2's dropped `Connection` or `Upgrade`) and when the
  command holds credentials (`Authorization`, `Cookie`), so take care where you paste it.
  The command runs outside brainproxy, so the engagement scope doesn't apply to it. Bodies
  over 128 KB may be too long for one shell argument; save those to a file and use
  `--data-binary @FILE`.
- **WebSocket tabs** (**+ WS**, or Send to Replay from Proxy › WebSockets): edit the
  handshake and the messages to send (text, separated by a line with `---`), then
  **Connect and send**. brainproxy opens a new connection (with a fresh key), sends the
  messages, and lists what comes back for **Listen** seconds after the last one, or until a
  reply matches **Until**. Each run is recorded like proxied traffic, as it happens.

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
  - **Processing:** each set can be encoded, compressed (gzip, zlib, deflate), hashed, or
    prefixed.
- **Matching:** grep for text in responses, extract values, or match status codes.
- **Encoding:** payloads placed in the URL or a form body are URL-encoded where needed
  (option on by default).
- **Results:** show live, with the baseline response and *outliers* (unusual status or size)
  highlighted.
- **Discover content:** sets up `GET /§path§` with the content-discovery list to find
  files and folders such as `.git`, `.env`, backups, admin panels, and debug consoles.

### Scans
- **Guided API scan:** in the guided scan, *Testing an API?* tests an API from its definition: an
  OpenAPI 3 or Swagger 2.0 file (JSON or YAML), a Postman collection, or a GraphQL schema (SDL file
  or introspection result), by file or URL; or a GraphQL endpoint, which is asked for its schema
  when you tick *GraphQL endpoint*. A URL is fetched when you preview it, in scope only; nothing
  else is sent until you ask.
  - **Definition:** shows what was read, which operations were skipped and why, and warnings
    such as an external `$ref` that isn't followed. A Postman collection can take its
    **environment file**, which fills its variables; values the environment marks secret, or whose
    names look like credentials, are withheld. The collection's pre-request scripts are listed and
    never run unless you make one a signer (below).
  - **Server:** pick one of the listed servers or give a base URL, which is needed when the file
    has none or only relative ones (for a GraphQL schema file, the endpoint), and fill in Postman
    variables. Hosts outside the engagement are listed and those operations skipped; this flow
    can't widen the scope.
  - **Authentication** is optional and defaults to none:
    - An API key or bearer token, in a header or the query string. The value is kept in the auth
      profile, as static headers are, and history holds a placeholder. A key in the query string
      only goes to the addresses it was saved for: if you then choose a server elsewhere, the
      wizard says the key has to be saved again, and the scan can't start until you save it, go
      back to that server, or choose something else. Saving it again, or choosing something else,
      offers to remove the profile saved before. Back on that server, choosing an API key again
      uses the saved key. If you keep that profile and choose it as an existing profile on a
      server its key doesn't go to, the wizard says the scan runs without the key.
    - **OAuth 2:** client credentials, password, refresh token, or a browser sign-in (authorization
      code with PKCE), prefilled from what the definition declares; an OpenID Connect discovery URL
      can fill in the endpoints. Saving gets a token straight away, or runs the browser sign-in
      (which *Cancel* stops), and keeps the profile only if that works. The token endpoint must be
      in scope.
    - An existing auth profile.
    - **Signing** is a separate tick: HMAC, a private key, a JWT or AWS SigV4 (prefilled from a
      collection's AWS auth), or the collection's own pre-request script. A script is shown, with
      any invisible or text-direction characters flagged, before it can be chosen. The signer gets a
      session rule, and a key and a signer can share a profile.
    - Credentials found in the file are listed by name and not used. When you switch to entering
      different credentials, the wizard offers to remove the profile it saved before, with its
      stored secrets. Loading another definition, or leaving the wizard before the scan starts,
      offers the same for each profile saved in it that nothing would use any more.
    - *Try one request* sends one read-only operation (a GraphQL query counts) and says whether the
      API accepted it and whether the credentials and signature were on it.
  - **Operations:** lists every operation with its example request. GET, HEAD, OPTIONS and POST in
    scope are ticked. PUT, PATCH, DELETE and GraphQL mutations stay off until you opt in and tick
    them, and a later scan of history doesn't replay a mutation either unless asked (see
    `--include-methods MUTATION`). POST requests are replayed with attack data, so the same warning
    as the website scan applies.
  - **Depth and speed:** as in the guided scan. Each chosen operation is sent once, then attacked.
    Parameters without an example get a typed test value. An operation that answers 401 or 403 is
    still scanned, and the results point out that those baselines were rejected.
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
  OPTIONS requests are replayed, and logout paths never are. A request sent from
  **Traffic** (right-click › *Test access control…*) shows as *From Traffic*: it is tested
  as it is, whatever its method or path and even if it carries no credentials. It is sent
  twice as its owner, then as each identity and with no session. The form warns when it is a
  POST, a GraphQL mutation or another request that may change data, or when its path looks
  like a logout (which can end the owner's and each identity's session, so later results may
  not be reliable), and *Start run* asks first. Only a yes passes what `authz run` needs to
  replay it: `--include-methods` with its method, and for a logout an `--exclude` that matches
  no path. Once the run has started, the form goes back to all recorded requests.
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
working on the previous output. Decoding `url` reads `+` as a space, as form data does;
`percent` undoes only the `%XX` escapes and keeps `+`, as paths, cookies, and headers need.

- **Compression:** gzip, zlib, and raw deflate encode and decode; Brotli only decodes.
  Decoding `deflate` also takes the zlib-wrapped form servers send as
  `Content-Encoding: deflate`. Output over 16 MB is refused, so a small "zip bomb" can't
  fill memory.
- **Smart decode** finds the layers on the input and puts them in as steps, so you can see
  what it did and change it. It tries, in turn: gzip and zlib (by their first bytes), a JWT,
  URL escapes, HTML entities, hex, and Base64, up to 8 layers. It stops when nothing
  applies, and at JSON (a JWT's included): the document is left as the server holds it,
  with its strings' `%2F`, `+`, and `&quot;` intact. The note beside the button says when
  it stopped for another reason: the 8-layer limit (more may remain; use the last output as
  the input and run it again), or a gzip or zlib layer over the 16 MB limit. It is cautious:
  hex and Base64 count only when the whole input is one and it decodes to readable text,
  JSON, or compressed data that unpacks. Short inputs also need
  a clear sign: for Base64, padding, a symbol, or mixed case with digits; for hex, a `0x`
  prefix or spaces or colons between bytes. So words like `password` or `deadbeef` stay
  as they are. Base64 with a raw `+` and an escaped `=` (common in cookies) gets `percent`, not
  `url`, so the `+` survives even when the Base64 holds binary. When it finds no layer (JSON
  as the input included), the steps stay as they were. When it misses a layer, add the step
  by hand.

On the command line, `decode auto` does the same and lists what it applied in `steps`, and
why it stopped in `stopped`: `"nothing"`, `"json"`, `"depth"` (the 8-layer limit), or
`{"refused": "gzip", "error": "..."}` for a layer over the size limit. Text output (the
default in a terminal) is the result alone, read as UTF-8, so binary bytes come out as
replacement characters; JSON output gives them as Base64, and `--raw` prints them as they are:

```sh
brainproxy decode auto 'H4sIAAAAAAAA%2F6tWKsrPSVWyUkpMyc3MU6oFAOdvn34QAAAA'
# {"role":"admin"}, with "steps": ["url", "base64", "gzip"] and "stopped": "json" in the JSON output
brainproxy encode gzip,base64,url '{"role":"admin"}'    # and back again
brainproxy decode auto --raw "$cookie" > value.bin     # binary output, byte for byte
```

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
  Chromium, curl, or a shell at it. *Port* sets the port on 127.0.0.1 the app uses, for every
  project. Left empty, it is 8080, or the next free one when a project opens. A chosen port
  is used as is: if it's taken, the proxy stays off and says why. A running proxy on another
  port keeps it until you press *Restart on port N*, which keeps its bind address and
  options (a custom log file goes back to the default). Browsers opened earlier still point
  at the old port: close them and open them again, or their traffic goes to whatever proxy
  starts on that port later, maybe another project's. Reconfigure tools you set up by hand. `brainproxy proxy start` from a shell or MCP
  still defaults to 8080 unless given `--listen`.
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
  opens* (on the port set under *Proxy*). While it is on, a proxy the app started (when the
  project opened, or from the proxy pill, *Open browser*, *Start proxy* or *Record a login*)
  stops when the project or the window closes; one started from a shell or MCP keeps running.
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
brainproxy history list --contains apiKey --source proxy   # in requests and responses, bodies decoded; case-sensitive
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

### Who recorded what

Each history entry has:

- `origin`: `gui` (the desktop app), `cli` (a terminal or script) or `mcp` (an agent through
  MCP); NULL, shown as unknown, for entries recorded before brainproxy kept it. Background
  jobs, fuzz runs and the proxy record the origin of the command that started them.
- `client_addr`: for proxy entries, the address (`ip:port`) of the client that sent the
  request, whether intercepted, passed through, a WebSocket upgrade, or invisible.
- `edited_by`: for proxy entries, who changed the request before it went out, as a JSON
  list: `[{"by":"mcp","intercept":4}]` for an edit forwarded from the intercept queue,
  `[{"by":"gui","rule":2}]` for a match-and-replace rule (`by` is who added or last enabled
  the rule). NULL when nothing changed it; an intercept forwarded unchanged isn't an edit.
- `sni`: the TLS server name sent when `--sni` overrode it (`send`, `fuzz`, `ws send`); NULL
  when it was the target host, and for plain HTTP.
- `note_origin`, `note_changed_at`, `tags_origin`, `tags_changed_at`: who last set the note
  (`history note`) or changed the tags (`history tag`), and when.

**Origin is per process.** `origin` is who started the process that recorded the row, not
who sent the request. For proxy rows that is whoever started the proxy: a proxy started via
MCP records a person's browsing as `mcp`, and a proxy started from the app records an
agent's requests through it (say, from `browser open`) as `gui`. For proxy rows,
`client_addr` says which client sent it and `edited_by` who changed it on the way, and
`history show` says "recorded by a proxy started from ..." rather than "recorded from ...".
The same holds for findings: a finding's `origin` is who started the scan that raised it (the
proxy's passive scan, a scan job), not who sent the traffic it was found in.

```sh
brainproxy history list --origin mcp         # what agents' processes recorded; also gui, cli, unknown
brainproxy history show 42                   # entry.origin, client_addr, edited_by, sni, note_origin
brainproxy query "SELECT origin, count(*) FROM history GROUP BY origin"
brainproxy query "SELECT id, url, edited_by FROM history WHERE edited_by LIKE '%\"mcp\"%'"   # what agents edited
```

The intercept queue keeps who decided each held message: `resolved_by` is `gui`, `cli` or
`mcp` for `intercept forward` and `intercept drop`, and NULL when it expired or the proxy
dropped it itself; `edited` says whether it was forwarded with a different message
(`intercept list`, `intercept show`, the `intercepts` table). An edited request's history
row names the intercept in `edited_by`. A response edited at intercept, or changed by a
response rule, is recorded in history as the server sent it; the intercept row has the
edit. Match-and-replace rules keep an `origin` (`rules list`): who added the rule, or last
enabled it.

Findings have an `origin` too (who added them: the proxy's passive scan, a scan job, ...),
and `state_origin` and `state_changed_at` say who last changed the state with `findings mark`
and when, so a finding an agent marked as a false positive says so. `note_origin` and
`note_changed_at` do the same for the note. `findings list` and `findings show` include
them. Reports carry them in every format:

- JSON: each instance has `state_origin`, `state_changed_at`, `note_origin`,
  `note_changed_at` and `state_text` ("confirmed via MCP (an agent) at ...").
- Markdown and HTML say it in words on each finding. In HTML a finding a person confirmed
  (from the app or the command line) is tagged **confirmed**, one an agent confirmed
  **confirmed via MCP (an agent)**.
- SARIF: `stateOrigin`, `stateChangedAt`, `stateText`, `noteOrigin`, `noteChangedAt` in each
  result's properties.

False positives are left out of a report by default. The report counts them by who marked
them (`summary.false_positives_left_out`), and lists the ones an agent marked
(`agent_false_positives`; a "Marked false positive by an agent" section in Markdown and HTML,
`agentFalsePositives` in SARIF run properties), so an agent can't make a finding vanish
from a report unseen.

`scan passive --rescan` rescans all history and keeps what people decided: a finding found
again keeps its id, state, note, origin and who set them. One not found again (its rule was
turned off, say) is removed, unless it was triaged (its state was changed or it has a note):
that one is kept with `hits` 0. The result counts `removed` and `kept_not_found`.

The app sets `BRAINPROXY_CLIENT=gui` on the commands it runs; the MCP server sets
`BRAINPROXY_MCP_CALL`, which wins over it, and an agent can set neither.

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
  these methods. A GraphQL mutation (a request whose `query`, in a JSON body, an
  `application/graphql` body or the URL, defines one) is `MUTATION` whatever its method and however
  it was recorded, so one sent once by `import api --include-methods MUTATION`, a one-request check
  or the proxy isn't replayed by a later scan unless `--include-methods MUTATION` (or `all`) says
  so. A request picked with `--history-id` needs the same opt-in: naming a DELETE or a mutation
  without `--include-methods DELETE` (or `MUTATION`) is refused with exit code 2 before anything is sent.
- `scan active --checks`: the same opt-in applies to the requests a template sends, from any
  store or file. A check's PUT, PATCH, DELETE (or other method), or GraphQL mutation isn't sent
  without `--include-methods`; the output counts those in `check_skipped_methods`. Every request a
  check does send is recorded in history (source `scan`), finding or not.
- `import api SOURCE`: an OpenAPI 3, Swagger 2.0 (JSON or YAML) or Postman v2 document, or a
  GraphQL schema (SDL file or introspection result), detected from its contents. `--dry-run` previews and sends nothing for a local file: servers,
  declared credentials, variables, every operation with its index and whether it would be sent,
  and which operations were skipped and why. `--server N` picks a listed server, `--base-url`
  overrides them, `--var NAME=VALUE` sets a Postman variable, `--only 0,3,7` picks operations by
  index, and `--expect-sha256 HEX` refuses a document that changed since the preview. It sends
  GET, HEAD, OPTIONS and POST unless `--include-methods` adds others. Credentials in the
  document (Postman auth, secret-named headers, query parameters and body fields, and variables
  they use) are reported by name in `credentials` and never sent or stored; use an auth profile.
  A document fetched from a URL is recorded in history (source `import`) as it was sent and
  answered, like any other request (so are `--graphql`'s introspection and `scan active --api`'s
  fetch), except the document itself: the row keeps the response's head, and its error says
  `API document: body omitted (it can hold credentials the import withholds)` with the body's
  length and sha256 (the `document_sha256` the import reports).
- Postman environments: `--environment FILE` reads an environment export for the collection's
  variables (a local file only; `--var` goes on top). Values the environment marks secret, or whose
  names look like credentials, are withheld like the collection's own, and the preview lists them as
  secret with no value. Only the path goes in a background job's record. `--expect-environment-sha256`
  refuses a file that changed since the preview, which lists its sha256 under `environment`.
- Postman pre-request scripts are listed under `scripts` (where each runs, how many requests it
  reaches, whether it seems to sign, calls it makes that can't run) and never run by `import api`.
  `--show-scripts` adds their text. To run one for every request, make it a signer (below).
- GraphQL: a schema file has no endpoint, so it needs `--base-url URL` (the endpoint itself);
  `--graphql` with an endpoint's URL introspects it instead. Each query field becomes an
  operation with typed example variables, and mutations are opt-in as `--include-methods MUTATION`,
  like PUT and DELETE. Introspection that's turned off or needs a login says so; use a schema file,
  or `--auth`.
- The preview also lists what the document declares about OAuth (`oauth`: flow, token and sign-in
  URLs, scopes, an OpenID Connect discovery URL) and a Postman collection's AWS Signature settings
  (`aws`: region and service), to fill in a profile or signer. Client ids and secrets are never shown.
- `scan active --api SOURCE`: the same document flags in one job: send each chosen in-scope
  operation once as a baseline (history source `import`), then attack exactly those. Baselines
  count as the `scan` tool for session rules. A scan with nothing in scope exits 6 and sends
  nothing. The result has an `import` object with what was sent and skipped.
- `scan active --preset quick|standard|thorough`: the guided scan's depths, for scripts and CI.
  Flags given as well win, so `--preset thorough --strength high` scans with high strength.
  `--preset` doesn't crawl by itself; pair it with `--crawl`, as the guided scan does.

  | Preset | Same as |
  |--------|---------|
  | `quick` | `--strength medium --crawl-depth 3 --crawl-max-pages 150` |
  | `standard` | `--strength high --crawl-depth 5 --crawl-max-pages 500 --cookies --url-path` |
  | `thorough` | `--strength insane --crawl-depth 8 --crawl-max-pages 1500 --cookies --url-path` |

  The guided Thorough scan also adds `--browser` when a browser is installed.

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

API keys in an auth profile: `auth add NAME --header-env 'X-Api-Key=VAR'` reads the variable once
and stores the value as `--header` does, so it stays off the command line (for a bearer token,
`'Authorization=VAR'` with `Bearer ...` in the variable). `auth add NAME --query-key 'api_key=VAR'
--key-origin ORIGIN` is for a key in the query string: history and findings hold
`«auth:NAME:query:api_key»`, the value goes only into the request line of requests to those
origins, and scans don't attack it. `auth show` and `auth list` mask both. `auth add` on an
existing name replaces the profile's fields, query keys (unless `--keep-query-keys`), OAuth setup
(unless `--keep-oauth`) and session, and keeps its signers, rules and macros.

OAuth 2.0 in an auth profile, in place of a login:

- `auth add NAME --oauth-flow FLOW --oauth-token-url URL --oauth-client-id ID
  [--oauth-client-secret-env VAR] [--oauth-scope S] [--oauth-audience A] [--oauth-param K=V ...]
  [--oauth-client-auth body|basic]`. FLOW is `client_credentials`, `password` (with `--username` and
  a password), `refresh_token` (with `--oauth-refresh-token-env VAR`) or `authorization_code` (with
  `--oauth-authorize-url URL`, then `auth oauth authorize NAME`). Variables are read at each token
  request and never stored, unless `--oauth-store-secrets` reads them once and stores the values in
  the project, for background jobs that won't have them (the desktop app does this). The access
  token is kept in the project like a login's token. A refresh token the server sends is kept only
  for the command that got it, unless `--oauth-store-secrets` is set: without it, the next command
  starts from the flow's own grant (the refresh token variable for `refresh_token`, a new
  `auth oauth authorize` for `authorization_code` once the access token has expired). A server that
  rotates refresh tokens needs `--oauth-store-secrets` for the `refresh_token` flow to carry on past
  one command. `--oauth-param`
  is stored as given, so a name that looks like a credential (`client_assertion`, `*_token`,
  `*secret*`, ...) is refused; `auth show` masks such a value if one is there.
- `auth oauth authorize NAME [--no-open] [--wait SECONDS]` prints the sign-in URL on stderr, opens
  the browser, and waits on `http://127.0.0.1:PORT/callback` (`--oauth-redirect-port` for a client
  registered with a fixed port; any free port otherwise) with PKCE (S256) and a `state` check. A
  redirect without the right `state`, or on another path, is refused and the wait goes on.
- `auth oauth discover URL` reads an OpenID Connect discovery document (in scope) and prints the
  token and sign-in URLs. The fetch is recorded in history (source `auth`), as `send` records.
- The token goes on requests as `Authorization: Bearer «auth:NAME:token»`, filled on the wire like a
  login's token. A token due to expire within 30 seconds is renewed before the next request, once
  however many requests notice, with the refresh token when there is one (a rotated one replaces
  it) and the flow's own grant when it fails; a 401 renews it too, within `--max-relogins`. A
  browser sign-in that can't be renewed asks for `auth oauth authorize` again.
- The token endpoint must be in the engagement's scope; nothing widens it. Token requests get none
  of the profile's other credentials and follow no redirects. Their history rows keep only the
  method, URL without its query, and outcome, since they carry the client secret and the answers
  hold tokens. Errors give the endpoint's `error` code, never
  its description. `auth status` says whether there is a token and a refresh token, and when the
  token expires, never what they are.
- Only bearer tokens are taken. Not built: the device code and implicit flows, private-key JWT
  client authentication, and token introspection.

Request signing (`auth sign`), for APIs that reject a request whose signature doesn't match
and targets that want a JWT you choose the claims of:

- `auth sign add PROFILE NAME (--secret-env VAR | --secret-file PATH) --origin ORIGIN ...
  --to header:NAME|query:NAME [--wrap 'Bearer {{signature}}'] [--set-header 'NAME: TEMPLATE' ...]`,
  then `--canonical TEMPLATE [--hash sha1|sha256|sha384|sha512] [--output hex|base64|base64url]` for
  an HMAC, or `--jwt HS256|HS384|HS512|RS256 [--claims JSON] [--ttl SECONDS] [--kid ID] [--resign]`
  for a JWT, or `--key-alg ALG --canonical TEMPLATE [--output ...]` for a signature made with a
  private key. JWT algorithms are HS256/384/512, RS256/384/512, PS256/384/512, ES256/384 and EdDSA;
  `--key-alg` takes all but the HS ones. `--secret-encoding hex|base64` decodes an HMAC key; the
  others take a PEM private key (RSA as PKCS#8 or PKCS#1, EC and Ed25519 as PKCS#8:
  `openssl pkcs8 -topk8 -nocrypt` converts one). ECDSA signatures are the fixed r||s form JWS uses.
  `auth sign list/remove`. Then `auth rule add PROFILE --action sign:NAME [--tool ...] [--url ...]`
  turns it on; a rule's `check` doesn't skip its `sign`. Adding a name that exists replaces the
  signer and runs it last, or keeps its place with `--keep-place`. Settings › Auth profiles has
  all of this too.
- AWS Signature Version 4: `auth sign add PROFILE NAME --sigv4-region R --sigv4-service S
  (--secret-env VAR | --secret-file PATH) (--access-key-env VAR | --access-key-file PATH)
  [--session-token-env VAR | --session-token-file PATH] --origin ORIGIN`. It sets `X-Amz-Date`,
  `X-Amz-Content-Sha256` and, with a session token, `X-Amz-Security-Token`, and signs `host`,
  `content-type` and every `x-amz-*` header into `Authorization`. The path is encoded again for every
  service but S3, as AWS expects. None of the three values is stored; all three are read when the
  signer first signs in a command and kept until it ends, so credentials renewed in their files are
  picked up by the next command (a running proxy keeps them until it restarts).
- A Postman pre-request script: `auth sign add PROFILE NAME --script FILE [--script-sha256 HEX]
  [--environment ENV_FILE] [--script-var NAME=VALUE ...] --origin ORIGIN`. FILE is a collection
  (`--script-sha256` picks one of its scripts, as `import api` lists them, unless it has only one)
  or a `.js` file. This runs code from that file, so read it first: `import api --show-scripts`.
  The script sees the request as it is sent (method, URL, headers, body) through `pm.request`,
  the collection's variables, then the environment's, then `--script-var`, through `pm.environment`,
  `pm.variables` and the rest, and CryptoJS, `require('crypto-js')`, `require('crypto')`'s hashes and
  HMACs, `uuid`, `btoa` and `atob`. It may change headers and the query; a variable it sets fills
  `{{name}}` in the request line and in the collection headers that use it (which `import api`
  strips as credentials). Changing the method, URL, host, body, `Content-Length` or cookies fails the
  send, as do `pm.sendRequest`, `pm.cookies`, `pm.vault` and other modules.
- A script runs in a memory-safe interpreter with no file, network or process access, in a fresh
  context per request, with a loop and recursion limit and without `SharedArrayBuffer`, `Atomics` or
  `Temporal`. Each run is a child process of brainproxy with an empty environment, killed after five
  seconds, so a script that never ends (a regex that backtracks, a loop of `await`s) leaves nothing
  running. On Linux the child's address space is limited to 1 GiB; macOS doesn't enforce that limit
  and Windows has none, so there only the time limit bounds a run. A script stopped at a limit
  stops its signer for the rest of the command: later requests fail at once, without another run;
  a script that throws fails only that request. One never runs unless chosen. The collection and
  environment stay in their files:
  the signer stores their paths and the script's sha256, and refuses a script that changed. Error
  messages mask the variables' values. Only the chosen script runs; scripts of folders and requests,
  and test scripts, don't.
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
- Signers are data: templates name request parts and nothing is executed, except a script signer's
  script (above). A signer can read any file the process can as its key. An HMAC, private-key or
  JWT signer sends only the signature made with it. A SigV4 signer also sends the access key id (in
  `Authorization`) and the session token (`X-Amz-Security-Token`) as they are. A script signer can
  put anything it sees, its environment file and variables included, into a header or the query.
  So point `--access-key-*`, `--session-token-*` and `--environment` only at what that API may
  receive.
- Through MCP (`mcp serve`), `auth sign add --script` is refused: a person reads the script and
  adds that signer in the app or a terminal. Variables named by `--secret-env`, `--access-key-env`,
  `--session-token-env` (and by `auth add`'s `--header-env`, `--query-key`, `--password-env` and
  `--oauth-*-env`) must start with `BRAINPROXY_SECRET_`, and `auth oauth authorize` doesn't open a
  browser.

### What is recorded when a request doesn't finish

Every request brainproxy puts on the wire leaves a history row, whatever happens next.

- `send`, `send --race` and `ws send` write each request's row just before it goes out, with
  the error `sent; no response recorded (cancelled or interrupted)`, and complete it with the
  response or the failure. A command that is killed or crashes keeps that row. Ctrl-C or
  SIGTERM while it waits records `cancelled by user before a response was recorded` instead
  (the request may not have gone out yet, if its connection was still opening), and the
  command fails. A row already answered is never changed.
- With `--auth`, the session's own requests (login, CSRF page, check URL, macro steps) are
  recorded the same way, with source `auth`. A request answered with "logged out" keeps its
  row (the 401, say); the request sent again after the re-login gets a second row. Stopped
  during the re-login, the login's row keeps the pending error.
- OAuth token requests carry the client secret and the answers hold tokens, so their rows
  keep no content: method, URL without its query string, time, and how they ended, with an
  error starting `token request: content omitted`.
- The app, and the MCP server when a call is cancelled or times out, stop a command with
  SIGTERM and kill it 3 seconds later if it is still running. Windows has no SIGTERM: there
  the command is killed at once, and its row keeps the pending error.
- `ws send` records the connection and each message as they happen, not at the end (a
  message to the server when it is queued, so one queued just before the connection dropped
  may not have gone out). Killed while listening, the connection stays `open` with every
  message up to then; stopped with Ctrl-C or SIGTERM, it is closed with that error.
- An HTTP/2 race (`send --race N --http2`) that fails after connecting records each copy
  with the error. If no copy got a response, the command fails with the error's kind (exit
  3) and the message lists the rows; with `--format json` the envelope's `data.results`
  has each copy's `id` too. Every item of a race that ran, failed or not, has its history `id`.
- The requests a `scan active --checks` template sends, and the document fetches of `import`
  and `scan active --api` (with `--graphql`, the introspection), are recorded the same way: a row
  just before the request goes out, completed with the response or the failure. A check request
  cut off by its timeout, or by a stopped scan, keeps `sent; no response recorded (the check
  timed out or the scan stopped)`.
- `proxy stop` (and anything that stops the proxy) stops sending, then waits up to 3 seconds
  for requests already forwarded. Ones still unanswered are recorded with `proxy stopped
  before the response arrived`. Requests arriving meanwhile get a 503 and aren't sent, and
  neither is a re-login retry. The proxy then writes out every capture still queued
  (passive checks of the last ones wait for the next scan); `proxy stop` waits up to 30
  seconds for it to exit before killing it.
- `--no-store` (`send`, `send --race`, `ws send`) keeps no content, but still writes a row:
  the time, source, target, method, and path. The query string is left out too, since it
  often holds a token: `query` is empty, and `url` and the stored request line stop at the
  path. Headers, bodies, and the response are left out, `status` is empty (so passive checks
  skip it), and `error` starts with `not stored (--no-store): content omitted`, then
  `; query string omitted` if there was one, then how it ended (`; response status 200`,
  or the failure). The session's own requests for that command (`--auth`) are recorded the
  same way. Find these rows with `SELECT * FROM history WHERE error LIKE 'not stored%'`.
  `ws send --no-store` records the handshake that way and nothing of the connection or its
  messages.

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

`--scan JOB --since-scan EARLIER` is for a pipeline that scans the same project again and again.
"New" against one scan means first found by that scan, so a finding first seen by a run that failed
or was stopped, and found again by the next run, would count as unchanged and never trip
`--new-only`. With `--since-scan`, a finding the scan found that was first seen after `EARLIER`
finished is new as well; what `EARLIER` found itself is not. Give the last scan that completed.
"Unchanged" and "fixed" are still against `JOB`, and `data.baseline.since_scan` shows the job and
when it finished. `EARLIER` must be
an active scan that completed (not failed, stopped, or out of `--max-minutes`) and finished before
`JOB` started; anything else is refused with `2`.

```bash
# Job 12 completed; job 13 failed after finding something; job 14 completed.
brainproxy --project app.bpdb findings compare --scan 14 --since-scan 12 --fail-on high --new-only
```

| Exit code | Meaning |
|-----------|---------|
| `0` | Compared, and the gate (if any) passed |
| `5` | Compared, and the gate found something. The output is complete: `ok` is true, and `data.gate` has `passed: false`, the `count`, and the `findings` |
| `4` | The baseline file, project, or scan job (`--scan` or `--since-scan`) doesn't exist |
| `2` | Bad arguments; a file that isn't usable (not a report, cut off, or the baseline and the findings compared being the same file); `--fail-on` with a filtered `--current` or a scan that didn't complete; or a `--since-scan` job that didn't complete before the `--scan` one started |

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
so the owner stays logged in. A request picked with `--history-id` may lack credentials, but its
method needs `--include-methods` like any other, and one matching `--exclude` is refused
(exit code 2, nothing sent) unless `--exclude` is given a pattern it doesn't match. URLs on
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
Everything its tool calls record (history, findings, finding state changes) is marked with
origin `mcp`, including what a proxy or job it started records; see
[Who recorded what](#who-recorded-what).

A tool call can't leave what it sends out of history: `send` and `ws send` with `--no-store`
and `fuzz run --store none` or `--store matches` are refused. `browser open` isn't offered (the
project's browser profile keeps the person's sign-ins), and other options that need a person are
refused too; docs/MCP.md lists them.

---

## Rules, checks, and wordlists

- **ZAP rules.** The passive (53) and active (52) scan rules are ported from OWASP ZAP,
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
| Container: "can't verify job N" (or fuzz run) | The same for a job or fuzz run: `brainproxy job stop --forget N` (or `fuzz stop --forget N`) marks it failed. |
| Container: "can't open the proxy lock file" | A lock file is there that this user can't open, so starting would go unseen from other containers. Make it readable (`chmod 644`), or remove it if no proxy (or OOB listener) runs for this project anywhere. |
| Container: "unable to open database file" | The user in the container can't write to the folder mounted at `/work`. Add `--user "$(id -u):$(id -g)"` for a host folder you own. See [Container image](#container-image). |
| "The proxy didn't start: none of ports 8080-8089 could be opened" | Other programs hold or block those ports. Stop them, or choose a port in **Settings › Proxy**. From a shell: `brainproxy proxy start --listen 127.0.0.1:9090`. |
| "cannot listen on …: the port is already in use" | Another program or another project's proxy holds that port. Stop it, or choose another port in **Settings › Proxy** (or with `--listen`). A chosen port is never swapped for another, so the proxy stays off until then. |
| "cannot listen on …: permission denied" | Ports below 1024 usually need elevated privileges, and the system can reserve others (Windows does, in ranges that change). Choose another port in **Settings › Proxy** (or with `--listen`). |
| A scan finds little | Make sure it covers the site: use *Crawl and audit* (with *Run JavaScript* for single-page apps), browse the app through the proxy first, or log in with an auth profile. Download the Nuclei templates. |
| Windows says "Windows protected your PC" | The installer isn't signed yet: More info → Run anyway. |
| Windows: tools other than the opened browser reject the CA | `brainproxy ca install-system` adds it to your user's Trusted Root store (Windows asks you to confirm). Firefox keeps its own store; import it there. |
| macOS says the app can't be opened or is damaged | System Settings → Privacy & Security → Open Anyway, or run the `xattr` command in [Install](#install). |
