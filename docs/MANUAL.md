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
Settings › Rules & Updates turns the check off, or makes the download automatic. On the
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

The scope decides where a connection goes: the target's address and, over TLS, a server name
set with `--sni` (one other than the target's must be listed by name). With an IP address or a
CIDR range in scope, any host name that resolves to it, by DNS or through a `connection hosts`
override, is in scope as a target too. On a shared front end (a CDN or load balancer), list the
sites' names in the scope rather than its addresses.

A `Host` header (HTTP/2 sends it as `:authority`) doesn't pick where the connection goes, but on
a shared front end it can pick the site, so a request to an in-scope address can reach a site
outside the scope. Host-header injection tests need such a request, so it isn't simply refused.
Every request is checked as it goes on the wire, after an auth profile's session, its values
and signers have been applied: a host it names that isn't the target's and isn't listed by name
in the engagement scope (on the target's port, or with no port) is foreign. So is a request
target other than a path, `*` or a URL naming a listed host (a URL holding a `\` counts, since
servers read it differently), a request line that isn't three tokens separated by single
spaces (a space in the path or an HTTP/0.9 line counts too), a bare CR or LF in the head, and a
second request after the body its framing (Content-Length or chunked) says (with no framing, a
`--verbatim` body that starts with a request line is one, in any case), and framing servers may
read differently: Content-Length headers that differ, or Content-Length with Transfer-Encoding.
So request smuggling tests (CL.TE, TE.CL, a request after the body) are Host-header tests here:
through MCP they need `--host-header-test`. `send` (races too) and `ws send` warn about a
foreign host in the output's `host_warning`, and on stderr in text mode; so does `fuzz run` for
its template.

Through MCP a request with a foreign host is refused (`out_of_scope`) unless the command says
the test is meant with `--host-header-test` (`send`, `fuzz run`, `ws send`, `scan active` for its
base requests, and `auth login`, `auth status` and `auth macro run` for a profile's own
requests), so the intent is on record. One refused before it is written to history leaves no
row; one refused on the wire (a fuzz payload that makes a header a Host, a Host a session added)
keeps its row, with the refusal as its error, and a scan never picks such a row or takes it as
`--history-id`. A crawl's or an import's `-H Host` or a collection's Host header is refused the
same way, request by request, and their summaries list the host in `out_of_scope_hosts`.
`scan active` checks its base requests (URLs, API items, recorded rows, a session's) the same
way and lists the hosts of those it doesn't attack in `refused_hosts`; a rule's own Host is its
test (below). A fuzz payload with a raw line break that goes into the head unencoded (a
CRLF-injection test) needs `--host-header-test` through MCP, as it can start a Host header.

Settings that put a Host on requests still to come are checked when they are saved too: an auth
profile's `--header` or `--token-header`, its login request and `--login-header` (the login
URL's own host is fine), a macro's steps (`auth macro add`), and a match-and-replace rule (`rules
add`, `rules import`, or `rules enable` of a disabled one) whose replacement writes a Host line
or an absolute URL, sets the header named `Host`, rewrites the Host of a request to a host the
engagement lists, or copies a header's name or the request target from the request (`$1`). A rule
can match anything, so that check is best effort; the proxy also compares each request's foreign
hosts before and after the rules, and refuses one an agent's rule brought in (a 502, and a row
saying so) unless the rule was added or enabled with `--host-header-test`. So do `send`, a fuzz
run and a scan for the rules that apply to them (the request fails as out of scope, unsent). Session rules and signers can't set the Host at all. Saving a setting
again with the Host it already had isn't checked again; an edited request forwarded with
`intercept forward` is checked for hosts the edit brings in. A person on the command line or in
the app is warned, never refused.

For everyone: a header name or value given as input (`-H`, an auth profile's headers, a
collection's) can't hold a CR, LF or NUL, which would start another header, and neither can a
proxy rule's request-line or request-header replacement, or a value a session fills into a
request's head (a token or cookie learned from a reply, a macro's value): such a request isn't
sent. A `-H Host` takes the place of the target's Host rather than adding a second, and a request
sent over HTTP/2 must have a path, `*` or a URL as its target, and a Host with no user part, so
nothing runs into the `:authority`.

Not checked: what active scan rules and check templates put in the Host header themselves
(Cloud Metadata names the metadata service, for one; `scan active --inject-header Host` puts
payloads there), which are Host-header tests by nature and connect to the scanned in-scope host;
requests sent again as they were recorded (`findings retest`); and a proxied client's own
requests.

**Proxy scope.** A separate, changeable list that decides which proxied traffic is
recorded and intercepted. It is empty by default, which means everything the engagement
allows. Traffic outside it still goes out and leaves a row in history, with only its request
line (see [What is recorded when a request doesn't finish](#what-is-recorded-when-a-request-doesnt-finish)),
and each change to it says who made it (see [Who recorded what](#who-recorded-what)).

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
6. **Report.** **Findings › Report…** builds a report with a live preview, leaving out
   false positives, accepted risks and fixed findings: a summary in plain words, what to fix
   first, then each issue with what it means, how to fix it, and where it was found, with
   the technical evidence folded away. Pick who it is for (see [Report layouts](#report-layouts)),
   your branding and the format: HTML, PDF, Word (DOCX) or Markdown. On the command line:
   `brainproxy report html -o report.html` (also `markdown`, `json`, `sarif`, `pdf`, `docx`). Every format masks session secrets
   (cookie values, `Authorization` credentials and a Basic credential's decoded password,
   API-key and other secret-named headers (any name that says `auth`, but not `Author` or
   `Authority`; a credential key such as `Api-Key`, `X-Functions-Key`, `Ocp-Apim-Subscription-Key`,
   `User-Key` or any other `...-Key`, but not a key that is data such as `Sort-Key`, `Primary-Key` or
   `X-Cache-Key`; and any header whose value starts with an auth scheme such as `Bearer` or
   `Basic` followed by a credential rather than a word, keeping the scheme; tokens sent as WebSocket subprotocols in `Sec-WebSocket-Protocol`, keeping plain
   subprotocol names such as `graphql-transport-ws`; not `WWW-Authenticate` challenges, `Sec-WebSocket-Key` or `Idempotency-Key`, which
   hold no credential), token and password parameters in URLs and their
   fragments, forms, multipart, JSON (arrays and JSON inside strings too), XML and script
   bodies, hidden form fields and secret-named attributes, passwords in URLs, JWTs, and every
   password, token, cookie and credential header the project's auth profiles hold) as
   `[redacted]`, wherever the report quotes them, in any ASCII case (an accented or other
   non-ASCII letter must match as written) and percent-, JSON-, HTML- or
   base64-encoded (notes, write-ups, ticket links and findings added by hand included), and says how
   many places it masked; `--no-redact` keeps
   them as recorded. A signed cookie's session id (`s:ID.signature`, as Express writes
   `connect.sid`) is masked where it is quoted on its own too, and two secrets that overlap
   are masked together. A secret nothing marks, such as a token typed into a finding's title
   or a note ("used token ..."), can't be told from other text: name it with `--mask VALUE`
   (repeatable, at least 6 characters) and it is masked like the project's own secrets,
   everywhere the report quotes it, in every format: the title, the layout's company, the
   engagement scope and filters it shows, hosts and states included. A body is cut to its
   evidence limit only once its secrets are masked, so none is left half shown at the cut.
   `findings repro` takes `--mask` too; `findings ticket` doesn't, since the command it
   prints runs it again to file the ticket (see *Tickets* below). An issue seen in more than one
   request also carries its latest sighting next to the first. A project collects findings across
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
  curl command. Before scanning a DELETE, PUT or PATCH request or a GraphQL mutation, the Site
  map asks, naming it, as such a request is only attacked when you opt in; a branch scan skips
  them.
- **Import API (sends each once)…:** puts an API's operations in history without scanning them, to
  work on by hand. This isn't offline: every ticked operation is sent to the target once. It takes
  the same steps as the *Guided API scan* (definition, server, authentication, operations; PUT,
  PATCH, DELETE and GraphQL mutations stay off unless you opt in), then sends each ticked operation
  once, as written, in scope only (`import api`). *Hide* shows the map while it runs; *Show* in the
  toolbar brings the progress back. It ends with how many requests were recorded and links to the
  Site map and **Proxy › Traffic**, which opens showing only the source `import`; right-click one to
  send it to Replay. A definition read from a URL shows there too, as its fetch: each fetch (the
  preview's and the import's) keeps the response's head only, not the document. One import runs at a time. The guided API scan's first step links here too.
  A HAR file (a browser's or another proxy's recording) can be picked as the definition too: each
  of its requests is one operation, as below under `import har`.
- **Scope tab:** shows the engagement, checks whether a host would be allowed, and edits
  the proxy scope. Below it, the latest changes to the proxy scope and the TLS pass-through
  list, with who made each and whether it narrowed recording. While an agent's narrowing
  change hasn't been changed by a person since, the tab says so, and so does a **Recording
  narrowed by an agent** pill in the top bar, which opens this tab. Saving the scope yourself,
  even unchanged, clears the scope's flag, and changing the pass-through list clears the
  pass-through list's; **Keep as it is** keeps what the agent changed and clears every flag
  shown (if the agent narrowed something since the tab showed it, it shows that instead and
  keeps nothing), and the agent putting a setting back as it was clears that setting's. An
  agent's change to where traffic goes (upstream proxies, host overrides, client
  certificates) gets its own notice there and a **Routing changed by an agent** pill; changing
  that setting in Settings › Connections clears it, and its **Keep as it is** runs
  `connection review`.

### Proxy
- **Intercept:** turn it on to hold requests (and optionally responses) before they are
  sent. Edit a held message and Forward it, or Drop it. Requests outside the engagement are
  never held, because they are refused anyway. Unanswered messages are forwarded after a
  timeout (Settings › Intercept options).
- **Traffic:** everything that went through the proxy, Replay, the crawler, scanners, and
  imports.
  - **Filters:** text, source, status, static assets, and out-of-scope requests (hidden by
    default).
  - **URL, Contents, Query:** the list beside the text box says what the text does. **URL**
    (the default) filters the URL, title and method of the rows shown.
  - **Contents:** search the text inside requests and responses instead: headers
    and bodies, compressed and chunked bodies included. Unlike the plain filter, the search is
    case-sensitive and literal: it matches the bytes as stored, so `a@b.com` doesn't find
    `a%40b.com`, a JSON-escaped value has to be typed escaped, and HTTP/2 header names are
    lower-case. Text that is only spaces is ignored. The other filters still apply, and
    changing one doesn't search again. New traffic that matches shows up as it arrives. A
    search stops at the first 10,000 matches the other filters show and says so; narrow it to
    see later ones.
  - **Query:** the text is a query in the filter language, run by the CLI (`history list
    --filter`) like a contents search, with the same live updates and 10,000-match stop. For
    example `status:5xx resp.body:"stack trace"`, `host:api.acme.test method=POST NOT
    path:/health` or `resp.header.server~"(?i)nginx" OR req.header.authorization:*`:
    - `FIELD:VALUE` contains the value, ASCII letters in any case; `=` equals (the same way), `!=` differs, `~`
      and `!~` match a Rust regex (case-sensitive unless it starts with `(?i)`), `<`, `<=`,
      `>`, `>=` compare numbers and times, and `FIELD:*` is present.
    - Fields: `id`, `method`, `scheme`, `host`, `port`, `path`, `query`, `url`, `status` (also
      `status:5xx`), `length` (response body bytes), `duration` (ms), `time` (`time:2026-11-08`
      is that day), `source`, `origin`, `title`, `type` (response Content-Type), `error`,
      `note`, `tag` (`tag=race:ID` is exact), `sni`, `client`, `req` and `resp` (the raw
      messages), `req.body`, `resp.body`, `body` (either), `req.type`, `req.length`,
      `req.headers`, `resp.headers`, and one header by name: `req.header.NAME`,
      `resp.header.NAME` (letters, digits, `-`, `_` and `.` in the name). A repeated header such
      as `Set-Cookie` matches when any of its values does (`!=` and `!~` when none does), and
      `:*` finds a header that is there even when it is empty.
    - Times compare as instants (`time>=2026-11-08T12:00:00Z`, to the millisecond, or with an
      offset such as `+01:00`), so a stored fraction of a second doesn't throw the order off; `time:` is a
      prefix. A regex on `req`, `resp` or a body reads the bytes, so a body that isn't UTF-8 is
      searched too.
    - A bare word searches the URL and title, as the URL filter does; a quoted one is searched
      as text, so `"status:500"` finds that text. Terms side by side must all match; `AND`,
      `OR`, `NOT` (in any case, so quote `"or"` to search for the word) and parentheses combine
      them (`NOT` first, then `AND`, then `OR`). Values with
      spaces go in double quotes, with `\"` and `\\` inside. `NOT status:500` keeps requests
      that got no response.
    - A query that doesn't parse says why and where in the toolbar, and isn't run until you
      change it. Values are always passed to the database as values, never as SQL.
    - A query on notes or tags is run again when you change a note or a highlight in Traffic;
      a change made elsewhere (the CLI, an agent) shows once you change the query.
  - **Saved filters:** *Save…* names the current filters (text and what it searches, sources
    and the checkboxes); pick one from the list to apply it again, or *Delete* it. They are kept
    in the project file (`history filters list` and `history filters save`), so they travel
    with it and an agent can read them, or add one under a new name; an agent can't change or
    remove yours. Each records who saved it (`origin`: gui, cli or mcp; `history filters list`
    marks an agent's). A saved search for a token or password stays in the project until you delete
    it. Filters an older version kept in the app's own storage move into the project the first
    time it is opened, next to any already there; one whose name is taken by a different filter
    is added as "NAME (this computer)".
  - **By:** who recorded the entry: the app, the CLI, or an agent (MCP). For a proxy entry
    that is who started the proxy, not who sent the request: hover it to see the address of
    the client that sent it.
  - **Viewer:** select a row to see the request and response (Raw, Pretty, Hex, search).
  - **Actions:** right-click to send to Replay, Fuzzer, or Diff, copy the URL or the request
    as a curl command, add a note, highlight (*Remove highlight* on a highlighted row), or
    *Create finding…* for an issue you found by hand in that request.
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
    (`authz run --history-id`). Pick the identities and start it. A request other than GET,
    HEAD or OPTIONS, or one whose path looks like a logout, is asked about first; saying yes
    passes the opt-ins the CLI needs for it (`--include-methods`, and an `--exclude` it doesn't
    match).
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
- **Event streams:** every server-sent event stream a client opened through the proxy (an
  `EventSource`, an API answer streamed as `text/event-stream`), and the ones Replay read.
  Select a stream to see its events (type, id, data, retry, arrival time); the list fills in
  while the stream is open. Select an event to read its data. Right-click a stream to send
  its request to Replay.
  - **Relayed as it arrives:** the client gets each event when the server sends it, over
    HTTP/1.1 and HTTP/2. The stream's request is in Traffic from the moment it opens; its
    response there has the head only until the stream ends, then the body too.
  - **Size limit:** a stream stores up to 4 MiB of body and 10000 events. One that goes over
    is still relayed, but nothing more of it is stored: its note starts **TRUNCATED** and the
    tab says so above the list.
  - **What doesn't apply to a stream:** response body rules, holding the response in
    Intercept, and live access-control testing need a finished response, so a stream skips
    them. Response header rules, request rules and holding the request work as usual.
  - **Replay** reads a stream for 5 seconds or 100 events and then stops, and says which.

### Replay
Edit a raw request and send it as often as you like, in separate tabs.
- **Sending:** ⌘/Ctrl+Enter sends; **Stop** gives up on a request that is still waiting.
  A stopped request may already have reached the server; if it went out, history has it,
  marked cancelled (on Windows, where the app can only kill the command, its row keeps
  `sent; no response recorded`). A stopped WebSocket tab's connection is closed as
  cancelled, with the messages sent up to then (left open on Windows).
  A send carries on while you look at another tab, and its response lands in its own tab;
  closing the tab (or the project, or quitting) stops it, so the app asks first while one
  is running. ‹ › step back and forward through what you sent. A step sent with other
  options than the tab has now says which, next to the response.
- **Auto URL-encode** (on by default): on send, characters that aren't valid in a URL
  (spaces, quotes, `<>`, `#`, non-ASCII) are encoded in the request line and in form bodies.
  `&`, `=`, `'` and existing `%XX` stay as typed, so `?q=x' OR 1=1--` arrives as
  `?q=x'%20OR%201=1--`.
- **Create finding…:** write up an issue this request shows, linked to its last send (see
  *New finding…* under **Findings**).
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
  It follows the tab's **Options**: `--http2` with HTTP/2 on, `-k` for https unless Verify TLS
  is on (Send doesn't check certificates either), `--max-time` for a timeout, and the CRLF
  body; the toast says when Send as typed or SNI is set, since curl can't do either.
  The command runs outside brainproxy, so the engagement scope doesn't apply to it. Bodies
  over 128 KB may be too long for one shell argument; save those to a file and use
  `--data-binary @FILE`.
- **Options** (per tab): each option that isn't the default shows as a chip next to the
  button, so you can see how the tab sends.
  - **HTTP/2**: send over HTTP/2 (`send --http2`). The request line can stay `HTTP/1.1`.
  - **Send as typed** (`send --verbatim`): for request smuggling and other malformed
    requests. HTTP/1 only: HTTP/2 rebuilds the request into frames, so it is greyed out
    while **HTTP/2** is on (and applies again when it is turned off). Content-Length isn't
    updated, auto URL-encode is skipped, and no blank line is added after the headers. The
    editor can't hold a CR, so the head's line breaks go out as CRLF. The body goes out as
    the editor holds it: one sent from Traffic keeps its own line breaks, and one you typed
    has bare LF ones.
  - **CRLF body**: every line break in the body goes out as CRLF, for chunked bodies typed
    by hand. Not offered for a binary body, which always keeps its bytes.
  - **SNI**: the TLS server name to send instead of the target's host.
  - **Timeout**: seconds the request may take, as a plain number such as `60` or `2.5`
    (30 by default, at most a day).
  - **Verify TLS**: refuse a server certificate that isn't valid (off by default).
  - **Don't record** (`--no-store`): history keeps only a row with the time, target, method
    and path, without the query string, headers, bodies or response. Agents can't use it
    through MCP.
- **Race:** set how many copies to send (2 to 1000) and click **Race** to send the request
  that many times at once, to look for race conditions such as a coupon redeemed twice.
  To race different requests together (for example apply coupon and checkout), tick the
  checkboxes beside other HTTP tab titles, then click **Race G tabs** in the active tab.
  The active tab is always the primary, followed by the checked tabs in tab order. All must
  have the same origin (scheme, host and port); a mismatch is refused before sending.
  The active tab's send options apply to every member. The count is copies **per tab**:
  G tabs × N copies produces G*N requests, with all copies of the primary first, then each
  other tab. Groups allow N=1; the total is at most 1000 (100 for HTTP/2), and the file
  descriptor budget also applies to the total. Results appear separately in each tab and
  compare copies of that tab's request. **Stop** in any participating tab stops the group. Over
  HTTP/1.1 each copy gets its own connection and the last byte of every copy is released
  together (last-byte sync). With **HTTP/2** on in the tab's Options, or a request line ending
  in `HTTP/2`, all copies go on one connection and their final frames leave in a single packet
  (single-packet attack, up to 100 copies). The race uses the tab's other options too (send as
  typed, SNI, timeout, Verify TLS, Don't record). The toolbar shows which was used, the spread between the fastest and slowest
  response, and how many responses differ from the most common one. Each copy is listed with
  its status (or error), length, time since the release and history id; ones whose status or
  length differ from the most common response are highlighted, and so is every failure. Select
  one to open it. Every copy is recorded in Traffic (source `race`), tagged with the race it was
  in (`race:ID`), how it was sent (`race-sync:last-byte` or `race-sync:single-packet`), its place
  (`race-pos:3/20`), and `race-partial` when not every final frame fitted in the one packet;
  its time is measured from the release. A last-byte race needs a connection per copy: if the
  open-file limit (`ulimit -n`) has no room for that many, the race is refused before anything
  is sent. Every copy's row is written, with its tags, before any copy goes out, so **Stop**
  (or closing the tab) leaves them all in history as one race, marked cancelled (on Windows,
  with `sent; no response recorded`). You can switch tabs while a race runs; its results show
  up in its tab when it ends (not if you close the project first). The same as
  `brainproxy send req.http --also checkout.http --race 20` for a two-tab group (omit
  `--also` for one tab), with the active tab's options as flags (`--http2`, `--sni`,
  `--timeout`, `--verify-tls`, `--no-store`).
- **WebSocket tabs** (**+ WS**, or Send to Replay from Proxy › WebSockets): edit the
  handshake and the messages to send (text, separated by a line with `---`), then
  **Connect and send**. brainproxy opens a new connection (with a fresh key), sends the
  messages, and lists what comes back for **Listen** seconds after the last one, or until a
  reply matches **Until**. Each run is recorded like proxied traffic, as it happens; with
  **Don't record** on, only the handshake gets a row, without its content. Their Options are
  SNI, Timeout, Verify TLS and Don't record. **Stop** ends a run early; what it sent may
  already have reached the server, and history keeps what was recorded up to then.
- **Kept with the project:** open tabs are saved in the project file a moment after you
  change them and when you close it, and come back when you open it again (copies made with
  `project save` or *Save as…* have them too). A tab keeps its title, target, request (or
  handshake and messages), Listen and Until, and its Options except **Don't record**, which
  is chosen again each time (so a reopened tab, or one an agent prepared, never sends
  unrecorded); responses and the ‹ › send history are not kept. Requests are kept exactly as typed, auth placeholders included. If saving fails
  (more than 500 tabs or 16 MB), the app says so and the tabs stay open; *Save as…* keeps
  the temporary engagement open, and switching project asks first. From the command
  line or an agent: `replay tabs list` and `replay tabs save`, so an agent can prepare tabs
  for you to send (through MCP it can only add tabs, never replace or clear yours). Tabs
  saved from elsewhere while the project is open in the app are added to the open ones when
  the app next saves or its window comes back to the front; the app never saves over them.
  A request sent over from history keeps its live `Cookie` or `Authorization` values, and
  `replay tabs list` returns them in full, so anyone with a copy of the project file can
  read them: replace them with `«auth:…»` placeholders before you keep or share the
  project. A project whose tabs were saved by a newer brainproxy shows them but doesn't
  save over them.

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
    `sqli-time`'s sleep and wait payloads ask for 5 seconds, so a hit stands out in the
    response times; *Edit as list* to change it (`benchmark` ones take as long as the
    server's CPU does).
  - **List:** type your own payloads.
  - **Numbers:** a range.
  - **File:** a wordlist on disk.
  - **Processing:** each set can be encoded, compressed (gzip, zlib, deflate), hashed, or
    prefixed, or passed through a script of yours (`script:` and the file's full path as a
    step; see [Scripts](#scripts)).
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
  else is sent until you ask. To only send each operation once and record it, without scanning,
  use *Send each operation once and record it, without scanning* (the Site map's *Import API (sends
  each once)…*).
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
      wizard says the key has to be saved again, and the scan (or *Import API*) can't start until you save it, go
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
    and URL paths mentioned in page text or scripts (error pages included), including template
    literals such as `` `/api/users/${id}` `` and the code-split chunks a bundle loads later
    (`import("./About-x.js")`, `"assets/About-x.js"`); placeholder values such as `?key=…`,
    `/users/{id}` or `${id}` are replaced with test values. It keeps the
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
  - **Options:** a saved scan policy, strength, rules, login profile, speed limits, and
    *Include Nuclei templates* (on when installed, high severity and above by default). With a
    policy, *Strength* is the policy's unless you pick one, and a strength, *Only rules* or
    *Skip rules* given here win over the policy's (see [Scan policies](#scan-policies)).
  - **Keep only attack requests that back a finding:** off by default, so every attack request
    stays in history. On, a scan deletes when it ends (finished, stopped with *Stop*, or out
    of time) the attack requests it sent that nothing refers to. It is saved for the project and shared with
    the CLI (`scan prune`), and applies to every kind of active scan. See
    [Pruning a scan's attack requests](#pruning-a-scans-attack-requests).
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
- **Policies:** saved scan policies, each a choice of which active rules run, at what strength,
  and how sure a rule must be to raise a finding (its threshold). Pick a saved one or *New
  policy*, set the strength and threshold every rule gets, untick *Rules on unless turned off*
  to run only the rules you tick, and give single rules their own strength or threshold
  (*reset* puts a rule back on the policy's). *Save* keeps it in the project under its name.
  *New scan* and the guided scan's *How thorough* step (when a policy is saved) can use one.
  See [Scan policies](#scan-policies).
- **Tasks:** running and finished scans and crawls with progress; Stop; View findings. A
  scan's result shows the policy it ran with and how many findings its thresholds held back.
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
  replay it: `--include-methods` with its method (`MUTATION` for a mutation), and for a logout an `--exclude` that matches
  no path. Once the run has started, the form goes back to all recorded requests.
- **Test live while browsing:** restarts the proxy on the same address, with the options it
  had (such as its login profile), so each in-scope request you browse is also tried as
  those identities in the background. It is one `proxy restart`, as in **Settings › Proxy**, so
  a proxy started meanwhile from a shell or MCP can't take its place. If it doesn't start, the
  previous proxy is started again and the message says where the proxy is. Results fill the
  grid as you go; stopping the proxy ends the run.
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
- **Layout:** one row per issue (an alert type on one host: a header missing on 500 pages
  is one issue with 500 locations), filterable by risk (critical to info), source (passive,
  active, access control, by hand) and host. *Hide closed* (on by default) hides false
  positives, accepted risks and fixed findings. The search box keeps findings whose name,
  alert, URL, parameter, evidence or state hold every word typed (or `#id`), and opens the
  issues it matches.
- **States:** *open*, *confirmed*, *false positive*, *accepted* (real, not to be fixed;
  left out of gates), *retest pending* (fixed by the developers, waiting to be checked) and
  *fixed*. A fixed finding a scanner sees again is open again, and its timeline says it
  came back.
- **Bulk triage:** tick findings, or a whole issue with its checkbox, then set their state
  at once (`findings mark ID ID...` or `findings mark --issue ISSUE` on the command line;
  each call changes all of them or none).
- **Retest** (passive findings): sends the finding's request again and lets its rule read
  the answer, then records the outcome: not reproduced marks it fixed, and a fixed finding
  still there is open again (`findings retest ID`). Only GET, HEAD and OPTIONS go without
  asking; anything else asks first (`--allow-unsafe`). Active findings are retested by
  scanning again.
- **Timeline:** every finding lists what happened to it, oldest first: found, marked,
  noted, retested, moved between issues, seen again after a fix; each with who did it
  (desktop app, command line, agent) and when (`findings timeline ID`).
- **Note:** write why a finding is confirmed or a false positive; reports show it with who
  wrote it and when. Saving an empty note clears it (`findings mark ID --note ""`); the
  finding still counts as triaged, so a rescan that no longer finds it keeps it.
- **Detail:** for each issue, the rule, confidence, CWE/WASC, description, solution,
  references, the evidence highlighted in the response, and the request.
- **Actions:** set its state, retest it, send the request to Replay.
- **New finding…:** write up an issue you found by hand: title, risk, confidence, URL,
  parameter, CWE, the history entries that show it, description, solution and evidence.
  Nothing is sent; it is only recorded in the project. *Create finding…* in Traffic's
  right-click menu and in Replay opens the same form with the URL and the request filled in.
  Findings with the same title are grouped together and tagged *by hand* (*via MCP* for one
  an agent added); they appear in reports like any other (marked *found by hand*, or *added
  via MCP (an agent)*, in the HTML report) and can be removed
  again (*Remove*); the project keeps a record of a removed one, so comparing with an
  earlier report shows it as removed, not fixed. Scanner findings can't be removed, only
  marked. If the description or solution differs from the one findings with that title
  already share, the form says so and offers to replace it (the earlier text is kept).
- **Compare with a scan:** pick a finished active scan to show only what it found for the
  first time (*New in*), what it found again (*Still found by*), or what it covered but
  didn't find again (*Not found again by*: likely fixed). A scan covers a finding when it
  tested the finding's site (scheme, host and port) and, for active findings, its rule;
  passive findings (headers, cookies) count only when the scan crawled. Findings added by
  hand are left out: no scan looks for them. The command line
  has the same comparison: [`findings compare`](#comparing-findings-and-failing-a-build-findings-compare).
- **Report…:** the report builder: a saved layout to start from, who it is for, its
  sections, a title, your company, colour and logo, and the format, with a preview of the
  HTML beside them. *Save layout* keeps the choices as a report profile; *Save report…*
  writes the file and shows it in Finder or Explorer.

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
  A login that asks for a one-time code is replayed too once the profile has the TOTP
  secret (the wizard asks for it when a code was typed): brainproxy then makes each code
  itself. In a Chromium-based browser (Linux and macOS) what you do in the page is recorded
  as well, so a login plain requests can't repeat (single sign-on on another site, a page
  that builds the login in JavaScript, a passkey) is replayed by running those steps again
  in a browser with no window. *The login uses a passkey* puts a virtual authenticator in
  the recording browser: a passkey you register there is kept with the profile and signs in
  at every replay. Without the secret or the steps, the profile carries the recorded session
  until it expires. (CLI: `auth record start URL`, `auth record finish NAME --save`; see
  "One-time codes, browser logins and passkeys" below.) The password is kept in the project, as the proxy
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
    value as `{{name}}` (also `{{username}}`, `{{password}}` and, with a TOTP secret in the
    profile, `{{totp}}` for the current one-time code), and their parameters with
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
    `Bearer …`); a parameter being fuzzed or attacked keeps its payload. Mapping a name to
    `totp` (`otp=totp`) puts the profile's current one-time code there.
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
- **Match & replace:** rules that rewrite requests and responses on their way. A rule says
  *where* it works: the method, the path, a query parameter or a header by name (set it, add
  another, or remove it), the status code, a body, a WebSocket message, or, as before, each raw
  header line or the request line. It says *what to match* there (a regex, plain text, or the
  whole value; nothing means the whole value) and what to write instead. **Applies to** is whose
  traffic it changes: the proxy unless you tick Replay, the Fuzzer or Scans too (a WebSocket rule:
  messages to the server, to the client, or both), and a host regex limits it to some targets.
  Below the list, **Test** tries the rule you are writing, the selected rule, or all enabled
  rules on a message you paste or on a history row, and shows the message after the rules and
  which rules changed it; nothing is sent. Choose **Script** in place of **Text** and the
  replacement is what a JavaScript file of yours returns for each match: the app asks before
  it adds such a rule, shows in the list which rules run a script and when one is not applied
  because its file changed, and the tester says when a script failed (see
  [Scripts](#scripts)). *Copy as JSON* and *Import* move rules between
  projects through the clipboard; an import that would run scripts names their files first. In Traffic, an exchange a rule changed has both versions:
  *Before rules* and *Sent* on the request, *Received* and *After rules* on the response. See
  [Match-and-replace rules](#match-and-replace-rules-rules).
- **Intercept options:** which methods, hosts, and paths to hold, and the timeout.
- **Proxy:** whether it runs (with a start button), its URL, and how to point a browser,
  Chromium, curl, or a shell at it. *Port* sets the port the app's proxy listens on, for every
  project. Left empty, it is 8080, or the next free one when a project opens. A chosen port
  is used as is: if it's taken, the proxy stays off and says why. A running proxy on another
  port keeps it until you press *Restart on port N*, which keeps its bind address (when it fits *Who can connect*) and
  options (a custom log file goes back to the default). It is one `proxy restart`, so a
  proxy started meanwhile from a shell or MCP can't take its place; if the new port can't be
  opened, the proxy goes back to the old one and the message says where it is. Browsers
  opened earlier still point at the old port: close them and open them again, or their traffic goes to whatever proxy
  starts on that port later, maybe another project's. Reconfigure tools you set up by hand. `brainproxy proxy start` from a shell or MCP
  still defaults to 8080 unless given `--listen`. Ports below 1024 may need elevated
  privileges (on Linux, root or the `CAP_NET_BIND_SERVICE` capability); if the system
  refuses, the proxy stays off and says why.
  - *Who can connect:* this computer only (127.0.0.1, the default) or every network
    interface (0.0.0.0), for another device. The second asks first: anyone who can reach
    your computer can then use the proxy without a password, their requests get the
    project's auth profiles, session rules and platform auth (Basic, Digest, NTLM), and
    they are recorded in the project with their client address (`client_addr`). Its proxy starts that way whenever the project opens:
    a message says so, the top-bar pill says *open to the network* while it runs, and this
    page shows a warning. Live access-control testing started from **Access** when the proxy
    is off starts it the same way, so other devices' requests are then also sent as each
    identity. The setup lines show 127.0.0.1 for this computer; other devices use its LAN
    address on the same port.
  - *Invisible mode* (`--invisible`): for a device or program with no proxy setting. Point
    the target's name at this computer with DNS or the hosts file, set *Port* to the site's
    own (usually 80 or 443), and the client connects here as if to the site; it has to trust
    the brainproxy CA. The proxy listens on one port, so it covers a site's plain HTTP (80)
    or its HTTPS (443), not both, and a project runs one proxy at a time: choose the port
    the client uses. TLS always goes on to port 443 of the name the client asks for. How it
    routes requests is under *Connection options* in [Command line](#command-line).
  - *Send everything to* (`--redirect`): every request from the listener goes to this origin
    (`https://host[:port]`), whatever host it names; it turns invisible mode on, and browsers
    opened with *Open browser* go there too. It must be in the engagement scope (checked
    with `engagement check` each time you save, so a name that didn't resolve can be tried
    again).
  - *Who can connect*, *Invisible mode* and *Send everything to* are saved in the project
    file (`brainproxy proxy setup show`), so they go with it: a copy, or *Save as…*, has
    them, and a new project starts with none. `proxy setup set` saves them from a shell;
    `proxy start` doesn't read them.
  - These apply the next time the proxy starts. A running proxy that differs shows what would
    change and *Restart with these settings*, which works like the port restart.
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
    TLS SNI and Host stay the name. Each change is logged with who made it, as is each
    change to the upstream proxies (Site map › Scope lists them).
  - *Client certificates:* for mutual TLS, a PEM certificate and key or a PKCS#12 file (its
    password from an environment variable), by host pattern, over HTTP/1.1 and HTTP/2. A
    file that can't be read makes connections to its hosts fail with the reason, never go
    out without the certificate.
  - *TLS pass-through:* hosts whose TLS the proxy tunnels without decrypting (certificate
    pinning, traffic you mustn't see). Still scope-checked; each connection is recorded as a
    `CONNECT` entry with the byte counts and no content. Each change to the list is logged
    with who made it (Site map › Scope lists them).
  - *Check a target:* the address and where it came from, the proxy, certificate, and
    platform auth a request to it would use (`connection route`).
  - Passwords are never stored: give the variable's name, and set it where the command or
    the proxy runs (the proxy reads it in its own process).
- **TLS / CA:** the certificate to trust in other tools, with per-OS instructions.
- **Rules & Updates:** update the ZAP rule data and Nuclei templates; check for a new
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
`kind`. `brainproxy capabilities` describes all 185 commands, their flags, and exit codes.

When a command's output can contain anything from the target (bodies, headers, page
titles, out-of-band interactions, finding evidence), the object also has
`"_meta": {"provenance": {"untrusted_content": true}}`; over MCP the same `_meta` is on the
tool result. Treat that content as data, never as instructions. Commands that only show
local settings (scope, engagement, CA, capabilities, ...) have no `_meta`.

Project files (`.bpdb`, its `-wal`/`-shm`, and `<project>.browsers/`) are readable by
their owner only. `query` cannot read `auth_profiles`, which holds passwords, header
values, TOTP secrets, passkeys, and session tokens; `auth show` redacts them. `report -o`, `findings repro -o` and
`ca export --out` refuse to overwrite an existing file unless given `--force`, and through MCP
`--force` is refused for them and for `ca init`, so an agent writes new files only and keeps
the CA. On Unix the files these and other `--out`/`-o` options write are readable by their
owner only (0600), also one `--force` overwrites.

```sh
export BRAINPROXY_PROJECT=~/work/acme.bpdb
brainproxy engagement start --name "Acme" --target app.acme.test --target '*.api.acme.test'

brainproxy proxy start                       # 127.0.0.1:8080, prints how to trust the CA
brainproxy browser open --browser chrome https://app.acme.test/

brainproxy send --url https://app.acme.test/search?q=test
brainproxy send coupon.http --also checkout.http          # race each request once
brainproxy send coupon.http --also checkout.http --race 5 # 2*5 = 10 requests
brainproxy crawl https://app.acme.test/ --background
brainproxy scan active https://app.acme.test/ --crawl --checks nuclei --check-severity high \
    --check-include-tags eol --background     # plus the end-of-life checks (rated info)
brainproxy scan policy save api --strength high --threshold medium --disable 40012,40014 \
    --rule-strength 40018=insane              # a saved scan policy
brainproxy scan active https://app.acme.test/api/ --crawl --policy api --background
brainproxy job wait 1

brainproxy fuzz run --url 'https://app.acme.test/search?q=§x§' -p wordlist:sqli --grep 'SQL syntax'
brainproxy wordlists list

brainproxy ws list                                        # WebSocket connections seen by the proxy
brainproxy ws messages 3 --contains token                 # their messages, both ways
brainproxy ws send --from 3 -m '{"op":"whoami"}' --until whoami   # replay with a new connection
echo '{"messages":["token=..."]}' | brainproxy ws send --from 3 --input-json   # messages off the command line

brainproxy sse list                                       # event streams (text/event-stream) seen by the proxy
brainproxy sse events 2 --contains token                  # a stream's events; sse event 41 shows one
brainproxy send --url https://app.acme.test/api/stream --stream-wait 10 --max-events 20   # read one, then stop

brainproxy replay tabs list                               # the app's Replay tabs, saved in the project
brainproxy replay tabs list --summary                     # without the requests; --index N for one tab (from 0)
echo '{"tabs":[{"title":"search","target":"https://app.acme.test","request":"GET /search?q=x HTTP/1.1\nHost: app.acme.test\n\n"}]}' \
    | brainproxy replay tabs save --append                # adds a tab (replaces them without --append); sends nothing

brainproxy findings list
brainproxy findings show 12
brainproxy findings add --title "Order IDOR" --risk high --history-id 42 --param id \
    --description-file idor.md                # an issue found by hand; nothing is sent
brainproxy query "SELECT url, status FROM history WHERE status >= 500"
brainproxy history list --contains apiKey --source proxy   # in requests and responses, bodies decoded; case-sensitive
brainproxy history list --filter 'status:5xx resp.body:"stack trace" NOT path:/health'   # the filter language (Traffic's Query)
brainproxy history filters list                           # the app's saved Traffic filters, kept in the project
echo '{"filters":[{"name":"errors","filter":{"text":"status:5xx","query":true}}]}' \
    | brainproxy history filters save --append            # adds one (replaces them without --append)
brainproxy report html -o acme-report.html

# Session handling: a macro that fetches a fresh CSRF token (history #42 is the form page),
# and a rule that puts one into every request of active scans and fuzz runs
brainproxy auth macro add app csrf --step 42 --extract '1:csrf=input:csrf_token'
brainproxy auth macro run app csrf
brainproxy auth rule add app --tool scan,checks,fuzz --action macro:csrf:each --action update:csrf
brainproxy scan active https://app.acme.test/account --auth app

# A login with a one-time code: record it, give the secret, and it is replayed from then on
brainproxy auth record start https://app.acme.test/login     # log in in the browser, code and all
APP_TOTP='otpauth://totp/Acme:me?secret=JBSWY3DPEHPK3PXP' \
    brainproxy auth record finish app --save --totp-secret-env APP_TOTP
# A passkey: register one in a virtual authenticator, then record signing in with it
brainproxy auth record start https://app.acme.test/login --passkey          # log in, add a passkey
brainproxy auth record finish app --save
brainproxy auth record start https://app.acme.test/login --passkeys-from app   # sign in with it
brainproxy auth record finish app --save && brainproxy auth login app

brainproxy project save --output ~/work/acme-copy.bpdb   # consistent copy, safe while in use; never overwrites
brainproxy project stop     # stop the project's proxy, OOB listener, jobs and fuzz runs (deletes nothing)
```

### Racing different requests (`send --also`)

`send PRIMARY --also FILE [--also FILE ...] --race N` races a group of different raw HTTP
requests. The primary can also be stdin (`-`, or no file) or `--url`. `--also` is repeatable;
`--also -` reads stdin, but only one group member may read stdin. With `--also`, `--race`
defaults to 1. N is copies per member: G members produce G*N results, in blocking order
(all N copies of the primary, then all N copies of the first `--also`, and so on).

Every member uses the same send options, header edits, SNI and auth profile. Additional raw
requests inherit the primary target's scheme and infer their host/port from their Host header;
an explicit `--target` overrides the destination for every member. All resolved targets must
have the same origin (scheme + host + port). Scope, SNI and MCP Host-header opt-in checks run
for the entire group before session preparation or sending. A request whose Host deliberately
names an unlisted host still needs `--host-header-test` through MCP, even with `--target`.

HTTP/1.1 uses one connection per copy and last-byte sync; if `--http2` is set or **any**
member's request line says `HTTP/2`, the whole group uses the single HTTP/2 connection and
single-packet sync. The total must be at most 1000, at most 100 for single-packet sync,
and fit the open-file budget for last-byte sync. Counts and the whole group are checked
before sending, including any auth login.

JSON keeps `race` as the per-member count, `race_id`, `sync`, `synced`, `target`,
`distinct_responses`, `results` and `hint`. Each result adds a zero-based `request` index
and `request_line`, including failures. For multiple members, `requests` lists
`{index, request_line}` and `total` is G*N. `race-pos:I/N` tags count positions across that
full list. The text summary lists each member and its history rows. Different members may
normally return different statuses or lengths: compare copies within one request index.
The flag is also on the MCP `send` tool and in `capabilities send`; through MCP a
member comes from the call's stdin (`--also -`), not a file (see MCP.md).

### Match-and-replace rules (`rules`)

A rule rewrites one place in a message. `--location` names the place, `--match` what to find
there and `--replace` what to write instead:

| `--location` | Works on |
|---|---|
| `method`, `path` | The request's method; its path, without the query string |
| `query-param --name N` | The value of query parameter `N`, as written in the request line (not decoded). `N` is the parameter's decoded name: it matches `a+b` and `a%20b` alike, and is written encoded where the rule adds the parameter |
| `request-header --name N`, `response-header --name N` | The value of header `N` |
| `status` | The response's status code; the replacement is a code from 200 up, with a reason if you like (`404` or `404 Not Found`). To or from 204 and 304, which have no body, the body and its framing follow |
| `request-body`, `response-body` | The body (a compressed response body is decoded first and sent on decoded). A response that has no body (1xx, 204, 304, or the answer to a `HEAD`) is left without one |
| `ws-message` | The payload of a WebSocket text or binary message the proxy relays |
| `request-line`, `request-header`, `response-header` (no `--name`) | The raw request line, or each header line (`Name: value`) on its own; with an empty `--match`, a header location adds `--replace` as a new header line |

`--match-kind` says how `--match` is read: `regex` (the default; the replacement may use `$1`),
`literal` (plain text, each occurrence replaced with `--replace` as written) or `whole` (the
whole value, when it equals `--match`). An empty `--match` stands for the whole value, whatever
it is; only a regex on `request-line` or a body matches nothing when empty, as it always did. A
regex replaces what it matched, not the whole value: to turn every 4xx into 200, match `^4..$`.

With `--name`, `--action` says what to do with the header or parameter: `set` (the default)
rewrites its value where `--match` matches, and with no `--match` sets it, adding the header or
parameter when the message has none; `add` adds another one whatever is there; `remove` removes
it (with `--match`, only where the value matches).

`--applies-to` lists whose traffic the rule changes: `proxy` (the default: in-scope requests and
responses the proxy relays), `send` (and so the app's Replay, a race included), `fuzz`, `scan`
(the attack requests of active scans and checks), and for a `ws-message` rule `ws-to-server` and
`ws-to-client` (default: both). `--host REGEX` limits it to targets whose host matches. `send`,
a fuzz run and a scan read the rules when they start and apply them before the session of
`--auth`, as the proxy does. A rule applies to every request an engine sends, so `add` on a
request recorded with the same rule adds a second copy; `set` doesn't. A response rule changes
what the engine reads: `send` shows the response after it, the fuzzer greps and counts it, and
a scan's rules look for their evidence in it (and read the baseline they compare with through the
same rules), so a finding raised from a rewritten response
points at a row whose response, as received, may not hold the evidence (`history show` has the
rewritten one as `modified_response`).

```sh
brainproxy rules add --location query-param --name role --replace admin
brainproxy rules add --location request-header --name X-Forwarded-For --action add --replace 127.0.0.1 \
    --applies-to proxy,send,fuzz,scan --host '(^|\.)app\.test$'
brainproxy rules add --location status --match '^403$' --replace 200
brainproxy rules add --location response-header --name Content-Security-Policy --action remove
brainproxy rules add --location ws-message --match-kind literal --match '"admin":false' --replace '"admin":true' \
    --applies-to ws-to-client
```

`rules test` tries rules on a message and sends nothing: the message is a raw request or
response in a file or on stdin (a response is told by its `HTTP/` start; `--message` says
otherwise, and `ws-to-server` or `ws-to-client` reads it as a WebSocket payload), or a history
row's request and response (`--history ID`). It prints the message after the rules and the ids
of the rules that changed it. By default the enabled rules apply as the proxy would apply them
(`--as send`, `fuzz` or `scan` for another engine); `--rule 3,5` tries those saved rules,
enabled or not; and `--location` with the other `rules add` flags tries a rule that isn't saved
(it shows as rule 0). `--target-host` gives the host for `--host` conditions when the message
has no Host header.

```sh
brainproxy rules test request.http                       # the enabled rules, as the proxy applies them
brainproxy rules test --history 42 --rule 3              # rule 3 on a recorded exchange
printf 'GET /a?role=user HTTP/1.1\nHost: app.test\n\n' | \
    brainproxy rules test --location query-param --name role --replace admin
```

When a rule changes an exchange, its history row still holds the request that went out and the
response that came back, and `history show` adds the other two: `original_request` (the request
before the rules) and `modified_response` (the response after them, which is what the proxy's
client or `send` was given) with `response_edits`, the rules that changed it; the request's
rules are in `entry.edited_by`. `history show ID --raw --part original-request` and `--part
modified-response` print them, and the `rule_edits` table holds them for `query`. Rows that
keep no content (`--no-store`) keep neither. A WebSocket message a rule rewrote is recorded as
forwarded, marked `rule` in `ws messages` (its `intercept` column); the original payload isn't
kept.

`rules list` prints the rules as JSON, and `rules import` reads that JSON back (a file, or
stdin) into this or another project: each rule gets a new id and the importer's origin, and is
checked as `rules add` checks it; `--replace` removes the rules there are first, `--disabled`
adds them all disabled.

A rule that puts a host the scope doesn't list in the Host header (or makes the request
target an absolute URL) is checked as before, structured or not: saving it warns a person and
is refused through MCP without `--host-header-test`, and a request an agent's rule did that to
isn't sent by the proxy, `send`, a fuzz run or a scan.

`--script FILE` in place of `--replace` has a script make the replacement; see
[Scripts](#scripts).

### Scripts

Where text isn't enough, three places take a JavaScript file of yours: a match-and-replace
rule whose replacement is computed, a fuzz payload processor, and a passive check. A script is
handed data and returns data. It can't send anything, open a file or read the environment, and
whatever it is handed is read-only.

```sh
brainproxy rules add --location request-header --name X-Signature --script sign.js \
    --applies-to proxy,send,fuzz,scan                       # a replacement computed for each request
brainproxy rules test --history 42 --location request-header --name X-Signature --script sign.js
brainproxy fuzz run --url 'https://app.test/api?token=§t§' -p file:tokens.txt --process script:wrap.js
brainproxy scan script add debug-headers checks/debug.js    # a passive check of your own
brainproxy scan script test checks/debug.js --history 42    # what it finds in one exchange; nothing saved
```

**A rule's replacement** (`rules add --script FILE`, in place of `--replace`): the file defines
`replace(match, ctx)`, called for the matches of each message, and what it returns is written
in place of the match.

```js
// sign.js: sign the method, path and body of each request with a shared key
function replace(match, ctx) {
  const r = ctx.request;
  return CryptoJS.HmacSHA256(r.method + "\n" + r.path + "\n" + r.body, "shared-key").toString(CryptoJS.enc.Hex);
}
```

- `match.text` is what was matched (the whole value where the rule has no `--match`, and empty
  where the rule adds a header or parameter that isn't there). With a regex, `match.groups` are
  its groups (`groups[0]` the whole match; a group that took no part is `null`) and
  `match.named` its named groups. Bytes that aren't UTF-8 are also in `match.base64`.
- `ctx` has `location`, `name` (the rule's `--name`), `engine` (`proxy`, `send`, `fuzz`, `scan`,
  `ws-to-server`, `ws-to-client`) and `host`, and the message as it is when the rule gets to it,
  after the rules before it: for a request location `ctx.request` (`line`, `method`, `target`,
  `path`, `query`, `headers` as `[name, value]` pairs, `body`, and `bodyBase64` when the body
  isn't text); for a response location `ctx.response` (`line`, `status`, `headers`, `body`
  decoded, or `null` when it can't be decoded); for a WebSocket message `ctx.message` (`text`,
  `base64`). A response rule isn't told the request.
- It returns a string, `{ base64: "..." }` for bytes, or `null` to leave that match as it is.
- The rule works in every engine it applies to and in `rules test`, with every location,
  `--match-kind` and `--action` except `remove` (which writes nothing). All the matches of one
  value go to the script in one call, so a regex with many matches costs one round trip.
- What it returns is checked as a rule's text is, when it has run: a line break or NUL for a
  request's line or headers, or something that is no status for `status`, fails the rule. A Host
  or absolute URL a script puts in a request is seen by the same checks as a text rule's.

**A fuzz payload processor** (`fuzz run --process script:FILE`, a step like `base64` or
`prefix:`): the file defines `process(payload, ctx)`, called once for each payload of the set
before the run starts. `payload` is the payload as text; `ctx.set` is the payload set's number,
`ctx.index` the payload's place in it, and `ctx.base64` its bytes when it isn't text. It returns
the payload to send: a string, `{ base64 }`, or `null` to keep it. Steps run left to right, so
`upper,script:sign.js,url` hands the script upper-cased payloads and URL-encodes what it
returns; `2=script:sign.js` processes only set 2; a comma in the path is written `\,`. The
run's `config` in `fuzz_runs` records the file and its sha256 as `process_scripts`.

**A passive check** (`scan script add NAME FILE`): the file defines `check(exchange)`, called
for each exchange the passive scanner reads, after the built-in rules.

```js
// debug.js: a debug header on any response
function check(x) {
  const header = x.response.headers.find(([name]) => /^x-debug/i.test(name));
  if (header) return { name: "Debug header in a response", risk: "low", param: header[0], evidence: header[1] };
}
```

- `exchange` has `id` (the history row), `method`, `url`, `scheme`, `host`, `port`, `path`,
  `query`, `status`, and `request` and `response`, each with `headers` (`[name, value]` pairs),
  `body` (the response's decoded), `bodyBase64` when it isn't text, and `bodyTruncated`: a body
  is cut at 2 MiB for a script.
- It returns nothing, one finding or a list (50 at most): `{ name, risk, confidence, param,
  evidence, info, description, solution, cwe, id }`. Only `name` is needed; `risk` is `info`
  (the default), `low`, `medium`, `high` or `critical`, and `confidence` `low`, `medium` (the
  default) or `high`. A field it doesn't know is refused, so a typo doesn't pass for a default.
- Its findings are stored and reported like a rule's (source `passive`), with alert ref
  `script:NAME:ID`, where the id is the finding's `id` or made of its name; the description
  says a user's script raised it, and its tag is `user-script`. Findings of one id are one
  alert type, whose name, description and solution are the first one's; a script may raise 64
  types. `scan rules` lists the check as `script:NAME`, `scan disable script:NAME` and `scan
  enable script:NAME` switch it off and on, `findings retest` runs it again on the reply, and
  `scan passive --rescan` runs it over the history there already is. `scan script list` shows
  the checks with their files; `scan script remove NAME` removes one; its findings stay until a rescan, which removes
  the ones nobody triaged, as for a rule that is switched off.

What every script finds around it: the language itself (no `fetch`, `XMLHttpRequest`, timers
that wait, modules or `import`), `CryptoJS` (MD5, SHA-1, SHA-256, SHA-384, SHA-512 and their
HMACs; the Hex, Base64, Base64url, Utf8 and Latin1 encoders), `btoa`, `atob`, `Buffer.from`,
and `require` for `crypto-js`, `crypto` (`createHash`, `createHmac`, `randomBytes`,
`randomUUID`) and `uuid`. `console` is there and writes nowhere. A global a script sets stays
for the next call in the same process, and brainproxy starts and stops those processes as it
sees fit (up to four a script), so keep nothing in one that a result depends on.

How a script is kept and run:

- **Pinned.** A script stays in its file. Where it is named (`rules add`, `scan script add`),
  the file's full path and the sha256 of its text are stored, and `--script-sha256 HEX` (or
  `scan script add --sha256`) refuses a file that isn't the one you read. A file that changes
  afterwards doesn't run: its rule is left out and listed under `skipped` in `rules list`, its
  check stops and `scan script list` says why, until you name it again (add the rule again and
  remove the old one, or `scan script add` with the same name). The pin is checked whenever
  the rules or checks are loaded: by every command as it starts, and by a running proxy when
  the project's settings change or it restarts. Between those, a running proxy goes on with
  the text it pinned; the changed file itself never runs. A `fuzz run` reads its script when it starts. Rules
  copied to another project or computer carry the path and the pin, not the code.
- **Contained.** A script runs in the sandbox a signer's Postman script runs in: a memory-safe
  interpreter with no file, network or process access and no helper that reaches out, in a
  child process of brainproxy with an empty environment, its memory limited to 1 GiB (as
  below, for a signer's script) and without `SharedArrayBuffer`, `Atomics` or `Temporal`. It
  opens no connection, so the engagement scope has nothing to check: all a script can do is
  change the bytes of a message that goes where it was going, or report a finding.
- **Bounded.** A script file is at most 1 MiB. Each call (the matches of one value, one
  payload, one exchange) has 2 seconds, and a process 5 seconds to start; a loop has two million
  rounds and recursion 200 levels. What a call is handed is at most 16 MiB, and so is what it
  returns (for a batch of payloads, in all). A rule's script is called for at most 10,000
  matches in one value, a pattern that matches more often fails as a script does, and a
  payload set may come to 256 MiB after a script. A process is replaced after its calls have
  taken 30 seconds in all.
- **A failure is said, and changes nothing.** A script that throws, returns something of the
  wrong shape, or reaches for what isn't there fails that call: the rule leaves that message
  as it is, all of it (a script that fails on the second of two headers changes neither; the
  rules after it still apply), the fuzz run doesn't start (it names the payload),
  the check finds nothing in that exchange. A script stopped at the time or memory limit, or
  one that doesn't load (it throws at the top, or has no function of its kind), runs no more
  until the command or the proxy starts again (or its rule is switched off and on), so a script that hangs costs its time limit once
  and not for every request. The failure is on stderr, once for each different one; in `rule_errors` of `send`'s
  output (in a race, for the requests as they went out) and `errors` of `rules test`'s (the rule's
  id and why); and in `script_errors` of
  `scan passive`'s (the script, why, on how many exchanges, and the first history row; the
  first twenty different failures, with every script that failed in `failed_scripts`). A
  passive rescan keeps the findings of a script that failed or didn't run, where it removes
  those of a rule that finds nothing any more. The last failure of each rule's script, in
  whichever engine, is also kept with the project: `rules list` gives it under `failures`
  (the rule, why, when, which engine) and the app shows it on the rule's row, until the rule
  is switched off or on, or removed.
- **A person's.** Through MCP no script is named: `rules add --script`, `rules test --script`, an
  import or `rules enable` of a script rule, `fuzz run --process script:`, `scan enable` of a
  script check, and `scan script add`, `test` and `remove` are refused or not offered. An
  agent's requests still go through the script rules a person set, as they go through a
  signer's script, and it can list them, try a saved rule that is switched on with `rules test
  --rule`, and switch a rule or check off.

### Server-sent events (`sse`, `send --stream-wait`)

A response with `Content-Type: text/event-stream` (and a 2xx status) is a stream of events
that may never end: an `EventSource`'s feed, a chat API's answer token by token. brainproxy
doesn't wait for its end.

- **The proxy** relays the stream to the client as it arrives, over HTTP/1.1 and HTTP/2
  (also an HTTP/2 client with an HTTP/1.1 origin), and records it meanwhile. The request is a
  history row from the moment the response's head arrives; the row's response is the head
  until the stream ends, then the head and the body as received. `sse list` shows the stream
  (`state` open or closed, `events`, `history_id`), `sse events STREAM` its events as they
  were parsed (`event`, `event_id`, `data`, `retry`, `time` of arrival; `--event TYPE`,
  `--contains TEXT`, `--after ID` to poll), `sse event ID` one event with its whole data
  (`--raw` for the data alone) and `sse show STREAM` the stream with its request, response
  head and event counts by type. `history show` on the row names its stream.
- **`send`** reads a stream until the server ends it, `--stream-wait` seconds pass (5 by
  default, from the head; at most a day) or `--max-events` events arrive (100 by default),
  then closes the connection. The row's response is what arrived, and `stream` in the output
  says why reading stopped (`closed`, `wait`, `max-events`, `cap`, `error`) and lists the
  events; they are stored too (`sse list --source send`), unless `--no-store`. Events that
  arrive together with the last one are read and listed too, so the list can be a little
  longer than `--max-events`: it is always every event in the row's body. Every other
  sender (crawl, scans, fuzzing, `authz`, a login) reads a stream for 5 seconds or 100
  events, so none of them waits out its timeout on one. `send --race` reads whole responses
  only, as before, and refuses the two flags.
- **An event** is a block of lines ended by a blank line. One with no `data` line is listed
  with `data` null: a browser dispatches nothing for it, but takes its `id` and `retry`. A
  comment line (`: keep-alive`) is in the row's body and not an event. A block the stream ends
  inside isn't one either.
- **The cap:** one stream stores up to 4 MiB of body (as received, and as decoded when it is
  compressed) and 10000 events. Past either the stream is still relayed, nothing more of it
  is stored, and it is marked at once, while it is still open: `truncated` is true in
  `sse list`, `sse show` and `sse events`, and its `error` says which limit it reached. The
  row's body then ends where recording stopped. The streams a proxy has open at one time
  store up to 256 MiB of body between them; one that would pass that is marked the same way.
- **Compressed streams** (`Content-Encoding: gzip`, `deflate`, `br`) are relayed as they are
  and decoded for the events as they arrive. Another coding is relayed and its body kept,
  with no events; the stream's `error` says so.
- **How it ended** is in `ended`: `server` (the response ended, or the server closed the
  connection), `client` (the proxy's client closed its connection or reset the stream; the
  proxy then closes the server's too), `stopped` (the proxy stopped, or `send` stopped
  reading) or `error`. Stopping the proxy completes the rows of the streams open then with
  what they stored. A proxy that is killed can't: its streams stay `open` until a proxy next
  starts on the project, which closes them with `the proxy stopped before the stream ended`;
  their events are kept, and their rows keep the head only.
- **What doesn't apply to a stream:** response body and status rules (`rules add --location
  response-body` or `status`), response intercept (`intercept enable --responses`) and live
  access-control testing (`proxy start --authz`) need a finished response, so the proxy
  skips them for a stream. Response header rules apply to its head (all but its
  Content-Length and Transfer-Encoding, which frame the body relayed after it), and request rules, the
  auth session and request intercept to its request, as for any other. The passive scanner
  reads the row when the stream opens (its headers) and again when it ends (its body); a
  stream still open when the proxy stops is read again by the next passive scan (`scan
  passive`, or the next proxy). HAR export writes the row as it is: the body so far.
- An HTTP/1.x client's connection ends with the stream, and a client that closes its side
  while the stream is open ends it, so one that half-closes after its request (`nc -N`) gets
  no events. A `HEAD` is answered as usual. Events are recorded only for traffic inside the
  recording scope; outside it the stream is relayed and leaves its row, as other traffic does.
- Search events with `query`: tables `sse_streams` and `sse_events`, and the full-text index
  `sse_events_fts` over `data` (`schema` lists the columns).

### Who recorded what

Each history entry has:

- `origin`: `gui` (the desktop app), `cli` (a terminal or script) or `mcp` (an agent through
  MCP); NULL, shown as unknown, for entries recorded before brainproxy kept it. Background
  jobs, fuzz runs and the proxy record the origin of the command that started them.
- `client_addr`: for proxy entries, the address (`ip:port`) of the client that sent the
  request, whether intercepted, passed through, a WebSocket upgrade, or invisible.
- `edited_by`: who changed the request before it went out (for proxy entries, and for a
  `send`, fuzz or scan request a match-and-replace rule changed), as a JSON
  list: `[{"by":"mcp","intercept":4}]` for an edit forwarded from the intercept queue,
  `[{"by":"gui","rule":2}]` for a match-and-replace rule (`by` is who added or last enabled
  the rule). A proxy started with `--auth NAME` adds `{"by":"gui","auth":"NAME"}` when the
  profile's session (its cookies, including those its macros got, headers or token) changed
  the request (`by`: who last changed the profile), then
  `{"by":"mcp","auth":"NAME","session_rule":3}` for each session rule that changed it (one
  whose URL matched but that changed nothing isn't named) and
  `{"by":"cli","auth":"NAME","macro":"csrf"}` for each macro whose values those rules put in
  (`by`: who added the rule or macro, or last changed it). NULL when nothing changed it; an
  intercept forwarded unchanged isn't an edit.
- `sni`: the TLS server name sent when `--sni` overrode it (`send`, `fuzz`, `ws send`, and
  a session's own requests in those); NULL when it was the target host, for plain HTTP, and
  when `--sni` was an IP address, which can't be a server name, so none is sent. A `--sni`
  the scope refuses fails before any connection is opened, and before any row is written, as an
  out-of-scope target does.
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
edit, and `history show` has what a rule made of it (`modified_response`). Match-and-replace rules keep an `origin` (`rules list`): who added the rule, or last
enabled it. A request-line or request-header rule whose replacement holds a line break or NUL
(saved by a build that didn't refuse one) is left out when the proxy loads its rules, and
`rules list` (`skipped`) and `proxy status` (`rules_skipped`) say so. So do auth profiles (`auth show`: `profile.origin`, who last changed it), their
session rules and macros (`origin`, who added one or last changed it; saving any of them
unchanged, as the app's edit form does, keeps it), and their session: `session_origin` and `session_changed_at` say who last stored
it (logged in, got an OAuth token, or the proxy or a scan that learnt its cookies). A rule id,
match-and-replace or session rule (of any profile), is never handed out again once its rule is
removed (or all are cleared), so an old row's `edited_by` can't come to name another rule;
a project from before this starts counting after the highest ids it has.

The other tables say who started what wrote them, as `origin` (NULL for rows from before
brainproxy kept it): `jobs`, `fuzz_runs`, `authz_results` (who started the run, or the proxy
for live testing), `ws_connections` (who started the proxy or `ws send`), and
`oob_interactions` (who started the listener or poll that stored it). An OOB payload's
`issued_by` is who started the scan or ran `oob payload` (its `origin` column is the attacked
site). Every saved setting (scope, rules, intercept, connection settings, live authz, ...) is
logged in `setting_changes` with its `key`, `time` and `origin`, without its value, which can
hold credentials.

A proxy records the schema of the build that started it (`proxy.schema` in `proxy status`).
One started by an older build goes on writing rows the old way, without what came since (who
changed a request, for one), so `proxy status` warns about it in `proxy_outdated` and a
`warning:` line, until it is restarted (`proxy restart`).

Narrowing the proxy scope or adding a TLS pass-through host keeps traffic's content out of
history (only request lines and tunnels' rows remain), so each change to either is logged:
`scope set`, `scope add` and `scope clear`, and `connection passthrough add|remove|clear` and
`connection clear`. Changes to where traffic goes are logged the same way: upstream proxies
(`connection upstream ...`, setting `upstream`, summary `added * via http://10.0.0.1:3128`) and
host overrides (`connection hosts ...`, setting `hosts`, summary `added app.test -> 10.0.0.7`), and
client certificates, which decide who the person is to a server (`connection cert ...`,
setting `client_certs`). Password variables are named, never their values.
They never narrow recording, but an agent sending the person's traffic through a proxy, to an
address or as a certificate of its choice doesn't show in the traffic either, so any routing
change made through MCP is flagged, apart from narrowing: `routing_changed_by_agent` in `scope
show` and `proxy status` (whose text says `not reviewed: host overrides changed via MCP (an
agent) at ...`), until a person changes that setting (a `connection upstream`, `hosts` or `cert`
command, or `connection clear`), runs `connection review [upstream|hosts|client_certs]` to keep
it as it is, or the agent puts it back as it was. `connection review` isn't available through
MCP, and refuses a tool call: an agent can't approve its own changes. A flagged change's
`summary` says everything that changed since the agent's first change to that setting, so a
small later one can't stand in for it; `connection review --seen TIME` (the flagged changes'
`time`s, as the app passes them) keeps nothing if what is flagged has changed since. Like an agent's other
changes, these are kept in the log for good. A change has `time`, `by` (`gui`, `cli` or `mcp`),
`setting` (`scope`, `passthrough`, `upstream`, `hosts` or `client_certs`), `summary`
(`include: added ^a\.test$`), `before` and `after`, and `narrowed`:
whether it left traffic out that was recorded in full before. That is an include list that
went from empty (everything) to some hosts or lost a pattern (patterns are compared exactly,
as the regexes they are), a new exclude pattern, or `--record-out-of-scope` turned off while
something is out of scope, or a new pass-through pattern. `--record-out-of-scope` doesn't make
a smaller scope harmless: HTTPS to a host outside it is tunnelled, never decrypted. The
setting is read, edited and saved with its log entry in one transaction, so a change by
another process can't slip between them unlogged, or be overwritten and logged as this one's
undoing it. `scope show` lists the latest 20 and every earlier one
made through MCP or that narrowed recording (`recording_changes`, newest first); `proxy
status` has the last one (`recording_last_change`) and those made through MCP or that narrowed
recording (`recording_kept_changes`, newest first). A narrowing change made through MCP is also listed in
`narrowed_by_agent` (`scope show`) and `recording_narrowed_by_agent` (`proxy status`, whose
text says `not reviewed: recording scope changed via MCP (an agent) at ...`) until a person
changes that setting from the app or a terminal (saving it unchanged with a command that edits
it counts: `scope add` with nothing to add, say), or the agent puts it back as it was; the
agent's later changes don't clear it, nor does another connection command saving the settings
the pass-through list is kept with. The log keeps every change made through MCP or that
narrowed recording, and the last 100 others, as JSON in the `meta` table
(`proxy.recording_changes`): however many changes follow, an agent's narrowing stays listed,
even once its flag is cleared. If that value doesn't parse (edited by hand, say), `proxy
status` and `scope show` still answer, with the problem in `recording_changes_problem` (and a
`warning:` line in text), but scope and connection changes are refused until it is repaired,
so the log isn't silently replaced.

An agent that can run commands in a shell, as well as through MCP, and runs `brainproxy`
there counts as `cli`: brainproxy can't tell who typed a command. Such a change clears the
flag like a person's would, but it is still logged, with `by: "cli"`, and the agent's
narrowing stays in the log.

```sh
brainproxy scope show                        # recording_changes, narrowed_by_agent
brainproxy proxy status                      # recording_last_change, recording_narrowed_by_agent, recording_kept_changes
```

Findings have an `origin` too (who added them: the proxy's passive scan, a scan job,
`findings add`, ...), and `state_origin` and `state_changed_at` say who last changed the state
with `findings mark` (or `findings remove`) and when, so a finding an agent marked as a false positive says so. `note_origin` and
`note_changed_at` do the same for the note. `findings list` and `findings show` include
them. The description and solution a title added by hand shares keep who wrote them
(`description_origin` and `solution_origin` in `findings show` and the `finding_types`
table): whoever gave the text first, filled it in when it was left blank, or replaced it.
Reports carry a finding's origins in every format:

- JSON: each instance has `state_origin`, `state_changed_at`, `note_origin`,
  `note_changed_at` and `state_text` ("confirmed via MCP (an agent) at ...").
- Markdown and HTML say it in words on each finding. In HTML a finding a person confirmed
  (from the app or the command line) is tagged **confirmed**, one an agent confirmed
  **confirmed via MCP (an agent)**. A finding added with `findings add` is tagged **found by
  hand**, or **added via MCP (an agent)** when an agent added it.
- SARIF: `stateOrigin`, `stateChangedAt`, `stateText`, `noteOrigin`, `noteChangedAt` in each
  result's properties.

In SARIF, each result's `partialFingerprints["brainproxy/v3"]` is a hash of the key the
project uses to tell findings apart (alert, method, URL without its query or its path's
`;name=value` parameters, parameter), so code scanning sees a finding found again with
another query string, or another session id in its path (`/login;jsessionid=...`), as the
same result, and no secret in the URL travels with it. `report json` gives the same hash as
each instance's `fingerprint`; `findings compare --baseline` matches by it, so a redacted
report still compares with the project as it was. (It was `brainproxy/v1`, which kept the
query, then `brainproxy/v2`, which kept path parameters: the first upload after updating may
show existing alerts as closed and opened again. A URL without path parameters has the same
hash as under v2, so only those findings change in `report json`, `report defectdojo` and
baselines: write a baseline again after updating, or they show as new and fixed once. A
project opened by this version merges the findings it stored once per session id, keeping
the latest state and note, the summed hits and the highest risk; a merged finding goes to the
issue that holds a title, rating or write-up and would otherwise be left with no findings. A
URL fragment's parameters (`#/view;id=1`, a client-side route) stay part of the identity.)
A result marked false positive or accepted risk (in a report written with `--state all`)
carries `suppressions` (`kind` external, `status` accepted, the note as `justification`), so
code scanning shows it as dismissed rather than open.
`baselineState` is set only with `report sarif --scan JOB`: `new` for what that scan found
first, `unchanged` for what it found again. `lastHistoryId` and `lastSeen` give the latest
sighting.

False positives are left out of a report by default. The report counts them by who marked
them (`summary.false_positives_left_out`), and lists the ones an agent marked
(`agent_false_positives`; a "Marked false positive by an agent" section in Markdown and HTML,
`agentFalsePositives` in SARIF run properties), so an agent can't make a finding vanish
from a report unseen.

`scan passive --rescan` rescans all history and keeps what people decided: a finding found
again keeps its id, state, note, origin and who set them. One not found again (its rule was
turned off, say) is removed, unless it was triaged (its state was changed or it has a note)
or has other records (a retest, a move to another issue, a ticket, or a title, rating or
write-up on its issue): that one is kept with `hits` 0. The result counts `removed` and `kept_not_found`.

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
brainproxy connection review                            # keep an agent's routing changes as they are
brainproxy connection show
brainproxy auth add corp --platform ntlm --platform-host '*.acme.test' --username 'ACME\me' --password-env CORP_PW
brainproxy proxy start --listen 0.0.0.0:8080 --invisible  # also serve clients that don't know they're proxied
brainproxy proxy start --listen 127.0.0.1:8443 --redirect https://app.acme.test  # everything to one origin
brainproxy proxy setup set --network all --invisible   # how the desktop app starts this project's proxy
brainproxy proxy setup show
```

With `--invisible`, plain requests in origin form (`GET /path`) go to their Host header's
host and port, and a TLS client that connects directly gets a certificate for its SNI and
goes to that name on port 443 (whatever port it connected to); ordinary proxy requests work
on the same listener. One listener has one port, so it serves a site's plain HTTP or its
HTTPS, not both. A
`--redirect URL` sends every request from the listener to that origin (implies
`--invisible`). Pass-through hosts and hosts outside the proxy scope are tunnelled as with
CONNECT. On `0.0.0.0` or `[::]`, the proxy URL and setup lines that `proxy start` and
`proxy status` print use 127.0.0.1 or `[::1]` (their text output names the wildcard address
too); other devices use this computer's LAN address.

`proxy setup set` saves, in the project file, how the desktop app starts the project's proxy
(Settings › Proxy): `--network local|all` (127.0.0.1 or 0.0.0.0), `--invisible` and
`--redirect URL`, replacing the whole setup each time; `proxy setup show` prints it with the
`proxy start` options it stands for. An MCP tool call can't save `--network all`,
`--invisible` or `--redirect`: the app would start the person's proxy with them.

To move a running proxy to another address or options, restart it in one step:

```sh
brainproxy proxy restart --listen 127.0.0.1:9090 --auth alice
```

`proxy restart` takes `proxy start`'s options, defaults included: what isn't given isn't
carried over from the running proxy. It holds the project's proxy record from before it
stops the proxy until the new one is listening, so a `proxy start` (or another restart, or
`proxy stop --forget`) from a shell, an agent or the app meanwhile fails with "the proxy is
being restarted" instead of getting in between, and `proxy status` shows `"restarting": true`.
If the new proxy doesn't come up (the port is taken, say), the old one is started again on the
address it had, with its options, and the command fails with an error that ends with where the
proxy is now. The error's `data` says the same for a script or an agent: `{"stopped": true,
"failure": "<why the new proxy didn't come up>", "restarted": {"pid": N, "listen": "ADDR"}}`, with
`"restarted": null` if the old one couldn't be started again (an error before anything stopped
has `{"stopped": false}`). With no proxy running it starts nothing and fails with `not_found`:
use `proxy start`. `--wait` is 0 to 60 seconds for a restart (0 to 3600 for `proxy start`), for
the new proxy and again for going back, since every other start waits meanwhile; it is checked
with the other options, before anything stops. On success it prints what `proxy start` does,
plus `replaced`: the old pid and address, whether it had to be killed, and `args`, what it ran
with, so you can see what a restart without those options left out. While a restart runs it
holds `brainproxy.bpdb-proxy-restart.lock`, which is how another container on the same volume
knows it is still under way. Before it stops the old proxy, a restart starts a guard (a `proxy
run` of its own that runs no proxy; its output goes to the new proxy's log), which stands by
until the new proxy is started. If the restart is killed (Ctrl-C, say, or an MCP client's
timeout or cancel) in between, while it stops the old proxy or just after, the guard finishes
stopping it and starts it again on the address it had, with its options. Killed while its new
proxy starts, the hold lasts until that proxy is up or has failed, and that proxy goes back to
the old one itself if it can't come up, or isn't up within the restart's `--wait` (logging in
for `--auth` to a server that never answers, say). Either way the hold lasts meanwhile, and a
`proxy stop` stops the guard or that proxy instead, leaving the proxy off. (Killed before it
asked the old proxy to stop, the restart hadn't stopped anything: the guard, or the next
command, gives the old proxy its record back, and it runs on as it was.) The proxy started again
this way is a new process with a new pid and the old options, not the ones the restart asked
for, and a live authz run it had ends as a new one starts. The guard shows in `ps` as a
`brainproxy ... proxy run` without `--listen`. `proxy status` says it happened in
`restart_gone`, until a proxy next starts: `{"at": <Unix time>, "by": "the restart's guard",
"restart_pid": N, "restart_origin": "mcp", "proxy": {"pid": N, "listen": "ADDR"}, "note": null}`,
with `"proxy": null` and the reason in `note` if the proxy was left off.

`proxy stop` during a restart calls the restart off: the proxy it was starting is killed, the
proxy it replaced stays off, and the restart fails saying so (`"called_off": true` in its
error's `data`). The stop waits up to 40 seconds for the restart to let go (it is refused if the
restart doesn't), then stops whatever proxy runs; its output names the restart in
`restart_called_off`. `proxy stop --pid N` stops the proxy only if it is still pid N in this
container, and fails with `not_found` otherwise, calling nothing off: what the app runs when it
closes a project, so a proxy started since from a shell or an agent is left alone. `proxy stop`
marks the record as being stopped until the proxy has exited, so a restart (or start) meanwhile
fails with "the proxy is being stopped" and the proxy ends up off. If another proxy has taken
the record by the time the old one is gone, the stop fails and names it rather than reporting
the proxy off. `project stop` calls off a restart under way too, stops the OOB listener, jobs
and fuzz runs, then the proxy, and also a proxy that took the record meanwhile. If something
doesn't stop, it still stops the rest, then fails naming every failure, with what it did stop
in the error's `data` (`proxy`, `oob`, `work`).

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
  these methods. A GraphQL mutation (a request whose `query`, in a JSON body or batch, an
  `application/graphql` body, a multipart upload's `operations`, a form body or the URL, defines
  one) is `MUTATION` however it was recorded, and needs `MUTATION` as well as its method when
  that isn't sent by default: a DELETE that names a persisted query needs both, so neither
  opt-in stands for the other. So is an operation sent
  without its document (a persisted query's hash in `extensions.persistedQuery`, a `doc_id`, or an
  `id` with `operationName` or `variables`), and a body at a GraphQL-looking request that can't be
  decoded (zstd, say): neither can be shown to be read-only. So one sent once by `import api
  --include-methods MUTATION`, a one-request check or the proxy isn't replayed by a later scan
  unless `--include-methods MUTATION` (or `all`) says so. A request picked with `--history-id` needs the same opt-in: naming a DELETE or a mutation
  without `--include-methods DELETE` (or `MUTATION`) is refused with exit code 2 before anything is sent.
- `scan active --checks`: the same opt-in applies to the requests a template sends, from any
  store or file. A check's PUT, PATCH, DELETE (or other method), or GraphQL mutation isn't sent
  without `--include-methods`; the output counts those in `check_skipped_methods`. Every request a
  check or rule does send is recorded in history (source `scan`), finding or not.
- `import api SOURCE`: an OpenAPI 3, Swagger 2.0 (JSON or YAML) or Postman v2 document, a
  GraphQL schema (SDL file or introspection result), or a HAR file (see `import har`), detected from its contents. Through MCP a local
  file (this, `import har`'s, `--schema`, `--environment` and `scan active --api`'s too) is read
  only from the project file's folder, symlinks followed (not when that folder is the home
  folder or `/`), and its parse errors give only a line and column; `-` (stdin) and URLs are
  not limited (see MCP.md). `--dry-run` previews and sends nothing for a local file: servers,
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
- `import har FILE`: a HAR 1.2 file (Chrome's or Firefox's *Save all as HAR*, or another proxy's
  export) under the same rules; `import api` and `scan active --api` take one too, detected from
  its contents, up to 256 MiB (other documents: 32 MiB). Each entry's request (method, URL,
  headers, cookies, query, and body: its text, or its form or multipart `params`, a file part's
  content standing in as `test`) becomes one operation, named `METHOD URL` without the query.
  Not taken from the file: `Host` (the URL gives it, so `--base-url` can move a recording to
  another server), `Content-Length`, the connection's own headers, `Accept-Encoding`,
  `Content-Encoding` (a HAR records the decoded body), HTTP/2's pseudo-headers, and a GET's or
  HEAD's cache validators (`If-None-Match`, `If-Modified-Since`, ...). A write keeps its
  preconditions (`If-Match`, `If-Unmodified-Since`), so a stale recording fails with 412 rather
  than overwriting newer data. A body `history export` wrote as base64 (`_encoding`) is decoded.
  Left out and counted in `warnings`: static assets (scripts, styles, images, fonts and media, by
  Chrome's resource type, the response's content type or the file's extension; `--keep-static`
  keeps them), an entry with the same method, URL, `Accept` header and body as an earlier one
  (the first is kept),
  WebSocket handshakes (`ws send --from` replays a connection), and URLs that aren't http(s).
  Entries outside the engagement scope are listed with `excluded_reason: "scope"` and only
  their method and host (no path, query, headers or body), never sent,
  and counted in `skipped_out_of_scope`. The method opt-ins are those of any document: DELETE,
  PUT, PATCH and GraphQL mutations need `--include-methods`. The recorded `Cookie` and
  `Authorization` headers, other credential headers (`X-CSRF-Token`, `X-Api-Key`,
  `X-Session-Id`, any name that says `auth` or names a credential key, and any header whose
  value starts with an auth scheme and a credential, and a `Sec-WebSocket-Protocol` that carries more than plain
  subprotocol names: the rule exports mask by), and credentials in URLs and bodies (form, JSON, XML and multipart fields)
  are left out and listed under `credentials` by name, as for a Postman collection's saved keys;
  use an auth profile. As a HAR holds live values, its names are judged as reports judge them
  (`session`, `sid`, `jwt`, `signature`, `key` and the like count too). `--keep-credentials` sends the recorded
  credential headers as they were (a recorded session is often stale by now); those in the URL
  and body are still left out, as URLs are shown and logged, and the preview shows the kept ones
  as `********` and says `credentials_kept`. The HAR's responses are not read (only their content
  type, to tell a static asset) or stored: each request is sent again, and the live answer is
  recorded. A HAR fetched from a URL is recorded like any document, its body omitted.
- `history export har`: history rows as a HAR 1.2 file, chosen with `history list`'s filters
  (`--host`, `--method`, `--status`, `--source`, `--tag`, `--origin`, `--contains`, `--filter`,
  `--after`),
  oldest first, up to `--limit` (1000; `truncated` says when more matched). Session secrets are
  masked as reports mask them (cookie values, `Authorization` credentials, API-key headers, token
  and password parameters, JWTs, the project's auth profile secrets, and each value wherever else
  it appears); a body that isn't text can't be searched, so it is left out with a `comment` and
  counted in `binary_bodies_left_out`. `--mask VALUE` masks more; `--no-redact` keeps everything
  as recorded, binary bodies as base64 (a request's with `_encoding: "base64"`, which `import
  har` reads back). Reason phrases are masked too. Each entry's `_brainproxy` holds its history id and
  source, and `_error` why it failed. `-o FILE` writes the file (an existing one is kept unless
  `--force`, which MCP refuses); without it the HAR is printed, under `data.har` in JSON mode.
  The app has no export button yet.

  ```sh
  brainproxy import har recording.har --dry-run                 # what would go out, and what was left out
  brainproxy import har recording.har --expect-sha256 HEX --auth app
  brainproxy scan active --api recording.har --only 0,2 --auth app
  brainproxy history export har --source proxy --host app.acme.test -o acme.har
  ```
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
(unless `--keep-oauth`), TOTP secret (unless `--keep-totp`), what a recording gave it (its raw
login request, the requests after it and its browser steps, unless `--keep-recorded`) and
session, and keeps its signers, rules, macros and passkeys.

One-time codes, browser logins and passkeys in an auth profile:

- **TOTP.** `auth add NAME ... --totp-secret-env VAR` names the variable that holds the secret
  an authenticator app would hold: base32, or the `otpauth://` URI a QR code holds, whose
  algorithm (SHA-1, SHA-256, SHA-512), digits and period then apply (`--totp-algorithm`,
  `--totp-digits`, `--totp-period` set them otherwise; SHA-1, 6 digits and 30 seconds by
  default). The variable is read at each login and never stored; `--totp-secret` (or
  `BRAINPROXY_SECRET_TOTP`, which the app uses) stores the secret in the project file like a
  stored password, and `auth show` masks it. `{{totp}}` is then the current code: in
  `--login-body` and `--login-request`, in a macro step, in the requests and steps a recording
  makes, and as `update:PARAM=totp` in a session rule. Requests carry the placeholder
  `«auth:NAME:totp»`, which is worked out as the bytes go on the wire, so history, reports and
  exports never hold a code, and a login re-sent from history gets a fresh one. Like the
  password, it only goes to the login's origins (and a macro's, or a rule's URL).
  A site may take each code once, so a login waits for the next code when this profile already
  sent the current one (the project remembers, across commands; up to one period). A code
  that went out within a few seconds of its period's edge and was refused is sent once more
  (the next code, or the same one a little later); a login refused in the middle of a period
  is not repeated. One process at a time logs in with a profile that sends a code, across
  commands, so two never send the same one.
- **A code in a recorded login.** `auth record finish NAME --totp-secret-env VAR` (or
  `--totp-secret`) makes a login with a code replayable: the code field of the login request
  becomes `{{totp}}`, or the request that posts the code on its own page becomes a step after
  the login request (`login_steps` in `auth show`), with the token its form or a header carries read
  again each time (the first request after the login that posts a code, or the last time it
  went to the same URL when a mistyped code was sent again). A code is 4 to 10 digits in a field
  named for one (`otp`, `mfa_code`, `smsCode`, `code`); a postcode, a company, customer, invite or
  coupon code, or the user's name is not one, in a request as in a field typed in. The output
  says whether the secret makes the code that was typed while recording, and `needs_totp` is true
  when a code was typed and no secret is known.
- **Browser steps.** `auth record start URL` opens a Chromium-based browser held by a
  background brainproxy process (Linux and macOS; Firefox, Windows and `--no-steps` record the
  traffic only, as before). Fields filled, boxes ticked, buttons and links clicked, Enter, and
  pages opened by their address are recorded in the tab the browser opens with; other tabs,
  pop-up windows and embedded frames are not (the output says when something happened there).
  `auth record finish NAME` closes the browser and lists the steps. When plain requests can't
  repeat the login, or with `--in-browser`, the profile replays them (`mode: browser`):
  `{{username}}`, `{{password}}` and `{{totp}}` stand for what was typed, and what went into
  another password field is kept masked (other fields are kept as typed, and shown). The
  recorder listens from a world of its own in the page, so a page's scripts can't add steps. `--steps-from N` keeps the steps from N on, for a
  recording that did more than log in. An unsaved recording is held only in that background
  process's memory (for two hours at most); the project file gets it when the profile is saved.
- **Replay.** `auth login NAME`, and every re-login of scans, the fuzzer, the crawler, the proxy
  and `send --auth NAME`, starts a headless browser (the first Chromium-based one of
  `browser list`), runs the steps, and takes the site's cookies and the token its pages send
  (the header `token_header` names) into the session. The browser's only way out is a gateway
  that sends with the engagement-guarded client, as for `crawl --browser`: a page a step opens
  outside the scope is refused before the browser starts, a step that leads outside it ends
  the login with an out-of-scope error, and other hosts the pages ask for are refused one by
  one. Its requests are recorded (source `auth`), and
  those to the sites the password, the one-time code and anything else typed into a password
  field were typed on carry placeholders in their place. The replay types such a value only
  on the site it was typed on when recorded: a login that now leads somewhere else is stopped. A step waits up to 15 seconds for its element and a login
  takes two minutes at most; `BRAINPROXY_LOGIN_BROWSER_SHOW=1` shows the window, to see why a
  replay stops, and `BRAINPROXY_BROWSER_NO_SANDBOX=1` applies as for the browser crawl.
- **Passkeys.** `auth record start URL --passkey` puts a virtual authenticator in the
  recording browser (the machine's own authenticators and security keys aren't offered there).
  Log in as usual, register a passkey in the account's security settings, and
  `auth record finish NAME --save`: the credential (private key, site, user handle, signature
  counter) is kept with the profile, in the table `query` can't read, and `auth show` lists it
  without its key. To record the sign-in itself, `auth record start URL --passkeys-from NAME`
  starts the authenticator with the profile's passkeys; sign in with the passkey and finish.
  Every replay puts the passkeys back and stores the counters they reached, whatever came of
  the login (a recording with `--passkeys-from` stores them as it goes, too), so a counter only
  goes up; one process at a time signs with a profile's passkeys.

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
- A signer's script runs in a memory-safe interpreter with no file, network or process access, in a fresh
  context per request, with a loop and recursion limit and without `SharedArrayBuffer`, `Atomics` or
  `Temporal` (the sandbox the scripts of [Scripts](#scripts) run in too). Each run is a child process of brainproxy with an empty environment, killed after five
  seconds, so a script that never ends (a regex that backtracks, a loop of `await`s) leaves nothing
  running. Its memory is limited to 1 GiB: on Linux as the child's address space, on Windows by a
  job object, and on macOS by brainproxy watching the child's memory and killing it over the limit
  (it looks every 10 ms, so a fast allocation can briefly go a little over). A script stopped at
  a limit stops its signer for the rest of the command: later requests fail at once, without another run;
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
  `--session-token-env` (and by `auth add`'s `--header-env`, `--query-key`, `--password-env`,
  `--totp-secret-env` and `--oauth-*-env`, and `auth record finish`'s `--password-env` and
  `--totp-secret-env`) must start with `BRAINPROXY_SECRET_`, and `auth oauth authorize` doesn't open a
  browser.

### Findings found by hand (`findings add`)

`findings add` records an issue you found yourself, with source `manual`. It sends nothing.

```sh
brainproxy findings add --title "Order IDOR" --risk high --confidence high \
    --url https://app.acme.test/orders/7 --method GET --param id --cwe 639 \
    --history-id 42,43 --evidence 'customer_email: bob@' --description-file idor.md \
    --solution "Check that the order belongs to the signed-in user."
brainproxy findings list --source manual
brainproxy findings remove 17
```

- `--title` and `--risk` are required; `--confidence` defaults to medium.
- `--url` must be an absolute http(s) or ws(s) URL, without a user name or password. Without it,
  the URL and method are those of the first `--history-id` entry. A URL outside the engagement
  scope is recorded with a warning. The path and query are kept as given (`/public/%2e%2e/admin`
  is not resolved to `/admin`); only the scheme, host and port are normalised, and a space or
  non-ASCII character is percent-encoded.
- `--history-id` (repeatable or comma-separated) links the history entries that show the issue;
  the first is the request and response in reports. The result lists each linked entry's method
  and URL in `history`, and warns about one on another host or port than the finding's URL
  (`other_site`), which may be linked by mistake.
- `--description`, `--solution` and `--evidence` take the text; `--description-file`,
  `--solution-file` and `--evidence-file` read it from a file, or stdin with `-` (one of them).
  Through MCP the file flags only take `-`, the call's stdin.
- In Markdown reports and SARIF help, the title, description and solution are plain text: HTML,
  links, images, code spans, emphasis, lists and tables show as typed, not rendered. Only fenced
  code blocks (a line of three or more backticks or tildes, indented at most three spaces) keep
  their text as written, as code; leading spaces on other lines are dropped.
- `--input-json` reads all three from stdin instead, as
  `{"description": "...", "solution": "...", "evidence": "...", "url": "...", "method": "..."}`
  (each optional; `url` and `method` in place of `--url` and `--method`). Text on the command
  line is visible in the process list, so use it for evidence or a URL that holds a token.
- Findings with the same title share an alert type, `manual:<title>` (`manual:order-idor`), so
  reports group them. The type holds the description and solution: leaving them out keeps the
  type's, and one that differs from it is refused with `conflict` unless `--replace-text` is
  given. Replacing keeps the earlier text: `findings show` lists it in `replaced_texts`, with
  when it was replaced and who replaced it (`by`). Through MCP `--replace-text` is refused, since the text may be a
  person's. A long title is shortened and ends in a short hash, so only titles that are the
  same apart from case and punctuation share a type.
- Each finding keeps its own `--cwe`. Reports show the first one given for the type, and an
  instance's own when it differs.
- The same title, method, URL without its query or path parameters, and parameter as an existing finding is refused
  with `conflict`.
- `findings mark` triages them like any other. `findings remove ID...` removes findings added by
  hand; scanner findings are refused (mark them false positive instead), and then nothing is
  removed. A removed finding is kept with state `removed`: `findings list`, `report` and
  `findings compare` leave it out unless `--state all` (or `removed`), `findings show` gives
  when it was removed and the state it had in `removed`, and it can't be marked. The same issue
  can then be added again, as a new finding. `findings remove` is refused through MCP (and not
  offered as a tool): an agent can't tell a person's finding from its own, so it marks one
  `false_positive` with a note instead.
- `findings show` lists every linked entry in `history_ids`; in the `findings` table (`query`),
  `history_id` is the first and `last_history_id` the last.
- `findings list`, `report` and `findings compare` show them with `source: manual` (each group
  of the grouped `findings list` has a `source` too); `--source manual` picks only them.
  `findings compare --scan` leaves them out (no scan looks for them, so a scan never "fixes"
  them and its gate doesn't count them), while a file baseline and the plain `--fail-on` gate
  compare them like any other. A finding of the baseline that was removed here is listed under
  `removed`, never `fixed`, and no gate counts it.
- Like any finding, each records who added it in `origin` (`gui`, `cli` or `mcp`; see
  [Who recorded what](#who-recorded-what)); `findings remove` sets `state_origin` and `state_changed_at`, and
  `removed` in `findings show` also says who removed it (`by`) and who set the state it had.
  Reports say how each was added, and one an agent added is marked *added via MCP (an agent)*
  in the HTML report and in the app, never *found by hand*.

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
  may not have gone out). Killed while listening, the connection is left `open` with every
  message up to then, and the next `ws send`, `ws list` or `ws show` closes it with the error
  `ws send ended without closing it (killed)`: while it runs, `ws send` holds
  `<project>-ws-ID.lock`, which the system lets go of when the process dies. Stopped with
  Ctrl-C or SIGTERM, it is closed with that error.
- An HTTP/2 race (`send --race N --http2`) that fails after connecting records each copy
  with the error. If no copy got a response, the command fails with the error's kind (exit
  3) and the message lists the rows; with `--format json` the envelope's `data.results`
  has each copy's `id` too. Every item of a race that ran, failed or not, has its history `id`.
- The document fetches of `import` and `scan active --api` (with `--graphql`, the
  introspection) are recorded the same way: a row just before the request goes out, completed
  with the response or the failure.
- So are the requests of `crawl` (source `crawl`), `crawl --browser` (`crawl-browser`),
  `authz run` and its live mode (`authz`, the baseline's second copy too), `fuzz run` with
  `--store all`, the default (`fuzz`), and `scan active` (`scan`): the page `--url` fetches,
  and every request a rule or a `--checks` template sends, finding or not. A killed run leaves
  the requests it had out with the pending error. A request answered with "logged out" keeps
  its row and the one sent again after the re-login gets the next, as for `send --auth`.
  A scan request cut off by a check's timeout, or by a stopped scan, keeps `sent; no response
  recorded (the check timed out or the scan stopped)`; a browser crawl's request still out
  when the crawl ends keeps the pending error. An out-of-band finding points to its attack's
  own row. `fuzz run --store matches` records a matching request with its response, once it
  is known to match, so a killed run leaves no row for the request it had out; `--store
  none` records none. A request the engagement scope refuses outright isn't sent and gets no
  pending row (`crawl` and `fuzz run --store all` record it as failed).
- `scan active` keeps every one of these rows by default; with pruning on it deletes, once
  the scan ends, the ones nothing refers to (see
  [Pruning a scan's attack requests](#pruning-a-scans-attack-requests)). The rows are still
  written before each request goes out, so a killed scan keeps them all.
- These commands write their rows on a thread of their own: everything queued since its last
  write (rows about to go out, and completions) goes in one transaction, and a request goes
  out only once its row is committed. With many requests out at once, that is one write for
  many rows.
- `proxy stop` (and anything that stops the proxy) stops sending, then waits up to 3 seconds
  for requests already forwarded. Ones still unanswered are recorded with `proxy stopped
  before the response arrived`; one answered "logged out" whose re-login is still running
  keeps that answer. Requests arriving meanwhile get a 503 and aren't sent, and neither is a
  re-login retry. The proxy then writes out every capture still queued
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
- The proxy forwards traffic outside its proxy (recording) scope and keeps it the same way,
  unless out-of-scope traffic is recorded too (`scope set --record-out-of-scope`): a row with
  only the request line, `error` starting `outside the recording scope: content omitted`,
  then as for `--no-store`. A WebSocket upgrade gets that row and nothing of its messages. An
  HTTPS tunnel (`CONNECT`) outside the scope is never decrypted and gets one `CONNECT` row
  for the tunnel, `error` starting `outside the recording scope: tunnelled, not decrypted`,
  as a TLS pass-through connection gets one starting `TLS pass-through, not decrypted`. The
  row is written as the tunnel opens, before anything goes upstream, its `error` ending
  `open, no close recorded yet`, and completed with the byte counts as it closes. A tunnel
  still open when the proxy stops gets `still open when the proxy stopped` instead (stopping
  doesn't wait for it); one whose proxy was killed keeps the first text.
  Narrowing the scope hides what went out, never that it did. A
  request outside both scopes is refused by the engagement before it goes out and gets no
  row. Find these rows with `SELECT * FROM history WHERE error LIKE 'outside the recording scope%'`.

### Scan policies

A scan policy is a saved, named choice of which active rules run, how hard each attacks
(strength) and how sure each must be before it raises a finding (threshold), as ZAP's scan
policies are. Policies are kept in the project (setting `scan_policies`, logged in
`setting_changes`) and edited in *Scans › Policies* or with `scan policy`:

```sh
brainproxy scan policy save api --strength high --threshold medium --disable 40012,40014 \
    --rule-strength 40018=insane --rule-threshold 40018=high
brainproxy scan policy save sqli --others off --enable 40018,40019   # only these rules
brainproxy scan policy save api-lite --from api --strength low --reset 40018
echo '{"strength": "low", "rules": {"40018": {"threshold": "high"}}}' \
    | brainproxy scan policy save from-json --json -
brainproxy scan policy list
brainproxy scan policy show api      # every rule as the policy runs it (* = its own settings)
brainproxy scan policy remove api-lite
brainproxy scan active https://app.acme.test/ --crawl --policy api
```

- **Strength** is ZAP's attack strength (`low`, `medium`, `high`, `insane`): how many attacks a
  rule tries. A rule's own `--rule-strength` wins over the policy's.
- **Threshold** is ZAP's alert threshold, read against the confidence a rule gives each
  finding: `low` raises every finding (what a scan without a policy does), `medium` raises
  findings of medium or high confidence, `high` only high-confidence ones. A finding below its
  rule's threshold isn't raised; the scan counts it per alert in `below_threshold`. The attacks
  sent are the same at every threshold: the rules keep ZAP's checks at its default MEDIUM
  threshold (see [ACTIVE_RULES.md](ACTIVE_RULES.md#differences-from-zap)). An out-of-band check
  is held to the confidence its callback raises the alert at, and a check below its threshold
  isn't registered. ZAP's OFF threshold is a rule turned off (`--disable`).
- **On and off:** with `--others on` (the default) every rule runs except those the policy turns
  off; with `--others off` only the rules it turns on run, so a rule added in a later version
  stays off. Rules the turned-on ones depend on (the persistent XSS rule's Prime and Spider)
  run with them unless the policy turns them off.
- `save` builds on `--from POLICY` or `--json` (inline, or `-` for stdin), then applies the
  flags: `--strength`, `--threshold`, `--others`, `--reset IDS` (the rules take the policy's
  settings again), `--enable`, `--disable`, `--rule-strength ID=S`, `--rule-threshold ID=T`.
  Saving a name that exists replaces it. `--json` refuses a field it doesn't know.
- A policy saved by a newer brainproxy that this one can't read is listed under `unreadable`
  and kept as it is; the others still work.
- Policies tune the ported rules only: `--checks` templates run at the scan's strength and
  threshold (the policy's own, or `--strength`/`--threshold`), never at a rule's own.

`scan active --policy NAME` runs the rules as the policy says. Flags given as well win:
`--strength` and `--threshold` apply to every rule, those with settings of their own too;
`--rules` runs the rules it names instead of the policy's; `--exclude-rules` skips rules as well
as those the policy turns off. With `--preset`, the policy's strength wins over the preset's;
the preset still sets the crawl. `--threshold` also works without a policy. The result's
`policy` says what applied: `name`, `strength`, `threshold`, `rule_strengths`,
`rule_thresholds`, `rules` (the ported rules that ran, once the rules they depend on are
resolved), `exclude_rules`, and `flags_over_policy` (the flags given as well). A policy picked
in the app that was removed since stays picked, and the scan refuses to start rather than run
every rule.

`findings compare --scan` reads the rules and thresholds a policy scan ran with from its result,
not from the policy as it is now: a finding of a rule the policy turned off, or of lower
confidence than its rule's threshold, isn't counted as fixed. A `--policy` scan whose result
doesn't say (one that didn't finish) covers no ported rule.

Through MCP, `scan policy save` saves a new name only (a saved policy may be a person's) and
`scan policy remove` is refused; an agent can run a scan with any policy.

### Pruning a scan's attack requests

An active scan records every attack request it sends, so a scan of a few pages can add
hundreds of rows to history. To keep only the ones that matter, turn pruning on for the
project (*Keep only attack requests that back a finding* under *New scan*, or `brainproxy scan
prune on`; `scan prune` shows it, `scan prune off` turns it off), or pass `scan active --prune`
for one scan. `--no-prune` keeps everything for one scan whatever the setting. Changing the
setting is logged in `setting_changes` (key `active`).

With pruning on, when the scan ends it deletes the history rows of its own attack requests
that nothing refers to. It ends that way when it finishes, when it is stopped with `job stop`
(the app's *Stop* on a task), and when `--max-minutes` runs out. If the process dies first
(killed, Ctrl-C on a scan run in the foreground, a crash) or the scan fails with an error,
nothing is deleted: the rows were written before each request went out, as always, and stay.

A row is kept if it is a finding's first or last sighting or one of a hand-added finding's
linked entries, a finding event's request (a retest's, say), an `authz` result's request
tested, response or baseline, a fuzz result, a WebSocket connection's upgrade, an event stream's request, an auth macro
step's source, or an out-of-band payload's attack (a callback can still arrive and raise a
finding), or if it has a note or tags. The requests the scan starts from (history rows, the
pages a URL or `--api` scan fetches first, a `--crawl`'s requests) and a login's requests are
never its attack rows and are always kept.

Rows are deleted 500 at a time, each batch checked and deleted in a transaction of its own, so
a running proxy or another scan can keep writing meanwhile. The scan's result gives the number
deleted as `pruned` (left out when the scan kept everything). If deleting fails part way, the
scan still completes: `pruned` counts what was deleted, `prune_error` says why it stopped, and
the rest of the rows stay.

What it doesn't see:
- A reference made by another process after its batch was deleted points at a row that is
  gone: for example a passive scan of source `scan` (`scan sources`), or a second scan started
  meanwhile from the first one's attack rows (`--where "source = 'scan'"`).
- History ids in a job's arguments (`jobs.args`, such as `--history-id`) don't keep a row.
- History ids are never reused, so a deleted id never points at another request.

Through MCP, `--prune` and `scan prune on` are refused, and an agent's scan keeps every request
even with the setting on (its result says so in `prune_hint`), so a person can see everything
sent on their behalf.

### Issues, timelines, retests and posture

Findings are records with a history, not just rows:

- **Issues** (`findings issues`, `findings issue show ID`): each finding is an instance of an
  issue, one alert type on one host. `findings issues` lists them riskiest first with their
  instance count, first and last sighting, states and sources, and takes the same filters as
  `findings list`. Grouping by rule and host can merge two bugs or split one:
  `findings issue split ID... --title T` moves findings into a new issue, `findings issue
  merge INTO FROM...` moves every finding of the others into the first, and `findings issue
  title ID T` names an issue ("" goes back to the alert's name). An issue's `host` names the
  hosts of its findings (`a.test, b.test` after merging issues from two hosts; `hosts` lists
  them), and so does its write-up's heading in reports. New findings join the first issue for
  their alert and host; a finding found again stays in its issue.
- **States:** `open`, `confirmed`, `false_positive`, `accepted_risk`, `retest_pending` and
  `fixed` (`findings mark --state`; `--issue ISSUE` marks every finding of an issue). Marking
  a finding with the state it already has changes nothing: who changed it and when stay as
  they were. `findings list` and `report` show work still to do by default: open, confirmed
  and retest pending.
  A fixed finding a scanner sees again goes back to open, with a `regressed` event.
- **Timeline** (`findings timeline ID`): created, state and note changes, retests, moves
  between issues, regressions, risk changes (a sighting rated it higher, or a rescan rated it
  afresh) and removals, each with who did it (`gui`, `cli`, `mcp`) and
  when. The `finding_events` table holds them for `query`; a project from an older build gets
  a timeline built from what its findings already recorded.
- **Retest** (`findings retest ID [--auth PROFILE]`): a passive finding's latest request is
  sent again, recorded with source `retest` (which the background passive scan leaves alone),
  and the finding's own rule or passive check reads that one response. Not reproduced marks it
  `fixed`; a `fixed` or `retest_pending` finding still there is `open` again; false positives
  and accepted risks keep their state. A retest that still sees it counts as a sighting (a
  hit, and its reply as the latest); `--no-mark` records the outcome only, leaving the
  finding as it was. The passive scan never reads retest traffic, even from a source list
  saved before `scan sources` refused it, so a retest is counted once. A rule that is
  switched off (or no longer loaded) can't tell, so the retest is refused (kind conflict), and
  so is one whose reply has another kind of status than the finding's request had (a redirect
  to a login page, an error) and doesn't show the finding: nothing is marked. A "not
  reproduced" older than the finding's latest sighting is recorded but marks nothing. Only GET, HEAD and OPTIONS
  are sent unless `--allow-unsafe`. An active finding's evidence is the attack, not the request
  the scan started from, and its rule may send other methods, so it is retested by scanning
  again: the error gives the `scan active` command. Findings added by hand are retested by
  hand, access-control findings with `authz run`.
- **Posture** (`findings posture`): open issues and findings by risk, findings by state, a
  risk × confidence grid, the 20 hosts with most open findings, what each completed
  background active scan found new, still and no longer (the `scan_observations` table, stored
  as the scan ends, before `job wait` sees it complete; a scan that timed out records nothing
  as gone), retest outcomes and regressions. The Overview shows it. Like `findings compare
  --scan`, a scan's new and still are what was seen while it ran, so a finding raised by other
  traffic at the same time counts too.

Risks run `info`, `low`, `medium`, `high` and `critical` (`risk_level` 0 to 4). Checks and
vulnerable JavaScript libraries rated critical are critical; SARIF gives critical a
`security-severity` of 9.5. A finding found again at a higher risk than it was stored with
moves up, and `scan passive --rescan` rates passive findings afresh: each takes the highest
risk its sightings give now, so findings recorded as high by older builds go up to critical,
and one a rule rated too high before it was fixed comes down. Each change is a `risk` event on
the finding's timeline. Between rescans a lower rating doesn't lower it, since one URL can be
rated two ways at once (a library file served old and new under two query strings).

### Report layouts

One project gives a report for each reader. `report --preset` picks the sections:

| Preset | For | Sections |
|---|---|---|
| `technical` (default) | testers, security teams | summary, fixfirst, list, issues, evidence, about |
| `executive` | management | summary, fixfirst, posture, list, about |
| `developer` | the people fixing it | list, issues, evidence, reproduce |
| `retest` | a retest letter | retest, about |

`--sections a,b,c` names them instead: `summary` (at a glance), `fixfirst` (the ten most
serious, with their fixes), `posture` (open issues by risk, what recent scans found new and
no longer found, retests), `list` (the table of issues), `issues` (a section per issue),
`evidence` (each finding's details, request and response), `reproduce` (a curl command per
finding, with masked secrets still masked), `retest` (fixed, still there, back after a fix
and awaiting a retest since `--since DAY`, default the last 30 days, each with the retest
request as proof), `about`. `evidence` and `reproduce` sit in the issue sections, so
either brings `issues` with it. The curl lines send the request as recorded
(`--globoff --path-as-is`, the URL after `--url`, the recorded `Host`), masked secrets still masked.

Branding: `--company NAME` on the cover, `--accent #rrggbb` for the cover and headings,
`--logo FILE` (PNG, JPEG, GIF or WebP, at most 256 KiB, embedded; SVG is refused because it
can carry script). Through MCP `--logo` reads no file: save the logo in a profile from a
terminal or the app.

`report-profile save NAME [layout flags]` keeps a layout in the project (`report-profile
list | show | remove`; `--from PROFILE` saves on top of another, keeping its logo). Through
MCP a profile is saved only under a new name, and `remove` is refused: a saved layout may be
a person's branding. `report --profile NAME` starts from it; flags given with it override it, and an empty one
(`--company=`, `--accent=`, `--logo=`, `--since=`) clears what the profile has. The
retest, posture and list sections keep to the report's filters (`--host`, `--risk`, ...),
and a note says when the report is cut short by `--limit` whatever its sections.

Formats: `pdf` prints the HTML report in a headless Chromium (the one `browser list` finds;
nothing is fetched while it prints), and `docx` writes a Word document with the same
sections as headings, tables and code paragraphs, for consultancies that edit and restyle
the deliverable. Both need `--output`. The logo goes on the HTML and PDF cover, not in
the Word document.

CVSS 4.0: `findings issue cvss ISSUE 'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N'`
rates an issue ("" removes it). The score follows FIRST's method (the macrovector table of
FIRST's reference calculator), including threat (`E`) and environmental metrics. Reports show
the score, its severity and the vector on the issue and in the list; JSON and SARIF carry
them on each finding (`cvss`, SARIF `properties.cvssV4`), and SARIF's `security-severity` is
the highest score of the alert type when one is rated. CVSS 3.1 vectors are refused.

### Proof, write-ups and agents

- **Write-ups** (`findings issue narrative ISSUE --text T` or `--file F|-`; "" clears it): prose
  for an issue in reports, often drafted by an agent through MCP. A new text is a draft:
  reports leave it out (or show it marked as a draft with `report --drafts`) until a person
  reviews it, and then print it with who drafted it and who reviewed it. A review names the
  text it approves by its hash (`findings issue show` gives `narrative.hash`): `findings issue
  review ISSUE --hash H`, or *Mark reviewed* in the app, which sends the hash of the text on
  screen; a text an agent changed after it was read is refused, not approved in its place.
  `report-summary set | show | review --hash H` is the same for the executive summary at the
  top of reports. Reviewing isn't offered through MCP: an agent can't vouch for itself.
  Reports mask credentials in write-ups and ticket links like everywhere else.
- **Agent trail** (`findings trail ID`): for a finding an agent added, changed, re-raised in
  its own traffic, or whose issue it changed (write-up, title, CVSS), the requests it sent to
  that host (from half an hour before its first such act until its last), its changes, and the
  first change a person made to the finding or its issue after them. Reports say it on each
  such finding ("agent's work reviewed" or "not reviewed"), with the request range in the
  technical details.
- **Repro pack** (`findings repro ID [--output FILE [--force]] [--no-redact | --mask VALUE]`):
  the request (secrets masked), a curl command, the response around the evidence, what the rule looks for, and the
  command that checks it again (for an active finding on anything but a plain GET, the scan
  has to start from the original request: the command says which history id to give it).
  An existing `--output` file is kept unless `--force`, which is refused through MCP.
- **Tickets** (`findings ticket ID --to github --repo OWNER/NAME` or `--to jira --key KEY`):
  a title and Markdown body (what it is, where, CVSS, the reviewed write-up, how to fix and
  reproduce it, its fingerprint) and the command that files it: this command again, piped
  through `jq` into `gh issue create` or Jira's REST call (run it where the project is open).
  The project's secrets are masked, but there is no `--mask`: the printed command runs this
  one again, so a value nothing marks (a token typed into a title) is masked by editing the
  ticket before it is filed.
  The Jira description is a `{noformat}` block, so nothing the target sent is read as Jira
  markup. The GitHub command adds no labels, since `gh` refuses one the repository lacks;
  `labels` lists the suggested ones. Nothing is sent. `--record URL` keeps the filed ticket's link on the finding's
  timeline and in reports; it is refused through MCP, since the link would reach reports
  without a person reading it. *Copy ticket* in the app copies the GitHub version.
- **Exports**: `report csv` (a row per finding; cells starting `=`, `+`, `-` or `@` are
  defused for spreadsheets), `report junit` (a test suite per alert type, a failing test per
  finding still to fix, skipped once closed) and `report defectdojo` (DefectDojo's Generic
  Findings Import JSON with its own name and type, `brainproxy`, and the fingerprint as
  `unique_id_from_tool`). DefectDojo deduplicates Generic Findings Import by a hash that
  includes the description by default, so a changed write-up or note would look new. The
  setting is per scan type, and the scan type is Generic Findings Import whatever tool wrote
  the file, so choose one that still works for your other generic imports:
  `DD_DEDUPLICATION_ALGORITHM_PER_PARSER='{"Generic Findings Import": "unique_id_from_tool_or_hash_code"}'`
  matches brainproxy's findings by fingerprint and the others by hash as before. Every export names a finding by the same fingerprint
  as `report json`, SARIF and tickets.

### Comparing findings and failing a build (`findings compare`)

`findings compare` reports which findings are new, unchanged, or fixed against a baseline, and
`--fail-on` turns that into an exit code for CI. The baseline can be:

- **A file** (`--baseline FILE`): `report json` output, to compare runs in different project files.
  Findings match by alert, method, URL without its query or path parameters, and parameter, so the URL's
  scheme, host and port must be the same in both runs. `--current FILE` compares two reports and
  doesn't touch `--project`. "Fixed" only means not found this run, so it's as good as the run's
  coverage. A finding added by hand and removed since (`findings remove`) is listed under
  `removed` (with a count in `summary.removed`), not as fixed. A `--current` file needs
  `--state all` for that, since only then does it keep removed findings; without it they count
  as fixed, with a warning.
- **A scan** (`--scan JOB`): a `scan active --background` job in this project, using the same logic
  as the app's *Compare with a scan*: first found by it, found again by it, or covered by it and not
  found again. Foreground scans have no job to name.
- **Nothing**: every finding is new, which makes `--fail-on` a plain severity gate.

Write the baseline with `--state all`, so that false positives and accepted risks you've triaged
stay triaged when a later run finds them again (a gate never counts them, nor a finding marked
fixed; one marked fixed here counts as fixed against a baseline that has it), and a `--limit` above the number of findings: a report cut off at its
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
whatever `--state` lists. With `--scan`, only what that scan found counts, so findings added by
hand don't; with a file baseline or none, they count like any other.

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

`--scan JOB --baseline FILE` is for a pipeline that starts each run with a fresh project and keeps
the findings it knows in a file between runs. The scan is compared with the file's findings instead
of the project's: **new** if the scan found it and the file doesn't have it, **unchanged** if the
scan found it and the file has it (a false-positive mark in the file holds), and **fixed** if the
file has it, the scan covered it, and the scan didn't find it. Covered means the same as for `--scan`
alone: the finding's site, and its rule for an active finding (a report written before reports had
rule ids is covered only by a scan of every rule). The file's findings the scan didn't cover count
in `summary.other`, not as fixed. `data.baseline` is the scan, with `report` naming the file.
`--allow-missing-baseline` works as with a file baseline; `--since-scan` can't be combined with it.

```bash
# A fresh project each run; known.json holds what earlier runs found.
brainproxy --project run.bpdb findings compare --scan 1 --baseline known.json --fail-on high --new-only
```

A fresh project starts with every finding open, so its reports would show what earlier runs marked
as false positives. `findings mark --from FILE` copies the marks first: each of the project's
findings that matches one of FILE's (alert, method, URL without its query or path parameters, and parameter, as
`compare` matches them; a report's `fingerprint` where it has one, so a redacted report still
matches) gets that finding's mark where it is `confirmed`, `false_positive` or `accepted_risk`,
or `--state` for every match. FILE is a `report json`, or a list a team keeps of the findings it has
accepted:

```json
[{"alert_ref": "10038-1", "url": "https://shop.test/", "note": "CSP set by the CDN"},
 {"alert_ref": "40018", "method": "POST", "url": "https://shop.test/search", "param": "q", "state": "false_positive"}]
```

`method` defaults to GET, `param` to empty and `state` to `false_positive`; `note` is for the
list's readers and isn't copied. Removed findings are left as they are. The output lists each
change (`marked`: id, from, to) and how many of the file's findings matched none (`unmatched`).
Refused through MCP: an agent marks findings by id, with a note.

```bash
brainproxy --project run.bpdb findings mark --from known.json
brainproxy --project run.bpdb findings mark --from accepted.json
```

| Exit code | Meaning |
|-----------|---------|
| `0` | Compared, and the gate (if any) passed |
| `5` | Compared, and the gate found something. The output is complete: `ok` is true, and `data.gate` has `passed: false`, the `count`, and the `findings` |
| `4` | The baseline file, project, or scan job (`--scan` or `--since-scan`) doesn't exist |
| `2` | Bad arguments; a file that isn't usable (not a report, cut off, or the baseline and the findings compared being the same file); `--fail-on` with a filtered `--current` or a scan that didn't complete; a `--since-scan` job that didn't complete before the `--scan` one started; or `--since-scan` with `--baseline` |

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
another user. A GraphQL mutation needs `MUTATION` as well as its method, as in a scan (a
persisted query sent without its document counts as one too), so a mutation sent as POST is
replayed with `--include-methods POST,MUTATION`, not with either alone, and one sent as GET with
`--include-methods MUTATION`. A URL given to `authz run` needs the same opt-in: one
whose `query` parameter is a mutation is refused (exit code 2, nothing sent) without
`--include-methods MUTATION`. Paths matching `--exclude` (default: logout and sign-off) are never replayed,
so the owner stays logged in. A request picked with `--history-id` may lack credentials, but its
method needs `--include-methods` like any other, and one matching `--exclude` is refused
(exit code 2, nothing sent) unless `--exclude` is given a pattern it doesn't match. URLs on
the command line are fetched with GET and need `--owner`. Every request stays inside the
engagement scope and is recorded in history with source `authz`.

`authz run --background` returns a run id; `job wait|status|stop` work on it, and
`authz list` shows recent runs. The rows are also in the `authz_results` table for `query`.

**Live mode.** `proxy start --authz bob,anonymous` tests requests while you browse. Each
in-scope request the proxy records that carries credentials, uses GET, HEAD or OPTIONS
(and isn't a GraphQL mutation), doesn't match `--authz-exclude` (default: logout and sign-off) and got a 2xx response that
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
and `fuzz run --store none` or `--store matches` are refused, and so are `scan active --prune`
and `scan prune on`; an agent's scans keep every request whatever the project's prune setting. An agent can change the proxy
scope and the TLS pass-through list, but traffic left out still leaves rows, and a change
that narrows recording is flagged until a person changes that setting or the agent puts it
back as it was, and stays in the log either way (see [Who recorded what](#who-recorded-what)).
An agent that also runs `brainproxy` in a shell counts as `cli` there, as a person would, so
it can clear the flag that way; the change is still logged. A request whose Host header names a
host the scope doesn't list is refused without `host_header_test` (see
[Concepts](#concepts)). `browser open` isn't offered (the
project's browser profile keeps the person's sign-ins), nor is naming a script to run (a rule's
`--script`, `fuzz run --process script:`, `scan script add`; see [Scripts](#scripts)), and
other options that need a person are refused too; docs/MCP.md lists them.

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
| "the proxy is being restarted" | A `proxy restart` (from the app's *Restart on port N* or *Test live while browsing*, a shell or an agent) is between stopping the proxy and starting it again, for a few minutes at most. Try again once it has finished, or call it off with `brainproxy proxy stop`, which leaves the proxy off. If its process was killed, the next command clears its hold, and gives the record back to the old proxy if that still runs. |
| "the proxy is being stopped" | A `proxy stop` (or `project stop`) is waiting for the proxy to exit. Start it again once it has. |
| "cannot listen on …: the port is already in use" | Another program or another project's proxy holds that port. Stop it, or choose another port in **Settings › Proxy** (or with `--listen`). A chosen port is never swapped for another, so the proxy stays off until then. |
| "cannot listen on …: permission denied" | Ports below 1024 usually need elevated privileges, and the system can reserve others (Windows does, in ranges that change). Choose another port in **Settings › Proxy** (or with `--listen`). |
| A scan finds little | Make sure it covers the site: use *Crawl and audit* (with *Run JavaScript* for single-page apps), browse the app through the proxy first, or log in with an auth profile. Download the Nuclei templates. |
| Windows says "Windows protected your PC" | The installer isn't signed yet: More info → Run anyway. |
| Windows: tools other than the opened browser reject the CA | `brainproxy ca install-system` adds it to your user's Trusted Root store (Windows asks you to confirm). Firefox keeps its own store; import it there. |
| macOS says the app can't be opened or is damaged | System Settings → Privacy & Security → Open Anyway, or run the `xattr` command in [Install](#install). |
