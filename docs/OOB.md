# Out-of-band (OOB) interactions

A Collaborator/interactsh-like listener so blind issues (Log4Shell, blind XXE, blind
SSTI/command execution, blind SSRF found by hand) can be confirmed by the target calling
back to us.

## Shape

```
brainproxy oob start [--http-listen 0.0.0.0:8880] [--dns-listen 0.0.0.0:53 --domain oob.example.com]
                     [--public-host H] [--public-port P] [--public-ip IP]
brainproxy oob run     # same, in the foreground
brainproxy oob status | stop
brainproxy oob payload [--note TEXT] [--count N]      # payloads for manual testing
brainproxy oob poll [--token T] [--since ID] [--wait SECS] [--limit N]
brainproxy scan active ... [--oob-wait SECS] [--no-oob]
```

- **Listener** (`crates/core/src/oob/server.rs`) runs in one background process per
  project, like the proxy (state in `meta` key `oob.state`). It only receives:
  - TCP (`--http-listen`): HTTP requests get an empty `200`; an LDAP bind (first byte
    `0x30`, what JNDI sends for `ldap://`) gets a minimal bind-success so the client goes
    on to send the search request whose DN carries the token; a TLS ClientHello (`https://`
    payloads) is recorded for its SNI and closed. Anything else is recorded as `tcp`.
  - UDP DNS (`--dns-listen`, needs `--domain`): every query is recorded; names under the
    domain get an `A`/`AAAA` answer with `--public-ip` (TTL 0), others `REFUSED`.
  - Bounded: 16 KiB recorded per interaction, 5 s per connection, 128 connections at once.
- **Reachability / NAT**: payloads use the public names, not the listen address.
  - DNS mode (`--domain`): payload host is `<token>.<domain>` (delegate the domain's NS to
    the runner, or point a wildcard A record at it). URLs are `http://<token>.<domain>[:port]/`.
  - Host mode (no domain): payload host is `<public-host>:<public-port>` and the token
    goes in the path: `http://<public-host>:<port>/<token>`. `--public-host` defaults to the
    listen IP, or the address of the outbound interface when listening on 0.0.0.0
    (found with a UDP `connect`, which sends nothing). When it was guessed, each target's
    payloads use the local address that routes to that target instead (so a LAN target
    gets the LAN address even with a VPN as the default route; `oob payload --target`).
    Set it (and `--public-port`) to the NAT/port-forward/tunnel address targets can reach.
- **Tokens**: `bp` + 18 random base32 characters (`/dev/urandom`), unique per attack
  request. The listener extracts the first `bp[a-z2-7]{18}` it sees in the lowercased
  bytes (Host, path, DNS name, SNI, LDAP DN), preferring one that is registered.
- **Storage** (schema v8): `oob_payloads` (one row per token: source `scan`/`manual`,
  rule id, alert ref, param, attack, origin, the attack request/response, note,
  history_id once a finding was recorded) and `oob_interactions` (protocol, remote
  address, token, summary line, raw bytes, `processed`). Both are visible to `query`.
- **Attribution**: rules call `cx.oob_payload()` (None when no listener is running: the
  OOB part is skipped, like ZAP without its OAST add-on) and `cx.oob_register(...)` with
  the finding they would raise and the attack exchange. The scan is never blocked by OOB:
  after all units finish, `scan active` waits up to `--oob-wait` seconds (default 5) while
  correlating. `oob::correlate` turns each unprocessed interaction whose token belongs to a
  scan payload into a finding (evidence: the interaction summary; other info: ZAP's
  "Received ... Request: ..." text) backed by the attack exchange recorded in history.
  Late callbacks are raised by any later `oob poll` (or the next scan).
- **Security boundary**: the listener never opens outbound connections and the DNS server
  only answers with our own address. Rules' attack requests still go through `Cx::send*`,
  i.e. the guarded `Client`. The OOB host is never contacted by brainproxy itself.

## Rules using it

- Log4Shell (40043, CVE-2021-44228 / CVE-2021-45046), ported from ZAP.
- XXE (90023) check #2 (out-of-band external entity, http and https).
- Blind SSTI (90036) callback payloads (`curl`/`wget`) at HIGH/INSANE strength.

## Not done

- No interactsh client or remote listener (the listener must write to the project file).
- No SMTP listener; no HTTPS server (TLS ClientHello is recorded, the handshake isn't completed).
