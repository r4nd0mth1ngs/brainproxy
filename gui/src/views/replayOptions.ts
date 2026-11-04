// Per-tab send options for Replay: which `send` / `ws send` flags a tab adds, the short
// labels the tab shows for the ones that aren't the default, and the request text a send
// writes on stdin.

// With their extensions, so the tests can load these modules.
import { splitRaw } from "../ui/message.ts";
import { autoEncodeRequest } from "../ui/urlencode.ts";

export interface ReplayOptions {
  /** `--http2`: ALPN h2 for https, prior knowledge for http. */
  http2: boolean;
  /**
   * `--verbatim`: no Content-Length update and no header end added; the GUI skips auto URL-encode
   * too. HTTP/1 only: with `http2` on it is kept but not used (sendsAsTyped).
   */
  verbatim: boolean;
  /** Not a CLI flag: the GUI writes a text body's line breaks as CRLF (the editor can't hold a CR). */
  crlfBody: boolean;
  /** `--sni`: the TLS server name to send instead of the target's host. Empty: the target's. */
  sni: string;
  /** `--timeout` in seconds, as typed. Empty: the CLI's 30. */
  timeout: string;
  /** `--verify-tls`: check the server certificate (off by default). */
  verifyTls: boolean;
  /** `--no-store`: keep the exchange's content out of history (it still gets a row). */
  noStore: boolean;
}

/** HTTP tabs offer every option; WebSocket tabs only what `ws send` has. */
export type TabKind = "http" | "ws";

export const DEFAULT_OPTIONS: ReplayOptions = { http2: false, verbatim: false, crlfBody: false, sni: "", timeout: "", verifyTls: false, noStore: false };

/** The CLI's default `--timeout` for both `send` and `ws send`. */
export const DEFAULT_TIMEOUT = 30;
/** The longest timeout a tab takes (a day); the CLI can't hold a much larger one. */
export const MAX_TIMEOUT = 86400;

/** A tab's options with every field filled (tabs made before a field existed have none). */
export function withDefaults(o: Partial<ReplayOptions> | undefined): ReplayOptions {
  return { ...DEFAULT_OPTIONS, ...o };
}

/**
 * Whether the tab sends as typed. Only over HTTP/1: HTTP/2 rebuilds the request into frames from
 * the parsed text, so "as typed" means nothing on the wire there and `--verbatim` isn't passed.
 */
export function sendsAsTyped(o: Partial<ReplayOptions> | undefined): boolean {
  const f = withDefaults(o);
  return f.verbatim && !f.http2;
}

/**
 * The timeout in seconds; null for the CLI's default (empty, or exactly the default);
 * "invalid" when it isn't a plain number of seconds in range (optionsProblem says why).
 * Plain digits only: Number() would also take `0x10`, `1e3` or `+5`.
 */
function timeoutSeconds(o: ReplayOptions): number | null | "invalid" {
  const t = o.timeout.trim();
  if (!t) return null;
  if (!/^\d+(\.\d+)?$/.test(t)) return "invalid";
  const n = Number(t);
  if (!(n > 0 && n <= MAX_TIMEOUT)) return "invalid";
  return n === DEFAULT_TIMEOUT ? null : n;
}

/** Why the options can't be sent, or null. */
export function optionsProblem(o: Partial<ReplayOptions> | undefined): string | null {
  const t = withDefaults(o).timeout.trim();
  if (timeoutSeconds(withDefaults(o)) === "invalid") return `Timeout must be a plain number of seconds above 0 and at most ${MAX_TIMEOUT}, such as 60 or 2.5, not "${t}"`;
  const sni = withDefaults(o).sni.trim();
  if (/\s/.test(sni)) return "The SNI host name can't contain spaces";
  if (sni && !validServerName(sni)) return `The SNI "${sni}" isn't a valid TLS server name (a DNS name or an IP address)`;
  return null;
}

const IPV4 = /^(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}$/;

/**
 * Whether `name` is an IPv6 address as rustls reads one: Rust's own parser, which this follows
 * step by step. Eight groups of 1 to 4 hex digits, or fewer with one `::` standing for at least
 * one zero group; the last two groups may be an IPv4 address, but not before a `::`. No brackets
 * and no zone (`%eth0`). A URL's host parser is looser: it takes `::1]/x/[`, say.
 */
function validIpv6(name: string): boolean {
  let at = 0;
  // Each read moves on only if it succeeds.
  const char = (c: string) => name[at] === c && ++at > 0;
  const number = (digit: RegExp, maxDigits: number, max: number, zeroPrefix: boolean) => {
    let n = 0;
    while (at + n < name.length && digit.test(name[at + n])) n++;
    if (n === 0 || n > maxDigits || (!zeroPrefix && n > 1 && name[at] === "0")) return false;
    if (parseInt(name.slice(at, at + n), digit === HEX ? 16 : 10) > max) return false;
    at += n;
    return true;
  };
  const atomically = (read: () => boolean) => {
    const from = at;
    if (read()) return true;
    at = from;
    return false;
  };
  const ipv4 = () => [0, 1, 2, 3].every((i) => (i === 0 || char(".")) && number(DEC, 3, 255, false));
  // Up to `limit` groups, the first without a ':' before it: how many, and whether the last two
  // were an IPv4 address.
  const groups = (limit: number): [number, boolean] => {
    for (let i = 0; i < limit; i++) {
      if (i < limit - 1 && atomically(() => (i === 0 || char(":")) && ipv4())) return [i + 2, true];
      if (!atomically(() => (i === 0 || char(":")) && number(HEX, 4, 0xffff, true))) return [i, false];
    }
    return [limit, false];
  };
  const [head, headIpv4] = groups(8);
  if (head < 8) {
    if (headIpv4 || !char(":") || !char(":")) return false;
    groups(7 - head);
  }
  return at === name.length;
}

const HEX = /[0-9A-Fa-f]/;
const DEC = /[0-9]/;

/**
 * Whether `name` is a TLS server name `--sni` takes: an IP address, or a DNS name as rustls
 * reads one (at most 253 bytes; labels of 1 to 63 letters, digits, `_` and `-`, not starting or
 * ending with `-`; a trailing dot allowed; the last label not all digits).
 */
export function validServerName(name: string): boolean {
  if (IPV4.test(name)) return true;
  if (name.includes(":")) return validIpv6(name);
  if (!name || name.length > 253) return false;
  const labels = (name.endsWith(".") ? name.slice(0, -1) : name).split(".");
  if (!labels.every((l) => /^[A-Za-z0-9_](?:[A-Za-z0-9_-]{0,61}[A-Za-z0-9_])?$/.test(l))) return false;
  return !/^\d+$/.test(labels[labels.length - 1]);
}

/** A tab's options as `replay tabs save` keeps them (`options`), or undefined when all are defaults. */
export interface SavedOptions {
  http2?: true;
  verbatim?: true;
  crlfBody?: true;
  sni?: string;
  timeout?: number;
  verifyTls?: true;
}

/**
 * The options kept with a saved tab, in the order the CLI writes them. Never Don't record: a
 * reopened tab, or one an agent prepared, must not make a person's send unrecorded. An SNI or
 * timeout that isn't valid yet (still being typed) is left out rather than failing the save.
 */
export function savedOptions(o: Partial<ReplayOptions> | undefined, kind: TabKind): SavedOptions | undefined {
  const f = withDefaults(o);
  const out: SavedOptions = {};
  if (kind === "http" && f.http2) out.http2 = true;
  if (kind === "http" && f.verbatim) out.verbatim = true;
  if (kind === "http" && f.crlfBody) out.crlfBody = true;
  const sni = f.sni.trim();
  if (sni && validServerName(sni)) out.sni = sni;
  const t = timeoutSeconds(f);
  if (typeof t === "number") out.timeout = t;
  if (f.verifyTls) out.verifyTls = true;
  return Object.keys(out).length ? out : undefined;
}

/** A saved tab's options back as a tab's; anything unknown or out of range is ignored. */
export function optionsFromSaved(v: unknown, kind: TabKind): Partial<ReplayOptions> | undefined {
  if (!v || typeof v !== "object") return undefined;
  const s = v as Record<string, unknown>;
  const out: Partial<ReplayOptions> = {};
  if (kind === "http" && s.http2 === true) out.http2 = true;
  if (kind === "http" && s.verbatim === true) out.verbatim = true;
  if (kind === "http" && s.crlfBody === true) out.crlfBody = true;
  if (typeof s.sni === "string" && validServerName(s.sni)) out.sni = s.sni;
  if (typeof s.timeout === "number" && s.timeout > 0 && s.timeout <= MAX_TIMEOUT) out.timeout = String(s.timeout);
  if (s.verifyTls === true) out.verifyTls = true;
  return Object.keys(out).length ? out : undefined;
}

/** The flags for the options that aren't the default, as `--flag` or `--flag=value`. */
export function optionArgs(o: Partial<ReplayOptions> | undefined, kind: TabKind): string[] {
  const f = withDefaults(o);
  const args: string[] = [];
  if (kind === "http" && f.http2) args.push("--http2");
  if (kind === "http" && sendsAsTyped(f)) args.push("--verbatim");
  if (f.sni.trim()) args.push(`--sni=${f.sni.trim()}`);
  const t = timeoutSeconds(f);
  if (typeof t === "number") args.push(`--timeout=${t}`);
  if (f.verifyTls) args.push("--verify-tls");
  if (f.noStore) args.push("--no-store");
  return args;
}

/** `send` arguments for a Replay tab; the request goes on stdin. */
export function sendArgs(target: string, o: Partial<ReplayOptions> | undefined): string[] {
  return ["send", `--target=${target}`, ...optionArgs(o, "http"), "-"];
}

/**
 * How Copy as cURL follows the tab's options (`toCurl`'s `send`): HTTP/2, `-k` unless Verify
 * TLS is on (Send doesn't check certificates either), the timeout as `--max-time`, and a
 * warning for "send as typed" and SNI, which curl can't reproduce. The CRLF body is already in
 * the text requestToSend gives; Don't record has nothing to do with curl.
 */
export function curlOptions(o: Partial<ReplayOptions> | undefined): { http2: boolean; insecure: boolean; asTyped: boolean; sni: string; timeout?: number } {
  const f = withDefaults(o);
  const t = timeoutSeconds(f);
  return { http2: f.http2, insecure: !f.verifyTls, asTyped: sendsAsTyped(f), sni: f.sni.trim(), ...(typeof t === "number" ? { timeout: t } : {}) };
}

/** Short labels for the options that aren't the default, shown on the tab. */
export function activeLabels(o: Partial<ReplayOptions> | undefined, kind: TabKind): string[] {
  const f = withDefaults(o);
  const out: string[] = [];
  if (kind === "http" && f.http2) out.push("HTTP/2");
  if (kind === "http" && sendsAsTyped(f)) out.push("as typed");
  if (kind === "http" && f.crlfBody) out.push("CRLF body");
  if (f.sni.trim()) out.push(`SNI ${f.sni.trim()}`);
  const t = timeoutSeconds(f);
  if (t === "invalid") out.push("timeout invalid");
  else if (t != null) out.push(`timeout ${t} s`);
  if (f.verifyTls) out.push("verify TLS");
  if (f.noStore) out.push("not recorded");
  return out;
}

const crlf = (s: string) => s.replace(/\r?\n/g, "\r\n");

/** The head's line breaks and the header end as CRLF; the body keeps its bytes. */
export function crlfHead(raw: string): string {
  const { head, sep, body } = splitRaw(raw);
  return crlf(head) + (sep ? "\r\n\r\n" : "") + body;
}

/** A text body's line breaks as CRLF; the head is left alone. */
export function crlfBody(raw: string): string {
  const { head, sep, body } = splitRaw(raw);
  return sep ? head + sep + crlf(body) : raw;
}

/**
 * The request text a send writes on stdin and how many characters auto URL-encode changed.
 * Sent as typed (`--verbatim`, HTTP/1 only), the CLI changes nothing, so the head's line
 * breaks are written as CRLF here (the editor holds only \n there) and auto URL-encode is
 * skipped. Otherwise the CLI turns the head's line breaks into CRLF and fixes Content-Length.
 * Either way the body is as the editor holds it (an unedited one keeps its bytes), unless
 * "CRLF body" is on.
 */
export function requestToSend(raw: string, o: { binary?: boolean; autoEncode: boolean; options?: Partial<ReplayOptions> }): { text: string; encoded: number } {
  const f = withDefaults(o.options);
  const out = sendsAsTyped(f) ? { text: crlfHead(raw), encoded: 0 } : o.autoEncode ? autoEncodeRequest(raw) : { text: raw, encoded: 0 };
  if (f.crlfBody && !o.binary) out.text = crlfBody(out.text);
  return out;
}

/** What the send of a step in a tab's history used, when that isn't what the tab now has. */
export function sentWithNote(sentLabels: string[] | undefined, current: string[]): string | null {
  if (!sentLabels || sentLabels.join("\n") === current.join("\n")) return null;
  return sentLabels.length ? `sent with: ${sentLabels.join(", ")}` : "sent with the default options";
}
