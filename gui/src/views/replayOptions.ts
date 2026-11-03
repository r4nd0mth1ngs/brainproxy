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
  return null;
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
