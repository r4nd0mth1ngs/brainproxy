// Per-tab send options for Replay: which `send` / `ws send` flags a tab adds, the short
// labels the tab shows for the ones that aren't the default, and the request text a send
// writes on stdin.

// With their extensions, so the tests can load these modules.
import { splitRaw } from "../ui/message.ts";
import { autoEncodeRequest } from "../ui/urlencode.ts";

export interface ReplayOptions {
  /** `--http2`: ALPN h2 for https, prior knowledge for http. */
  http2: boolean;
  /** `--verbatim`: no Content-Length update and no header end added; the GUI skips auto URL-encode too. */
  verbatim: boolean;
  /** `--sni`: the TLS server name to send instead of the target's host. Empty: the target's. */
  sni: string;
  /** `--timeout` in seconds, as typed. Empty: the CLI's 30. */
  timeout: string;
  /** `--verify-tls`: check the server certificate (off by default). */
  verifyTls: boolean;
  /** `--no-store`: don't record the exchange in history. */
  noStore: boolean;
}

/** HTTP tabs offer every option; WebSocket tabs only what `ws send` has. */
export type TabKind = "http" | "ws";

export const DEFAULT_OPTIONS: ReplayOptions = { http2: false, verbatim: false, sni: "", timeout: "", verifyTls: false, noStore: false };

/** The CLI's default `--timeout` for both `send` and `ws send`. */
export const DEFAULT_TIMEOUT = 30;
/** The longest timeout a tab takes (a day); the CLI can't hold a much larger one. */
export const MAX_TIMEOUT = 86400;

/** A tab's options with every field filled (tabs made before a field existed have none). */
export function withDefaults(o: Partial<ReplayOptions> | undefined): ReplayOptions {
  return { ...DEFAULT_OPTIONS, ...o };
}

/** The timeout in seconds, or null for the CLI's default (empty, or exactly the default). */
function timeoutSeconds(o: ReplayOptions): number | null {
  const t = o.timeout.trim();
  if (!t) return null;
  const n = Number(t);
  return n === DEFAULT_TIMEOUT ? null : n;
}

/** Why the options can't be sent, or null. */
export function optionsProblem(o: Partial<ReplayOptions> | undefined): string | null {
  const t = withDefaults(o).timeout.trim();
  if (t && !(Number(t) > 0 && Number(t) <= MAX_TIMEOUT)) return `Timeout must be a number of seconds above 0 and at most ${MAX_TIMEOUT}, not "${t}"`;
  const sni = withDefaults(o).sni.trim();
  if (/\s/.test(sni)) return "The SNI host name can't contain spaces";
  return null;
}

/** The flags for the options that aren't the default, as `--flag` or `--flag=value`. */
export function optionArgs(o: Partial<ReplayOptions> | undefined, kind: TabKind): string[] {
  const f = withDefaults(o);
  const args: string[] = [];
  if (kind === "http" && f.http2) args.push("--http2");
  if (kind === "http" && f.verbatim) args.push("--verbatim");
  if (f.sni.trim()) args.push(`--sni=${f.sni.trim()}`);
  const t = timeoutSeconds(f);
  if (t != null) args.push(`--timeout=${t}`);
  if (f.verifyTls) args.push("--verify-tls");
  if (f.noStore) args.push("--no-store");
  return args;
}

/** `send` arguments for a Replay tab; the request goes on stdin. */
export function sendArgs(target: string, o: Partial<ReplayOptions> | undefined): string[] {
  return ["send", `--target=${target}`, ...optionArgs(o, "http"), "-"];
}

/** Short labels for the options that aren't the default, shown on the tab. */
export function activeLabels(o: Partial<ReplayOptions> | undefined, kind: TabKind): string[] {
  const f = withDefaults(o);
  const out: string[] = [];
  if (kind === "http" && f.http2) out.push("HTTP/2");
  if (kind === "http" && f.verbatim) out.push("as typed");
  if (f.sni.trim()) out.push(`SNI ${f.sni.trim()}`);
  const t = timeoutSeconds(f);
  if (t != null) out.push(`timeout ${t} s`);
  if (f.verifyTls) out.push("verify TLS");
  if (f.noStore) out.push("not recorded");
  return out;
}

/** Every line break as CRLF; a binary body keeps its bytes (only its head changes). */
export function crlfLines(raw: string, binary: boolean): string {
  const fix = (s: string) => s.replace(/\r?\n/g, "\r\n");
  if (!binary) return fix(raw);
  const { head, sep, body } = splitRaw(raw);
  return fix(head) + (sep ? "\r\n\r\n" : "") + body;
}

/**
 * The request text a send writes on stdin and how many characters auto URL-encode changed.
 * Sent as typed (`--verbatim`), the CLI changes nothing, so line breaks are written as CRLF
 * here (the editor holds only \n) and auto URL-encode is skipped. Otherwise the CLI turns
 * the head's line breaks into CRLF and fixes Content-Length.
 */
export function requestToSend(raw: string, o: { binary?: boolean; autoEncode: boolean; options?: Partial<ReplayOptions> }): { text: string; encoded: number } {
  if (withDefaults(o.options).verbatim) return { text: crlfLines(raw, !!o.binary), encoded: 0 };
  return o.autoEncode ? autoEncodeRequest(raw) : { text: raw, encoded: 0 };
}
