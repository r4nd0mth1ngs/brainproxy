// Every engine call is a brainproxy CLI invocation returning its JSON envelope. In the desktop
// app it goes through the Tauri `cli` command; under `npm run dev` in a browser, through the
// Vite dev bridge (/api/cli).

export type Envelope<T = any> =
  | { ok: true; command: string; data: T }
  | { ok: false; command?: string; error: { kind: string; message: string } };

export class CliError extends Error {
  kind: string;
  constructor(kind: string, message: string) {
    super(message);
    this.kind = kind;
  }
}

export const inTauri = typeof window !== "undefined" && "__TAURI_INTERNALS__" in window; // no window under node --test

let project = "";
export const setProject = (p: string) => (project = p);
export const getProject = () => project;

/**
 * Input for one CLI call. `stdin` text is sent as UTF-8; pass bytes (see `textBytes`) when it
 * holds a binary body. `env` sets BRAINPROXY_SECRET_* variables on the child, so secrets stay
 * off the command line (e.g. BRAINPROXY_SECRET_PASSWORD for `auth add`).
 */
export interface CliInput {
  stdin?: string | Uint8Array;
  env?: Record<string, string>;
}

export async function cli<T = any>(args: string[], input: string | Uint8Array | CliInput = {}): Promise<Envelope<T>> {
  const { stdin, env } = typeof input === "string" || input instanceof Uint8Array ? { stdin: input, env: undefined } : input;
  // Bytes go as a number array (Vec<u8> in Tauri, a Buffer in the dev bridge), so nothing is re-encoded.
  const bytes = stdin == null ? null : Array.from(typeof stdin === "string" ? new TextEncoder().encode(stdin) : stdin);
  if (inTauri) {
    const { invoke } = await import("@tauri-apps/api/core");
    return invoke<Envelope<T>>("cli", { project, args, stdin: bytes, env: env ?? null });
  }
  const res = await fetch("/api/cli", {
    method: "POST",
    headers: { "content-type": "application/json", "x-brainproxy": "1" },
    body: JSON.stringify({ project, args, stdin: bytes, env }),
  });
  return res.json();
}

/** The desktop app's pid, which owns its temporary projects (none under the dev bridge). */
export async function appPid(): Promise<number | null> {
  if (!inTauri) return null;
  const { invoke } = await import("@tauri-apps/api/core");
  return invoke<number>("app_pid");
}

/** Runs a command and returns its data, throwing CliError when ok is false. */
export async function run<T = any>(args: string[], input?: string | Uint8Array | CliInput): Promise<T> {
  const env = await cli<T>(args, input);
  if (!env.ok) throw new CliError(env.error.kind, env.error.message);
  return env.data;
}

// --- Shapes of the CLI output the UI uses ---

export interface Body {
  encoding: "utf8" | "base64";
  content: string;
  length?: number;
  truncated?: boolean;
}

export interface HistoryItem {
  id: number;
  time: string;
  source: string;
  method: string;
  url: string;
  status: number | null;
  resp_content_type: string | null;
  resp_body_length: number | null;
  title: string | null;
  duration_ms: number | null;
  error: string | null;
  note: string | null;
  tags: string[];
}

export interface HistoryEntry {
  id: number;
  url: string;
  duration_ms: number | null;
  request: Body;
  response: { status: number; reason: string; headers: string[]; body: Body; http_version?: string } | null;
  entry: HistoryItem;
}

export type Risk = "high" | "medium" | "low" | "info";

export interface FindingGroup {
  alert_ref: string;
  name: string;
  risk: Risk;
  instances: number;
  hits: number;
  hosts: number;
}

export interface FindingItem {
  id: number;
  alert_ref: string;
  name: string;
  risk: Risk;
  confidence: string;
  host: string;
  method: string;
  url: string;
  param: string;
  evidence: string;
  hits: number;
  history_id: number | null;
  state: string;
}

export interface Finding extends FindingItem {
  rule_id: number;
  cwe: number | null;
  wasc: number | null;
  other_info: string;
  attack: string;
  description: string;
  solution?: string;
  refs?: string[];
  tags: string[];
  note: string | null;
  source: string;
}

/** True when a body came as base64, i.e. `bodyText` gives one char per byte (Latin-1). */
export const isBinary = (b: Body | undefined | null): boolean => b?.encoding === "base64";

/**
 * Bytes of message text. Text from a binary body (`binary`) holds one byte per char; a char
 * above 0xFF (typed in by hand) goes in as UTF-8. Other text is UTF-8.
 */
export function textBytes(text: string, binary = false): Uint8Array {
  const enc = new TextEncoder();
  if (!binary) return enc.encode(text);
  const out: number[] = [];
  for (const ch of text) {
    const c = ch.codePointAt(0)!;
    if (c <= 0xff) out.push(c);
    else out.push(...enc.encode(ch));
  }
  return Uint8Array.from(out);
}

/** Text of a body: UTF-8 as is, base64 decoded as Latin-1 so every byte stays visible. */
export function bodyText(b: Body | undefined | null): string {
  if (!b) return "";
  if (b.encoding === "utf8") return b.content;
  try {
    return atob(b.content);
  } catch {
    return b.content;
  }
}

/** --max-body for messages the GUI edits or resends, so they arrive whole (the CLI default is 64 KiB). */
export const MAX_BODY = "--max-body=2000000";

/** Throws when a body arrived cut short: editing or sending it would lose the rest. */
export function requireWhole(b: Body, what = "This message"): void {
  if (b.truncated) throw new CliError("truncated", `${what} is ${b.length ?? "over 2000000"} bytes, too large to edit or send from the app; use the CLI.`);
}

/** The request of a history entry, ready for Replay or the Fuzzer. Throws when it is truncated. */
export async function historyRequest(id: number): Promise<{ raw: string; binary: boolean; entry: HistoryEntry }> {
  const entry = await run<HistoryEntry>(["history", "show", String(id), MAX_BODY]);
  requireWhole(entry.request, `Request #${id}`);
  return { raw: bodyText(entry.request), binary: isBinary(entry.request), entry };
}

/** A raw HTTP response rebuilt from `history show` (status line, headers, body). */
export function rawResponse(e: HistoryEntry): string {
  const r = e.response;
  if (!r) return "";
  return `${r.http_version ?? "HTTP/1.1"} ${r.status} ${r.reason}\r\n${r.headers.join("\r\n")}\r\n\r\n${bodyText(r.body)}`;
}

export function hostOf(url: string): string {
  try {
    return new URL(url).host;
  } catch {
    return "";
  }
}

export function pathOf(url: string): string {
  try {
    const u = new URL(url);
    return u.pathname + u.search;
  } catch {
    return url;
  }
}

/**
 * Adds a scheme to a URL typed without one ("10.0.0.5:8100/x", "app.example.com"):
 * https for port 443/8443 or no port, http for any other explicit port.
 */
export function withScheme(url: string): string {
  const u = url.trim();
  if (!u || /^[a-z][a-z0-9+.-]*:\/\//i.test(u)) return u;
  const port = /^[^/?#]*:(\d+)(?:[/?#]|$)/.exec(u)?.[1];
  return `${!port || port === "443" || port === "8443" ? "https" : "http"}://${u}`;
}
