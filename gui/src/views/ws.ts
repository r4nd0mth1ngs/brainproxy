// WebSocket shapes from the CLI (`ws list`, `ws messages`, `ws send`) and the helpers the
// WebSockets tab and Replay's WebSocket mode share.

import { bodyText, isBinary, requireWhole, textBytes, type Body } from "../api.ts";
import { optionArgs, type ReplayOptions } from "./replayOptions.ts";

export interface WsConnection {
  id: number;
  time: string;
  source: string;
  history_id: number | null;
  url: string;
  host: string;
  extensions: string | null;
  protocol: string | null;
  state: "open" | "closed";
  closed_time: string | null;
  close_code: number | null;
  close_reason: string | null;
  messages: number;
  error: string | null;
}

export interface WsMessage {
  id: number | null;
  connection_id?: number;
  time?: string;
  direction: "to-server" | "to-client";
  opcode: "text" | "binary" | "close" | "ping" | "pong";
  payload: Body;
  length?: number;
  compressed: boolean;
  fragments?: number;
  intercept?: string | null;
  elapsed_ms?: number;
}

export interface WsSendResult {
  connection_id: number | null;
  history_id: number | null;
  url: string;
  upgraded: boolean;
  accept_ok?: boolean;
  extensions?: string | null;
  stopped?: string;
  received?: number;
  close?: { code: number | null; reason: string | null };
  error?: string | null;
  messages?: WsMessage[];
  /** When the server refused the upgrade. */
  response?: { status: number; reason: string; headers: string[]; body: Body } | null;
}

/**
 * A message to send, as `ws send --input-json` and a saved Replay tab hold it: a string is a
 * text message, `{hex}` or `{base64}` a binary one, written as typed (decoded when sent).
 */
export type WsOut = string | { hex: string } | { base64: string };
export type BinaryKind = "hex" | "base64";

/** The line that separates messages in Replay's message box. */
export const SEPARATOR = "---";
/**
 * A separator line, or with backslashes before it a message line that looks like one (an
 * escape: the box holds `\---` for a text line `---`). `--- hex` or `--- base64` makes the
 * message after it binary, written that way; `--- text` makes it text.
 */
const SEPARATOR_LIKE = /^(\\*)---(?:[ \t]+(text|hex|base64))?$/i;

/** Whether `m` is a message as saved (a string, or one hex or base64 string), not something else. */
export function isWsOut(m: unknown): m is WsOut {
  if (typeof m === "string") return true;
  if (!m || typeof m !== "object" || Array.isArray(m)) return false;
  const keys = Object.keys(m);
  return keys.length === 1 && (keys[0] === "hex" || keys[0] === "base64") && typeof (m as Record<string, unknown>)[keys[0]] === "string";
}

/** Hex or base64 when `m` is binary, else null. */
export const binaryKind = (m: WsOut): BinaryKind | null => (typeof m === "string" ? null : "hex" in m ? "hex" : "base64");
const binaryText = (m: Exclude<WsOut, string>): string => ("hex" in m ? m.hex : m.base64);

/**
 * Messages typed in Replay, one per block between separator lines: `---` before a text
 * message (the first needs none), `--- hex` or `--- base64` before a binary one, `--- text`
 * before a text one. A blank block after a plain `---` (or before the first) is skipped, so a
 * stray separator adds nothing; after a named one it is an empty message. A line that only
 * looks like a separator is written with a backslash before it (`\---`), which is taken off.
 */
export function splitMessages(text: string): WsOut[] {
  const out: WsOut[] = [];
  let cur: string[] = [];
  let kind: string | null = null;
  const flush = () => {
    const m = cur.join("\n");
    if (kind === "hex") out.push({ hex: m });
    else if (kind === "base64") out.push({ base64: m });
    else if (kind === "text" || m.trim()) out.push(m);
    cur = [];
  };
  for (const line of text.replace(/\r\n/g, "\n").split("\n")) {
    const t = line.trim();
    const sep = SEPARATOR_LIKE.exec(t);
    if (!sep) cur.push(line);
    else if (sep[1]) {
      // Escaped: one backslash fewer, as message text.
      const at = line.length - line.trimStart().length;
      cur.push(line.slice(0, at) + line.slice(at + 1));
    } else {
      flush();
      kind = sep[2]?.toLowerCase() ?? null;
    }
  }
  flush();
  return out;
}

/** The box's text for `messages`; [splitMessages] gives them back exactly. */
export function joinMessages(messages: WsOut[]): string {
  // A message line that would read as a separator gets one more backslash.
  const escape = (m: string) =>
    m
      .split("\n")
      .map((line) => {
        if (!SEPARATOR_LIKE.test(line.trim())) return line;
        const at = line.length - line.trimStart().length;
        return `${line.slice(0, at)}\\${line.slice(at)}`;
      })
      .join("\n");
  return messages
    .map((m, i) => {
      const kind = binaryKind(m);
      if (kind) return `${SEPARATOR} ${kind}\n${escape(binaryText(m as Exclude<WsOut, string>))}`;
      const text = escape(m as string);
      // A blank text message needs its kind named, or it would be skipped.
      if (!text.trim()) return `${SEPARATOR} text\n${text}`;
      return i === 0 ? text : `${SEPARATOR}\n${text}`;
    })
    .join("\n");
}

/**
 * Bytes of hex as `ws send` reads it: whitespace and colons are ignored, and so is a leading
 * `0x`. Throws saying what is wrong.
 */
export function hexBytes(text: string): Uint8Array {
  // ASCII whitespace only, as `ws send` strips it: a no-break space isn't hex.
  let s = text.replace(/[ \t\n\f\r:]/g, "");
  if (s.startsWith("0x")) s = s.slice(2);
  const bad = /[^0-9a-fA-F]/.exec(s);
  if (bad) throw new Error(`“${bad[0]}” isn't a hex digit`);
  if (s.length % 2) throw new Error(`an odd number of hex digits (${s.length})`);
  const out = new Uint8Array(s.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(s.slice(i * 2, i * 2 + 2), 16);
  return out;
}

/** Bytes of base64, standard or URL-safe, padded or not, whitespace ignored. Throws saying what is wrong. */
export function base64Bytes(text: string): Uint8Array {
  const s = text.replace(/[ \t\n\f\r]/g, "");
  const body = s.replace(/=+$/, "");
  const urlSafe = /[-_]/.test(body);
  const bad = (urlSafe ? /[^A-Za-z0-9\-_]/ : /[^A-Za-z0-9+/]/).exec(body);
  if (bad) throw new Error(bad[0] === "=" ? "“=” only belongs at the end" : `“${bad[0]}” isn't a base64 character`);
  if (body.length % 4 === 1 || s.length - body.length > 2) throw new Error("its length is wrong for base64; is a character missing?");
  const std = urlSafe ? body.replace(/-/g, "+").replace(/_/g, "/") : body;
  const bin = atob(std + "=".repeat((4 - (std.length % 4)) % 4));
  // atob ignores bits left over in the last character; `ws send` refuses them (a value cut short).
  if (btoa(bin).replace(/=+$/, "") !== std) throw new Error("its last character has bits left over; is it cut short?");
  return Uint8Array.from(bin, (c) => c.charCodeAt(0));
}

export function toBase64(bytes: Uint8Array): string {
  let bin = "";
  // In slices: spreading a whole large payload into fromCharCode overflows the stack.
  for (let i = 0; i < bytes.length; i += 0x8000) bin += String.fromCharCode(...bytes.subarray(i, i + 0x8000));
  return btoa(bin);
}

/** Hex pairs, 16 to a line: how a binary message opens in Replay. */
export function toHex(bytes: Uint8Array): string {
  const lines: string[] = [];
  for (let i = 0; i < bytes.length; i += 16) lines.push(Array.from(bytes.subarray(i, i + 16), (b) => b.toString(16).padStart(2, "0")).join(" "));
  return lines.join("\n");
}

/**
 * The messages as `ws send --input-json` takes them, binary ones as base64 decoded and checked
 * here, so a mistake is reported before anything is sent. Throws naming the message.
 */
export function wsInputMessages(messages: WsOut[]): (string | { base64: string })[] {
  return messages.map((m, i) => {
    const bytes = decodeMessage(m, i);
    return bytes ? { base64: toBase64(bytes) } : (m as string);
  });
}

/** A binary message's bytes (null for text); throws naming message `i` when it doesn't decode. */
function decodeMessage(m: WsOut, i: number): Uint8Array | null {
  const kind = binaryKind(m);
  if (!kind) return null;
  try {
    const text = binaryText(m as Exclude<WsOut, string>);
    return kind === "hex" ? hexBytes(text) : base64Bytes(text);
  } catch (e: any) {
    throw new Error(`Message ${i + 1} (${kind}): ${e.message}`);
  }
}

/** What the box holds, for its toolbar: how many of each kind, or the first mistake. */
export function messagesSummary(messages: WsOut[]): { text: string; problem: boolean } {
  try {
    // Decoded only, not encoded again: this runs as the person types.
    messages.forEach(decodeMessage);
  } catch (e: any) {
    return { text: e.message, problem: true };
  }
  const binary = messages.filter((m) => typeof m !== "string").length;
  const n = messages.length;
  if (!n) return { text: "", problem: false };
  return { text: `${n} message${n === 1 ? "" : "s"}${binary ? ` (${binary} binary)` : ""}`, problem: false };
}

/** Binary messages up to this many bytes open in Replay as hex, larger ones as base64 (a third the size). */
export const HEX_MAX = 16384;

/** A recorded message as Replay sends it: text as it is, binary with its bytes exactly. */
export function replayMessage(m: Pick<WsMessage, "opcode" | "payload" | "id">): WsOut {
  if (m.opcode === "text") return bodyText(m.payload);
  if (m.opcode !== "binary") throw new Error(`Message #${m.id} is a ${m.opcode} frame; only text and binary messages can be sent to Replay`);
  // A binary payload that is valid UTF-8 is listed as text: its bytes are that text's UTF-8.
  const bytes = textBytes(bodyText(m.payload), isBinary(m.payload));
  return bytes.length <= HEX_MAX ? { hex: toHex(bytes) } : { base64: toBase64(bytes) };
}

/**
 * The first `n` bytes of a payload, decoding only as much as that takes: a table row's preview
 * runs for every row, and again in each sort comparison, on payloads of up to 2 MB.
 */
export function payloadPrefix(b: Body, n: number): Uint8Array {
  if (isBinary(b)) {
    try {
      const bin = atob(b.content.slice(0, Math.ceil(n / 3) * 4));
      return Uint8Array.from(bin.slice(0, n), (c) => c.charCodeAt(0));
    } catch {
      return new Uint8Array();
    }
  }
  // Every character is at least one byte; by code point, so a surrogate pair isn't split.
  let text = "";
  let count = 0;
  for (const ch of b.content) {
    if (count++ >= n) break;
    text += ch;
  }
  return textBytes(text).subarray(0, n);
}

/** How many of a connection's messages Send to Replay takes. */
export const HANDOFF_MAX = 20;

/**
 * A connection's Send to Replay: the first text and binary messages it sent (each list as
 * `ws messages --opcode` gives it, oldest first), in order, at most [HANDOFF_MAX] in all.
 * Throws when one of them was cut short.
 */
export function connectionMessages(text: WsMessage[], binary: WsMessage[]): WsOut[] {
  const items = [...text, ...binary].sort((a, b) => a.id! - b.id!).slice(0, HANDOFF_MAX);
  items.forEach((m) => requireWhole(m.payload, `Message #${m.id}`));
  return items.map(replayMessage);
}

/** A payload's start for a table row: a binary message as hex, whatever its bytes are. */
export function payloadPreview(m: Pick<WsMessage, "opcode" | "payload" | "length">, max: number): string {
  if (m.opcode === "binary") {
    // Hex then the printable ASCII, so JSON or text sent in binary frames still reads.
    const bytes = payloadPrefix(m.payload, Math.floor(max / 4));
    const hex = toHex(bytes).replace(/\n/g, " ");
    const ascii = Array.from(bytes, (b) => (b >= 32 && b < 127 ? String.fromCharCode(b) : ".")).join("");
    const length = m.length ?? m.payload.length ?? bytes.length;
    const more = length > bytes.length ? "…" : "";
    return `(${length} bytes) ${hex}${more && " …"}  ${ascii}${more}`;
  }
  const t = isBinary(m.payload) ? `(binary, ${m.payload.length ?? "?"} bytes)` : bodyText(m.payload);
  return t.length > max ? t.slice(0, max) + "…" : t;
}

/** `ws send` arguments; the handshake and messages go on stdin (see `wsSendInput`), out of the process list. */
export function wsSendArgs(o: { target: string; wait: number; until?: string; options?: Partial<ReplayOptions> }): string[] {
  return [
    "ws",
    "send",
    `--target=${o.target}`,
    "--wait",
    String(o.wait),
    ...(o.until ? [`--until=${o.until}`] : []),
    ...optionArgs(o.options, "ws"),
    "--input-json",
    "--max-body=2000000",
  ];
}

/** Stdin for `ws send --input-json`; throws naming a binary message that doesn't decode. */
export function wsSendInput(handshake: string, messages: WsOut[]): string {
  return JSON.stringify({ handshake, messages: wsInputMessages(messages) });
}

export const arrow = (d: WsMessage["direction"]) => (d === "to-server" ? "→" : "←");

/** ws(s)://host/path → http(s)://host, the origin the handshake goes to. */
export function wsOrigin(url: string): string {
  try {
    const u = new URL(url.replace(/^ws(s?):/, "http$1:"));
    return u.origin;
  } catch {
    return "";
  }
}

export const BLANK_HANDSHAKE =
  "GET / HTTP/1.1\nHost: \nUpgrade: websocket\nConnection: Upgrade\nSec-WebSocket-Version: 13\nSec-WebSocket-Key: (replaced when sent)\n\n";
