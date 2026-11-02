// WebSocket shapes from the CLI (`ws list`, `ws messages`, `ws send`) and the helpers the
// WebSockets tab and Replay's WebSocket mode share.

import type { Body } from "../api";
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

/** The line that separates messages in Replay's message box. */
export const SEPARATOR = "---";

/** Messages typed in Replay, one per block between lines holding only `---`. Blank blocks are skipped. */
export function splitMessages(text: string): string[] {
  const out: string[] = [];
  let cur: string[] = [];
  const flush = () => {
    const m = cur.join("\n");
    if (m.trim()) out.push(m);
    cur = [];
  };
  for (const line of text.replace(/\r\n/g, "\n").split("\n")) {
    if (line.trim() === SEPARATOR) flush();
    else cur.push(line);
  }
  flush();
  return out;
}

export function joinMessages(messages: string[]): string {
  return messages.join(`\n${SEPARATOR}\n`);
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

/** Stdin for `ws send --input-json`. */
export function wsSendInput(handshake: string, messages: string[]): string {
  return JSON.stringify({ handshake, messages });
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
