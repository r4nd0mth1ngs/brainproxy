// Replay's Send in order: `send --sequence single|separate --also FILE...` with a group of tabs,
// each tab then showing its own request's result. No DOM, so it can be tested on its own
// (sequence.test.ts).

import type { HistoryEntry } from "../api.ts";
import { optionArgs, sendsAsTyped, type ReplayOptions } from "./replayOptions.ts";

/** How the group's requests are carried: one keep-alive connection, or a new one each. */
export type Connections = "single" | "separate";

export const CONNECTIONS: Connections[] = ["single", "separate"];

/** One request of a sequence, as `send --sequence` lists it, in the order sent. */
export type SequenceItem = { request: number; request_line: string } & (
  | ({ outcome: "answered" } & Pick<HistoryEntry, "id" | "url" | "duration_ms" | "response">)
  | { outcome: "failed"; id: number | null; error: string; kind: string }
  | { outcome: "not_sent" }
);

export interface SequenceResult {
  sequence: Connections;
  /** Every row the sequence recorded is tagged `sequence:<sequence_id>`. */
  sequence_id: string;
  target: string;
  http2: boolean;
  /** Connections opened. */
  connections: number;
  total: number;
  answered: number;
  complete: boolean;
  /**
   * Where and why it stopped early: request `request` failed ("failed"), wasn't sent because the
   * connection ended after the one before it ("closed"), or was going out when the user stopped
   * the group ("cancelled").
   */
  stopped: { request: number; cause: "failed" | "closed" | "cancelled"; reason: string } | null;
  results: SequenceItem[];
  /** The target has platform credentials, which a sequence (like a race) doesn't answer. */
  platform_auth_warning?: string;
}

/** The connection choice in words. */
export function connectionsLabel(c: Connections): string {
  return c === "single" ? "one connection" : "separate connections";
}

/** A stored choice, or one connection (Burp's and Caido's default for a sequence). */
export function parseConnections(text: string | null): Connections {
  return text === "separate" ? "separate" : "single";
}

/**
 * The CLI call: Replay's Send with the active tab's options (HTTP/2, as typed, SNI, timeout,
 * Verify TLS, Don't record), plus --sequence and one `--also` per other tab. The other tabs'
 * requests are staged privately by the shell; only file names enter argv.
 */
export function sequenceArgs(target: string, connections: Connections, additional: number, options?: Partial<ReplayOptions>): string[] {
  // A sequence goes over TCP: send refuses --http3 with it, and "as typed", which the tab shows
  // off while HTTP/3 is on, stays off.
  const tcp = { ...options, http3: false, verbatim: sendsAsTyped(options) };
  const also = Array.from({ length: additional }, (_, i) => `--also=@request:${i}`);
  return ["send", `--target=${target}`, `--sequence=${connections}`, ...optionArgs(tcp, "http"), ...also, "-"];
}

/** What one tab shows of the sequence: its response, or why it has none. */
export interface TabOutcome {
  result: Pick<HistoryEntry, "id" | "url" | "duration_ms" | "response"> | null;
  error: string | null;
}

/**
 * The part of the sequence of the tab sent `index`th (from 0, in the order sent). `titles` names
 * the group's tabs in that order, for saying where the sequence stopped; `stopped` is what to say
 * for the request that was going out when the user stopped the group. Null when the result has
 * no item for it.
 */
export function tabOutcome(r: SequenceResult, index: number, titles: string[], stopped?: string): TabOutcome | null {
  const item = r.results.find((x) => x.request === index);
  if (!item) return null;
  if (item.outcome === "answered") {
    const { id, url, duration_ms, response } = item;
    return { result: { id, url, duration_ms, response }, error: null };
  }
  if (item.outcome === "failed") return { result: null, error: r.stopped?.cause === "cancelled" && stopped ? stopped : item.error };
  return { result: null, error: `Not sent: ${stopText(r, titles) ?? "the sequence stopped before it"}` };
}

/**
 * Where and why the sequence stopped, naming tabs by `titles` (in the order sent), or null when it
 * didn't stop early.
 */
export function stopText(r: SequenceResult, titles: string[]): string | null {
  const s = r.stopped;
  if (!s) return null;
  const name = (i: number) => (titles[i] != null ? `“${titles[i]}”` : `request ${i + 1}`);
  if (s.cause === "closed") return `the connection ended after ${name(s.request - 1)} (${s.reason})`;
  if (s.cause === "cancelled") return `stopped at ${name(s.request)}`;
  return `${name(s.request)} failed (${s.reason})`;
}

/** The sequence in a few words, for the toolbar: where this tab was in it, and how it went. */
export function sequenceTag(r: SequenceResult, index: number): string {
  const over = r.sequence === "single" ? `one${r.http2 ? " HTTP/2" : ""} connection` : `${r.connections} connections`;
  return `in order ${index + 1}/${r.total} · ${over}`;
}

/** A line for the toolbar's tooltip: how far the sequence got. */
export function sequenceSummary(r: SequenceResult): string {
  const got = r.complete ? `All ${r.total} answered` : `${r.answered} of ${r.total} answered`;
  return `${got}, ${connectionsLabel(r.sequence)} (${r.connections} opened). History rows tagged sequence:${r.sequence_id}`;
}

/** What a group needs before it can be sent in order: at least two tabs. */
export function sequenceProblem(tabs: number): string | null {
  return tabs < 2 ? "Tick the checkbox of at least one other HTTP tab to send a group in order" : null;
}
