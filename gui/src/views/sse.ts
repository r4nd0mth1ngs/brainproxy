// Server-sent event shapes from the CLI (`sse list`, `sse events`, `send`) and the helpers the
// Event streams tab and Replay share.

import type { Body } from "../api";

/** The most body bytes one stream stores (`sse::MAX_STREAM_BYTES`): no event's data is longer. */
export const MAX_STREAM_BYTES = 4 * 1024 * 1024;

export interface SseStream {
  id: number;
  time: string;
  source: string;
  history_id: number | null;
  url: string;
  host: string;
  state: "open" | "closed";
  closed_time: string | null;
  events: number;
  /** The stream went over what one may store: what came after isn't in the project. */
  truncated: boolean;
  ended: string | null;
  error: string | null;
}

export interface SseEvent {
  /** Null for an event `send` just read, not listed from the project. */
  id: number | null;
  stream_id?: number;
  time: string;
  event: string;
  event_id: string | null;
  /** Null for a block without a data line, which a browser dispatches no event for. */
  data: Body | null;
  retry: number | null;
  length?: number;
}

/** What `send` says of an event stream it read. */
export interface SseRead {
  stream_id: number | null;
  stopped: "closed" | "wait" | "max-events" | "cap" | "error";
  truncated: boolean;
  note: string | null;
  count: number;
  events: SseEvent[];
}

const ENDED: Record<string, string> = {
  server: "ended by the server",
  client: "the client went away",
  stopped: "reading stopped",
  error: "ended by an error",
};

/** The Note column: that the stream was cut at the cap comes first, then how it ended and why. */
export function streamNote(s: Pick<SseStream, "state" | "truncated" | "ended" | "error">): string {
  const parts: string[] = [];
  if (s.truncated) parts.push("TRUNCATED");
  if (s.state === "closed" && s.ended) parts.push(ENDED[s.ended] ?? s.ended);
  if (s.error) parts.push(s.error);
  return parts.join(" · ");
}

/** Events already shown with the ones a poll brought, each id once, in order (ids only grow). */
export function appendEvents(shown: SseEvent[], polled: SseEvent[]): SseEvent[] {
  const max = shown.length ? (shown[shown.length - 1].id ?? 0) : 0;
  const fresh = polled.filter((e) => (e.id ?? 0) > max);
  return fresh.length ? [...shown, ...fresh] : shown;
}

/** Replay's status for a response that was an event stream: why reading stopped. */
export function readSummary(r: Pick<SseRead, "count" | "stopped" | "truncated">): string {
  const why: Record<SseRead["stopped"], string> = {
    closed: "the server ended it",
    wait: "stopped after the wait",
    "max-events": "stopped at the event limit",
    cap: "stopped at what a stream may store",
    error: "reading failed",
  };
  return `event stream: ${r.count} event${r.count === 1 ? "" : "s"}, ${why[r.stopped] ?? r.stopped}${r.truncated ? " (truncated)" : ""}`;
}
