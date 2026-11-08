// Replay's Race: `send --race N [--also FILE]` with the tabs' requests and results. No DOM, so it can be
// tested on its own (race.test.ts).

import { autoEncodeRequest } from "../ui/urlencode.ts";
import { optionArgs, type ReplayOptions } from "./replayOptions.ts";

/**
 * One request of a race, as `send --race` returns it: a response, or why it failed. `id` is the
 * history row that records either (null with --no-store).
 */
export type RaceItem = { request?: number; request_line?: string } & (
  | { id: number | null; status: number | null; length: number | null; duration_ms: number }
  | { id?: number | null; error: string; kind: string }
);

export interface RaceResult {
  race: number;
  total?: number;
  requests?: { index: number; request_line: string }[];
  /** Every row the race recorded is tagged `race:<race_id>`. */
  race_id?: string;
  /** The technique: "last-byte" (HTTP/1.1) or "single-packet" (HTTP/2). */
  sync: string;
  /** Single-packet only: final frames that went out in the one write. */
  synced: number | null;
  target: string;
  distinct_responses: Record<string, number>;
  results: RaceItem[];
}

/** A race needs two requests; the CLI takes up to 1000, or 100 for a single-packet race. */
export const RACE_MIN = 2;
export const RACE_MAX = 1000;
export const RACE_MAX_HTTP2 = 100;

/**
 * Whether the request line says HTTP/2, which makes `send` (and so the race) use HTTP/2. Reads
 * the line as the CLI does: the version is everything after the second space, and only exactly
 * "HTTP/2" (any case) counts, so "GET  / HTTP/2" or a trailing space means HTTP/1.1.
 */
export function isHttp2Request(raw: string): boolean {
  const line = raw.split("\n", 1)[0].replace(/\r$/, "");
  const a = line.indexOf(" ");
  if (a <= 0) return false; // no method: the CLI refuses the request
  const b = line.indexOf(" ", a + 1);
  return b >= 0 && /^HTTP\/2$/i.test(line.slice(b + 1));
}

/** The request line as Replay will send it: auto URL-encoding can move where the version starts. */
export function sentRequestLine(raw: string, autoEncode: boolean): string {
  const line = raw.split("\n", 1)[0].replace(/\r$/, "");
  return autoEncode ? autoEncodeRequest(line).text : line;
}

/**
 * Whether the race goes over HTTP/2 (single-packet): the tab's HTTP/2 option (`--http2`) or a
 * request line saying so, as `send` decides.
 */
export function racesHttp2(raw: string, http2 = false): boolean {
  return http2 || isHttp2Request(raw);
}

export function raceMax(raw: string, http2 = false): number {
  return racesHttp2(raw, http2) ? RACE_MAX_HTTP2 : RACE_MAX;
}

/** The count typed in, or null when it isn't a whole number the CLI accepts for this request. */
export function parseRaceCount(text: string, raw: string, http2 = false): number | null {
  if (!/^\s*\d+\s*$/.test(text)) return null;
  const n = Number(text);
  return n >= RACE_MIN && n <= raceMax(raw, http2) ? n : null;
}

/**
 * The CLI call: the same as Replay's Send, with the tab's options (HTTP/2, as typed, SNI,
 * timeout, Verify TLS, Don't record), plus --race.
 */
export function raceArgs(target: string, n: number, options?: Partial<ReplayOptions>): string[] {
  return ["send", `--target=${target}`, `--race=${n}`, ...optionArgs(options, "http"), "-"];
}

/** The technique in words. */
export function techniqueLabel(sync: string): string {
  if (sync === "single-packet") return "single-packet attack (HTTP/2)";
  if (sync === "last-byte") return "last-byte sync (HTTP/1.1)";
  return sync;
}

/** What `send` will use for this request, before racing. */
export function plannedTechnique(raw: string, http2 = false): string {
  return techniqueLabel(racesHttp2(raw, http2) ? "single-packet" : "last-byte");
}

export const isRaceError = (r: RaceItem): r is { id?: number | null; error: string; kind: string } => "error" in r;

/** What two responses are compared by: status and length, or the kind of error. */
export function shapeOf(r: RaceItem): string {
  return isRaceError(r) ? `error: ${r.kind}` : `${r.status ?? "?"} ${r.length ?? "?"}`;
}

export interface RaceRow {
  /** Position in the race, from 0. */
  idx: number;
  id: number | null;
  status: number | null;
  length: number | null;
  duration_ms: number | null;
  error: string | null;
  /** Status, length, or error differs from the most common response's (see baselineOf). */
  differs: boolean;
}

/**
 * The request the others are compared with: the first of the most common responses (status and
 * length). A failure is no response, so it only counts when nothing came back; then it's the
 * most common kind of error. Null for an empty race.
 */
export function baselineOf(results: RaceItem[]): number | null {
  const pick = (only: (r: RaceItem) => boolean): number | null => {
    const counts = new Map<string, { first: number; n: number }>();
    results.forEach((r, i) => {
      if (!only(r)) return;
      const c = counts.get(shapeOf(r));
      if (c) c.n++;
      else counts.set(shapeOf(r), { first: i, n: 1 });
    });
    let best: { first: number; n: number } | null = null;
    for (const c of counts.values()) if (!best || c.n > best.n) best = c; // ties: the earliest
    return best?.first ?? null;
  };
  return pick((r) => !isRaceError(r)) ?? pick(() => true);
}

/** The baseline in words, for the toolbar. */
export function shapeLabel(r: RaceItem): string {
  return isRaceError(r) ? `error: ${r.kind}` : `${r.status ?? "no status"}, ${r.length ?? "?"} bytes`;
}

export function raceRows(r: RaceResult): RaceRow[] {
  const at = baselineOf(r.results);
  const base = at == null ? "" : shapeOf(r.results[at]);
  return r.results.map((item, idx) =>
    isRaceError(item)
      ? { idx, id: item.id ?? null, status: null, length: null, duration_ms: null, error: item.error, differs: shapeOf(item) !== base }
      : { idx, id: item.id, status: item.status, length: item.length, duration_ms: item.duration_ms, error: null, differs: shapeOf(item) !== base },
  );
}

export interface RaceSummary {
  responses: number;
  errors: number;
  /** Slowest minus fastest response time (ms since the release), or null without responses. */
  spread: number | null;
  fastest: number | null;
  slowest: number | null;
  /** Requests whose status, length or error differs from the most common response's. */
  differing: number;
  distinct: number;
  /** The request the others are compared with (see baselineOf). */
  baseline: number | null;
}

export function raceSummary(r: RaceResult): RaceSummary {
  const rows = raceRows(r);
  const times = rows.flatMap((x) => (x.duration_ms == null ? [] : [x.duration_ms]));
  const fastest = times.length ? Math.min(...times) : null;
  const slowest = times.length ? Math.max(...times) : null;
  return {
    responses: times.length,
    errors: rows.filter((x) => x.error != null).length,
    spread: fastest == null || slowest == null ? null : slowest - fastest,
    fastest,
    slowest,
    differing: rows.filter((x) => x.differs).length,
    distinct: new Set(r.results.map(shapeOf)).size,
    baseline: baselineOf(r.results),
  };
}

/** A note when a single-packet race couldn't put every final frame in the one packet. */
export function syncNote(r: RaceResult): string | null {
  if (r.sync !== "single-packet" || r.synced == null || r.synced >= (r.total ?? r.results.length)) return null;
  return `${r.synced} of ${r.total ?? r.results.length} final frames went in the single packet; the rest were sent separately`;
}

/** Whether a row has a recorded response to open with `history show` (a failure has only its error). */
export const openable = (x: RaceRow): boolean => x.id != null && x.error == null;

/** The row to open first: the first request with a recorded response. */
export function firstOpenable(rows: RaceRow[]): number | null {
  return rows.find(openable)?.idx ?? null;
}

/** What Replay keeps per race: its results and the response open in the response pane. */
export interface Raced {
  result: RaceResult;
  open: number | null;
}

/**
 * Applies `patch` to the entry holding this race, but only while response `idx` is still the one
 * open in it: a response that comes back after the user opened another one is dropped.
 */
export function patchOpen<T extends { race?: Raced }>(list: T[], result: RaceResult, idx: number, patch: Partial<T>): T[] {
  return list.map((e) => (e.race?.result === result && e.race.open === idx ? { ...e, ...patch } : e));
}

/** Additional requests are staged privately by the shell; only file paths enter argv. */
export function raceGroupArgs(target: string, n: number, additional: number, options?: Partial<ReplayOptions>): string[] {
  const args = raceArgs(target, n, options);
  args.splice(args.length - 1, 0, ...Array.from({ length: additional }, (_, i) => `--also=@request:${i}`));
  return args;
}

/** Counts are per member; HTTP/2 on any member puts the entire group on one connection. */
export function groupRaceMax(raw: string[], http2 = false): number {
  const limit = raw.some((r) => racesHttp2(r, http2)) ? RACE_MAX_HTTP2 : RACE_MAX;
  return Math.floor(limit / Math.max(1, raw.length));
}

export function parseGroupRaceCount(text: string, raw: string[], http2 = false): number | null {
  if (!/^\s*\d+\s*$/.test(text)) return null;
  const n = Number(text);
  return n >= (raw.length > 1 ? 1 : RACE_MIN) && n <= groupRaceMax(raw, http2) ? n : null;
}

/** One tab's results, so comparisons and response selection stay within that request. */
export function raceResultForRequest(result: RaceResult, request: number): RaceResult {
  const results = result.results.filter((r) => (r.request ?? 0) === request);
  const distinct: Record<string, number> = {};
  for (const item of results) {
    const key = isRaceError(item) ? `error: ${item.kind}` : `${item.status ?? 0} ${item.length ?? 0}B`;
    distinct[key] = (distinct[key] ?? 0) + 1;
  }
  return { ...result, results, distinct_responses: distinct };
}
