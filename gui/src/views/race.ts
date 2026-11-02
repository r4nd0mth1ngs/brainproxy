// Replay's Race: `send --race N` with the tab's request, and its results. No DOM, so it can be
// tested on its own (race.test.ts).

import { autoEncodeRequest } from "../ui/urlencode.ts";

/** One request of a race, as `send --race` returns it: a response, or why it failed. */
export type RaceItem =
  | { id: number | null; status: number | null; length: number | null; duration_ms: number }
  | { error: string; kind: string };

export interface RaceResult {
  race: number;
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

export function raceMax(raw: string): number {
  return isHttp2Request(raw) ? RACE_MAX_HTTP2 : RACE_MAX;
}

/** The count typed in, or null when it isn't a whole number the CLI accepts for this request. */
export function parseRaceCount(text: string, raw: string): number | null {
  if (!/^\s*\d+\s*$/.test(text)) return null;
  const n = Number(text);
  return n >= RACE_MIN && n <= raceMax(raw) ? n : null;
}

/** The CLI call: the same as Replay's Send, plus --race. */
export function raceArgs(target: string, n: number): string[] {
  return ["send", `--target=${target}`, `--race=${n}`, "-"];
}

/** The technique in words. */
export function techniqueLabel(sync: string): string {
  if (sync === "single-packet") return "single-packet attack (HTTP/2)";
  if (sync === "last-byte") return "last-byte sync (HTTP/1.1)";
  return sync;
}

/** What `send` will use for this request, before racing. */
export function plannedTechnique(raw: string): string {
  return techniqueLabel(isHttp2Request(raw) ? "single-packet" : "last-byte");
}

export const isRaceError = (r: RaceItem): r is { error: string; kind: string } => "error" in r;

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
  /** Status, length, or error differs from the first request's. */
  differs: boolean;
}

export function raceRows(r: RaceResult): RaceRow[] {
  const first = r.results[0] ? shapeOf(r.results[0]) : "";
  return r.results.map((item, idx) =>
    isRaceError(item)
      ? { idx, id: null, status: null, length: null, duration_ms: null, error: item.error, differs: shapeOf(item) !== first }
      : { idx, id: item.id, status: item.status, length: item.length, duration_ms: item.duration_ms, error: null, differs: shapeOf(item) !== first },
  );
}

export interface RaceSummary {
  responses: number;
  errors: number;
  /** Slowest minus fastest response time (ms since the release), or null without responses. */
  spread: number | null;
  fastest: number | null;
  slowest: number | null;
  /** Requests whose status, length or error differs from the first's. */
  differing: number;
  distinct: number;
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
  };
}

/** A note when a single-packet race couldn't put every final frame in the one packet. */
export function syncNote(r: RaceResult): string | null {
  if (r.sync !== "single-packet" || r.synced == null || r.synced >= r.results.length) return null;
  return `${r.synced} of ${r.results.length} final frames went in the single packet; the rest were sent separately`;
}

/** The row to open first: the first request with a recorded response. */
export function firstOpenable(rows: RaceRow[]): number | null {
  return rows.find((x) => x.id != null)?.idx ?? null;
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
