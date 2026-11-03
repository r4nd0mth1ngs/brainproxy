// Proxy › Traffic filters: the filter state, saved filters (per project, in localStorage), and
// the contents search, which asks the CLI (`history list --contains`) and keeps up with the
// rows the live poll adds.

import type { HistoryItem } from "../api";

export interface TrafficFilter {
  text: string;
  /** Search `text` inside requests and responses (the CLI) instead of URL, title and method. */
  contents: boolean;
  /** Empty: every source. */
  sources: string[];
  hideErrors: boolean;
  hideAssets: boolean;
  hideRefused: boolean;
}

// Refused requests (outside the engagement scope) are mostly browser background noise.
export const DEFAULT_FILTER: TrafficFilter = { text: "", contents: false, sources: [], hideErrors: false, hideAssets: false, hideRefused: true };

const ASSET = /\.(css|js|png|jpe?g|gif|svg|ico|woff2?|ttf|map)(\?|$)/i;

/** The proxy refused it (outside the engagement scope). */
export const isRefused = (r: { error?: string | null }) => !!r.error?.startsWith("out of scope");

/** Whether a row passes the filters checked here. The text counts only outside contents mode. */
export function matchesFilter(r: HistoryItem, f: TrafficFilter): boolean {
  const t = f.contents ? "" : f.text.toLowerCase();
  return (
    (!t || r.url.toLowerCase().includes(t) || (r.title ?? "").toLowerCase().includes(t) || r.method.toLowerCase() === t) &&
    (f.sources.length === 0 || f.sources.includes(r.source)) &&
    (!f.hideErrors || (r.status != null && r.status < 400)) &&
    (!f.hideAssets || !ASSET.test(r.url)) &&
    (!f.hideRefused || !isRefused(r))
  );
}

// ---------------- Saved filters ----------------

export interface SavedFilter {
  name: string;
  filter: TrafficFilter;
}

export const savedKey = (project: string) => `traffic-filters:${project}`;

/** A filter from stored JSON: unknown fields are dropped and missing ones take the defaults. */
export function parseFilter(v: unknown): TrafficFilter {
  const o = v && typeof v === "object" ? (v as Record<string, unknown>) : {};
  const bool = (k: keyof TrafficFilter) => (typeof o[k] === "boolean" ? (o[k] as boolean) : (DEFAULT_FILTER[k] as boolean));
  return {
    text: typeof o.text === "string" ? o.text : "",
    contents: bool("contents"),
    sources: Array.isArray(o.sources) ? [...new Set(o.sources.filter((s): s is string => typeof s === "string"))] : [],
    hideErrors: bool("hideErrors"),
    hideAssets: bool("hideAssets"),
    hideRefused: bool("hideRefused"),
  };
}

/** Saved filters from stored text; anything unreadable is skipped. */
export function parseSaved(text: string | null): SavedFilter[] {
  let v: unknown;
  try {
    v = JSON.parse(text ?? "[]");
  } catch {
    return [];
  }
  if (!Array.isArray(v)) return [];
  const out: SavedFilter[] = [];
  for (const s of v) {
    const name = typeof s?.name === "string" ? s.name.trim() : "";
    if (name && !out.some((o) => o.name === name)) out.push({ name, filter: parseFilter(s.filter) });
  }
  return out;
}

export function loadSaved(project: string): SavedFilter[] {
  try {
    return parseSaved(localStorage.getItem(savedKey(project)));
  } catch {
    return [];
  }
}

/** Stores the list for the project; false when storage is unavailable. */
export function storeSaved(project: string, list: SavedFilter[]): boolean {
  try {
    localStorage.setItem(savedKey(project), JSON.stringify(list));
    return true;
  } catch {
    return false;
  }
}

/** The list with `filter` saved as `name`: a filter with that name is replaced in place, a new one goes last. */
export function withSaved(list: SavedFilter[], name: string, filter: TrafficFilter): SavedFilter[] {
  const n = name.trim();
  if (!n) return list;
  const entry = { name: n, filter: parseFilter(filter) };
  return list.some((s) => s.name === n) ? list.map((s) => (s.name === n ? entry : s)) : [...list, entry];
}

export const withoutSaved = (list: SavedFilter[], name: string) => list.filter((s) => s.name !== name);

/** `f` in a fixed form (sources sorted, fields in order), to compare filters. */
function normal(f: TrafficFilter): TrafficFilter {
  const n = parseFilter(f);
  return { ...n, sources: n.sources.sort() };
}

const same = (a: TrafficFilter, b: TrafficFilter) => JSON.stringify(normal(a)) === JSON.stringify(normal(b));

/** The saved filter equal to `f`, if any (to show which one is applied). */
export function savedMatching(list: SavedFilter[], f: TrafficFilter): string | null {
  return list.find((s) => same(s.filter, f))?.name ?? null;
}

/**
 * The saved filter to show as applied: `picked` (the one last chosen or saved) while the filter
 * still equals it, so of two saved filters with the same state the chosen one is shown and
 * deleted; otherwise the first equal one.
 */
export function appliedSaved(list: SavedFilter[], f: TrafficFilter, picked: string | null): string | null {
  const p = picked == null ? undefined : list.find((s) => s.name === picked);
  return p && same(p.filter, f) ? p.name : savedMatching(list, f);
}

/**
 * Adds the saved filters of `from` to those of `to` (same name: `from` wins), for a temporary
 * engagement saved to a file. False when storage is unavailable.
 */
export function copySaved(from: string, to: string): boolean {
  const list = loadSaved(from);
  if (!list.length) return true;
  return storeSaved(to, list.reduce((acc, s) => withSaved(acc, s.name, s.filter), loadSaved(to)));
}

// ---------------- Contents search ----------------

/** Rows per `history list --contains` call. */
export const SEARCH_PAGE = 2000;
/** A search stops after this many matches (oldest first); the rest needs a narrower search. */
export const MAX_MATCHES = 10000;
/** After a failed page the next try waits this long, doubling per failure up to RETRY_MAX (ms). */
export const RETRY_BASE = 2000;
export const RETRY_MAX = 60000;

/** What the CLI is asked: the text for --contains and the one source for --source (null: all). */
export interface SearchQuery {
  text: string;
  source: string | null;
}

export interface ContentSearch {
  query: SearchQuery;
  /**
   * Every row the CLI matched up to `cursor`, whether the other filters show it or not, so
   * changing a checkbox needs no new search. The fields those filters use never change.
   */
  matches: Map<number, HistoryItem>;
  /** Every match with an id up to here is in `matches`. */
  cursor: number;
  /** Stopped at MAX_MATCHES shown matches: rows after `cursor` aren't searched. */
  capped: boolean;
  /** The last page failed; it is tried again from `retryAt` (ms, Date.now). */
  error: string | null;
  /** Pages failed in a row, for the backoff. */
  failures: number;
  retryAt: number;
}

/**
 * The search a filter asks for, or null when the contents search is off or its text is only
 * whitespace (it would match almost every row). Only the text and a single source are sent to
 * the CLI, so only they make a new search; the checkboxes are applied here (see refilter).
 */
export function searchFor(f: TrafficFilter): SearchQuery | null {
  if (!f.contents || !f.text.trim()) return null;
  return { text: f.text, source: f.sources.length === 1 ? f.sources[0] : null };
}

export const newSearch = (query: SearchQuery): ContentSearch => ({
  query: { ...query },
  matches: new Map(),
  cursor: 0,
  capped: false,
  error: null,
  failures: 0,
  retryAt: 0,
});

/** Whether `s` is the search the filter asks for (else its matches belong to an older query). */
export const isCurrent = (s: ContentSearch | null, f: TrafficFilter): s is ContentSearch => {
  const want = searchFor(f);
  return !!s && !!want && s.query.text === want.text && s.query.source === want.source;
};

/** `history list` arguments for the next page of a search. */
export function searchArgs(s: ContentSearch): string[] {
  const { text, source } = s.query;
  return ["history", "list", `--contains=${text}`, ...(source ? [`--source=${source}`] : []), `--after=${s.cursor}`, `--limit=${SEARCH_PAGE}`];
}

/**
 * Whether rows up to `upTo` (the newest id the poll has) still need searching. After a failure,
 * not before `retryAt`: the caller stops and a later poll tries again.
 */
export const needsSearch = (s: ContentSearch, upTo: number, now = Date.now()) => !s.capped && s.cursor < upTo && now >= s.retryAt;

/** How many of the search's matches `f` shows. */
export function shownMatches(s: ContentSearch, f: TrafficFilter): number {
  let n = 0;
  for (const i of s.matches.values()) if (matchesFilter(i, f)) n++;
  return n;
}

/**
 * The search after one page of results. `upTo` is the newest polled id, read before the call:
 * a short page means every match up to it (and up to the last match) is known; a full page
 * covers ids up to its last row only, so the next page starts there. Every match is kept, but
 * only those `f` shows count: a shown match past MAX_MATCHES stops the search.
 */
export function mergePage(s: ContentSearch, items: HistoryItem[], upTo: number, f: TrafficFilter): ContentSearch {
  const matches = new Map(s.matches);
  let shown = shownMatches(s, f);
  let cursor = s.cursor;
  let capped = false;
  for (const i of items) {
    if (i.id <= s.cursor) continue;
    if (matchesFilter(i, f)) {
      if (shown >= MAX_MATCHES) {
        capped = true;
        break;
      }
      shown++;
    }
    matches.set(i.id, i);
    cursor = Math.max(cursor, i.id);
  }
  if (!capped && items.length < SEARCH_PAGE) cursor = Math.max(cursor, upTo);
  return { ...s, matches, cursor, capped, error: null, failures: 0, retryAt: 0 };
}

/** The search after a failed page: it keeps its matches and waits longer after each failure. */
export function failPage(s: ContentSearch, error: string, now = Date.now()): ContentSearch {
  const failures = s.failures + 1;
  return { ...s, error, failures, retryAt: now + Math.min(RETRY_MAX, RETRY_BASE * 2 ** (failures - 1)) };
}

/**
 * The search with the cap worked out again for `f`, after a checkbox (or a second source)
 * changed: the matches stay, nothing is searched again. Capped, it carries on from its cursor
 * when `f` shows no more than MAX_MATCHES of them (the next shown match stops it again); when
 * `f` shows more, it stops before the first match past the cap. The same object when nothing
 * changes.
 */
export function refilter(s: ContentSearch, f: TrafficFilter): ContentSearch {
  const ids = [...s.matches.keys()].sort((a, b) => a - b);
  let shown = 0;
  for (const id of ids) {
    if (!matchesFilter(s.matches.get(id)!, f)) continue;
    if (shown === MAX_MATCHES) {
      const matches = new Map(ids.filter((x) => x < id).map((x) => [x, s.matches.get(x)!]));
      return { ...s, matches, cursor: id - 1, capped: true };
    }
    shown++;
  }
  return s.capped ? { ...s, capped: false } : s;
}

/**
 * The rows to show. In contents mode only rows the search matched, so polled rows it hasn't
 * searched yet stay hidden until it has; before the search for the current text has
 * answered, nothing.
 */
export function visibleRows(rows: HistoryItem[], f: TrafficFilter, s: ContentSearch | null): HistoryItem[] {
  if (searchFor(f)) {
    if (!isCurrent(s, f)) return [];
    return rows.filter((r) => s.matches.has(r.id) && matchesFilter(r, f));
  }
  return rows.filter((r) => matchesFilter(r, f));
}

/** A short status for the toolbar while contents search is on. */
export function searchNote(s: ContentSearch | null, upTo: number): string {
  if (!s) return "Searching…";
  if (s.error) return `Search failed (trying again): ${s.error}`;
  if (s.capped) return `Stopped at the first ${MAX_MATCHES.toLocaleString("en-US")} matches (up to #${s.cursor}); narrow the search or filters to see later ones`;
  if (needsSearch(s, upTo)) return "Searching…";
  return "";
}
