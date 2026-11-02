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

export const isRefused = (r: HistoryItem) => !!r.error?.startsWith("out of scope");

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

/** The saved filter equal to `f`, if any (to show which one is applied). */
export function savedMatching(list: SavedFilter[], f: TrafficFilter): string | null {
  const key = (x: TrafficFilter) => JSON.stringify({ ...parseFilter(x), sources: [...x.sources].sort() });
  return list.find((s) => key(s.filter) === key(f))?.name ?? null;
}

// ---------------- Contents search ----------------

/** Rows per `history list --contains` call. */
export const SEARCH_PAGE = 2000;
/** A search stops after this many matches (oldest first); the rest needs a narrower search. */
export const MAX_MATCHES = 10000;

export interface ContentSearch {
  query: string;
  /** Passed as --source (when the filter picks exactly one source). */
  source: string | null;
  matches: Set<number>;
  /** Every match with an id up to here is in `matches`. */
  cursor: number;
  /** Stopped at MAX_MATCHES: rows after `cursor` aren't searched. */
  capped: boolean;
  error: string | null;
}

/** The search a filter asks for, or null when the contents search is off or has no text. */
export function searchFor(f: TrafficFilter): { query: string; source: string | null } | null {
  if (!f.contents || !f.text) return null;
  return { query: f.text, source: f.sources.length === 1 ? f.sources[0] : null };
}

export const newSearch = (query: string, source: string | null): ContentSearch => ({
  query,
  source,
  matches: new Set(),
  cursor: 0,
  capped: false,
  error: null,
});

/** Whether `s` is the search the filter asks for (else its matches belong to an older query). */
export const isCurrent = (s: ContentSearch | null, f: TrafficFilter): s is ContentSearch => {
  const want = searchFor(f);
  return !!s && !!want && s.query === want.query && s.source === want.source;
};

/** `history list` arguments for the next page of a search. */
export function searchArgs(s: ContentSearch): string[] {
  return [
    "history",
    "list",
    `--contains=${s.query}`,
    ...(s.source ? [`--source=${s.source}`] : []),
    `--after=${s.cursor}`,
    `--limit=${SEARCH_PAGE}`,
  ];
}

/** Whether rows up to `upTo` (the newest id the poll has) still need searching. */
export const needsSearch = (s: ContentSearch, upTo: number) => !s.capped && !s.error && s.cursor < upTo;

/**
 * The search after one page of results. `upTo` is the newest polled id, read before the call:
 * a short page means every match up to it (and up to the last match) is known; a full page
 * covers ids up to its last row only, so the next page starts there. A match past MAX_MATCHES
 * stops the search.
 */
export function mergePage(s: ContentSearch, items: HistoryItem[], upTo: number): ContentSearch {
  const matches = new Set(s.matches);
  let cursor = s.cursor;
  let capped = false;
  for (const i of items) {
    if (i.id <= s.cursor) continue;
    if (matches.size >= MAX_MATCHES) {
      capped = true;
      break;
    }
    matches.add(i.id);
    cursor = Math.max(cursor, i.id);
  }
  if (!capped && items.length < SEARCH_PAGE) cursor = Math.max(cursor, upTo);
  return { ...s, matches, cursor, capped };
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
  if (s.error) return `Search failed: ${s.error}`;
  if (s.capped) return `Stopped at the first ${MAX_MATCHES.toLocaleString("en-US")} matches (up to #${s.cursor}); narrow the search to see later ones`;
  if (needsSearch(s, upTo)) return "Searching…";
  return "";
}
