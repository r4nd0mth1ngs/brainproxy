// Traffic rows written before their request went out. send, race, fuzz, scan, crawl and authz
// record each row first and complete it when the answer comes, but the Traffic poll reads only
// ids it hasn't seen, so such a row is read again by id until it is complete.

import type { HistoryItem } from "../api";

/** The error of a row whose request went out and isn't answered yet (crates/core/src/sent.rs
 * `PENDING`). A row kept without content (`--no-store`) has it at the end of its error. */
export const PENDING = "sent; no response recorded (cancelled or interrupted)";

/**
 * How long a row may stay pending and still be waited for. A command that was killed (the app's
 * Stop on Windows) or crashed leaves its rows pending for good, and re-reading those on every
 * poll would never end. No request waits longer than a day (`--timeout` takes up to that).
 */
export const PENDING_FOR_MS = 24 * 60 * 60 * 1000;

/**
 * A row pending longer than this is asked about only once every SLOW_EVERY_MS: most requests are
 * answered within it, and one still waiting after it was more likely left by a killed command.
 */
export const SLOW_AFTER_MS = 2 * 60 * 1000;
export const SLOW_EVERY_MS = 60 * 1000;

/** Terms one `--filter` query takes (crates/core/src/filter.rs `MAX_TERMS`). */
const PER_QUERY = 64;

/** The rows waited for: each pending id with when it was recorded (ms). */
export type Pending = Map<number, number>;

/** Whether a row is waiting for its response, and recent enough that the answer may still come. */
export function isPending(r: Pick<HistoryItem, "status" | "error" | "time">, now: number): boolean {
  if (r.status != null || !r.error?.endsWith(PENDING)) return false;
  const t = Date.parse(r.time);
  return Number.isFinite(t) && now - t <= PENDING_FOR_MS;
}

export const pendingIds = (items: HistoryItem[], now: number): number[] => items.filter((r) => isPending(r, now)).map((r) => r.id);

/** `pending` with the pending rows of `items` added. */
export function withPending(pending: Pending, items: HistoryItem[], now: number): Pending {
  const next = new Map(pending);
  for (const r of items) if (isPending(r, now)) next.set(r.id, Date.parse(r.time));
  return next;
}

/** The pending ids to read again now: the recent ones on every poll, older ones only when `slow`. */
export const dueIds = (pending: Pending, now: number, slow: boolean): number[] =>
  [...pending].filter(([, t]) => slow || now - t < SLOW_AFTER_MS).map(([id]) => id);

/** `history list` calls that read these rows again, a filter's worth of ids each. */
export function recheckCalls(ids: Iterable<number>): { ids: number[]; args: string[] }[] {
  const sorted = [...new Set(ids)].sort((a, b) => a - b);
  const out: { ids: number[]; args: string[] }[] = [];
  for (let i = 0; i < sorted.length; i += PER_QUERY) {
    const chunk = sorted.slice(i, i + PER_QUERY);
    const filter = chunk.map((id) => `id=${id}`).join(" OR ");
    out.push({ ids: chunk, args: ["history", "list", "--after", String(chunk[0] - 1), "--filter", filter, "--limit", String(chunk.length)] });
  }
  return out;
}

/**
 * The rows with those read again in their place. The note and tags stay as shown: completing a
 * row never changes them, and an edit made here may have landed after this read started.
 */
export function mergeRechecked(rows: HistoryItem[], fresh: HistoryItem[]): HistoryItem[] {
  if (!fresh.length) return rows;
  const byId = new Map(fresh.map((r) => [r.id, r]));
  let changed = false;
  const out = rows.map((r) => {
    const f = byId.get(r.id);
    if (!f) return r;
    const merged = { ...f, note: r.note, tags: r.tags };
    // A row still pending reads the same every time: kept as it is, so the table (sorting and
    // filtering every row) isn't redrawn on each poll for nothing.
    if (sameRow(merged, r)) return r;
    changed = true;
    return merged;
  });
  return changed ? out : rows;
}

const sameRow = (a: HistoryItem, b: HistoryItem) => {
  const keys = new Set([...Object.keys(a), ...Object.keys(b)]) as Set<keyof HistoryItem>;
  return [...keys].every((k) => JSON.stringify(a[k]) === JSON.stringify(b[k]));
};

/**
 * The pending ids after one recheck: those asked about that are still pending stay, those
 * answered (or gone) are dropped, and ids that weren't asked about are kept.
 */
export function stillPending(pending: Pending, asked: number[], fresh: HistoryItem[], now: number): Pending {
  const ask = new Set(asked);
  const next = new Map([...pending].filter(([id]) => !ask.has(id)));
  return withPending(next, fresh.filter((r) => ask.has(r.id)), now);
}
