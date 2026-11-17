// The Findings view's list, read in pages (`findings list --all --offset --limit`), so a large
// project isn't cut silently at one call's limit. Kept apart from the view so it can be tested
// without a window.

import type { FindingItem } from "../api.ts";

/** Findings per `findings list` call. */
export const PAGE = 5000;
/** Most findings the view holds; past this it says how many it left out. */
export const MAX_ROWS = 50_000;

/** What `findings list --all` answers. */
export interface ListPage {
  items: FindingItem[];
  /** Every finding that matches (a CLI from before paging leaves it out). */
  total?: number;
  /** More are left after this page. */
  truncated?: boolean;
}

/** The list as the view holds it. */
export interface Loaded {
  items: FindingItem[];
  total: number;
  /** Fewer are held than match: past MAX_ROWS. */
  truncated: boolean;
}

/** The command for one page of findings in `states`. */
export function pageArgs(states: string, offset: number, limit = PAGE): string[] {
  return ["findings", "list", "--all", "--state", states, "--limit", String(limit), "--offset", String(offset)];
}

/**
 * Every finding in `states`, page after page, up to `max`. A finding added between two pages
 * shifts the next one, so one may come twice: each is kept once.
 */
export async function loadAll(list: (args: string[]) => Promise<ListPage>, states: string, page = PAGE, max = MAX_ROWS): Promise<Loaded> {
  const byId = new Map<number, FindingItem>();
  let offset = 0;
  let total = 0;
  let full = false;
  for (;;) {
    const p = await list(pageArgs(states, offset, Math.min(page, max - byId.size)));
    for (const f of p.items) if (!byId.has(f.id)) byId.set(f.id, f);
    total = Math.max(p.total ?? 0, byId.size);
    full = byId.size >= max;
    if (!p.truncated || !p.items.length || full) break;
    offset += p.items.length;
  }
  // One added between pages (and so missed) comes with the next read: only the cap leaves some out.
  return { items: [...byId.values()], total, truncated: full && byId.size < total };
}

/** The toolbar's note when the list holds fewer findings than match, else "". */
export function heldNote(l: Loaded | null | undefined): string {
  if (!l?.truncated) return "";
  return `Showing ${l.items.length.toLocaleString("en")} of ${l.total.toLocaleString("en")} findings (the list holds at most ${MAX_ROWS.toLocaleString("en")})`;
}
