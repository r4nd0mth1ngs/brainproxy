// Replay tabs kept in the project file (`replay tabs list/save`), so they come back when it is
// opened again. Only what was typed is saved, never responses; text goes as typed, auth
// placeholders included. Saves are debounced, one at a time, and a failed one leaves the
// tabs in the app as they are.

import type { RepeaterTab } from "../store";

/** One tab as `replay tabs save` takes it. */
export interface SavedTab {
  kind: "http" | "ws";
  title: string;
  target: string;
  /** The raw request, or a WebSocket tab's handshake. */
  request: string;
  binary?: boolean;
  messages?: string[];
  wait?: number;
  until?: string;
}

export interface SavedTabs {
  tabs: SavedTab[];
  /** Index of the tab shown. */
  active?: number;
}

export const LIST_ARGS = ["replay", "tabs", "list"];
export const SAVE_ARGS = ["replay", "tabs", "save"];

/** The open tabs as saved: no keys, no responses. */
export function toSaved(tabs: RepeaterTab[], activeKey: number): SavedTabs {
  const saved = tabs.map((t): SavedTab => {
    const base = { title: t.title, target: t.target, request: t.raw };
    if (t.ws)
      return {
        kind: "ws",
        ...base,
        messages: t.ws,
        ...(t.wsWait != null ? { wait: t.wsWait } : {}),
        ...(t.wsUntil ? { until: t.wsUntil } : {}),
      };
    return { kind: "http", ...base, ...(t.binary ? { binary: true } : {}) };
  });
  const active = tabs.findIndex((t) => t.key === activeKey);
  return active >= 0 ? { tabs: saved, active } : { tabs: saved };
}

const str = (v: unknown): string => (typeof v === "string" ? v : "");

/**
 * Tabs from `replay tabs list`, with new keys. Anything that isn't a tab is skipped, so a set
 * saved by a newer version still opens. `activeKey` is null when none was saved.
 */
export function fromSaved(data: unknown, nextKey: () => number): { tabs: RepeaterTab[]; activeKey: number | null } {
  const d = (data ?? {}) as { tabs?: unknown; active?: unknown };
  const list = Array.isArray(d.tabs) ? d.tabs : [];
  const tabs: RepeaterTab[] = [];
  let activeKey: number | null = null;
  list.forEach((item, i) => {
    if (!item || typeof item !== "object" || typeof (item as SavedTab).request !== "string") return;
    const t = item as Partial<SavedTab>;
    const key = nextKey();
    const tab: RepeaterTab = { key, title: str(t.title) || String(tabs.length + 1), target: str(t.target), raw: str(t.request) };
    if (t.kind === "ws") {
      tab.ws = Array.isArray(t.messages) ? t.messages.filter((m): m is string => typeof m === "string") : [];
      if (typeof t.wait === "number" && t.wait >= 0) tab.wsWait = t.wait;
      if (t.until) tab.wsUntil = str(t.until);
    } else if (t.binary === true) tab.binary = true;
    tabs.push(tab);
    if (i === d.active) activeKey = key;
  });
  return { tabs, activeKey };
}

/**
 * Saves the latest body `delay` ms after the last change. One save runs at a time and later
 * changes wait for it; the last body saved isn't sent again. `onError` hears each new
 * failure once (not every retry of the same one), `onSaved` each success.
 */
export function saver(o: {
  save: (body: string) => Promise<unknown>;
  delay: number;
  onError: (e: Error) => void;
  onSaved?: () => void;
}) {
  let pending: string | null = null;
  let saved: string | null = null;
  let lastError = "";
  let timer: ReturnType<typeof setTimeout> | null = null;
  let running: Promise<void> | null = null;

  const write = async (body: string) => {
    try {
      await o.save(body);
      saved = body;
      lastError = "";
      o.onSaved?.();
    } catch (e: any) {
      // Kept for the next try (another change, or the flush on close).
      if (pending == null) pending = body;
      const err = e instanceof Error ? e : new Error(String(e));
      if (err.message !== lastError) o.onError(err);
      lastError = err.message;
    }
  };

  const flush = async (): Promise<void> => {
    if (timer) clearTimeout(timer);
    timer = null;
    // Another flush may be writing: wait for it, then save whatever came in meanwhile.
    while (running) await running;
    const body = pending;
    pending = null;
    if (body == null || body === saved) return;
    running = write(body).finally(() => (running = null));
    await running;
  };

  return {
    /** The tabs changed: save `body` once they stay unchanged for `delay` ms. */
    schedule(body: string) {
      if (body === saved && pending == null) return;
      pending = body;
      if (timer) clearTimeout(timer);
      timer = setTimeout(() => void flush(), o.delay);
    },
    /** Saves what is waiting now (the project or the window is closing). */
    flush,
    /** Marks `body` as what the project holds, e.g. the set just loaded, so it isn't saved back. */
    loaded(body: string) {
      saved = body;
    },
    /** Stops a waiting save without running it. */
    cancel() {
      if (timer) clearTimeout(timer);
      timer = null;
      pending = null;
    },
  };
}
