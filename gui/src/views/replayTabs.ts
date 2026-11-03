// Replay tabs kept in the project file (`replay tabs list/save`), so they come back when it is
// opened again. Only what was typed is saved, never responses; text goes as typed, auth
// placeholders included. Saves are debounced, one at a time, and a failed one leaves the
// tabs in the app as they are. Each save checks the set's revision, so tabs saved from
// elsewhere meanwhile (an agent's) are added to the app's rather than replaced.

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
  /** As listed: the set's revision (0 before the first save) and format. */
  rev?: number;
  v?: number;
}

export const LIST_ARGS = ["replay", "tabs", "list"];
export const SAVE_ARGS = ["replay", "tabs", "save"];
/** The revision only, without the requests: what a check for tabs saved elsewhere reads first. */
export const SUMMARY_ARGS = ["replay", "tabs", "list", "--summary"];
/** A save over the set at `rev`; one saved elsewhere since fails with a conflict. */
export const saveArgs = (rev: number) => [...SAVE_ARGS, "--if-revision", String(rev)];

/** The format this build reads and writes. A newer set has fields this one would drop. */
const FORMAT = 1;
/** Longest WebSocket Listen, in seconds (`ws send --wait` refuses more). */
export const MAX_WAIT = 86400;

export const NEWER = "they were saved by a newer brainproxy, so this one doesn't save over them; update it";

/** Whether `data` (a listing) was saved by a newer version, which this one mustn't save over. */
export function newerFormat(data: unknown): boolean {
  const v = (data as { v?: unknown } | null)?.v;
  return typeof v === "number" && v > FORMAT;
}

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
 * Tabs from `replay tabs list`, with new keys, untitled ones numbered from `firstNumber`.
 * Anything that isn't a tab is skipped, so a set saved by a newer version still opens.
 * `activeKey` is null when none was saved.
 */
export function fromSaved(data: unknown, nextKey: () => number, firstNumber = 1): { tabs: RepeaterTab[]; activeKey: number | null } {
  const d = (data ?? {}) as { tabs?: unknown; active?: unknown };
  const list = Array.isArray(d.tabs) ? d.tabs : [];
  const tabs: RepeaterTab[] = [];
  let activeKey: number | null = null;
  list.forEach((item, i) => {
    if (!item || typeof item !== "object" || typeof (item as SavedTab).request !== "string") return;
    const t = item as Partial<SavedTab>;
    // A kind this version doesn't know isn't opened as something else.
    if (t.kind !== undefined && t.kind !== "http" && t.kind !== "ws") return;
    const key = nextKey();
    const tab: RepeaterTab = { key, title: str(t.title) || String(tabs.length + firstNumber), target: str(t.target), raw: str(t.request) };
    if (t.kind === "ws") {
      tab.ws = Array.isArray(t.messages) ? t.messages.filter((m): m is string => typeof m === "string") : [];
      if (typeof t.wait === "number" && t.wait >= 0 && t.wait <= MAX_WAIT) tab.wsWait = t.wait;
      if (t.until) tab.wsUntil = str(t.until);
    } else if (t.binary === true) tab.binary = true;
    tabs.push(tab);
    if (i === d.active) activeKey = key;
  });
  return { tabs, activeKey };
}

/** Each saved tab as text, to tell the tabs of one set from another's (`body` is a save's stdin or a listing). */
export function tabTexts(body: string | unknown): string[] {
  const d = (typeof body === "string" ? JSON.parse(body) : body) as { tabs?: unknown } | null;
  return Array.isArray(d?.tabs) ? d.tabs.map((t) => JSON.stringify(t)) : [];
}

/**
 * The tabs of `data` (a listing) that weren't in the set last read or saved (`known`, from
 * [tabTexts]): saved from elsewhere since, by an agent or the command line. `now` is what
 * the project holds, the next `known`. Tabs the app closed stay closed, since they are in `known`.
 */
export function addedSince(known: string[], data: unknown, nextKey: () => number, firstNumber = 1): { added: RepeaterTab[]; now: string[] } {
  const left = new Map<string, number>();
  for (const k of known) left.set(k, (left.get(k) ?? 0) + 1);
  const now = tabTexts(data);
  const list = Array.isArray((data as { tabs?: unknown } | null)?.tabs) ? (data as { tabs: unknown[] }).tabs : [];
  const fresh = list.filter((_, i) => {
    const n = left.get(now[i]) ?? 0;
    if (n > 0) left.set(now[i], n - 1);
    return n === 0;
  });
  return { added: fromSaved({ tabs: fresh }, nextKey, firstNumber).tabs, now };
}

/** Runs the calls given one at a time, in order, whether the one before worked or not. */
export function serial() {
  let last: Promise<unknown> = Promise.resolve();
  return <T>(f: () => Promise<T>): Promise<T> => {
    const p = last.then(f);
    last = p.catch(() => {});
    return p;
  };
}

/**
 * The app's side of the saved set's revision: each save says which revision it replaces, so
 * one saved elsewhere meanwhile (an agent preparing tabs) is a conflict, not lost. Then the
 * tabs saved there are added to the app's (`add`) and the whole lot is saved. `cli` runs a
 * command with optional stdin and returns its data; `body` is the app's set now (after
 * `add`); `count` how many tabs are open, to number untitled ones.
 */
export function revisions(o: {
  cli: (args: string[], stdin?: string) => Promise<any>;
  body: () => string;
  add: (tabs: RepeaterTab[]) => void;
  count: () => number;
  nextKey: () => number;
}) {
  let rev = 0;
  let known: string[] = [];
  // A check and a save never interleave: each reads the revision the other sets.
  const one = serial();
  const take = (data: unknown) => {
    if (newerFormat(data)) throw new Error(NEWER);
    const r = addedSince(known, data, o.nextKey, o.count() + 1);
    rev = (data as SavedTabs).rev ?? 0;
    known = r.now;
    if (r.added.length) o.add(r.added);
  };
  return {
    /** The set read when the project opened. */
    loaded(data: unknown) {
      rev = (data as SavedTabs | null)?.rev ?? 0;
      known = tabTexts(data);
    },
    /** Saves `body`, or takes in tabs saved elsewhere since and saves them with the app's. Returns what it wrote. */
    save: (body: string) => {
      const seen = rev;
      return one(async () => {
        // A check queued before took in tabs meanwhile: `body` was made without them.
        if (rev !== seen) body = o.body();
        let r: { rev: number };
        try {
          r = await o.cli(saveArgs(rev), body);
        } catch (e: any) {
          if (e?.kind !== "conflict") throw e;
          take(await o.cli(LIST_ARGS));
          body = o.body();
          r = await o.cli(saveArgs(rev), body);
        }
        rev = r.rev;
        known = tabTexts(body);
        return body;
      });
    },
    /** Takes in tabs saved elsewhere since (the window came back to the front); reads them only if the revision moved. */
    check: () =>
      one(async () => {
        const s = await o.cli(SUMMARY_ARGS);
        if ((s?.rev ?? 0) !== rev) take(await o.cli(LIST_ARGS));
      }),
  };
}

/**
 * Saves the latest body `delay` ms after the last change. One save runs at a time and later
 * changes wait for it; the body is made only when a save is due (it can be large), and one
 * equal to the last saved isn't sent again. `onError` hears each new failure once (not every
 * retry of the same one), `onSaved` each success. `flush` also rejects when its save fails, so
 * whoever needs the tabs saved (Save as) can stop. `save` may return the body it wrote instead
 * (it took in tabs saved elsewhere first).
 */
export function saver(o: {
  save: (body: string) => Promise<string | void>;
  delay: number;
  onError: (e: Error) => void;
  onSaved?: () => void;
}) {
  let pending: (() => string) | null = null;
  let saved: string | null = null;
  let lastError = "";
  let timer: ReturnType<typeof setTimeout> | null = null;
  let running: Promise<Error | null> | null = null;

  const write = async (body: string): Promise<Error | null> => {
    try {
      const wrote = await o.save(body);
      saved = typeof wrote === "string" ? wrote : body;
      lastError = "";
      o.onSaved?.();
      return null;
    } catch (e: any) {
      // Kept for the next try (another change, or the flush on close).
      if (pending == null) pending = () => body;
      const err = e instanceof Error ? e : new Error(String(e));
      if (err.message !== lastError) o.onError(err);
      lastError = err.message;
      return err;
    }
  };

  const flush = async (): Promise<void> => {
    if (timer) clearTimeout(timer);
    timer = null;
    // Another flush may be writing: wait for it, then save whatever came in meanwhile. The
    // comparison with what is saved happens only now, so going back to the saved set while a
    // different one is being written still saves it.
    while (running) await running;
    const next = pending;
    pending = null;
    if (next == null) return;
    const body = next();
    if (body === saved) return;
    running = write(body).finally(() => (running = null));
    const err = await running;
    if (err) throw err;
  };

  return {
    /** The tabs changed: save `body` (or what it returns then) once they stay unchanged for `delay` ms. */
    schedule(body: string | (() => string)) {
      pending = typeof body === "string" ? () => body : body;
      if (timer) clearTimeout(timer);
      // A failure here is reported through onError.
      timer = setTimeout(() => void flush().catch(() => {}), o.delay);
    },
    /** Saves what is waiting now (the project or the window is closing); rejects if that fails. */
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

/**
 * Saves still running for projects that were closed. A project opened again waits for its own
 * before reading its tabs: otherwise it would load the set from before them, and its next save
 * would replace the newer one.
 */
export function closingSaves() {
  const running = new Map<string, Promise<unknown>>();
  return {
    /** `project` is closing and saving its tabs with `save`. */
    add(project: string, save: Promise<unknown>) {
      // After any earlier one still running for it (a quick close, reopen and close again).
      const done: Promise<unknown> = Promise.all([running.get(project), save.catch(() => {})]).finally(() => {
        if (running.get(project) === done) running.delete(project);
      });
      running.set(project, done);
    },
    /** Resolves once `project`'s saves on close are done, failed or not. */
    async wait(project: string) {
      await running.get(project);
    },
  };
}
