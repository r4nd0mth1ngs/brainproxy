// Replay tabs kept in the project file (`replay tabs list/save`), so they come back when it is
// opened again. Only what was typed is saved, never responses; text goes as typed, auth
// placeholders included. Saves are debounced, one at a time, and a failed one leaves the
// tabs in the app as they are. Each save checks the set's revision, and the set is read again
// while Replay is shown, so changes saved elsewhere meanwhile (an agent's, another window's)
// are merged with the app's by tab id rather than replaced (mergeTabs).

import type { RepeaterTab } from "../store";
import { marksFromSaved, type Mark } from "./payloadMarks.ts";
import { optionsFromSaved, savedOptions, type SavedOptions } from "./replayOptions.ts";
import { isWsOut, type WsOut } from "./ws.ts";

/** One tab as `replay tabs save` takes it. */
export interface SavedTab {
  /** Stays the same wherever the tab is open; the CLI makes one when a save leaves it out. */
  id?: string;
  kind: "http" | "ws";
  title: string;
  target: string;
  /** The raw request, or a WebSocket tab's handshake. */
  request: string;
  binary?: boolean;
  /** A WebSocket tab's messages: text, or binary as `{hex}` / `{base64}` as typed. */
  messages?: WsOut[];
  wait?: number;
  until?: string;
  /** How the tab sends; never Don't record (see savedOptions). */
  options?: SavedOptions;
  /** HTTP tabs: the highlighted parts of the request, and the finding it came from. */
  marks?: Mark[];
  finding?: number;
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

/**
 * The newest format this build reads and writes; a newer set has fields this one would drop.
 * 2 added binary WebSocket messages, 3 tab ids (the CLI writes the lowest a set needs).
 */
const FORMAT = 3;
/** Longest WebSocket Listen, in seconds (`ws send --wait` refuses more). */
export const MAX_WAIT = 86400;

export const NEWER = "they were saved by a newer brainproxy, so this one doesn't save over them; update it";

/** Whether `data` (a listing) was saved by a newer version, which this one mustn't save over. */
export function newerFormat(data: unknown): boolean {
  const v = (data as { v?: unknown } | null)?.v;
  return typeof v === "number" && v > FORMAT;
}

/** A new tab id, in what the CLI takes (letters, digits, -). */
export const newTabId = (): string => globalThis.crypto.randomUUID();

/**
 * The tabs, each with an id of its own: one without (just opened) or with another's (a copy of
 * a tab) gets a new one. The same array when nothing changes.
 */
export function withIds(tabs: RepeaterTab[], make: () => string = newTabId): RepeaterTab[] {
  const seen = new Set<string>();
  let changed = false;
  const out = tabs.map((t) => {
    if (t.id && !seen.has(t.id)) {
      seen.add(t.id);
      return t;
    }
    changed = true;
    const id = make();
    seen.add(id);
    return { ...t, id };
  });
  return changed ? out : tabs;
}

/** One open tab as saved: no key, no response. */
export function savedTab(t: RepeaterTab): SavedTab {
  const id = t.id ? { id: t.id } : {};
  const base = { title: t.title, target: t.target, request: t.raw };
  // In the order the CLI writes a tab, so a listing's tab reads the same as the app's.
  const opts = (o: SavedOptions | undefined) => (o ? { options: o } : {});
  if (t.ws)
    return {
      ...id,
      kind: "ws",
      ...base,
      messages: t.ws,
      ...(t.wsWait != null ? { wait: t.wsWait } : {}),
      ...(t.wsUntil ? { until: t.wsUntil } : {}),
      ...opts(savedOptions(t.options, "ws")),
    };
  return {
    ...id,
    kind: "http",
    ...base,
    ...(t.binary ? { binary: true } : {}),
    ...opts(savedOptions(t.options, "http")),
    ...(t.marks?.length ? { marks: t.marks } : {}),
    ...(t.finding != null ? { finding: t.finding } : {}),
  };
}

/** The open tabs as saved: no keys, no responses. */
export function toSaved(tabs: RepeaterTab[], activeKey: number): SavedTabs {
  const saved = tabs.map(savedTab);
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
    // A set saved before ids is listed with ids by place; the same here for one that has none.
    tab.id = typeof t.id === "string" && t.id ? t.id : `i${i}`;
    if (t.kind === "ws") {
      tab.ws = Array.isArray(t.messages) ? t.messages.filter(isWsOut) : [];
      if (typeof t.wait === "number" && t.wait >= 0 && t.wait <= MAX_WAIT) tab.wsWait = t.wait;
      if (t.until) tab.wsUntil = str(t.until);
    } else {
      if (t.binary === true) tab.binary = true;
      const marks = marksFromSaved(t.marks);
      if (marks) tab.marks = marks;
      if (Number.isInteger(t.finding) && t.finding! > 0) tab.finding = t.finding;
    }
    const options = optionsFromSaved(t.options, t.kind === "ws" ? "ws" : "http");
    if (options) tab.options = options;
    tabs.push(tab);
    if (i === d.active) activeKey = key;
  });
  return { tabs, activeKey };
}

/** `v` as JSON with every object's keys sorted, so the CLI's order and the app's compare equal. */
function canonical(v: unknown): string {
  if (Array.isArray(v)) return `[${v.map(canonical).join(",")}]`;
  if (v && typeof v === "object") {
    const o = v as Record<string, unknown>;
    return `{${Object.keys(o)
      .filter((k) => o[k] !== undefined)
      .sort()
      .map((k) => `${JSON.stringify(k)}:${canonical(o[k])}`)
      .join(",")}}`;
  }
  return JSON.stringify(v);
}

const listed = (data: unknown): unknown[] => {
  const tabs = (data as { tabs?: unknown } | null)?.tabs;
  return Array.isArray(tabs) ? tabs : [];
};
const idOf = (item: unknown, i: number): string => {
  const id = (item as { id?: unknown } | null)?.id;
  return typeof id === "string" && id ? id : `i${i}`;
};

/** Each saved tab as text, by id (`body` is a save's stdin or a listing): the set as last synced. */
export function tabTexts(body: string | unknown): Map<string, string> {
  const d = typeof body === "string" ? JSON.parse(body) : body;
  return new Map(listed(d).map((t, i) => [idOf(t, i), canonical(t)]));
}

/** What a merge did: the tabs to show, and what came from elsewhere. */
export interface Merged {
  tabs: RepeaterTab[];
  added: number;
  removed: number;
  updated: number;
  /** Removed elsewhere, but changed here since: kept, and saved again. */
  kept: RepeaterTab[];
}

/**
 * A three-way merge of Replay's tabs by id: `base` is the set as last read or saved (tabTexts),
 * `local` the open tabs, `data` the set the project holds now (a listing).
 * - A tab added elsewhere is added at the end (untitled ones numbered from `firstNumber`).
 * - A tab changed elsewhere takes the change if it is unchanged here; changed on both sides,
 *   the app's stays (and is saved over the other).
 * - A tab removed elsewhere goes if it is unchanged here; changed here, it is kept (`kept`).
 * - A tab the app closed stays closed, and one it opened stays.
 * Keys and the order of the open tabs are kept.
 */
export function mergeTabs(base: Map<string, string>, local: RepeaterTab[], data: unknown, nextKey: () => number, firstNumber = 1): Merged {
  const remote = new Map(listed(data).map((item, i) => [idOf(item, i), item]));
  const texts = tabTexts(data);
  const out: RepeaterTab[] = [];
  const kept: RepeaterTab[] = [];
  let removed = 0;
  let updated = 0;
  for (const t of local) {
    const was = t.id == null ? undefined : base.get(t.id);
    const now = t.id == null ? undefined : texts.get(t.id);
    if (was === undefined) {
      out.push(t);
      continue;
    }
    const mine = canonical(savedTab(t));
    if (now === undefined) {
      if (mine === was) removed++;
      else {
        out.push(t);
        kept.push(t);
      }
    } else if (now !== was && mine === was) {
      const fresh = fromSaved({ tabs: [remote.get(t.id!)] }, () => t.key, out.length + 1).tabs[0];
      if (fresh) {
        out.push(fresh);
        updated++;
      } else out.push(t);
    } else out.push(t);
  }
  const open = new Set(local.map((t) => t.id));
  const fresh = [...remote].filter(([id]) => !open.has(id) && !base.has(id)).map(([, item]) => item);
  const added = fromSaved({ tabs: fresh }, nextKey, firstNumber).tabs;
  // fromSaved numbers the ids of those without by their place among `fresh`: the listing's own.
  added.forEach((t, i) => (t.id = idOf(fresh[i], listed(data).indexOf(fresh[i]))));
  out.push(...added);
  return { tabs: out, added: added.length, removed, updated, kept };
}

/** Whether a merge changed anything the app shows. */
export const mergeChanged = (m: Merged) => m.added + m.removed + m.updated > 0;

/** What a merge tells the person, or "" when nothing came from elsewhere. */
export function mergeNote(m: Merged): string {
  const n = (k: number, what: string) => (k ? [`${k} ${k === 1 ? "tab" : "tabs"} ${what}`] : []);
  const parts = [...n(m.added, "added"), ...n(m.updated, "changed"), ...n(m.removed, "closed")];
  const kept = m.kept.map((t) => `"${t.title}"`).join(", ");
  const lines = parts.length ? [`Replay: ${parts.join(", ")} elsewhere (an agent, the command line or another window).`] : [];
  if (kept) lines.push(`Kept ${kept} here, closed elsewhere, because you changed ${m.kept.length === 1 ? "it" : "them"}.`);
  return lines.join(" ");
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
 * one saved elsewhere meanwhile (an agent preparing tabs, another window) is a conflict, not
 * lost. Then the set saved there is merged with the app's (`mergeTabs`, given to `apply`) and
 * the result is saved. `cli` runs a command with optional stdin and returns its data; `body` is
 * the app's set now (after `apply`); `tabs` the open tabs.
 */
export function revisions(o: {
  cli: (args: string[], stdin?: string) => Promise<any>;
  body: () => string;
  tabs: () => RepeaterTab[];
  apply: (m: Merged) => void;
  nextKey: () => number;
}) {
  let rev = 0;
  let known = new Map<string, string>();
  // A check and a save never interleave: each reads the revision the other sets.
  const one = serial();
  const take = (data: unknown) => {
    if (newerFormat(data)) throw new Error(NEWER);
    const open = o.tabs();
    const m = mergeTabs(known, open, data, o.nextKey, open.length + 1);
    rev = (data as SavedTabs).rev ?? 0;
    known = tabTexts(data);
    if (mergeChanged(m) || m.kept.length) o.apply(m);
  };
  return {
    /** The set read when the project opened. */
    loaded(data: unknown) {
      rev = (data as SavedTabs | null)?.rev ?? 0;
      known = tabTexts(data);
    },
    /** Saves `body`, or merges in what was saved elsewhere since and saves the result. Returns what it wrote. */
    save: (body: string) => {
      const seen = rev;
      return one(async () => {
        // A check queued before merged changes in meanwhile: `body` was made without them.
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
    /** Merges in what was saved elsewhere since (polled while Replay is shown); reads the set only if the revision moved. */
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
