// The app's actions, in one registry: the command palette lists them, keyboard shortcuts run
// them, and Settings › Keyboard rebinds them. Views add their own while mounted (useActions), so
// a new feature adds itself; an action matched where it happens (the message editor's encode,
// a dialog's submit) is defined once here with `define` and checked with `matches`.
//
// Bindings are the person's, not the project's: only the ones changed from the defaults are
// kept, in the app's local storage beside its other preferences (theme, Recent, ...).

import { bindProblem, hasCommandModifier, normalize } from "./chords.ts";

/**
 * Where an action applies. "global": anywhere in a project. A view's id ("repeater", "proxy",
 * ...): only while that view shows. "editor": in a message editor, matched there. "dialog": in
 * an open dialog, matched there (other shortcuts don't run while a dialog is open).
 */
export type Where = string;

export interface ActionDef {
  /** Stable: bindings are kept by it. */
  id: string;
  /** What it does, as the palette and Settings show it ("Send the request"). */
  title: string;
  /** The heading it is listed under ("Go to", "Replay", "Proxy", ...). */
  group: string;
  /** The default chord ("Mod+Enter"), if it has one. */
  keys?: string;
  where?: Where;
  /** Runs while typing in a text field too (only with Mod, Ctrl or Alt held). */
  typing?: boolean;
  /** Left out of the palette (it needs a place: the editor's selection, an open dialog). */
  noPalette?: boolean;
  /** Left out of Settings › Keyboard and never bound (a Recent project, ...). */
  unbindable?: boolean;
  /** More words the palette matches. */
  keywords?: string;
}

export interface Action extends ActionDef {
  run?: () => unknown;
  /** Not open to the palette or shortcuts now (another sub-tab shows, say). */
  hidden?: boolean;
  /** Why it can't run now; the palette shows it dimmed with this. */
  disabled?: string | false;
}

// ---------------- Registry ----------------

type Entry = { get: () => Action };

/** Each id's registrations, latest last (the same view may mount twice, as in Strict Mode). */
const entries = new Map<string, Entry[]>();
const listeners = new Set<() => void>();
let version = 0;
const changed = () => {
  version++;
  for (const l of listeners) l();
};

/** Adds actions read through `get` each time they're used; returns the undo. */
export function register(list: { id: string; get: () => Action }[]): () => void {
  const mine = list.map(({ id, get }) => [id, { get }] as const);
  for (const [id, e] of mine) entries.set(id, [...(entries.get(id) ?? []), e]);
  changed();
  return () => {
    for (const [id, e] of mine) {
      const rest = (entries.get(id) ?? []).filter((x) => x !== e);
      if (rest.length) entries.set(id, rest);
      else entries.delete(id);
    }
    changed();
  };
}

/** Defines actions that are matched where they happen, listed whatever is mounted. */
export function define(defs: ActionDef[]): void {
  register(defs.map((d) => ({ id: d.id, get: () => d })));
}

/** Every action registered now, each id once. */
export function actions(): Action[] {
  return [...entries.values()].map((list) => list[list.length - 1].get());
}

export const actionsVersion = () => version;
export function subscribeActions(l: () => void): () => void {
  listeners.add(l);
  return () => listeners.delete(l);
}

// ---------------- Bindings ----------------

/** Bindings changed from the defaults: a chord, or null for none. */
export type Overrides = Record<string, string | null>;

export const BINDINGS_KEY = "shortcuts";

interface Store {
  getItem(k: string): string | null;
  setItem(k: string, v: string): void;
  removeItem(k: string): void;
}

/** The saved overrides; ones that aren't chords (an older or hand-edited file) are left out. */
export function parseOverrides(text: string | null, mac: boolean): Overrides {
  if (!text) return {};
  let data: unknown;
  try {
    data = JSON.parse(text);
  } catch {
    return {};
  }
  const keys = (data as { keys?: unknown } | null)?.keys;
  if (!keys || typeof keys !== "object" || Array.isArray(keys)) return {};
  const out: Overrides = {};
  for (const [id, v] of Object.entries(keys as Record<string, unknown>)) {
    if (v === null) out[id] = null;
    else if (typeof v === "string") {
      const chord = normalize(v, mac);
      if (chord && !bindProblem(chord)) out[id] = chord;
    }
  }
  return out;
}

export function loadOverrides(store: Store | null, mac: boolean): Overrides {
  try {
    return parseOverrides(store?.getItem(BINDINGS_KEY) ?? null, mac);
  } catch {
    return {};
  }
}

/** Saves the overrides (none: the key is removed); false if storage is unavailable. */
export function saveOverrides(store: Store | null, o: Overrides): boolean {
  try {
    if (!store) return false;
    if (Object.keys(o).length === 0) store.removeItem(BINDINGS_KEY);
    else store.setItem(BINDINGS_KEY, JSON.stringify({ version: 1, keys: o }));
    return true;
  } catch {
    return false;
  }
}

/** The action's chord with these overrides, or null for none. */
export function bindingOf(a: ActionDef, o: Overrides): string | null {
  if (a.unbindable) return null;
  return Object.hasOwn(o, a.id) ? o[a.id] : (a.keys ?? null);
}

/** The overrides with `a` bound to `chord` (null: no shortcut); a default kept is not stored. */
export function withBinding(o: Overrides, a: ActionDef, chord: string | null): Overrides {
  const next = { ...o };
  if (chord === (a.keys ?? null)) delete next[a.id];
  else next[a.id] = chord;
  return next;
}

/**
 * Whether two actions can both be in reach of one key press: a dialog's only with another
 * dialog's; the editor's with ones that run while typing; a view's with that view's and the
 * global ones.
 */
export function overlaps(a: ActionDef, b: ActionDef): boolean {
  const wa = a.where ?? "global";
  const wb = b.where ?? "global";
  if (wa === "dialog" || wb === "dialog") return wa === wb;
  if (wa === "editor") return wb === "editor" || !!b.typing;
  if (wb === "editor") return !!a.typing;
  return wa === "global" || wb === "global" || wa === wb;
}

/** For each action whose chord another can take, the ids of those others. */
export function conflicts(list: ActionDef[], o: Overrides): Map<string, string[]> {
  const out = new Map<string, string[]>();
  const bound = list.map((a) => [a, bindingOf(a, o)] as const).filter(([, c]) => c);
  for (const [a, ca] of bound)
    for (const [b, cb] of bound) if (a.id !== b.id && ca === cb && overlaps(a, b)) out.set(a.id, [...(out.get(a.id) ?? []), b.id]);
  return out;
}

/** The actions in `list` that would clash with `a` bound to `chord`. */
export function clashes(list: ActionDef[], o: Overrides, a: ActionDef, chord: string): ActionDef[] {
  return list.filter((b) => b.id !== a.id && bindingOf(b, o) === chord && overlaps(a, b));
}

// The person's bindings, shared by the whole window.

let overrides: Overrides | null = null;
const bindingListeners = new Set<() => void>();
const storage = (): Store | null => {
  try {
    return typeof localStorage === "undefined" ? null : localStorage;
  } catch {
    return null;
  }
};
let mac = false;

/** Reads the saved bindings (once), for macOS or not. */
export function initBindings(isMac: boolean): void {
  mac = isMac;
  overrides = loadOverrides(storage(), mac);
}

export function currentOverrides(): Overrides {
  return overrides ?? (overrides = loadOverrides(storage(), mac));
}

/** Changes the bindings for everyone in this window and saves them; false if they couldn't be saved. */
export function setOverrides(o: Overrides): boolean {
  overrides = o;
  for (const l of bindingListeners) l();
  return saveOverrides(storage(), o);
}

export function subscribeBindings(l: () => void): () => void {
  bindingListeners.add(l);
  return () => bindingListeners.delete(l);
}

// ---------------- Running ----------------

/** What a key press landed on. */
export interface Target {
  tagName?: string;
  type?: string;
  isContentEditable?: boolean;
}

/** Input types that take typed text (not checkboxes, buttons, ...). */
const TEXT_INPUTS = new Set(["", "text", "search", "url", "email", "password", "number", "tel", "date", "datetime-local", "month", "week", "time"]);

/** Whether a key press on `t` is typing: in a text field, text area, list box or editable text. */
export function isTyping(t: Target | null | undefined): boolean {
  if (!t) return false;
  if (t.isContentEditable) return true;
  const tag = (t.tagName ?? "").toUpperCase();
  if (tag === "TEXTAREA" || tag === "SELECT") return true;
  return tag === "INPUT" && TEXT_INPUTS.has((t.type ?? "").toLowerCase());
}

/** Whether `chord` may run `a` with focus on `t`: while typing only ones meant to, and only with a command modifier. */
export function mayRunWhileTyping(a: ActionDef, chord: string, t: Target | null | undefined): boolean {
  return !isTyping(t) || (!!a.typing && hasCommandModifier(chord));
}

/**
 * The action a key press runs, given the view that shows and what has focus: one that applies
 * there (a view's own before a global one), isn't hidden, and may run while typing. Editor and
 * dialog actions are matched where they happen, never here.
 */
export function actionFor(list: Action[], o: Overrides, chord: string, view: string, t: Target | null | undefined): Action | null {
  let found: Action | null = null;
  for (const a of list) {
    const where = a.where ?? "global";
    if (a.hidden || (where !== "global" && where !== view) || bindingOf(a, o) !== chord || !mayRunWhileTyping(a, chord, t)) continue;
    if (!found || (where !== "global" && (found.where ?? "global") === "global")) found = a;
  }
  return found;
}

/** Whether a key press is `id`'s current chord (for actions matched where they happen). */
export function matches(id: string, chord: string | null): boolean {
  if (!chord) return false;
  const a = entries.get(id)?.at(-1)?.get();
  return !!a && bindingOf(a, currentOverrides()) === chord;
}
