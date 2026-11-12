// Keyboard chords for the app's shortcuts: what a key press is called, how it is shown, and
// which ones can't be used. A chord is written "Mod+Shift+K": modifiers in a fixed order, then
// the key. Mod is ⌘ on macOS and Ctrl on Linux and Windows, so a binding means the same thing on
// each; Ctrl is the Control key on macOS only (elsewhere it is Mod). Letters, digits and
// punctuation are named by where the key is (as on a US keyboard), so Shift or Option doesn't
// change the name.

/** Modifiers, in the order a chord lists them. */
const MODS = ["Mod", "Ctrl", "Alt", "Shift"] as const;
type Mod = (typeof MODS)[number];

/** Keys named by `KeyboardEvent.key` as they are. */
const NAMED = new Set([
  "Enter",
  "Escape",
  "Tab",
  "Space",
  "Backspace",
  "Delete",
  "Insert",
  "Home",
  "End",
  "PageUp",
  "PageDown",
  "ArrowUp",
  "ArrowDown",
  "ArrowLeft",
  "ArrowRight",
  "Plus",
]);

/** Punctuation keys by `KeyboardEvent.code`. */
const PUNCT: Record<string, string> = {
  Comma: ",",
  Period: ".",
  Slash: "/",
  Semicolon: ";",
  Quote: "'",
  BracketLeft: "[",
  BracketRight: "]",
  Backslash: "\\",
  Minus: "-",
  Equal: "=",
  Backquote: "`",
};

const isKeyName = (k: string) => NAMED.has(k) || /^F([1-9]|1[0-9]|2[0-4])$/.test(k) || /^[A-Z0-9]$/.test(k) || Object.values(PUNCT).includes(k);

/** Whether the app runs on macOS (or iOS), where Mod is ⌘. */
export function isMac(): boolean {
  if (typeof navigator === "undefined") return false;
  const nav = navigator as Navigator & { userAgentData?: { platform?: string } };
  return /mac|iphone|ipad/i.test(nav.userAgentData?.platform || nav.platform || nav.userAgent || "");
}

/** The parts of a key press a chord is made from. */
export interface KeyPress {
  key: string;
  code: string;
  ctrlKey: boolean;
  metaKey: boolean;
  altKey: boolean;
  shiftKey: boolean;
  getModifierState?: (key: string) => boolean;
}

/** The key's name in a chord, or null for a modifier on its own or a key with no name here. */
function keyName(e: KeyPress): string | null {
  const c = e.code ?? "";
  if (/^Key[A-Z]$/.test(c)) return c.slice(3);
  if (/^(Digit|Numpad)[0-9]$/.test(c)) return c.slice(-1);
  if (PUNCT[c]) return PUNCT[c];
  const k = e.key;
  if (k === " ") return "Space";
  if (k === "+") return "Plus";
  if (NAMED.has(k) || /^F([1-9]|1[0-9]|2[0-4])$/.test(k)) return k;
  // A keyboard that reports no code (some virtual and remote ones): by what the key types.
  if (!c && /^[a-z0-9]$/i.test(k)) return k.toUpperCase();
  if (!c && Object.values(PUNCT).includes(k)) return k;
  return null;
}

/**
 * The chord a key press makes, or null when it makes none: a modifier pressed alone, AltGr
 * (which types characters on many keyboards, and reports Ctrl+Alt on Windows), or the Windows
 * or Super key on Linux and Windows (the system's own).
 */
export function chordOf(e: KeyPress, mac: boolean): string | null {
  if (e.getModifierState?.("AltGraph")) return null;
  if (!mac && e.metaKey) return null;
  const key = keyName(e);
  if (!key) return null;
  const mods: Mod[] = [];
  if (mac ? e.metaKey : e.ctrlKey) mods.push("Mod");
  if (mac && e.ctrlKey) mods.push("Ctrl");
  if (e.altKey) mods.push("Alt");
  if (e.shiftKey) mods.push("Shift");
  return [...mods, key].join("+");
}

/**
 * The chord in its usual spelling (modifiers in order, "Cmd"/"Control" and lower case
 * accepted), or null when it isn't one. Ctrl is Mod except on macOS.
 */
export function normalize(chord: string, mac: boolean): string | null {
  const parts = chord.split("+").map((p) => p.trim());
  if (parts.some((p) => !p)) return null;
  const key = parts.pop()!;
  const mods = new Set<Mod>();
  for (const p of parts) {
    const m = p.toLowerCase();
    const mod: Mod | null =
      m === "mod" || m === "cmd" || m === "command" || m === "meta" ? "Mod" : m === "ctrl" || m === "control" ? (mac ? "Ctrl" : "Mod") : m === "alt" || m === "option" ? "Alt" : m === "shift" ? "Shift" : null;
    if (!mod || mods.has(mod)) return null;
    mods.add(mod);
  }
  const name = key.length === 1 ? key.toUpperCase() : NAMED_LOWER.get(key.toLowerCase()) ?? key;
  if (!isKeyName(name)) return null;
  return [...MODS.filter((m) => mods.has(m)), name].join("+");
}

const NAMED_LOWER = new Map([...NAMED, ...Array.from({ length: 24 }, (_, i) => `F${i + 1}`)].map((k) => [k.toLowerCase(), k]));

const split = (chord: string) => {
  const parts = chord.split("+");
  return { mods: new Set(parts.slice(0, -1)), key: parts[parts.length - 1] };
};

/** Whether the chord holds Mod, Ctrl or Alt: one that doesn't types text in a field. */
export function hasCommandModifier(chord: string): boolean {
  const { mods } = split(chord);
  return mods.has("Mod") || mods.has("Ctrl") || mods.has("Alt");
}

const MAC_KEYS: Record<string, string> = {
  Enter: "↩",
  Escape: "⎋",
  Backspace: "⌫",
  Delete: "⌦",
  Tab: "⇥",
  ArrowUp: "↑",
  ArrowDown: "↓",
  ArrowLeft: "←",
  ArrowRight: "→",
  PageUp: "⇞",
  PageDown: "⇟",
  Plus: "+",
};
const OTHER_KEYS: Record<string, string> = { ArrowUp: "Up", ArrowDown: "Down", ArrowLeft: "Left", ArrowRight: "Right", PageUp: "Page Up", PageDown: "Page Down", Escape: "Esc", Plus: "+" };

/** The chord as the platform shows it: "⌘⇧K" on macOS, "Ctrl+Shift+K" elsewhere. */
export function formatChord(chord: string, mac: boolean): string {
  const { mods, key } = split(chord);
  if (mac) {
    // Apple's order: Control, Option, Shift, Command.
    const sym = [mods.has("Ctrl") ? "⌃" : "", mods.has("Alt") ? "⌥" : "", mods.has("Shift") ? "⇧" : "", mods.has("Mod") ? "⌘" : ""].join("");
    return sym + (MAC_KEYS[key] ?? key);
  }
  const names = [mods.has("Mod") ? "Ctrl" : "", mods.has("Alt") ? "Alt" : "", mods.has("Shift") ? "Shift" : ""].filter(Boolean);
  return [...names, OTHER_KEYS[key] ?? key].join("+");
}

/** Keys that move around lists and edit text, which a shortcut without Mod, Ctrl or Alt would take over. */
const MOVING = new Set(["Enter", "Space", "Backspace", "Delete", "Home", "End", "PageUp", "PageDown", "ArrowUp", "ArrowDown", "ArrowLeft", "ArrowRight"]);

/** Chords the window and text fields already use everywhere. */
const RESERVED: Record<string, string> = {
  "Mod+C": "copy",
  "Mod+V": "paste",
  "Mod+X": "cut",
  "Mod+A": "select all",
  "Mod+Z": "undo",
  "Mod+Shift+Z": "redo",
  "Mod+Y": "redo",
  "Mod+Q": "quit",
  "Mod+W": "close the window",
  "Mod+H": "hide the app on macOS",
  "Mod+M": "minimise the window",
  "Mod+Ctrl+F": "full screen on macOS",
};

/** Why a chord can't be a shortcut, or null when it can. */
export function bindProblem(chord: string): string | null {
  const { key } = split(chord);
  if (key === "Escape") return "Esc closes dialogs and menus, so it can't be a shortcut.";
  if (key === "Tab" && !hasCommandModifier(chord)) return "Tab moves between fields, so it needs Ctrl or Alt (⌘ or ⌥ on macOS).";
  if (MOVING.has(key) && !hasCommandModifier(chord)) return `${key} moves around lists and edits text, so it needs Ctrl or Alt (⌘ or ⌥ on macOS).`;
  const used = RESERVED[chord];
  if (used) return `That is ${used} everywhere, so it can't be a shortcut.`;
  return null;
}
