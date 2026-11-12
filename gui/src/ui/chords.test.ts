import { test } from "node:test";
import assert from "node:assert/strict";
import { bindProblem, chordOf, formatChord, hasCommandModifier, normalize, type KeyPress } from "./chords.ts";

const press = (p: Partial<KeyPress>): KeyPress => ({ key: "", code: "", ctrlKey: false, metaKey: false, altKey: false, shiftKey: false, ...p });

test("Mod is ⌘ on macOS and Ctrl elsewhere", () => {
  assert.equal(chordOf(press({ key: "k", code: "KeyK", metaKey: true }), true), "Mod+K");
  assert.equal(chordOf(press({ key: "k", code: "KeyK", ctrlKey: true }), false), "Mod+K");
  // The Control key on macOS is its own modifier.
  assert.equal(chordOf(press({ key: "k", code: "KeyK", ctrlKey: true }), true), "Ctrl+K");
  assert.equal(chordOf(press({ key: "k", code: "KeyK", ctrlKey: true, metaKey: true }), true), "Mod+Ctrl+K");
});

test("letters, digits and punctuation are named by the key, whatever Shift or Option types", () => {
  assert.equal(chordOf(press({ key: "U", code: "KeyU", ctrlKey: true, shiftKey: true }), false), "Mod+Shift+U");
  assert.equal(chordOf(press({ key: "!", code: "Digit1", ctrlKey: true, shiftKey: true }), false), "Mod+Shift+1");
  // Option+A types "å" on macOS.
  assert.equal(chordOf(press({ key: "å", code: "KeyA", altKey: true }), true), "Alt+A");
  assert.equal(chordOf(press({ key: "?", code: "Slash", shiftKey: true }), false), "Shift+/");
  assert.equal(chordOf(press({ key: ",", code: "Comma", metaKey: true }), true), "Mod+,");
  assert.equal(chordOf(press({ key: "Enter", code: "Enter", ctrlKey: true }), false), "Mod+Enter");
  assert.equal(chordOf(press({ key: "PageDown", code: "PageDown", ctrlKey: true }), false), "Mod+PageDown");
  assert.equal(chordOf(press({ key: " ", code: "Space" }), false), "Space");
  assert.equal(chordOf(press({ key: "F5", code: "F5" }), false), "F5");
});

test("a modifier alone, AltGr and the Windows key make no chord", () => {
  assert.equal(chordOf(press({ key: "Control", code: "ControlLeft", ctrlKey: true }), false), null);
  assert.equal(chordOf(press({ key: "Shift", code: "ShiftLeft", shiftKey: true }), true), null);
  // AltGr+Q types "@" on a German keyboard, and Windows reports it as Ctrl+Alt.
  assert.equal(chordOf(press({ key: "@", code: "KeyQ", ctrlKey: true, altKey: true, getModifierState: (k) => k === "AltGraph" }), false), null);
  assert.equal(chordOf(press({ key: "1", code: "Digit1", metaKey: true }), false), null);
  assert.equal(chordOf(press({ key: "Dead", code: "" }), false), null);
});

test("a keyboard with no codes names letters by what they type", () => {
  assert.equal(chordOf(press({ key: "k", ctrlKey: true }), false), "Mod+K");
  assert.equal(chordOf(press({ key: ",", ctrlKey: true }), false), "Mod+,");
  // With a code, what it types doesn't decide: an unknown key makes none.
  assert.equal(chordOf(press({ key: "k", code: "IntlRo", ctrlKey: true }), false), null);
});

test("normalize puts modifiers in order and accepts other spellings", () => {
  assert.equal(normalize("shift+mod+k", false), "Mod+Shift+K");
  assert.equal(normalize("Cmd+Option+p", true), "Mod+Alt+P");
  assert.equal(normalize("Ctrl+Enter", false), "Mod+Enter");
  assert.equal(normalize("Ctrl+Enter", true), "Ctrl+Enter");
  assert.equal(normalize("mod+pagedown", false), "Mod+PageDown");
  assert.equal(normalize("f12", false), "F12");
  assert.equal(normalize("Mod+,", false), "Mod+,");
  for (const bad of ["", "Mod+", "Mod+Mod+K", "Hyper+K", "Mod+Nope", "Mod++"]) assert.equal(normalize(bad, false), null, bad);
});

test("chords show as the platform writes them", () => {
  assert.equal(formatChord("Mod+Shift+U", true), "⇧⌘U");
  assert.equal(formatChord("Mod+Shift+U", false), "Ctrl+Shift+U");
  assert.equal(formatChord("Mod+Enter", true), "⌘↩");
  assert.equal(formatChord("Mod+Enter", false), "Ctrl+Enter");
  assert.equal(formatChord("Mod+Ctrl+Alt+K", true), "⌃⌥⌘K");
  assert.equal(formatChord("Mod+PageDown", false), "Ctrl+Page Down");
});

test("a command modifier is Mod, Ctrl or Alt, not Shift", () => {
  assert.equal(hasCommandModifier("Mod+K"), true);
  assert.equal(hasCommandModifier("Alt+K"), true);
  assert.equal(hasCommandModifier("Ctrl+K"), true);
  assert.equal(hasCommandModifier("Shift+K"), false);
  assert.equal(hasCommandModifier("K"), false);
  // Option types characters on macOS.
  assert.equal(hasCommandModifier("Alt+K", true), false);
  assert.equal(hasCommandModifier("Ctrl+K", true), true);
});

test("keys the window and fields use can't be shortcuts", () => {
  assert.match(bindProblem("Escape")!, /Esc/);
  assert.match(bindProblem("Mod+Escape")!, /Esc/);
  assert.match(bindProblem("Tab")!, /Tab/);
  assert.match(bindProblem("Shift+Tab")!, /Tab/);
  assert.equal(bindProblem("Mod+Tab"), null);
  assert.match(bindProblem("Enter")!, /moves around/);
  assert.match(bindProblem("Shift+ArrowDown")!, /moves around/);
  assert.equal(bindProblem("Mod+Enter"), null);
  assert.match(bindProblem("Mod+C")!, /copy/);
  assert.match(bindProblem("Mod+Shift+Z")!, /redo/);
  assert.match(bindProblem("Mod+Q")!, /quit/);
  // A plain letter can be one; it never runs while typing (actions.ts).
  assert.equal(bindProblem("G"), null);
  assert.equal(bindProblem("F5"), null);
});
