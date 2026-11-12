import { test } from "node:test";
import assert from "node:assert/strict";
import {
  BINDINGS_KEY,
  actionFor,
  actions,
  bindingOf,
  clashes,
  conflicts,
  define,
  isTyping,
  loadOverrides,
  matches,
  mayRunWhileTyping,
  overlaps,
  parseOverrides,
  register,
  saveOverrides,
  setOverrides,
  withBinding,
  type Action,
  type ActionDef,
} from "./actions.ts";

/** An in-memory stand-in for localStorage. */
function memory(init: Record<string, string> = {}) {
  const data = new Map(Object.entries(init));
  return {
    data,
    getItem: (k: string) => data.get(k) ?? null,
    setItem: (k: string, v: string) => void data.set(k, v),
    removeItem: (k: string) => void data.delete(k),
  };
}

const def = (id: string, p: Partial<ActionDef> = {}): ActionDef => ({ id, title: id, group: "Test", ...p });

// ---------------- Registry ----------------

test("views add actions while mounted and take them away again", () => {
  const before = actions().length;
  const undo = register([{ id: "t.one", get: () => ({ ...def("t.one"), run: () => {} }) }]);
  assert.equal(actions().length, before + 1);
  assert.ok(actions().some((a) => a.id === "t.one"));
  undo();
  assert.equal(actions().length, before);
});

test("the same id twice (Strict Mode's second mount) lists once, the latest", () => {
  const a = register([{ id: "t.twice", get: () => def("t.twice", { title: "first" }) }]);
  const b = register([{ id: "t.twice", get: () => def("t.twice", { title: "second" }) }]);
  assert.deepEqual(actions().filter((x) => x.id === "t.twice").map((x) => x.title), ["second"]);
  b();
  assert.deepEqual(actions().filter((x) => x.id === "t.twice").map((x) => x.title), ["first"]);
  a();
  assert.equal(actions().some((x) => x.id === "t.twice"), false);
});

test("actions are read when used, so a view's latest state counts", () => {
  let busy = false;
  const undo = register([{ id: "t.live", get: () => ({ ...def("t.live"), disabled: busy ? "Sending…" : false }) }]);
  assert.equal(actions().find((a) => a.id === "t.live")?.disabled, false);
  busy = true;
  assert.equal(actions().find((a) => a.id === "t.live")?.disabled, "Sending…");
  undo();
});

test("an action matched where it happens follows the person's binding", () => {
  define([def("t.editor", { keys: "Mod+U", where: "editor", typing: true })]);
  assert.equal(matches("t.editor", "Mod+U"), true);
  assert.equal(matches("t.editor", "Mod+Shift+U"), false);
  assert.equal(matches("t.editor", null), false);
  setOverrides({ "t.editor": "Mod+E" });
  assert.equal(matches("t.editor", "Mod+U"), false);
  assert.equal(matches("t.editor", "Mod+E"), true);
  setOverrides({ "t.editor": null });
  assert.equal(matches("t.editor", "Mod+E"), false);
  setOverrides({});
  assert.equal(matches("t.unknown", "Mod+U"), false);
});

// ---------------- Bindings and persistence ----------------

test("a binding is the person's override, else the default", () => {
  const a = def("a", { keys: "Mod+K" });
  assert.equal(bindingOf(a, {}), "Mod+K");
  assert.equal(bindingOf(a, { a: "Mod+J" }), "Mod+J");
  assert.equal(bindingOf(a, { a: null }), null);
  assert.equal(bindingOf(def("b"), {}), null);
  // A Recent project is never bound, whatever was saved.
  assert.equal(bindingOf(def("c", { unbindable: true }), { c: "Mod+J" }), null);
});

test("only changes from the defaults are kept", () => {
  const a = def("a", { keys: "Mod+K" });
  assert.deepEqual(withBinding({}, a, "Mod+J"), { a: "Mod+J" });
  assert.deepEqual(withBinding({ a: "Mod+J" }, a, "Mod+K"), {});
  assert.deepEqual(withBinding({}, a, null), { a: null });
  // No default: clearing is the default.
  assert.deepEqual(withBinding({ b: "Mod+J" }, def("b"), null), {});
});

test("bindings are saved per person in local storage and read back", () => {
  const store = memory();
  assert.equal(saveOverrides(store, { a: "Mod+J", b: null }), true);
  assert.deepEqual(JSON.parse(store.data.get(BINDINGS_KEY)!), { version: 1, keys: { a: "Mod+J", b: null } });
  assert.deepEqual(loadOverrides(store, false), { a: "Mod+J", b: null });
  // Back to the defaults: nothing is kept.
  saveOverrides(store, {});
  assert.equal(store.data.has(BINDINGS_KEY), false);
});

test("saved bindings that aren't chords, or can't be shortcuts, are left out", () => {
  assert.deepEqual(parseOverrides(null, false), {});
  assert.deepEqual(parseOverrides("not json", false), {});
  assert.deepEqual(parseOverrides("[1,2]", false), {});
  assert.deepEqual(parseOverrides('{"keys":[]}', false), {});
  assert.deepEqual(
    parseOverrides(JSON.stringify({ keys: { a: "ctrl+shift+k", b: "Hyper+X", c: 5, d: "Mod+C", e: "Escape", f: null } }), false),
    { a: "Mod+Shift+K", f: null },
  );
  // Written on Linux, read on macOS: Ctrl there is the Control key.
  assert.deepEqual(parseOverrides(JSON.stringify({ keys: { a: "Ctrl+K" } }), true), { a: "Ctrl+K" });
});

test("storage that throws or is missing loses nothing but the save", () => {
  const broken = {
    getItem: () => {
      throw new Error("denied");
    },
    setItem: () => {
      throw new Error("full");
    },
    removeItem: () => {},
  };
  assert.deepEqual(loadOverrides(broken, false), {});
  assert.equal(saveOverrides(broken, { a: "Mod+J" }), false);
  assert.equal(saveOverrides(null, { a: "Mod+J" }), false);
});

// ---------------- Conflicts ----------------

test("actions overlap where one key press can reach both", () => {
  const global = def("g");
  const replay = def("r", { where: "repeater" });
  const replayTyping = def("rt", { where: "repeater", typing: true });
  const proxy = def("p", { where: "proxy" });
  const editor = def("e", { where: "editor", typing: true });
  const dialog = def("d", { where: "dialog" });
  assert.equal(overlaps(global, replay), true);
  assert.equal(overlaps(replay, replay), true);
  assert.equal(overlaps(replay, proxy), false);
  // The editor is inside views: it meets the ones that run while typing.
  assert.equal(overlaps(editor, replayTyping), true);
  assert.equal(overlaps(editor, replay), false);
  assert.equal(overlaps(editor, global), false);
  assert.equal(overlaps(editor, editor), true);
  // Nothing else runs while a dialog is open.
  assert.equal(overlaps(dialog, global), false);
  assert.equal(overlaps(dialog, editor), false);
  assert.equal(overlaps(dialog, def("d2", { where: "dialog" })), true);
});

test("conflicts are found with the person's bindings, not only the defaults", () => {
  const list = [
    def("palette", { keys: "Mod+K", typing: true }),
    def("send", { keys: "Mod+Enter", where: "repeater", typing: true }),
    def("forward", { keys: "Mod+F", where: "proxy", typing: true }),
    def("curl", { keys: "Mod+Enter", where: "dialog" }),
    def("encode", { keys: "Mod+U", where: "editor", typing: true }),
  ];
  // The defaults: Mod+Enter is Send in Replay and the cURL dialog's, which never meet.
  assert.equal(conflicts(list, {}).size, 0);
  // Forward rebound to Send's chord: different views, no conflict.
  assert.equal(conflicts(list, { forward: "Mod+Enter" }).size, 0);
  // Encode rebound to the palette's: both reach the editor.
  const c = conflicts(list, { encode: "Mod+K" });
  assert.deepEqual(c.get("encode"), ["palette"]);
  assert.deepEqual(c.get("palette"), ["encode"]);
  // A cleared binding clashes with nothing.
  assert.equal(conflicts(list, { encode: "Mod+K", palette: null }).size, 0);
  assert.deepEqual(
    clashes(list, {}, list[2], "Mod+K").map((a) => a.id),
    ["palette"],
  );
  assert.deepEqual(clashes(list, {}, list[2], "Mod+Enter"), []);
});

// ---------------- Not while typing ----------------

test("typing is in a text field, text area, list box or editable text", () => {
  assert.equal(isTyping({ tagName: "TEXTAREA" }), true);
  assert.equal(isTyping({ tagName: "INPUT", type: "text" }), true);
  assert.equal(isTyping({ tagName: "INPUT", type: "" }), true);
  assert.equal(isTyping({ tagName: "INPUT", type: "search" }), true);
  assert.equal(isTyping({ tagName: "INPUT", type: "number" }), true);
  assert.equal(isTyping({ tagName: "SELECT" }), true);
  assert.equal(isTyping({ tagName: "DIV", isContentEditable: true }), true);
  // A checkbox or button that has focus after a click isn't typing.
  assert.equal(isTyping({ tagName: "INPUT", type: "checkbox" }), false);
  assert.equal(isTyping({ tagName: "INPUT", type: "radio" }), false);
  assert.equal(isTyping({ tagName: "BUTTON" }), false);
  assert.equal(isTyping({ tagName: "DIV" }), false);
  assert.equal(isTyping(null), false);
});

test("while typing, only actions meant to run there do, and only with a command modifier", () => {
  const field = { tagName: "TEXTAREA" };
  const send = def("send", { typing: true });
  const go = def("go");
  assert.equal(mayRunWhileTyping(send, "Mod+Enter", field), true);
  assert.equal(mayRunWhileTyping(go, "Mod+3", field), false);
  assert.equal(mayRunWhileTyping(go, "Mod+3", { tagName: "BUTTON" }), true);
  // Rebound to a plain letter (or Shift+letter): never while typing, even if meant to.
  assert.equal(mayRunWhileTyping(send, "G", field), false);
  assert.equal(mayRunWhileTyping(send, "Shift+G", field), false);
  assert.equal(mayRunWhileTyping(send, "G", { tagName: "DIV" }), true);
});

test("a key press runs the action for the view that shows, its own before a global one", () => {
  const ran: string[] = [];
  const act = (id: string, p: Partial<Action> = {}): Action => ({ ...def(id), run: () => ran.push(id), ...p });
  const list = [
    act("go.proxy", { keys: "Mod+3" }),
    act("global.f", { keys: "Mod+F" }),
    act("proxy.forward", { keys: "Mod+F", where: "proxy", typing: true }),
    act("replay.send", { keys: "Mod+Enter", where: "repeater", typing: true }),
    act("encode", { keys: "Mod+U", where: "editor", typing: true }),
    act("curl", { keys: "Mod+Enter", where: "dialog", typing: true }),
    act("hidden", { keys: "Mod+H2", hidden: true }),
  ];
  const body = { tagName: "BODY" };
  const field = { tagName: "TEXTAREA" };
  assert.equal(actionFor(list, {}, "Mod+3", "findings", body)?.id, "go.proxy");
  assert.equal(actionFor(list, {}, "Mod+3", "findings", field), null);
  assert.equal(actionFor(list, {}, "Mod+F", "proxy", body)?.id, "proxy.forward");
  assert.equal(actionFor(list, {}, "Mod+F", "findings", body)?.id, "global.f");
  // Send only in Replay; the dialog's and editor's are matched where they happen.
  assert.equal(actionFor(list, {}, "Mod+Enter", "repeater", field)?.id, "replay.send");
  assert.equal(actionFor(list, {}, "Mod+Enter", "proxy", body), null);
  assert.equal(actionFor(list, {}, "Mod+U", "repeater", field), null);
  assert.equal(actionFor(list, {}, "Mod+H2", "proxy", body), null);
  // Rebound and cleared.
  assert.equal(actionFor(list, { "go.proxy": "Alt+P" }, "Alt+P", "dashboard", body)?.id, "go.proxy");
  assert.equal(actionFor(list, { "go.proxy": null }, "Mod+3", "dashboard", body), null);
});
