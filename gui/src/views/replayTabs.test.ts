import { test } from "node:test";
import assert from "node:assert/strict";
import { CliError } from "../api.ts";
import type { RepeaterTab } from "../store.tsx";
import { MAX_WAIT, NEWER, addedSince, closingSaves, fromSaved, newerFormat, revisions, saver, serial, tabTexts, toSaved, type SavedTabs } from "./replayTabs.ts";

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

test("tabs round-trip without keys or responses, text as typed", () => {
  const req = "GET /?k=«auth:app:query:k» HTTP/1.1\nHost: a.test\n\n\u0001ÿ";
  const tabs = [
    { key: 7, title: "1", target: "https://a.test", raw: req, binary: true },
    { key: 9, title: "WS 2", target: "wss://a.test", raw: "GET /ws HTTP/1.1\n\n", ws: ["a", "«auth:app:header:X»"], wsWait: 0, wsUntil: "done|(" },
  ];
  const saved = toSaved(tabs, 9);
  assert.deepEqual(saved, {
    tabs: [
      { kind: "http", title: "1", target: "https://a.test", request: req, binary: true },
      { kind: "ws", title: "WS 2", target: "wss://a.test", request: "GET /ws HTTP/1.1\n\n", messages: ["a", "«auth:app:header:X»"], wait: 0, until: "done|(" },
    ],
    active: 1,
  });
  let k = 100;
  const back = fromSaved(JSON.parse(JSON.stringify(saved)), () => k++);
  assert.deepEqual(back.tabs, [
    { key: 100, title: "1", target: "https://a.test", raw: req, binary: true },
    { key: 101, title: "WS 2", target: "wss://a.test", raw: "GET /ws HTTP/1.1\n\n", ws: ["a", "«auth:app:header:X»"], wsWait: 0, wsUntil: "done|(" },
  ]);
  assert.equal(back.activeKey, 101);
  // No active tab saved when none is open.
  assert.equal(toSaved(tabs, 0).active, undefined);
});

test("a tab's send options are kept, but never Don't record", () => {
  const tabs: RepeaterTab[] = [
    { key: 1, title: "a", target: "https://a.test", raw: "GET / HTTP/1.1\n\n", options: { http2: true, verbatim: true, crlfBody: true, sni: " other.test ", timeout: "2.5", verifyTls: true, noStore: true } },
    // A WebSocket tab keeps only what `ws send` has; defaults and Don't record leave nothing.
    { key: 2, title: "b", target: "wss://a.test", raw: "", ws: [], options: { http2: true, sni: "10.0.0.1", timeout: "30", noStore: true } },
    { key: 3, title: "c", target: "", raw: "", options: { noStore: true, timeout: "30" } },
    // What isn't valid yet (being typed) is left out, so the save doesn't fail.
    { key: 4, title: "d", target: "", raw: "", options: { sni: "half-", timeout: "1e3" } },
  ];
  const saved = toSaved(tabs, 0);
  assert.deepEqual(
    saved.tabs.map((t) => t.options),
    [{ http2: true, verbatim: true, crlfBody: true, sni: "other.test", timeout: 2.5, verifyTls: true }, { sni: "10.0.0.1" }, undefined, undefined],
  );
  assert.doesNotMatch(JSON.stringify(saved), /noStore/);
  // The CLI's order, so a listed tab reads the same as the app's (tabTexts).
  assert.deepEqual(Object.keys(saved.tabs[0]), ["kind", "title", "target", "request", "options"]);
  assert.deepEqual(Object.keys(saved.tabs[0].options!), ["http2", "verbatim", "crlfBody", "sni", "timeout", "verifyTls"]);
  let k = 1;
  const back = fromSaved(JSON.parse(JSON.stringify(saved)), () => k++).tabs;
  assert.deepEqual(back[0].options, { http2: true, verbatim: true, crlfBody: true, sni: "other.test", timeout: "2.5", verifyTls: true });
  assert.deepEqual(back[1].options, { sni: "10.0.0.1" });
  assert.equal(back[2].options, undefined);
  // A set saved elsewhere (an agent's) can't turn Don't record on, nor HTTP-only options for a WebSocket tab.
  const listed = { tabs: [{ request: "", options: { noStore: true, timeout: 99999, sni: "a b" } }, { kind: "ws", request: "", options: { http2: true, timeout: 60 } }] };
  const agent = fromSaved(listed, () => k++).tabs;
  assert.equal(agent[0].options, undefined);
  assert.deepEqual(agent[1].options, { timeout: "60" });
});

test("loading skips what isn't a tab", () => {
  let k = 1;
  const r = fromSaved({ tabs: [null, "x", { title: "no request" }, { request: "GET / HTTP/1.1\n\n", future: 1 }, { kind: "ws", request: "", messages: [1, "m"] }], active: 0 }, () => k++);
  assert.deepEqual(r.tabs, [
    { key: 1, title: "1", target: "", raw: "GET / HTTP/1.1\n\n" },
    { key: 2, title: "2", target: "", raw: "", ws: ["m"] },
  ]);
  assert.equal(r.activeKey, null);
  assert.deepEqual(fromSaved(undefined, () => k++), { tabs: [], activeKey: null });
});

test("saves are debounced and skip what is already saved", async () => {
  const saves: string[] = [];
  const s = saver({ save: async (b) => void saves.push(b), delay: 10, onError: () => assert.fail("no error") });
  s.loaded("A");
  s.schedule("A");
  s.schedule("B");
  s.schedule("C");
  await sleep(30);
  assert.deepEqual(saves, ["C"]);
  s.schedule("C");
  await sleep(30);
  assert.deepEqual(saves, ["C"]);
  // Close: what is waiting is saved at once.
  s.schedule("D");
  await s.flush();
  assert.deepEqual(saves, ["C", "D"]);
  s.schedule("E");
  s.cancel();
  await sleep(30);
  assert.deepEqual(saves, ["C", "D"]);
});

test("a failed save is reported once and tried again", async () => {
  let fail = true;
  const saves: string[] = [];
  const errors: string[] = [];
  const s = saver({
    save: async (b) => {
      if (fail) throw new Error("too big");
      saves.push(b);
    },
    delay: 5,
    onError: (e) => errors.push(e.message),
  });
  s.schedule("A");
  await sleep(20);
  s.schedule("B");
  await sleep(20);
  assert.deepEqual(errors, ["too big"]);
  fail = false;
  // Nothing changed since, but closing still saves what failed.
  await s.flush();
  assert.deepEqual(saves, ["B"]);
});

test("one save at a time, and a flush waits for the one running", async () => {
  const order: string[] = [];
  let release!: () => void;
  const s = saver({
    save: (b) => {
      order.push(`start ${b}`);
      return b === "A" ? new Promise<void>((r) => (release = () => (order.push("end A"), r()))) : Promise.resolve();
    },
    delay: 1,
    onError: () => assert.fail("no error"),
  });
  s.schedule("A");
  await sleep(10);
  s.schedule("B");
  const closing = s.flush();
  await sleep(10);
  assert.deepEqual(order, ["start A"]);
  release();
  await closing;
  assert.deepEqual(order, ["start A", "end A", "start B"]);
});

// The fields `replay tabs save` takes; anything else is refused and the whole set isn't saved.
const TAB_FIELDS = new Set(["kind", "title", "target", "request", "binary", "messages", "wait", "until"]);

test("saved tabs only carry what the command takes", () => {
  const tabs = [
    // A handshake marked binary (not possible today) is still saved as text: ws tabs can't be binary.
    { key: 1, title: "WS", target: "wss://a.test", raw: "GET / HTTP/1.1\n\n", ws: [], binary: true, wsUntil: "" },
    { key: 2, title: "h", target: "https://a.test", raw: "GET / HTTP/1.1\n\n", binary: false, wsWait: 2, wsUntil: "x" },
  ];
  const saved = toSaved(tabs, 3);
  assert.deepEqual(saved, {
    tabs: [
      { kind: "ws", title: "WS", target: "wss://a.test", request: "GET / HTTP/1.1\n\n", messages: [] },
      { kind: "http", title: "h", target: "https://a.test", request: "GET / HTTP/1.1\n\n" },
    ],
  });
  for (const t of saved.tabs) for (const k of Object.keys(t)) assert.ok(TAB_FIELDS.has(k), k);
  assert.deepEqual(toSaved([], 1), { tabs: [] });
  // A Listen box that isn't a number goes as null, which the command reads as unset.
  const nan = JSON.parse(JSON.stringify(toSaved([{ key: 1, title: "", target: "", raw: "", ws: [], wsWait: NaN }], 1)));
  assert.equal(nan.tabs[0].wait, null);
  let k = 1;
  assert.equal(fromSaved(nan, () => k++).tabs[0].wsWait, undefined);
});

test("every byte of a binary request comes back", () => {
  const raw = "POST / HTTP/1.1\r\n\r\n" + Array.from({ length: 256 }, (_, i) => String.fromCharCode(i)).join("");
  let k = 1;
  const back = fromSaved(JSON.parse(JSON.stringify(toSaved([{ key: 5, title: "b", target: "", raw, binary: true }], 5))), () => k++);
  assert.equal(back.tabs[0].raw, raw);
  assert.equal(back.tabs[0].binary, true);
  assert.equal(back.activeKey, 1);
});

test("loading takes only well-formed values", () => {
  let k = 1;
  const next = () => k++;
  // active is an index into the list as saved, so it still finds its tab past a skipped one.
  const r = fromSaved({ tabs: [7, { request: "a", title: "A" }], active: 1 }, next);
  assert.equal(r.activeKey, r.tabs[0].key);
  for (const active of [2, -1, "0", null, 0.5])
    assert.equal(fromSaved({ tabs: [{ request: "" }], active }, next).activeKey, null, String(active));
  for (const data of ["x", 3, [], { tabs: "no" }, { tabs: {} }, null]) assert.deepEqual(fromSaved(data, next), { tabs: [], activeKey: null });
  const loaded = fromSaved(
    {
      tabs: [
        { kind: "ws", request: "", messages: "m", wait: -1, until: 5 },
        { kind: "http", request: "", binary: "true", messages: ["m"], wait: 2, until: "u" },
        { kind: "grpc", request: "" },
        { request: "", title: 9, target: ["t"] },
        { kind: "ws", request: "", wait: 1e300 },
      ],
    },
    next,
  ).tabs;
  const [ws, http, other, long] = loaded;
  assert.equal(loaded.length, 4);
  assert.deepEqual(ws.ws, []);
  assert.equal(ws.wsWait, undefined);
  assert.ok(!ws.wsUntil, "until that isn't text");
  // An http tab ignores ws-only fields and a binary that isn't true.
  assert.deepEqual(Object.keys(http).sort(), ["key", "raw", "target", "title"]);
  // A kind this version doesn't know is skipped, not opened as http (saving it would change it).
  // A title or target that isn't text is left out (numbered by position).
  assert.equal(other.ws, undefined);
  assert.equal(other.title, "3");
  assert.equal(other.target, "");
  // A wait Send would refuse (over a day) isn't taken.
  assert.equal(long.wsWait, undefined);
  assert.equal(fromSaved({ tabs: [{ kind: "ws", request: "", wait: MAX_WAIT }] }, next).tabs[0].wsWait, MAX_WAIT);
});

test("a change made while a save fails is the one tried again", async () => {
  const saves: string[] = [];
  const errors: string[] = [];
  let reject!: (e: unknown) => void;
  const s = saver({
    save: (b) => (b === "A" ? new Promise((_, r) => (reject = r)) : (saves.push(b), Promise.resolve())),
    delay: 1,
    onError: (e) => errors.push(e.message),
  });
  s.schedule("A");
  await sleep(10);
  s.schedule("B");
  // Not an Error: reported with its text.
  reject("disk full");
  await sleep(10);
  assert.deepEqual(errors, ["disk full"]);
  await s.flush();
  assert.deepEqual(saves, ["B"]);
});

test("going back to what is saved after a failure saves nothing", async () => {
  let calls = 0;
  const s = saver({
    save: async () => {
      calls++;
      throw new Error("locked");
    },
    delay: 1,
    onError: () => {},
  });
  s.loaded("A");
  s.schedule("B");
  await sleep(10);
  assert.equal(calls, 1);
  s.schedule("A");
  await sleep(10);
  await s.flush();
  assert.equal(calls, 1);
});

test("the same error is reported again after a save in between works", async () => {
  let fail = true;
  const errors: string[] = [];
  let ok = 0;
  const s = saver({
    save: async () => {
      if (fail) throw new Error("locked");
    },
    delay: 1,
    onError: (e) => errors.push(e.message),
    onSaved: () => ok++,
  });
  s.schedule("A");
  await assert.rejects(s.flush(), /locked/);
  fail = false;
  s.schedule("B");
  await s.flush();
  fail = true;
  s.schedule("C");
  await assert.rejects(s.flush(), /locked/);
  assert.deepEqual(errors, ["locked", "locked"]);
  assert.equal(ok, 1);
});

test("flush with nothing waiting saves nothing; cancel drops a failed set too", async () => {
  const saves: string[] = [];
  let fail = true;
  const s = saver({
    save: async (b) => {
      if (fail) throw new Error("x");
      saves.push(b);
    },
    delay: 1000,
    onError: () => {},
  });
  await s.flush();
  s.schedule("A");
  await assert.rejects(s.flush(), /x/);
  fail = false;
  // A temporary project being discarded: what failed isn't tried again.
  s.cancel();
  await s.flush();
  assert.deepEqual(saves, []);
});

test("cancel lets a running save finish but drops what waits", async () => {
  const saves: string[] = [];
  let release!: () => void;
  const s = saver({
    save: (b) => {
      if (b === "A") return new Promise<void>((r) => (release = () => (saves.push(b), r())));
      saves.push(b);
      return Promise.resolve();
    },
    delay: 1,
    onError: () => assert.fail("no error"),
  });
  s.schedule("A");
  await sleep(10);
  s.schedule("B");
  s.cancel();
  release();
  await s.flush();
  await sleep(10);
  assert.deepEqual(saves, ["A"]);
});

test("flushes at once each save the latest set once, in order", async () => {
  const saves: string[] = [];
  const s = saver({
    save: async (b) => {
      await sleep(5);
      saves.push(b);
    },
    delay: 1000,
    onError: () => assert.fail("no error"),
  });
  s.schedule("A");
  const first = s.flush();
  s.schedule("B");
  const second = s.flush();
  const third = s.flush();
  await Promise.all([first, second, third]);
  assert.deepEqual(saves, ["A", "B"]);
});

test("going back to the saved set while another is being written saves it again", async () => {
  const saves: string[] = [];
  let release!: () => void;
  const s = saver({
    save: (b) => {
      if (b === "B") return new Promise<void>((r) => (release = () => (saves.push(b), r())));
      saves.push(b);
      return Promise.resolve();
    },
    delay: 1,
    onError: () => assert.fail("no error"),
  });
  s.loaded("A");
  s.schedule("B");
  await sleep(10);
  // B is being written; the user undoes the change.
  s.schedule("A");
  await sleep(10);
  release();
  await sleep(10);
  await s.flush();
  assert.deepEqual(saves, ["B", "A"]);
});

test("the body is made only when a save is due", async () => {
  const saves: string[] = [];
  let made = 0;
  let state = "A";
  const body = () => (made++, state);
  const s = saver({ save: async (b) => void saves.push(b), delay: 10, onError: () => assert.fail("no error") });
  s.loaded("A");
  state = "B";
  s.schedule(body);
  state = "C";
  s.schedule(body);
  assert.equal(made, 0);
  await sleep(30);
  assert.equal(made, 1);
  assert.deepEqual(saves, ["C"]);
});

test("a flush that can't save rejects, so Save as stops; a later one that works resolves", async () => {
  let fail = true;
  const saves: string[] = [];
  const errors: string[] = [];
  const s = saver({
    save: async (b) => {
      if (fail) throw new Error("over 16 MB");
      saves.push(b);
    },
    delay: 1,
    onError: (e) => errors.push(e.message),
  });
  // The pause's save fails first: reported once, and the flush after it still rejects.
  s.schedule("A");
  await sleep(10);
  assert.deepEqual(errors, ["over 16 MB"]);
  await assert.rejects(s.flush(), (e: Error) => e.message === "over 16 MB");
  // Another flush waiting on the one that fails rejects too, after trying again itself.
  s.schedule("B");
  const first = s.flush();
  const second = s.flush();
  await assert.rejects(first, /over 16 MB/);
  await assert.rejects(second, /over 16 MB/);
  assert.deepEqual(errors, ["over 16 MB"]);
  fail = false;
  await s.flush();
  assert.deepEqual(saves, ["B"]);
});

test("a failed save after the pause doesn't reject unheard", async () => {
  const unhandled: unknown[] = [];
  const onUnhandled = (e: unknown) => unhandled.push(e);
  process.on("unhandledRejection", onUnhandled);
  try {
    const errors: string[] = [];
    const s = saver({ save: async () => Promise.reject(new Error("locked")), delay: 1, onError: (e) => errors.push(e.message) });
    s.schedule("A");
    await sleep(20);
    assert.deepEqual(errors, ["locked"]);
    assert.deepEqual(unhandled, []);
  } finally {
    process.off("unhandledRejection", onUnhandled);
  }
});

test("a project opened again reads its tabs after the save from closing it", async () => {
  // The project file: what `replay tabs list` returns.
  let stored = "old";
  let release!: () => void;
  const s = saver({
    save: (b) => new Promise<void>((r) => (release = () => ((stored = b), r()))),
    delay: 1000,
    onError: () => assert.fail("no error"),
  });
  const closing = closingSaves();
  s.loaded("old");
  s.schedule("new");
  // Closed while the save is slow, then opened again at once.
  closing.add("/p.bpx", s.flush());
  let read: string | null = null;
  const reopened = closing.wait("/p.bpx").then(() => (read = stored));
  // Another project doesn't wait.
  await closing.wait("/other.bpx");
  await sleep(10);
  assert.equal(read, null);
  release();
  await reopened;
  assert.equal(read, "new");
  // Done: nothing left to wait for.
  await closing.wait("/p.bpx");
});

test("waiting on closing saves covers each one and outlasts a failure", async () => {
  const closing = closingSaves();
  let releaseA!: () => void;
  let rejectB!: (e: Error) => void;
  closing.add("/p.bpx", new Promise<void>((r) => (releaseA = r)));
  closing.add("/p.bpx", new Promise<void>((_, r) => (rejectB = r)));
  let done = false;
  const waiting = closing.wait("/p.bpx").then(() => (done = true));
  rejectB(new Error("locked"));
  await sleep(10);
  // The first close's save is still running.
  assert.equal(done, false);
  releaseA();
  await waiting;
  assert.equal(done, true);
});

test("tabs saved elsewhere since are told apart from the app's, duplicates counted", () => {
  const a = { kind: "http", title: "a", target: "", request: "A" };
  const b = { kind: "http", title: "b", target: "", request: "B" };
  const known = tabTexts(JSON.stringify({ tabs: [a, a, b] }));
  let k = 1;
  // Two a's and a b were known: only the third a and the new WebSocket tab are new, numbered
  // after the three open.
  const r = addedSince(known, { rev: 3, tabs: [a, { ...a }, b, a, { kind: "ws", request: "W" }] }, () => k++, 4);
  assert.deepEqual(
    r.added.map((t) => [t.title, t.raw, !!t.ws]),
    [
      ["a", "A", false],
      ["5", "W", true],
    ],
  );
  assert.equal(r.now.length, 5);
  // The CLI writes a wait of 3 as 3.0; read back it is the same tab.
  assert.deepEqual(tabTexts({ tabs: [JSON.parse('{"kind":"ws","wait":3.0}')] }), tabTexts('{"tabs":[{"kind":"ws","wait":3}]}'));
  assert.deepEqual(addedSince(known, { tabs: [b] }, () => k++).added, []);
});

test("one call at a time, in order, past a failure", async () => {
  const one = serial();
  const log: string[] = [];
  const step = (name: string, ms: number, fail = false) =>
    one(async () => {
      log.push(`${name}+`);
      await sleep(ms);
      log.push(`${name}-`);
      if (fail) throw new Error(name);
      return name;
    });
  const results = await Promise.allSettled([step("a", 15), step("b", 1, true), step("c", 1)]);
  assert.deepEqual(log, ["a+", "a-", "b+", "b-", "c+", "c-"]);
  assert.deepEqual(results.map((r) => r.status), ["fulfilled", "rejected", "fulfilled"]);
});

/** A fake CLI holding one saved set, revisions and --if-revision as `replay tabs` keeps them. */
function fakeCli(start: SavedTabs = { tabs: [] }) {
  const db = { set: { v: 1, rev: 0, ...start } as SavedTabs & { rev: number } };
  const calls: string[] = [];
  const cli = async (args: string[], stdin?: string): Promise<any> => {
    calls.push(args.slice(2).join(" "));
    await sleep(1);
    if (args.includes("save")) {
      const want = Number(args[args.indexOf("--if-revision") + 1]);
      if (want !== db.set.rev) throw new CliError("conflict", `at revision ${db.set.rev}, not ${want}`);
      const given = JSON.parse(stdin!) as SavedTabs;
      db.set = { ...db.set, ...given, rev: db.set.rev + 1 };
      return { count: given.tabs.length, rev: db.set.rev };
    }
    return args.includes("--summary") ? { rev: db.set.rev, tabs: [] } : JSON.parse(JSON.stringify(db.set));
  };
  /** Another writer: an agent's `--append`. */
  const append = (...tabs: SavedTabs["tabs"]) => (db.set = { ...db.set, tabs: [...db.set.tabs, ...tabs], rev: db.set.rev + 1 });
  return { db, cli, calls, append };
}

function app(f: ReturnType<typeof fakeCli>, open: string[]) {
  let k = 1;
  const tabs: RepeaterTab[] = open.map((raw) => ({ key: k++, title: raw, target: "", raw }));
  const added: string[][] = [];
  const revs = revisions({
    cli: f.cli,
    body: () => JSON.stringify(toSaved(tabs, 0)),
    add: (ts) => {
      tabs.push(...ts);
      added.push(ts.map((t) => t.raw));
    },
    count: () => tabs.length,
    nextKey: () => k++,
  });
  return { tabs, added, revs, body: () => JSON.stringify(toSaved(tabs, 0)) };
}

test("the app's save keeps tabs an agent saved meanwhile", async () => {
  const f = fakeCli({ tabs: [{ kind: "http", title: "mine", target: "", request: "mine" }] });
  const a = app(f, ["mine"]);
  a.revs.loaded(await f.cli(["replay", "tabs", "list"]));
  // Saved while the app is open: the app's next save (any change, even switching tabs) conflicts,
  // takes the agent's tab in, and saves both.
  f.append({ kind: "http", title: "agent", target: "", request: "agent" });
  a.tabs.push({ key: 99, title: "new", target: "", raw: "new" });
  const wrote = await a.revs.save(a.body());
  assert.deepEqual(a.added, [["agent"]]);
  assert.deepEqual(f.db.set.tabs.map((t) => t.request), ["mine", "new", "agent"]);
  assert.equal(wrote, a.body());
  assert.equal(f.db.set.rev, 2);
  // Nothing new since: a plain save, and a closed tab stays closed.
  a.tabs.splice(0, 1);
  await a.revs.save(a.body());
  assert.deepEqual(f.db.set.tabs.map((t) => t.request), ["new", "agent"]);
  assert.deepEqual(a.added, [["agent"]]);
});

test("coming back to the window shows an agent's tabs without a save", async () => {
  const f = fakeCli();
  const a = app(f, []);
  a.revs.loaded(await f.cli(["replay", "tabs", "list"]));
  await a.revs.check();
  assert.deepEqual(f.calls, ["list", "list --summary"], "the full set is read only when the revision moved");
  f.append({ kind: "ws", title: "feed", target: "", request: "ws", messages: ["hi"] });
  await a.revs.check();
  assert.deepEqual(a.added, [["ws"]]);
  assert.deepEqual(a.tabs[0].ws, ["hi"]);
  // The app saves them back at the revision it read, with no conflict and nothing doubled.
  await a.revs.save(a.body());
  assert.deepEqual(f.db.set.tabs.length, 1);
  assert.deepEqual(a.added, [["ws"]]);
  // A check queued behind a running save reads the revision that save set.
  a.tabs.push({ key: 50, title: "x", target: "", raw: "x" });
  await Promise.all([a.revs.save(a.body()), a.revs.check()]);
  assert.deepEqual(a.added, [["ws"]], "its own save isn't taken for someone else's");
  // A save made while a check was waiting goes after it, with the tabs it took in.
  f.append({ kind: "http", title: "late", target: "", request: "late" });
  const stale = a.body();
  await Promise.all([a.revs.check(), a.revs.save(stale)]);
  assert.deepEqual(a.added.at(-1), ["late"]);
  assert.deepEqual(f.db.set.tabs.map((t) => t.request), ["ws", "x", "late"]);
});

test("a set saved by a newer version isn't saved over", async () => {
  assert.equal(newerFormat({ v: 2, tabs: [] }), true);
  assert.equal(newerFormat({ v: 1, tabs: [] }), false);
  assert.equal(newerFormat({ tabs: [] }), false);
  const f = fakeCli();
  const a = app(f, ["mine"]);
  a.revs.loaded(await f.cli(["replay", "tabs", "list"]));
  f.db.set = { v: 2, rev: 5, tabs: [] };
  await assert.rejects(a.revs.save(a.body()), (e: Error) => e.message === NEWER);
  assert.equal(f.db.set.rev, 5);
  // Other errors are passed on as they are.
  const b = app({ ...f, cli: async () => Promise.reject(new CliError("invalid_input", "over 16 MB")) }, []);
  await assert.rejects(b.revs.save("{}"), /over 16 MB/);
});
