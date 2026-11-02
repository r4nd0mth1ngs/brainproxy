import { test } from "node:test";
import assert from "node:assert/strict";
import { fromSaved, saver, toSaved } from "./replayTabs.ts";

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
  const [ws, http, other] = fromSaved(
    {
      tabs: [
        { kind: "ws", request: "", messages: "m", wait: -1, until: 5 },
        { kind: "http", request: "", binary: "true", messages: ["m"], wait: 2, until: "u" },
        { kind: "grpc", request: "", title: 9, target: ["t"] },
      ],
    },
    next,
  ).tabs;
  assert.deepEqual(ws.ws, []);
  assert.equal(ws.wsWait, undefined);
  assert.ok(!ws.wsUntil, "until that isn't text");
  // An http tab ignores ws-only fields and a binary that isn't true.
  assert.deepEqual(Object.keys(http).sort(), ["key", "raw", "target", "title"]);
  // An unknown kind opens as http; a title or target that isn't text is left out (numbered by position).
  assert.equal(other.ws, undefined);
  assert.equal(other.title, "3");
  assert.equal(other.target, "");
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
  await s.flush();
  fail = false;
  s.schedule("B");
  await s.flush();
  fail = true;
  s.schedule("C");
  await s.flush();
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
  await s.flush();
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
