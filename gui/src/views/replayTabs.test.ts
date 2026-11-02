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
