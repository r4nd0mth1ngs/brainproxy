import { test } from "node:test";
import assert from "node:assert/strict";
import { beginCall, clearReplayTabs, endCall, forgetTab, replayCalls, stopCall, tabSlot } from "./replayCalls.ts";

/** A stand-in for cancelCli that records what it was asked to stop. */
function canceller() {
  const stopped: string[] = [];
  return { stopped, cancel: async (call: string) => void stopped.push(call) };
}

const results = tabSlot<string[]>([]);

test("a send in flight outlives its tab's view: Stop still finds it and the result lands in the tab", () => {
  clearReplayTabs(async () => {});
  const id = beginCall(1, "replay-send");
  // The user switches to another tab and back: the new view reads the tab's call afresh.
  assert.equal(replayCalls.get(1), id);
  assert.equal(replayCalls.get(2), null);
  const { stopped, cancel } = canceller();
  stopCall(1, cancel);
  assert.deepEqual(stopped, [id]);
  // The run then fails as cancelled; its outcome still belongs to tab 1.
  assert.equal(endCall(1, id), true);
  results.update(1, (r) => [...r, "Stopped"]);
  assert.equal(replayCalls.get(1), null);
  assert.deepEqual(results.get(1), ["Stopped"]);
  // Nothing left to stop.
  stopCall(1, cancel);
  assert.deepEqual(stopped, [id]);
});

test("closing the project stops its sends and drops their results, so the next project's tab 1 starts clean", () => {
  clearReplayTabs(async () => {});
  const a = beginCall(1, "replay-send");
  const b = beginCall(3, "replay-ws-send");
  results.update(1, () => ["old project's response"]);
  const { stopped, cancel } = canceller();
  clearReplayTabs(cancel);
  assert.deepEqual(stopped.sort(), [a, b].sort());
  assert.equal(replayCalls.get(1), null);
  assert.deepEqual(results.get(1), []);
  // The old project's send ends after the new project opened a tab 1.
  assert.equal(endCall(1, a), false);
  assert.equal(replayCalls.get(1), null);
});

test("a new send in a reused tab key isn't ended by the old project's send", () => {
  clearReplayTabs(async () => {});
  const old = beginCall(1, "replay-send");
  clearReplayTabs(async () => {});
  const fresh = beginCall(1, "replay-send");
  assert.notEqual(old, fresh);
  assert.equal(endCall(1, old), false);
  assert.equal(replayCalls.get(1), fresh);
});

test("closing a tab stops its send and forgets only that tab", () => {
  clearReplayTabs(async () => {});
  const a = beginCall(1, "replay-send");
  const b = beginCall(2, "replay-send");
  results.update(2, () => ["kept"]);
  const { stopped, cancel } = canceller();
  forgetTab(1, cancel);
  assert.deepEqual(stopped, [a]);
  assert.equal(endCall(1, a), false);
  assert.equal(replayCalls.get(2), b);
  assert.deepEqual(results.get(2), ["kept"]);
});

test("a slot tells its subscribers about every change", () => {
  clearReplayTabs(async () => {});
  let n = 0;
  const off = results.subscribe(() => n++);
  results.update(5, () => ["x"]);
  forgetTab(5, async () => {});
  off();
  results.update(5, () => ["y"]);
  assert.equal(n, 2);
  // The default for a tab without a value is the same object each time (useSyncExternalStore needs that).
  assert.equal(results.get(9), results.get(9));
});
