import { test } from "node:test";
import assert from "node:assert/strict";
import { beginCall, clearReplayTabs, closeQuestion, endCall, failureText, forgetTab, replayCalls, sendsInFlight, stopAllCalls, stopCall, stoppedText, tabSlot } from "./replayCalls.ts";

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

test("closing asks only while a send is running, and says what stopping it means", () => {
  clearReplayTabs(async () => {});
  assert.equal(closeQuestion(), null);
  assert.equal(closeQuestion(1), null);
  const a = beginCall(1, "replay-send");
  beginCall(2, "replay-ws-send");
  assert.equal(sendsInFlight(), 2);
  assert.equal(sendsInFlight(1), 1);
  assert.equal(sendsInFlight(3), 0);
  const tab = closeQuestion(1);
  assert.match(tab?.message ?? "", /Closing this tab stops it: the server may already have the request, and history keeps it as cancelled \(on Windows, as sent with no response recorded\)/);
  assert.equal(closeQuestion(3), null);
  assert.match(closeQuestion()?.message ?? "", /^2 Replay sends are still waiting\. Closing the project stops them/);
  // A finished send isn't running any more, though its tab still has a (null) call.
  endCall(1, a);
  assert.equal(closeQuestion(1), null);
  assert.equal(sendsInFlight(), 1);
  assert.match(closeQuestion()?.message ?? "", /^A Replay send is still waiting/);
  clearReplayTabs(async () => {});
  assert.equal(closeQuestion(), null);
});

test("a stopped send doesn't read as not sent", () => {
  assert.equal(failureText({ kind: "cancelled", message: "cancelled" }, "http"), stoppedText("http"));
  assert.equal(failureText({ kind: "cancelled" }, "ws"), stoppedText("ws"));
  for (const kind of ["http", "ws"] as const) {
    assert.match(stoppedText(kind), /may already have reached the server/);
    // The CLI records a request before it goes out, so a stopped send isn't promised to be missing.
    assert.match(stoppedText(kind), /history has/);
    assert.match(stoppedText(kind), /cancelled \(on Windows, /);
    assert.doesNotMatch(stoppedText(kind), /not be in history/);
  }
  // A CLI that answered in time names its rows; that is kept.
  const said = "cancelled by user before a response was recorded (history #7)";
  assert.equal(failureText({ kind: "cancelled", message: said }, "http"), `${stoppedText("http")} (${said})`);
  assert.equal(failureText({ kind: "cli", message: "connection refused" }, "http"), "connection refused");
  assert.equal(failureText(new Error("timed out"), "ws"), "timed out");
});

test("before quitting, every send in flight is cancelled and waited for", async () => {
  clearReplayTabs(async () => {});
  const a = beginCall(1, "replay-send");
  const b = beginCall(2, "replay-ws-send");
  const done = beginCall(3, "replay-send");
  endCall(3, done);
  const cancelled: string[] = [];
  // A slow cancel, and one that fails: both are waited for, and the failure doesn't stop the rest.
  await stopAllCalls(async (call) => {
    await new Promise((r) => setTimeout(r, 5));
    cancelled.push(call);
    if (call === a) throw new Error("already gone");
  });
  assert.deepEqual(cancelled.sort(), [a, b].sort());
  // Once their runs have ended, there is nothing left to cancel.
  endCall(1, a);
  endCall(2, b);
  const again: string[] = [];
  await stopAllCalls(async (call) => void again.push(call));
  assert.deepEqual(again, []);
});
