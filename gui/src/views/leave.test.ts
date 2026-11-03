import { test } from "node:test";
import assert from "node:assert/strict";
import { leaveProject, leaver } from "./leave.ts";
import { saver } from "./replayTabs.ts";

const tick = () => new Promise((r) => setTimeout(r, 0));

function deferred<T = void>() {
  let resolve!: (v: T) => void;
  let reject!: (e: Error) => void;
  const promise = new Promise<T>((res, rej) => ((resolve = res), (reject = rej)));
  return { promise, resolve, reject };
}

/** The shell's Switch project with the app's saver: each write waits for the test to settle it. */
function shell(temp = false) {
  const writes: ReturnType<typeof deferred<void>>[] = [];
  const asks: ReturnType<typeof deferred<boolean>>[] = [];
  let closed = 0;
  const s = saver({ save: () => (writes.push(deferred()), writes.at(-1)!.promise), delay: 1000, onError: () => {} });
  const guard = leaver();
  const detach = { fn: guard.attach() };
  const leave = () =>
    guard.run((stale) =>
      leaveProject({
        temp,
        flush: () => (s.schedule("tabs"), s.flush()),
        ask: () => (asks.push(deferred<boolean>()), asks.at(-1)!.promise),
        close: () => void closed++,
        stale,
      }),
    );
  return { writes, asks, closed: () => closed, leave, guard, detach };
}

test("a second click while the tabs save joins the first; Keep open keeps it open", async () => {
  const sh = shell();
  const first = sh.leave();
  const second = sh.leave();
  assert.equal(first, second);
  await tick();
  assert.equal(sh.writes.length, 1);
  // The save fails once: one question, and no second save behind it that could close anyway.
  sh.writes[0].reject(new Error("disk full"));
  await tick();
  assert.equal(sh.asks.length, 1);
  assert.equal(sh.writes.length, 1);
  sh.asks[0].resolve(false);
  await first;
  assert.equal(sh.closed(), 0);
  // Clicking again tries again, and closes once that save works.
  const third = sh.leave();
  await tick();
  assert.equal(sh.writes.length, 2);
  sh.writes[1].resolve();
  await third;
  assert.equal(sh.closed(), 1);
});

test("Close anyway closes once, however often it was clicked", async () => {
  const sh = shell();
  const p = sh.leave();
  sh.leave();
  await tick();
  sh.writes[0].reject(new Error("disk full"));
  await tick();
  sh.leave();
  sh.asks[0].resolve(true);
  await p;
  assert.equal(sh.asks.length, 1);
  assert.equal(sh.closed(), 1);
});

test("a switch that finishes after its shell is gone closes nothing", async () => {
  // Unmounted while the save runs.
  let sh = shell();
  let p = sh.leave();
  await tick();
  sh.detach.fn();
  sh.writes[0].resolve();
  await p;
  assert.equal(sh.closed(), 0);

  // Unmounted while the question is open, then answered Close anyway.
  sh = shell();
  p = sh.leave();
  await tick();
  sh.writes[0].reject(new Error("disk full"));
  await tick();
  sh.detach.fn();
  sh.asks[0].resolve(true);
  await p;
  assert.equal(sh.closed(), 0);
});

test("after the project changes, an old switch closes nothing and a click starts a new one", async () => {
  const sh = shell();
  const old = sh.leave();
  await tick();
  sh.detach.fn();
  sh.detach.fn = sh.guard.attach();
  const fresh = sh.leave();
  assert.notEqual(fresh, old);
  await tick();
  // The new switch's save waits for the old one's in the saver, then finds the tabs saved.
  sh.writes[0].resolve();
  await Promise.all([old, fresh]);
  assert.equal(sh.writes.length, 1);
  // Only the new one closed.
  assert.equal(sh.closed(), 1);
});

test("a temporary project isn't saved, and clicks during its discard question join it", async () => {
  let closes = 0;
  const answer = deferred();
  const guard = leaver();
  guard.attach();
  const leave = () =>
    guard.run((stale) =>
      leaveProject({
        temp: true,
        flush: () => assert.fail("not saved"),
        ask: () => assert.fail("not asked"),
        close: () => (closes++, answer.promise),
        stale,
      }),
    );
  const p = leave();
  assert.equal(leave(), p);
  answer.resolve();
  await p;
  assert.equal(closes, 1);
});
