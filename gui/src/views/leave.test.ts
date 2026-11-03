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
        sends: async () => true,
        temp,
        flush: () => (s.schedule("tabs"), s.flush()),
        ask: () => (asks.push(deferred<boolean>()), asks.at(-1)!.promise),
        discard: () => assert.fail("not a temporary project"),
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
  const answer = deferred<boolean>();
  const guard = leaver();
  guard.attach();
  const leave = () =>
    guard.run((stale) =>
      leaveProject({
        sends: async () => true,
        temp: true,
        flush: () => assert.fail("not saved"),
        ask: () => assert.fail("not asked"),
        discard: () => answer.promise,
        close: () => void closes++,
        stale,
      }),
    );
  const p = leave();
  assert.equal(leave(), p);
  answer.resolve(true);
  await p;
  assert.equal(closes, 1);

  // Keep open keeps it open.
  const kept = deferred<boolean>();
  const q = guard.run((stale) =>
    leaveProject({ sends: async () => true, temp: true, flush: assert.fail, ask: assert.fail, discard: () => kept.promise, close: () => void closes++, stale }),
  );
  kept.resolve(false);
  await q;
  assert.equal(closes, 1);
});

test("Discard answered after Save as opened the saved project leaves that project open", async () => {
  // The app's state: the temporary project, until Save as or a close replaces it.
  let open: string | null = "temp";
  let closes = 0;
  const answer = deferred<boolean>();
  const guard = leaver();
  const detach = guard.attach();
  const p = guard.run((stale) =>
    leaveProject({
      sends: async () => true,
      temp: true,
      flush: () => assert.fail("not saved"),
      ask: () => assert.fail("not asked"),
      discard: () => answer.promise,
      close: () => void (closes++, (open = null)),
      stale,
    }),
  );
  await tick();
  // Save as, already copying, finishes while the question is open: this shell goes and the
  // saved project opens in a new one.
  detach();
  open = "saved.bpx";
  leaver().attach();
  answer.resolve(true);
  await p;
  // Nothing was closed, before the answer or after it.
  assert.equal(closes, 0);
  assert.equal(open, "saved.bpx");
});

test("Keep open on the sends question saves nothing and closes nothing", async () => {
  for (const temp of [false, true]) {
    let closes = 0;
    const guard = leaver();
    guard.attach();
    await guard.run((stale) =>
      leaveProject({ sends: async () => false, temp, flush: assert.fail, ask: assert.fail, discard: assert.fail, close: () => void closes++, stale }),
    );
    assert.equal(closes, 0);
  }
});
