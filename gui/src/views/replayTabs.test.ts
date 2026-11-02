import { test } from "node:test";
import assert from "node:assert/strict";
import { tabStore } from "./replayTabs.ts";

type S = { list: string[]; busy: boolean };
const EMPTY: S = { list: [], busy: false };

test("a result that comes back while the tab isn't showing is kept for it", () => {
  const store = tabStore<S>(EMPTY);
  const seen: S[] = [];
  const stop = store.listen(1, (s) => seen.push(s));
  store.update(1, (s) => ({ ...s, busy: true }));
  stop(); // the user switched to another tab
  store.update(1, (s) => ({ list: [...s.list, "race"], busy: false }));
  assert.deepEqual(store.get(1), { list: ["race"], busy: false });
  assert.equal(seen.length, 1);
  // Back on the tab: the new view starts from the kept state and gets later updates.
  const again: S[] = [];
  store.listen(1, (s) => again.push(s));
  store.update(1, (s) => ({ ...s, list: [...s.list, "send"] }));
  assert.deepEqual(again, [{ list: ["race", "send"], busy: false }]);
});

test("a tab that is still busy stays busy after a remount", () => {
  const store = tabStore<S>(EMPTY);
  const stop = store.listen(1, () => {});
  store.update(1, (s) => ({ ...s, busy: true }));
  stop();
  assert.equal(store.get(1).busy, true);
});

test("tabs are kept apart, and an old view unregistering doesn't drop the new one", () => {
  const store = tabStore<S>(EMPTY);
  assert.equal(store.get(7), EMPTY);
  const old: S[] = [];
  const now: S[] = [];
  const stopOld = store.listen(1, (s) => old.push(s));
  store.listen(1, (s) => now.push(s)); // remounted before the old view's cleanup ran
  stopOld();
  store.update(1, (s) => ({ ...s, busy: true }));
  store.update(2, (s) => ({ ...s, list: ["other"] }));
  assert.deepEqual([old.length, now.length], [0, 1]);
  assert.deepEqual(store.get(1).list, []);
  assert.deepEqual(store.get(2).list, ["other"]);
});
