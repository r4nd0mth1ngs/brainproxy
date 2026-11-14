import { test } from "node:test";
import assert from "node:assert/strict";
import type { HistoryItem } from "../api";
import { dueIds, isPending, mergeRechecked, PENDING, PENDING_FOR_MS, pendingIds, recheckCalls, SLOW_AFTER_MS, stillPending, withPending } from "./trafficPending.ts";

const now = Date.parse("2026-11-14T12:00:00.000Z");
const at = (ms: number) => new Date(now - ms).toISOString();
const item = (id: number, over: Partial<HistoryItem> = {}): HistoryItem => ({
  id,
  time: at(1000),
  source: "scan",
  method: "GET",
  url: `https://a.test/${id}`,
  status: 200,
  resp_content_type: "text/html",
  resp_body_length: 10,
  title: null,
  duration_ms: 5,
  error: null,
  note: null,
  tags: [],
  ...over,
});
const waiting = (id: number, over: Partial<HistoryItem> = {}) => item(id, { status: null, resp_content_type: null, resp_body_length: null, duration_ms: null, error: PENDING, ...over });

test("a row written before its request went out is pending until it is answered or fails", () => {
  assert.ok(isPending(waiting(1), now));
  assert.ok(isPending(waiting(1, { error: `not stored (--no-store): content omitted; ${PENDING}` }), now), "a row kept without content");
  assert.ok(!isPending(item(1), now));
  assert.ok(!isPending(waiting(1, { error: "connection refused" }), now), "a final error");
  assert.ok(!isPending(waiting(1, { error: "cancelled by user before a response was recorded" }), now));
  assert.ok(!isPending(waiting(1, { error: null }), now));
  // A command killed or crashed leaves its rows pending for good: they aren't waited for.
  assert.ok(isPending(waiting(1, { time: at(PENDING_FOR_MS) }), now));
  assert.ok(!isPending(waiting(1, { time: at(PENDING_FOR_MS + 1) }), now));
  assert.ok(!isPending(waiting(1, { time: "not a time" }), now));
  assert.deepEqual(pendingIds([item(1), waiting(2), item(3), waiting(4)], now), [2, 4]);
});

test("pending rows are read again by id, as many per call as a filter takes", () => {
  assert.deepEqual(recheckCalls([]), []);
  assert.deepEqual(recheckCalls([9, 4, 4]), [{ ids: [4, 9], args: ["history", "list", "--after", "3", "--filter", "id=4 OR id=9", "--limit", "2"] }]);
  const many = recheckCalls(Array.from({ length: 130 }, (_, i) => 1000 - i));
  assert.deepEqual(many.map((c) => c.ids.length), [64, 64, 2]);
  assert.deepEqual(many[0].args.slice(0, 4), ["history", "list", "--after", "870"]);
  assert.equal(many[1].ids[0], 935);
  assert.equal(many[0].args[5].split(" OR ").length, 64);
});

test("a row read again takes the place of the pending one, keeping its note and tags", () => {
  const rows = [item(1), waiting(2, { note: "mine", tags: ["highlight"] }), waiting(3)];
  const done = item(2, { status: 302, note: null, tags: [] });
  const merged = mergeRechecked(rows, [done]);
  assert.equal(merged[1].status, 302);
  assert.equal(merged[1].error, null);
  assert.equal(merged[1].note, "mine");
  assert.deepEqual(merged[1].tags, ["highlight"]);
  assert.equal(merged[0], rows[0]);
  assert.equal(merged[2], rows[2]);
  assert.equal(mergeRechecked(rows, []), rows, "nothing read: the same rows");
  assert.equal(mergeRechecked(rows, [item(99)]), rows, "a row not shown isn't added");
  // Still pending, read the same: the same rows, so nothing is redrawn.
  assert.equal(mergeRechecked(rows, [waiting(3)]), rows);
  assert.equal(mergeRechecked(rows, [waiting(2, { note: "theirs", tags: [] })]), rows, "note and tags stay as shown");
});

test("rows pending a while are read again only now and then", () => {
  const p = withPending(new Map(), [item(1), waiting(2), waiting(3, { time: at(SLOW_AFTER_MS + 1) })], now);
  assert.deepEqual([...p.keys()], [2, 3]);
  assert.deepEqual(dueIds(p, now, false), [2], "a recent one every poll");
  assert.deepEqual(dueIds(p, now, true), [2, 3], "an old one when it's time");
});

test("an id stays pending only while the row read again still is", () => {
  const pending = withPending(new Map(), [waiting(2), waiting(3), waiting(7)], now);
  const ids = (p: Map<number, number>) => [...p.keys()].sort();
  assert.deepEqual(ids(stillPending(pending, [2, 3], [item(2), waiting(3)], now)), [3, 7], "2 answered; 7 wasn't asked about");
  assert.deepEqual(ids(stillPending(pending, [2, 3], [], now)), [7], "rows no longer there are dropped");
  assert.deepEqual(ids(stillPending(pending, [2], [waiting(5)], now)), [3, 7], "a row not asked about isn't added");
  assert.deepEqual(ids(pending), [2, 3, 7], "the map passed in is left as it was");
});
