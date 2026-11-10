import { test } from "node:test";
import assert from "node:assert/strict";
import { appendEvents, readSummary, streamNote, type SseEvent } from "./sse.ts";

const event = (id: number): SseEvent => ({ id, time: "t", event: "message", event_id: null, data: { encoding: "utf8", content: `e${id}` }, retry: null });

test("a stream cut at the cap says so first", () => {
  assert.equal(streamNote({ state: "open", truncated: false, ended: null, error: null }), "");
  assert.equal(streamNote({ state: "closed", truncated: false, ended: "server", error: null }), "ended by the server");
  assert.equal(
    streamNote({ state: "closed", truncated: true, ended: "client", error: "recording stopped at the 4 MiB a stream may store" }),
    "TRUNCATED · the client went away · recording stopped at the 4 MiB a stream may store",
  );
  // An open stream over the cap is marked while it is still being relayed.
  assert.equal(streamNote({ state: "open", truncated: true, ended: null, error: null }), "TRUNCATED");
  assert.equal(streamNote({ state: "closed", truncated: false, ended: "new-kind", error: null }), "new-kind");
});

test("polled events are added once, in order", () => {
  const shown = [event(1), event(2)];
  // Overlapping polls can bring the same events again.
  assert.deepEqual(appendEvents(shown, [event(2), event(3)]).map((e) => e.id), [1, 2, 3]);
  // Nothing new: the same array, so nothing re-renders.
  assert.equal(appendEvents(shown, [event(1), event(2)]), shown);
  assert.equal(appendEvents(shown, []), shown);
  assert.deepEqual(appendEvents([], [event(5)]).map((e) => e.id), [5]);
});

test("Replay says why reading a stream stopped", () => {
  assert.equal(readSummary({ count: 1, stopped: "wait", truncated: false }), "event stream: 1 event, stopped after the wait");
  assert.equal(readSummary({ count: 100, stopped: "max-events", truncated: false }), "event stream: 100 events, stopped at the event limit");
  assert.equal(readSummary({ count: 3, stopped: "cap", truncated: true }), "event stream: 3 events, stopped at what a stream may store (truncated)");
});
