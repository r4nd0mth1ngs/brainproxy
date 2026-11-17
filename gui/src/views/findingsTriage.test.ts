import { test } from "node:test";
import assert from "node:assert/strict";
import { bindProblem, normalize } from "../ui/chords.ts";
import { conflicts } from "../ui/actions.ts";
import { STATES } from "./findingsFilter.ts";
import type { FindingEvent } from "../api.ts";
import { eventText } from "./findingsFilter.ts";
import {
  acceptCommand,
  afterMark,
  DISMISSED_MAX,
  draftOf,
  dropDraft,
  NEXT_FINDING,
  parseDismissed,
  pendingSuggestions,
  PREVIOUS_FINDING,
  stepFinding,
  TRIAGE_KEYS,
  withDismissed,
  withDraft,
} from "./findingsTriage.ts";

test("next and previous walk the list and stop at its ends", () => {
  const order = [4, 9, 2];
  assert.equal(stepFinding(order, 4, 1), 9);
  assert.equal(stepFinding(order, 9, 1), 2);
  assert.equal(stepFinding(order, 2, 1), 2);
  assert.equal(stepFinding(order, 9, -1), 4);
  assert.equal(stepFinding(order, 4, -1), 4);
});

test("with nothing open, or the open finding filtered out, next starts at the top and previous at the bottom", () => {
  assert.equal(stepFinding([4, 9, 2], null, 1), 4);
  assert.equal(stepFinding([4, 9, 2], null, -1), 2);
  assert.equal(stepFinding([4, 9, 2], 77, 1), 4);
  assert.equal(stepFinding([], null, 1), null);
});

test("after a mark the next finding opens, or the previous one at the end of the list", () => {
  assert.equal(afterMark([4, 9, 2], 4), 9);
  assert.equal(afterMark([4, 9, 2], 2), 9);
  assert.equal(afterMark([4], 4), null);
  assert.equal(afterMark([4, 9], 5), 4);
  assert.equal(afterMark([], 5), null);
});

test("every triage key marks a known state, with a chord Settings accepts", () => {
  const states = new Set(STATES.map((s) => s.id));
  for (const k of TRIAGE_KEYS) {
    assert.ok(states.has(k.state), k.state);
    assert.equal(normalize(k.keys!, false), k.keys);
    assert.equal(bindProblem(k.keys!), null);
    assert.equal(k.where, "findings");
  }
  for (const id of ["confirmed", "false_positive", "accepted_risk", "fixed"]) assert.ok(TRIAGE_KEYS.some((k) => k.state === id), id);
});

test("the Findings keys don't clash with each other", () => {
  assert.equal(conflicts([...TRIAGE_KEYS, NEXT_FINDING, PREVIOUS_FINDING], {}).size, 0);
});

test("a draft is kept per finding until it is saved, and typing back to the saved text drops it", () => {
  let d: ReadonlyMap<number, string> = new Map();
  d = withDraft(d, 5, "half a sent", "");
  d = withDraft(d, 6, "other", "saved");
  // Another finding opened and back: each shows its own draft, or its saved note.
  assert.equal(draftOf(d, 5, ""), "half a sent");
  assert.equal(draftOf(d, 6, "saved"), "other");
  assert.equal(draftOf(d, 7, "its note"), "its note");
  assert.equal(withDraft(d, 6, "saved", "saved").has(6), false);
  // Saved: dropped, unless more was typed while it saved.
  assert.equal(dropDraft(d, 5, "half a sent").has(5), false);
  assert.equal(dropDraft(d, 5, "half a").get(5), "half a sent");
  assert.equal(dropDraft(d, 9, "x"), d);
});

const ev = (id: number, kind: string, over: Partial<FindingEvent> = {}): FindingEvent => ({ id, time: "2026-11-17T10:00:00Z", kind, old: null, new: null, text: null, by: "via MCP (an agent)", history_id: null, ...over });

test("an agent's suggestion waits until the state or note changes after it, or it is dismissed", () => {
  const s1 = ev(2, "suggested", { old: "open", new: "false_positive", text: "a CDN header" });
  const s2 = ev(4, "suggested", { old: "confirmed", text: "retest after the deploy" });
  const events = [ev(1, "created"), s1, ev(3, "state", { old: "open", new: "confirmed" }), s2, ev(5, "retest")];
  assert.deepEqual(pendingSuggestions(events, new Set()).map((e) => e.id), [4]);
  assert.deepEqual(pendingSuggestions(events, new Set([4])), []);
  assert.deepEqual(pendingSuggestions([s1], new Set()).map((e) => e.id), [2]);
  assert.equal(eventText(s1), 'Suggested: mark it false positive, with the note "a CDN header" (it was open)');
  assert.equal(eventText(s2), 'Suggested: note "retest after the deploy" (it was confirmed)');
});

test("accepting applies the suggestion only while the finding is in the state on screen", () => {
  const s = ev(2, "suggested", { old: "open", new: "false_positive", text: "a CDN header" });
  assert.deepEqual(acceptCommand(9, s, "open"), ["findings", "mark", "9", "--state", "false_positive", "--note=a CDN header", "--if-state", "open"]);
  assert.deepEqual(acceptCommand(9, ev(3, "suggested", { new: "confirmed" }), "open"), ["findings", "mark", "9", "--state", "confirmed", "--if-state", "open"]);
  assert.equal(acceptCommand(9, ev(3, "suggested"), "open"), null);
});

test("dismissed suggestions are remembered, newest kept, and a damaged store reads as none", () => {
  assert.deepEqual([...parseDismissed(null)], []);
  assert.deepEqual([...parseDismissed("not json")], []);
  assert.deepEqual([...parseDismissed('{"a":1}')], []);
  assert.deepEqual([...parseDismissed('[3, "x", 1.5, 7]')], [3, 7]);
  const { set, text } = withDismissed(new Set([3, 7]), 3);
  assert.deepEqual([...set], [7, 3]);
  assert.deepEqual([...parseDismissed(text)], [7, 3]);
  const full = new Set(Array.from({ length: DISMISSED_MAX }, (_, i) => i));
  const after = withDismissed(full, 99999).set;
  assert.equal(after.size, DISMISSED_MAX);
  assert.ok(after.has(99999) && !after.has(0));
});
