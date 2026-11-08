import { test } from "node:test";
import assert from "node:assert/strict";
import type { FindingItem } from "../api.ts";
import { CLOSED, eventText, narrativeCommand, narrativeCredit, trailLine, groupKey, hostsOf, MARK_BATCH, markCommands, matchesFinding, NO_FILTER, noteBy, noteCommand, retestCommand, STATES } from "./findingsFilter.ts";

const item = (over: Partial<FindingItem>): FindingItem => ({
  id: 1,
  alert_ref: "10037",
  name: "Server Leaks Information via X-Powered-By",
  risk: "low",
  confidence: "medium",
  host: "app.test",
  method: "GET",
  url: "https://app.test/login?next=/",
  param: "",
  evidence: "X-Powered-By: PHP/5.1",
  hits: 1,
  history_id: 1,
  state: "open",
  source: "passive",
  ...over,
});

test("every word must match, in any case and field", () => {
  const f = item({});
  assert.ok(matchesFinding(f, NO_FILTER));
  assert.ok(matchesFinding(f, { ...NO_FILTER, text: "php LOGIN" }));
  assert.ok(matchesFinding(f, { ...NO_FILTER, text: "10037" }));
  assert.ok(matchesFinding(f, { ...NO_FILTER, text: "#1" }));
  assert.ok(matchesFinding(item({ state: "false_positive" }), { ...NO_FILTER, text: "false positive" }));
  assert.ok(!matchesFinding(f, { ...NO_FILTER, text: "php admin" }));
});

test("source and host narrow the list", () => {
  const f = item({});
  assert.ok(matchesFinding(f, { ...NO_FILTER, source: "passive", host: "app.test" }));
  assert.ok(!matchesFinding(f, { ...NO_FILTER, source: "manual" }));
  assert.ok(!matchesFinding(f, { ...NO_FILTER, host: "api.test" }));
  assert.deepEqual(hostsOf([item({ host: "b.test" }), f, item({ host: "b.test" }), item({ host: "" })]), ["app.test", "b.test"]);
});

test("bulk triage runs in batches and notes travel as one argument", () => {
  assert.deepEqual(markCommands([3, 4], "confirmed"), [["findings", "mark", "3", "4", "--state", "confirmed"]]);
  const many = Array.from({ length: MARK_BATCH + 1 }, (_, i) => i + 1);
  const cmds = markCommands(many, "false_positive");
  assert.equal(cmds.length, 2);
  assert.deepEqual(cmds[1], ["findings", "mark", String(MARK_BATCH + 1), "--state", "false_positive"]);
  assert.deepEqual(markCommands([], "open"), []);
  // A note that starts with a dash is still the note, not a flag; an empty one clears it.
  assert.deepEqual(noteCommand(5, " --state open "), ["findings", "mark", "5", "--note=--state open"]);
  assert.deepEqual(noteCommand(5, "  "), ["findings", "mark", "5", "--note="]);
});

test("who wrote a note is said in words", () => {
  assert.equal(noteBy("mcp", null), "by an agent (via MCP)");
  assert.equal(noteBy(null, null), "");
  assert.ok(noteBy("gui", "2026-11-05T10:00:00Z").startsWith("by the desktop app on "));
});

test("findings group by issue, and retests say when they may change data", () => {
  assert.equal(groupKey(item({ issue_id: 4 })), "issue:4");
  assert.equal(groupKey(item({ issue_id: null })), "alert:10037");
  assert.deepEqual(retestCommand(7), ["findings", "retest", "7"]);
  assert.deepEqual(retestCommand(7, true), ["findings", "retest", "7", "--allow-unsafe"]);
  assert.ok(STATES.every((s) => s.id === "open" || s.id === "confirmed" || s.id === "retest_pending" || CLOSED.has(s.id)));
});

test("timeline events read as sentences", () => {
  const e = (over: object) => ({ id: 1, time: "", kind: "state", old: null, new: null, text: null, by: "", history_id: null, ...over });
  assert.equal(eventText(e({ old: "open", new: "false_positive" })), "Marked false positive (was open)");
  assert.equal(eventText(e({ kind: "created", history_id: 3 })), "Found in history #3");
  assert.equal(eventText(e({ kind: "risk", old: "high", new: "low", history_id: 9 })), "Risk high → low (history #9)");
  assert.equal(eventText(e({ kind: "note", text: "" })), "Note cleared");
  assert.equal(eventText(e({ kind: "retest", new: "not_reproduced", text: "GET /a" })), "Retest: not reproduced (GET /a)");
  assert.equal(eventText(e({ kind: "ticket", new: "github", text: "https://github.com/o/r/issues/3" })), "GitHub ticket filed: https://github.com/o/r/issues/3");
  assert.equal(eventText(e({ kind: "regressed", history_id: 9 })), "Seen again after it was fixed (history #9): open again");
  assert.equal(eventText(e({ kind: "moved", old: "1", new: "2" })), "Moved from issue #1 to #2");
});

test("write-ups and agent trails read as sentences", () => {
  assert.deepEqual(narrativeCommand(3, " text "), ["findings", "issue", "narrative", "3", "--text=text"]);
  const n = { text: "x", hash: "00", origin: "mcp", at: null, reviewed_origin: null, reviewed_at: null };
  assert.equal(narrativeCredit(n), "Drafted by an agent (via MCP); not reviewed, so reports leave it out.");
  assert.ok(narrativeCredit({ ...n, reviewed_origin: "gui", reviewed_at: "2026-11-06T10:00:00Z" }).includes("reviewed by the desktop app"));
  assert.equal(trailLine({ agent_involved: false, requests_total: 0, reviewed_by: null, reviewed_at: null }), "");
  assert.equal(trailLine({ agent_involved: true, requests_total: 1, reviewed_by: null, reviewed_at: null }), "An agent sent 1 request for this finding; no person has looked at it since.");
});
