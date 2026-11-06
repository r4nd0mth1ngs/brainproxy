import { test } from "node:test";
import assert from "node:assert/strict";
import type { FindingItem } from "../api.ts";
import { hostsOf, MARK_BATCH, markCommands, matchesFinding, NO_FILTER, noteBy, noteCommand } from "./findingsFilter.ts";

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
