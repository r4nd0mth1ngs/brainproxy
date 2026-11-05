import { test } from "node:test";
import assert from "node:assert/strict";
import { byText, changeText, narrowedNotice, reroutedNotice, reviewCommands, sameFlagged, type RecordingChange } from "./recording.ts";

const change = (c: Partial<RecordingChange>): RecordingChange => ({
  time: "2026-01-31T12:00:00.000Z",
  by: "mcp",
  setting: "scope",
  narrowed: true,
  summary: "include: added ^a\\.test$",
  ...c,
});
const when = (t: string) => t.slice(11, 16);

test("an agent's narrowing gets a notice saying when and what", () => {
  assert.equal(narrowedNotice([change({})], when), "Recording narrowed by an agent at 12:00: recording scope: include: added ^a\\.test$");
  const both = narrowedNotice([change({ setting: "passthrough", summary: "added b.test", time: "2026-01-31T13:05:00.000Z" }), change({})], when);
  assert.equal(both, "Recording narrowed by an agent at 13:05: TLS pass-through list: added b.test\nRecording narrowed by an agent at 12:00: recording scope: include: added ^a\\.test$");
});

test("no notice without an agent's narrowing", () => {
  assert.equal(narrowedNotice([], when), null);
  assert.equal(narrowedNotice(undefined, when), null);
  assert.equal(narrowedNotice(null, when), null);
  // Only an agent's narrowing is flagged; anything else that turns up isn't one.
  assert.equal(narrowedNotice([change({ by: "gui" }), change({ narrowed: false })], when), null);
});

test("an agent's routing change gets its own notice", () => {
  const up = change({ setting: "upstream", narrowed: false, summary: "added * via http://192.0.2.7:3128" });
  assert.equal(reroutedNotice([up], when), "Routing changed by an agent at 12:00: upstream proxies: added * via http://192.0.2.7:3128");
  assert.equal(reroutedNotice([change({ setting: "hosts", by: "gui", narrowed: false })], when), null);
  assert.equal(reroutedNotice(undefined, when), null);
  assert.equal(changeText(change({ setting: "client_certs", summary: "added a.test: c.pem" })), "client certificates: added a.test: c.pem");
});

test("changes in words", () => {
  assert.equal(changeText(change({ setting: "passthrough", summary: "removed b.test" })), "TLS pass-through list: removed b.test");
  assert.deepEqual(["mcp", "gui", "cli", "x"].map(byText), ["an agent", "the app", "the command line", "an unknown origin"]);
});

test("marking an agent's narrowing as reviewed saves each flagged setting unchanged", () => {
  assert.deepEqual(reviewCommands([], ["a.test"]), []);
  assert.deepEqual(reviewCommands([change({})], []), [["scope", "add"]]);
  assert.deepEqual(reviewCommands([change({ setting: "passthrough" })], ["a.test", "b.test"]), [["connection", "passthrough", "add", "--", "a.test"]]);
  assert.deepEqual(reviewCommands([change({ setting: "passthrough" }), change({})], []), [["scope", "add"], ["connection", "passthrough", "clear"]]);
});

test("keeping it as it is only approves the narrowing shown", () => {
  const a = change({});
  const b = change({ setting: "passthrough", summary: "added b.test", time: "2026-01-31T13:05:00.000Z" });
  assert.equal(sameFlagged([a, b], [b, a]), true);
  assert.equal(sameFlagged([], undefined), true);
  // The agent narrowed the same setting again since: the flag now holds a change not shown.
  assert.equal(sameFlagged([a], [change({ summary: "exclude: added .*", time: "2026-01-31T12:01:00.000Z" })]), false);
  // Or another setting.
  assert.equal(sameFlagged([a], [a, b]), false);
  // Or the flag went (a person kept it elsewhere): nothing to approve.
  assert.equal(sameFlagged([a], []), false);
});
