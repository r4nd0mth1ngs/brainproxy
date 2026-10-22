import { test } from "node:test";
import assert from "node:assert/strict";
import { describeUpdate, guidedChecks, quickCheckArgs, updateDue, type FeedState, type FeedUpdate } from "./feed.ts";

const feed = (checks: number, passive: number): FeedState => ({
  repository: "https://github.com/r4nd0mth1ngs/brainproxy", ref: "main", commit: "abc", source: "github", updated_unix: 1, serial: 2,
  key: "k", files: checks, checks, passive, quick_checks: [], skipped: [],
});

test("guided scans add the feed's active checks and, from Standard, Nuclei", () => {
  assert.deepEqual(guidedChecks("quick", true, null), { args: [], text: "" });
  assert.deepEqual(guidedChecks("quick", true, feed(2, 1)).args, ["--checks", "brainproxy"]);
  // Only passive checks: nothing for an active scan to run.
  assert.deepEqual(guidedChecks("quick", false, feed(1, 1)).args, []);
  assert.deepEqual(guidedChecks("standard", true, feed(2, 1)).args, ["--checks", "brainproxy,nuclei", "--check-severity", "high", "--check-include-tags", "eol"]);
  const t = guidedChecks("thorough", true, undefined);
  assert.deepEqual(t.args, ["--checks", "nuclei", "--check-severity", "medium", "--check-include-tags", "eol"]);
  assert.equal(t.text, "Nuclei templates, medium severity and above, plus end-of-life checks");
  assert.equal(guidedChecks("standard", false, feed(3, 0)).text, "brainproxy's own checks");
});

test("a quick check runs that one feed check", () => {
  assert.deepEqual(quickCheckArgs("CVE-1"), ["--no-rules", "--checks=brainproxy", "--check-ids=CVE-1", "--check-exclude-tags="]);
});

test("update summaries name what changed", () => {
  const u: FeedUpdate = { ...feed(3, 1), unchanged: false, added: [{ file: "http/a.yaml", id: "a" }], changed: [{ file: "passive/b.yaml" }], removed: [] };
  assert.equal(describeUpdate(u), "brainproxy checks updated (3 checks). new: a; updated: passive/b.yaml.");
  assert.equal(describeUpdate({ ...u, unchanged: true }), "brainproxy checks are up to date.");
});

test("the daily update is due after a day", () => {
  const day = 24 * 3600 * 1000;
  assert.ok(updateDue(null, 5));
  assert.ok(!updateDue(1000, 1000 + day - 1));
  assert.ok(updateDue(1000, 1000 + day));
});
