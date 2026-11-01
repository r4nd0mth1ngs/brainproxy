import { test } from "node:test";
import assert from "node:assert/strict";
import { compareArgs, seenById } from "./compare.ts";

test("the comparison comes from the command, for every triage state", () => {
  assert.deepEqual(compareArgs(7), ["findings", "compare", "--scan", "7", "--state", "all", "--limit", "10000"]);
});

test("each finding gets its place in the comparison", () => {
  const seen = seenById({ new: [{ id: 1 }], unchanged: [{ id: 2 }, { id: 3 }], fixed: [{ id: 4 }, { id: null }] });
  assert.deepEqual([...seen], [[1, "new"], [2, "still"], [3, "still"], [4, "gone"]]);
  assert.equal(seenById(null).size, 0);
});
