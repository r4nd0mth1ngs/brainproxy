import { test } from "node:test";
import assert from "node:assert/strict";
import { attacksPaths, depthArgs } from "./wizardDepths.ts";

test("Standard and Thorough attack URL paths, Quick stays light", () => {
  assert.equal(attacksPaths("quick"), false);
  assert.equal(attacksPaths("standard"), true);
  assert.equal(attacksPaths("thorough"), true);
});

test("each depth is a scan active preset", () => {
  assert.deepEqual(depthArgs("quick"), ["--preset", "quick"]);
  assert.deepEqual(depthArgs("thorough"), ["--preset", "thorough"]);
});
