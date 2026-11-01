import { test } from "node:test";
import assert from "node:assert/strict";
import { attacksPaths } from "./wizardDepths.ts";

test("Standard and Thorough attack URL paths, Quick stays light", () => {
  assert.equal(attacksPaths("quick"), false);
  assert.equal(attacksPaths("standard"), true);
  assert.equal(attacksPaths("thorough"), true);
});
