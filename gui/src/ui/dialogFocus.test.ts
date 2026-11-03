import { test } from "node:test";
import assert from "node:assert/strict";
import { nextFocus } from "./dialogFocus.ts";

test("Tab wraps around inside a dialog, both ways", () => {
  assert.equal(nextFocus(0, 3, false), 1);
  assert.equal(nextFocus(2, 3, false), 0);
  assert.equal(nextFocus(0, 3, true), 2);
  assert.equal(nextFocus(1, 3, true), 0);
  // Focus outside the dialog comes back to its first (or, going back, last) control.
  assert.equal(nextFocus(-1, 3, false), 0);
  assert.equal(nextFocus(-1, 3, true), 2);
  assert.equal(nextFocus(0, 1, true), 0);
  assert.equal(nextFocus(-1, 0, false), -1);
});
