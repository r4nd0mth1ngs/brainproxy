import { test } from "node:test";
import assert from "node:assert/strict";
import { focusLost, nextFocus } from "./dialogFocus.ts";

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

test("a closed dialog gives focus back only when it was lost, not when the next dialog took it", () => {
  const body = {} as Element;
  const field = {} as Element;
  assert.equal(focusLost(null, body), true);
  assert.equal(focusLost(body, body), true);
  assert.equal(focusLost(field, body), false);
});
