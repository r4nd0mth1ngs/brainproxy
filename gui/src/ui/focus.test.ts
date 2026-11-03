import { test } from "node:test";
import assert from "node:assert/strict";
import { trapTab } from "./focus.ts";

test("Tab wraps around a dialog's controls and comes back in from outside", () => {
  // Inside the list the browser moves focus itself.
  assert.equal(trapTab(0, 3, false), null);
  assert.equal(trapTab(1, 3, true), null);
  // At either end it wraps to the other.
  assert.equal(trapTab(2, 3, false), 0);
  assert.equal(trapTab(0, 3, true), 2);
  // Focus that slipped outside comes back to the first, or with Shift the last.
  assert.equal(trapTab(-1, 3, false), 0);
  assert.equal(trapTab(-1, 3, true), 2);
  // One control keeps it; none leaves it to the browser.
  assert.equal(trapTab(0, 1, false), 0);
  assert.equal(trapTab(0, 1, true), 0);
  assert.equal(trapTab(-1, 0, false), null);
});
