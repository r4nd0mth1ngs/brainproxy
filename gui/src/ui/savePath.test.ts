import { test } from "node:test";
import assert from "node:assert/strict";
import { savePath } from "./savePath.ts";

test("only a file the save dialog asked about is replaced", () => {
  assert.deepEqual(savePath("/a/t.HAR", "har", true), { path: "/a/t.HAR", overwrite: true });
  // The dialog asked about /a/t, not the name the app made.
  assert.deepEqual(savePath("/a/t", "har", true), { path: "/a/t.har", overwrite: false });
  // A typed path was never asked about.
  assert.deepEqual(savePath("/a/t.json", "json", false), { path: "/a/t.json", overwrite: false });
  assert.deepEqual(savePath("/a/t.har.json", "har", true), { path: "/a/t.har.json.har", overwrite: false });
});
