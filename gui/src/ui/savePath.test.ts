import { test } from "node:test";
import assert from "node:assert/strict";
import { saveFailure, savePath } from "./savePath.ts";

test("only a file the save dialog asked about is replaced", () => {
  assert.deepEqual(savePath("/a/t.HAR", "har", true), { path: "/a/t.HAR", overwrite: true });
  // The dialog asked about /a/t, not the name the app made.
  assert.deepEqual(savePath("/a/t", "har", true), { path: "/a/t.har", overwrite: false });
  // A typed path was never asked about.
  assert.deepEqual(savePath("/a/t.json", "json", false), { path: "/a/t.json", overwrite: false });
  assert.deepEqual(savePath("/a/t.har.json", "har", true), { path: "/a/t.har.json.har", overwrite: false });
});

test("a kept file is said so in the app's words; other errors as they are", () => {
  const kept = { kind: "conflict", message: "conflict: /a/t.har already exists; pass --force to overwrite it" };
  assert.equal(saveFailure(kept, "/a/t.har"), "/a/t.har already exists and was kept: choose another name.");
  assert.equal(saveFailure({ kind: "io", message: "permission denied" }, "/a/t.har"), "permission denied");
});
