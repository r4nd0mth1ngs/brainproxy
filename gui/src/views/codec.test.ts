import { test } from "node:test";
import assert from "node:assert/strict";
import { KINDS, smartNote, smartSteps } from "./codec.ts";

test("Smart decode's steps become editable decode steps", () => {
  assert.deepEqual(smartSteps(["url", "base64", "gzip"]), [
    { op: "decode", kind: "url" },
    { op: "decode", kind: "base64" },
    { op: "decode", kind: "gzip" },
  ]);
  assert.deepEqual(smartSteps(["jwt"]), [{ op: "decode", kind: "jwt" }]);
});

test("unknown or malformed steps are dropped", () => {
  assert.deepEqual(smartSteps(["auto", 3, "zstd", "hex"]), [{ op: "decode", kind: "hex" }]);
  assert.deepEqual(smartSteps(undefined), []);
  assert.deepEqual(smartSteps("url"), []);
});

test("the note names the layers found, or says there were none", () => {
  assert.equal(smartNote([]), "Nothing to decode: no URL, Base64, hex, HTML, JWT, gzip, or zlib layer found.");
  assert.equal(smartNote(smartSteps(["base64"])), "Found 1 layer: base64");
  assert.equal(smartNote(smartSteps(["url", "base64", "gzip"])), "Found 3 layers: url → base64 → gzip");
});

test("compression is offered both ways; brotli only decodes", () => {
  for (const k of ["gzip", "zlib", "deflate"]) {
    assert.ok(KINDS.encode.includes(k) && KINDS.decode.includes(k), k);
  }
  assert.ok(KINDS.decode.includes("brotli") && !KINDS.encode.includes("brotli"));
  assert.ok(!KINDS.decode.includes("auto"));
});
