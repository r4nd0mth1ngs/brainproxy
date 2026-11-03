import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { KINDS, SmartRuns, smartNote, smartSteps, smartStopped } from "./codec.ts";

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

test("the view offers the CLI's kinds, less auto", () => {
  // crates/core/src/codec.rs: ENCODINGS, DECODINGS, and HASHES.
  const rust = readFileSync(new URL("../../../crates/core/src/codec.rs", import.meta.url), "utf8");
  const list = (name: string) => {
    const m = rust.match(new RegExp(`pub const ${name}: &\\[&str\\] =\\s*&\\[([^\\]]*)\\]`));
    assert.ok(m, name);
    return [...m[1].matchAll(/"([^"]+)"/g)].map((k) => k[1]);
  };
  assert.deepEqual(KINDS.encode, list("ENCODINGS"));
  assert.deepEqual(KINDS.decode, list("DECODINGS").filter((k) => k !== "auto"));
  assert.deepEqual(KINDS.hash, list("HASHES"));
});

test("every layer Smart decode can find becomes a step", () => {
  const found = ["url", "percent", "html", "base64", "base64url", "hex", "jwt", "gzip", "zlib"];
  assert.deepEqual(smartSteps(found).map((s) => s.kind), found);
  assert.ok(smartSteps(found).every((s) => s.op === "decode"));
  assert.deepEqual(smartSteps([]), []);
  assert.deepEqual(smartSteps([null, { kind: "url" }, ["url"]]), []);
});

test("the note counts repeated layers", () => {
  assert.equal(smartNote(smartSteps(["url", "url"])), "Found 2 layers: url → url");
});

test("an edit drops a pending Smart decode; a new run supersedes an old one", () => {
  const runs = new SmartRuns();
  const first = runs.start();
  assert.ok(runs.current(first));
  runs.edit();
  assert.ok(!runs.current(first));
  const second = runs.start();
  const third = runs.start();
  assert.ok(!runs.current(second) && runs.current(third));
});

test("the Codec view edits steps only through editSteps, which drops a pending run", () => {
  const view = readFileSync(new URL("./Decoder.tsx", import.meta.url), "utf8");
  const edit = view.match(/const editSteps = [^]*?\n  \};/);
  assert.ok(edit && edit[0].includes("smartRuns.edit()"));
  // The only other setSteps is Smart decode applying its own, still current, answer.
  const rest = view.replace(edit[0], "");
  const calls = [...rest.matchAll(/setSteps\(/g)];
  assert.equal(calls.length, 1);
  assert.match(rest, /if \(!smartRuns\.current\(id\)\) return;[^]*?setSteps\(found\)/);
});

test("the note says why Smart decode stopped, when it isn't that nothing applied", () => {
  const steps = smartSteps(["base64", "gzip"]);
  assert.equal(smartNote(steps, "nothing"), "Found 2 layers: base64 → gzip");
  assert.equal(smartNote(steps, "json"), "Found 2 layers: base64 → gzip");
  assert.equal(smartNote([], "json"), "Nothing to decode: Smart decode leaves JSON as it is. The steps below are unchanged.");
  assert.equal(
    smartNote(smartSteps(Array(8).fill("base64")), "depth"),
    `Found 8 layers: ${Array(8).fill("base64").join(" → ")}. Stopped at the layer limit: more may remain (use the last output as input and run it again).`,
  );
  const error = "gzip: output is over the 16 MB limit (a decompression bomb?)";
  assert.equal(
    smartNote(smartSteps(["base64"]), { refused: "gzip", error }),
    `Found 1 layer: base64. Stopped before a layer it refused to unpack: ${error}`,
  );
  assert.match(smartNote([], { refused: "zlib", error: "zlib: too big" }), /^Nothing to decode: .*Stopped before a layer it refused to unpack: zlib: too big$/);
});

test("decode auto's stopped is read defensively", () => {
  assert.equal(smartStopped("json"), "json");
  assert.equal(smartStopped("depth"), "depth");
  assert.equal(smartStopped("nothing"), "nothing");
  assert.deepEqual(smartStopped({ refused: "gzip", error: "e" }), { refused: "gzip", error: "e" });
  for (const odd of [undefined, null, "later", 3, { refused: "gzip" }, { refused: 1, error: "e" }]) {
    assert.equal(smartStopped(odd), "nothing", JSON.stringify(odd));
  }
});

test("the Smart decode note is announced and the button shows a run in progress", () => {
  const view = readFileSync(new URL("./Decoder.tsx", import.meta.url), "utf8");
  assert.match(view, /aria-live="polite"/);
  // The live region is always rendered, not mounted with its text, so the change is announced.
  assert.doesNotMatch(view, /\{note && <span/);
  assert.match(view, /disabled=\{!input \|\| busy\}/);
  assert.match(view, /aria-busy=\{busy\}/);
  assert.match(view, /finally \{\s*setBusy\(false\);/);
});
