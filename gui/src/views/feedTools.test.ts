import { test } from "node:test";
import assert from "node:assert/strict";
import { OWN_KEY_NOTE, VALIDATE_LIMIT, keygenArgs, keygenText, signArgs, signProblem, signText, validateArgs, validateSummary, verifyArgs, verifyText } from "./feedTools.ts";

test("paths stay arguments, never flags", () => {
  assert.deepEqual(validateArgs(["/t/a.yaml", "-odd.yaml"]), ["checks", "validate", `--limit=${VALIDATE_LIMIT}`, "--", "/t/a.yaml", "-odd.yaml"]);
  assert.deepEqual(verifyArgs("/feed"), ["checks", "feed", "verify", "--", "/feed"]);
  assert.deepEqual(keygenArgs("/keys/-k"), ["checks", "feed", "keygen", "--out=/keys/-k"]);
  assert.deepEqual(signArgs("-feed", "/k.key"), ["checks", "feed", "sign", "--key=/k.key", "--", "-feed"]);
});

test("a validation says how many templates load, and why the others don't", () => {
  const files = [
    { file: "a.yaml", id: "a", ok: true },
    { file: "b.yaml", id: "b", ok: false, kind: "unsupported", reason: "a dns request" },
  ];
  const r = validateSummary({ ok: 1, not_loaded: 1, files, truncated: false });
  assert.equal(r.line, "1 of 2 templates load; 1 doesn't.");
  assert.deepEqual(r.problems, [files[1]]);
  assert.equal(validateSummary({ ok: 3, not_loaded: 0, files: [], truncated: false }).line, "All 3 templates load.");
  assert.equal(validateSummary({ ok: 1, not_loaded: 0, files: [], truncated: false }).line, "All 1 template loads.");
  assert.equal(validateSummary({ ok: 0, not_loaded: 0, files: [], truncated: false }).line, "No templates found there.");
  assert.match(validateSummary({ ok: 600, not_loaded: 2, files, truncated: true }).line, /Only the first 500 files are listed\.$/);
});

test("results say what was done, and a feed signed here is said not to verify", () => {
  assert.equal(verifyText({ files: 4, key_id: "bp-1" }), "4 files verified, signed by bp-1.");
  assert.equal(signText({ files: 1, key_id: "k2", dir: "/feed" }), "Signed 1 file in /feed with key k2 (feed.json and feed.sig written).");
  assert.match(keygenText({ key: "/k.key", key_id: "k2", public_key: "PUB" }), /^Private key saved to \/k\.key .* Public key k2: PUB$/);
  assert.match(OWN_KEY_NOTE, /won't verify/);
  assert.match(OWN_KEY_NOTE, /compiled in/);
  assert.equal(signProblem("", "/k"), "Choose the feed folder to sign");
  assert.equal(signProblem("/f", " "), "Choose the private key to sign with");
  assert.equal(signProblem("/f", "/k"), null);
});
