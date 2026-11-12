import { test } from "node:test";
import assert from "node:assert/strict";
import { diffRows, needsUnsafe, sideCells, unsafeReason, verdictLine, verifyArgs, type Verify, type VerifySide } from "./verifyFinding.ts";

const side = (o: Partial<VerifySide>): VerifySide => ({
  request_history_id: 1,
  history_ids: [10],
  status: 200,
  length: 40,
  duration_ms: 3,
  evidence: 0,
  answered: 1,
  sends: [{ history_id: 10, status: 200, length: 40, duration_ms: 3, evidence: false }],
  ...o,
});

test("the command: repeats, an edited request on stdin, and a confirmed unsafe one", () => {
  assert.deepEqual(verifyArgs(7), ["findings", "verify", "7"]);
  assert.deepEqual(verifyArgs(7, { repeat: 3, edited: true, unsafe: true }), ["findings", "verify", "7", "--repeat", "3", "--request", "-", "--allow-unsafe"]);
  const refusal = "invalid input: finding 7's attack request is a POST, which may change data when sent again; pass --allow-unsafe to send it";
  assert.ok(needsUnsafe(refusal));
  assert.equal(unsafeReason(refusal), "finding 7's attack request is a POST, which may change data when sent again.");
});

test("each side in the strip's words", () => {
  assert.deepEqual(sideCells(side({})), { status: "200", length: "40 B", time: "3 ms", evidence: "no" });
  const repeated = side({ answered: 2, evidence: 1, sends: [side({}).sends[0], { history_id: 11, status: null, length: null, duration_ms: null, evidence: null, error: "timed out" }, side({}).sends[0]] });
  assert.deepEqual(sideCells(repeated), { status: "200 (1 failed)", length: "40 B", time: "3 ms", evidence: "1 of 2" });
  assert.deepEqual(sideCells(side({ status: null, length: null, duration_ms: null, evidence: null, answered: 0 })).status, "no response");
});

test("the verdict and the rows Diff compares", () => {
  const v = {
    id: 7, attack: "'", evidence: "SQL", baseline_from: "scan", edited_request: false, repeat: 1,
    without: side({ history_ids: [10, 12] }), with: side({ history_ids: [11, 13], status: 500 }),
    differences: { status_changed: true, length_delta: 5, duration_delta_ms: 0, evidence_only_with_payload: true, summary: ["status 200 without the payload, 500 with it", "+5 bytes with the payload"] },
  } satisfies Verify;
  assert.equal(verdictLine(v), "status 200 without the payload, 500 with it; +5 bytes with the payload");
  assert.deepEqual(diffRows(v), [12, 13]);
  assert.match(verdictLine({ ...v, differences: { ...v.differences, summary: [] } }), /^No difference/);
  assert.equal(diffRows({ ...v, with: side({ history_ids: [] }) }), null);
});
