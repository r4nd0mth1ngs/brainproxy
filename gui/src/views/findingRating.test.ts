import { test } from "node:test";
import assert from "node:assert/strict";
import { conflicts } from "../ui/actions.ts";
import { eventText } from "./findingsFilter.ts";
import { NEXT_FINDING, PREVIOUS_FINDING, TRIAGE_KEYS } from "./findingsTriage.ts";
import {
  clearCommands,
  issueRatingLine,
  RATE_BATCH,
  RATE_FINDING,
  ratable,
  ratableOf,
  rateCommands,
  ratedEventText,
  ratedLine,
  ratedTitle,
  ratedToast,
  rateFormFor,
  rateProblem,
  ratingOf,
  ratingParts,
  type RateForm,
} from "./findingRating.ts";

const form = (p: Partial<RateForm>): RateForm => ({ risk: "", confidence: "", reason: "", wholeIssue: false, ...p });

test("a rating is read from the list's rated object or from findings show's columns", () => {
  const rated = { scanner_risk: "medium" as const, scanner_confidence: "high", reason: "internal only", origin: "gui", at: "2026-11-19T10:00:00Z", by: "from the desktop app" };
  assert.deepEqual(ratingOf({ rated }), rated);
  assert.equal(ratingOf({ rated: null }), null);
  assert.equal(ratingOf({}), null);
  assert.deepEqual(ratingOf({ rated_origin: "cli", rated_reason: "why", rated_at: null, scanner_risk: "high", scanner_confidence: "low" }), {
    scanner_risk: "high",
    scanner_confidence: "low",
    reason: "why",
    origin: "cli",
    at: null,
  });
  // The scanner's columns alone (no person's rating) are no rating.
  assert.equal(ratingOf({ rated_origin: null, scanner_risk: "high" }), null);
});

test("only scanner findings that are still there can be rated", () => {
  assert.ok(ratable({ source: "passive", state: "open" }));
  assert.ok(ratable({ source: "active", state: "false_positive" }));
  assert.ok(!ratable({ source: "manual", state: "open" }));
  assert.ok(!ratable({ source: "passive", state: "removed" }));
  const picked = [
    { id: 1, source: "passive", state: "open" },
    { id: 2, source: "manual", state: "open" },
    { id: 3, source: "authz", state: "confirmed" },
  ];
  const { ids, skipped } = ratableOf(picked);
  assert.deepEqual(
    ids.map((f) => f.id),
    [1, 3],
  );
  assert.equal(skipped, 1);
});

test("one finding's form starts from its rating; several start with each part left as it is", () => {
  const one = rateFormFor([{ risk: "medium", confidence: "high", rated_origin: "gui", rated_reason: "behind VPN" }]);
  assert.deepEqual(one, { risk: "medium", confidence: "high", reason: "behind VPN", wholeIssue: false, start: { risk: "medium", confidence: "high" } });
  const scanner = rateFormFor([{ risk: "low", confidence: "medium" }]);
  assert.equal(scanner.reason, "");
  // A confidence the dialog doesn't offer starts unset rather than sent back.
  assert.equal(rateFormFor([{ risk: "low", confidence: "confirmed" }]).confidence, "");
  assert.deepEqual(
    rateFormFor([
      { risk: "low", confidence: "medium" },
      { risk: "high", confidence: "high" },
    ]),
    form({}),
  );
});

test("a rating needs a part and a reason", () => {
  assert.match(rateProblem(form({ reason: "x" }))!, /risk/);
  assert.match(rateProblem(form({ risk: "low", reason: "  " }))!, /why/i);
  assert.equal(rateProblem(form({ risk: "low", reason: "x" })), null);
  assert.equal(rateProblem(form({ confidence: "low", reason: "x" })), null);
});

test("only the parts changed from where one finding started are sent", () => {
  const start = { risk: "medium" as const, confidence: "high" as const };
  assert.deepEqual(ratingParts(form({ risk: "low", confidence: "high", start })), { risk: "low", confidence: "" });
  assert.deepEqual(ratingParts(form({ risk: "medium", confidence: "low", start })), { risk: "", confidence: "low" });
  // Nothing changed (a new reason, or the scanner's rating kept as the person's): both.
  assert.deepEqual(ratingParts(form({ risk: "medium", confidence: "high", start })), { risk: "medium", confidence: "high" });
  // Several findings: as picked.
  assert.deepEqual(ratingParts(form({ risk: "low" })), { risk: "low", confidence: "" });
});

test("rating commands carry the ids in batches, the parts given and the reason as one argument", () => {
  assert.deepEqual(rateCommands([4, 9], form({ risk: "low", confidence: "high", reason: " behind a VPN " })), [
    ["findings", "rate", "4", "9", "--risk", "low", "--confidence", "high", "--reason=behind a VPN"],
  ]);
  // A reason that looks like a flag stays the reason.
  assert.deepEqual(rateCommands([1], form({ confidence: "low", reason: "--clear" })), [["findings", "rate", "1", "--confidence", "low", "--reason=--clear"]]);
  const many = Array.from({ length: RATE_BATCH + 2 }, (_, i) => i + 1);
  const cmds = rateCommands(many, form({ risk: "info", reason: "noise" }));
  assert.equal(cmds.length, 2);
  assert.equal(cmds[0].length, 2 + RATE_BATCH + 3);
  assert.deepEqual(cmds[1], ["findings", "rate", String(RATE_BATCH + 1), String(RATE_BATCH + 2), "--risk", "info", "--reason=noise"]);
  // A whole issue: by issue, not by id, so findings it gets later take the rating too.
  assert.deepEqual(rateCommands([4], form({ risk: "high", confidence: "medium", reason: "r", start: { risk: "medium", confidence: "medium" } }), 7), [
    ["findings", "rate", "--issue", "7", "--risk", "high", "--reason=r"],
  ]);
});

test("clearing gives the scanner's rating back by id, or ends an issue's rating", () => {
  assert.deepEqual(clearCommands([3, 5]), [["findings", "rate", "3", "5", "--clear"]]);
  assert.deepEqual(clearCommands([3], 2), [["findings", "rate", "--issue", "2", "--clear"]]);
  assert.equal(clearCommands(Array.from({ length: RATE_BATCH * 2 + 1 }, (_, i) => i)).length, 3);
  assert.deepEqual(clearCommands([]), []);
});

test("a rating says whose it is, why, and what the scanner said", () => {
  const r = { scanner_risk: "medium" as const, scanner_confidence: "high", reason: "only reachable inside", origin: "gui", at: null };
  assert.equal(ratedLine(r), "Rated by a person from the desktop app: only reachable inside. The scanner said medium risk, high confidence.");
  assert.equal(ratedLine({ ...r, origin: "cli", reason: null }), "Rated by a person from the command line. The scanner said medium risk, high confidence.");
  assert.equal(
    ratedTitle({ risk: "low", confidence: "high" }, r),
    "Rated low risk, high confidence by a person; the scanner said medium risk, high confidence. only reachable inside",
  );
  assert.equal(
    issueRatingLine(7, { risk: "low", confidence: null, reason: "staging", origin: "cli", at: null }),
    "Issue #7 is rated low risk as a whole from the command line: staging. Findings it gets later take this rating.",
  );
});

test("rated timeline events read as a rating, or as the scanner's rating back", () => {
  assert.equal(ratedEventText({ old: "medium/high", new: "low/high", text: "internal" }), "Rated low risk, high confidence (was medium risk, high confidence): internal");
  assert.equal(
    ratedEventText({ old: "low/high", new: "medium/high", text: "the scanner's rating again" }),
    "The scanner's rating again: medium risk, high confidence (was low risk, high confidence)",
  );
  assert.equal(ratedEventText({ old: "medium/high", new: "high/high", text: "rated as issue 3 was: prod" }), "Rated high risk, high confidence (was medium risk, high confidence): rated as issue 3 was: prod");
  // The Findings timeline uses it.
  const e = { id: 1, time: "2026-11-19T10:00:00Z", kind: "rated", old: "medium/high", new: "low/high", text: "x", by: "", history_id: null };
  assert.equal(eventText(e), ratedEventText(e));
});

test("the toast counts what changed, what already had the rating and what was left out", () => {
  assert.equal(ratedToast(3, 3, false), "Rated 3 findings.");
  assert.equal(ratedToast(1, 3, false), "Rated 1 finding. 2 findings already had this rating.");
  assert.equal(ratedToast(2, 2, false, 1), "Rated 2 findings. 1 finding added by hand was left out: edit its risk instead.");
  assert.equal(ratedToast(2, 2, false, 3), "Rated 2 findings. 3 findings added by hand were left out: edit their risk instead.");
  assert.equal(ratedToast(1, 4, true), "1 finding has the scanner's rating again.");
  assert.equal(ratedToast(0, 4, true), "No finding was rated: nothing changed.");
});

test("the rating key is a Findings key that clashes with no triage key", () => {
  assert.equal(RATE_FINDING.where, "findings");
  assert.equal(conflicts([...TRIAGE_KEYS, NEXT_FINDING, PREVIOUS_FINDING, RATE_FINDING], {}).size, 0);
});
