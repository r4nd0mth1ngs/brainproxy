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
  runRating,
  withWholeIssue,
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
  // The timeline reads this text as a cleared rating, so a rating doesn't get it as its reason.
  assert.match(rateProblem(form({ risk: "low", reason: " The scanner's rating again " }))!, /cleared/);
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
  assert.deepEqual(rateCommands([4], form({ risk: "high", reason: "r", wholeIssue: true }), 7), [["findings", "rate", "--issue", "7", "--risk", "high", "--reason=r"]]);
});

test("ticking the whole issue starts from the issue's own rating, never the finding's", () => {
  const one = rateFormFor([{ risk: "medium", confidence: "high", rated_origin: "gui", rated_reason: "mine" }]);
  // Not rated as a whole: each part left as it is, so a reason alone sends nothing of this
  // finding's rating to the rest of the issue (it's refused until a part is picked).
  const fresh = withWholeIssue(one, true, null);
  assert.deepEqual([fresh.risk, fresh.confidence, fresh.reason, fresh.wholeIssue], ["", "", "mine", true]);
  assert.match(rateProblem(fresh)!, /Pick/);
  // Already rated low as a whole: changing the confidence sends the risk too, so set_rating,
  // which stores what it is sent, keeps the issue's risk for findings found later.
  const issue = { risk: "low" as const, confidence: null, reason: "staging", origin: "gui", at: null };
  const rated = withWholeIssue(one, true, issue);
  assert.deepEqual([rated.risk, rated.confidence, rated.reason], ["low", "", "staging"]);
  assert.deepEqual(rateCommands([1], { ...rated, confidence: "high" }, 7), [["findings", "rate", "--issue", "7", "--risk", "low", "--confidence", "high", "--reason=staging"]]);
  // Even when what's picked equals where the finding started, the whole issue gets exactly that.
  assert.deepEqual(ratingParts({ ...rated, risk: "medium", confidence: "" }), { risk: "medium", confidence: "" });
  // Unticked: the finding's own rating again.
  const back = withWholeIssue(rated, false, issue);
  assert.deepEqual([back.risk, back.confidence, back.wholeIssue], ["medium", "high", false]);
});

test("rating calls stop at the first failure and count only the findings of the calls that went through", async () => {
  const cmds = rateCommands(
    Array.from({ length: RATE_BATCH + 3 }, (_, i) => i + 1),
    form({ risk: "low", reason: "r" }),
  );
  const calls: string[][] = [];
  const r = await runRating(cmds, async (args) => {
    calls.push(args);
    if (calls.length === 2) throw new Error("finding 501 was removed");
    return { ids: [1, 2, 3] };
  });
  assert.deepEqual(r, { changed: 3, sent: RATE_BATCH, done: 1, error: "finding 501 was removed" });
  // So the toast doesn't count the unsent findings as ones that already had the rating.
  assert.equal(ratedToast(r.changed, r.sent, false), `Rated 3 findings. ${RATE_BATCH - 3} findings already had this rating.`);
  const first = await runRating(cmds, async () => Promise.reject(new Error("no")));
  assert.deepEqual(first, { changed: 0, sent: 0, done: 0, error: "no" });
  // An issue's call names no ids: nothing is counted as sent, but it went through.
  const whole = await runRating(rateCommands([], form({ risk: "low", reason: "r", wholeIssue: true }), 7), async () => ({ ids: [4] }));
  assert.deepEqual(whole, { changed: 1, sent: 0, done: 1, error: null });
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
  // A whole issue is rated even when none of its findings changed.
  assert.equal(ratedToast(0, 0, false, 0, 7), "Issue #7 is rated as a whole: 0 findings of it changed, and findings a later scan adds take the rating.");
});

test("the rating key is a Findings key that clashes with no triage key", () => {
  assert.equal(RATE_FINDING.where, "findings");
  assert.equal(conflicts([...TRIAGE_KEYS, NEXT_FINDING, PREVIOUS_FINDING, RATE_FINDING], {}).size, 0);
});
