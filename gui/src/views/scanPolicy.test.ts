import { test } from "node:test";
import assert from "node:assert/strict";
import { DEFAULT_POLICY, describe, effective, enabledCount, nameProblem, optInConfirm, optInReason, optInsLeftOut, policyFacts, policyScanArgs, saveCommand, setEnabled, setRule } from "./scanPolicy.ts";

test("a rule takes what it sets and the policy the rest", () => {
  const p = { ...DEFAULT_POLICY, strength: "high" as const, rules: { "40018": { threshold: "high" as const } } };
  assert.deepEqual(effective(p, 40018), { enabled: true, strength: "high", threshold: "high", own: true });
  assert.deepEqual(effective(p, 40012), { enabled: true, strength: "high", threshold: "low", own: false });
});

test("setting a rule back to the policy's drops its entry", () => {
  let p = setRule(DEFAULT_POLICY, 40018, { strength: "insane" });
  p = setRule(p, 40018, { threshold: "medium" });
  assert.deepEqual(p.rules, { "40018": { strength: "insane", threshold: "medium" } });
  p = setRule(p, 40018, { strength: undefined });
  assert.deepEqual(p.rules, { "40018": { threshold: "medium" } });
  p = setRule(p, 40018, { threshold: "" });
  assert.deepEqual(p.rules, {});
  // The default policy is left as it was.
  assert.deepEqual(DEFAULT_POLICY.rules, {});
});

test("turning a rule on or off is kept only where it differs from the policy", () => {
  let p = setEnabled(DEFAULT_POLICY, 40012, false);
  assert.deepEqual(p.rules, { "40012": { enabled: false } });
  assert.equal(enabledCount(p, [{ id: 40012 }, { id: 40018 }]), 1);
  p = setEnabled(p, 40012, true);
  assert.deepEqual(p.rules, {});
  // With others off, a rule turned on is the one kept.
  const only = setEnabled({ ...DEFAULT_POLICY, enabled: false }, 40018, true);
  assert.deepEqual(only.rules, { "40018": { enabled: true } });
  assert.equal(enabledCount(only, [{ id: 40012 }, { id: 40018 }]), 1);
});

test("an opt-in rule is off unless the policy turns it on, and turning it on is kept", () => {
  assert.equal(effective(DEFAULT_POLICY, 40041, true).enabled, false);
  assert.equal(effective(DEFAULT_POLICY, 40041).enabled, true, "not known as opt-in: the policy's default");
  let p = setEnabled(DEFAULT_POLICY, 40041, true, true);
  assert.deepEqual(p.rules, { "40041": { enabled: true } });
  assert.equal(effective(p, 40041, true).enabled, true);
  p = setEnabled(p, 40041, false, true);
  assert.deepEqual(p.rules, {}, "off is its default");
  const rules = [{ id: 40012 }, { id: 40041, opt_in: true }];
  assert.equal(enabledCount(DEFAULT_POLICY, rules), 1);
  assert.equal(enabledCount(setEnabled(DEFAULT_POLICY, 40041, true, true), rules), 2);
});

test("an opt-in rule says why it is off, and asks before it is turned on", () => {
  assert.match(optInReason(40041), /stay on the server/);
  assert.match(optInReason(40023), /lock the account/);
  assert.match(optInReason(1), /change the site/);
  const [title, text] = optInConfirm({ id: 40041, name: "File Upload", opt_in: true });
  assert.equal(title, "Turn on File Upload?");
  assert.match(text, /^Rule 40041 is off unless turned on: it uploads test files/);
});

test("New scan says which opt-in rules it leaves out", () => {
  const rules = [
    { id: 40012, name: "XSS" },
    { id: 40023, name: "Possible Username Enumeration", opt_in: true },
    { id: 40041, name: "File Upload", opt_in: true },
  ];
  assert.deepEqual(optInsLeftOut(rules, "").map((r) => r.id), [40023, 40041]);
  assert.deepEqual(optInsLeftOut(rules, "40041, 40012"), [], "named rules are the only ones that run");
  const p = setEnabled(DEFAULT_POLICY, 40041, true, true);
  assert.deepEqual(optInsLeftOut(rules, " ", p).map((r) => r.id), [40023]);
});

test("a policy is saved as JSON on stdin, under its trimmed name", () => {
  const p = setRule(DEFAULT_POLICY, 40018, { strength: "high" });
  const c = saveCommand(" api ", p);
  assert.deepEqual(c.args, ["scan", "policy", "save", "api", "--json", "-"]);
  assert.deepEqual(JSON.parse(c.stdin), { enabled: true, strength: "medium", threshold: "low", rules: { "40018": { strength: "high" } } });
  assert.equal(nameProblem(" "), "Give the policy a name.");
  assert.equal(nameProblem("-x"), "A name can't start with -.");
  assert.equal(nameProblem("a\tb"), "A name can't hold control characters.");
  assert.equal(nameProblem("x".repeat(65)), "A name has at most 64 characters.");
  assert.equal(nameProblem("é".repeat(33)), "A name has at most 64 characters.");
  assert.equal(nameProblem("api"), null);
});

test("with a policy the scan takes its strength unless one is picked", () => {
  assert.deepEqual(policyScanArgs("", "high"), ["--strength=high"]);
  assert.deepEqual(policyScanArgs("", ""), ["--strength=medium"]);
  assert.deepEqual(policyScanArgs("api", ""), ["--policy=api"]);
  assert.deepEqual(policyScanArgs("api", "low"), ["--policy=api", "--strength=low"]);
});

test("a saved policy reads as one line", () => {
  const s = { name: "api", ...DEFAULT_POLICY, threshold: "medium" as const, rules: { "1": { enabled: false } }, rules_enabled: 53, rules_disabled: 1 };
  assert.equal(describe(s), "53 rules on, strength medium, raises findings of medium or high confidence, 1 rule set apart");
});

test("a scan's result says which policy applied and what it held back", () => {
  assert.deepEqual(policyFacts({}), []);
  const r = { policy: { name: "api", strength: "high", threshold: "medium", flags_over_policy: ["--strength"] }, below_threshold: { "40012-1": 2, "40018": 1 } };
  assert.deepEqual(policyFacts(r), [
    ["Policy", "api: strength high, threshold medium (--strength given as well)"],
    ["Below threshold", "3 findings not raised"],
  ]);
  assert.deepEqual(policyFacts({ below_threshold: { "1": 1 } }), [["Below threshold", "1 finding not raised"]]);
  assert.deepEqual(policyFacts({ skipped: [{ rule: 40013, reason: "it needs --auth with a login" }] }), [["Skipped rule 40013", "it needs --auth with a login"]]);
});
