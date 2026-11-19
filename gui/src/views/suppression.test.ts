import { test } from "node:test";
import assert from "node:assert/strict";
import { addedNote, alertNames, canSuppress, draftFor, draftProblem, removedNote, ruleWhere, rulesLabel, rulesSummary, suppressAddArgs, suppressedCount, suppressRemoveArgs } from "./suppression.ts";

const finding = { alert_ref: "10038", host: "app.test", url: "https://app.test/static/app.js?v=3", param: "" };

test("a rule starts from the finding: its alert, host, path and parameter", () => {
  assert.deepEqual(draftFor(finding), { alert: "10038", host: "app.test", pathPrefix: "/static/app.js", param: "", reason: "" });
  assert.deepEqual(draftFor({ ...finding, url: "http://127.0.0.1:3000/search?q=1", host: "127.0.0.1", param: "q" }), {
    alert: "10038",
    host: "127.0.0.1:3000",
    pathPrefix: "/search",
    param: "q",
    reason: "",
  });
});

test("the host keeps a port only when the URL names one that isn't the default", () => {
  assert.equal(draftFor({ ...finding, url: "https://app.test:443/" }).host, "app.test");
  assert.equal(draftFor({ ...finding, url: "http://app.test:80/a" }).host, "app.test");
  assert.equal(draftFor({ ...finding, url: "https://app.test:8443/a" }).host, "app.test:8443");
  assert.equal(draftFor({ ...finding, host: "::1", url: "http://[::1]:3000/a" }).host, "[::1]:3000");
});

test("the site's root is every path, and a finding with no URL starts from its host", () => {
  assert.equal(draftFor({ ...finding, url: "https://app.test/" }).pathPrefix, "");
  assert.deepEqual(draftFor({ ...finding, url: "" }), { alert: "10038", host: "app.test", pathPrefix: "", param: "", reason: "" });
});

test("the dialog says what the CLI would refuse before it runs", () => {
  const ok = { alert: "10038", host: "app.test", pathPrefix: "/static/", param: "", reason: "served by the CDN" };
  assert.equal(draftProblem(ok), null);
  assert.match(draftProblem({ ...ok, alert: " " })!, /alert/);
  assert.match(draftProblem({ ...ok, host: "" })!, /host/);
  for (const host of ["app.test/x", "a b", "user@app.test", "app.test?x", "app.test#x"]) assert.match(draftProblem({ ...ok, host })!, /host is a name/, host);
  assert.equal(draftProblem({ ...ok, host: "[::1]:3000" }), null);
  assert.match(draftProblem({ ...ok, pathPrefix: "static/" })!, /starts with \//);
  assert.equal(draftProblem({ ...ok, pathPrefix: " " }), null);
  assert.match(draftProblem({ ...ok, reason: "  " })!, /reason/);
});

test("add sends each value as --flag=value, leaving out an empty path and parameter", () => {
  const d = { alert: " 10038 ", host: " app.test ", pathPrefix: "", param: "", reason: " not ours " };
  assert.deepEqual(suppressAddArgs(d), ["findings", "suppress", "add", "--alert=10038", "--host=app.test", "--reason=not ours"]);
  // A reason or parameter starting with "-" stays a value.
  assert.deepEqual(suppressAddArgs({ ...d, pathPrefix: " /static/ ", param: "-x", reason: "--reopen is wrong here" }), [
    "findings",
    "suppress",
    "add",
    "--alert=10038",
    "--host=app.test",
    "--path-prefix=/static/",
    "--param=-x",
    "--reason=--reopen is wrong here",
  ]);
  assert.ok(!suppressAddArgs({ ...d, param: "   " }).some((a) => a.startsWith("--param")));
});

test("remove opens the findings again only when asked", () => {
  assert.deepEqual(suppressRemoveArgs(4, false), ["findings", "suppress", "remove", "4"]);
  assert.deepEqual(suppressRemoveArgs(4, true), ["findings", "suppress", "remove", "4", "--reopen"]);
});

test("a rule's scope reads as one line", () => {
  const r = { host: "app.test", port: null, path_prefix: "", param: null };
  assert.equal(ruleWhere(r), "app.test");
  assert.equal(ruleWhere({ ...r, port: 3000, path_prefix: "/static/", param: "id" }), "app.test:3000/static/ · parameter id");
  assert.equal(ruleWhere({ ...r, host: "::1", port: 8080 }), "[::1]:8080");
  assert.equal(ruleWhere({ ...r, host: "::1" }), "::1");
  assert.equal(ruleWhere({ ...r, param: "" }), "app.test");
});

test("the toolbar counts the rules and the findings they hold", () => {
  assert.equal(rulesLabel(null), "Suppression rules…");
  assert.equal(rulesLabel([]), "Suppression rules…");
  assert.equal(suppressedCount([{ findings: 3 }, { findings: 0 }, { findings: 9 }]), 12);
  assert.equal(rulesLabel([{ findings: 3 }, { findings: 9 }]), "Suppression rules (2) · 12 suppressed…");
});

test("after adding, it says what the rule marked", () => {
  assert.equal(addedNote(2, 1), "Suppression rule 2 added: it marked 1 finding false positive.");
  assert.equal(addedNote(2, 5), "Suppression rule 2 added: it marked 5 findings false positive.");
  assert.match(addedNote(2, 0), /^Suppression rule 2 added\. No open, untriaged finding matched it yet/);
});

test("after adding, it says when the finding it came from was left alone", () => {
  assert.equal(addedNote(2, 3, { id: 7, state: "false_positive", suppressed_by: 2 }), "Suppression rule 2 added: it marked 3 findings false positive.");
  // Someone else had already marked it a false positive: nothing to say.
  assert.equal(addedNote(2, 0, { id: 7, state: "false_positive", suppressed_by: null }), addedNote(2, 0));
  assert.match(addedNote(2, 3, { id: 7, state: "confirmed", suppressed_by: null }), /Finding #7 stays confirmed: someone triaged it,/);
  assert.match(addedNote(2, 3, { id: 7, state: "accepted_risk", suppressed_by: null }), /stays accepted risk:/);
  assert.match(addedNote(2, 0, { id: 7, state: "open", suppressed_by: null }), /Finding #7 stays open: the rule doesn't match it, or someone triaged it before/);
});

test("after removing, it says what happened to the findings", () => {
  assert.equal(removedNote(3, 0, false), "Suppression rule 3 removed. The findings it marked stay false positives.");
  assert.equal(removedNote(3, 1, true), "Suppression rule 3 removed: 1 finding open again.");
  assert.equal(removedNote(3, 4, true), "Suppression rule 3 removed: 4 findings open again.");
});

test("only scanners' findings start a rule", () => {
  assert.equal(canSuppress({ source: "passive" }), true);
  assert.equal(canSuppress({ source: "active" }), true);
  assert.equal(canSuppress({ source: "authz" }), true);
  assert.equal(canSuppress({ source: "manual" }), false);
});

test("the rules dialog says what the rules hold, or how to make one", () => {
  assert.match(rulesSummary([]), /^No rules yet\. .*Suppress…/);
  assert.match(rulesSummary([{ findings: 1 }]), /^1 finding is a false positive by these rules\./);
  assert.match(rulesSummary([{ findings: 0 }, { findings: 2 }]), /^2 findings are false positives by these rules\./);
  assert.match(rulesSummary([{ findings: 0 }]), /^0 findings are false positives/);
});

test("rules show the alert's name where a finding of it is loaded", () => {
  const names = alertNames([
    { alert_ref: "10038", name: "CSP header not set" },
    { alert_ref: "40018", name: "SQL injection - MySQL" },
    { alert_ref: "40018", name: "SQL injection - PostgreSQL" },
  ]);
  assert.equal(names.get("10038"), "CSP header not set");
  assert.equal(names.get("40018"), "SQL injection - MySQL");
  assert.equal(names.get("10020"), undefined);
});
