import { test } from "node:test";
import assert from "node:assert/strict";
import type { FindingItem } from "../api.ts";
import {
  cvssLabel,
  filterIssues,
  type IssueInfo,
  issueActionProblems,
  issueLabel,
  issueMap,
  issuesArgs,
  issuesOfFindings,
  ISSUE_LIMIT,
  MERGE_BATCH,
  mergeCommands,
  mergeWarning,
  missingIssues,
  pickedActions,
  SPLIT_MAX,
  splitCommand,
  splitProblem,
  splitStart,
  staleSplit,
  titleCommand,
} from "./issueTools.ts";

const issue = (id: number, over: Partial<IssueInfo> = {}): IssueInfo => ({
  id,
  alert_ref: "10020",
  title: "Missing anti-clickjacking header",
  titled: false,
  risk: "medium",
  host: "a.test",
  instances: 2,
  cvss: null,
  ...over,
});

const finding = (id: number, issue_id: number | null): FindingItem => ({
  id,
  alert_ref: "10020",
  name: "n",
  risk: "low",
  confidence: "medium",
  host: "a.test",
  method: "GET",
  url: `https://a.test/${id}`,
  param: "",
  evidence: "",
  hits: 1,
  history_id: null,
  state: "open",
  source: "passive",
  issue_id,
});

test("the issue list asks for far more issues than the view holds findings, past the CLI's default", () => {
  assert.deepEqual(issuesArgs("open,fixed"), ["findings", "issues", "--state", "open,fixed", "--limit", String(ISSUE_LIMIT)]);
  assert.ok(ISSUE_LIMIT >= 50_000 * 10);
});

test("issues are found by id and labelled by number, title and hosts", () => {
  const m = issueMap([issue(1), issue(2, { title: "Two", host: "" })]);
  assert.equal(m.get(2)?.title, "Two");
  assert.equal(issueMap(undefined).size, 0);
  assert.equal(issueLabel(issue(1)), "#1 Missing anti-clickjacking header · a.test");
  assert.equal(issueLabel(issue(2, { title: "Two", host: "" })), "#2 Two");
});

test("the issues the findings name but the issue list lacks make one key, the same for the same set", () => {
  const m = issueMap([issue(1)]);
  assert.equal(missingIssues([finding(1, 1), finding(2, null)], m), "");
  assert.equal(missingIssues(undefined, m), "");
  assert.equal(missingIssues([finding(1, 7), finding(2, 3), finding(3, 7), finding(4, 1)], m), "3,7");
  assert.equal(missingIssues([finding(5, 3), finding(6, 7)], m), "3,7");
});

test("a CVSS rating reads in short, with one decimal", () => {
  assert.equal(cvssLabel(issue(1, { cvss: { vector: "CVSS:4.0/...", score: 9, severity: "critical" } })), "CVSS 9.0 critical");
  assert.equal(cvssLabel(issue(1)), "");
  assert.equal(cvssLabel(undefined), "");
});

test("a title goes after --, trimmed, so one starting with - isn't a flag; empty resets it", () => {
  assert.deepEqual(titleCommand(3, "  -x Login CSRF "), ["findings", "issue", "title", "3", "--", "-x Login CSRF"]);
  assert.deepEqual(titleCommand(3, ""), ["findings", "issue", "title", "3", "--", ""]);
});

test("the issues of ticked findings are named once each, in order, leaving out findings with none", () => {
  const byId = new Map([finding(1, 7), finding(2, 9), finding(3, 7), finding(4, null)].map((f) => [f.id, f]));
  assert.deepEqual(issuesOfFindings([1, 2, 3, 4, 99], byId), [7, 9]);
});

test("a merge leaves the target out of the issues it empties, and is nothing without another", () => {
  assert.deepEqual(mergeCommands(5, [5, 6, 6, 8]), [["findings", "issue", "merge", "5", "6", "8"]]);
  assert.deepEqual(mergeCommands(5, [5]), []);
  assert.deepEqual(mergeCommands(5, []), []);
});

test("a merge of many issues goes in batches, each naming the kept issue first", () => {
  const from = Array.from({ length: MERGE_BATCH * 2 + 1 }, (_, i) => i + 10);
  const cmds = mergeCommands(1, from);
  assert.deepEqual(cmds.map((c) => c.length - 4), [MERGE_BATCH, MERGE_BATCH, 1]);
  assert.ok(cmds.every((c) => c[3] === "1"));
  assert.deepEqual(cmds.flatMap((c) => c.slice(4)).map(Number), from);
});

test("a merge of different alerts says the kept issue keeps its title, or that an untitled one may be named after another alert", () => {
  assert.equal(mergeWarning(issue(1), [issue(2)]), "");
  assert.match(mergeWarning(issue(1), [issue(2, { alert_ref: "10038" })]), /no title of its own: it may then be listed under another alert's name\. Rename it/);
  assert.match(mergeWarning(issue(1, { titled: true }), [issue(2, { alert_ref: "10038" })]), /keeps its title/);
});

test("a merge warns that an emptied issue's own title or rating is left behind", () => {
  const w = mergeWarning(issue(1), [issue(1, { titled: true }), issue(2, { titled: true }), issue(3, { cvss: { vector: "v", score: 5, severity: "medium" } })]);
  assert.match(w, /#2, #3 have a title or CVSS rating of their own/);
  assert.doesNotMatch(w, /#1/);
  assert.match(mergeWarning(issue(1), [issue(2, { titled: true })]), /#2 has a title or CVSS rating of its own/);
});

test("a merge warns that new findings take the kept issue's whole-issue decision and rating", () => {
  const keep = issue(1, { decision: { state: "false_positive" } });
  assert.match(mergeWarning(keep, [issue(2)]), /#1 is marked false positive as a whole: new findings of the issues merged into it will arrive marked false positive/);
  const rated = issue(1, { decision: { state: "accepted_risk" }, rating: { risk: "low", confidence: null } });
  assert.match(mergeWarning(rated, [issue(2)]), /is marked accepted risk and rated as a whole/);
  // An emptied issue's decision stops applying to the findings it would have had.
  assert.match(mergeWarning(issue(1), [issue(2, { decision: { state: "fixed" } }), issue(3, { rating: { risk: "high", confidence: "high" } })]), /#2, #3 are marked or rated as a whole; that stops applying/);
  assert.equal(mergeWarning(issue(1, { decision: null, rating: null }), [issue(2, { decision: null })]), "");
});

test("a split names the findings and, when given, the title as one argument", () => {
  assert.deepEqual(splitCommand([4, 5], " Stored XSS in comments "), ["findings", "issue", "split", "4", "5", "--title=Stored XSS in comments"]);
  assert.deepEqual(splitCommand([4], "  "), ["findings", "issue", "split", "4"]);
  assert.deepEqual(splitCommand([4], "--force"), ["findings", "issue", "split", "4", "--title=--force"]);
});

test("a split needs some findings picked, at least one left behind, and not too many for one command line", () => {
  assert.match(splitProblem(0, 3), /Pick/);
  assert.match(splitProblem(3, 3), /at least one/);
  assert.equal(splitProblem(2, 3), "");
  assert.equal(splitProblem(SPLIT_MAX, SPLIT_MAX + 1), "");
  assert.match(splitProblem(SPLIT_MAX + 1, SPLIT_MAX + 5), /at most 2,000/);
});

test("a split is checked against the issue as it is just before, since the CLI takes only the findings", () => {
  const now = [finding(1, 7), finding(2, 7), finding(3, 7)];
  assert.equal(staleSplit(7, [2], now), "");
  // A finding moved to another issue meanwhile would be split out of that one.
  assert.match(staleSplit(7, [2, 9], now), /#9 is no longer in it/);
  assert.match(staleSplit(7, [5, 9], now), /#5, #9 are no longer/);
  // Findings taken out meanwhile: the picked ones would now be all of them.
  assert.match(staleSplit(7, [1, 2], [finding(1, 7), finding(2, 7)]), /all of its findings now/);
});

test("an issue's menu can merge only with another issue there, and split only an issue of two or more", () => {
  assert.deepEqual(issueActionProblems(issue(1, { instances: 2 }), 2), { merge: "", split: "" });
  assert.deepEqual(issueActionProblems(issue(1, { instances: 1 }), 1), { merge: "There is no other issue", split: "It has one finding" });
});

test("ticked findings merge their issues when in two or more, and split off when some of one issue", () => {
  const byId = new Map([finding(1, 7), finding(2, 7), finding(3, 9), finding(4, null)].map((f) => [f.id, f]));
  const issues = issueMap([issue(7, { instances: 2 }), issue(9, { instances: 1 })]);
  assert.deepEqual(pickedActions([1, 3], byId, issues).merge.map((i) => i.id), [7, 9]);
  assert.equal(pickedActions([1, 3], byId, issues).split, null);
  assert.equal(pickedActions([1], byId, issues).split?.id, 7);
  // All of an issue's findings: nothing to split off.
  assert.equal(pickedActions([1, 2], byId, issues).split, null);
  // A ticked finding with no issue doesn't count against the issue's.
  assert.equal(pickedActions([1, 4], byId, issues).split?.id, 7);
  // An issue the list hasn't read yet: no merge with part of the issues.
  assert.deepEqual(pickedActions([1, 3], byId, issueMap([issue(7)])).merge, []);
  assert.deepEqual(pickedActions([], byId, issues), { merge: [], split: null });
});

test("the split dialog starts with the issue's ticked findings, unless all of them are", () => {
  assert.deepEqual([...splitStart([1, 2, 3], new Set([2, 9]))], [2]);
  assert.deepEqual([...splitStart([1, 2], new Set([1, 2]))], []);
  assert.deepEqual([...splitStart([1, 2], new Set())], []);
});

test("the merge dialog's filter matches every word in the title, alert, hosts or #id", () => {
  const list = [issue(1, { title: "Reflected XSS" }), issue(12, { title: "SQL injection", host: "b.test", alert_ref: "40018" })];
  assert.deepEqual(filterIssues(list, "").map((i) => i.id), [1, 12]);
  assert.deepEqual(filterIssues(list, "xss").map((i) => i.id), [1]);
  assert.deepEqual(filterIssues(list, "#12").map((i) => i.id), [12]);
  assert.deepEqual(filterIssues(list, "40018 B.TEST").map((i) => i.id), [12]);
  assert.deepEqual(filterIssues(list, "sql a.test").map((i) => i.id), []);
});
