import { test } from "node:test";
import assert from "node:assert/strict";
import type { FindingItem } from "../api.ts";
import {
  cvssLabel,
  filterIssues,
  type IssueInfo,
  issueLabel,
  issueMap,
  issuesArgs,
  issuesOfFindings,
  mergeCommand,
  mergeWarning,
  splitCommand,
  splitProblem,
  splitStart,
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

test("the issue list asks for as many issues as the view holds findings", () => {
  assert.deepEqual(issuesArgs("open,fixed", 50000), ["findings", "issues", "--state", "open,fixed", "--limit", "50000"]);
});

test("issues are found by id and labelled by number, title and hosts", () => {
  const m = issueMap([issue(1), issue(2, { title: "Two", host: "" })]);
  assert.equal(m.get(2)?.title, "Two");
  assert.equal(issueMap(undefined).size, 0);
  assert.equal(issueLabel(issue(1)), "#1 Missing anti-clickjacking header · a.test");
  assert.equal(issueLabel(issue(2, { title: "Two", host: "" })), "#2 Two");
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
  assert.deepEqual(mergeCommand(5, [5, 6, 6, 8]), ["findings", "issue", "merge", "5", "6", "8"]);
  assert.equal(mergeCommand(5, [5]), null);
  assert.equal(mergeCommand(5, []), null);
});

test("a merge warns when alerts differ and when an emptied issue had its own title or rating", () => {
  const keep = issue(1);
  assert.equal(mergeWarning(keep, [issue(2)]), "");
  assert.match(mergeWarning(keep, [issue(2, { alert_ref: "10038" })]), /different alerts/);
  const w = mergeWarning(keep, [issue(1, { titled: true }), issue(2, { titled: true }), issue(3, { cvss: { vector: "v", score: 5, severity: "medium" } })]);
  assert.match(w, /#2, #3 have a title or CVSS rating/);
  assert.doesNotMatch(w, /#1/);
  assert.match(mergeWarning(keep, [issue(2, { titled: true })]), /#2 has a title/);
});

test("a split names the findings and, when given, the title as one argument", () => {
  assert.deepEqual(splitCommand([4, 5], " Stored XSS in comments "), ["findings", "issue", "split", "4", "5", "--title=Stored XSS in comments"]);
  assert.deepEqual(splitCommand([4], "  "), ["findings", "issue", "split", "4"]);
  assert.deepEqual(splitCommand([4], "--force"), ["findings", "issue", "split", "4", "--title=--force"]);
});

test("a split needs some findings picked and at least one left behind", () => {
  assert.match(splitProblem(0, 3), /Pick/);
  assert.match(splitProblem(3, 3), /at least one/);
  assert.equal(splitProblem(2, 3), "");
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
