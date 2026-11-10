import { test } from "node:test";
import assert from "node:assert/strict";
import {
  EMPTY_DRAFT,
  addArgs,
  defaultEngines,
  describeMatch,
  describeReplace,
  describeScope,
  describeWhere,
  draftProblem,
  enginesFor,
  ruleEditNote,
  testArgs,
  testProblem,
  testedNote,
  testedSides,
  withLocation,
  type Draft,
  type Rule,
  type Tested,
} from "./matchReplace.ts";

const draft = (d: Partial<Draft>): Draft => ({ ...EMPTY_DRAFT, ...d });
const rule = (r: Partial<Rule>): Rule => ({ id: 1, location: "request-header", pattern: "", replace: "", enabled: true, ...r });

test("a rule as the editor always made them says nothing new", () => {
  assert.deepEqual(addArgs(draft({ match: "^X: (.*)$", replace: "X: $1!" })), ["rules", "add", "--location=request-header", "--match=^X: (.*)$", "--replace=X: $1!"]);
  assert.deepEqual(addArgs(draft({ replace: "X-A: 1", comment: "add", disabled: true })), [
    "rules",
    "add",
    "--location=request-header",
    "--match=",
    "--replace=X-A: 1",
    "--comment=add",
    "--disabled",
  ]);
});

test("a structured rule names its header or parameter, its action, matcher, engines and host", () => {
  const d = draft({ location: "query-param", name: " role ", replace: "admin", matcher: "whole", match: "user", appliesTo: ["scan", "proxy", "send"], host: " ^api\\. " });
  assert.deepEqual(addArgs(d), [
    "rules",
    "add",
    "--location=query-param",
    "--match=user",
    "--replace=admin",
    "--match-kind=whole",
    "--name=role",
    "--host=^api\\.",
    // In the order the app lists them, whatever order they were ticked in.
    "--applies-to=proxy,send,scan",
  ]);
  // Add sends no match and remove no replacement, even if one was typed for another action.
  assert.deepEqual(addArgs(draft({ name: "X-A", action: "add", replace: "1" })).slice(2), ["--location=request-header", "--replace=1", "--name=X-A", "--action=add"]);
  assert.deepEqual(addArgs(draft({ name: "X-A", action: "remove", match: "^a", replace: "left over" })).slice(2), ["--location=request-header", "--match=^a", "--name=X-A", "--action=remove"]);
  // A WebSocket rule for both directions says nothing; for one it says which.
  const ws = withLocation(draft({ match: "a", replace: "b" }), "ws-message");
  assert.deepEqual(addArgs(ws).slice(2), ["--location=ws-message", "--match=a", "--replace=b"]);
  assert.deepEqual(addArgs({ ...ws, appliesTo: ["ws-to-client"] }).at(-1), "--applies-to=ws-to-client");
});

test("moving a draft to another location drops what no longer fits", () => {
  const named = draft({ location: "query-param", name: "id", action: "remove", appliesTo: ["proxy", "fuzz"] });
  assert.deepEqual(withLocation(named, "request-header"), { ...named, location: "request-header" });
  const path = withLocation(named, "path");
  assert.deepEqual([path.name, path.action, path.appliesTo], ["", "set", ["proxy", "fuzz"]]);
  const ws = withLocation(named, "ws-message");
  assert.deepEqual(ws.appliesTo, ["ws-to-server", "ws-to-client"]);
  assert.deepEqual(withLocation(ws, "method").appliesTo, ["proxy"]);
  assert.deepEqual(enginesFor("ws-message").map((e) => e.id), defaultEngines("ws-message"));
});

test("draftProblem says what a draft still needs", () => {
  assert.equal(draftProblem(draft({})), "Give a match, a replacement, or both.");
  assert.equal(draftProblem(draft({ replace: "X: 1" })), null);
  assert.equal(draftProblem(draft({ location: "query-param", replace: "x" })), "Name the query parameter.");
  // A named rule with nothing else sets the value to nothing, or removes it.
  assert.equal(draftProblem(draft({ location: "query-param", name: "debug", action: "remove" })), null);
  // A match left over from before the action became Add is left out, not a reason to stop.
  const leftover = draft({ name: "X-Mode", action: "add", match: "user", replace: "admin" });
  assert.equal(draftProblem(leftover), null);
  assert.deepEqual(addArgs(leftover).slice(2), ["--location=request-header", "--replace=admin", "--name=X-Mode", "--action=add"]);
  assert.equal(testProblem({ kind: "draft", draft: leftover }, { message: "auto", history: "", host: "" }, "GET / HTTP/1.1\n\n"), null);
  assert.match(draftProblem(draft({ replace: "x", appliesTo: [] }))!, /applies to/);
  assert.match(draftProblem(draft({ location: "status", replace: "20" }))!, /status is a code/);
  assert.equal(draftProblem(draft({ location: "status", replace: "404 Gone away" })), null);
  assert.equal(draftProblem(draft({ location: "status", match: "^(4)04$", replace: "${1}10" })), null);
});

test("testArgs tries the draft, a saved rule, or an engine's rules, on text or a history row", () => {
  const on = { message: "auto", history: "", host: "" };
  const d = draft({ location: "path", matcher: "literal", match: "/v1/", replace: "/v2/", appliesTo: ["fuzz"], comment: "c" });
  // What a rule applies to and its comment are not part of trying it.
  assert.deepEqual(testArgs({ kind: "draft", draft: d }, on), ["rules", "test", "--max-body=2000000", "-", "--location=path", "--match=/v1/", "--replace=/v2/", "--match-kind=literal"]);
  assert.deepEqual(testArgs({ kind: "rule", id: 7 }, { message: "response", history: "", host: " a.test " }), [
    "rules",
    "test",
    "--max-body=2000000",
    "-",
    "--message=response",
    "--target-host=a.test",
    "--rule=7",
  ]);
  // A history row brings its own host and both messages.
  assert.deepEqual(testArgs({ kind: "engine", engine: "send" }, { message: "response", history: " 42 ", host: "a.test" }), ["rules", "test", "--max-body=2000000", "--history=42", "--as=send"]);
});

test("testProblem wants something to try the rules on", () => {
  const on = { message: "auto", history: "", host: "" };
  assert.match(testProblem({ kind: "rule", id: 1 }, on, "")!, /Paste a request/);
  assert.equal(testProblem({ kind: "rule", id: 1 }, on, "GET / HTTP/1.1\n\n"), null);
  assert.equal(testProblem({ kind: "engine", engine: "proxy" }, { ...on, history: "12" }, ""), null);
  assert.match(testProblem({ kind: "engine", engine: "proxy" }, { ...on, history: "12a" }, "")!, /number/);
  assert.equal(testProblem({ kind: "draft", draft: draft({}) }, on, "x"), "Give a match, a replacement, or both.");
});

test("the table says where a rule works, what it matches and writes, and what it applies to", () => {
  const legacy = rule({ pattern: "^X", replace: "Y" });
  assert.deepEqual([describeWhere(legacy), describeMatch(legacy), describeReplace(legacy), describeScope(legacy)], ["Request header (each line)", "^X", "Y", "Proxy"]);
  assert.equal(describeMatch(rule({ replace: "X-A: 1" })), "(add header)");
  assert.equal(describeMatch(rule({ location: "request-body", replace: "x" })), "(nothing)");
  assert.equal(describeMatch(rule({ location: "request-body", matcher: "whole", replace: "x" })), "(whole value)");
  assert.equal(describeReplace(rule({ pattern: "^X.*$" })), "(remove)");
  const named = rule({ location: "query-param", name: "role", matcher: "whole", pattern: "user", replace: "admin", applies_to: ["send", "fuzz"], host: "^api\\." });
  assert.deepEqual([describeWhere(named), describeMatch(named), describeScope(named)], ["Query parameter role", "is user", "Replay, Fuzzer · host ^api\\."]);
  assert.equal(describeMatch(rule({ name: "X-A", action: "add", replace: "1" })), "(add)");
  assert.equal(describeReplace(rule({ name: "X-A", action: "remove", pattern: "^a" })), "(remove)");
  assert.equal(describeReplace(rule({ name: "X-A" })), "(empty)");
  assert.equal(describeMatch(rule({ location: "path", matcher: "literal", pattern: "/v1/" })), "text /v1/");
  assert.equal(describeScope(rule({ location: "ws-message", pattern: "a" })), "WebSocket: to server, to client");
  assert.equal(describeScope(rule({ location: "ws-message", pattern: "a", applies_to: ["ws-to-client"] })), "WebSocket: to client");
  // A location or engine from a newer build is shown as it is named.
  assert.equal(describeWhere(rule({ location: "trailer" })), "trailer");
  assert.equal(describeScope(rule({ applies_to: ["crawl"] })), "crawl");
});

test("a tested message says which rules changed it", () => {
  const tested = (t: Partial<Tested>): Tested => ({ changed: true, rules: [], result: { encoding: "utf8", content: "" }, ...t });
  assert.equal(testedNote(tested({ changed: false })), "Unchanged");
  assert.equal(testedNote(tested({ rules: [0] })), "Changed by this rule");
  assert.equal(testedNote(tested({ rules: [3, 5] })), "Changed by rule 3, 5");
  assert.equal(testedNote(tested({ rules: [3, 0] })), "Changed by rule 3 and this rule");
  const both = { request: tested({}), response: tested({ changed: false }), host: "h", tried: [1] };
  assert.deepEqual(testedSides(both).map((s) => s.label), ["Request", "Response"]);
  assert.deepEqual(testedSides({ message: tested({}), host: "", tried: [] }).map((s) => s.id), ["message"]);
});

test("a history row says which rules changed it", () => {
  // Other edits (an intercept's, a session's) are in the same list and are not rules.
  assert.equal(ruleEditNote([{ rule: 2 }, { rule: null }, {}, { rule: 5 }]), "Changed by match-and-replace rule 2, 5");
  assert.equal(ruleEditNote(undefined), "Changed by a match-and-replace rule");
});
