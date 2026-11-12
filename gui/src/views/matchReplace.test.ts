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
  failureNote,
  importQuestion,
  importSummary,
  ruleEditNote,
  scriptName,
  scriptStop,
  isScriptAnswer,
  scriptQuestion,
  skippedReason,
  testArgs,
  testProblem,
  testedNote,
  testedProblems,
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

test("a rule whose replacement a script makes names its file, not a replacement", () => {
  const scripted = draft({ name: "X-Sig", replacer: "script", script: " /work/sign.js ", replace: "typed before", appliesTo: ["proxy", "send"] });
  assert.deepEqual(addArgs(scripted), ["rules", "add", "--location=request-header", "--match=", "--script=/work/sign.js", "--name=X-Sig", "--applies-to=proxy,send"]);
  assert.deepEqual(testArgs({ kind: "draft", draft: scripted }, { message: "auto", history: "7", host: "" }), [
    "rules",
    "test",
    "--max-body=2000000",
    "--history=7",
    "--location=request-header",
    "--match=",
    "--script=/work/sign.js",
    "--name=X-Sig",
  ]);
  // Back to text: the file is left out as the text was, and nothing of it is lost in the draft.
  assert.deepEqual(addArgs({ ...scripted, replacer: "text" }).filter((a) => a.startsWith("--replace") || a.startsWith("--script")), ["--replace=typed before"]);
  // An add takes no match, with a script as with text.
  assert.ok(!addArgs({ ...scripted, action: "add" }).some((a) => a.startsWith("--match")));
});

test("a script draft needs its file, and what it returns is checked when it runs", () => {
  assert.equal(draftProblem(draft({ replacer: "script" })), "Choose the script file.");
  assert.equal(draftProblem(draft({ replacer: "script", script: "  " })), "Choose the script file.");
  assert.equal(draftProblem(draft({ replacer: "script", script: "/s.js" })), null);
  // No match and no text is fine: the script gives the header line. So is a status it computes.
  assert.equal(draftProblem(draft({ location: "status", replacer: "script", script: "/s.js" })), null);
  assert.equal(draftProblem(draft({ location: "status", replace: "abc" })), 'A status is a code, with a reason if you like: "404" or "404 Not Found".');
  assert.match(draftProblem(draft({ name: "X-A", action: "remove", replacer: "script", script: "/s.js" }))!, /takes no script/);
  assert.equal(draftProblem(draft({ location: "query-param", replacer: "script", script: "/s.js" })), "Name the query parameter.");
  assert.equal(testProblem({ kind: "draft", draft: draft({ replacer: "script" }) }, { message: "auto", history: "", host: "" }, "x"), "Choose the script file.");
});

test("the table names a rule's script, and says why a rule is left out", () => {
  const scripted = rule({ id: 4, name: "X-Sig", replacer: "script", script: { file: "/work/hooks/sign.js", sha256: "ab".repeat(32) } });
  assert.equal(describeReplace(scripted), "script sign.js");
  assert.equal(describeReplace(rule({ name: "X-Sig", action: "remove", replacer: "script" })), "(remove)");
  assert.equal(scriptName("C:\\hooks\\sign.js"), "sign.js");
  assert.equal(scriptName("sign.js"), "sign.js");
  const skipped = [{ id: 4, reason: "script file /work/hooks/sign.js changed since it was named here; read it and name it again" }];
  assert.match(skippedReason(scripted, skipped)!, /changed since it was named/);
  assert.equal(skippedReason(rule({ id: 5 }), skipped), null);
  assert.equal(skippedReason(scripted, []), null);
});

test("a test says which script failed or was left out", () => {
  const tested = (t: Partial<Tested>): Tested => ({ changed: false, rules: [], result: { encoding: "utf8", content: "" }, ...t });
  assert.deepEqual(testedProblems(tested({})), []);
  assert.deepEqual(testedProblems(tested({ errors: [{ id: 0, error: "Error: boom" }, { id: 3, error: "it ran past the time limit of 2 s" }] })), [
    "This rule's script failed, so it changed nothing: Error: boom",
    "Rule 3's script failed, so it changed nothing: it ran past the time limit of 2 s",
  ]);
  assert.deepEqual(testedProblems(tested({}), [{ id: 2, reason: "script file /s.js can't be read" }]), ["Rule 2 was left out: script file /s.js can't be read"]);
  // A failed script's rule changed nothing, which is what the note beside it says.
  assert.equal(testedNote(tested({ errors: [{ id: 0, error: "x" }] })), "Unchanged");
});

test("an import says how many rules it brings and which scripts they would run", () => {
  const text = (v: unknown) => JSON.stringify(v);
  assert.equal(importSummary("not json"), null);
  assert.equal(importSummary(text({ rules: [] })), null);
  assert.equal(importSummary(text({ other: 1 })), null);
  const plain = importSummary(text([{ location: "path" }, { location: "method" }]))!;
  assert.deepEqual(plain, { count: 2, scripts: [] });
  assert.equal(importQuestion(plain), "Add the 2 rules on the clipboard to this project?");
  assert.equal(importQuestion({ count: 1, scripts: [] }), "Add the 1 rule on the clipboard to this project?");
  const script = { file: "/work/sign.js", sha256: "0".repeat(64) };
  const one = importSummary(text({ rules: [{ location: "path", replacer: "script", script }, { location: "path", replacer: "script", script }] }))!;
  assert.deepEqual(one, { count: 2, scripts: ["/work/sign.js"] });
  assert.match(importQuestion(one), /One runs a script on this computer for every match, cut off from your files and the network: \/work\/sign\.js\. Read it first\.$/);
  const two = importSummary(text({ data: { rules: [{ script }, { script: { file: "/b.js" } }, { script: { file: "" } }, null] } }))!;
  assert.deepEqual(two, { count: 4, scripts: ["/work/sign.js", "/b.js"] });
  assert.match(importQuestion(two), /Some run scripts .*: \/work\/sign\.js, \/b\.js\. Read them first\.$/);
});

test("adding a script rule asks first, naming the file", () => {
  assert.match(scriptQuestion("/work/hooks/sign.js"), /^sign\.js will run for every match of this rule, cut off from your files and the network/);
  assert.match(scriptQuestion("/work/hooks/sign.js"), /the rule stops until you add it again\.$/);
});

test("a rule's row says when its script last failed, and where", () => {
  const scripted = rule({ id: 4, replacer: "script", script: { file: "/s.js", sha256: "0".repeat(64) } });
  const failure = { id: 4, error: "Error: boom", time: "2026-11-10T09:15:02.123Z", engine: "proxy" };
  assert.equal(failureNote(scripted, []), null);
  assert.equal(failureNote(rule({ id: 5 }), [failure]), null);
  assert.equal(failureNote(scripted, [failure]), "its script last failed 2026-11-10 09:15:02 UTC in the Proxy, leaving the message as it was: Error: boom");
  assert.match(failureNote(scripted, [{ ...failure, engine: "send" }])!, /in the Replay,/);
  assert.match(failureNote(scripted, [{ ...failure, engine: "scan" }])!, /in the scans,/);
  assert.match(failureNote(scripted, [{ ...failure, engine: "ws-to-client" }])!, /in a WebSocket message to client,/);
  // An engine a newer build names is shown as it is named.
  assert.match(failureNote(scripted, [{ ...failure, engine: "crawl" }])!, /in the crawl,/);
});

test("a request rule is a script given the whole request: no match, no replacement", () => {
  const draft: Draft = withLocation({ ...EMPTY_DRAFT, match: "x", replace: "y" }, "request");
  assert.equal(draft.replacer, "script");
  assert.equal(draftProblem(draft), "Choose the script file: it defines request(req, ctx).");
  const ready = { ...draft, script: " /s/gate.js ", host: "app" };
  assert.equal(draftProblem(ready), null);
  assert.deepEqual(addArgs(ready), ["rules", "add", "--location=request", "--script=/s/gate.js", "--host=app"]);
  assert.deepEqual(addArgs({ ...ready, appliesTo: ["proxy", "scan"] }).slice(-1), ["--applies-to=proxy,scan"]);
  const rule: Rule = { id: 4, location: "request", pattern: "", replace: "", enabled: true, replacer: "script", script: { file: "/s/gate.js", sha256: "ab" } };
  assert.equal(describeMatch(rule), "(the whole request)");
  assert.equal(describeReplace(rule), "script gate.js");
  assert.match(scriptQuestion("/s/gate.js", "request"), /block it, or answer it/);
});

test("a request a script stopped says so in the tester and on its history row", () => {
  const answer = { encoding: "utf8" as const, content: "HTTP/1.1 200 OK\r\n\r\nhi" };
  const tested: Tested = { changed: false, rules: [], result: { encoding: "utf8", content: "GET / HTTP/1.1" }, stopped: { rule: 0, outcome: "answered", response: answer } };
  assert.equal(testedNote(tested), "Answered by this rule's script: nothing would be sent");
  const sides = testedSides({ request: tested, host: "h", tried: [] });
  assert.deepEqual(sides.map((s) => s.id), ["request", "answer"]);
  assert.equal(testedNote(sides[1].tested), "The script's response, which the target never sent");
  assert.equal(testedNote({ ...tested, stopped: { rule: 3, outcome: "blocked", reason: "no" } }), "Blocked by rule 3's script: nothing would be sent");

  assert.equal(scriptStop([{ rule: 2 }]), null);
  assert.equal(scriptStop([{ rule: 2 }, { rule: 5, outcome: "answered" }])?.rule, 5);
  assert.equal(
    ruleEditNote([{ rule: 2 }, { rule: 5, outcome: "answered" }]),
    "Changed by match-and-replace rule 2. Answered by the script of rule 5: the response is the script's, the target sent nothing",
  );
  assert.equal(ruleEditNote([{ rule: 5, outcome: "blocked" }]), "Blocked by the script of rule 5: nothing was sent");
});

test("a finding raised from a script's answer is told apart by its alert type", () => {
  assert.equal(isScriptAnswer("script-answer:10021"), true);
  assert.equal(isScriptAnswer("10021"), false);
  assert.equal(isScriptAnswer("script:check:x"), false);
  assert.equal(isScriptAnswer(undefined), false);
});
