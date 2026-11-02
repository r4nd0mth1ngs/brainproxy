import { test } from "node:test";
import assert from "node:assert/strict";
import { draftFromRequest, findingAddArgs, formFromDraft, formProblem, historyIds, type FindingForm } from "./manualFinding.ts";

const filled = (over: Partial<FindingForm> = {}): FindingForm => ({
  ...formFromDraft({ url: "https://app.test/orders/7?x=1", method: "post", history: [12] }),
  title: "Order IDOR",
  ...over,
});

test("a draft from another tool fills the form", () => {
  const f = formFromDraft({ url: "https://app.test/a", method: "PUT", history: [3, 4] });
  assert.deepEqual([f.url, f.method, f.history, f.risk, f.confidence], ["https://app.test/a", "PUT", "3, 4", "medium", "medium"]);
  assert.deepEqual([formFromDraft(null).method, formFromDraft(null).history], ["GET", ""]);
});

test("history ids are numbers, separated by commas or spaces", () => {
  assert.deepEqual(historyIds("12, 15 #20,,12"), [12, 15, 20]);
  assert.deepEqual(historyIds(""), []);
  assert.equal(historyIds("12, abc"), null);
  assert.equal(historyIds("0"), null);
  assert.equal(historyIds("-3"), null);
});

test("the form says what is missing before anything runs", () => {
  assert.equal(formProblem(filled()), null);
  assert.match(formProblem(filled({ title: "  " }))!, /title/);
  assert.match(formProblem(filled({ title: "!!!" }))!, /letter or digit/);
  assert.match(formProblem(filled({ url: "app.test/x" }))!, /absolute/);
  assert.match(formProblem(filled({ url: "ftp://app.test/" }))!, /http/);
  assert.match(formProblem(filled({ url: "", history: "" }))!, /URL/);
  assert.equal(formProblem(filled({ url: "", history: "12" })), null);
  assert.match(formProblem(filled({ history: "x" }))!, /numbers/);
  assert.match(formProblem(filled({ method: "GET /" }))!, /method/);
  assert.match(formProblem(filled({ cwe: "CWE-639" }))!, /CWE/);
  assert.equal(formProblem(filled({ url: "wss://app.test/socket", cwe: "639" })), null);
});

test("the form becomes one findings add call, the description on stdin", () => {
  const { args, stdin } = findingAddArgs(
    filled({ risk: "high", confidence: "high", param: "id", cwe: " 639 ", history: "12, 15", description: " Any user can read any order. ", solution: "Check the owner.", evidence: "-leading dash" }),
  );
  assert.deepEqual(args, [
    "findings",
    "add",
    "--title=Order IDOR",
    "--risk=high",
    "--confidence=high",
    "--url=https://app.test/orders/7?x=1",
    "--method=POST",
    "--history-id=12,15",
    "--param=id",
    "--cwe=639",
    "--solution=Check the owner.",
    "--evidence=-leading dash",
    "--description-file=-",
  ]);
  assert.equal(stdin, "Any user can read any order.");
  // Nothing optional: no empty flags and no stdin; without a URL the history entry gives it and its method.
  const bare = findingAddArgs(filled({ url: "", history: "12" }));
  assert.deepEqual(bare, { args: ["findings", "add", "--title=Order IDOR", "--risk=medium", "--confidence=medium", "--history-id=12"] });
});

test("Replay hands over its last send, or the request it holds", () => {
  const raw = "POST /orders/7?x=1 HTTP/1.1\nHost: app.test\n\nid=7";
  assert.deepEqual(draftFromRequest(raw, "https://app.test", 42, "https://app.test/orders/7?x=1"), {
    method: "POST",
    url: "https://app.test/orders/7?x=1",
    history: [42],
  });
  assert.deepEqual(draftFromRequest(raw, "https://app.test"), { method: "POST", url: "https://app.test/orders/7?x=1", history: [] });
  assert.deepEqual(draftFromRequest(raw, ""), { method: "POST", url: undefined, history: [] });
  assert.deepEqual(draftFromRequest("", ""), { method: undefined, url: undefined, history: [] });
});

test("only web URLs with a host pass, whatever the method", () => {
  for (const url of ["javascript:alert(1)", "file:///etc/passwd", "data:text/html,x", "http://", "mailto:a@b.test"]) {
    assert.notEqual(formProblem(filled({ url })), null, url);
  }
  // The method only goes with a URL; without one the history entry's is used, so it isn't checked.
  assert.equal(formProblem(filled({ url: "", history: "12", method: "GET /" })), null);
  assert.match(formProblem(filled({ cwe: "0" }))!, /CWE/);
  assert.equal(formProblem(filled({ title: "Überprüfung fehlt" })), null);
  assert.equal(formProblem(filled({ title: "注入" })), null);
});

test("odd history ids are refused, repeats dropped", () => {
  for (const text of ["1.5", "1e3", "0x10", "12a", "+3"]) assert.equal(historyIds(text), null, text);
  assert.deepEqual(historyIds(" #7  #7\n8 "), [7, 8]);
  assert.deepEqual(historyIds(" , "), []);
});

test("flags can't be confused with values", () => {
  // Every value is joined to its flag, so text that starts with a dash stays text.
  const { args, stdin } = findingAddArgs(
    filled({ title: "--risk=info", param: "--url", solution: "-x", evidence: "  kept as typed ", description: "   " }),
  );
  assert.ok(args.every((a, i) => i < 2 || a.startsWith("--")));
  assert.ok(args.includes("--title=--risk=info") && args.includes("--param=--url") && args.includes("--solution=-x"));
  assert.ok(args.includes("--evidence=  kept as typed "));
  assert.equal(args.filter((a) => a.startsWith("--risk=")).length, 1);
  // A blank description is no description, and nothing reads stdin.
  assert.equal(stdin, undefined);
  assert.ok(!args.includes("--description-file=-"));
  // History ids the form can't read are left out (formProblem stops the save first).
  assert.ok(!findingAddArgs(filled({ history: "x" })).args.some((a) => a.startsWith("--history-id")));
});

test("Replay drafts read CRLF requests and absolute request lines", () => {
  assert.deepEqual(draftFromRequest("GET /a?b=1 HTTP/1.1\r\nHost: app.test\r\n\r\n", "http://app.test:8080"), {
    method: "GET",
    url: "http://app.test:8080/a?b=1",
    history: [],
  });
  assert.equal(draftFromRequest("GET http://other.test/x HTTP/1.1\n\n", "https://app.test").url, "http://other.test/x");
  // The last send's URL wins over the request text.
  assert.equal(draftFromRequest("GET /old HTTP/1.1\n\n", "https://app.test", 5, "https://app.test/new").url, "https://app.test/new");
  assert.deepEqual(draftFromRequest("GET", "https://app.test"), { method: "GET", url: undefined, history: [] });
});
