import { test } from "node:test";
import assert from "node:assert/strict";
import { connectionsLabel, parseConnections, sequenceArgs, sequenceProblem, sequenceSummary, sequenceTag, stopText, tabOutcome, type SequenceResult } from "./sequence.ts";

const response = { status: 200, reason: "OK", headers: ["Content-Length: 2"], body: { encoding: "utf8" as const, content: "ok", length: 2, truncated: false } };

function result(over: Partial<SequenceResult> = {}): SequenceResult {
  return {
    sequence: "single",
    sequence_id: "abc",
    target: "https://shop.test",
    http2: false,
    connections: 1,
    total: 3,
    answered: 3,
    complete: true,
    stopped: null,
    results: [0, 1, 2].map((i) => ({ request: i, request_line: `GET /${i} HTTP/1.1`, outcome: "answered" as const, id: 10 + i, url: `https://shop.test/${i}`, duration_ms: 3, response })),
    ...over,
  };
}

test("the call is Replay's send plus --sequence and one --also per other tab", () => {
  assert.deepEqual(sequenceArgs("https://shop.test", "single", 2), [
    "send",
    "--target=https://shop.test",
    "--sequence=single",
    "--also=@request:0",
    "--also=@request:1",
    "-",
  ]);
  assert.deepEqual(sequenceArgs("https://shop.test", "separate", 1, { http2: true, sni: "x.test", noStore: true }), [
    "send",
    "--target=https://shop.test",
    "--sequence=separate",
    "--http2",
    "--sni=x.test",
    "--no-store",
    "--also=@request:0",
    "-",
  ]);
});

test("a sequence goes over TCP: the tab's HTTP/3 option is left out, and so is as typed with it", () => {
  const args = sequenceArgs("https://shop.test", "single", 1, { http3: true, verbatim: true });
  assert.ok(!args.includes("--http3"), args.join(" "));
  assert.ok(!args.includes("--verbatim"), args.join(" "));
  assert.ok(sequenceArgs("https://shop.test", "single", 1, { verbatim: true }).includes("--verbatim"));
});

test("each tab gets its own request's response", () => {
  const r = result();
  for (const i of [0, 1, 2]) {
    const o = tabOutcome(r, i, ["a", "b", "c"]);
    assert.equal(o?.error, null);
    assert.equal(o?.result?.id, 10 + i);
    assert.equal(o?.result?.url, `https://shop.test/${i}`);
    assert.equal(o?.result?.response?.status, 200);
  }
  assert.equal(tabOutcome(r, 3, []), null);
});

test("a stop says, in the tabs that weren't sent, where and why by tab name", () => {
  const closed = result({
    complete: false,
    answered: 1,
    stopped: { request: 1, cause: "closed", reason: "the response said Connection: close" },
    results: [result().results[0], { request: 1, request_line: "GET /1 HTTP/1.1", outcome: "not_sent" }, { request: 2, request_line: "GET /2 HTTP/1.1", outcome: "not_sent" }],
  });
  assert.equal(tabOutcome(closed, 1, ["login", "cart", "pay"])?.error, "Not sent: the connection ended after “login” (the response said Connection: close)");
  assert.equal(tabOutcome(closed, 0, ["login", "cart", "pay"])?.result?.id, 10);

  const failed = result({
    complete: false,
    answered: 1,
    stopped: { request: 1, cause: "failed", reason: "timed out after 5s" },
    results: [
      result().results[0],
      { request: 1, request_line: "GET /1 HTTP/1.1", outcome: "failed", id: 11, error: "timed out after 5s", kind: "timeout" },
      { request: 2, request_line: "GET /2 HTTP/1.1", outcome: "not_sent" },
    ],
  });
  assert.deepEqual(tabOutcome(failed, 1, ["login", "cart", "pay"]), { result: null, error: "timed out after 5s" });
  assert.equal(tabOutcome(failed, 2, ["login", "cart", "pay"])?.error, "Not sent: “cart” failed (timed out after 5s)");
  // Without a title, the request's place (from 1) stands in.
  assert.equal(stopText(failed, []), "request 2 failed (timed out after 5s)");
  assert.equal(stopText(result(), ["a"]), null);
  assert.match(sequenceSummary(failed), /^1 of 3 answered, one connection \(1 opened\)\. History rows tagged sequence:abc$/);
});

test("labels, the stored choice, and what a group needs", () => {
  assert.equal(connectionsLabel("single"), "one connection");
  assert.equal(connectionsLabel("separate"), "separate connections");
  assert.equal(parseConnections("separate"), "separate");
  assert.equal(parseConnections(null), "single");
  assert.equal(parseConnections("junk"), "single");
  assert.equal(sequenceTag(result(), 1), "in order 2/3 · one connection");
  assert.equal(sequenceTag(result({ http2: true }), 0), "in order 1/3 · one HTTP/2 connection");
  assert.equal(sequenceTag(result({ sequence: "separate", connections: 3 }), 2), "in order 3/3 · 3 connections");
  assert.match(sequenceSummary(result()), /^All 3 answered/);
  assert.ok(sequenceProblem(1));
  assert.equal(sequenceProblem(2), null);
});
