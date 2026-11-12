import { test } from "node:test";
import assert from "node:assert/strict";
import { changedSpans, encodedForms, isPayloadPart, markRanges, marksFromSaved, MAX_MARKS, payloadMarks } from "./payloadMarks.ts";

const texts = (raw: string, marks: { at: number; text: string }[]) => marks.map((m) => raw.replace(/\r\n/g, "\n").slice(m.at, m.at + m.text.length));

test("with the baseline, what the attack changed is the payload as sent", () => {
  const base = "GET /item?q=hi&x=1 HTTP/1.1\r\nHost: a.test\r\nConnection: close\r\n\r\n";
  const attack = "GET /item?q=%27&x=1 HTTP/1.1\r\nHost: a.test\r\nConnection: keep-alive\r\n\r\n";
  const marks = payloadMarks(attack, "'", base);
  assert.deepEqual(marks, [{ at: 12, text: "%27" }]);
  // The Connection header the scan changed isn't marked.
  assert.deepEqual(texts(attack, marks), ["%27"]);
});

test("an attack that kept the value's start is marked whole", () => {
  const base = "GET /item?q=hi HTTP/1.1\nHost: a\n\n";
  const attack = "GET /item?q=hi%27%20OR%201%3D1 HTTP/1.1\nHost: a\n\n";
  assert.deepEqual(texts(attack, payloadMarks(attack, "hi' OR 1=1", base)), ["hi%27%20OR%201%3D1"]);
});

test("a JSON body: the escaped payload, not the Content-Length it changed", () => {
  const base = 'POST /f HTTP/1.1\nContent-Type: application/json\nContent-Length: 13\n\n{"q":"hello"}';
  const attack = 'POST /f HTTP/1.1\nContent-Type: application/json\nContent-Length: 30\n\n{"q":"<x a=\\"1\\">"}';
  assert.deepEqual(texts(attack, payloadMarks(attack, '<x a="1">', base)), ['<x a=\\"1\\">']);
});

test("a change that isn't the payload (a session cookie) is left out", () => {
  const base = "GET /?q=a HTTP/1.1\nCookie: s=1\n\n";
  const attack = "GET /?q=<script> HTTP/1.1\nCookie: s=2\n\n";
  assert.deepEqual(texts(attack, payloadMarks(attack, "<script>", base)), ["<script>"]);
  // Without a payload to tell, every change is the scan's.
  assert.equal(payloadMarks(attack, "", base).length, 2);
});

test("without a baseline, the payload is found in its encoded forms", () => {
  const raw = "POST /s?a=1 HTTP/1.1\nContent-Type: application/x-www-form-urlencoded\n\nq=a+b%3Cx%3E&r=1";
  assert.deepEqual(texts(raw, payloadMarks(raw, "a b<x>")), ["a+b%3Cx%3E"]);
  assert.deepEqual(texts(raw, payloadMarks(raw, "a b<x>", null)), ["a+b%3Cx%3E"]);
  const json = 'POST / HTTP/1.1\n\n{"q":"say \\"hi\\""}';
  assert.deepEqual(texts(json, payloadMarks(json, 'say "hi"')), ['say \\"hi\\"']);
  assert.deepEqual(payloadMarks("GET / HTTP/1.1\n\n", "<nothing>"), []);
  assert.deepEqual(payloadMarks("GET / HTTP/1.1\n\n", ""), []);
  // Heads that don't pair up fall back to the search.
  const attack = "GET /?q=%27 HTTP/1.1\nX-Scan: 1\n\n";
  assert.deepEqual(texts(attack, payloadMarks(attack, "'", "GET /?q=a HTTP/1.1\n\n")), ["%27"]);
});

test("forms and parts", () => {
  assert.ok(encodedForms("a b'").includes("a+b%27"));
  assert.ok(encodedForms("a b'").includes("a%20b%27"));
  assert.ok(isPayloadPart("%27", "hi'"));
  assert.ok(isPayloadPart("hi%27%20x", "hi' x"));
  assert.ok(!isPayloadPart("2", "<script>"));
  assert.deepEqual(changedSpans("GET / HTTP/1.1\nA: 1\n\n", "GET / HTTP/1.1\n\n"), null);
});

test("marks follow an edit, or go when their text does", () => {
  const marks = [{ at: 12, text: "%27" }];
  assert.deepEqual(markRanges("GET /item?q=%27 HTTP/1.1", marks), [[12, 15]]);
  // Text typed before it moves it.
  assert.deepEqual(markRanges("GET /items/x?q=%27 HTTP/1.1", marks), [[15, 18]]);
  // The payload edited away: nothing marked, not whatever is there now.
  assert.deepEqual(markRanges("GET /item?q=abc HTTP/1.1", marks), []);
  // The nearest of several.
  assert.deepEqual(markRanges("%27 GET /item?q=x%27 HTTP/1.1", marks), [[17, 20]]);
  assert.deepEqual(markRanges("anything", undefined), []);
});

test("saved marks are checked", () => {
  assert.equal(marksFromSaved(undefined), undefined);
  assert.equal(marksFromSaved([]), undefined);
  assert.deepEqual(marksFromSaved([{ at: 1, text: "x", extra: 1 }, { at: -1, text: "y" }, { at: 2 }, null]), [{ at: 1, text: "x" }]);
  assert.equal(marksFromSaved(Array.from({ length: 50 }, (_, i) => ({ at: i, text: "x" })))!.length, MAX_MARKS);
});
