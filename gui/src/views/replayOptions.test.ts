import { test } from "node:test";
import assert from "node:assert/strict";
import { DEFAULT_OPTIONS, activeLabels, crlfLines, optionArgs, optionsProblem, requestToSend, sendArgs, withDefaults } from "./replayOptions.ts";
import { wsSendArgs } from "./ws.ts";

test("default options add no flags and show nothing", () => {
  assert.deepEqual(sendArgs("https://a.test", undefined), ["send", "--target=https://a.test", "-"]);
  assert.deepEqual(sendArgs("https://a.test", DEFAULT_OPTIONS), ["send", "--target=https://a.test", "-"]);
  assert.deepEqual(activeLabels(undefined, "http"), []);
  // A tab saved before a field existed gets its default.
  assert.deepEqual(withDefaults({ http2: true }), { ...DEFAULT_OPTIONS, http2: true });
});

test("every option maps to its send flag, before the stdin '-'", () => {
  const o = { http2: true, verbatim: true, sni: " other.test ", timeout: "5", verifyTls: true, noStore: true };
  assert.deepEqual(sendArgs("https://a.test", o), [
    "send",
    "--target=https://a.test",
    "--http2",
    "--verbatim",
    "--sni=other.test",
    "--timeout=5",
    "--verify-tls",
    "--no-store",
    "-",
  ]);
  assert.deepEqual(activeLabels(o, "http"), ["HTTP/2", "as typed", "SNI other.test", "timeout 5 s", "verify TLS", "not recorded"]);
});

test("a value is one argument, so one starting with - isn't read as a flag", () => {
  assert.deepEqual(optionArgs({ sni: "-x.test" }, "http"), ["--sni=-x.test"]);
});

test("the timeout is passed only when it isn't the CLI's 30 s", () => {
  assert.deepEqual(optionArgs({ timeout: "30" }, "http"), []);
  assert.deepEqual(optionArgs({ timeout: " 2.5 " }, "http"), ["--timeout=2.5"]);
  assert.deepEqual(activeLabels({ timeout: "30.0" }, "http"), []);
  assert.deepEqual(activeLabels({ timeout: "0.5" }, "http"), ["timeout 0.5 s"]);
});

test("bad options are refused before sending", () => {
  assert.equal(optionsProblem(undefined), null);
  assert.equal(optionsProblem({ timeout: "10", sni: "a.test" }), null);
  for (const t of ["0", "-1", "abc", "1e400", "100000"]) assert.match(optionsProblem({ timeout: t }) ?? "", /Timeout/, t);
  assert.match(optionsProblem({ sni: "a b" }) ?? "", /SNI/);
});

test("WebSocket tabs get only what ws send has", () => {
  const o = { http2: true, verbatim: true, sni: "s.test", timeout: "10", verifyTls: true, noStore: true };
  assert.deepEqual(optionArgs(o, "ws"), ["--sni=s.test", "--timeout=10", "--verify-tls", "--no-store"]);
  assert.deepEqual(activeLabels(o, "ws"), ["SNI s.test", "timeout 10 s", "verify TLS", "not recorded"]);
  assert.deepEqual(wsSendArgs({ target: "wss://a.test", wait: 3, options: o }), [
    "ws",
    "send",
    "--target=wss://a.test",
    "--wait",
    "3",
    "--sni=s.test",
    "--timeout=10",
    "--verify-tls",
    "--no-store",
    "--input-json",
    "--max-body=2000000",
  ]);
});

test("sent as typed: CRLF line breaks, no auto URL-encode", () => {
  const raw = "POST /a b HTTP/1.1\nHost: a.test\nContent-Length: 4\nTransfer-Encoding: chunked\n\n0\n\nGET /admin HTTP/1.1\nX: x";
  const { text, encoded } = requestToSend(raw, { autoEncode: true, options: { verbatim: true } });
  assert.equal(encoded, 0);
  assert.equal(text, raw.replace(/\n/g, "\r\n"));
  // Not as typed: auto URL-encode applies, line endings are left to the CLI.
  const normal = requestToSend(raw, { autoEncode: true, options: {} });
  assert.equal(normal.encoded, 1);
  assert.ok(normal.text.startsWith("POST /a%20b HTTP/1.1\nHost"));
  assert.equal(requestToSend(raw, { autoEncode: false }).text, raw);
});

test("CRLF lines keep existing CRLF and a binary body's bytes", () => {
  assert.equal(crlfLines("GET / HTTP/1.1\nA: b\r\n\r\nx\r\ny\nz", false), "GET / HTTP/1.1\r\nA: b\r\n\r\nx\r\ny\r\nz");
  // No blank line is added after the headers.
  assert.equal(crlfLines("GET / HTTP/1.1\nHost: a", false), "GET / HTTP/1.1\r\nHost: a");
  const bin = "POST / HTTP/1.1\nHost: a\n\n\x89PNG\r\n\x1a\n\x00";
  assert.equal(crlfLines(bin, true), "POST / HTTP/1.1\r\nHost: a\r\n\r\n\x89PNG\r\n\x1a\n\x00");
  assert.equal(requestToSend(bin, { binary: true, autoEncode: true, options: { verbatim: true } }).text, crlfLines(bin, true));
});
