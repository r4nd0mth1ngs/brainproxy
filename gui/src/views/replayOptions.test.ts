import { test } from "node:test";
import assert from "node:assert/strict";
import { DEFAULT_OPTIONS, activeLabels, crlfBody, crlfHead, optionArgs, optionsProblem, requestToSend, sendArgs, sentWithNote, withDefaults } from "./replayOptions.ts";
import { autoEncodeRequest } from "../ui/urlencode.ts";
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

test("sent as typed: CRLF head, body as held, no auto URL-encode", () => {
  const raw = "POST /a b HTTP/1.1\nHost: a.test\nContent-Length: 4\nTransfer-Encoding: chunked\n\n0\n\nGET /admin HTTP/1.1\nX: x";
  const { text, encoded } = requestToSend(raw, { autoEncode: true, options: { verbatim: true } });
  assert.equal(encoded, 0);
  assert.equal(text, "POST /a b HTTP/1.1\r\nHost: a.test\r\nContent-Length: 4\r\nTransfer-Encoding: chunked\r\n\r\n0\n\nGET /admin HTTP/1.1\nX: x");
  // With CRLF body, the hand-typed chunks go out with CRLF too.
  assert.equal(requestToSend(raw, { autoEncode: true, options: { verbatim: true, crlfBody: true } }).text, raw.replace(/\n/g, "\r\n"));
  // Not as typed: auto URL-encode applies, line endings are left to the CLI.
  const normal = requestToSend(raw, { autoEncode: true, options: {} });
  assert.equal(normal.encoded, 1);
  assert.ok(normal.text.startsWith("POST /a%20b HTTP/1.1\nHost"));
  assert.equal(requestToSend(raw, { autoEncode: false }).text, raw);
});

test("CRLF head keeps existing CRLF and the body's bytes", () => {
  assert.equal(crlfHead("GET / HTTP/1.1\nA: b\r\n\r\nx\r\ny\nz"), "GET / HTTP/1.1\r\nA: b\r\n\r\nx\r\ny\nz");
  // No blank line is added after the headers.
  assert.equal(crlfHead("GET / HTTP/1.1\nHost: a"), "GET / HTTP/1.1\r\nHost: a");
  const bin = "POST / HTTP/1.1\nHost: a\n\n\x89PNG\r\n\x1a\n\x00";
  assert.equal(crlfHead(bin), "POST / HTTP/1.1\r\nHost: a\r\n\r\n\x89PNG\r\n\x1a\n\x00");
  assert.equal(requestToSend(bin, { binary: true, autoEncode: true, options: { verbatim: true } }).text, crlfHead(bin));
  // CRLF body never touches a binary body.
  assert.equal(requestToSend(bin, { binary: true, autoEncode: true, options: { verbatim: true, crlfBody: true } }).text, crlfHead(bin));
});

test("sent as typed, an unedited body from Traffic keeps its bytes and its length", () => {
  // Pretty-printed JSON with bare LF: Content-Length still matches what goes out.
  const body = '{\n  "a": 1,\n  "b": 2\n}';
  const raw = `POST /api HTTP/1.1\r\nHost: a.test\r\nContent-Length: ${body.length}\r\n\r\n${body}`;
  const { text } = requestToSend(raw, { autoEncode: true, options: { verbatim: true } });
  assert.equal(text, raw);
  assert.equal(text.slice(text.indexOf("\r\n\r\n") + 4).length, body.length);
  // A bare LF typed in the body (a chunk line probe) goes out as a bare LF.
  const probe = "POST / HTTP/1.1\nHost: a\nTransfer-Encoding: chunked\n\n1\nx\r\n0\r\n\r\n";
  assert.equal(requestToSend(probe, { autoEncode: false, options: { verbatim: true } }).text, "POST / HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked\r\n\r\n1\nx\r\n0\r\n\r\n");
});

test("CRLF body changes only the body, whether or not it's sent as typed", () => {
  assert.equal(crlfBody("POST / HTTP/1.1\nHost: a\n\na\nb\r\nc"), "POST / HTTP/1.1\nHost: a\n\na\r\nb\r\nc");
  // No header end: no body to change.
  assert.equal(crlfBody("GET / HTTP/1.1\nHost: a"), "GET / HTTP/1.1\nHost: a");
  // Not sent as typed: the head is left to the CLI, after auto URL-encode.
  const raw = "POST /a b HTTP/1.1\nHost: a\n\n0\n\n";
  const r = requestToSend(raw, { autoEncode: true, options: { crlfBody: true } });
  assert.deepEqual(r, { text: "POST /a%20b HTTP/1.1\nHost: a\n\n0\r\n\r\n", encoded: 1 });
  assert.deepEqual(activeLabels({ crlfBody: true }, "http"), ["CRLF body"]);
  assert.deepEqual(optionArgs({ crlfBody: true }, "http"), []);
  assert.deepEqual(activeLabels({ crlfBody: true }, "ws"), []);
});

test("an invalid timeout shows as invalid and is never passed", () => {
  for (const t of ["abc", "-1", "5s", "0", "100000", "NaN"]) {
    assert.deepEqual(activeLabels({ timeout: t }, "http"), ["timeout invalid"], t);
    assert.deepEqual(optionArgs({ timeout: t }, "http"), [], t);
    assert.deepEqual(optionArgs({ timeout: t }, "ws"), [], t);
  }
});

test("a step sent with other options than the tab has now says so", () => {
  assert.equal(sentWithNote(["HTTP/2", "SNI x"], ["HTTP/2", "SNI x"]), null);
  assert.equal(sentWithNote(undefined, ["HTTP/2"]), null);
  assert.equal(sentWithNote(["HTTP/2", "SNI x"], []), "sent with: HTTP/2, SNI x");
  assert.equal(sentWithNote([], ["not recorded"]), "sent with the default options");
});

test("a timeout that's accepted goes out as a plain positive number", () => {
  for (const [typed, arg] of [
    ["1e-3", "--timeout=0.001"],
    ["+5", "--timeout=5"],
    ["0x10", "--timeout=16"],
    ["86400", "--timeout=86400"],
  ]) {
    assert.equal(optionsProblem({ timeout: typed }), null, typed);
    assert.deepEqual(optionArgs({ timeout: typed }, "http"), [arg], typed);
  }
  // Blank is the default: no problem, no flag, no chip.
  assert.equal(optionsProblem({ timeout: "   " }), null);
  assert.deepEqual(optionArgs({ timeout: "   " }, "ws"), []);
  assert.deepEqual(activeLabels({ timeout: "   " }, "ws"), []);
  for (const t of ["86400.5", "Infinity", "NaN", "1_000", "5s", "--5"]) assert.match(optionsProblem({ timeout: t }) ?? "", /Timeout/, t);
});

test("an SNI value can't smuggle in another argument or line", () => {
  for (const s of ["a.test --no-store", "a.test\n--verbatim", "a.test\tb", "a\r\nb"]) assert.match(optionsProblem({ sni: s }) ?? "", /SNI/, JSON.stringify(s));
  // Surrounding blanks are trimmed; blank only is the target's host.
  assert.equal(optionsProblem({ sni: "  a.test\n" }), null);
  assert.deepEqual(optionArgs({ sni: "  a.test\n" }, "http"), ["--sni=a.test"]);
  assert.equal(optionsProblem({ sni: " \t " }), null);
  assert.deepEqual(optionArgs({ sni: " \t " }, "http"), []);
  assert.deepEqual(activeLabels({ sni: " \t " }, "http"), []);
});

test("options never move the target or the stdin '-'", () => {
  const all = { http2: true, verbatim: true, sni: "s.test", timeout: "9", verifyTls: true, noStore: true };
  const args = sendArgs("http://a.test:8080", all);
  assert.deepEqual(args.slice(0, 2), ["send", "--target=http://a.test:8080"]);
  assert.equal(args.at(-1), "-");
  assert.equal(args.filter((a) => a === "-").length, 1);
  // Every option is one --flag or --flag=value argument.
  for (const a of args.slice(2, -1)) assert.match(a, /^--[a-z0-9-]+(=.*)?$/, a);
});

test("each flag has its chip, so nothing is sent that the tab doesn't show", () => {
  const keys = ["http2", "verbatim", "verifyTls", "noStore"] as const;
  for (let mask = 0; mask < 64; mask++) {
    const o: Record<string, unknown> = {};
    keys.forEach((k, i) => (o[k] = !!(mask & (1 << i))));
    if (mask & 16) o.sni = "s.test";
    if (mask & 32) o.timeout = "7";
    for (const kind of ["http", "ws"] as const) assert.equal(optionArgs(o, kind).length, activeLabels(o, kind).length, `${kind} ${mask}`);
  }
});

test("withDefaults gives a new object and leaves the defaults alone", () => {
  const o = withDefaults(undefined);
  o.http2 = true;
  o.sni = "x";
  assert.deepEqual(DEFAULT_OPTIONS, { http2: false, verbatim: false, crlfBody: false, sni: "", timeout: "", verifyTls: false, noStore: false });
  // Reset merges the defaults over a tab's options, as the Options row does.
  assert.deepEqual({ ...withDefaults({ verbatim: true, timeout: "3" }), ...DEFAULT_OPTIONS }, DEFAULT_OPTIONS);
});

test("not sent as typed, the request is what it was before options existed", () => {
  const raw = "GET /a b?q=<x> HTTP/1.1\nHost: a.test\n\nname=a b";
  assert.deepEqual(requestToSend(raw, { autoEncode: true }), autoEncodeRequest(raw));
  assert.deepEqual(requestToSend(raw, { autoEncode: true, options: { http2: true, sni: "s", noStore: true } }), autoEncodeRequest(raw));
  assert.deepEqual(requestToSend(raw, { autoEncode: false, options: DEFAULT_OPTIONS }), { text: raw, encoded: 0 });
  // Binary bodies are left alone when auto URL-encode is off.
  const bin = "POST / HTTP/1.1\nHost: a\n\n\x00\n\xff";
  assert.deepEqual(requestToSend(bin, { binary: true, autoEncode: false }), { text: bin, encoded: 0 });
});

test("sent as typed: the auto URL-encode setting doesn't matter and nothing else changes", () => {
  // A wrong Content-Length and a missing header end stay as typed; a lone CR stays a CR.
  const raw = "GET /a b HTTP/1.1\nHost: a.test\nContent-Length: 99\nX: a\rb";
  const on = requestToSend(raw, { autoEncode: true, options: { verbatim: true } });
  assert.deepEqual(requestToSend(raw, { autoEncode: false, options: { verbatim: true } }), on);
  assert.equal(on.text, "GET /a b HTTP/1.1\r\nHost: a.test\r\nContent-Length: 99\r\nX: a\rb");
  // Already CRLF: unchanged, never \r\r\n.
  const crlf = "GET / HTTP/1.1\r\nHost: a\r\n\r\n";
  assert.equal(requestToSend(crlf, { autoEncode: true, options: { verbatim: true } }).text, crlf);
  assert.equal(requestToSend("", { autoEncode: true, options: { verbatim: true } }).text, "");
});

test("sent as typed: only the head's line breaks change", () => {
  // No header end: the whole text is the head.
  assert.equal(crlfHead("GET / HTTP/1.1\nHost: a"), "GET / HTTP/1.1\r\nHost: a");
  // A CRLF header end and a body with bare \n: the body keeps its bytes.
  const bin = "POST / HTTP/1.1\r\nHost: a\r\n\r\n\n\x01\n\n\x02";
  assert.equal(crlfHead(bin), bin);
  // Text tab: the body's \n stay \n unless CRLF body is on.
  const text = "POST / HTTP/1.1\nHost: a\n\na\nb";
  assert.equal(requestToSend(text, { autoEncode: true, options: { verbatim: true } }).text, "POST / HTTP/1.1\r\nHost: a\r\n\r\na\nb");
  assert.equal(requestToSend(text, { autoEncode: true, options: { verbatim: true, crlfBody: true } }).text, "POST / HTTP/1.1\r\nHost: a\r\n\r\na\r\nb");
});

test("WebSocket options go after --until and before the stdin flags", () => {
  const args = wsSendArgs({ target: "wss://a.test", wait: 2, until: "done", options: { sni: "s.test", noStore: true, verbatim: true, http2: true } });
  assert.deepEqual(args, ["ws", "send", "--target=wss://a.test", "--wait", "2", "--until=done", "--sni=s.test", "--no-store", "--input-json", "--max-body=2000000"]);
  // No options, or the defaults: the same arguments as before options existed.
  assert.deepEqual(wsSendArgs({ target: "ws://a", wait: 1, options: DEFAULT_OPTIONS }), wsSendArgs({ target: "ws://a", wait: 1 }));
  assert.ok(!wsSendArgs({ target: "ws://a", wait: 1, options: { timeout: "30" } }).some((a) => a.startsWith("--timeout")));
});
