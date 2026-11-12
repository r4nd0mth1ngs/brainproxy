import { test } from "node:test";
import assert from "node:assert/strict";
import { raceArgs } from "./race.ts";
import { DEFAULT_OPTIONS, validServerName, activeLabels, crlfBody, crlfHead, curlOptions, optionArgs, optionsProblem, requestToSend, savedOptions, sendArgs, sendsAsTyped, sentWithNote, withDefaults } from "./replayOptions.ts";
import { autoEncodeRequest } from "../ui/urlencode.ts";
import { parseCurl, toCurl } from "../ui/curl.ts";
import { wsSendArgs } from "./ws.ts";

test("default options add no flags and show nothing", () => {
  assert.deepEqual(sendArgs("https://a.test", undefined), ["send", "--target=https://a.test", "-"]);
  assert.deepEqual(sendArgs("https://a.test", DEFAULT_OPTIONS), ["send", "--target=https://a.test", "-"]);
  assert.deepEqual(activeLabels(undefined, "http"), []);
  // A tab saved before a field existed gets its default.
  assert.deepEqual(withDefaults({ http2: true }), { ...DEFAULT_OPTIONS, http2: true });
});

test("every option maps to its send flag, before the stdin '-'", () => {
  const o = { verbatim: true, sni: " other.test ", timeout: "5", verifyTls: true, noStore: true };
  assert.deepEqual(sendArgs("https://a.test", o), ["send", "--target=https://a.test", "--verbatim", "--sni=other.test", "--timeout=5", "--verify-tls", "--no-store", "-"]);
  assert.deepEqual(activeLabels(o, "http"), ["as typed", "SNI other.test", "timeout 5 s", "verify TLS", "not recorded"]);
  assert.deepEqual(sendArgs("https://a.test", { http2: true }), ["send", "--target=https://a.test", "--http2", "-"]);
  assert.deepEqual(activeLabels({ http2: true }, "http"), ["HTTP/2"]);
});

test("send as typed is HTTP/1 only: with HTTP/2 on it isn't passed, shown or applied", () => {
  const o = { http2: true, verbatim: true, sni: "s.test" };
  assert.equal(sendsAsTyped(o), false);
  assert.equal(sendsAsTyped({ verbatim: true }), true);
  assert.equal(sendsAsTyped(undefined), false);
  // HTTP/2 rebuilds the request into frames, so --verbatim would only mislead.
  assert.deepEqual(sendArgs("https://a.test", o), ["send", "--target=https://a.test", "--http2", "--sni=s.test", "-"]);
  assert.deepEqual(activeLabels(o, "http"), ["HTTP/2", "SNI s.test"]);
  // The request goes as without "as typed": auto URL-encode applies, the head isn't rewritten.
  const raw = "GET /a b HTTP/1.1\nHost: a.test\n\n";
  assert.deepEqual(requestToSend(raw, { autoEncode: true, options: o }), autoEncodeRequest(raw));
  assert.deepEqual(requestToSend(raw, { autoEncode: false, options: o }), { text: raw, encoded: 0 });
  // The choice is kept, and applies again once HTTP/2 is off.
  assert.deepEqual(optionArgs({ ...o, http2: false }, "http"), ["--verbatim", "--sni=s.test"]);
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
  for (const t of ["abc", "-1", "5s", "0", "100000", "NaN", "0x10", "1e3"]) {
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
  // The SNI a step went out with is named, also when only the SNI changed since.
  assert.equal(sentWithNote(activeLabels({ sni: "a.test" }, "http"), activeLabels({ sni: "b.test" }, "http")), "sent with: SNI a.test");
});

test("a timeout that's accepted goes out as a plain positive number", () => {
  for (const [typed, arg] of [
    ["0.001", "--timeout=0.001"],
    ["05", "--timeout=5"],
    ["2.50", "--timeout=2.5"],
    [" 86400 ", "--timeout=86400"],
  ]) {
    assert.equal(optionsProblem({ timeout: typed }), null, typed);
    assert.deepEqual(optionArgs({ timeout: typed }, "http"), [arg], typed);
  }
  // Blank is the default: no problem, no flag, no chip.
  assert.equal(optionsProblem({ timeout: "   " }), null);
  assert.deepEqual(optionArgs({ timeout: "   " }, "ws"), []);
  assert.deepEqual(activeLabels({ timeout: "   " }, "ws"), []);
  for (const t of ["86400.5", "Infinity", "NaN", "1_000", "5s", "--5"]) assert.match(optionsProblem({ timeout: t }) ?? "", /Timeout/, t);
  // Only plain digits with an optional decimal part: Number() would take all of these.
  for (const t of ["0x10", "1e3", "1e-3", "+5", ".5", "5.", "0b1", "1 0", "1,5"]) {
    assert.match(optionsProblem({ timeout: t }) ?? "", /plain number/, t);
    assert.deepEqual(optionArgs({ timeout: t }, "http"), [], t);
  }
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
  assert.deepEqual(DEFAULT_OPTIONS, { http2: false, http3: false, verbatim: false, crlfBody: false, sni: "", timeout: "", verifyTls: false, noStore: false });
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

test("Copy as cURL sends the way the tab does", () => {
  const raw = "POST /a HTTP/1.1\nHost: h.test\nContent-Type: text/plain\n\nl1\nl2";
  const copy = (o: Parameters<typeof curlOptions>[0], target = "https://h.test") =>
    toCurl(requestToSend(raw, { autoEncode: true, options: o }).text, target, false, curlOptions(o));
  // Defaults: HTTP/1.1 kept, -k as Send doesn't check certificates, no warnings.
  const plain = copy(undefined);
  assert.match(plain.command, /--http1\.1 \\\n {2}-k /);
  assert.doesNotMatch(plain.command, /--max-time/);
  assert.deepEqual(plain.warnings, []);
  // -k only for https, and not with Verify TLS.
  assert.doesNotMatch(copy(undefined, "http://h.test").command, / -k/);
  assert.doesNotMatch(copy({ verifyTls: true }).command, / -k/);
  // HTTP/2 with an HTTP/1.1 request line, as send --http2.
  const h2 = copy({ http2: true });
  assert.match(h2.command, /--http2 /);
  assert.doesNotMatch(h2.command, /--http1/);
  assert.match(copy({ http2: true }, "http://h.test").command, /--http2-prior-knowledge/);
  // CRLF body: the body's line breaks go out as CRLF (through printf, as \r is a control byte).
  const crlf = copy({ crlfBody: true });
  assert.match(crlf.command, /printf 'l1\\015\\nl2'/);
  assert.equal(parseCurl(crlf.command).raw.split("\n\n")[1], "l1\r\nl2");
  // A timeout other than the default is --max-time; the default isn't written.
  assert.match(copy({ timeout: "2.5" }).command, /--max-time 2\.5/);
  assert.doesNotMatch(copy({ timeout: "30" }).command, /--max-time/);
  // What curl can't do is said.
  assert.match(copy({ verbatim: true }).warnings.join("\n"), /Send as typed can't be reproduced by curl/);
  assert.deepEqual(copy({ verbatim: true, http2: true }).warnings, []);
  assert.match(copy({ sni: "other.test" }).warnings.join("\n"), /not the tab's SNI \(other\.test\)/);
  assert.deepEqual(copy({ sni: "other.test" }, "http://h.test").warnings, []);
});

test("an SNI must be a TLS server name, as the CLI's --sni takes", () => {
  for (const ok of ["a.test", "a.test.", "x_y.test", "a-b.test", "localhost", "10.0.0.1", "::1", "2001:db8::1", "a".repeat(63) + ".test"]) assert.equal(validServerName(ok), true, ok);
  for (const bad of ["", "-a.test", "a-.test", "a..test", "1.2.3", "300.1.1.1", "a.test/x", "a b", "a".repeat(64) + ".test", "x." + "a".repeat(250), ":::x", "[::1]"])
    assert.equal(validServerName(bad), false, bad);
  assert.match(optionsProblem({ sni: "-x.test" }) ?? "", /isn't a valid TLS server name/);
  assert.equal(optionsProblem({ sni: "x.test" }), null);
});

test("an IPv6 SNI is read as rustls reads it, which a URL's host parser isn't", () => {
  // Each checked against rustls-pki-types' ServerName, which `--sni` and `replay tabs save` use.
  for (const ok of ["::", "1::", "::2:3:4:5:6:7:8", "1:2:3:4:5:6:7::", "1:2:3:4:5:6:7:8", "ABCD::ef01", "0000::0001", "::1.2.3.4", "::ffff:10.0.0.1", "1:2:3:4:5::1.2.3.4", "1:2:3:4:5:6:1.2.3.4"])
    assert.equal(validServerName(ok), true, ok);
  for (const bad of [
    // A URL takes these: the rest of a URL after the address.
    "::1]/x/[", "::1]?a=[", "::1]#[", "::1:",
    // Nor are these addresses.
    "fe80::1%eth0", "1:2:3:4:5:6:7:8:9", "1:2:3:4:5:6:7:8::", "1::2:3:4:5:6:7:8", "1::2::3", ":::", "1:::2", ":1", "1:", "12345::", "::0x1",
    // An IPv4 part only at the end, with no octet over 255 or with a leading zero, and not before a ::.
    "::1.2.3", "::1.2.3.04", "::256.1.1.1", "::1.2.3.4:5", "1.2.3.4::", "1:2:3:4:5:6::1.2.3.4", "1:2:3:4:5:6:7:1.2.3.4",
  ])
    assert.equal(validServerName(bad), false, bad);
  // Left out of a saved tab rather than failing the save.
  assert.equal(savedOptions({ sni: "::1]/x/[" }, "http"), undefined);
  assert.deepEqual(savedOptions({ sni: " ::1 " }, "http"), { sni: "::1" });
});

test("HTTP/3: its flag, label and saved option, never as typed, and not for races or ws tabs", () => {
  const o = { ...DEFAULT_OPTIONS, http3: true, verbatim: true };
  assert.deepEqual(sendArgs("https://a.test", o), ["send", "--target=https://a.test", "--http3", "-"]);
  assert.equal(sendsAsTyped(o), false);
  assert.deepEqual(activeLabels(o, "http"), ["HTTP/3"]);
  assert.deepEqual(optionArgs(o, "ws"), []);
  assert.deepEqual(savedOptions(o, "http"), { http3: true, verbatim: true });
  assert.equal(curlOptions(o).http3, true);
  assert.deepEqual(raceArgs("https://a.test", 5, o), ["send", "--target=https://a.test", "--race=5", "-"]);
});
