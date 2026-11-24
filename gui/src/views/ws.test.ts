import { test } from "node:test";
import assert from "node:assert/strict";
import {
  closedSince,
  CONN_PAGE,
  newerArgs,
  newestArgs,
  NO_CONNS,
  olderArgs,
  openArgs,
  recheckArgs,
  RECHECK_MAX,
  withNewer,
  withNewest,
  withOlder,
  withUpdated,
  type WsConnection,
  base64Bytes,
  connectionMessages,
  HANDOFF_MAX,
  payloadPrefix,
  hexBytes,
  isWsOut,
  joinMessages,
  messagesSummary,
  payloadPreview,
  replayMessage,
  splitMessages,
  toBase64,
  toHex,
  wsOrigin,
  wsSendArgs,
  wsSendInput,
  HEX_MAX,
  type WsMessage,
  type WsOut,
} from "./ws.ts";

test("messages are split on lines holding only ---", () => {
  assert.deepEqual(splitMessages('{"a":1}\n---\nline one\nline two\r\n  ---  \n\n---\nlast'), ['{"a":1}', "line one\nline two", "last"]);
  assert.deepEqual(splitMessages(""), []);
  // A --- inside a line is part of the message.
  assert.deepEqual(splitMessages("a --- b"), ["a --- b"]);
  assert.deepEqual(splitMessages(joinMessages(["x", "y\nz"])), ["x", "y\nz"]);
});

test("messages go on stdin, never in the arguments", () => {
  const args = wsSendArgs({ target: "wss://a.test", wait: 3, until: "ok" });
  assert.deepEqual(args, ["ws", "send", "--target=wss://a.test", "--wait", "3", "--until=ok", "--input-json", "--max-body=2000000"]);
  assert.ok(!wsSendArgs({ target: "ws://a", wait: 1 }).some((a) => a.startsWith("--until")));
  assert.deepEqual(JSON.parse(wsSendInput("GET / HTTP/1.1\n\n", ["--not-a-flag", "token=secret"])), { handshake: "GET / HTTP/1.1\n\n", messages: ["--not-a-flag", "token=secret"] });
});

test("a ws URL's origin is the http origin of its handshake", () => {
  assert.equal(wsOrigin("wss://a.test:8443/chat?x=1"), "https://a.test:8443");
  assert.equal(wsOrigin("ws://a.test/chat"), "http://a.test");
  assert.equal(wsOrigin("not a url"), "");
});

test("--- hex and --- base64 make the next message binary, kept as typed", () => {
  const text = "--- hex\n00 ff\n0a\n---\nhello\n--- BASE64\nAP8=\n--- text\n--- hex not a separator";
  const msgs = splitMessages(text);
  assert.deepEqual(msgs, [{ hex: "00 ff\n0a" }, "hello", { base64: "AP8=" }, "--- hex not a separator"]);
  // Back to the same messages; text alone is joined as before.
  assert.deepEqual(splitMessages(joinMessages(msgs)), msgs);
  assert.equal(joinMessages(["a", "b"]), "a\n---\nb");
  assert.equal(joinMessages(["a", { hex: "00" }]), "a\n--- hex\n00");
  // A plain separator with nothing after it adds no message; a named one is an empty message.
  assert.deepEqual(splitMessages("a\n---\n  \n---"), ["a"]);
  assert.deepEqual(splitMessages("a\n--- hex\n--- text\n---\nb"), ["a", { hex: "" }, "", "b"]);
});

test("every message comes back from the box as it went in, separator-like lines and empty ones included", () => {
  const cases: WsOut[][] = [
    // Saved as text by 0.9.0: lines that now read as separators stay text.
    ["title: x\n--- hex\nbody", "---", "  --- BASE64  ", "\\--- text", "a\n\\\\---\nb"],
    [{ hex: "" }, "", "  ", { base64: "" }, "x"],
    ["", { hex: "00\n---\nff" }],
    [{ base64: "AP8=" }],
  ];
  for (const msgs of cases) assert.deepEqual(splitMessages(joinMessages(msgs)), msgs, JSON.stringify(msgs));
  // Typed by hand: a backslash keeps a separator-like line as text, and is taken off.
  assert.deepEqual(splitMessages("a\n\\--- hex\nb"), ["a\n--- hex\nb"]);
  assert.equal(joinMessages(["title\n--- hex"]), "title\n\\--- hex");
});

test("hex and base64 are read as ws send reads them, with a reason when they aren't", () => {
  assert.deepEqual([...hexBytes("0x00 ff:0A\n7f")], [0, 255, 10, 127]);
  assert.deepEqual([...hexBytes("")], []);
  assert.throws(() => hexBytes("0g"), /“g” isn't a hex digit/);
  assert.throws(() => hexBytes("abc"), /odd number of hex digits \(3\)/);
  // Only ASCII whitespace is skipped, as ws send skips it.
  assert.throws(() => hexBytes("00\u00a0ff"), /isn't a hex digit/);
  assert.throws(() => base64Bytes("AP8\u00a0="), /isn't a base64 character/);
  // Bits left over in the last character: ws send refuses them, so the app does too.
  assert.throws(() => base64Bytes("AB=="), /bits left over/);
  assert.throws(() => base64Bytes("AP9"), /bits left over/);
  assert.deepEqual([...base64Bytes("AJ+S\nlg==")], [0, 159, 146, 150]);
  assert.deepEqual([...base64Bytes("AJ-Slg")], [0, 159, 146, 150]);
  assert.deepEqual([...base64Bytes("AP8")], [0, 255]);
  assert.throws(() => base64Bytes("A"), /length is wrong/);
  assert.throws(() => base64Bytes("AA=A"), /only belongs at the end/);
  assert.throws(() => base64Bytes("AA!A"), /“!” isn't a base64 character/);
  assert.throws(() => base64Bytes("AA==="), /length is wrong/);
  const big = Uint8Array.from({ length: 100_000 }, (_, i) => i % 256);
  assert.deepEqual(base64Bytes(toBase64(big)), big);
  assert.equal(toHex(Uint8Array.from({ length: 17 }, (_, i) => i)), "00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f\n10");
});

test("binary messages go to ws send as checked base64, and a bad one is named before anything is sent", () => {
  const input = JSON.parse(wsSendInput("GET / HTTP/1.1\n\n", ["hi", { hex: "00 ff 0a" }, { base64: "AJ-Slg" }]));
  assert.deepEqual(input.messages, ["hi", { base64: "AP8K" }, { base64: "AJ+Slg==" }]);
  assert.throws(() => wsSendInput("", ["a", { hex: "zz" }]), /^Error: Message 2 \(hex\): “z” isn't a hex digit$/);
  assert.deepEqual(messagesSummary(["a", { hex: "00" }]), { text: "2 messages (1 binary)", problem: false });
  assert.deepEqual(messagesSummary(["a"]), { text: "1 message", problem: false });
  assert.deepEqual(messagesSummary([]), { text: "", problem: false });
  assert.deepEqual(messagesSummary([{ base64: "A" }]), { text: "Message 1 (base64): its length is wrong for base64; is a character missing?", problem: true });
});

test("a recorded message goes to Replay with its bytes exactly", () => {
  assert.equal(replayMessage({ id: 1, opcode: "text", payload: { encoding: "utf8", content: "hé" } }), "hé");
  assert.deepEqual(replayMessage({ id: 2, opcode: "binary", payload: { encoding: "base64", content: "AJ+Slg==" } }), { hex: "00 9f 92 96" });
  // A binary payload that happens to be UTF-8 is listed as text; its bytes are still sent.
  assert.deepEqual(replayMessage({ id: 3, opcode: "binary", payload: { encoding: "utf8", content: "é" } }), { hex: "c3 a9" });
  // Large ones as base64, a third the size of hex.
  const big = Uint8Array.from({ length: HEX_MAX + 1 }, (_, i) => i % 256);
  const m = replayMessage({ id: 4, opcode: "binary", payload: { encoding: "base64", content: toBase64(big) } });
  assert.deepEqual(m, { base64: toBase64(big) });
  assert.throws(() => replayMessage({ id: 5, opcode: "ping", payload: { encoding: "utf8", content: "" } }), /ping frame/);
  // Round trip through the box and ws send: the bytes the proxy saw.
  const sent = JSON.parse(wsSendInput("", splitMessages(joinMessages([replayMessage({ id: 2, opcode: "binary", payload: { encoding: "base64", content: "AJ+Slg==" } })]))));
  assert.deepEqual(sent.messages, [{ base64: "AJ+Slg==" }]);
});

test("a binary message's preview is hex and its printable ASCII, whatever its bytes are", () => {
  assert.equal(payloadPreview({ opcode: "binary", payload: { encoding: "base64", content: "AJ+Slg==", length: 4 }, length: 4 }, 300), "(4 bytes) 00 9f 92 96  ....");
  assert.equal(payloadPreview({ opcode: "binary", payload: { encoding: "utf8", content: '{"a":1}', length: 40, truncated: true }, length: 40 }, 12), '(40 bytes) 7b 22 61 …  {"a…');
  assert.equal(payloadPreview({ opcode: "text", payload: { encoding: "utf8", content: "x".repeat(10) } }, 4), "xxxx…");
});

test("a preview decodes only the bytes it shows", () => {
  const big = Uint8Array.from({ length: 2_000_000 }, (_, i) => i % 256);
  const b64 = { encoding: "base64" as const, content: toBase64(big) };
  const started = performance.now();
  for (let i = 0; i < 200; i++) payloadPreview({ opcode: "binary", payload: b64, length: big.length }, 300);
  assert.ok(performance.now() - started < 500, "200 previews of 2 MB payloads");
  assert.deepEqual([...payloadPrefix(b64, 5)], [0, 1, 2, 3, 4]);
  assert.deepEqual([...payloadPrefix({ encoding: "base64", content: "AP8=" }, 10)], [0, 255]);
  // Text by code point: a character outside the BMP isn't split into a bad surrogate.
  assert.deepEqual([...payloadPrefix({ encoding: "utf8", content: "😀é" }, 4)], [0xf0, 0x9f, 0x98, 0x80]);
  assert.deepEqual([...payloadPrefix({ encoding: "utf8", content: "aé" }, 2)], [0x61, 0xc3]);
});

test("a connection goes to Replay with its first text and binary messages, in order", () => {
  const msg = (id: number, opcode: "text" | "binary", content: string, truncated = false): WsMessage => ({
    id,
    direction: "to-server",
    opcode,
    compressed: false,
    payload: opcode === "text" ? { encoding: "utf8", content, truncated } : { encoding: "base64", content, truncated },
  });
  const text = [msg(1, "text", "a"), msg(4, "text", "b")];
  const binary = [msg(2, "binary", "AP8="), msg(3, "binary", "AA==")];
  assert.deepEqual(connectionMessages(text, binary), ["a", { hex: "00 ff" }, { hex: "00" }, "b"]);
  // One limit across both types.
  const many = (from: number, op: "text" | "binary") => Array.from({ length: HANDOFF_MAX }, (_, i) => msg(from + i * 2, op, op === "text" ? `t${i}` : "AA=="));
  const r = connectionMessages(many(1, "text"), many(2, "binary"));
  assert.equal(r.length, HANDOFF_MAX);
  assert.deepEqual(r.slice(0, 3), ["t0", { hex: "00" }, "t1"]);
  // A message cut short is refused, not sent in part.
  assert.throws(() => connectionMessages([msg(1, "text", "a")], [msg(2, "binary", "AA==", true)]), /Message #2/);
  // Beyond the limit, a cut-short message doesn't matter.
  assert.equal(connectionMessages(many(1, "text"), [msg(1000, "binary", "AA==", true)]).length, HANDOFF_MAX);
});

test("only strings and single hex or base64 fields are saved messages", () => {
  for (const m of ["a", { hex: "00" }, { base64: "" }]) assert.ok(isWsOut(m), JSON.stringify(m));
  for (const m of [1, null, [], {}, { hex: 1 }, { hex: "00", base64: "AA==" }, { utf16: "x" }]) assert.ok(!isWsOut(m), JSON.stringify(m));
});

// ---------------- The connection list ----------------

const conn = (id: number, patch: Partial<WsConnection> = {}): WsConnection => ({
  id,
  time: "2026-01-01T00:00:00Z",
  source: "proxy",
  history_id: id,
  url: `ws://a.test/c${id}`,
  host: "a.test",
  extensions: null,
  protocol: null,
  state: "closed",
  closed_time: null,
  close_code: 1000,
  close_reason: null,
  messages: 1,
  error: null,
  ...patch,
});
const conns = (from: number, to: number) => Array.from({ length: to - from + 1 }, (_, i) => conn(from + i));

test("the list starts with the newest page and pages back past it with --before", () => {
  assert.deepEqual(newestArgs(), ["ws", "list", "--newest", "--limit", String(CONN_PAGE)]);
  assert.equal(olderArgs(NO_CONNS), null, "nothing loaded yet");
  // A full newest page: older ones may exist.
  let l = withNewest(conns(5001, 10000));
  assert.ok(l.more);
  assert.deepEqual(olderArgs(l), ["ws", "list", "--newest", "--before=5001", "--limit", String(CONN_PAGE)]);
  l = withOlder(l, conns(1, 5000));
  assert.equal(l.items.length, 10000);
  assert.deepEqual([l.items[0].id, l.items.at(-1)!.id], [1, 10000]);
  // Still a full page: one more call says there is nothing before it.
  assert.ok(l.more);
  l = withOlder(l, []);
  assert.ok(!l.more);
  assert.equal(olderArgs(l), null);
  // A short first page has nothing older.
  assert.equal(olderArgs(withNewest(conns(1, 3))), null);
});

test("new connections are added after the newest, each once", () => {
  let l = withNewest(conns(1, 3));
  assert.deepEqual(newerArgs(l), ["ws", "list", "--after=3", "--limit", String(CONN_PAGE)]);
  l = withNewer(l, [conn(3), conn(4), conn(5)]);
  assert.deepEqual(
    l.items.map((c) => c.id),
    [1, 2, 3, 4, 5],
  );
  assert.equal(withNewer(l, [conn(5)]), l, "nothing new: the same list");
  assert.deepEqual(newerArgs(NO_CONNS), ["ws", "list", "--after=0", "--limit", String(CONN_PAGE)]);
});

test("open connections are refreshed, and ones that closed are read again", () => {
  let l = withNewest([conn(1), conn(2, { state: "open", messages: 1 }), conn(3), conn(4, { state: "open" }), conn(5, { state: "open" })]);
  assert.deepEqual(openArgs(l), ["ws", "list", "--state=open", "--after=1", "--limit", String(CONN_PAGE)]);
  // 2 has more messages, 4 closed, 5 is still open.
  const open = [conn(2, { state: "open", messages: 9 }), conn(5, { state: "open" })];
  assert.deepEqual(closedSince(l, open), [4]);
  l = withUpdated(l, open);
  assert.equal(l.items[1].messages, 9);
  assert.deepEqual(recheckArgs(4), ["ws", "list", "--after=3", "--before=5", "--limit", "1"]);
  l = withUpdated(l, [conn(4, { close_code: 1001 })]);
  assert.deepEqual([l.items[3].state, l.items[3].close_code], ["closed", 1001]);
  assert.equal(withUpdated(l, [conn(4, { close_code: 1001 })]), l, "unchanged: the same list");
  assert.equal(openArgs(withNewest(conns(1, 2))), null, "none open: nothing to ask");
  // A full answer says nothing about ids past its last one.
  const many = withNewest(Array.from({ length: CONN_PAGE + 2 }, (_, i) => conn(i + 1, { state: "open" })));
  const full = Array.from({ length: CONN_PAGE }, (_, i) => conn(i + 1, { state: "open" })).filter((c) => c.id !== 7);
  full.push(conn(CONN_PAGE + 1, { state: "open" }));
  assert.deepEqual(closedSince(many, full), [7]);
  // At most RECHECK_MAX are read again per poll, the oldest first.
  const lots = withNewest(Array.from({ length: 50 }, (_, i) => conn(i + 1, { state: "open" })));
  assert.deepEqual(
    closedSince(lots, []),
    Array.from({ length: RECHECK_MAX }, (_, i) => i + 1),
  );
});
