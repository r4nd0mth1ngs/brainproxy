import { test } from "node:test";
import assert from "node:assert/strict";
import {
  base64Bytes,
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
  // A separator with nothing after it adds no message.
  assert.deepEqual(splitMessages("a\n--- hex\n  \n"), ["a"]);
});

test("hex and base64 are read as ws send reads them, with a reason when they aren't", () => {
  assert.deepEqual([...hexBytes("0x00 ff:0A\n7f")], [0, 255, 10, 127]);
  assert.deepEqual([...hexBytes("")], []);
  assert.throws(() => hexBytes("0g"), /“g” isn't a hex digit/);
  assert.throws(() => hexBytes("abc"), /odd number of hex digits \(3\)/);
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

test("a binary message's preview is hex, whatever its bytes are", () => {
  assert.equal(payloadPreview({ opcode: "binary", payload: { encoding: "base64", content: "AJ+Slg==", length: 4 }, length: 4 }, 300), "(4 bytes) 00 9f 92 96");
  assert.equal(payloadPreview({ opcode: "binary", payload: { encoding: "utf8", content: "abcd", length: 40, truncated: true }, length: 40 }, 9), "(40 bytes) 61 62 63 …");
  assert.equal(payloadPreview({ opcode: "text", payload: { encoding: "utf8", content: "x".repeat(10) } }, 4), "xxxx…");
});

test("only strings and single hex or base64 fields are saved messages", () => {
  for (const m of ["a", { hex: "00" }, { base64: "" }]) assert.ok(isWsOut(m), JSON.stringify(m));
  for (const m of [1, null, [], {}, { hex: 1 }, { hex: "00", base64: "AA==" }, { utf16: "x" }]) assert.ok(!isWsOut(m), JSON.stringify(m));
});
