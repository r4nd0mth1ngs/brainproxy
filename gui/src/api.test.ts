import { test } from "node:test";
import assert from "node:assert/strict";
import { cli, run, CliError, bodyText, isBinary, requireWhole, textBytes, type Body } from "./api.ts";

const gzip = Uint8Array.from([0x1f, 0x8b, 0x08, 0x00, 0x91, 0xff, 0x00, 0x0a]);
const b64 = (bytes: Uint8Array) => btoa(String.fromCharCode(...bytes));

test("a base64 body round-trips to its exact bytes", () => {
  const body: Body = { encoding: "base64", content: b64(gzip) };
  assert.ok(isBinary(body));
  assert.deepEqual(textBytes(bodyText(body), isBinary(body)), gzip);
  // The bug: encoding that text as UTF-8 doubles every byte >= 0x80.
  assert.notDeepEqual(new TextEncoder().encode(bodyText(body)), gzip);
});

test("text bodies are UTF-8; chars above 0xFF typed into binary text go in as UTF-8", () => {
  assert.deepEqual(textBytes("é"), Uint8Array.from([0xc3, 0xa9]));
  assert.ok(!isBinary({ encoding: "utf8", content: "é" }));
  assert.deepEqual(textBytes("\xff€", true), Uint8Array.from([0xff, 0xe2, 0x82, 0xac]));
});

test("a truncated body can't be edited or sent", () => {
  assert.throws(() => requireWhole({ encoding: "utf8", content: "x", length: 3000000, truncated: true }), /3000000 bytes/);
  requireWhole({ encoding: "utf8", content: "x", length: 1, truncated: false });
});

test("race input sends each staged request as bytes with the shared cancellable call", async () => {
  const original = globalThis.fetch;
  let received: { args: string[]; stdin: number[]; requestFiles: number[][]; call: string; project: string } | undefined;
  globalThis.fetch = (async (_url: unknown, input: RequestInit) => {
    received = JSON.parse(String(input.body));
    return { json: async () => ({ ok: true, command: "send", data: {} }) } as Response;
  }) as typeof fetch;
  try {
    const args = ["send", "--target=https://shop.test", "--race=1", "--also=@request:0", "-"];
    await cli(args, { stdin: "GET / HTTP/1.1\r\n\r\n", requestFiles: [gzip], call: "replay-race-group", project: "shop.bpdb" });
    assert.deepEqual(received?.args, args);
    assert.deepEqual(received?.stdin, Array.from(new TextEncoder().encode("GET / HTTP/1.1\r\n\r\n")));
    assert.deepEqual(received?.requestFiles, [Array.from(gzip)]);
    assert.equal(received?.call, "replay-race-group");
    assert.equal(received?.project, "shop.bpdb");
  } finally {
    globalThis.fetch = original;
  }
});

test("failed race output keeps its per-request results for the Replay tabs", async () => {
  const original = globalThis.fetch;
  const data = { race: 1, total: 2, results: [{ request: 0, error: "closed", kind: "protocol" }, { request: 1, error: "closed", kind: "protocol" }] };
  try {
    // error_with places data beside error; other failures place it inside error.
    for (const envelope of [
      { ok: false, error: { kind: "protocol", message: "closed" }, data },
      { ok: false, error: { kind: "protocol", message: "closed", data } },
    ]) {
      globalThis.fetch = (async () => ({ json: async () => envelope }) as Response) as typeof fetch;
      await assert.rejects(run(["send"]), (error: unknown) => error instanceof CliError && error.data === data);
    }
  } finally {
    globalThis.fetch = original;
  }
});
