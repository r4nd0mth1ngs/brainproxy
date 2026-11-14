import { test } from "node:test";
import assert from "node:assert/strict";
import { shownSimilarity, type Similarity } from "./comparerSimilarity.ts";

const s: Similarity = { a: "HTTP/1.1 200 OK\r\n\r\nhello", b: "HTTP/1.1 200 OK\r\n\r\nhullo", unit: "lines", value: 0.5 };

test("the CLI's similarity shows only for the pair and unit it was worked out for", () => {
  assert.equal(shownSimilarity(s, s.a, s.b, "lines"), 0.5);
  assert.equal(shownSimilarity(s, s.a, s.b, "bytes"), null, "another unit: the line similarity doesn't hold");
  assert.equal(shownSimilarity(s, s.b, s.a, "lines"), null, "swapped");
  // Clear all, then two other items in the same places.
  assert.equal(shownSimilarity(s, "GET / HTTP/1.1", "GET /a HTTP/1.1", "lines"), null);
  assert.equal(shownSimilarity(s, s.a, undefined, "lines"), null);
  assert.equal(shownSimilarity(null, s.a, s.b, "lines"), null);
  // The same texts are the same pair wherever they are in the list.
  assert.equal(shownSimilarity(s, `${s.a}`, `${s.b}`, "lines"), 0.5);
});
