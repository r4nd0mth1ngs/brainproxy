import { test } from "node:test";
import assert from "node:assert/strict";
import {
  firstOpenable,
  isHttp2Request,
  parseRaceCount,
  plannedTechnique,
  raceArgs,
  raceMax,
  raceRows,
  raceSummary,
  syncNote,
  techniqueLabel,
  type RaceResult,
} from "./race.ts";

const H1 = "POST /redeem HTTP/1.1\nHost: shop.test\n\ncode=X";
const H2 = "POST /redeem HTTP/2\r\nHost: shop.test\r\n\r\ncode=X";

function result(results: RaceResult["results"], sync = "last-byte", synced: number | null = null): RaceResult {
  return { race: results.length, sync, synced, target: "https://shop.test", distinct_responses: {}, results };
}

test("an HTTP/2 request line means a single-packet race of at most 100", () => {
  assert.equal(isHttp2Request(H2), true);
  assert.equal(isHttp2Request(H1), false);
  assert.equal(isHttp2Request("GET / HTTP/2.0\n"), false); // the CLI only treats "HTTP/2" as HTTP/2
  assert.equal(raceMax(H1), 1000);
  assert.equal(raceMax(H2), 100);
  assert.equal(plannedTechnique(H2), "single-packet attack (HTTP/2)");
  assert.equal(plannedTechnique(H1), "last-byte sync (HTTP/1.1)");
});

test("the count must be a whole number the CLI accepts", () => {
  assert.equal(parseRaceCount("20", H1), 20);
  assert.equal(parseRaceCount(" 1000 ", H1), 1000);
  assert.equal(parseRaceCount("1001", H1), null);
  assert.equal(parseRaceCount("1", H1), null);
  assert.equal(parseRaceCount("101", H2), null);
  assert.equal(parseRaceCount("100", H2), 100);
  assert.equal(parseRaceCount("2.5", H1), null);
  assert.equal(parseRaceCount("", H1), null);
  assert.equal(parseRaceCount("-5", H1), null);
});

test("the race is Replay's send plus --race", () => {
  assert.deepEqual(raceArgs("https://shop.test", 20), ["send", "--target=https://shop.test", "--race=20", "-"]);
});

test("responses that differ from the first are marked", () => {
  const rows = raceRows(
    result([
      { id: 1, status: 200, length: 12, duration_ms: 40 },
      { id: 2, status: 200, length: 12, duration_ms: 41 },
      { id: 3, status: 200, length: 30, duration_ms: 45 },
      { id: 4, status: 409, length: 12, duration_ms: 43 },
      { error: "connection reset", kind: "io" },
    ]),
  );
  assert.deepEqual(
    rows.map((r) => r.differs),
    [false, false, true, true, true],
  );
  assert.equal(rows[4].error, "connection reset");
  assert.equal(rows[4].duration_ms, null);
});

test("when the first failed, other failures of the same kind match it", () => {
  const rows = raceRows(
    result([
      { error: "timed out", kind: "timeout" },
      { error: "timed out", kind: "timeout" },
      { id: 3, status: 200, length: 5, duration_ms: 9 },
    ]),
  );
  assert.deepEqual(
    rows.map((r) => r.differs),
    [false, false, true],
  );
  assert.equal(firstOpenable(rows), 2);
});

test("the summary gives the spread of response times and the counts", () => {
  const s = raceSummary(
    result([
      { id: 1, status: 200, length: 12, duration_ms: 40 },
      { id: 2, status: 200, length: 12, duration_ms: 47 },
      { id: 3, status: 409, length: 3, duration_ms: 42 },
      { error: "reset", kind: "io" },
    ]),
  );
  assert.deepEqual(s, { responses: 3, errors: 1, spread: 7, fastest: 40, slowest: 47, differing: 2, distinct: 3 });
  assert.equal(raceSummary(result([{ error: "reset", kind: "io" }])).spread, null);
});

test("techniques are named, and a partial single packet is pointed out", () => {
  assert.equal(techniqueLabel("last-byte"), "last-byte sync (HTTP/1.1)");
  assert.equal(techniqueLabel("something-new"), "something-new");
  const ok = { id: 1, status: 200, length: 1, duration_ms: 1 };
  assert.equal(syncNote(result([ok, ok], "single-packet", 2)), null);
  assert.equal(syncNote(result([ok, ok], "last-byte")), null);
  assert.match(syncNote(result([ok, ok, ok], "single-packet", 1)) ?? "", /^1 of 3 final frames/);
});
