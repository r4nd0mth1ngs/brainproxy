import { test } from "node:test";
import assert from "node:assert/strict";
import {
  baselineOf,
  firstOpenable,
  isHttp2Request,
  openable,
  parseRaceCount,
  patchOpen,
  plannedTechnique,
  raceArgs,
  raceMax,
  raceRows,
  raceSummary,
  sentRequestLine,
  shapeLabel,
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

test("responses that differ from the most common one are marked", () => {
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

test("a failed first request isn't what the others are compared with", () => {
  // Failures are no response: with any response, it's the baseline and every failure differs.
  const rows = raceRows(
    result([
      { id: 1, error: "timed out", kind: "timeout" },
      { id: 2, error: "timed out", kind: "timeout" },
      { id: 3, status: 200, length: 5, duration_ms: 9 },
    ]),
  );
  assert.deepEqual(
    rows.map((r) => r.differs),
    [true, true, false],
  );
  assert.equal(firstOpenable(rows), 2);
});

test("the most common response is the baseline, not request #1", () => {
  const r = result([
    { id: 1, status: 409, length: 3, duration_ms: 1 },
    { id: 2, status: 200, length: 12, duration_ms: 1 },
    { id: 3, status: 200, length: 12, duration_ms: 1 },
  ]);
  assert.equal(baselineOf(r.results), 1);
  assert.deepEqual(
    raceRows(r).map((x) => x.differs),
    [true, false, false],
  );
  assert.equal(raceSummary(r).differing, 1);
  assert.equal(shapeLabel(r.results[1]), "200, 12 bytes");
  // A tie goes to the earliest; an empty race has none.
  assert.equal(baselineOf(r.results.slice(0, 2)), 0);
  assert.equal(baselineOf([]), null);
});

test("local failures outnumbering responses don't make every response differ", () => {
  // e.g. "Too many open files" for most of a large race: the few responses are the baseline.
  const fails = Array.from({ length: 8 }, (_, i) => ({ id: 10 + i, error: "Too many open files (os error 24)", kind: "io" }));
  const r = result([...fails, { id: 20, status: 200, length: 2, duration_ms: 5 }, { id: 21, status: 200, length: 2, duration_ms: 6 }]);
  const s = raceSummary(r);
  assert.equal(s.baseline, 8);
  assert.equal(s.differing, 8);
  assert.deepEqual(
    raceRows(r).filter((x) => !x.differs).map((x) => x.id),
    [20, 21],
  );
  assert.equal(shapeLabel(fails[0]), "error: io");
});

test("a recorded failure shows its history id but has no response to open", () => {
  const rows = raceRows(
    result([
      { id: 5, error: "refused", kind: "connect" },
      { id: 6, status: 200, length: 2, duration_ms: 3 },
    ]),
  );
  assert.equal(rows[0].id, 5);
  assert.equal(openable(rows[0]), false);
  assert.equal(openable(rows[1]), true);
  assert.equal(firstOpenable(rows), 1);
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
  assert.deepEqual(s, { responses: 3, errors: 1, spread: 7, fastest: 40, slowest: 47, differing: 2, distinct: 3, baseline: 0 });
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

test("the HTTP/2 check reads only the request line, like the CLI", () => {
  assert.equal(isHttp2Request("get / http/2\n"), true); // the CLI ignores case too
  assert.equal(isHttp2Request("GET / HTTP/2"), true);
  assert.equal(isHttp2Request("GET / HTTP/1.1\nX-Via: HTTP/2\n\nupgrade to HTTP/2"), false);
  assert.equal(isHttp2Request("GET /HTTP/2 HTTP/1.1\n"), false);
  assert.equal(isHttp2Request(""), false);
  assert.equal(parseRaceCount("1000", ""), 1000);
});

test("counts that only look like numbers are refused", () => {
  for (const s of ["1e3", "0x10", "+5", "20ms", "2 0", "１０", "Infinity", "NaN", "99999999999999999999"]) {
    assert.equal(parseRaceCount(s, H1), null, s);
  }
  assert.equal(parseRaceCount("020", H1), 20);
  assert.equal(parseRaceCount("2", H2), 2);
});

test("the target stays one argument, so it can't add flags", () => {
  const args = raceArgs("--project=/tmp/other --no-store", 5);
  assert.deepEqual(args, ["send", "--target=--project=/tmp/other --no-store", "--race=5", "-"]);
  assert.equal(args.at(-1), "-"); // the request comes on stdin
});

test("an empty race has no rows, no spread and nothing to open", () => {
  const r = result([]);
  assert.deepEqual(raceRows(r), []);
  assert.deepEqual(raceSummary(r), { responses: 0, errors: 0, spread: null, fastest: null, slowest: null, differing: 0, distinct: 0, baseline: null });
  assert.equal(firstOpenable(raceRows(r)), null);
  assert.equal(syncNote(result([], "single-packet", 0)), null);
});

test("responses that weren't recorded can't be opened", () => {
  // --no-store, or a race where every request failed: no history ids.
  const rows = raceRows(
    result([
      { id: null, status: 200, length: 2, duration_ms: 3 },
      { error: "refused", kind: "connect" },
    ]),
  );
  assert.equal(firstOpenable(rows), null);
  assert.equal(rows[0].id, null);
});

test("failures are compared by kind, not by message", () => {
  const rows = raceRows(
    result([
      { error: "connection refused (os error 111)", kind: "connect" },
      { error: "connection refused at 10:01", kind: "connect" },
      { error: "timed out", kind: "timeout" },
    ]),
  );
  assert.deepEqual(
    rows.map((r) => r.differs),
    [false, false, true],
  );
});

test("an unparsed response (no status or length) differs from a parsed one", () => {
  const rows = raceRows(
    result([
      { id: 1, status: 200, length: 0, duration_ms: 1 },
      { id: 2, status: null, length: null, duration_ms: 1 },
      { id: 3, status: 200, length: 0, duration_ms: 1 },
    ]),
  );
  assert.deepEqual(
    rows.map((r) => r.differs),
    [false, true, false],
  );
});

test("the summary's distinct count matches the CLI's distinct_responses", () => {
  // Output of `send --race 5` as the CLI prints it.
  const r: RaceResult = {
    race: 5,
    sync: "last-byte",
    synced: null,
    target: "https://shop.test",
    distinct_responses: { "200 12B": 3, "409 3B": 1, "error: io": 1 },
    results: [
      { id: 7, status: 200, length: 12, duration_ms: 0 },
      { id: 8, status: 409, length: 3, duration_ms: 0 },
      { id: 9, status: 200, length: 12, duration_ms: 0 },
      { error: "reset", kind: "io" },
      { id: 10, status: 200, length: 12, duration_ms: 0 },
    ],
  };
  const s = raceSummary(r);
  assert.equal(s.distinct, Object.keys(r.distinct_responses).length);
  assert.equal(s.spread, 0); // all at once is a spread of 0, not "no responses"
  assert.equal(s.differing, 2);
  assert.equal(firstOpenable(raceRows(r)), 0);
});

test("a single-packet race that synced all, or reported nothing, has no note", () => {
  const ok = { id: 1, status: 200, length: 1, duration_ms: 1 };
  assert.equal(techniqueLabel("single-packet"), "single-packet attack (HTTP/2)");
  assert.equal(syncNote(result([ok, ok], "single-packet", null)), null);
  assert.equal(syncNote(result([ok, ok], "single-packet", 3)), null);
  assert.equal(syncNote(result([ok, ok], "single-packet", 0)), "0 of 2 final frames went in the single packet; the rest were sent separately");
});

test("only a version of exactly HTTP/2 after the second space means HTTP/2, as in the CLI", () => {
  // The CLI splits the request line on the first two spaces; anything else races last-byte.
  for (const line of ["GET / HTTP/2 ", "GET /\tHTTP/2", "GET  / HTTP/2", "GET HTTP/2", " GET / HTTP/2", "GET /a b HTTP/2"]) {
    const raw = line + "\nHost: a\n\n";
    assert.equal(isHttp2Request(raw), false, JSON.stringify(line));
    assert.equal(raceMax(raw), 1000, JSON.stringify(line));
  }
  assert.equal(isHttp2Request("GET / HTTP/2\r\nHost: a\r\n\r\n"), true);
  assert.equal(isHttp2Request("GET /a?b=c HTTP/2\n"), true);
});

test("the HTTP/2 check reads the request line as it will be sent", () => {
  // Auto URL-encoding turns the space in the path into %20, which leaves HTTP/2 as the version.
  const raw = "GET /a b HTTP/2\nHost: a\n\n";
  assert.equal(sentRequestLine(raw, false), "GET /a b HTTP/2");
  assert.equal(isHttp2Request(sentRequestLine(raw, false)), false);
  assert.equal(sentRequestLine(raw, true), "GET /a%20b HTTP/2");
  assert.equal(raceMax(sentRequestLine(raw, true)), 100);
  // A trailing space is encoded as part of the path, so there is no version at all.
  assert.equal(isHttp2Request(sentRequestLine("GET / HTTP/2 \r\n\r\n", true)), false);
  assert.equal(sentRequestLine("GET / HTTP/2\r\nHost: a", true), "GET / HTTP/2");
});

test("a raced response only lands if its row is still open", () => {
  const a = result([{ id: 1, status: 200, length: 1, duration_ms: 1 }]);
  const b = result([{ id: 2, status: 200, length: 1, duration_ms: 1 }]);
  type E = { name: string; race?: { result: RaceResult; open: number | null } };
  const list: E[] = [{ name: "send" }, { name: "a", race: { result: a, open: 0 } }, { name: "b", race: { result: b, open: 1 } }];
  // Race A's row 0 is still open: its response fills A's entry, whatever B is doing.
  assert.deepEqual(
    patchOpen(list, a, 0, { name: "a filled" }).map((e) => e.name),
    ["send", "a filled", "b"],
  );
  // The user opened row 1 of race B since: a late response for row 0 is dropped.
  assert.deepEqual(
    patchOpen(list, b, 0, { name: "b filled" }).map((e) => e.name),
    ["send", "a", "b"],
  );
});
