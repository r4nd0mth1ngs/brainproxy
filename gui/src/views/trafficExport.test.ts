import { test } from "node:test";
import assert from "node:assert/strict";
import { DEFAULT_FILTER } from "./trafficFilter.ts";
import { balanced, DEFAULT_EXPORT, EXPORT_LIMIT, exportArgs, exportNote, exportProblem, exportQuery, maskValues, quoted } from "./trafficExport.ts";

const NONE = { ...DEFAULT_FILTER, hideRefused: false };

test("quoted escapes quotes and backslashes for the filter language", () => {
  assert.equal(quoted('a"b\\c'), '"a\\"b\\\\c"');
});

test("an empty filter exports everything", () => {
  assert.equal(exportQuery(NONE), "");
  assert.deepEqual(exportArgs(NONE, DEFAULT_EXPORT, "/x/t.har", true), ["history", "export", "har", `--limit=${EXPORT_LIMIT}`, "--output=/x/t.har", "--force"]);
});

test("the default filter hides refused requests, as Traffic does", () => {
  assert.equal(exportQuery(DEFAULT_FILTER), 'NOT error~"^out of scope"');
});

test("URL text matches the URL or title in any case, or the method", () => {
  assert.equal(exportQuery({ ...NONE, text: "Lo.gin" }), '(url~"(?i)lo\\\\.gin" OR title~"(?i)lo\\\\.gin" OR method~"(?i)^lo\\\\.gin$")');
});

test("sources and checkboxes become terms ANDed together", () => {
  const q = exportQuery({ ...DEFAULT_FILTER, sources: ["proxy", "send"], hideErrors: true, hideAssets: true });
  assert.equal(
    q,
    '(source="proxy" OR source="send") AND status<400 AND NOT url~"(?i)\\\\.(css|js|png|jpe?g|gif|svg|ico|woff2?|ttf|map)(\\\\?|$)" AND NOT error~"^out of scope"',
  );
});

test("a contents search goes to --contains; the rest to --filter", () => {
  const args = exportArgs({ ...NONE, text: "token", contents: true, hideErrors: true }, DEFAULT_EXPORT, "/t.har", true);
  assert.deepEqual(args.slice(3, 5), ["--contains=token", "--filter=status<400"]);
});

test("a contents search of only spaces searches nothing, as in Traffic", () => {
  assert.deepEqual(exportArgs({ ...NONE, text: "  ", contents: true }, DEFAULT_EXPORT, "/t.har", true).slice(3, 4), [`--limit=${EXPORT_LIMIT}`]);
});

test("a query goes first, in parentheses, so OR inside it stays inside", () => {
  assert.equal(exportQuery({ ...DEFAULT_FILTER, query: true, text: "status:5xx OR host:a" }), '(status:5xx OR host:a) AND NOT error~"^out of scope"');
});

test("balanced pairs parentheses outside quoted values", () => {
  assert.equal(balanced("(a OR b) AND c"), true);
  assert.equal(balanced('path:")" OR (x)'), true);
  assert.equal(balanced('path:"a\\")"'), true);
  assert.equal(balanced("a) OR (b"), false);
  assert.equal(balanced("(a"), false);
  assert.equal(balanced('"open'), false);
  // A quote inside an unquoted word or value is a character, as the CLI reads it.
  assert.equal(balanced('url:foo"bar'), true);
  assert.equal(balanced('a"b AND (c)'), true);
  assert.equal(balanced('title="x)" AND (y)'), true);
  assert.equal(balanced('url:"a""b"'), true);
  assert.equal(balanced('url:"a" "b'), false);
});

test("exportProblem refuses an unbalanced query, and short masks unless secrets are kept", () => {
  assert.match(exportProblem({ ...NONE, query: true, text: "a) OR (b" }, DEFAULT_EXPORT)!, /pair up/);
  assert.equal(exportProblem({ ...NONE, query: false, text: "a) OR (b" }, DEFAULT_EXPORT), null);
  assert.match(exportProblem(NONE, { keepSecrets: false, mask: "longvalue\nabc" })!, /at least 6 characters: abc/);
  assert.equal(exportProblem(NONE, { keepSecrets: true, mask: "abc" }), null);
  assert.equal(exportProblem(NONE, { keepSecrets: false, mask: " longvalue \n\n" }), null);
});

test("mask values go one per --mask; keeping secrets passes --no-redact", () => {
  assert.deepEqual(maskValues(" abcdef \n\nghijkl"), ["abcdef", "ghijkl"]);
  assert.deepEqual(exportArgs(NONE, { keepSecrets: false, mask: "abcdef\nghijkl" }, "/t.har", false).slice(4), ["--mask=abcdef", "--mask=ghijkl", "--output=/t.har"]);
  assert.deepEqual(exportArgs(NONE, { keepSecrets: true, mask: "abcdef" }, "/t.har", false).slice(4), ["--no-redact", "--output=/t.har"]);
});


test("exportNote says what was cut, masked and left out", () => {
  assert.equal(exportNote({ entries: 1, truncated: false, redacted: 0, binary_bodies_left_out: 0, path: "/t.har" }), "Exported 1 request to /t.har.");
  const n = exportNote({ entries: 5000, truncated: true, redacted: 3, binary_bodies_left_out: 2, path: "/t.har" });
  assert.match(n, /oldest 5,000/);
  assert.match(n, /masked in 3 places/);
  assert.match(n, /2 binary bodies were left out/);
  assert.match(exportNote({ entries: 2, truncated: false, redacted: null, binary_bodies_left_out: 0, path: "/t.har" }), /kept as recorded/);
});
