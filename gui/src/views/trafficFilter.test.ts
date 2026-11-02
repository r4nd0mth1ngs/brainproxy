import { afterEach, test } from "node:test";
import assert from "node:assert/strict";
import type { HistoryItem } from "../api";
import {
  DEFAULT_FILTER,
  MAX_MATCHES,
  SEARCH_PAGE,
  isCurrent,
  loadSaved,
  matchesFilter,
  mergePage,
  needsSearch,
  newSearch,
  parseFilter,
  parseSaved,
  savedKey,
  savedMatching,
  searchArgs,
  searchFor,
  searchNote,
  storeSaved,
  visibleRows,
  withSaved,
  withoutSaved,
  type TrafficFilter,
} from "./trafficFilter.ts";

const row = (id: number, patch: Partial<HistoryItem> = {}): HistoryItem => ({
  id,
  time: "",
  source: "proxy",
  method: "GET",
  url: `https://a.test/p${id}`,
  status: 200,
  resp_content_type: null,
  resp_body_length: null,
  title: null,
  duration_ms: null,
  error: null,
  note: null,
  tags: [],
  ...patch,
});

const rows = (from: number, to: number) => Array.from({ length: to - from + 1 }, (_, i) => row(from + i));
const filter = (patch: Partial<TrafficFilter> = {}): TrafficFilter => ({ ...DEFAULT_FILTER, ...patch });

// ---------------- Client-side filters ----------------

test("the text filters URL, title and method only outside contents mode", () => {
  const r = row(1, { url: "https://a.test/login", title: "Sign in" });
  assert.ok(matchesFilter(r, filter({ text: "LOGIN" })));
  assert.ok(matchesFilter(r, filter({ text: "sign" })));
  assert.ok(matchesFilter(r, filter({ text: "get" })));
  assert.ok(!matchesFilter(r, filter({ text: "password" })));
  // In contents mode the CLI matches the text; the other filters still apply here.
  assert.ok(matchesFilter(r, filter({ text: "password", contents: true })));
  assert.ok(!matchesFilter(r, filter({ text: "password", contents: true, sources: ["send"] })));
});

test("sources, errors, assets and out-of-scope rows are filtered", () => {
  assert.ok(!matchesFilter(row(1, { source: "scan" }), filter({ sources: ["proxy", "send"] })));
  assert.ok(matchesFilter(row(1, { source: "send" }), filter({ sources: ["proxy", "send"] })));
  assert.ok(!matchesFilter(row(1, { status: 404 }), filter({ hideErrors: true })));
  assert.ok(!matchesFilter(row(1, { status: null, error: "boom" }), filter({ hideErrors: true })));
  assert.ok(!matchesFilter(row(1, { url: "https://a.test/app.js?v=2" }), filter({ hideAssets: true })));
  const refused = row(1, { status: null, error: "out of scope: b.test" });
  assert.ok(!matchesFilter(refused, DEFAULT_FILTER));
  assert.ok(matchesFilter(refused, filter({ hideRefused: false })));
});

// ---------------- Saved filters ----------------

test("stored filters are read defensively", () => {
  assert.deepEqual(parseSaved(null), []);
  assert.deepEqual(parseSaved("not json"), []);
  assert.deepEqual(parseSaved('{"name":"x"}'), []);
  const list = parseSaved(
    JSON.stringify([
      { name: " api ", filter: { text: "token", contents: true, sources: ["send", 3, "send"], extra: 1 } },
      { name: "", filter: {} },
      { name: "api", filter: { text: "dup" } },
      { filter: {} },
      null,
      { name: "bare" },
    ]),
  );
  assert.deepEqual(list, [
    { name: "api", filter: { ...DEFAULT_FILTER, text: "token", contents: true, sources: ["send"] } },
    { name: "bare", filter: DEFAULT_FILTER },
  ]);
  assert.deepEqual(parseFilter({ hideRefused: "no" }), DEFAULT_FILTER);
});

test("saving replaces a filter of the same name in place and deleting removes it", () => {
  let list = withSaved([], "errors", filter({ hideErrors: true }));
  list = withSaved(list, "api", filter({ sources: ["send"] }));
  list = withSaved(list, " errors ", filter({ text: "admin" }));
  assert.deepEqual(
    list.map((s) => s.name),
    ["errors", "api"],
  );
  assert.equal(list[0].filter.text, "admin");
  assert.equal(withSaved(list, "  ", filter()), list);
  assert.deepEqual(
    withoutSaved(list, "errors").map((s) => s.name),
    ["api"],
  );
});

test("the applied saved filter is found whatever the order of its sources", () => {
  const list = withSaved([], "two", filter({ sources: ["send", "proxy"] }));
  assert.equal(savedMatching(list, filter({ sources: ["proxy", "send"] })), "two");
  assert.equal(savedMatching(list, filter({ sources: ["proxy"] })), null);
});

const realStorage = Object.getOwnPropertyDescriptor(globalThis, "localStorage");
afterEach(() => {
  delete (globalThis as any).localStorage;
  if (realStorage) Object.defineProperty(globalThis, "localStorage", realStorage);
});

function stubStorage(overrides: object = {}) {
  const items = new Map<string, string>();
  const stub = { getItem: (k: string) => items.get(k) ?? null, setItem: (k: string, v: string) => void items.set(k, v), ...overrides };
  Object.defineProperty(globalThis, "localStorage", { value: stub, configurable: true, writable: true });
  return items;
}

test("saved filters are kept per project", () => {
  const items = stubStorage();
  const list = withSaved([], "mine", filter({ text: "x" }));
  assert.ok(storeSaved("/w/a.bpdb", list));
  assert.ok(items.has(savedKey("/w/a.bpdb")));
  assert.deepEqual(loadSaved("/w/a.bpdb"), list);
  assert.deepEqual(loadSaved("/w/b.bpdb"), []);
});

test("unavailable storage loads nothing and reports a failed save", () => {
  const boom = () => {
    throw new Error("denied");
  };
  stubStorage({ getItem: boom, setItem: boom });
  assert.deepEqual(loadSaved("/w/a.bpdb"), []);
  assert.equal(storeSaved("/w/a.bpdb", []), false);
});

// ---------------- Contents search ----------------

test("a contents search needs text and passes a single source to the CLI", () => {
  assert.equal(searchFor(filter({ text: "token" })), null);
  assert.equal(searchFor(filter({ contents: true })), null);
  assert.deepEqual(searchFor(filter({ contents: true, text: "token", sources: ["send", "proxy"] })), { query: "token", source: null });
  const want = searchFor(filter({ contents: true, text: "-x y", sources: ["send"] }))!;
  assert.deepEqual(want, { query: "-x y", source: "send" });
  const s = { ...newSearch(want.query, want.source), cursor: 41 };
  assert.deepEqual(searchArgs(s), ["history", "list", "--contains=-x y", "--source=send", `--after=41`, `--limit=${SEARCH_PAGE}`]);
  assert.deepEqual(searchArgs(newSearch("a", null)), ["history", "list", "--contains=a", "--after=0", `--limit=${SEARCH_PAGE}`]);
});

test("a short page covers everything up to the polled id", () => {
  let s = newSearch("token", null);
  assert.ok(needsSearch(s, 50));
  assert.ok(!needsSearch(s, 0));
  s = mergePage(s, [row(3), row(17)], 50);
  assert.deepEqual([...s.matches], [3, 17]);
  assert.equal(s.cursor, 50);
  assert.ok(!needsSearch(s, 50));
  // New rows arrive: only they are searched next.
  assert.ok(needsSearch(s, 60));
  assert.deepEqual(searchArgs(s).slice(-2), ["--after=50", `--limit=${SEARCH_PAGE}`]);
  // A match newer than the polled rows (recorded during the call) moves the cursor past it.
  s = mergePage(s, [row(55), row(63)], 60);
  assert.equal(s.cursor, 63);
  assert.deepEqual([...s.matches], [3, 17, 55, 63]);
});

test("a full page continues from its last row", () => {
  const page = rows(1, SEARCH_PAGE).map((r) => row(r.id * 2));
  const s = mergePage(newSearch("a", null), page, 100000);
  assert.equal(s.cursor, SEARCH_PAGE * 2);
  assert.ok(needsSearch(s, 100000));
  assert.ok(!s.capped);
});

test("rows already searched are not counted twice", () => {
  let s = mergePage(newSearch("a", null), [row(5)], 10);
  s = mergePage(s, [row(5), row(11)], 12);
  assert.deepEqual([...s.matches], [5, 11]);
});

test("the search stops at MAX_MATCHES and says so", () => {
  let s = newSearch("a", null);
  let id = 0;
  while (s.matches.size < MAX_MATCHES) {
    const page = Array.from({ length: SEARCH_PAGE }, () => row(++id));
    s = mergePage(s, page, 1e9);
  }
  assert.equal(s.matches.size, MAX_MATCHES);
  // Exactly MAX_MATCHES so far: one more page tells whether there are more.
  assert.ok(!s.capped && needsSearch(s, 1e9));
  const end = mergePage(s, [], 1e9);
  assert.ok(!end.capped && !needsSearch(end, 1e9));
  s = mergePage(s, [row(++id)], 1e9);
  assert.ok(s.capped);
  assert.equal(s.matches.size, MAX_MATCHES);
  assert.equal(s.cursor, MAX_MATCHES);
  assert.ok(!needsSearch(s, 1e9));
  assert.match(searchNote(s, 1e9), /first 10,000 matches \(up to #10000\)/);
});

test("contents mode shows matched rows only, and nothing for an older query", () => {
  const all = [...rows(1, 6), row(7, { source: "scan" })];
  const f = filter({ contents: true, text: "token" });
  // Rows 6 and 7 were polled after the search covered up to 5: hidden until searched.
  let s = mergePage(newSearch("token", null), [row(2), row(4)], 5);
  assert.deepEqual(
    visibleRows(all, f, s).map((r) => r.id),
    [2, 4],
  );
  s = mergePage(s, [row(7)], 7);
  assert.deepEqual(
    visibleRows(all, f, s).map((r) => r.id),
    [2, 4, 7],
  );
  // Other filters still apply.
  assert.deepEqual(
    visibleRows(all, { ...f, sources: ["proxy", "send"] }, s).map((r) => r.id),
    [2, 4],
  );
  // The text changed: the old matches aren't shown while the new search runs.
  assert.deepEqual(visibleRows(all, { ...f, text: "tok" }, s), []);
  assert.ok(!isCurrent(s, { ...f, text: "tok" }));
  assert.ok(!isCurrent(s, { ...f, sources: ["scan"] }));
  // Off: the plain filter.
  assert.equal(visibleRows(all, filter({ text: "p3" }), s).length, 1);
  assert.equal(visibleRows(all, filter({ contents: true }), null).length, 7);
});

test("the search note says when it is still running or failed", () => {
  assert.equal(searchNote(null, 0), "Searching…");
  const s = newSearch("a", null);
  assert.equal(searchNote(s, 10), "Searching…");
  assert.equal(searchNote(mergePage(s, [], 10), 10), "");
  assert.equal(searchNote({ ...s, error: "boom" }, 10), "Search failed: boom");
});

// ---------------- Edge cases ----------------

test("the contents search keeps the text as typed, case and spaces included", () => {
  assert.deepEqual(searchFor(filter({ contents: true, text: " Token " })), { query: " Token ", source: null });
  // Outside contents mode the same text is matched case-insensitively here.
  assert.ok(matchesFilter(row(1, { url: "https://a.test/TOKEN" }), filter({ text: "token" })));
});

test("search text stays one argument whatever it holds", () => {
  for (const q of ["--format=text", "a b", 'x" ; rm -rf /', "line\nbreak", "k=v=w", "«auth:p:password:form»", "$(id)"]) {
    const args = searchArgs(newSearch(q, null));
    assert.equal(args.length, 5, q);
    assert.equal(args[2], `--contains=${q}`);
    assert.ok(!args.includes(q), q);
  }
  assert.equal(searchArgs(newSearch("a", "proxy"))[3], "--source=proxy");
});

test("a cap reached in the middle of a page stops at the last match kept", () => {
  const ids = Array.from({ length: MAX_MATCHES - 1 }, (_, i) => i + 1);
  let s = { ...newSearch("a", null), matches: new Set(ids), cursor: MAX_MATCHES - 1 };
  s = mergePage(s, [row(20001), row(20005), row(20009)], 30000);
  assert.ok(s.capped);
  assert.equal(s.matches.size, MAX_MATCHES);
  assert.ok(s.matches.has(20001) && !s.matches.has(20005));
  assert.equal(s.cursor, 20001);
  // Capped: later polls don't search on.
  assert.ok(!needsSearch(s, 40000));
  assert.match(searchNote(s, 40000), /up to #20001/);
  const all = [row(20001), row(20005), row(20009)];
  assert.deepEqual(
    visibleRows(all, filter({ contents: true, text: "a" }), s).map((r) => r.id),
    [20001],
  );
});

test("a full page followed by a short one covers everything up to the polled id", () => {
  let s = mergePage(newSearch("a", null), rows(1, SEARCH_PAGE), 5000);
  assert.equal(s.cursor, SEARCH_PAGE);
  assert.ok(needsSearch(s, 5000));
  assert.equal(searchArgs(s)[3], `--after=${SEARCH_PAGE}`);
  s = mergePage(s, [row(4000)], 5000);
  assert.equal(s.cursor, 5000);
  assert.equal(s.matches.size, SEARCH_PAGE + 1);
  assert.ok(!needsSearch(s, 5000));
  assert.equal(searchNote(s, 5000), "");
});

test("a full page past the polled rows waits for the poll to catch up", () => {
  // Rows were recorded during the call: the page ends after the newest polled id.
  const s = mergePage(newSearch("a", null), rows(1, SEARCH_PAGE), 10);
  assert.equal(s.cursor, SEARCH_PAGE);
  assert.ok(!needsSearch(s, 10));
  assert.ok(needsSearch(s, SEARCH_PAGE + 1));
});

test("a failed search keeps its matches, stops, and says why", () => {
  const s = { ...mergePage(newSearch("a", null), [row(2)], 5), error: "database is locked" };
  assert.ok(!needsSearch(s, 100));
  assert.equal(searchNote(s, 100), "Search failed: database is locked");
  // The error wins over the cap note.
  assert.match(searchNote({ ...s, capped: true }, 100), /^Search failed/);
  assert.deepEqual(
    visibleRows(rows(1, 6), filter({ contents: true, text: "a" }), s).map((r) => r.id),
    [2],
  );
});

test("matches the poll hasn't fetched yet show once their rows arrive", () => {
  const f = filter({ contents: true, text: "a" });
  const s = mergePage(newSearch("a", null), [row(3), row(8)], 5);
  assert.equal(s.cursor, 8);
  assert.deepEqual(
    visibleRows(rows(1, 5), f, s).map((r) => r.id),
    [3],
  );
  assert.deepEqual(
    visibleRows(rows(1, 8), f, s).map((r) => r.id),
    [3, 8],
  );
});

test("contents mode still hides out-of-scope matches by default", () => {
  const f = filter({ contents: true, text: "a" });
  const all = [row(1), row(2, { status: null, error: "out of scope: b.test" })];
  const s = mergePage(newSearch("a", null), all, 2);
  assert.deepEqual(
    visibleRows(all, f, s).map((r) => r.id),
    [1],
  );
  assert.equal(visibleRows(all, { ...f, hideRefused: false }, s).length, 2);
});

test("a search is only current for the filter that asked for it", () => {
  const s = newSearch("a", "send");
  assert.ok(isCurrent(s, filter({ contents: true, text: "a", sources: ["send"] })));
  assert.ok(!isCurrent(s, filter({ text: "a", sources: ["send"] })));
  assert.ok(!isCurrent(s, filter({ contents: true, text: "A", sources: ["send"] })));
  assert.ok(!isCurrent(s, filter({ contents: true, text: "a", sources: ["send", "proxy"] })));
  assert.ok(!isCurrent(null, filter({ contents: true, text: "a" })));
});

test("a saved filter is a copy of the filter it was saved from", () => {
  const f = filter({ sources: ["send"] });
  const list = withSaved([], "mine", f);
  f.sources.push("proxy");
  assert.deepEqual(list[0].filter.sources, ["send"]);
  assert.equal(savedMatching(list, filter({ sources: ["send"] })), "mine");
  assert.equal(savedMatching([], DEFAULT_FILTER), null);
  // Deleting a name that isn't saved changes nothing.
  assert.deepEqual(withoutSaved(list, "other"), list);
});

test("stored filters can't set fields through __proto__", () => {
  const f = parseFilter(JSON.parse('{"__proto__":{"hideErrors":true,"text":"x"},"constructor":{"prototype":{"y":1}}}'));
  assert.deepEqual(f, DEFAULT_FILTER);
  const list = parseSaved('[{"name":"__proto__","filter":{"__proto__":{"contents":true}}}]');
  assert.deepEqual(list, [{ name: "__proto__", filter: DEFAULT_FILTER }]);
  assert.equal(({} as any).contents, undefined);
});

test("saved filters survive a round trip through storage, odd names included", () => {
  const items = stubStorage();
  let list = withSaved([], "tokens «auth» / ünïcode", filter({ contents: true, text: 'a"b\\c\n', sources: ["proxy", "send"] }));
  list = withSaved(list, "<script>", filter({ hideAssets: true }));
  assert.ok(storeSaved("C:\\proj\\a.bpdb", list));
  assert.deepEqual(loadSaved("C:\\proj\\a.bpdb"), list);
  assert.notEqual(savedKey("/w/a.bpdb"), savedKey("/w/a.bpdb2"));
  // Garbage written by something else loads as nothing.
  items.set(savedKey("/w/x.bpdb"), "{broken");
  assert.deepEqual(loadSaved("/w/x.bpdb"), []);
});

test("no storage at all loads nothing and reports a failed save", () => {
  delete (globalThis as any).localStorage;
  Object.defineProperty(globalThis, "localStorage", {
    get() {
      throw new Error("SecurityError");
    },
    configurable: true,
  });
  assert.deepEqual(loadSaved("/w/a.bpdb"), []);
  assert.equal(storeSaved("/w/a.bpdb", withSaved([], "x", DEFAULT_FILTER)), false);
});
