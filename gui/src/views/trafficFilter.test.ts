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
