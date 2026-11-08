import { afterEach, test } from "node:test";
import assert from "node:assert/strict";
import type { HistoryItem } from "../api";
import {
  appliedSaved,
  copySaved,
  DEFAULT_FILTER,
  failPage,
  MAX_MATCHES,
  RETRY_BASE,
  RETRY_MAX,
  SEARCH_PAGE,
  isCurrent,
  loadSaved,
  matchesFilter,
  mergePage,
  modeOf,
  needsSearch,
  newSearch,
  parseFilter,
  parseSaved,
  refilter,
  rerun,
  mergeLocal,
  usesEditableFields,
  saveChange,
  clearLocalSaved,
  filtersSaveArgs,
  savedBody,
  savedFrom,
  savedKey,
  savedMatching,
  searchArgs,
  searchFor,
  searchNote,
  shownMatches,
  storeSaved,
  visibleRows,
  withMode,
  withSaved,
  withoutSaved,
  type ContentSearch,
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
/** A contents search filter for `text`. */
const cf = (text: string, patch: Partial<TrafficFilter> = {}) => filter({ contents: true, text, ...patch });

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

/** A new contents search for `text` (and the filter's single source). */
const ns = (text: string, patch: Partial<TrafficFilter> = {}) => newSearch(searchFor(cf(text, patch))!);
/** A search whose earlier pages matched `ids` (rows the default filter shows). */
const found = (text: string, ids: number[], cursor = Math.max(0, ...ids)) => ({ ...ns(text), matches: new Map(ids.map((id) => [id, row(id)])), cursor });
const ids = (s: ContentSearch) => [...s.matches.keys()];

test("a contents search needs text and passes a single source to the CLI", () => {
  assert.equal(searchFor(filter({ text: "token" })), null);
  assert.equal(searchFor(filter({ contents: true })), null);
  assert.deepEqual(searchFor(cf("token", { sources: ["send", "proxy"] })), { kind: "contains", text: "token", source: null });
  assert.deepEqual(searchArgs(ns("token", { sources: ["send", "proxy"] })), ["history", "list", "--contains=token", "--after=0", `--limit=${SEARCH_PAGE}`]);
  const s = { ...ns("-x y", { sources: ["send"] }), cursor: 41 };
  assert.deepEqual(searchArgs(s), ["history", "list", "--contains=-x y", "--source=send", `--after=41`, `--limit=${SEARCH_PAGE}`]);
  assert.deepEqual(searchArgs(ns("a")), ["history", "list", "--contains=a", "--after=0", `--limit=${SEARCH_PAGE}`]);
});

// ---------------- Saved filters in the project ----------------

test("saved filters go to the project as history filters save takes them", () => {
  assert.deepEqual(filtersSaveArgs(3), ["history", "filters", "save", "--if-revision", "3"]);
  const list = [{ name: "errors", filter: filter({ query: true, text: "status:5xx", sources: ["proxy"] }) }];
  const body = JSON.parse(savedBody(list));
  assert.deepEqual(body, { filters: [{ name: "errors", filter: { ...DEFAULT_FILTER, query: true, text: "status:5xx", sources: ["proxy"] } }] });
  // What `history filters list` returns reads back the same (its mode field is ignored).
  assert.deepEqual(savedFrom([{ ...body.filters[0], mode: "query" }]), list);
  assert.deepEqual(savedFrom(null), []);
});

test("a save that meets a newer saved set applies the change to it, once", async () => {
  const conflict = new Error("conflict");
  const isConflict = (e: unknown) => e === conflict;
  const mine = { name: "mine", filter: filter({ text: "a" }) };
  const theirs = { name: "agent", filter: filter({ query: true, text: "status:5xx" }) };
  const calls: string[][] = [];
  // The project is at revision 2, with a filter an agent added after the app read revision 1.
  const cli = async (args: string[], stdin?: string) => {
    calls.push(args);
    if (args[2] === "list") return { rev: 2, filters: JSON.parse(savedBody([mine, theirs])).filters };
    if (args.at(-1) !== "2") throw conflict;
    return { rev: 3, filters: JSON.parse(stdin!).filters };
  };
  const added = { name: "new", filter: filter({ text: "b" }) };
  const out = await saveChange(cli, { rev: 1, list: [mine] }, (l) => withSaved(l, added.name, added.filter), isConflict);
  assert.deepEqual(out, { rev: 3, list: [mine, theirs, added] });
  assert.deepEqual(calls.map((c) => c.join(" ")), ["history filters save --if-revision 1", "history filters list", "history filters save --if-revision 2"]);
  // Another error isn't retried.
  await assert.rejects(saveChange(async () => Promise.reject(new Error("io")), { rev: 1, list: [] }, (l) => l, isConflict), /io/);
});

test("filters kept by an older build are added to the project's without losing either", () => {
  const agent = { name: "errors", filter: filter({ query: true, text: "status:5xx" }) };
  const sameAsSaved = { name: "errors", filter: filter({ query: true, text: "status:5xx" }) };
  const clash = { name: "errors", filter: filter({ text: "boom" }) };
  const fresh = { name: "tokens", filter: filter({ contents: true, text: "Bearer" }) };
  assert.deepEqual(mergeLocal([agent], [sameAsSaved, fresh]), [agent, fresh]);
  assert.deepEqual(
    mergeLocal([agent, { name: "errors (this computer)", filter: filter() }], [clash]).map((s) => s.name),
    ["errors", "errors (this computer)", "errors (this computer 2)"],
  );
});

test("a rerun search keeps showing the earlier matches it hasn't reached yet", () => {
  const f = qf("NOT tag=highlight");
  const all = rows(1, 6);
  let s = mergePage(newSearch(searchFor(f)!), [row(1), row(3), row(5)], 6, f);
  s = rerun(s);
  // Nothing searched yet: the table shows what it showed.
  assert.deepEqual(visibleRows(all, f, s).map((r) => r.id), [1, 3, 5]);
  // Searched up to 3 (row 3 was highlighted meanwhile): below the cursor only the new matches count.
  s = { ...s, matches: new Map([[1, row(1)]]), cursor: 3 };
  assert.deepEqual(visibleRows(all, f, s).map((r) => r.id), [1, 5]);
  // Caught up: the earlier matches are dropped.
  s = mergePage(s, [row(6)], 6, f);
  assert.equal(s.previous, undefined);
  assert.deepEqual(visibleRows(all, f, s).map((r) => r.id), [1, 6]);
});

test("a query on notes or tags is searched again after an edit", () => {
  for (const q of ["tag=highlight", "NOT tag:x", "(note:todo)", "a NOTE~x"]) assert.ok(usesEditableFields(q), q);
  for (const q of ["status:5xx", "path:/tag:x", '"tag:x"', "notes"]) assert.ok(!usesEditableFields(q), q);
});

test("filters kept by an older build are removed once moved", () => {
  const store = new Map<string, string>();
  (globalThis as any).localStorage = { getItem: (k: string) => store.get(k) ?? null, setItem: (k: string, v: string) => store.set(k, v), removeItem: (k: string) => store.delete(k) };
  store.set(savedKey("/p.bpdb"), "[]");
  clearLocalSaved("/p.bpdb");
  assert.equal(store.has(savedKey("/p.bpdb")), false);
});

// ---------------- Query search ----------------

/** A query search filter for `text`. */
const qf = (text: string, patch: Partial<TrafficFilter> = {}) => filter({ query: true, text, ...patch });

test("query mode sends the text as --filter, and is its own search", () => {
  assert.equal(searchFor(qf("  ")), null);
  assert.deepEqual(searchFor(qf("status:5xx", { sources: ["send"] })), { kind: "filter", text: "status:5xx", source: "send" });
  const s = { ...newSearch(searchFor(qf('-x resp.body:"a b"'))!), cursor: 9 };
  assert.deepEqual(searchArgs(s), ["history", "list", '--filter=-x resp.body:"a b"', "--after=9", `--limit=${SEARCH_PAGE}`]);
  // The same text as a contents search is another search.
  assert.ok(isCurrent(s, qf('-x resp.body:"a b"')));
  assert.ok(!isCurrent(s, cf('-x resp.body:"a b"')));
  // The text isn't matched here: the CLI did.
  assert.ok(matchesFilter(row(1), qf("nothing-like-this")));
});

test("the search mode: one of URL, contents and query", () => {
  assert.equal(modeOf(DEFAULT_FILTER), "text");
  assert.deepEqual([withMode(DEFAULT_FILTER, "query").query, withMode(DEFAULT_FILTER, "query").contents], [true, false]);
  assert.deepEqual([withMode(cf("a"), "query").query, withMode(cf("a"), "query").contents], [true, false]);
  assert.equal(modeOf(withMode(qf("a"), "contents")), "contents");
  assert.equal(modeOf(withMode(qf("a"), "text")), "text");
  // Stored filters: older ones have no query field, and both on reads as a query.
  assert.equal(parseFilter({ text: "a", contents: true }).query, false);
  assert.deepEqual([parseFilter({ contents: true, query: true }).contents, parseFilter({ contents: true, query: true }).query], [false, true]);
});

test("a query the CLI refuses is not tried again until it changes", () => {
  const s = newSearch(searchFor(qf("stauts:500"))!);
  const bad = failPage(s, 'filter: unknown field "stauts" at position 1', 1000, true);
  assert.ok(bad.invalid);
  assert.ok(!needsSearch(bad, 50, 1e15));
  assert.equal(searchNote(bad, 50), 'Query: unknown field "stauts" at position 1');
  // Any other failure is retried, and a good page clears it.
  const flaky = failPage(s, "busy", 1000);
  assert.ok(!flaky.invalid && needsSearch(flaky, 50, 1000 + RETRY_BASE));
  assert.ok(!mergePage(bad, [], 50, qf("stauts:500")).invalid);
});

test("a short page covers everything up to the polled id", () => {
  const f = cf("token");
  let s = ns("token");
  assert.ok(needsSearch(s, 50));
  assert.ok(!needsSearch(s, 0));
  s = mergePage(s, [row(3), row(17)], 50, f);
  assert.deepEqual(ids(s), [3, 17]);
  assert.equal(s.cursor, 50);
  assert.ok(!needsSearch(s, 50));
  // New rows arrive: only they are searched next.
  assert.ok(needsSearch(s, 60));
  assert.deepEqual(searchArgs(s).slice(-2), ["--after=50", `--limit=${SEARCH_PAGE}`]);
  // A match newer than the polled rows (recorded during the call) moves the cursor past it.
  s = mergePage(s, [row(55), row(63)], 60, f);
  assert.equal(s.cursor, 63);
  assert.deepEqual(ids(s), [3, 17, 55, 63]);
});

test("a full page continues from its last row", () => {
  const page = rows(1, SEARCH_PAGE).map((r) => row(r.id * 2));
  const s = mergePage(ns("a"), page, 100000, cf("a"));
  assert.equal(s.cursor, SEARCH_PAGE * 2);
  assert.ok(needsSearch(s, 100000));
  assert.ok(!s.capped);
});

test("rows already searched are not counted twice", () => {
  let s = mergePage(ns("a"), [row(5)], 10, cf("a"));
  s = mergePage(s, [row(5), row(11)], 12, cf("a"));
  assert.deepEqual(ids(s), [5, 11]);
});

test("the search stops at MAX_MATCHES and says so", () => {
  const f = cf("a");
  let s = ns("a");
  let id = 0;
  while (s.matches.size < MAX_MATCHES) {
    const page = Array.from({ length: SEARCH_PAGE }, () => row(++id));
    s = mergePage(s, page, 1e9, f);
  }
  assert.equal(s.matches.size, MAX_MATCHES);
  // Exactly MAX_MATCHES so far: one more page tells whether there are more.
  assert.ok(!s.capped && needsSearch(s, 1e9));
  const end = mergePage(s, [], 1e9, f);
  assert.ok(!end.capped && !needsSearch(end, 1e9));
  s = mergePage(s, [row(++id)], 1e9, f);
  assert.ok(s.capped);
  assert.equal(s.matches.size, MAX_MATCHES);
  assert.equal(s.cursor, MAX_MATCHES);
  assert.ok(!needsSearch(s, 1e9));
  assert.match(searchNote(s, 1e9), /first 10,000 matches \(up to #10000\)/);
});

test("contents mode shows matched rows only, and nothing for an older query", () => {
  const all = [...rows(1, 6), row(7, { source: "scan" })];
  const f = cf("token");
  // Rows 6 and 7 were polled after the search covered up to 5: hidden until searched.
  let s = mergePage(ns("token"), [row(2), row(4)], 5, f);
  assert.deepEqual(
    visibleRows(all, f, s).map((r) => r.id),
    [2, 4],
  );
  s = mergePage(s, [row(7, { source: "scan" })], 7, f);
  assert.deepEqual(
    visibleRows(all, f, s).map((r) => r.id),
    [2, 4, 7],
  );
  // Several sources are filtered here, on the same search's matches.
  const narrow = { ...f, sources: ["proxy", "send"] };
  assert.ok(isCurrent(s, narrow));
  assert.deepEqual(
    visibleRows(all, narrow, s).map((r) => r.id),
    [2, 4],
  );
  // The text changed: the old matches aren't shown while the new search runs.
  assert.deepEqual(visibleRows(all, { ...f, text: "tok" }, s), []);
  assert.ok(!isCurrent(s, { ...f, text: "tok" }));
  // A single source goes to the CLI, so it is a new search.
  assert.ok(!isCurrent(s, { ...f, sources: ["scan"] }));
  // Off: the plain filter.
  assert.equal(visibleRows(all, filter({ text: "p3" }), s).length, 1);
  assert.equal(visibleRows(all, filter({ contents: true }), null).length, 7);
});

test("the search note says when it is still running or failed", () => {
  assert.equal(searchNote(null, 0), "Searching…");
  const s = ns("a");
  assert.equal(searchNote(s, 10), "Searching…");
  assert.equal(searchNote(mergePage(s, [], 10, cf("a")), 10), "");
  assert.equal(searchNote(failPage(s, "boom"), 10), "Search failed (trying again): boom");
});

// ---------------- Edge cases ----------------

test("the contents search keeps the text as typed, case and spaces included", () => {
  assert.equal(searchFor(cf(" Token "))!.text, " Token ");
  assert.equal(searchArgs(ns(" Token "))[2], "--contains= Token ");
  // Outside contents mode the same text is matched case-insensitively here.
  assert.ok(matchesFilter(row(1, { url: "https://a.test/TOKEN" }), filter({ text: "token" })));
});

test("search text stays one argument whatever it holds", () => {
  for (const q of ["--format=text", "a b", 'x" ; rm -rf /', "line\nbreak", "k=v=w", "«auth:p:password:form»", "$(id)"]) {
    const args = searchArgs(ns(q));
    assert.equal(args.length, 5, q);
    assert.equal(args[2], `--contains=${q}`);
    assert.ok(!args.includes(q), q);
  }
  assert.equal(searchArgs(ns("a", { sources: ["proxy"] }))[3], "--source=proxy");
});

test("a cap reached in the middle of a page stops at the last match kept", () => {
  let s = found("a", Array.from({ length: MAX_MATCHES - 1 }, (_, i) => i + 1));
  s = mergePage(s, [row(20001), row(20005), row(20009)], 30000, cf("a"));
  assert.ok(s.capped);
  assert.equal(s.matches.size, MAX_MATCHES);
  assert.ok(s.matches.has(20001) && !s.matches.has(20005));
  assert.equal(s.cursor, 20001);
  // Capped: later polls don't search on.
  assert.ok(!needsSearch(s, 40000));
  assert.match(searchNote(s, 40000), /up to #20001/);
  const all = [row(20001), row(20005), row(20009)];
  assert.deepEqual(
    visibleRows(all, cf("a"), s).map((r) => r.id),
    [20001],
  );
});

test("a full page followed by a short one covers everything up to the polled id", () => {
  let s = mergePage(ns("a"), rows(1, SEARCH_PAGE), 5000, cf("a"));
  assert.equal(s.cursor, SEARCH_PAGE);
  assert.ok(needsSearch(s, 5000));
  assert.equal(searchArgs(s)[3], `--after=${SEARCH_PAGE}`);
  s = mergePage(s, [row(4000)], 5000, cf("a"));
  assert.equal(s.cursor, 5000);
  assert.equal(s.matches.size, SEARCH_PAGE + 1);
  assert.ok(!needsSearch(s, 5000));
  assert.equal(searchNote(s, 5000), "");
});

test("a full page past the polled rows waits for the poll to catch up", () => {
  // Rows were recorded during the call: the page ends after the newest polled id.
  const s = mergePage(ns("a"), rows(1, SEARCH_PAGE), 10, cf("a"));
  assert.equal(s.cursor, SEARCH_PAGE);
  assert.ok(!needsSearch(s, 10));
  assert.ok(needsSearch(s, SEARCH_PAGE + 1));
});

test("a failed search keeps its matches and says why", () => {
  const s = failPage(mergePage(ns("a"), [row(2)], 5, cf("a")), "database is locked");
  assert.equal(searchNote(s, 100), "Search failed (trying again): database is locked");
  // The error wins over the cap note.
  assert.match(searchNote({ ...s, capped: true }, 100), /^Search failed/);
  assert.deepEqual(
    visibleRows(rows(1, 6), cf("a"), s).map((r) => r.id),
    [2],
  );
});

test("matches the poll hasn't fetched yet show once their rows arrive", () => {
  const f = cf("a");
  const s = mergePage(ns("a"), [row(3), row(8)], 5, f);
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
  const f = cf("a");
  const all = [row(1), row(2, { status: null, error: "out of scope: b.test" })];
  const s = mergePage(ns("a"), all, 2, f);
  assert.deepEqual(
    visibleRows(all, f, s).map((r) => r.id),
    [1],
  );
  // The hidden match is kept: showing out-of-scope rows needs no new search.
  assert.equal(visibleRows(all, { ...f, hideRefused: false }, s).length, 2);
});

test("a search is only current for the text and single source that asked for it", () => {
  const s = ns("a", { sources: ["send"] });
  assert.ok(isCurrent(s, cf("a", { sources: ["send"] })));
  // The checkboxes are applied in the app, so changing one is the same search.
  assert.ok(isCurrent(s, cf("a", { sources: ["send"], hideErrors: true })));
  assert.ok(isCurrent(s, cf("a", { sources: ["send"], hideAssets: true })));
  assert.ok(isCurrent(s, cf("a", { sources: ["send"], hideRefused: false })));
  // So are several sources, in any order: none goes to the CLI.
  const all = ns("a");
  assert.ok(isCurrent(all, cf("a", { sources: ["proxy", "send"] })));
  assert.ok(isCurrent(all, cf("a", { sources: ["send", "proxy", "scan"] })));
  assert.ok(!isCurrent(s, filter({ text: "a", sources: ["send"] })));
  assert.ok(!isCurrent(s, cf("A", { sources: ["send"] })));
  assert.ok(!isCurrent(s, cf("a", { sources: ["send", "proxy"] })));
  assert.ok(!isCurrent(s, cf("a", { sources: ["proxy"] })));
  assert.ok(!isCurrent(null, cf("a")));
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

// ---------------- Review fixes ----------------

test("a failed search tries again after a backoff and carries on", () => {
  let s = failPage(mergePage(ns("a"), [row(2)], 5, cf("a")), "database is locked", 1000);
  // Not on the very next poll: after RETRY_BASE, doubling per failure up to RETRY_MAX.
  assert.ok(!needsSearch(s, 9, 1000 + RETRY_BASE - 1));
  assert.ok(needsSearch(s, 9, 1000 + RETRY_BASE));
  assert.deepEqual(searchArgs(s).slice(-2), ["--after=5", `--limit=${SEARCH_PAGE}`]);
  const again = failPage(s, "database is locked", 5000);
  assert.equal(again.failures, 2);
  assert.equal(again.retryAt, 5000 + RETRY_BASE * 2);
  let many = s;
  for (let i = 0; i < 20; i++) many = failPage(many, "locked", 0);
  assert.equal(many.retryAt, RETRY_MAX);
  // A good page clears the error and the backoff.
  s = mergePage(s, [row(7)], 9, cf("a"));
  assert.equal(s.error, null);
  assert.equal(s.failures, 0);
  assert.ok(needsSearch(s, 10, 0));
  assert.equal(s.cursor, 9);
  assert.deepEqual(ids(s), [2, 7]);
  assert.equal(searchNote(s, 9), "");
  assert.deepEqual(
    visibleRows(rows(1, 9), cf("a"), s).map((r) => r.id),
    [2, 7],
  );
});

test("hidden rows don't count toward the cap", () => {
  // Hide out-of-scope is on by default: a page full of refused matches counts for nothing.
  const refused = Array.from({ length: SEARCH_PAGE }, (_, i) => row(i + 1, { status: null, error: "out of scope: b.test" }));
  let s = { ...found("a", []), matches: new Map(Array.from({ length: MAX_MATCHES - 1 }, (_, i) => [-i - 1, row(-i - 1)])) };
  s = mergePage(s, refused, 1e9, cf("a"));
  assert.ok(!s.capped);
  assert.equal(shownMatches(s, cf("a")), MAX_MATCHES - 1);
  // Every row of the page moves the cursor, counted or not, and is kept for later.
  assert.equal(s.cursor, SEARCH_PAGE);
  assert.equal(s.matches.size, MAX_MATCHES - 1 + SEARCH_PAGE);
  // Assets and errors too, when those boxes are ticked.
  const f = cf("a", { hideAssets: true, hideErrors: true });
  let t = mergePage(ns("a"), [row(1, { url: "https://a.test/app.js" }), row(2, { status: 500 }), row(3)], 3, f);
  assert.equal(shownMatches(t, f), 1);
  assert.equal(t.cursor, 3);
  // The cap is reached only by rows the table shows.
  t = { ...found("a", []), matches: new Map(Array.from({ length: MAX_MATCHES }, (_, i) => [-i - 1, row(-i - 1)])) };
  t = mergePage(t, [row(1, { status: null, error: "out of scope: b.test" }), row(2)], 9, cf("a"));
  assert.ok(t.capped);
  assert.equal(t.cursor, 1);
  assert.ok(!t.matches.has(2));
});

test("whitespace-only text doesn't search, other text is kept as typed", () => {
  for (const t of [" ", "   ", "\t", "\n "]) assert.equal(searchFor(cf(t)), null, JSON.stringify(t));
  // Contents mode with no search shows rows by the other filters, as with no text.
  const all = [row(1), row(2, { status: 500 })];
  assert.equal(visibleRows(all, cf("  "), null).length, 2);
  assert.equal(visibleRows(all, cf("  ", { hideErrors: true }), null).length, 1);
  assert.equal(searchFor(cf(" a "))!.text, " a ");
});

test("changing a checkbox keeps the matches and only works out the cap again", () => {
  const all = [row(1), row(2, { url: "https://a.test/app.js" }), row(3, { status: 500 })];
  const s = mergePage(ns("a"), all, 3, cf("a"));
  // Nothing to change: the same search, no new CLI call.
  assert.equal(refilter(s, cf("a", { hideAssets: true })), s);
  assert.deepEqual(
    visibleRows(all, cf("a", { hideAssets: true, hideErrors: true }), s).map((r) => r.id),
    [1],
  );
  assert.equal(visibleRows(all, cf("a"), s).length, 3);
});

test("a capped search carries on when a checkbox hides enough of its matches", () => {
  const f = cf("a");
  // MAX_MATCHES shown matches, half of them static assets, then one more stops it.
  const page = Array.from({ length: MAX_MATCHES + 1 }, (_, i) => row(i + 1, i % 2 ? { url: `https://a.test/s${i}.css` } : {}));
  let s = mergePage(ns("a"), page, 1e9, f);
  assert.ok(s.capped);
  assert.equal(s.cursor, MAX_MATCHES);
  const fewer = cf("a", { hideAssets: true });
  const next = refilter(s, fewer);
  assert.ok(!next.capped);
  assert.equal(next.cursor, MAX_MATCHES);
  assert.ok(needsSearch(next, 1e9));
  assert.deepEqual(searchArgs(next).slice(-2), [`--after=${MAX_MATCHES}`, `--limit=${SEARCH_PAGE}`]);
  // Same count after all: the next shown match stops it again, where it was.
  s = mergePage(refilter(s, f), [row(MAX_MATCHES + 1)], 1e9, f);
  assert.ok(s.capped);
  assert.equal(s.cursor, MAX_MATCHES);
});

test("unhiding rows past the cap stops the search before the first one over", () => {
  // MAX_MATCHES shown rows with refused (hidden) matches among them.
  const page = [row(1, { status: null, error: "out of scope: b.test" }), ...Array.from({ length: MAX_MATCHES }, (_, i) => row(i + 2)), row(MAX_MATCHES + 5, { status: null, error: "out of scope: b.test" })];
  const s = mergePage(ns("a"), page, MAX_MATCHES + 5, cf("a"));
  assert.ok(!s.capped);
  assert.equal(s.cursor, MAX_MATCHES + 5);
  const all = refilter(s, cf("a", { hideRefused: false }));
  assert.ok(all.capped);
  // Row 1 and the first MAX_MATCHES - 1 others are shown; the last one kept is MAX_MATCHES.
  assert.equal(shownMatches(all, cf("a", { hideRefused: false })), MAX_MATCHES);
  assert.equal(all.cursor, MAX_MATCHES);
  assert.ok(!all.matches.has(MAX_MATCHES + 1));
  assert.match(searchNote(all, 1e9), /up to #10000/);
  // Hiding them again: it carries on from there.
  const back = refilter(all, cf("a"));
  assert.ok(!back.capped && needsSearch(back, MAX_MATCHES + 5));
  assert.equal(back.cursor, MAX_MATCHES);
});

test("copying saved filters says when the destination can't be written", () => {
  const items = stubStorage({
    setItem: () => {
      throw new Error("QuotaExceededError");
    },
  });
  items.set(savedKey("/tmp/t/project.bpdb"), JSON.stringify(withSaved([], "api", cf("token"))));
  assert.equal(copySaved("/tmp/t/project.bpdb", "/w/dest.bpdb"), false);
});

test("the picked one of two equal saved filters is the one shown and deleted", () => {
  let list = withSaved([], "first", filter({ hideErrors: true }));
  list = withSaved(list, "second", filter({ hideErrors: true }));
  const f = filter({ hideErrors: true });
  assert.equal(appliedSaved(list, f, null), "first");
  assert.equal(appliedSaved(list, f, "second"), "second");
  // Changed since: the pick no longer applies.
  assert.equal(appliedSaved(list, filter(), "second"), null);
  assert.equal(appliedSaved(list, filter({ hideErrors: true, text: "x" }), "second"), null);
  // A picked name that was deleted falls back to an equal one.
  assert.equal(appliedSaved(withoutSaved(list, "second"), f, "second"), "first");
  assert.deepEqual(
    withoutSaved(list, appliedSaved(list, f, "second")!).map((s) => s.name),
    ["first"],
  );
});

test("saving a temporary engagement copies its saved filters to the file", () => {
  stubStorage();
  const tmp = "/tmp/brainproxy-temp-1/project.bpdb";
  storeSaved(tmp, withSaved(withSaved([], "api", cf("token")), "same", filter({ hideAssets: true })));
  storeSaved("/w/dest.bpdb", withSaved(withSaved([], "same", filter()), "old", filter({ hideErrors: true })));
  assert.ok(copySaved(tmp, "/w/dest.bpdb"));
  assert.deepEqual(
    loadSaved("/w/dest.bpdb").map((s) => [s.name, s.filter.hideAssets]),
    [
      ["same", true],
      ["old", false],
      ["api", false],
    ],
  );
  // Nothing saved: nothing written.
  assert.ok(copySaved("/w/none.bpdb", "/w/other.bpdb"));
  assert.deepEqual(loadSaved("/w/other.bpdb"), []);
});
