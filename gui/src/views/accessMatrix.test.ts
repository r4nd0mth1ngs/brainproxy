import { test } from "node:test";
import assert from "node:assert/strict";
import { afterStart, cellKind, grid, hostOf, liveArgs, notTested, parseSkipPaths, proxyOptions, runArgs, runLabel, skipSetArgs, withLive, type Matrix, type RunForm } from "./accessMatrix.ts";

const cell = (verdict: string, status: number | null, history_id: number, confidence: string | null = null) => ({ verdict, confidence, status, history_id });

const matrix: Matrix = {
  run_id: 7,
  identities: ["bob", "anonymous", "carol"],
  truncated: false,
  requests: [
    {
      source_id: 1,
      method: "GET",
      url: "http://shop.test/api/me",
      owner: "alice",
      baseline_history_id: 10,
      baseline_status: 200,
      cells: { anonymous: cell("enforced", 401, 11), bob: cell("different", 200, 12), carol: cell("different", 200, 13) },
    },
    {
      source_id: 2,
      method: "GET",
      url: "http://shop.test/api/orders/1",
      owner: "alice",
      baseline_history_id: 20,
      baseline_status: 200,
      cells: { anonymous: cell("enforced", 401, 21), bob: cell("bypass", 200, 22, "high"), carol: cell("error", null, 23) },
    },
    { source_id: 3, method: "GET", url: "http://shop.test/api/orders/9", owner: "alice", baseline_history_id: 30, baseline_status: 404, cells: {}, skipped: "skipped: baseline status 404; nothing to compare against" },
    {
      source_id: 4,
      method: "GET",
      url: "http://shop.test/dashboard",
      owner: "bob",
      baseline_history_id: 40,
      baseline_status: 200,
      // bob is the owner here, so he has no cell.
      cells: { anonymous: cell("public", 200, 41), carol: cell("bypass", 200, 42, "low") },
    },
  ],
};

test("cells get a kind from their verdict and confidence", () => {
  assert.equal(cellKind(cell("bypass", 200, 1, "high")), "bypass-high");
  assert.equal(cellKind(cell("bypass", 200, 1, "medium")), "bypass-medium");
  assert.equal(cellKind(cell("bypass", 200, 1, null)), "bypass-low");
  assert.equal(cellKind(cell("enforced", 403, 1)), "enforced");
  assert.equal(cellKind(cell("inconclusive", 204, 1)), "inconclusive");
  assert.equal(cellKind(cell("weird", 200, 1)), "none");
  assert.equal(cellKind(undefined), "none");
});

test("the matrix becomes rows with a cell per identity, anonymous first", () => {
  const g = grid(matrix);
  assert.deepEqual(g.columns, ["anonymous", "bob", "carol"]);
  assert.equal(g.rows.length, 4);
  const orders = g.rows[1];
  assert.deepEqual(
    orders.cells.map((c) => [c.identity, c.kind, c.text, c.historyId]),
    [
      ["anonymous", "enforced", "enforced 401", 21],
      ["bob", "bypass-high", "bypass 200", 22],
      ["carol", "error", "error", 23],
    ],
  );
  assert.equal(orders.worst, "bypass-high");
  assert.equal(orders.baselineId, 20);
  // The owner's own column says so; a skipped row has no verdicts.
  assert.deepEqual(g.rows[3].cells[1], { identity: "bob", kind: "none", text: "owner", historyId: null });
  assert.equal(g.rows[2].skipped, "skipped: baseline status 404; nothing to compare against");
  assert.equal(g.rows[2].worst, "none");
  assert.equal(g.skipped, 1);
  assert.deepEqual(
    Object.fromEntries(Object.entries(g.counts).filter(([, n]) => n)),
    { "bypass-high": 1, "bypass-low": 1, public: 1, different: 2, enforced: 2, error: 1, none: 1 },
  );
});

test("inconclusive cells are shown, counted and filterable", () => {
  const m: Matrix = {
    ...matrix,
    requests: [
      { source_id: 5, method: "HEAD", url: "http://shop.test/a", owner: "alice", baseline_history_id: 50, baseline_status: 200, cells: { anonymous: cell("enforced", 401, 51), bob: cell("inconclusive", 200, 52), carol: cell("different", 200, 53) } },
      { source_id: 6, method: "GET", url: "http://shop.test/b", owner: "alice", baseline_history_id: 60, baseline_status: 200, cells: { anonymous: cell("enforced", 401, 61), bob: cell("enforced", 403, 62), carol: cell("inconclusive", 204, 63) } },
    ],
  };
  const g = grid(m);
  assert.deepEqual([g.rows[0].cells[1].kind, g.rows[0].cells[1].text, g.rows[0].cells[1].historyId], ["inconclusive", "inconclusive 200", 52]);
  assert.equal(g.counts.inconclusive, 2);
  assert.equal(g.counts.none, 0);
  assert.equal(g.rows[1].worst, "inconclusive");
  assert.equal(grid(m, { only: "inconclusive" }).rows.length, 2);
  // Ranked below a real difference, above a refusal.
  assert.deepEqual(grid(m, { worstFirst: true }).rows.map((r) => r.worst), ["different", "inconclusive"]);
});

test("rows can be filtered by kind and sorted worst first", () => {
  assert.deepEqual(grid(matrix, { only: "bypass-low" }).rows.map((r) => r.url.split("/").pop()), ["dashboard"]);
  assert.deepEqual(grid(matrix, { worstFirst: true }).rows.map((r) => r.url.split("/").pop()), ["1", "dashboard", "me", "9"]);
});

test("noise is hidden unless asked for, and only rows with an issue are shown when asked", () => {
  const m: Matrix = {
    ...matrix,
    requests: [
      ...matrix.requests,
      { source_id: 7, method: "GET", url: "http://shop.test/static/app.js", owner: "alice", baseline_history_id: 70, baseline_status: 200, cells: { anonymous: cell("public", 200, 71), bob: cell("public", 200, 72) }, hidden: "static asset (Content-Type text/javascript)" },
      { source_id: 8, method: "GET", url: "http://shop.test/robots.txt", owner: "alice", baseline_history_id: 80, baseline_status: 200, cells: { anonymous: cell("public", 200, 81) }, hidden: "skip path /robots.txt$" },
    ],
  };
  const g = grid(m);
  assert.equal(g.rows.length, 4, "noise left out");
  assert.equal(g.hidden, 2);
  assert.equal(g.counts.public, 1, "noise isn't counted");
  const all = grid(m, { showHidden: true });
  assert.equal(all.rows.length, 6);
  assert.equal(all.counts.public, 4);
  assert.equal(all.rows[4].hidden, "static asset (Content-Type text/javascript)");
  assert.equal(all.rows[0].hidden, null);
  // Issues only: a bypass or public row; the others are counted.
  const issues = grid(m, { issuesOnly: true });
  // orders/1 has a bypass (and an error), the dashboard a public cell.
  assert.deepEqual(issues.rows.map((r) => r.url.split("/").pop()), ["1", "dashboard"]);
  assert.equal(issues.quiet, 2);
  // An error is no "no issue": nothing was compared.
  const failed: Matrix = { ...matrix, requests: [{ ...matrix.requests[0], cells: { anonymous: cell("enforced", 401, 11), bob: cell("error", null, 12) } }] };
  assert.equal(grid(failed, { issuesOnly: true }).rows.length, 1);
  // Noise the matrix left out is counted too.
  const left: Matrix = { ...matrix, hidden_requests: { static_assets: 3, skip_paths: 2 } };
  assert.equal(grid(left).hidden, 5);
  assert.equal(grid(m, { issuesOnly: true, showHidden: true }).rows.length, 4);
  // A verdict picked shows its rows whatever issuesOnly says.
  const enforced = grid(m, { issuesOnly: true, only: "enforced" });
  assert.equal(enforced.rows.length, 2);
  assert.equal(enforced.quiet, 0);
});

test("what a run left out, and skip paths as typed", () => {
  assert.equal(notTested({ static_assets: 12, skip_paths: 3, head_options: 1, duplicates: 4, noise_hint: "…" }), "not tested: 12 static assets · 3 skip paths · 1 HEAD/OPTIONS");
  assert.equal(notTested({ tested: 2, skipped_static: 5, skipped_skip_paths: 1, skipped_no_credentials: 2 }), "not tested: 5 static assets · 1 skip paths · 2 no credentials");
  assert.equal(notTested({}), "");
  assert.equal(notTested(null), "");
  assert.deepEqual(parseSkipPaths(" /static/ \n\n*/health$\n/static/\n"), ["/static/", "*/health$"]);
  assert.deepEqual(skipSetArgs(["/a", "-weird"]), ["authz", "skip", "set", "--", "/a", "-weird"]);
  assert.deepEqual(skipSetArgs([]), ["authz", "skip", "set"]);
});

const form: RunForm = { identities: ["bob", "carol"], anonymous: true, owner: "", select: "all", host: "", tag: "", where: "", history: [], keepCookies: "", rate: "", includeStatic: false };

test("a run's arguments come from the form", () => {
  assert.deepEqual(runArgs(form), ["authz", "run", "--as=bob,carol"]);
  assert.deepEqual(runArgs({ ...form, identities: [], owner: "alice", select: "tag", tag: " api ", keepCookies: "lang, theme", rate: "5" }), [
    "authz",
    "run",
    "--owner=alice",
    "--tag=api",
    "--keep-cookie=lang,theme",
    "--rate=5",
  ]);
  assert.deepEqual(runArgs({ ...form, anonymous: false, select: "host", host: "https://shop.test:8443/x" }), ["authz", "run", "--as=bob,carol", "--no-anonymous", "--where=host = 'shop.test'"]);
  // A quote in the host can't end the SQL string.
  assert.equal(runArgs({ ...form, select: "host", host: "a'b" }).at(-1), "--where=host = 'a''b'");
  assert.deepEqual(runArgs({ ...form, select: "where", where: "path LIKE '/api/%'" }).at(-1), "--where=path LIKE '/api/%'");
  assert.throws(() => runArgs({ ...form, identities: [], anonymous: false }), /at least one identity/);
  assert.throws(() => runArgs({ ...form, select: "host", host: " " }), /host/);
  assert.throws(() => runArgs({ ...form, rate: "oops" }), /Rate/);
  // Requests handed over from Traffic, tested by id.
  const history = [
    { id: 4, method: "GET", url: "https://shop.test/orders/4" },
    { id: 8, method: "POST", url: "https://shop.test/orders" },
  ];
  assert.deepEqual(runArgs({ ...form, select: "history", history }), ["authz", "run", "--as=bob,carol", "--history-id=4", "--history-id=8"]);
  assert.throws(() => runArgs({ ...form, select: "history" }), /No request picked/);
  // Static assets on request; requests from Traffic are tested as they are anyway.
  assert.deepEqual(runArgs({ ...form, includeStatic: true }), ["authz", "run", "--as=bob,carol", "--include-static"]);
  assert.deepEqual(runArgs({ ...form, includeStatic: true, select: "history", history }), ["authz", "run", "--as=bob,carol", "--history-id=4", "--history-id=8"]);
});

test("requests from Traffic: by id only, and only while that selection is on", () => {
  const history = [{ id: 31, method: "DELETE", url: "https://shop.test/x' --where=1=1" }];
  // The form keeps the handed-over requests when another selection is picked; they must not leak in.
  assert.deepEqual(runArgs({ ...form, history }), ["authz", "run", "--as=bob,carol"]);
  assert.deepEqual(runArgs({ ...form, select: "tag", tag: "api", history }), ["authz", "run", "--as=bob,carol", "--tag=api"]);
  assert.deepEqual(runArgs({ ...form, select: "host", host: "shop.test", history }), ["authz", "run", "--as=bob,carol", "--where=host = 'shop.test'"]);
  // The URL never reaches the argv, and the other options still apply.
  assert.deepEqual(runArgs({ ...form, select: "history", history, identities: [], owner: "alice", keepCookies: " theme , lang ", rate: "2" }), [
    "authz",
    "run",
    "--owner=alice",
    "--history-id=31",
    "--keep-cookie=theme,lang",
    "--rate=2",
  ]);
  assert.deepEqual(runArgs({ ...form, select: "history", history, anonymous: false }), ["authz", "run", "--as=bob,carol", "--no-anonymous", "--history-id=31"]);
  // The form's own checks come first.
  assert.throws(() => runArgs({ ...form, select: "history", history, identities: [], anonymous: false }), /at least one identity/);
  assert.throws(() => runArgs({ ...form, select: "history", history, rate: "-1" }), /Rate/);
});

test("requests from Traffic are opted in to only once the run's question was answered yes", () => {
  const history = [
    { id: 4, method: "GET", url: "https://shop.test/logout" },
    { id: 8, method: "PUT", url: "https://shop.test/orders/8" },
    { id: 9, method: "POST", url: "https://shop.test/graphql", mutation: true },
  ];
  const base = ["authz", "run", "--as=bob,carol", "--history-id=4", "--history-id=8", "--history-id=9"];
  // Unconfirmed, authz refuses the PUT, the mutation and the logout, and sends nothing.
  assert.deepEqual(runArgs({ ...form, select: "history", history }), base);
  assert.deepEqual(runArgs({ ...form, select: "history", history }, true), [...base, "--include-methods=MUTATION,PUT,POST", "--exclude=^$"]);
  // A GET that isn't a logout needs nothing, confirmed or not.
  const get = [{ id: 5, method: "GET", url: "https://shop.test/orders/5" }];
  assert.deepEqual(runArgs({ ...form, select: "history", history: get }, true), runArgs({ ...form, select: "history", history: get }));
  // Another selection never carries them, whatever the form still holds.
  assert.deepEqual(runArgs({ ...form, history }, true), ["authz", "run", "--as=bob,carol"]);
  assert.deepEqual(runArgs({ ...form, select: "tag", tag: "api", history }, true), ["authz", "run", "--as=bob,carol", "--tag=api"]);
  // The opt-ins come before the other options.
  assert.deepEqual(runArgs({ ...form, select: "history", history: history.slice(1, 2), rate: "2" }, true), [
    "authz",
    "run",
    "--as=bob,carol",
    "--history-id=8",
    "--include-methods=PUT",
    "--rate=2",
  ]);
});

test("live testing options, and the running proxy's options kept on a restart", () => {
  assert.deepEqual(liveArgs(form), ["--authz=anonymous,bob,carol"]);
  assert.deepEqual(liveArgs({ ...form, anonymous: false, identities: ["bob"], keepCookies: "lang, theme", rate: "2.5" }), ["--authz=bob", "--authz-keep-cookie=lang,theme", "--authz-rate=2.5"]);
  assert.throws(() => liveArgs({ ...form, rate: "oops" }), /Rate/);
  assert.throws(() => liveArgs({ ...form, rate: "-1" }), /Rate/);
  assert.deepEqual(liveArgs({ ...form, includeStatic: true }), ["--authz=anonymous,bob,carol", "--authz-include-static"]);
  const args = ["proxy", "run", "--listen", "127.0.0.1:8080", "--timeout", "30", "--log", "/p.proxy.log", "--verify-tls", "--auth", "alice", "--authz", "bob", "--authz-rate=5", "--no-http2"];
  assert.deepEqual(proxyOptions(args), ["--timeout=30", "--verify-tls", "--auth=alice", "--authz=bob", "--authz-rate=5", "--no-http2"]);
  // What the form doesn't set stays; what it sets replaces the old value.
  const live = proxyOptions([...args, "--authz-queue", "50", "--authz-exclude", "(?i)a=b"]);
  assert.deepEqual(withLive(live, ["--authz=carol"]), ["--timeout=30", "--verify-tls", "--auth=alice", "--authz-rate=5", "--no-http2", "--authz-queue=50", "--authz-exclude=(?i)a=b", "--authz=carol"]);
  assert.deepEqual(withLive(live, ["--authz=carol", "--authz-rate=2"]).filter((o) => o.startsWith("--authz-rate")), ["--authz-rate=2"]);
  assert.deepEqual(proxyOptions([]), []);
  // Static assets follow the form, on or off; skip paths given on the command line stay.
  const was = proxyOptions(["proxy", "run", "--authz", "bob", "--authz-include-static", "--authz-skip-path", "/x/", "--authz-skip-path=/y/"]);
  assert.deepEqual(was, ["--authz=bob", "--authz-include-static", "--authz-skip-path=/x/", "--authz-skip-path=/y/"]);
  assert.deepEqual(withLive(was, ["--authz=carol"]), ["--authz-skip-path=/x/", "--authz-skip-path=/y/", "--authz=carol"]);
  assert.deepEqual(withLive(was, ["--authz=carol", "--authz-include-static"]), ["--authz-skip-path=/x/", "--authz-skip-path=/y/", "--authz=carol", "--authz-include-static"]);
  // Invisible mode is a flag, the redirect takes a value.
  assert.deepEqual(proxyOptions(["proxy", "run", "--invisible", "--redirect", "https://app.test", "--no-http2"]), ["--invisible", "--redirect=https://app.test", "--no-http2"]);
});

test("hosts and run labels", () => {
  assert.equal(hostOf("shop.test:8080"), "shop.test");
  assert.equal(hostOf("http://10.0.0.5/x"), "10.0.0.5");
  const run = { run_id: 12, time: "2026-10-29T10:11:12.000Z", state: "running", args: ["proxy", "run", "--authz", "bob"], verdicts: { bypass: 2, enforced: 5 } };
  assert.equal(runLabel(run), "#12 · 2026-10-29 10:11 · live (proxy) · running · 2 bypasses");
  assert.equal(runLabel({ ...run, args: ["authz", "run"], verdicts: { bypass: 1 } }), "#12 · 2026-10-29 10:11 · running · 1 bypass");
});

test("a run that started drops the requests from Traffic, so the next one starts from all history", () => {
  const history = [{ id: 4, method: "GET", url: "https://shop.test/a" }];
  const f = { ...form, select: "history" as const, history, owner: "alice", keepCookies: "lang" };
  const next = afterStart(f);
  assert.equal(next.select, "all");
  assert.deepEqual(next.history, []);
  assert.deepEqual(runArgs(next), ["authz", "run", "--as=bob,carol", "--owner=alice", "--keep-cookie=lang"]);
  // The rest of the form stays, and the old form isn't changed.
  assert.deepEqual({ ...next, select: f.select, history: f.history }, f);
  assert.equal(f.select, "history");
  // Another choice is kept; picks left over from Traffic are dropped too.
  assert.deepEqual(afterStart({ ...form, select: "tag", tag: "api", history }), { ...form, select: "tag", tag: "api", history: [] });
});
