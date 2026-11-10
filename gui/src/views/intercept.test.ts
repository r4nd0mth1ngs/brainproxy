import { test } from "node:test";
import assert from "node:assert/strict";
import { filterChanged, interceptEnableArgs, savedQueries, savedQueryFor, withFilter, type InterceptSettings } from "./intercept";
import { DEFAULT_FILTER } from "./trafficFilter";

const base: InterceptSettings = { enabled: true, requests: true, responses: false, timeout_secs: 120, timeout_action: "forward" };

test("enable passes the filter back with every other setting", () => {
  const args = interceptEnableArgs({ ...base, responses: true, requests: false, method: "POST", filter: ' status:5xx resp.body:"stack trace" ' });
  assert.deepEqual(args, [
    "intercept",
    "enable",
    "--responses",
    "--method=POST",
    '--filter=status:5xx resp.body:"stack trace"',
    "--timeout",
    "120",
    "--timeout-action",
    "forward",
  ]);
  // A query starting with '-' stays the flag's value.
  assert.ok(interceptEnableArgs({ ...base, filter: "-x" }).includes("--filter=-x"));
  // None, or only spaces: no --filter, which clears it.
  assert.ok(!interceptEnableArgs(base).some((a) => a.startsWith("--filter")));
  assert.ok(!interceptEnableArgs({ ...base, filter: "  " }).some((a) => a.startsWith("--filter")));
});

test("the filter is trimmed, and empty is none", () => {
  assert.deepEqual(withFilter(base, "  method=POST "), { ...base, filter: "method=POST" });
  assert.deepEqual(withFilter({ ...base, filter: "host:a" }, "   "), base);
  assert.ok(!("filter" in withFilter({ ...base, filter: "host:a" }, "")));
  assert.equal(filterChanged({ ...base, filter: "host:a" }, " host:a "), false);
  assert.equal(filterChanged(base, ""), false);
  assert.equal(filterChanged(base, "host:a"), true);
  assert.equal(filterChanged({ ...base, filter: "host:a" }, ""), true);
});

test("only saved queries are offered, by name", () => {
  const saved = [
    { name: "errors", filter: { ...DEFAULT_FILTER, text: " status:5xx ", query: true, sources: ["proxy"] } },
    { name: "login urls", filter: { ...DEFAULT_FILTER, text: "login" } },
    { name: "token", filter: { ...DEFAULT_FILTER, text: "apiKey", contents: true } },
    { name: "empty query", filter: { ...DEFAULT_FILTER, text: "  ", query: true } },
    { name: "posts", filter: { ...DEFAULT_FILTER, text: "method=POST", query: true, hideAssets: true } },
  ];
  const offered = savedQueries(saved);
  assert.deepEqual(offered, [
    { name: "errors", text: "status:5xx" },
    { name: "posts", text: "method=POST" },
  ]);
  assert.equal(savedQueryFor(offered, "method=POST "), "posts");
  assert.equal(savedQueryFor(offered, "method=PUT"), null);
});
