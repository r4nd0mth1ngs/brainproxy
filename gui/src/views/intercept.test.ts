import { test } from "node:test";
import assert from "node:assert/strict";
import { mayRunWhileTyping } from "../ui/actions.ts";
import { FORWARD, filterChange, filterChanged, interceptChanger, interceptEnableArgs, savedQueries, savedQueryFor, withFilter, type InterceptSettings } from "./intercept.ts";
import { DEFAULT_FILTER } from "./trafficFilter.ts";

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

/** A CLI for one or more projects' intercept settings, answering after `delay` ms. */
function fakeCli(delay = 0) {
  const settings: Record<string, InterceptSettings> = { a: { ...base }, b: { ...base, enabled: false } };
  const calls: string[] = [];
  const cli = async <T,>(args: string[], { project }: { project: string }): Promise<T> => {
    await new Promise((r) => setTimeout(r, delay));
    calls.push(`${project}: ${args.slice(0, 2).join(" ")}`);
    if (args[1] === "status") return { settings: { ...settings[project] } } as T;
    const filter = args.find((a) => a.startsWith("--filter="))?.slice("--filter=".length);
    if (filter === "bad") throw new Error("invalid input: filter: refused");
    const { filter: _, ...rest } = settings[project];
    settings[project] = { ...rest, enabled: true, requests: args.includes("--requests"), responses: args.includes("--responses"), ...(filter ? { filter } : {}) };
    return {} as T;
  };
  return { settings, calls, cli };
}

test("changes run in turn, each on the settings the one before left", async () => {
  const { settings, cli } = fakeCli(5);
  const errors: unknown[] = [];
  let done = 0;
  const change = interceptChanger(cli, (e) => errors.push(e), () => done++);
  settings.a.filter = "host:a";
  // B, then back to A before B is saved: A wins, not "unchanged" against a stale poll.
  const b = change("a", filterChange("host:b"));
  const a = change("a", filterChange("host:a"));
  // A checkbox ticked meanwhile keeps the filter.
  const tick = change("a", (cur) => interceptEnableArgs({ ...cur, responses: true }));
  assert.deepEqual(await Promise.all([b, a, tick]), [true, true, true]);
  assert.equal(settings.a.filter, "host:a");
  assert.equal(settings.a.responses, true);
  assert.equal(done, 3);
  assert.deepEqual(errors, []);
});

test("a refused change is reported and the next still runs", async () => {
  const { settings, cli } = fakeCli();
  const errors: string[] = [];
  const change = interceptChanger(cli, (e) => errors.push((e as Error).message), () => {});
  assert.equal(await change("a", filterChange("bad")), false);
  assert.equal(await change("a", filterChange("host:c")), true);
  assert.deepEqual(errors, ["invalid input: filter: refused"]);
  assert.equal(settings.a.filter, "host:c");
});

test("a change runs against the project it was made for", async () => {
  const { settings, calls, cli } = fakeCli(5);
  const change = interceptChanger(cli, () => {}, () => {});
  await Promise.all([change("a", filterChange("host:a")), change("b", filterChange("host:b"))]);
  assert.equal(settings.a.filter, "host:a");
  // Intercept is off in b: the filter isn't applied there (enable would turn it on).
  assert.equal(settings.b.filter, undefined);
  assert.equal(settings.b.enabled, false);
  assert.deepEqual(calls, ["a: intercept status", "a: intercept enable", "b: intercept status"]);
});

test("Forward's shortcut isn't taken from find while a message or the filter is being edited", () => {
  const chord = FORWARD.keys;
  for (const t of [{ tagName: "TEXTAREA" }, { tagName: "DIV", isContentEditable: true }, { tagName: "INPUT", type: "text" }])
    for (const mac of [true, false]) assert.equal(mayRunWhileTyping(FORWARD, chord, t, mac), false, `${t.tagName} ${mac}`);
  // Elsewhere in Proxy (the held list, a button) it forwards, and the palette always lists it.
  for (const t of [null, { tagName: "BUTTON" }, { tagName: "TR" }]) assert.ok(mayRunWhileTyping(FORWARD, chord, t, true));
  assert.ok(!("noPalette" in FORWARD));
});
