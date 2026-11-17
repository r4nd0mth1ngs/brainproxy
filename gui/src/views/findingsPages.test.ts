import { test } from "node:test";
import assert from "node:assert/strict";
import type { FindingItem } from "../api.ts";
import { heldNote, loadAll, MAX_ROWS, pageArgs, type ListPage } from "./findingsPages.ts";

const item = (id: number): FindingItem => ({
  id,
  alert_ref: "10037",
  name: "n",
  risk: "low",
  confidence: "medium",
  host: "a.test",
  method: "GET",
  url: `https://a.test/${id}`,
  param: "",
  evidence: "",
  hits: 1,
  history_id: null,
  state: "open",
  source: "passive",
});

/** A `findings list` over `rows`, recording each call's arguments. */
function cli(rows: () => FindingItem[]) {
  const calls: string[][] = [];
  const list = async (args: string[]): Promise<ListPage> => {
    calls.push(args);
    const offset = Number(args[args.indexOf("--offset") + 1]);
    const limit = Number(args[args.indexOf("--limit") + 1]);
    const all = rows();
    const items = all.slice(offset, offset + limit);
    return { items, total: all.length, truncated: offset + items.length < all.length };
  };
  return { calls, list };
}

test("a page asks for every finding in the states, from an offset", () => {
  assert.deepEqual(pageArgs("open,confirmed", 10, 5), ["findings", "list", "--all", "--state", "open,confirmed", "--limit", "5", "--offset", "10"]);
});

test("the list is read page after page until nothing is left", async () => {
  const rows = Array.from({ length: 7 }, (_, i) => item(i + 1));
  const { calls, list } = cli(() => rows);
  const l = await loadAll(list, "open", 3);
  assert.deepEqual(l.items.map((f) => f.id), [1, 2, 3, 4, 5, 6, 7]);
  assert.deepEqual([l.total, l.truncated], [7, false]);
  assert.deepEqual(calls.map((c) => c[c.length - 1]), ["0", "3", "6"]);
  assert.equal(heldNote(l), "");
});

test("past the most it holds, it stops and says how many it left out", async () => {
  const rows = Array.from({ length: 10 }, (_, i) => item(i + 1));
  const { calls, list } = cli(() => rows);
  const l = await loadAll(list, "open", 3, 5);
  assert.equal(l.items.length, 5);
  assert.deepEqual([l.total, l.truncated], [10, true]);
  // The last page asks only for what still fits.
  assert.deepEqual(calls.map((c) => c[c.indexOf("--limit") + 1]), ["3", "2"]);
  assert.equal(heldNote({ items: rows.slice(0, 5), total: 61234, truncated: true }), `Showing 5 of 61,234 findings (the list holds at most ${MAX_ROWS.toLocaleString("en")})`);
});

test("a finding added between pages doesn't show twice", async () => {
  let rows = [item(1), item(2), item(3)];
  const { list } = cli(() => rows);
  const shifting = async (args: string[]) => {
    const p = await list(args);
    // One more finding sorts first after the first page, pushing the rest down.
    if (args.includes("0")) rows = [item(9), ...rows];
    return p;
  };
  const l = await loadAll(shifting, "open", 2);
  // #2 came on both pages; #9, missed, comes with the next poll.
  assert.deepEqual(l.items.map((f) => f.id), [1, 2, 3]);
  assert.equal(l.truncated, false);
});

test("a CLI from before paging (no total) gives its one page", async () => {
  const l = await loadAll(async () => ({ items: [item(1), item(2)] }), "open");
  assert.deepEqual([l.items.length, l.total, l.truncated], [2, 2, false]);
});
