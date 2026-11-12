import { test } from "node:test";
import assert from "node:assert/strict";
import { fuzzy, rank } from "./fuzzy.ts";

test("letters match in order, skipping others, ignoring case", () => {
  assert.deepEqual(fuzzy("tgi", "Toggle intercept")?.at.length, 3);
  assert.equal(fuzzy("TI", "toggle intercept") != null, true);
  assert.equal(fuzzy("it", "Toggle") != null, false);
  assert.equal(fuzzy("xyz", "Proxy"), null);
  assert.deepEqual(fuzzy("", "anything"), { score: 0, at: [] });
});

test("word starts are preferred, but not at the cost of a match", () => {
  // "i" at the start of "intercept", not the "i" nowhere near.
  assert.deepEqual(fuzzy("si", "Settings › Intercept")?.at, [0, 11]);
  // The word-start "a" would leave no "b" after it; the earlier one is taken.
  assert.deepEqual(fuzzy("ab", "xab a")?.at, [1, 2]);
});

test("a run and a start rank above scattered letters", () => {
  const a = fuzzy("rep", "Replay")!.score;
  const b = fuzzy("rep", "Proxy › Event streams")?.score ?? -Infinity;
  assert.ok(a > b);
});

const items = [
  { title: "Proxy › Traffic", group: "Go to" },
  { title: "Turn intercept on or off", group: "Proxy" },
  { title: "Send the request", group: "Replay" },
  { title: "Replay", group: "Go to" },
  { title: "Export Traffic as HAR…", group: "Proxy" },
];
const titles = (q: string) => rank(q, items, (i) => i.title, (i) => i.group).map((r) => r.item.title);

test("every word must match, the best first", () => {
  assert.deepEqual(titles("traffic"), ["Proxy › Traffic", "Export Traffic as HAR…"]);
  assert.deepEqual(titles("har traf"), ["Export Traffic as HAR…"]);
  assert.equal(titles("replay")[0], "Replay");
  assert.deepEqual(titles("nothing like it"), []);
});

test("a word may match the group when the title doesn't have it", () => {
  // "replay" is only the group of Send the request.
  assert.ok(titles("replay send").includes("Send the request"));
});

test("highlights are positions in the title", () => {
  const [r] = rank("har", items, (i) => i.title, (i) => i.group);
  assert.equal(r.item.title, "Export Traffic as HAR…");
  assert.deepEqual(r.at.map((k) => r.item.title[k]).join(""), "HAR");
});

test("ties keep their order", () => {
  const same = [{ t: "abc" }, { t: "abc" }, { t: "abc" }];
  assert.deepEqual(
    rank("a", same, (x) => x.t).map((r) => same.indexOf(r.item)),
    [0, 1, 2],
  );
});
