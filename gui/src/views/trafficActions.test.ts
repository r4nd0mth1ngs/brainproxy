import { test } from "node:test";
import assert from "node:assert/strict";
import { highlightArgs, scanArgs, scanConfirm, unsafeMethods, withHighlight, type HistoryPick } from "./trafficActions.ts";

const get: HistoryPick = { id: 7, method: "GET", url: "https://shop.test/search?q=x" };
const post: HistoryPick = { id: 9, method: "post", url: "https://shop.test/contact" };

test("methods that can change data", () => {
  assert.deepEqual(unsafeMethods([get, { ...get, method: "HEAD" }, { ...get, method: "options" }]), []);
  assert.deepEqual(unsafeMethods([get, post, { ...post, id: 10 }, { ...post, method: "DELETE" }]), ["POST", "DELETE"]);
});

test("a scan from Traffic uses the Scans view's defaults", () => {
  assert.deepEqual(scanArgs([get], { nuclei: false }), ["scan", "active", "--history-id=7", "--strength=medium", "--background"]);
  assert.deepEqual(scanArgs([get, post], { nuclei: true }), [
    "scan",
    "active",
    "--history-id=7",
    "--history-id=9",
    "--strength=medium",
    "--checks=nuclei,brainproxy",
    "--check-include-tags=eol",
    "--check-severity=high",
    "--background",
  ]);
  assert.throws(() => scanArgs([], { nuclei: false }), /No request/);
});

test("the question before a scan names the request and warns about a POST", () => {
  const g = scanConfirm([get]);
  assert.equal(g.title, "Scan this request?");
  assert.match(g.message, /real attack traffic/);
  assert.match(g.message, /GET https:\/\/shop\.test\/search\?q=x is sent again/);
  assert.doesNotMatch(g.message, /side effects/);
  assert.match(g.message, /engagement scope/);

  const p = scanConfirm([post]);
  assert.match(p.message, /POST https:\/\/shop\.test\/contact is sent again/);
  assert.match(p.message, /replayed even though it is a POST, and that can change data or trigger side effects/);

  const many = scanConfirm([get, post]);
  assert.equal(many.title, "Scan 2 requests?");
  assert.match(many.message, /2 requests are sent again/);
  assert.match(many.message, /POST requests among them are replayed too/);
});

test("highlight on and off", () => {
  assert.deepEqual(highlightArgs(3, true), ["history", "tag", "3", "--add", "highlight"]);
  assert.deepEqual(highlightArgs(3, false), ["history", "tag", "3", "--remove", "highlight"]);
  assert.deepEqual(withHighlight(["api"], true), ["api", "highlight"]);
  assert.deepEqual(withHighlight(["api", "highlight"], true), ["api", "highlight"]);
  assert.deepEqual(withHighlight(["highlight", "api"], false), ["api"]);
});

test("methods: none picked, case folded, first-seen order, anything but GET/HEAD/OPTIONS", () => {
  assert.deepEqual(unsafeMethods([]), []);
  assert.deepEqual(unsafeMethods([{ ...get, method: "get" }, { ...get, method: "Head" }]), []);
  assert.deepEqual(unsafeMethods([{ ...post, method: "patch" }, post, { ...post, method: "POST" }, { ...post, method: "PATCH" }]), ["PATCH", "POST"]);
  assert.deepEqual(unsafeMethods(["PUT", "TRACE", "CONNECT", "PROPFIND"].map((method) => ({ ...get, method }))), ["PUT", "TRACE", "CONNECT", "PROPFIND"]);
});

test("a scan from Traffic attacks only the picked entries, by id", () => {
  // The URL never reaches the argv: a recorded URL can't add a flag, another target or a wider selection.
  const hostile: HistoryPick = { id: 12, method: "GET", url: "--where=1=1 https://elsewhere.test/ --crawl" };
  for (const nuclei of [false, true]) {
    const args = scanArgs([hostile, get], { nuclei });
    assert.ok(!args.some((a) => a.includes("elsewhere") || a.includes("shop.test")), args.join(" "));
    assert.ok(!args.some((a) => /^--(where|crawl|include-methods|api|from)\b/.test(a)), args.join(" "));
    assert.ok(!args.some((a) => !a.startsWith("--") && a !== "scan" && a !== "active"), "no positional URL");
    assert.deepEqual(args.filter((a) => a.startsWith("--history-id=")), ["--history-id=12", "--history-id=7"]);
    // In the background, so the call returns the job id at once.
    assert.equal(args.at(-1), "--background");
  }
});

test("a scan of many picks keeps them all, in order", () => {
  const picks = Array.from({ length: 50 }, (_, i) => ({ ...get, id: 1000 - i }));
  const ids = scanArgs(picks, { nuclei: false }).filter((a) => a.startsWith("--history-id="));
  assert.deepEqual(ids, picks.map((p) => `--history-id=${p.id}`));
});

test("the question before a scan: plain wording, labels, and every method that changes data", () => {
  const q = scanConfirm([get]);
  assert.equal(q.ok, "Start scan");
  assert.equal(q.cancel, "Cancel");
  assert.match(q.message, /^This sends real attack traffic to the site: /);

  // A lower-case method is named in upper case.
  const put = scanConfirm([{ ...post, method: "put" }]);
  assert.match(put.message, /PUT https:\/\/shop\.test\/contact is sent again/);
  assert.match(put.message, /even though it is a PUT, and that can change data/);
  assert.match(put.message, /one contact form can send a lot of emails/);

  // Several safe requests: no replay warning, plural wording.
  const reads = scanConfirm([get, { ...get, id: 8, method: "HEAD" }]);
  assert.equal(reads.title, "Scan 2 requests?");
  assert.match(reads.message, /2 requests are sent again/);
  assert.doesNotMatch(reads.message, /side effects|replayed/);

  // Each method once, whatever its case.
  const mixed = scanConfirm([get, post, { ...post, id: 10, method: "POST" }, { ...post, id: 11, method: "delete" }]);
  assert.equal(mixed.title, "Scan 4 requests?");
  assert.match(mixed.message, / POST, DELETE requests among them are replayed too, and that can change data/);
});

test("the question shows the URL as recorded, as text", () => {
  const url = "https://shop.test/a?x=<script>alert(1)</script>&y=\"'";
  const q = scanConfirm([{ ...get, url }]);
  assert.ok(q.message.includes(`GET ${url} is sent again`));
  assert.ok(!q.title.includes(url), "the title stays short");
});

test("highlight: only that tag changes, and the row's tags are not changed in place", () => {
  assert.deepEqual(highlightArgs(123456789, true), ["history", "tag", "123456789", "--add", "highlight"]);
  const tags = ["api", "highlight", "highlighted", "Highlight"];
  const off = withHighlight(tags, false);
  assert.deepEqual(off, ["api", "highlighted", "Highlight"]);
  assert.deepEqual(tags, ["api", "highlight", "highlighted", "Highlight"]);
  const on = withHighlight(off, true);
  assert.deepEqual(on, ["api", "highlighted", "Highlight", "highlight"]);
  assert.notEqual(on, off);
  assert.deepEqual(withHighlight([], true), ["highlight"]);
  assert.deepEqual(withHighlight([], false), []);
  assert.deepEqual(withHighlight(["api"], false), ["api"]);
});
