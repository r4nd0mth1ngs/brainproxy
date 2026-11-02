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
