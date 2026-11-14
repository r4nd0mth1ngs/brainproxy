import { test } from "node:test";
import assert from "node:assert/strict";
import { jobEndedText, jobName, SOURCES_REFUSED, sourcesToggle } from "./scanJobs.ts";

test("each job kind is named for what it is", () => {
  assert.equal(jobEndedText({ kind: "active-scan", id: 3, state: "completed" }), "Scan #3 completed");
  assert.equal(jobEndedText({ kind: "crawl", id: 4, state: "failed" }), "Crawl #4 failed");
  assert.equal(jobEndedText({ kind: "authz", id: 5, state: "completed" }), "Access-control run #5 completed");
  assert.equal(jobEndedText({ kind: "import", id: 6, state: "stopped" }), "Import #6 stopped");
  assert.equal(jobName("checks-update"), "Checks download");
  assert.equal(jobName("something-new"), "Job");
});

test("a passive source is switched on or off, but the last one stays on", () => {
  const all = ["proxy", "send", "crawl"];
  assert.deepEqual(sourcesToggle(["proxy", "send"], "crawl", all), { args: ["scan", "sources", "proxy", "send", "crawl"] });
  assert.deepEqual(sourcesToggle(["crawl", "proxy"], "send", all), { args: ["scan", "sources", "proxy", "send", "crawl"] }, "in the list's order");
  assert.deepEqual(sourcesToggle(["proxy", "send"], "proxy", all), { args: ["scan", "sources", "send"] });
  // `scan sources` with no sources only shows the list: the switch would do nothing.
  assert.deepEqual(sourcesToggle(["proxy"], "proxy", all), { refused: SOURCES_REFUSED });
  assert.deepEqual(sourcesToggle([], "send", all), { args: ["scan", "sources", "send"] });
});
