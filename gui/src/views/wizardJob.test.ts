import { test } from "node:test";
import assert from "node:assert/strict";
import { followsJob, readWizardJob } from "./wizardJob.ts";

const fail = (kind: string) => Promise.reject(Object.assign(new Error(kind), { kind }));

test("a remembered job the project no longer has is gone", async () => {
  const scan = { kind: "active-scan", state: "running" };
  assert.equal(await readWizardJob(Promise.resolve(scan)), scan);
  assert.equal(await readWizardJob(fail("not_found")), "gone");
  assert.equal(await readWizardJob(Promise.resolve({ kind: "crawl", state: "running" })), "gone", "another copy's id");
  await assert.rejects(readWizardJob(fail("io")), /io/, "a failed read is tried again, not taken as gone");
});

test("the job is read only while the Overview shows and it can still change", () => {
  for (const state of ["queued", "running", "stopping"]) assert.ok(followsJob({ state }, true), state);
  assert.ok(followsJob(null, true), "not read yet");
  for (const state of ["completed", "failed", "stopped"]) assert.ok(!followsJob({ state }, true), state);
  assert.ok(!followsJob("gone", true));
  assert.ok(!followsJob({ state: "running" }, false), "another tab shows");
  assert.ok(!followsJob(null, false));
});
