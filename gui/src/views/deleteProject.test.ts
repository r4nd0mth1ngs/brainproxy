import { test } from "node:test";
import assert from "node:assert/strict";
import { baseName, deletedNotice, forgetProject, isProjectKey } from "./deleteProject.ts";

const P = "/home/me/acme.bpdb";

test("only the deleted project's own keys are its", () => {
  for (const k of [`traffic-filters:${P}`, `api-import-job:${P}`, `wizard-job:${P}`, `wizard-off:${P}`]) assert.ok(isProjectKey(k, P), k);
  for (const k of [
    "recent-projects",
    "theme",
    `traffic-filters:${P}x`,
    `traffic-filters:/home/me/acme.bpdb.old`,
    `traffic-filters:/x${P}`,
    `wizard-:${P}`,
    `other:${P}`,
    `traffic-filters:${P}:${P}`,
  ])
    assert.ok(!isProjectKey(k, P), k);
});

test("forgetting a project removes its keys and keeps the rest", () => {
  const data = new Map([
    [`traffic-filters:${P}`, "[]"],
    [`wizard-job:${P}`, "3"],
    ["traffic-filters:/home/me/other.bpdb", "[]"],
    ["theme", "dark"],
  ]);
  const storage = {
    get length() {
      return data.size;
    },
    key: (i: number) => [...data.keys()][i] ?? null,
    removeItem: (k: string) => void data.delete(k),
  };
  forgetProject(storage, P);
  assert.deepEqual([...data.keys()], ["traffic-filters:/home/me/other.bpdb", "theme"]);
});

test("what the user is told after a delete", () => {
  assert.equal(baseName(P), "acme.bpdb");
  assert.equal(baseName("C:\\work\\acme.bpdb"), "acme.bpdb");
  assert.deepEqual(deletedNotice(P, { state: "deleted", removed: [P], left: [] }), { text: "", problem: false });
  const gone = deletedNotice(P, { state: "gone" });
  assert.match(gone.text, /no longer there.*off Recent/);
  assert.equal(gone.problem, false);
  const stuck = deletedNotice(P, { state: "not_stopped", error: "job 4 is still running" });
  assert.deepEqual(stuck, { text: "acme.bpdb wasn't deleted: job 4 is still running", problem: true });
  const one = deletedNotice(P, { state: "deleted", removed: [P], left: [{ path: `${P}.browsers`, error: "busy" }] });
  assert.match(one.text, /acme\.bpdb was deleted, but \/home\/me\/acme\.bpdb\.browsers couldn't be \(busy\)\. Delete it by hand/);
  assert.equal(one.problem, true);
  const two = deletedNotice(P, { state: "deleted", removed: [P], left: [{ path: "a", error: "e" }, { path: "b", error: "e" }] });
  assert.match(two.text, /a and 1 more.*Delete them by hand/);
});
