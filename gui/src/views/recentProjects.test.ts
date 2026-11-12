import { test } from "node:test";
import assert from "node:assert/strict";
import { isAbsolute, openableRecents } from "./recentProjects.ts";

test("only a full path counts, as the OS reads it", () => {
  assert.ok(isAbsolute("/home/me/a.bpdb", false));
  for (const p of ["a.bpdb", "./a.bpdb", "../x/a.bpdb", "C:\\x\\a.bpdb", ""]) assert.ok(!isAbsolute(p, false), p);
  for (const p of ["C:\\x\\a.bpdb", "d:/x/a.bpdb", "\\\\server\\share\\a.bpdb"]) assert.ok(isAbsolute(p, true), p);
  for (const p of ["/x/a.bpdb", "\\x\\a.bpdb", "a.bpdb"]) assert.ok(!isAbsolute(p, true), p);
});

test("the palette's recent projects are the ones Welcome would open", () => {
  const recent = ["/home/me/open.bpdb", "relative.bpdb", "/home/me/other.bpdb", "./x.bpdb"];
  assert.deepEqual(openableRecents(recent, "/home/me/open.bpdb", false), ["/home/me/other.bpdb"]);
  assert.deepEqual(openableRecents(["C:\\p\\a.bpdb", "/b.bpdb"], null, true), ["C:\\p\\a.bpdb"]);
});
