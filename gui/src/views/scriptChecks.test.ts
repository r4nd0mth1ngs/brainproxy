import { test } from "node:test";
import assert from "node:assert/strict";
import { historyId, maxRiskLabel, passiveNote, pinFor, scriptAddArgs, scriptErrorNote, scriptNameProblem, scriptRemoveArgs, scriptTestArgs, testNote } from "./scriptChecks.ts";

test("a passive scan with no script failures says its counts", () => {
  assert.deepEqual(passiveNote({ scanned: 3, new_findings: 1 }), { text: "Passive scan: 3 captures, 1 new findings", error: false });
  assert.equal(passiveNote({ scanned: 0, new_findings: 0, script_errors: [] }).error, false);
});

test("a script check that failed or didn't run is said, as an error", () => {
  const threw = { script: "debug", error: "Error: boom", history_id: 12, count: 1 };
  const often = { script: "debug", error: "it ran past the time limit of 2 s", history_id: 4, count: 30 };
  const stale = { script: "old", error: "script file /x/old.js changed since it was named here; read it and name it again", history_id: 0, count: 1 };
  assert.equal(scriptErrorNote(threw), "Script check debug failed on history #12: Error: boom");
  assert.equal(scriptErrorNote(often), "Script check debug failed on 30 exchanges, first history #4: it ran past the time limit of 2 s");
  assert.match(scriptErrorNote(stale), /^Script check old didn't run: script file \/x\/old\.js changed/);
  const note = passiveNote({ scanned: 40, new_findings: 2, script_errors: [threw, stale] });
  assert.equal(note.error, true);
  assert.match(note.text, /^Passive scan: 40 captures, 2 new findings\. Script check debug failed on history #12: Error: boom\. Script check old didn't run/);
});

test("a script check's risk isn't known before it runs", () => {
  assert.equal(maxRiskLabel("high"), "high");
  assert.equal(maxRiskLabel(null), "set by the script");
  assert.equal(maxRiskLabel(undefined), "set by the script");
});

test("script check names follow the CLI's rule", () => {
  assert.equal(scriptNameProblem("csp.v2_x-1"), null);
  assert.equal(scriptNameProblem(""), "Name it");
  assert.match(scriptNameProblem("bad name")!, /letters, digits/);
  assert.match(scriptNameProblem("é")!, /letters, digits/);
  assert.match(scriptNameProblem("a".repeat(41))!, /40/);
  assert.equal(scriptNameProblem("a".repeat(40)), null);
});

test("historyId takes a positive id, with or without #", () => {
  assert.equal(historyId(" 12 "), 12);
  assert.equal(historyId("#7"), 7);
  assert.equal(historyId("0"), null);
  assert.equal(historyId("1.5"), null);
  assert.equal(historyId("-3"), null);
  assert.equal(historyId(""), null);
});

test("script commands put names and files after --, so a leading dash isn't a flag", () => {
  assert.deepEqual(scriptAddArgs("-x", "/a/c.js"), ["scan", "script", "add", "--", "-x", "/a/c.js"]);
  assert.deepEqual(scriptAddArgs("csp", "/a/c.js", "ab12"), ["scan", "script", "add", "--sha256=ab12", "--", "csp", "/a/c.js"]);
  assert.deepEqual(scriptTestArgs("-c.js", 4), ["scan", "script", "test", "--history=4", "--", "-c.js"]);
  assert.deepEqual(scriptRemoveArgs("csp"), ["scan", "script", "remove", "--", "csp"]);
});

test("an add is pinned to the tested text only for the file that was tested", () => {
  assert.equal(pinFor(null, "/a.js"), null);
  assert.equal(pinFor({ file: "/a.js", sha256: "ab" }, "/a.js"), "ab");
  assert.equal(pinFor({ file: "/a.js", sha256: "ab" }, "/b.js"), null);
});

test("testNote counts findings and says a failure", () => {
  assert.equal(testNote({ history: 3, sha256: "", findings: [], errors: [] }), "History #3: no findings.");
  const f = { alert_ref: "script:test:x", name: "X", risk: "low", confidence: "medium", param: "", evidence: "" };
  assert.equal(testNote({ history: 3, sha256: "", findings: [f, f], errors: [] }), "History #3: 2 findings.");
  assert.equal(
    testNote({ history: 3, sha256: "", findings: [], errors: [{ script: "test", error: "Error: boom", history_id: 3, count: 1 }] }),
    "History #3: no findings; the check failed: Error: boom",
  );
});
