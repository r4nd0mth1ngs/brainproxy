import { test } from "node:test";
import assert from "node:assert/strict";
import { maxRiskLabel, passiveNote, scriptErrorNote } from "./scriptChecks.ts";

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
