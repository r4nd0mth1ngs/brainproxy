import { test } from "node:test";
import assert from "node:assert/strict";
import {
  extractProblem,
  generatorSpec,
  generatorUnavailable,
  NEW_GENERATOR,
  NEW_SET,
  offeredGenerators,
  onlyExtract,
  payloadSpec,
  runControls,
  type Generator,
  type PayloadSet,
} from "./fuzzPayloads.ts";

const gen = (patch: Partial<Generator>): Generator => ({ ...NEW_GENERATOR, ...patch });
const set = (patch: Partial<PayloadSet>): PayloadSet => ({ ...NEW_SET, ...patch });

test("lists, ranges, files and built-in lists become their sources", () => {
  assert.equal(payloadSpec(set({ source: "builtin", wordlist: "xss" })), "wordlist:xss");
  assert.equal(payloadSpec(set({ source: "list", list: "a\r\nb,c\n\n" })), "list:a,b\\,c");
  assert.equal(payloadSpec(set({ source: "range", from: "1", to: "9", step: "1" })), "range:1-9");
  assert.equal(payloadSpec(set({ source: "range", from: "0", to: "90", step: "10" })), "range:0-90:10");
  assert.equal(payloadSpec(set({ source: "file", file: "/w.txt" })), "file:/w.txt");
});

test("each generator becomes the source fuzz run reads", () => {
  assert.equal(generatorSpec(gen({ kind: "null", count: " 5 " })), "null:5");
  assert.equal(generatorSpec(gen({ kind: "dates" })), "dates:2024-01-01..2024-12-31");
  assert.equal(generatorSpec(gen({ kind: "dates", dateStep: "1w", dateFormat: "%Y%m%d" })), "dates:2024-01-01..2024-12-31:1w:%Y%m%d");
  assert.equal(generatorSpec(gen({ kind: "dates", dateFormat: "%d/%m/%y" })), "dates:2024-01-01..2024-12-31:%d/%m/%y");
  assert.equal(generatorSpec(gen({ kind: "brute", charset: "a-f0-9", min: "2", max: "4" })), "brute:a-f0-9:2-4");
  assert.equal(generatorSpec(gen({ kind: "case", word: "Admin" })), "case:Admin");
  assert.equal(generatorSpec(gen({ kind: "subst", word: "pass" })), "subst:pass");
  assert.equal(generatorSpec(gen({ kind: "subst", word: "pass", map: " a=4@,s=5 " })), "subst:pass:a=4@,s=5");
  assert.equal(generatorSpec(gen({ kind: "bitflip" })), "bitflip");
  assert.equal(generatorSpec(gen({ kind: "bitflip", value: "AB" })), "bitflip:AB");
  assert.equal(generatorSpec(gen({ kind: "usernames", names: "John Smith\nSmith, Jr\n" })), "usernames:list:John Smith,Smith\\, Jr");
  assert.equal(generatorSpec(gen({ kind: "copy", position: "2" })), "copy:2");
  assert.equal(generatorSpec(gen({ kind: "extract" })), "extract");
  assert.equal(generatorSpec(gen({ kind: "extract", value: "tok0" })), "extract:tok0");
  assert.equal(generatorSpec(gen({ kind: "oob", count: "3" })), "oob:3");
  assert.equal(generatorSpec(gen({ kind: "oob", count: "3", oobForm: "host" })), "oob:3:host");
  assert.equal(payloadSpec(set({ source: "generator", gen: gen({ kind: "case", word: "ab" }) })), "case:ab");
});

test("generators are offered in the modes that allow them", () => {
  const kinds = (mode: Parameters<typeof offeredGenerators>[0], positions: number, oob: boolean) =>
    offeredGenerators(mode, positions, oob).map((g) => g.kind);
  assert.ok(!kinds("sniper", 1, false).includes("copy"));
  assert.ok(kinds("sniper", 1, false).includes("extract"));
  assert.ok(!kinds("sniper", 2, false).includes("extract"));
  assert.ok(kinds("pitchfork", 2, false).includes("copy") && kinds("pitchfork", 2, false).includes("extract"));
  assert.ok(kinds("cluster-bomb", 2, false).includes("copy") && !kinds("cluster-bomb", 2, false).includes("extract"));
  assert.ok(!kinds("pitchfork", 2, false).includes("oob") && kinds("pitchfork", 2, true).includes("oob"));
  assert.match(generatorUnavailable("oob", "sniper", 1, false)!, /OOB listener/);
  assert.equal(generatorUnavailable("brute", "cluster-bomb", 3, false), null);
});

test("an extract set needs the regex, and a run of extract sets alone a limit", () => {
  const extract = set({ source: "generator", gen: gen({ kind: "extract" }) });
  const copy = set({ source: "generator", gen: gen({ kind: "copy" }) });
  const list = set({ source: "list", list: "a" });
  assert.equal(extractProblem([list], "", ""), null);
  assert.match(extractProblem([extract, list], "", "")!, /Extract regex/);
  assert.equal(extractProblem([extract, list], "next=(\\w+)", ""), null);
  assert.ok(onlyExtract([extract, copy]) && !onlyExtract([copy]) && !onlyExtract([extract, list]));
  assert.match(extractProblem([extract, copy], "x", "")!, /Max/);
  assert.equal(extractProblem([extract, copy], "x", "50"), null);
});

test("a run's state says what it can be asked to do", () => {
  assert.deepEqual(runControls("running"), { pause: true, resume: false, resumeLabel: "Resume from here", stop: true });
  assert.deepEqual(runControls("paused"), { pause: false, resume: true, resumeLabel: "Resume", stop: true });
  for (const s of ["stopped", "failed"]) {
    const c = runControls(s);
    assert.ok(c.resume && !c.pause && !c.stop && c.resumeLabel === "Resume from here", s);
  }
  for (const s of ["completed", "stopping", undefined]) {
    const c = runControls(s);
    assert.ok(!c.resume && !c.pause, String(s));
  }
});
