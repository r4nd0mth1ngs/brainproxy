import { test } from "node:test";
import assert from "node:assert/strict";
import { DEFAULT_SPEC, layoutArgs, PRESET_SECTIONS, previewCommand, profileSaveCommand, reportCommand, specFromProfile, specProblem, toggleSection } from "./reportBuilder.ts";

test("a preset's own sections aren't repeated; changed ones go in report order", () => {
  assert.deepEqual(layoutArgs(DEFAULT_SPEC), ["--preset", "technical"]);
  const own = { ...DEFAULT_SPEC, sections: ["evidence", "summary"] };
  assert.deepEqual(layoutArgs(own), ["--preset", "technical", "--sections=summary,evidence"]);
  const exec = { ...DEFAULT_SPEC, preset: "executive" as const, sections: PRESET_SECTIONS.executive };
  assert.deepEqual(layoutArgs(exec), ["--preset", "executive"]);
});

test("branding travels as single arguments, a bad colour doesn't", () => {
  const spec = { ...DEFAULT_SPEC, company: " Acme --x ", accent: "#0a7cff", logo: "/tmp/logo.png", since: "2026-11-01", profile: "board" as string | null, title: "Q4" };
  assert.deepEqual(reportCommand(spec, "/tmp/r.pdf"), [
    "report", "html", "--profile=board", "--preset", "technical", "--company=Acme --x", "--accent=#0a7cff", "--logo=/tmp/logo.png",
    "--since=2026-11-01", "--title=Q4", "--output", "/tmp/r.pdf", "--force",
  ]);
  assert.ok(!layoutArgs({ ...DEFAULT_SPEC, accent: "red" }).some((a) => a.startsWith("--accent")));
  assert.equal(specProblem({ ...DEFAULT_SPEC, accent: "red" }), "The colour must be #rrggbb.");
  assert.equal(specProblem({ ...DEFAULT_SPEC, sections: [] }), "Pick at least one section.");
  assert.equal(specProblem(DEFAULT_SPEC), null);
  // A profile is saved on top of the one loaded, so its logo stays.
  assert.deepEqual(profileSaveCommand(" dev ", spec).slice(0, 5), ["report-profile", "save", "dev", "--from=board", "--preset"]);
  assert.deepEqual(profileSaveCommand("dev", { ...spec, profile: null }).slice(0, 4), ["report-profile", "save", "dev", "--preset"]);
  assert.ok(previewCommand(spec).includes("--max-evidence"));
});

test("a saved layout fills the choices", () => {
  const s = specFromProfile("board", { preset: "executive", company: "Acme" }, DEFAULT_SPEC);
  assert.deepEqual([s.profile, s.preset, s.company, s.sections], ["board", "executive", "Acme", PRESET_SECTIONS.executive]);
});

test("over a profile, emptied fields clear it; without one, they're left out", () => {
  const over = { ...DEFAULT_SPEC, profile: "board", logo: "" };
  assert.deepEqual(layoutArgs(over), ["--profile=board", "--preset", "technical", "--company=", "--accent=", "--logo=", "--since="]);
  assert.deepEqual(layoutArgs({ ...DEFAULT_SPEC, logo: "" }), ["--preset", "technical"]);
  // Evidence brings the issue sections, which then stay.
  assert.deepEqual(toggleSection(["list"], "evidence"), ["list", "evidence", "issues"]);
  assert.deepEqual(toggleSection(["issues", "evidence"], "issues"), ["issues", "evidence"]);
  assert.deepEqual(toggleSection(["issues", "list"], "issues"), ["list"]);
});
