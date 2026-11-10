import { test } from "node:test";
import assert from "node:assert/strict";
import {
  contentArgs,
  DEFAULT_SPEC,
  FORMATS,
  layoutArgs,
  maskValues,
  PRESET_SECTIONS,
  previewCommand,
  profileSaveCommand,
  REPORT_SOURCES,
  REPORT_STATES,
  reportCommand,
  savedNote,
  specFromProfile,
  specProblem,
  summaryCommand,
  summaryReviewCommand,
  toggleSection,
} from "./reportSpec.ts";

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

test("the findings chosen and the secrets shown go to the report and its preview, not to a saved layout", () => {
  const spec = {
    ...DEFAULT_SPEC,
    filter: { risk: "medium" as const, confidence: "high" as const, state: "all", source: "active" as const, host: " shop.test " },
    drafts: true,
    mask: " tok-123456 \n\n  sekrit-value\n",
  };
  const want = ["--risk=medium", "--confidence=high", "--state=all", "--source=active", "--host=shop.test", "--drafts", "--mask=tok-123456", "--mask=sekrit-value"];
  assert.deepEqual(contentArgs(spec), want);
  const cmd = reportCommand({ ...spec, format: "csv" }, "/r.csv");
  assert.deepEqual(cmd.slice(0, 2), ["report", "csv"]);
  assert.ok(want.every((a) => cmd.includes(a)));
  assert.deepEqual(cmd.slice(-3), ["--output", "/r.csv", "--force"]);
  assert.ok(want.every((a) => previewCommand(spec).includes(a)));
  assert.ok(!profileSaveCommand("x", spec).some((a) => want.includes(a)));
  // The defaults add nothing.
  assert.deepEqual(contentArgs(DEFAULT_SPEC), []);
});

test("keeping secrets drops the masks; a short mask value is refused, counted in characters", () => {
  const keep = { ...DEFAULT_SPEC, keepSecrets: true, mask: "abc" };
  assert.deepEqual(contentArgs(keep), ["--no-redact"]);
  assert.equal(specProblem(keep), null);
  assert.equal(specProblem({ ...DEFAULT_SPEC, mask: "abc" }), "Each value to mask needs at least 6 characters.");
  assert.equal(specProblem({ ...DEFAULT_SPEC, mask: "ééééé\u00e9" }), null);
  assert.equal(specProblem({ ...DEFAULT_SPEC, mask: "  abcdef  \n" }), null);
  assert.deepEqual(maskValues("a\r\n b \n"), ["a", "b"]);
});

test("formats, states and sources offer what the CLI takes", () => {
  assert.deepEqual(FORMATS.map((f) => f.id), ["html", "pdf", "docx", "markdown", "json", "csv", "sarif", "defectdojo"]);
  assert.deepEqual(FORMATS.filter((f) => f.listing).map((f) => f.id), ["csv", "sarif", "defectdojo"]);
  assert.deepEqual(REPORT_STATES.map((s) => s.id), ["", "open", "confirmed", "false_positive", "accepted_risk", "retest_pending", "fixed", "all"]);
  assert.deepEqual(REPORT_SOURCES.map((s) => s.id), ["", "passive", "active", "authz", "manual"]);
});

test("the saved note counts what was written", () => {
  assert.equal(savedNote("CSV", { total: 1, included: 1, truncated: false, redacted: null }, false), "CSV report saved with 1 finding.");
  assert.equal(
    savedNote("HTML", { total: 900, included: 500, truncated: true, redacted: 2 }, false),
    "HTML report saved with 500 of 900 findings (the first 500, riskiest first). Session secrets are masked in 2 places.",
  );
  assert.equal(savedNote("JSON", { total: 3, included: 3, truncated: false, redacted: null }, true), "JSON report saved with 3 findings. Secrets are quoted as recorded.");
});

test("the executive summary is saved as one argument and reviewed by its hash", () => {
  assert.deepEqual(summaryCommand("  --state all\nmore  "), ["report-summary", "set", "--text=--state all\nmore"]);
  assert.deepEqual(summaryCommand(""), ["report-summary", "set", "--text="]);
  assert.deepEqual(summaryReviewCommand("ab12"), ["report-summary", "review", "--hash=ab12"]);
});
