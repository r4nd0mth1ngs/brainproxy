// The report builder's choices and the commands they become. Kept apart from the dialog so it
// can be tested without a window. Presets and sections mirror crates/core/src/scan/layout.rs.

import { SOURCES, STATES, type Narrative } from "./findingsFilter.ts";

export type Preset = "technical" | "executive" | "developer" | "retest";
export type Format = "html" | "pdf" | "docx" | "markdown" | "csv" | "json" | "sarif" | "defectdojo";

export const PRESETS: { id: Preset; label: string; title: string }[] = [
  { id: "technical", label: "Technical", title: "Everything: summary, priorities, every issue with its evidence" },
  { id: "executive", label: "Executive", title: "A short read: verdict, priorities, posture and the list of issues" },
  { id: "developer", label: "Developer handoff", title: "Each issue with what to fix, its evidence and a curl line to reproduce it" },
  { id: "retest", label: "Retest letter", title: "What changed since a day: fixed, still there, back after a fix" },
];

export const SECTIONS: { id: string; label: string }[] = [
  { id: "summary", label: "At a glance" },
  { id: "fixfirst", label: "Fix these first" },
  { id: "posture", label: "Posture and trends" },
  { id: "list", label: "List of issues" },
  { id: "issues", label: "Issue sections" },
  { id: "evidence", label: "Evidence" },
  { id: "reproduce", label: "How to reproduce" },
  { id: "retest", label: "Retest results" },
  { id: "about", label: "About this report" },
];

export const PRESET_SECTIONS: Record<Preset, string[]> = {
  technical: ["summary", "fixfirst", "list", "issues", "evidence", "about"],
  executive: ["summary", "fixfirst", "posture", "list", "about"],
  developer: ["list", "issues", "evidence", "reproduce"],
  retest: ["retest", "about"],
};

/** Report formats; `listing` ones are findings for another tool, which sections and branding don't change. */
export const FORMATS: { id: Format; label: string; ext: string; listing?: boolean; note?: string }[] = [
  { id: "html", label: "HTML", ext: "html" },
  { id: "pdf", label: "PDF", ext: "pdf", note: "PDF is printed by Chromium, which must be installed." },
  { id: "docx", label: "Word (DOCX)", ext: "docx" },
  { id: "markdown", label: "Markdown", ext: "md" },
  { id: "json", label: "JSON", ext: "json", note: "The findings with the posture and retest data, for scripts." },
  { id: "csv", label: "CSV (spreadsheet)", ext: "csv", listing: true, note: "One row per finding, for spreadsheets." },
  { id: "sarif", label: "SARIF", ext: "sarif", listing: true, note: "SARIF 2.1 for code-scanning tools; a CVSS score becomes its security-severity." },
  { id: "defectdojo", label: "DefectDojo import", ext: "json", listing: true, note: "DefectDojo's Generic Findings Import JSON." },
];

export type Risk = "info" | "low" | "medium" | "high" | "critical";
export type Confidence = "low" | "medium" | "high";

/** Which findings a report includes; "" is the CLI's default for each. */
export interface ReportFilter {
  /** Minimum risk. */
  risk: "" | Risk;
  /** Minimum confidence. */
  confidence: "" | Confidence;
  /** One triage state, or "all"; "" is work still to do (open, confirmed, retest pending). */
  state: string;
  source: "" | "passive" | "active" | "authz" | "manual";
  host: string;
}

export const NO_REPORT_FILTER: ReportFilter = { risk: "", confidence: "", state: "", source: "", host: "" };

export const RISKS: Risk[] = ["info", "low", "medium", "high", "critical"];
export const CONFIDENCES: Confidence[] = ["low", "medium", "high"];

/** The state choices: the default, each triage state, or every finding. */
export const REPORT_STATES: { id: string; label: string }[] = [
  { id: "", label: "Work still to do" },
  ...STATES.map((s) => ({ id: s.id, label: s.label })),
  { id: "all", label: "All, closed ones too" },
];

/** The source choices, as the Findings view names them. */
export const REPORT_SOURCES: { id: ReportFilter["source"]; label: string }[] = SOURCES.map((s) => ({
  id: s.id === "all" ? "" : s.id,
  label: s.label,
}));

export interface ReportSpec {
  preset: Preset;
  sections: string[];
  company: string;
  /** #rrggbb, or "" for none. */
  accent: string;
  /** A logo file chosen now; null keeps a profile's own logo, "" removes it. */
  logo: string | null;
  /** YYYY-MM-DD for the retest section, or "". */
  since: string;
  format: Format;
  /** The saved profile this started from. */
  profile: string | null;
  title: string;
  /** Which findings it includes (not part of a saved layout). */
  filter: ReportFilter;
  /** Include write-ups and the executive summary nobody has reviewed yet, marked as drafts. */
  drafts: boolean;
  /** Quote session cookies, credentials and tokens as recorded (`--no-redact`). */
  keepSecrets: boolean;
  /** More values to mask, one per line. */
  mask: string;
}

export const DEFAULT_SPEC: ReportSpec = {
  preset: "technical",
  sections: PRESET_SECTIONS.technical,
  company: "",
  accent: "",
  logo: null,
  since: "",
  format: "html",
  profile: null,
  title: "",
  filter: NO_REPORT_FILTER,
  drafts: false,
  keepSecrets: false,
  mask: "",
};

/** The values to mask: one per line, trimmed. */
export const maskValues = (text: string): string[] =>
  text
    .split(/\r?\n/)
    .map((v) => v.trim())
    .filter(Boolean);

/** The flags that choose the findings and how secrets are shown, for the report and its preview. */
export function contentArgs(spec: ReportSpec): string[] {
  const f = spec.filter;
  const out: string[] = [];
  if (f.risk) out.push(`--risk=${f.risk}`);
  if (f.confidence) out.push(`--confidence=${f.confidence}`);
  if (f.state) out.push(`--state=${f.state}`);
  if (f.source) out.push(`--source=${f.source}`);
  if (f.host.trim()) out.push(`--host=${f.host.trim()}`);
  if (spec.drafts) out.push("--drafts");
  if (spec.keepSecrets) out.push("--no-redact");
  else out.push(...maskValues(spec.mask).map((v) => `--mask=${v}`));
  return out;
}

const same = (a: string[], b: string[]) => a.length === b.length && a.every((x) => b.includes(x));

/** The layout flags for `report` and `report-profile save`. */
export function layoutArgs(spec: ReportSpec, withProfile = true): string[] {
  const out: string[] = [];
  if (withProfile && spec.profile) out.push(`--profile=${spec.profile}`);
  out.push("--preset", spec.preset);
  // Sections in the report's own order, only when they differ from the preset's.
  if (!same(spec.sections, PRESET_SECTIONS[spec.preset])) {
    const ordered = SECTIONS.map((s) => s.id).filter((id) => spec.sections.includes(id));
    out.push(`--sections=${ordered.join(",") || "about"}`);
  }
  // Over a profile, an emptied field is sent empty, so it clears the profile's value.
  const base = spec.profile != null;
  if (spec.company.trim() || base) out.push(`--company=${spec.company.trim()}`);
  if (/^#[0-9a-fA-F]{6}$/.test(spec.accent)) out.push(`--accent=${spec.accent}`);
  else if (base) out.push("--accent=");
  if (spec.logo || (spec.logo === "" && base)) out.push(`--logo=${spec.logo}`);
  if (spec.since || base) out.push(`--since=${spec.since}`);
  return out;
}

/** The command that writes the report to `path`. */
export function reportCommand(spec: ReportSpec, path: string): string[] {
  const title = spec.title.trim() ? [`--title=${spec.title.trim()}`] : [];
  return ["report", spec.format, ...layoutArgs(spec), ...contentArgs(spec), ...title, "--output", path, "--force"];
}

/** The command for the live preview: the same layout as HTML, with short evidence. */
export function previewCommand(spec: ReportSpec): string[] {
  const title = spec.title.trim() ? [`--title=${spec.title.trim()}`] : [];
  return ["report", "html", ...layoutArgs(spec), ...contentArgs(spec), ...title, "--max-evidence", "1024", "--limit", "200"];
}

/** The command that saves these choices as a profile, on top of the one they started from
 * (so its logo stays unless replaced or removed). */
export function profileSaveCommand(name: string, spec: ReportSpec): string[] {
  const from = spec.profile ? [`--from=${spec.profile}`] : [];
  return ["report-profile", "save", name.trim(), ...from, ...layoutArgs(spec, false)];
}

/** Sections after ticking or unticking one: evidence and reproduction lines sit in the issue
 * sections, so they bring them, and the issue sections can't go while either is ticked. */
export function toggleSection(sections: string[], id: string): string[] {
  const on = sections.includes(id);
  if (on && id === "issues" && (sections.includes("evidence") || sections.includes("reproduce"))) return sections;
  const next = on ? sections.filter((s) => s !== id) : [...sections, id];
  if (!on && (id === "evidence" || id === "reproduce") && !next.includes("issues")) next.push("issues");
  return next;
}

/** The choices a saved layout makes. */
export function specFromProfile(name: string, layout: { preset?: Preset; sections?: string[]; company?: string; accent?: string; since?: string }, base: ReportSpec): ReportSpec {
  const preset = layout.preset ?? "technical";
  return {
    ...base,
    profile: name,
    preset,
    sections: layout.sections ?? PRESET_SECTIONS[preset],
    company: layout.company ?? "",
    accent: layout.accent ?? "",
    since: layout.since ?? "",
    logo: null,
  };
}

/** What's wrong with the choices, if anything. */
export function specProblem(spec: ReportSpec): string | null {
  if (spec.accent && !/^#[0-9a-fA-F]{6}$/.test(spec.accent)) return "The colour must be #rrggbb.";
  if (spec.since && !/^\d{4}-\d{2}-\d{2}$/.test(spec.since)) return "The day must be YYYY-MM-DD.";
  if (spec.sections.length === 0) return "Pick at least one section.";
  // As the CLI counts it: characters, not bytes.
  if (!spec.keepSecrets && maskValues(spec.mask).some((v) => [...v].length < 6)) return "Each value to mask needs at least 6 characters.";
  return null;
}

/** What `report` answers when it writes a file. */
export interface ReportWritten {
  total: number;
  included: number;
  truncated: boolean;
  redacted: number | null;
}

/** The toast after a report is saved. */
export function savedNote(label: string, r: ReportWritten, keptSecrets: boolean): string {
  const n = (k: number) => `${k} finding${k === 1 ? "" : "s"}`;
  const count = r.truncated ? `${r.included} of ${n(r.total)} (the riskiest first)` : n(r.total);
  const masked = keptSecrets
    ? " Secrets are quoted as recorded."
    : r.redacted
      ? ` Session secrets are masked in ${r.redacted} place${r.redacted === 1 ? "" : "s"}.`
      : "";
  return `${label} report saved with ${count}.${masked}`;
}

/** The executive summary (`report-summary show`): the narrative shape, null when there is none. */
export type Summary = Narrative;

/** The command that saves the executive summary (a draft until reviewed); "" clears it. The
 * text goes on stdin: up to 50,000 bytes is more than a Windows command line holds. */
export function summaryCommand(text: string): { args: string[]; stdin: string } {
  return { args: ["report-summary", "set", "--file=-"], stdin: text.trim() };
}

/** The hosts findings were raised on, for the host filter (which matches a host exactly). */
export const REPORT_HOSTS_SQL = "SELECT DISTINCT host FROM findings WHERE host <> '' ORDER BY host";

/** Most hosts offered; `query` stops at 200 rows unless given --limit. */
export const REPORT_HOSTS_LIMIT = 5000;

/** The `query` that lists them. */
export const reportHostsCommand = (): string[] => ["query", REPORT_HOSTS_SQL, "--limit", String(REPORT_HOSTS_LIMIT)];

/** The command that marks the summary reviewed: it names the text read, by its hash. */
export function summaryReviewCommand(hash: string): string[] {
  return ["report-summary", "review", `--hash=${hash}`];
}
