// The report builder's choices and the commands they become. Kept apart from the dialog so it
// can be tested without a window. Presets and sections mirror crates/core/src/scan/layout.rs.

export type Preset = "technical" | "executive" | "developer" | "retest";
export type Format = "html" | "pdf" | "docx" | "markdown";

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

export const FORMATS: { id: Format; label: string; ext: string }[] = [
  { id: "html", label: "HTML", ext: "html" },
  { id: "pdf", label: "PDF", ext: "pdf" },
  { id: "docx", label: "Word (DOCX)", ext: "docx" },
  { id: "markdown", label: "Markdown", ext: "md" },
];

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
};

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
  return ["report", spec.format, ...layoutArgs(spec), ...title, "--output", path, "--force"];
}

/** The command for the live preview: the same layout as HTML, with short evidence. */
export function previewCommand(spec: ReportSpec): string[] {
  const title = spec.title.trim() ? [`--title=${spec.title.trim()}`] : [];
  return ["report", "html", ...layoutArgs(spec), ...title, "--max-evidence", "1024", "--limit", "200"];
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
  return null;
}
