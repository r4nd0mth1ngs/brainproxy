// What the Findings view shows and the commands its triage runs. Kept apart from the view so
// it can be tested without a window.

import type { FindingItem } from "../api";

export type Source = "all" | "passive" | "active" | "authz" | "manual";

export const SOURCES: { id: Source; label: string }[] = [
  { id: "all", label: "Any source" },
  { id: "passive", label: "Passive scan" },
  { id: "active", label: "Active scan" },
  { id: "authz", label: "Access control" },
  { id: "manual", label: "Added by hand" },
];

export interface FindingFilter {
  /** Words that must all appear, in any case, in the finding's name, alert, URL, parameter, evidence or state, or `#id`. */
  text: string;
  source: Source;
  /** "" for every host. */
  host: string;
}

export const NO_FILTER: FindingFilter = { text: "", source: "all", host: "" };

export function matchesFinding(f: FindingItem, filter: FindingFilter): boolean {
  if (filter.source !== "all" && f.source !== filter.source) return false;
  if (filter.host && f.host !== filter.host) return false;
  const words = filter.text.toLowerCase().split(/\s+/).filter(Boolean);
  if (!words.length) return true;
  const hay = [f.name, f.alert_ref, f.method, f.url, f.param, f.evidence, f.state.replace("_", " "), `#${f.id}`].join("\n").toLowerCase();
  return words.every((w) => hay.includes(w));
}

/** The hosts findings were raised on, sorted, for the host filter. */
export function hostsOf(items: FindingItem[]): string[] {
  return [...new Set(items.map((f) => f.host))].filter(Boolean).sort();
}

/** Findings marked per command: one call is all or nothing, and a few hundred ids keep it short. */
export const MARK_BATCH = 500;

/** The commands that set the triage state of `ids`, in batches. */
export function markCommands(ids: number[], state: string): string[][] {
  const out: string[][] = [];
  for (let i = 0; i < ids.length; i += MARK_BATCH) {
    out.push(["findings", "mark", ...ids.slice(i, i + MARK_BATCH).map(String), "--state", state]);
  }
  return out;
}

/** The command that sets a finding's note; an empty note clears it. */
export function noteCommand(id: number, note: string): string[] {
  return ["findings", "mark", String(id), `--note=${note.trim()}`];
}

/** Who last wrote a note, and when, in words. */
export function noteBy(origin: string | null | undefined, at: string | null | undefined): string {
  const who = origin === "mcp" ? "an agent (via MCP)" : origin === "cli" ? "the command line" : origin === "gui" ? "the desktop app" : "";
  const when = at ? new Date(at).toLocaleString() : "";
  return [who && `by ${who}`, when && `on ${when}`].filter(Boolean).join(" ");
}
