// brainproxy's own checks feed (`checks update --source brainproxy`): its status as `checks
// status` reports it, and the scan arguments built from it. Kept out of the components so it
// can be tested.

export interface QuickCheck {
  id: string;
  name: string;
  description: string;
}

export interface FeedState {
  repository: string;
  ref: string;
  commit: string;
  source: string;
  updated_unix: number;
  serial: number;
  key: string;
  files: number;
  checks: number;
  passive: number;
  quick_checks: QuickCheck[];
  skipped: [string, string][];
}

export interface FeedStatus {
  dir: string;
  repository: string;
  installed?: FeedState;
  /** Signing keys this build trusts; 0 means it can't install the feed. */
  trusted_keys: number;
}

export interface FeedChange {
  file: string;
  id?: string;
}

/** `checks update --source brainproxy` output. */
export interface FeedUpdate extends FeedState {
  unchanged: boolean;
  added: FeedChange[];
  changed: FeedChange[];
  removed: FeedChange[];
}

export const FEED_UPDATE = ["checks", "update", "--source", "brainproxy"];

/** The feed has checks an active scan can run (passive ones run on recorded traffic). */
export const feedHasActive = (f?: FeedState | null) => !!f && f.checks - f.passive > 0;

export type Depth = "quick" | "standard" | "thorough";

/**
 * `--checks` arguments for a guided scan: brainproxy's feed whenever it has active checks, and
 * for Standard/Thorough the Nuclei templates when installed, from a minimum severity, plus the
 * end-of-life checks (outdated PHP, nginx, WordPress, ...), which are rated info. Quick adds no
 * Nuclei templates (thousands of extra requests).
 */
export function guidedChecks(depth: Depth, nuclei: boolean, feed?: FeedState | null): { args: string[]; text: string } {
  const sources: string[] = [];
  if (feedHasActive(feed)) sources.push("brainproxy");
  const severity = depth === "standard" ? "high" : depth === "thorough" ? "medium" : "";
  if (nuclei && severity) sources.push("nuclei");
  if (!sources.length) return { args: [], text: "" };
  const args = ["--checks", sources.join(",")];
  if (sources.includes("nuclei")) args.push("--check-severity", severity, "--check-include-tags", "eol");
  const parts = [
    sources.includes("brainproxy") ? "brainproxy's own checks" : "",
    sources.includes("nuclei") ? `Nuclei templates, ${severity} severity and above, plus end-of-life checks` : "",
  ].filter(Boolean);
  return { args, text: parts.join("; ") };
}

/** `scan active` arguments for a feed quick check: that check only, whatever its tags. */
export const quickCheckArgs = (id: string) => ["--no-rules", "--checks=brainproxy", `--check-ids=${id}`, "--check-exclude-tags="];

/** One line on what a feed update changed. */
export function describeUpdate(u: FeedUpdate): string {
  if (u.unchanged) return "brainproxy checks are up to date.";
  const name = (c: FeedChange) => c.id ?? c.file;
  const parts = [
    u.added.length ? `new: ${u.added.map(name).join(", ")}` : "",
    u.changed.length ? `updated: ${u.changed.map(name).join(", ")}` : "",
    u.removed.length ? `removed: ${u.removed.map(name).join(", ")}` : "",
  ].filter(Boolean);
  return `brainproxy checks updated (${u.checks} checks)${parts.length ? `. ${parts.join("; ")}` : ""}.`;
}

/** A daily automatic update is due: never ran, or more than a day ago. */
export const updateDue = (last: number | null, now: number) => last == null || now - last >= 24 * 3600 * 1000;
