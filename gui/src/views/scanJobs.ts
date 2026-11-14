// Names for background jobs, and the passive scan's source switches, for the Scans view.

/** The kinds `job list` reports: each command that runs with --background (`jobs_cmd::spawn_background`). */
const JOB_NAMES: Record<string, string> = {
  "active-scan": "Scan",
  crawl: "Crawl",
  import: "Import",
  authz: "Access-control run",
  "checks-update": "Checks download",
};

/** What a job is called in a toast; a kind this build doesn't know is a "Job". */
export const jobName = (kind: string): string => JOB_NAMES[kind] ?? "Job";

/** The toast for a job that has ended. */
export const jobEndedText = (j: { kind: string; id: number; state: string }): string => `${jobName(j.kind)} #${j.id} ${j.state}`;

export const SOURCES_REFUSED = "At least one source must stay on, as scan sources can't switch them all off: turn on another first, or switch off the rules you don't want";

/**
 * `scan sources` with `source` switched, in `all`'s order. Not for the last one on: with no
 * sources the command only shows the list, and it has no way to switch every source off.
 */
export function sourcesToggle(current: readonly string[], source: string, all: readonly string[]): { args: string[] } | { refused: string } {
  const on = new Set(current);
  if (on.has(source)) on.delete(source);
  else on.add(source);
  const next = all.filter((s) => on.has(s));
  return next.length ? { args: ["scan", "sources", ...next] } : { refused: SOURCES_REFUSED };
}
