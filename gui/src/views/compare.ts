// Findings against one scan: what it found first, what it found again, and what it no longer
// finds. `brainproxy findings compare --scan` decides; this only reads its answer.

export type Seen = "new" | "still" | "gone";

export interface ScanJob {
  id: number;
  time: string;
  finished_time: string | null;
  args: string[];
}

export interface ScanCompare {
  new: { id: number | null }[];
  unchanged: { id: number | null }[];
  fixed: { id: number | null }[];
}

/** The command, for findings in any triage state: the view hides false positives itself. */
export function compareArgs(scanId: number): string[] {
  return ["findings", "compare", "--scan", String(scanId), "--state", "all", "--limit", "10000"];
}

/** Each finding's place in the comparison; findings the scan says nothing about are left out. */
export function seenById(c: ScanCompare | null): Map<number, Seen> {
  const seen = new Map<number, Seen>();
  if (!c) return seen;
  for (const [list, s] of [[c.new, "new"], [c.unchanged, "still"], [c.fixed, "gone"]] as const) {
    for (const f of list) if (f.id != null) seen.set(f.id, s);
  }
  return seen;
}
