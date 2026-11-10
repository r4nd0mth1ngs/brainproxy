// Passive checks written as scripts (`scan script add`), as the Scanner's rule list and the
// passive scan's result show them.

/** A script check that failed on an exchange or didn't run, as `scan passive` reports it. */
export interface ScriptError {
  script: string;
  error: string;
  /** The first history row it failed on; 0 when it couldn't be loaded at all. */
  history_id: number;
  count: number;
}

/** What `scan passive` answers. */
export interface PassiveStats {
  scanned: number;
  new_findings: number;
  script_errors?: ScriptError[];
}

/** One failure, as a sentence. */
export function scriptErrorNote(e: ScriptError): string {
  if (e.history_id === 0) return `Script check ${e.script} didn't run: ${e.error}`;
  const where = e.count === 1 ? `history #${e.history_id}` : `${e.count} exchanges, first history #${e.history_id}`;
  return `Script check ${e.script} failed on ${where}: ${e.error}`;
}

/** What to say after a passive scan: its counts, and as an error any script check that failed. */
export function passiveNote(stats: PassiveStats): { text: string; error: boolean } {
  const text = `Passive scan: ${stats.scanned} captures, ${stats.new_findings} new findings`;
  const errors = stats.script_errors ?? [];
  if (!errors.length) return { text, error: false };
  return { text: `${text}. ${errors.map(scriptErrorNote).join(". ")}`, error: true };
}

/** A passive rule's highest risk for its row; a script check's isn't known before it runs. */
export const maxRiskLabel = (maxRisk: string | null | undefined) => maxRisk ?? "set by the script";
