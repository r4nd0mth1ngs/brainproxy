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

// ---------------- Adding, testing and removing ----------------

/** A script check, as `scan script list` lists it. */
export interface ScriptCheck {
  name: string;
  file: string;
  /** The file's sha256 when it was named; it runs only while the file still has it. */
  sha256: string;
  /** Who named it: gui, cli or mcp; absent from before brainproxy kept it. */
  origin?: string | null;
  /** Its check id, script:NAME, for `scan enable` and `scan disable`. */
  id: string;
  enabled: boolean;
  /** Why it doesn't run (its file changed or can't be read); absent when it runs. */
  problem?: string;
}

/** A finding a script returned, as `scan script test` shows it. */
export interface TestFinding {
  alert_ref: string;
  name: string;
  risk: string;
  confidence: string;
  param: string;
  evidence: string;
}

/** What `scan script test` answers: nothing is saved and nothing is sent. */
export interface ScriptTest {
  history: number;
  /** The sha256 of the file as it was tested. */
  sha256: string;
  findings: TestFinding[];
  errors: ScriptError[];
}

/** Why `name` can't name a script check, or null; the CLI checks the same. */
export function scriptNameProblem(name: string): string | null {
  if (!name) return "Name it";
  if (name.length > 40 || !/^[A-Za-z0-9_.-]+$/.test(name)) return "Use up to 40 letters, digits, '_', '-' and '.'";
  return null;
}

/** A history id typed in, or null when it isn't one. */
export function historyId(text: string): number | null {
  const t = text.trim().replace(/^#/, "");
  return /^[1-9]\d{0,15}$/.test(t) ? Number(t) : null;
}

/**
 * `scan script add`. `sha256` pins the file to the text that was tested, so a file changed
 * since is refused rather than added unseen.
 */
export const scriptAddArgs = (name: string, file: string, sha256?: string | null) => [
  "scan",
  "script",
  "add",
  ...(sha256 ? [`--sha256=${sha256}`] : []),
  "--",
  name,
  file,
];

export const scriptTestArgs = (file: string, history: number) => ["scan", "script", "test", `--history=${history}`, "--", file];

export const scriptRemoveArgs = (name: string) => ["scan", "script", "remove", "--", name];

export const SCRIPT_LIST_ARGS = ["scan", "script", "list"];

/** The sha256 to pin an add to: the last test's, when it tested this same file. */
export const pinFor = (tested: { file: string; sha256: string } | null, file: string) => (tested && tested.file === file ? tested.sha256 : null);

/** A test's outcome, as a sentence. */
export function testNote(t: ScriptTest): string {
  const found = t.findings.length;
  const what = `History #${t.history}: ${found ? `${found} finding${found === 1 ? "" : "s"}` : "no findings"}`;
  return t.errors.length ? `${what}; the check failed: ${t.errors.map((e) => e.error).join("; ")}` : `${what}.`;
}
