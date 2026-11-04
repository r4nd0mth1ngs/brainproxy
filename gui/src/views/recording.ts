// Changes to what the proxy records: the recording scope and the TLS pass-through list, as
// `scope show` and `proxy status` give them. An agent narrowing either hides traffic (the proxy
// then keeps only a request line, or a tunnel's row), so the app says so until a person changes
// that setting again.

/** One change, as the CLI logs it. */
export interface RecordingChange {
  time: string;
  /** gui, cli or mcp. */
  by: string;
  setting: "scope" | "passthrough";
  /** It left less traffic recorded in full than before. */
  narrowed: boolean;
  /** What changed: "include: added ^a\.test$". */
  summary: string;
}

/** Fired to show Target › Scope, where the changes are listed. */
export const SHOW_SCOPE = "show-scope";

const SETTING: Record<RecordingChange["setting"], string> = {
  scope: "recording scope",
  passthrough: "TLS pass-through list",
};

const BY: Record<string, string> = { mcp: "an agent", gui: "the app", cli: "the command line" };

/** Who made a change, in words. */
export function byText(by: string): string {
  return BY[by] ?? "an unknown origin";
}

/** "TLS pass-through list: added a.test", for a list of changes. */
export function changeText(c: RecordingChange): string {
  return `${SETTING[c.setting] ?? c.setting}: ${c.summary}`;
}

/**
 * The notice for the agents' narrowing changes nobody has changed back since (`narrowed_by_agent`),
 * or null when there are none: "Recording narrowed by an agent at <time>: <what>".
 */
export function narrowedNotice(changes: RecordingChange[] | null | undefined, when = (t: string) => new Date(t).toLocaleString()): string | null {
  const flagged = (changes ?? []).filter((c) => c.by === "mcp" && c.narrowed);
  if (!flagged.length) return null;
  return flagged.map((c) => `Recording narrowed by an agent at ${when(c.time)}: ${changeText(c)}`).join("\n");
}
