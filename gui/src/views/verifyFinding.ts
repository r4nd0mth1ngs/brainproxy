// A finding's request sent with and without its payload (`findings verify`), for Findings'
// "Compare with/without payload" and Replay's "Compare with baseline": the command line, and
// the result in words for the summary strip.

/** One side of `findings verify`: the request sent, and how its sends went. */
export interface VerifySide {
  request_history_id: number;
  history_ids: number[];
  status: number | null;
  length: number | null;
  duration_ms: number | null;
  /** How many sends showed the finding's evidence; null with no evidence to look for. */
  evidence: number | null;
  answered: number;
  sends: { history_id: number; status: number | null; length: number | null; duration_ms: number | null; evidence: boolean | null; error?: string }[];
}

export interface Verify {
  id: number;
  attack: string;
  evidence: string;
  baseline_from: "scan" | "history";
  edited_request: boolean;
  repeat: number;
  without: VerifySide;
  with: VerifySide;
  differences: {
    status_changed: boolean;
    length_delta: number | null;
    duration_delta_ms: number | null;
    evidence_only_with_payload: boolean | null;
    summary: string[];
  };
}

/** `findings verify`; `edited` sends the request on stdin as the one with the payload. */
export function verifyArgs(id: number, o: { unsafe?: boolean; edited?: boolean; repeat?: number } = {}): string[] {
  return [
    "findings",
    "verify",
    String(id),
    ...(o.repeat && o.repeat > 1 ? ["--repeat", String(o.repeat)] : []),
    ...(o.edited ? ["--request", "-"] : []),
    ...(o.unsafe ? ["--allow-unsafe"] : []),
  ];
}

/** The refusal of a request that may change data, which the user can confirm and send anyway. */
export const needsUnsafe = (message: string): boolean => /--allow-unsafe/.test(message);

/** The refusal's reason without the flag, for the confirmation. */
export const unsafeReason = (message: string): string => `${message.replace(/^invalid input: /, "").replace(/; pass --allow-unsafe.*$/, "")}.`;

/** A side's cells for the strip: status, length, time, evidence. */
export function sideCells(s: VerifySide): { status: string; length: string; time: string; evidence: string } {
  const failed = s.sends.length - s.answered;
  return {
    status: s.status == null ? "no response" : String(s.status) + (failed ? ` (${failed} failed)` : ""),
    length: s.length == null ? "–" : `${s.length} B`,
    time: s.duration_ms == null ? "–" : `${s.duration_ms} ms`,
    evidence: s.evidence == null ? "–" : s.answered > 1 ? `${s.evidence} of ${s.answered}` : s.evidence ? "yes" : "no",
  };
}

/** The result in one line, for a toast or the strip's heading. */
export function verdictLine(v: Verify): string {
  const d = v.differences.summary;
  return d.length ? d.join("; ") : "No difference between the responses with and without the payload";
}

/** The history rows whose responses Diff compares: each side's last send. */
export function diffRows(v: Verify): [number, number] | null {
  const a = v.without.history_ids.at(-1);
  const b = v.with.history_ids.at(-1);
  return a != null && b != null ? [a, b] : null;
}
