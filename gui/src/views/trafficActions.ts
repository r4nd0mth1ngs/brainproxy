// Traffic's right-click actions on recorded requests: an active scan of them, the highlight tag,
// and what Access is handed to test them as other users.

/** A recorded request picked in Traffic. */
export interface HistoryPick {
  id: number;
  method: string;
  url: string;
}

const SAFE = ["GET", "HEAD", "OPTIONS"];

/** Methods among the picks other than GET, HEAD and OPTIONS (each once, upper case): replaying them can change data. */
export function unsafeMethods(picks: HistoryPick[]): string[] {
  return [...new Set(picks.map((p) => p.method.toUpperCase()).filter((m) => !SAFE.includes(m)))];
}

/** Settings for a scan started from Traffic: the Scans view's defaults. */
export interface ScanDefaults {
  /** The Nuclei templates are downloaded (`checks status`). */
  nuclei: boolean;
}

/**
 * `scan active` on these history entries, in the background, with the Scans view's defaults:
 * medium strength and, once the Nuclei templates are downloaded, those of high severity and up
 * plus the end-of-life checks. Entries named by id are attacked whatever their method.
 */
export function scanArgs(picks: HistoryPick[], d: ScanDefaults): string[] {
  if (!picks.length) throw new Error("No request picked");
  return [
    "scan",
    "active",
    ...picks.map((p) => `--history-id=${p.id}`),
    "--strength=medium",
    ...(d.nuclei ? ["--checks=nuclei,brainproxy", "--check-include-tags=eol", "--check-severity=high"] : []),
    "--background",
  ];
}

/** The question asked before scanning the picks: what is attacked, and that a POST is replayed too. */
export function scanConfirm(picks: HistoryPick[]): { title: string; message: string; ok: string; cancel: string } {
  const one = picks.length === 1;
  const what = one ? `${picks[0].method.toUpperCase()} ${picks[0].url}` : `${picks.length} requests`;
  const unsafe = unsafeMethods(picks);
  const sideEffects = "that can change data or trigger side effects: one contact form can send a lot of emails.";
  const replay = !unsafe.length
    ? ""
    : one
      ? ` It is replayed even though it is a ${unsafe[0]}, and ${sideEffects}`
      : ` ${unsafe.join(", ")} requests among them are replayed too, and ${sideEffects}`;
  return {
    title: one ? "Scan this request?" : `Scan ${picks.length} requests?`,
    message: `This sends real attack traffic to the site: ${what} ${one ? "is" : "are"} sent again with attack data, often many times.${replay} Every request stays inside the engagement scope.`,
    ok: "Start scan",
    cancel: "Cancel",
  };
}

/** `history tag` adding or removing the highlight. */
export function highlightArgs(id: number, on: boolean): string[] {
  return ["history", "tag", String(id), on ? "--add" : "--remove", "highlight"];
}

/** A row's tags once the highlight is added or removed. */
export function withHighlight(tags: string[], on: boolean): string[] {
  return on ? [...new Set([...tags, "highlight"])] : tags.filter((t) => t !== "highlight");
}
