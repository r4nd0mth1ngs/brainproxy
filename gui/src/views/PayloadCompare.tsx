// A finding's request sent with and without its payload (`findings verify`), shown as a strip
// (status, length, time and evidence for each, and what differs), with the two responses one
// click away in Diff. Findings runs it on the recorded attack; Replay on the tab's request.

import { MAX_BODY, rawResponse, run, type HistoryEntry } from "../api";
import { useApp } from "../store";
import { confirm } from "../ui/Confirm";
import { diffRows, needsUnsafe, sideCells, unsafeReason, verdictLine, verifyArgs, type Verify } from "./verifyFinding.ts";

type App = ReturnType<typeof useApp>;

/**
 * Runs `findings verify` for finding `id` (`stdin`: an edited attack). A request that may change
 * data is sent only once the user confirms; null when they don't.
 */
export async function verifyFinding(id: number, o: { stdin?: Uint8Array; project?: string } = {}): Promise<Verify | null> {
  const call = (unsafe: boolean) => run<Verify>(verifyArgs(id, { edited: !!o.stdin, unsafe }), { stdin: o.stdin, project: o.project });
  try {
    return await call(false);
  } catch (e: any) {
    if (!needsUnsafe(e.message ?? "")) throw e;
    const ok = await confirm("Send these requests again?", unsafeReason(e.message), "Send them", "Cancel");
    return ok ? call(true) : null;
  }
}

/** Opens the last response of each side in Diff: without the payload as A, with it as B. */
export async function openVerifyDiff(app: App, v: Verify): Promise<void> {
  const rows = diffRows(v);
  if (!rows) return app.toast("Neither request got a response to compare", "error");
  const [a, b] = await Promise.all(rows.map((id) => run<HistoryEntry>(["history", "show", String(id), MAX_BODY])));
  app.setComparer([...app.comparer, rawResponse(a), rawResponse(b)]);
  app.setTab("comparer");
}

export function VerifyStrip({ v, onDiff }: { v: Verify; onDiff: () => void }) {
  const rows: [string, Verify["without"]][] = [
    ["Without payload", v.without],
    ["With payload", v.with],
  ];
  const differs = v.differences.summary.length > 0;
  return (
    <div className="verify-strip">
      <table className="verify-table">
        <thead>
          <tr>
            <th />
            <th>Status</th>
            <th>Length</th>
            <th>Time</th>
            {v.evidence && <th title={`Whether the response holds the finding's evidence: ${v.evidence}`}>Evidence</th>}
            <th>History</th>
          </tr>
        </thead>
        <tbody>
          {rows.map(([label, s]) => {
            const c = sideCells(s);
            return (
              <tr key={label}>
                <th scope="row">{label}</th>
                <td>{c.status}</td>
                <td>{c.length}</td>
                <td>{c.time}</td>
                {v.evidence && <td>{c.evidence}</td>}
                <td className="muted">{s.history_ids.map((h) => `#${h}`).join(", ")}</td>
              </tr>
            );
          })}
        </tbody>
      </table>
      <div className="toolbar flat">
        <span className={differs ? "" : "muted"}>{verdictLine(v)}</span>
        <button className="btn small" onClick={onDiff} title="Open both responses in Diff: without the payload as A, with it as B">
          Diff responses
        </button>
      </div>
      <p className="muted small">
        {v.baseline_from === "history"
          ? `Without the payload: request #${v.without.request_history_id}, the latest in history the attack repeats with only the payload changed (the scan didn't record one).`
          : `Without the payload: request #${v.without.request_history_id}, the one the scan started from.`}
        {v.repeat > 1 ? ` Each sent ${v.repeat} times; lengths and times are medians.` : ""}
      </p>
    </div>
  );
}
