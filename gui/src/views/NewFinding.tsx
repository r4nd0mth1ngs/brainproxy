// "New finding": writes up an issue found by hand with `findings add`. Opened from Findings, from
// Traffic's right-click menu, and from Replay, prefilled with the URL and history entry.

import { useState, type ReactNode } from "react";
import { run, type Risk } from "../api";
import { findingAddArgs, formFromDraft, formProblem, type FindingDraft, type FindingForm } from "./manualFinding";

const RISKS: Risk[] = ["high", "medium", "low", "info"];
const CONFIDENCES: FindingForm["confidence"][] = ["high", "medium", "low"];

function Field({ label, children, wide }: { label: string; children: ReactNode; wide?: boolean }) {
  return (
    <label className={wide ? "wide" : undefined}>
      <span className="label">{label}</span>
      {children}
    </label>
  );
}

export function NewFinding({ draft, onClose, onAdded }: { draft: FindingDraft; onClose: () => void; onAdded: (id: number, alertRef: string, warnings: string[]) => void }) {
  const [form, setForm] = useState(() => formFromDraft(draft));
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const set = (p: Partial<FindingForm>) => {
    setForm((f) => ({ ...f, ...p }));
    setError(null);
  };
  const problem = formProblem(form);

  const save = async () => {
    if (problem) return setError(problem);
    setBusy(true);
    try {
      const { args, stdin } = findingAddArgs(form);
      const r = await run<{ id: number; finding: { alert_ref: string }; warnings: string[] }>(args, stdin);
      onAdded(r.id, r.finding.alert_ref, r.warnings);
    } catch (e: any) {
      setError(e.message);
    }
    setBusy(false);
  };

  const area = (k: "description" | "solution" | "evidence", placeholder: string, mono = false) => (
    <textarea className={`input area ${mono ? "mono" : ""}`} value={form[k]} placeholder={placeholder} onChange={(e) => set({ [k]: e.target.value })} />
  );

  return (
    <div className="confirm-backdrop" onKeyDown={(e) => e.key === "Escape" && !busy && onClose()}>
      <div className="confirm-dialog finding-dialog" role="dialog" aria-modal="true" aria-labelledby="new-finding-title">
        <h2 id="new-finding-title">New finding</h2>
        <p>An issue you found by hand. It is only recorded in this project: nothing is sent.</p>
        <div className="form">
          <Field label="Title" wide>
            <input className="input" autoFocus value={form.title} placeholder="Another user's order is readable" onChange={(e) => set({ title: e.target.value })} />
          </Field>
          <Field label="Risk">
            <div className="seg">
              {RISKS.map((r) => (
                <button key={r} type="button" className={form.risk === r ? "on" : ""} onClick={() => set({ risk: r })}>
                  <span className={`dot-risk risk-${r}`} /> {r}
                </button>
              ))}
            </div>
          </Field>
          <Field label="Confidence">
            <div className="seg">
              {CONFIDENCES.map((c) => (
                <button key={c} type="button" className={form.confidence === c ? "on" : ""} onClick={() => set({ confidence: c })}>
                  {c}
                </button>
              ))}
            </div>
          </Field>
          <Field label="URL" wide>
            <div className="row gap">
              <input className="input mono" style={{ width: 90 }} value={form.method} disabled={!form.url.trim()} title="Request method" onChange={(e) => set({ method: e.target.value })} />
              <input className="input mono grow" value={form.url} placeholder="https://app.example.com/orders/7 (or leave empty to use the history entry's)" onChange={(e) => set({ url: e.target.value })} />
            </div>
          </Field>
          <Field label="Parameter, header or cookie">
            <input className="input mono" value={form.param} placeholder="id" onChange={(e) => set({ param: e.target.value })} />
          </Field>
          <Field label="CWE">
            <input className="input" value={form.cwe} placeholder="639" onChange={(e) => set({ cwe: e.target.value })} />
          </Field>
          <Field label="History entries (the first is the evidence)">
            <input className="input mono" value={form.history} placeholder="12, 15" onChange={(e) => set({ history: e.target.value })} />
          </Field>
          <Field label="Description" wide>
            {area("description", "What the issue is and why it matters")}
          </Field>
          <Field label="Solution" wide>
            {area("solution", "How to fix it")}
          </Field>
          <Field label="Evidence" wide>
            {area("evidence", "What shows it, such as a line of the response", true)}
          </Field>
        </div>
        {error && <div className="error">{error}</div>}
        <div className="row gap finding-dialog-actions">
          <span className="grow" />
          <button className="btn" disabled={busy} onClick={onClose}>
            Cancel
          </button>
          <button className="btn primary" disabled={busy || !!problem} title={problem ?? undefined} onClick={save}>
            {busy ? "Adding…" : "Add finding"}
          </button>
        </div>
      </div>
    </div>
  );
}
