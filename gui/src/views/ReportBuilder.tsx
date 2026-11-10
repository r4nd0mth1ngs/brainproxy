// The report builder: who it is for, which sections, the branding, the format, which findings
// and how secrets are shown, with a live preview of the HTML; saved layouts are report profiles
// in the project. The executive summary at the top of reports is written and reviewed here too.

import { useEffect, useRef, useState } from "react";
import { run } from "../api";
import { useApp } from "../store";
import { confirm } from "../ui/Confirm";
import { useDialogFocus } from "../ui/dialogFocus";
import { narrativeCredit } from "./findingsFilter";
import {
  CONFIDENCES,
  DEFAULT_SPEC,
  FORMATS,
  PRESET_SECTIONS,
  PRESETS,
  previewCommand,
  profileSaveCommand,
  REPORT_SOURCES,
  REPORT_STATES,
  reportCommand,
  type ReportFilter,
  type ReportWritten,
  RISKS,
  savedNote,
  SECTIONS,
  specFromProfile,
  specProblem,
  type Summary,
  summaryCommand,
  summaryReviewCommand,
  toggleSection,
  type Preset,
  type ReportSpec,
} from "./reportSpec";

interface Profile {
  name: string;
  layout: { preset?: Preset; sections?: string[]; company?: string; accent?: string; since?: string };
}

/** `hosts`: the hosts findings were raised on, offered for the host filter. */
export function ReportBuilder({ name, hosts = [], onClose }: { name: string; hosts?: string[]; onClose: () => void }) {
  const app = useApp();
  const [spec, setSpec] = useState<ReportSpec>({ ...DEFAULT_SPEC, title: `${name} security report` });
  const [profiles, setProfiles] = useState<Profile[]>([]);
  const [preview, setPreview] = useState("");
  const [previewError, setPreviewError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [profileName, setProfileName] = useState("");
  const [summary, setSummary] = useState<Summary | null>(null);
  const [summaryDraft, setSummaryDraft] = useState("");
  // Bumped when the summary changes, so the preview shows it.
  const [previewRun, setPreviewRun] = useState(0);
  const dialog = useRef<HTMLDivElement>(null);
  useDialogFocus(dialog);
  const set = (p: Partial<ReportSpec>) => setSpec((s) => ({ ...s, ...p }));
  const setFilter = (p: Partial<ReportFilter>) => setSpec((s) => ({ ...s, filter: { ...s.filter, ...p } }));
  const problem = specProblem(spec);

  const loadProfiles = () =>
    run<{ profiles: Profile[] }>(["report-profile", "list"]).then(
      (r) => setProfiles(r.profiles),
      () => setProfiles([]),
    );
  const loadSummary = () =>
    run<{ summary: Summary | null }>(["report-summary", "show"]).then(
      (r) => {
        setSummary(r.summary);
        setSummaryDraft(r.summary?.text ?? "");
      },
      (e) => app.toast(e.message, "error"),
    );
  useEffect(() => {
    loadProfiles();
    loadSummary();
  }, []);

  // The preview follows the choices, a moment after the last change.
  useEffect(() => {
    if (problem) return;
    let live = true;
    const t = setTimeout(() => {
      run<{ content: string }>(previewCommand(spec)).then(
        (r) => {
          if (!live) return;
          setPreview(r.content);
          setPreviewError(null);
        },
        (e) => live && setPreviewError(e.message),
      );
    }, 400);
    return () => {
      live = false;
      clearTimeout(t);
    };
  }, [spec, problem, previewRun]);

  const pickLogo = async () => {
    const dialogs = await import("@tauri-apps/plugin-dialog");
    const path = await dialogs.open({ multiple: false, filters: [{ name: "Image", extensions: ["png", "jpg", "jpeg", "gif", "webp"] }] });
    if (typeof path === "string") set({ logo: path });
  };

  const save = async () => {
    if (problem) return;
    const fmt = FORMATS.find((f) => f.id === spec.format)!;
    const dialogs = await import("@tauri-apps/plugin-dialog");
    const path = await dialogs.save({ defaultPath: `${name}-report.${fmt.ext}`, filters: [{ name: fmt.label, extensions: [fmt.ext] }] });
    if (typeof path !== "string") return;
    const file = path.toLowerCase().endsWith(`.${fmt.ext}`) ? path : `${path}.${fmt.ext}`;
    setBusy(true);
    try {
      const r = await run<ReportWritten>(reportCommand(spec, file));
      app.toast(savedNote(fmt.label, r, spec.keepSecrets));
      const { revealItemInDir } = await import("@tauri-apps/plugin-opener");
      await revealItemInDir(file).catch(() => {});
      onClose();
    } catch (e: any) {
      app.toast(e.message, "error");
    } finally {
      setBusy(false);
    }
  };

  const saveProfile = async () => {
    if (!profileName.trim() || problem) return;
    try {
      await run(profileSaveCommand(profileName, spec));
      app.toast(`Saved the layout as "${profileName.trim()}".`);
      set({ profile: profileName.trim(), logo: null });
      setProfileName("");
      loadProfiles();
    } catch (e: any) {
      app.toast(e.message, "error");
    }
  };

  // A saved layout may be someone's branding: removing one asks first.
  const removeProfile = async () => {
    const p = spec.profile;
    if (!p || !(await confirm("Delete saved layout?", `The layout "${p}" is removed from this project. Reports already written keep their look.`, "Delete", "Keep"))) return;
    try {
      await run(["report-profile", "remove", p]);
      app.toast(`Deleted the layout "${p}".`);
      setSpec((s) => (s.profile === p ? { ...s, profile: null } : s));
      loadProfiles();
    } catch (e: any) {
      app.toast(e.message, "error");
    }
  };

  // Secrets are masked unless the person says otherwise, knowing who may read the report.
  const keepSecrets = async (on: boolean) => {
    if (
      on &&
      !(await confirm(
        "Quote secrets as recorded?",
        "Session cookies, credentials, API keys and tokens go into the report as they were recorded, in its evidence, URLs and bodies. Anyone who reads the report can use them.",
        "Quote them",
        "Keep them masked",
      ))
    )
      return;
    set({ keepSecrets: on });
  };

  // The summary on screen is what a review approves: one changed since (by an agent, say) is refused.
  const saveSummary = async (review: boolean) => {
    try {
      await run(review ? summaryReviewCommand(summary?.hash ?? "") : summaryCommand(summaryDraft));
      if (review) app.toast("Summary reviewed: reports print it.");
    } catch (e: any) {
      app.toast(e.message, "error");
    }
    await loadSummary();
    setPreviewRun((n) => n + 1);
  };

  const tick = (id: string) => set({ sections: toggleSection(spec.sections, id) });
  const fmt = FORMATS.find((f) => f.id === spec.format)!;

  return (
    <div className="confirm-backdrop" onKeyDown={(e) => e.key === "Escape" && !busy && onClose()}>
      <div ref={dialog} className="confirm-dialog report-dialog" role="dialog" aria-modal="true" aria-labelledby="report-title">
        <div className="report-form">
          <h2 id="report-title">Report</h2>
          <label>
            <span className="label">Saved layout</span>
            <select
              className="input"
              value={spec.profile ?? ""}
              onChange={(e) => {
                const p = profiles.find((x) => x.name === e.target.value);
                setSpec(p ? specFromProfile(p.name, p.layout, spec) : { ...spec, profile: null });
              }}
            >
              <option value="">None</option>
              {profiles.map((p) => (
                <option key={p.name} value={p.name}>
                  {p.name}
                </option>
              ))}
            </select>
          </label>
          {spec.profile && (
            <button className="btn small" onClick={removeProfile} title="Remove this saved layout from the project">
              Delete layout…
            </button>
          )}
          <label>
            <span className="label">For</span>
            <select className="input" value={spec.preset} onChange={(e) => set({ preset: e.target.value as Preset, sections: PRESET_SECTIONS[e.target.value as Preset] })}>
              {PRESETS.map((p) => (
                <option key={p.id} value={p.id} title={p.title}>
                  {p.label}
                </option>
              ))}
            </select>
          </label>
          <p className="muted small">{PRESETS.find((p) => p.id === spec.preset)!.title}.</p>
          <div role="group" aria-labelledby="report-sections">
            <span className="label" id="report-sections">
              Sections
            </span>
            {SECTIONS.map((s) => (
              <label key={s.id} className="check">
                <input type="checkbox" checked={spec.sections.includes(s.id)} onChange={() => tick(s.id)} /> {s.label}
              </label>
            ))}
          </div>
          {spec.sections.includes("retest") && (
            <label>
              <span className="label">Changes since</span>
              <input className="input" type="date" value={spec.since} onChange={(e) => set({ since: e.target.value })} />
            </label>
          )}
          <label>
            <span className="label">Title</span>
            <input className="input" value={spec.title} onChange={(e) => set({ title: e.target.value })} />
          </label>
          <label>
            <span className="label">From (company)</span>
            <input className="input" value={spec.company} placeholder="Shown on the cover" onChange={(e) => set({ company: e.target.value })} />
          </label>
          <div className="row gap">
            <label>
              <span className="label">Colour</span>
              <input className="input report-colour" type="color" value={spec.accent || "#7a3cff"} onChange={(e) => set({ accent: e.target.value })} />
            </label>
            {spec.accent && (
              <button className="btn small" onClick={() => set({ accent: "" })}>
                No colour
              </button>
            )}
            <button className="btn small" onClick={pickLogo} title="A PNG, JPEG, GIF or WebP image, at most 256 KiB">
              {spec.logo ? "Change logo…" : "Logo…"}
            </button>
            {(spec.logo || (spec.profile && spec.logo === null)) && (
              <button className="btn small" onClick={() => set({ logo: spec.profile ? "" : null })} title="No logo on this report">
                No logo
              </button>
            )}
          </div>
          <label>
            <span className="label">Format</span>
            <select className="input" value={spec.format} onChange={(e) => set({ format: e.target.value as ReportSpec["format"] })}>
              {FORMATS.map((f) => (
                <option key={f.id} value={f.id}>
                  {f.label}
                </option>
              ))}
            </select>
          </label>
          {fmt.note && <p className="muted small">{fmt.note}</p>}
          {fmt.listing && <p className="muted small">Sections and branding don't change this format; the preview shows the HTML report.</p>}
          <h3>Findings</h3>
          <label>
            <span className="label">Triage state</span>
            <select className="input" value={spec.filter.state} onChange={(e) => setFilter({ state: e.target.value })}>
              {REPORT_STATES.map((s) => (
                <option key={s.id} value={s.id}>
                  {s.label}
                </option>
              ))}
            </select>
          </label>
          <div className="row gap">
            <label>
              <span className="label">Risk at least</span>
              <select className="input" value={spec.filter.risk} onChange={(e) => setFilter({ risk: e.target.value as ReportFilter["risk"] })}>
                <option value="">Any</option>
                {RISKS.map((r) => (
                  <option key={r} value={r}>
                    {r}
                  </option>
                ))}
              </select>
            </label>
            <label>
              <span className="label">Confidence at least</span>
              <select className="input" value={spec.filter.confidence} onChange={(e) => setFilter({ confidence: e.target.value as ReportFilter["confidence"] })}>
                <option value="">Any</option>
                {CONFIDENCES.map((c) => (
                  <option key={c} value={c}>
                    {c}
                  </option>
                ))}
              </select>
            </label>
          </div>
          <label>
            <span className="label">Source</span>
            <select className="input" value={spec.filter.source} onChange={(e) => setFilter({ source: e.target.value as ReportFilter["source"] })}>
              {REPORT_SOURCES.map((s) => (
                <option key={s.id} value={s.id}>
                  {s.label}
                </option>
              ))}
            </select>
          </label>
          <label>
            <span className="label">Host</span>
            <input className="input" list="report-hosts" value={spec.filter.host} placeholder="Every host" onChange={(e) => setFilter({ host: e.target.value })} />
            <datalist id="report-hosts">
              {hosts.map((h) => (
                <option key={h} value={h} />
              ))}
            </datalist>
          </label>
          <h3>Secrets</h3>
          <label className="check" title="Session cookies, credentials and tokens as recorded; by default they're shown as [redacted]">
            <input type="checkbox" checked={spec.keepSecrets} onChange={(e) => keepSecrets(e.target.checked)} /> Quote secrets as recorded
          </label>
          {!spec.keepSecrets && (
            <label>
              <span className="label">Also mask</span>
              <textarea
                className="input"
                rows={2}
                value={spec.mask}
                placeholder="One value per line, at least 6 characters: a token in a note, say"
                onChange={(e) => set({ mask: e.target.value })}
              />
            </label>
          )}
          <h3>Executive summary</h3>
          <textarea
            className="input note-input"
            rows={4}
            placeholder="A few lines at the top of reports: what was tested and what it found. An agent can draft it; it's printed once a person reviews it."
            value={summaryDraft}
            onChange={(e) => setSummaryDraft(e.target.value)}
          />
          <div className="toolbar flat">
            <button className="btn small" disabled={summaryDraft.trim() === (summary?.text ?? "")} onClick={() => saveSummary(false)}>
              {summaryDraft.trim() === "" && summary ? "Clear summary" : "Save summary"}
            </button>
            {summary && !summary.reviewed_at && summaryDraft.trim() === summary.text && (
              <button className="btn small" onClick={() => saveSummary(true)} title="You've read it and it's right: reports print it">
                Mark reviewed
              </button>
            )}
          </div>
          {summary && <p className="muted small">{narrativeCredit(summary)}</p>}
          <label className="check" title="Write-ups and the summary nobody has reviewed yet go in, marked as drafts">
            <input type="checkbox" checked={spec.drafts} onChange={(e) => set({ drafts: e.target.checked })} /> Include drafts
          </label>
          {problem && <p className="error">{problem}</p>}
          <div className="row gap">
            <input className="input" placeholder="Layout name" value={profileName} onChange={(e) => setProfileName(e.target.value)} />
            <button className="btn small" disabled={!profileName.trim() || !!problem} onClick={saveProfile} title="Keep these choices to use again">
              Save layout
            </button>
          </div>
          <div className="row gap finding-dialog-actions">
            <button className="btn primary" disabled={busy || !!problem} onClick={save}>
              {busy ? "Saving…" : "Save report…"}
            </button>
            <button className="btn" disabled={busy} onClick={onClose}>
              Cancel
            </button>
          </div>
        </div>
        <div className="report-preview">
          {previewError ? (
            <p className="error">{previewError}</p>
          ) : (
            // No scripts, no same-origin: the report is shown, nothing in it runs.
            <iframe title="Report preview" sandbox="" srcDoc={preview} />
          )}
        </div>
      </div>
    </div>
  );
}
