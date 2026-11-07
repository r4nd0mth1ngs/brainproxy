// The report builder: who it is for, which sections, the branding, the format, with a live
// preview of the HTML; saved layouts are report profiles in the project.

import { useEffect, useRef, useState } from "react";
import { run } from "../api";
import { useApp } from "../store";
import { useDialogFocus } from "../ui/dialogFocus";
import {
  DEFAULT_SPEC,
  FORMATS,
  PRESET_SECTIONS,
  PRESETS,
  previewCommand,
  profileSaveCommand,
  reportCommand,
  SECTIONS,
  specFromProfile,
  specProblem,
  toggleSection,
  type Preset,
  type ReportSpec,
} from "./reportSpec";

interface Profile {
  name: string;
  layout: { preset?: Preset; sections?: string[]; company?: string; accent?: string; since?: string };
}

export function ReportBuilder({ name, onClose }: { name: string; onClose: () => void }) {
  const app = useApp();
  const [spec, setSpec] = useState<ReportSpec>({ ...DEFAULT_SPEC, title: `${name} security report` });
  const [profiles, setProfiles] = useState<Profile[]>([]);
  const [preview, setPreview] = useState("");
  const [previewError, setPreviewError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [profileName, setProfileName] = useState("");
  const dialog = useRef<HTMLDivElement>(null);
  useDialogFocus(dialog);
  const set = (p: Partial<ReportSpec>) => setSpec((s) => ({ ...s, ...p }));
  const problem = specProblem(spec);

  const loadProfiles = () =>
    run<{ profiles: Profile[] }>(["report-profile", "list"]).then(
      (r) => setProfiles(r.profiles),
      () => setProfiles([]),
    );
  useEffect(() => {
    loadProfiles();
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
  }, [spec, problem]);

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
      const r = await run<{ total: number; redacted: number | null }>(reportCommand(spec, file));
      const masked = r.redacted ? ` Session secrets are masked in ${r.redacted} place${r.redacted === 1 ? "" : "s"}.` : "";
      app.toast(`${fmt.label} report saved with ${r.total} finding${r.total === 1 ? "" : "s"}.${masked}`);
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

  const tick = (id: string) => set({ sections: toggleSection(spec.sections, id) });

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
          {spec.format === "pdf" && <p className="muted small">PDF is printed by Chromium, which must be installed.</p>}
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
