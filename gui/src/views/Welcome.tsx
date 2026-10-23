// Welcome screen: start a new engagement (project file + write-once scope), a temporary one
// (no file to pick; wiped when it closes), or open an existing project.

import { useEffect, useMemo, useState } from "react";
import { appPid, inTauri, run, setProject } from "../api";
import { Logo } from "../ui/Logo";
import { MadeBy } from "../ui/Brand";

const RECENT = "recent-projects";

export function recent(): string[] {
  try {
    return JSON.parse(localStorage.getItem(RECENT) ?? "[]");
  } catch {
    return [];
  }
}

export function remember(path: string) {
  try {
    localStorage.setItem(RECENT, JSON.stringify([path, ...recent().filter((p) => p !== path)].slice(0, 8)));
  } catch {
    /* storage unavailable */
  }
}

const FILTERS = [{ name: "brainproxy project", extensions: ["bpdb"] }];

/** A file name from an engagement name: "Acme Web (Q4)" -> "acme-web-q4.bpdb". */
function fileName(name: string): string {
  const slug = name.toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-|-$/g, "");
  return `${slug || "engagement"}.bpdb`;
}

function dirOf(path: string): string {
  const i = path.lastIndexOf("/");
  return i > 0 ? path.slice(0, i) : "";
}

/** The CLI resolves a relative path against wherever it was started (the dev server's folder). */
/** On Windows "/foo" is relative to the current drive, so only a drive letter or UNC path counts. */
const isAbsolute = (path: string) =>
  (navigator.userAgent.includes("Windows") ? /^([a-z]:[\\/]|\\\\)/i : /^\//).test(path);
const FULL_PATH = "Use a full path, e.g. /home/you/engagements";

/** Where to save a project named after the engagement; null if the user cancels. */
export async function chooseProjectFile(name: string): Promise<string | null> {
  let p: string | null;
  if (inTauri) {
    const dialog = await import("@tauri-apps/plugin-dialog");
    p = await dialog.save({ filters: FILTERS, defaultPath: fileName(name) });
  } else {
    const dir = dirOf(recent()[0] ?? "");
    p = window.prompt("Save the engagement as (full path):", dir ? `${dir}/${fileName(name)}` : "")?.trim() || null;
    if (p && !isAbsolute(p)) throw new Error(`${FULL_PATH}/${fileName(name)}.`);
  }
  if (typeof p !== "string") return null;
  return p.endsWith(".bpdb") ? p : `${p}.bpdb`;
}

const TARGET = /^(\*\.)?([a-z0-9-]+\.)*[a-z0-9-]+(\/\d{1,3})?(:\d{1,5})?$|^\[[0-9a-f:]+\](:\d{1,5})?$/i;

/** One scope entry from a line: pasted URLs become host[:port]; returns null for blanks. */
export function parseTarget(line: string): { value: string; ok: boolean } | null {
  let t = line.trim();
  if (!t || t.startsWith("#")) return null;
  if (/^[a-z][a-z0-9+.-]*:\/\//i.test(t)) {
    try {
      const u = new URL(t);
      t = u.port ? `${u.hostname}:${u.port}` : u.hostname;
    } catch {
      return { value: t, ok: false };
    }
  }
  t = t.replace(/\/$/, "");
  return { value: t, ok: TARGET.test(t) };
}

export function Welcome({ open, notice }: { open: (path: string) => Promise<void>; notice?: string }) {
  const [mode, setMode] = useState<"home" | "new" | "temp">("home");
  const [error, setError] = useState("");
  const [path, setPath] = useState("");
  // Wipes temporary projects left by a crashed app, and says whether new ones go to RAM.
  const [ramBacked, setRamBacked] = useState<boolean | null>(null);
  useEffect(() => {
    run<{ ram_backed: boolean }>(["project", "sweep"]).then((d) => setRamBacked(d.ram_backed), () => {});
  }, []);
  const tryOpen = (p: string) =>
    isAbsolute(p) ? open(p).catch((e) => setError(String(e.message ?? e))) : setError(`${FULL_PATH}/project.bpdb.`);

  const browse = async () => {
    const dialog = await import("@tauri-apps/plugin-dialog");
    const p = await dialog.open({ filters: FILTERS, multiple: false });
    if (typeof p === "string") tryOpen(p);
  };

  return (
    <div className="picker">
      <div className="picker-madeby">
        <MadeBy />
      </div>
      <div className={`picker-card ${mode !== "home" ? "wide" : ""}`}>
        <div className="picker-brand">
          <Logo size={40} />
          <div>
            <h1>brainproxy</h1>
            <p className="muted">Web security testing workbench</p>
          </div>
        </div>
        {mode !== "home" ? (
          <NewEngagement open={open} cancel={() => setMode("home")} temp={mode === "temp" ? { ramBacked } : null} />
        ) : (
          <>
            <div className="welcome-actions">
              <button className="welcome-action primary" onClick={() => setMode("new")}>
                <span className="welcome-action-title">New engagement</span>
                <span className="welcome-action-sub">Create a project and set the targets you're allowed to test</span>
              </button>
              <button className="welcome-action" onClick={() => setMode("temp")}>
                <span className="welcome-action-title">Temporary engagement</span>
                <span className="welcome-action-sub">
                  No file: {ramBacked == null ? "" : ramBacked ? "kept in memory and " : "kept in the temp folder and "}wiped when you
                  close it
                </span>
              </button>
              {inTauri && (
                <button className="welcome-action" onClick={browse}>
                  <span className="welcome-action-title">Open project…</span>
                  <span className="welcome-action-sub">Continue an existing .bpdb file</span>
                </button>
              )}
            </div>
            {!inTauri && (
              <form
                className="row gap"
                onSubmit={(e) => {
                  e.preventDefault();
                  if (path) tryOpen(path);
                }}
              >
                <input className="input grow" placeholder="Open an existing project: /path/to/engagement.bpdb" value={path} onChange={(e) => setPath(e.target.value)} />
                <button className="btn">Open</button>
              </form>
            )}
            {error && <div className="error">{error}</div>}
            {notice && <div className="error">{notice}</div>}
            {recent().length > 0 && (
              <div className="recent">
                <div className="label">Recent</div>
                {recent().map((p) => (
                  <button key={p} className="recent-item" onClick={() => tryOpen(p)} title={p}>
                    <span>{p.split("/").pop()}</span>
                    <span className="muted">{p}</span>
                  </button>
                ))}
              </div>
            )}
            <p className="muted small">
              A project is one SQLite file holding history, findings, and settings. Requests are only sent to targets in the
              project's engagement scope.
            </p>
          </>
        )}
      </div>
    </div>
  );
}

/** Where a temporary project will live; `ramBacked` is null until the CLI has said. */
type TempPlace = { ramBacked: boolean | null };

function NewEngagement({
  open,
  cancel,
  temp,
}: {
  open: (path: string) => Promise<void>;
  cancel: () => void;
  temp: TempPlace | null;
}) {
  const [name, setName] = useState("");
  const [dir, setDir] = useState(() => dirOf(recent()[0] ?? ""));
  const [file, setFile] = useState<string | null>(null); // set when the user picked a file explicitly
  const [targets, setTargets] = useState("");
  const [excludes, setExcludes] = useState("");
  const [showExcludes, setShowExcludes] = useState(false);
  const [authorized, setAuthorized] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");

  const included = useMemo(() => targets.split("\n").map(parseTarget).filter((t) => t != null), [targets]);
  const excluded = useMemo(() => excludes.split("\n").map(parseTarget).filter((t) => t != null), [excludes]);
  const bad = [...included, ...excluded].filter((t) => !t.ok);
  const valid = included.filter((t) => t.ok).length;
  const projectPath = file ?? (dir ? `${dir.replace(/\/$/, "")}/${fileName(name)}` : "");
  const relative = !!projectPath && !isAbsolute(projectPath);
  const ready = included.length > 0 && bad.length === 0 && (temp ? true : !!projectPath && !relative) && authorized && !busy;

  const chooseLocation = async () => {
    const dialog = await import("@tauri-apps/plugin-dialog");
    const p = await dialog.save({ filters: FILTERS, defaultPath: projectPath || fileName(name) });
    if (typeof p === "string") setFile(p.endsWith(".bpdb") ? p : `${p}.bpdb`);
  };

  const engagementStart = () =>
    run([
      "engagement",
      "start",
      ...(name.trim() ? [`--name=${name.trim()}`] : []),
      ...included.map((t) => `--target=${t.value}`),
      ...excluded.map((t) => `--exclude=${t.value}`),
    ]);

  const createTemp = async () => {
    setBusy(true);
    setError("");
    try {
      // Owned by the app, so a crash leaves nothing behind for long: the next launch sweeps it.
      const pid = await appPid();
      const t = await run<{ path: string }>(["project", "temp", ...(pid ? [`--owner=${pid}`] : [])]);
      setProject(t.path);
      try {
        await engagementStart();
      } catch (e) {
        await run(["project", "discard"]).catch(() => {});
        throw e;
      }
      await open(t.path);
    } catch (e: any) {
      setError(e.message);
      setBusy(false);
    }
  };

  const create = async () => {
    if (temp) return createTemp();
    setBusy(true);
    setError("");
    setProject(projectPath);
    try {
      await engagementStart();
      remember(projectPath);
      await open(projectPath);
    } catch (e: any) {
      setError(
        /already|write-once|locked/i.test(e.message)
          ? `${projectPath} already has an engagement, and its scope can't be changed. Choose another file name, or open that project instead.`
          : e.message,
      );
      setBusy(false);
    }
  };

  return (
    <div className="engage">
      <div className="engage-step">
        <span className="step-n">1</span>
        <div className="grow">
          <label className="label">Engagement name</label>
          <input className="input full" autoFocus placeholder="e.g. Acme customer portal, Q4 retest" value={name} onChange={(e) => setName(e.target.value)} />
        </div>
      </div>

      {temp ? (
        <div className="engage-step">
          <span className="step-n">2</span>
          <div className="grow">
            <label className="label">Storage</label>
            <div className="hint">
              No file to choose.{" "}
              {temp.ramBacked == null
                ? ""
                : temp.ramBacked
                  ? "The project is kept in memory (a RAM-backed folder, not a disk filesystem). "
                  : "The project goes in the system temp folder, on disk, as this OS has no memory-backed folder. "}
              It is wiped when you switch project or close brainproxy. Use Save as… to keep it.
            </div>
          </div>
        </div>
      ) : (
      <div className="engage-step">
        <span className="step-n">2</span>
        <div className="grow">
          <label className="label">Project file</label>
          {inTauri ? (
            <div className="row gap">
              <span className={`mono path ${projectPath ? "" : "muted"}`}>{projectPath || "Choose where to save the project"}</span>
              <button className="btn" onClick={chooseLocation}>
                Choose location…
              </button>
            </div>
          ) : (
            <>
              <input className="input full mono" placeholder="Folder, e.g. /Users/me/engagements" value={dir} onChange={(e) => setDir(e.target.value)} />
              {projectPath && <div className="hint mono">{projectPath}</div>}
            </>
          )}
          {relative && <div className="error">{FULL_PATH} (missing folders are created).</div>}
        </div>
      </div>
      )}

      <div className="engage-step">
        <span className="step-n">3</span>
        <div className="grow">
          <label className="label">Targets in scope</label>
          <textarea
            className="input full multiline mono"
            rows={4}
            spellCheck={false}
            placeholder={"One per line, e.g.\napp.example.com\n*.api.example.com\n10.0.0.0/24:8443\nhttps://shop.example.com/login  (pasted URLs are fine)"}
            value={targets}
            onChange={(e) => setTargets(e.target.value)}
          />
          <div className="chips">
            {included.map((t, i) => (
              <span key={i} className={`chip ${t.ok ? "in" : "bad"}`} title={t.ok ? "In scope" : "Not a valid target"}>
                {t.value}
              </span>
            ))}
          </div>
          <div className="hint">
            Exact host, <span className="mono">*.domain</span> for subdomains, an IP or CIDR range, each with an optional{" "}
            <span className="mono">:port</span>. Everything else is refused, including redirects to other hosts.
          </div>
          {showExcludes ? (
            <>
              <label className="label" style={{ marginTop: 10, display: "block" }}>
                Never contact (exclusions)
              </label>
              <textarea
                className="input full multiline mono"
                rows={2}
                autoFocus
                spellCheck={false}
                placeholder={"e.g. payments.example.com\n10.0.0.1"}
                value={excludes}
                onChange={(e) => setExcludes(e.target.value)}
              />
              <div className="chips">
                {excluded.map((t, i) => (
                  <span key={i} className={`chip ${t.ok ? "out" : "bad"}`}>
                    {t.value}
                  </span>
                ))}
              </div>
            </>
          ) : (
            <button className="link" onClick={() => setShowExcludes(true)}>
              + Add exclusions
            </button>
          )}
        </div>
      </div>

      <div className="engage-confirm">
        <p>
          <strong>The scope is locked when the project is created.</strong> brainproxy will refuse to contact anything outside
          it, and it can't be widened or changed later. A different scope means a new engagement.
        </p>
        <label className="check">
          <input type="checkbox" checked={authorized} onChange={(e) => setAuthorized(e.target.checked)} />I have permission to test
          these targets.
        </label>
      </div>

      {error && <div className="error">{error}</div>}
      {bad.length > 0 && <div className="error">Fix or remove: {bad.map((t) => t.value).join(", ")}</div>}

      <div className="row gap">
        <button className="btn" onClick={cancel} disabled={busy}>
          Back
        </button>
        <span className="grow" />
        <button className="btn primary" disabled={!ready} onClick={create}>
          {busy ? "Creating…" : `Create ${temp ? "temporary " : ""}engagement${valid ? ` · ${valid} target${valid === 1 ? "" : "s"}` : ""}`}
        </button>
      </div>
    </div>
  );
}
