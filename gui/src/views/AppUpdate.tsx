// New brainproxy versions: checked on GitHub once a day when enabled (Settings › Rules & Updates),
// downloaded on request or automatically (checked against the release's sha256), then opened by
// the user. Nothing is installed behind their back.

import { useEffect, useState } from "react";
import { inTauri, run } from "../api";
import { useApp } from "../store";
import { openExternal } from "../ui/Brand";

export interface UpdateInfo {
  current: string;
  latest: string;
  update_available: boolean;
  release: { url: string; published_at: string };
  asset: { name: string; size: number } | null;
  path?: string;
}

const CHECK = "update-check";
const AUTO_DOWNLOAD = "update-download";
const LAST = "update-last";
const SAVED = "update-saved";
const DAY = 24 * 3600 * 1000;

function read(key: string): string | null {
  try {
    return localStorage.getItem(key);
  } catch {
    return null;
  }
}

function write(key: string, value: string) {
  try {
    localStorage.setItem(key, value);
  } catch {
    /* storage unavailable */
  }
}

export const autoCheck = () => read(CHECK) !== "off";
export const autoDownload = () => read(AUTO_DOWNLOAD) === "on";
export const setAutoCheck = (on: boolean) => write(CHECK, on ? "on" : "off");
export const setAutoDownload = (on: boolean) => write(AUTO_DOWNLOAD, on ? "on" : "off");

function json<T>(key: string): T | null {
  try {
    return JSON.parse(read(key) ?? "null");
  } catch {
    return null;
  }
}

/** "0.10.1" > "0.9.3", numeric parts. */
function newer(a: string, b: string) {
  const p = (v: string) => v.replace(/^v/, "").split(/[.+-]/).slice(0, 3).map((x) => parseInt(x, 10) || 0);
  const [x, y] = [p(a), p(b)];
  for (let i = 0; i < 3; i++) if ((x[i] ?? 0) !== (y[i] ?? 0)) return (x[i] ?? 0) > (y[i] ?? 0);
  return false;
}

interface LastCheck {
  at: number;
  info: UpdateInfo;
}

/** Fired with the LastCheck after every check, so views that stay mounted follow along. */
const CHECKED = "update-checked";

export async function checkForUpdate(): Promise<UpdateInfo> {
  const u = await run<UpdateInfo>(["update", "check", "--kind", "gui"]);
  const last: LastCheck = { at: Date.now(), info: u };
  write(LAST, JSON.stringify(last));
  window.dispatchEvent(new CustomEvent(CHECKED, { detail: last }));
  return u;
}

function useLastCheck() {
  const [last, setLast] = useState(() => json<LastCheck>(LAST));
  useEffect(() => {
    const on = (e: Event) => setLast((e as CustomEvent<LastCheck>).detail);
    window.addEventListener(CHECKED, on);
    return () => window.removeEventListener(CHECKED, on);
  }, []);
  return last;
}

/** The app's own version; in a plain browser, the CLI's from the last check. */
function useRunningVersion(info: UpdateInfo | null | undefined) {
  const [app, setApp] = useState("");
  useEffect(() => {
    if (!inTauri) return;
    import("@tauri-apps/api/app")
      .then((m) => m.getVersion())
      .then(setApp)
      .catch(() => {});
  }, []);
  return app || info?.current || "";
}

/** Saves the installer to the Downloads folder; returns its path. */
export async function downloadUpdate(): Promise<string> {
  const dir = inTauri ? ["--dir", await (await import("@tauri-apps/api/path")).downloadDir()] : [];
  const d = await run<UpdateInfo>(["update", "download", "--kind", "gui", ...dir]);
  write(SAVED, JSON.stringify({ version: d.latest, path: d.path }));
  return d.path!;
}

async function openInstaller(path: string) {
  const { openPath } = await import("@tauri-apps/plugin-opener");
  await openPath(path);
}

async function showInFolder(path: string) {
  const { revealItemInDir } = await import("@tauri-apps/plugin-opener");
  await revealItemInDir(path);
}

/** Overview card, shown only while a newer version exists. */
export function AppUpdateCard() {
  const app = useApp();
  const info = useLastCheck()?.info ?? null;
  const running = useRunningVersion(info);
  const [saved, setSaved] = useState(() => json<{ version: string; path: string }>(SAVED));
  const [busy, setBusy] = useState(false);

  const download = async () => {
    setBusy(true);
    try {
      const path = await downloadUpdate();
      setSaved(json(SAVED));
      app.toast(`brainproxy update saved to ${path}`);
    } catch (e: any) {
      app.toast(`Update download failed: ${e.message}`, "error");
    }
    setBusy(false);
  };

  useEffect(() => {
    const last = json<{ at: number }>(LAST);
    if (!autoCheck() || (last && Date.now() - last.at < DAY)) return;
    checkForUpdate()
      .then((u) => {
        if (!u.update_available) return;
        app.toast(`brainproxy ${u.latest} is available.`);
        if (autoDownload() && json<{ version: string }>(SAVED)?.version !== u.latest) download();
      })
      .catch(() => {}); // offline or rate-limited: try again next time
  }, []);

  if (!info || !running || !newer(info.latest, running)) return null;
  const ready = saved?.version === info.latest ? saved.path : "";
  return (
    <section className="dash-card updates attention">
      <header>
        <div>
          <div className="wiz-kicker">Update</div>
          <h2>brainproxy {info.latest} is available</h2>
        </div>
      </header>
      <p className="muted">
        You have {running}.{" "}
        {ready
          ? `The installer is in ${ready}. Close brainproxy before installing.`
          : `The download (${info.asset ? `${(info.asset.size / 1048576).toFixed(0)} MB, ` : ""}checked against its published sha256) goes to your Downloads folder.`}
      </p>
      <div className="row gap">
        {ready ? (
          <>
            <button className="btn primary" onClick={() => openInstaller(ready).catch((e) => app.toast(String(e), "error"))}>
              Open installer
            </button>
            <button className="btn" onClick={() => showInFolder(ready).catch((e) => app.toast(String(e), "error"))}>
              Show in folder
            </button>
          </>
        ) : (
          <button className="btn primary" disabled={busy || !info.asset} onClick={download}>
            {busy ? "Downloading…" : "Download"}
          </button>
        )}
        <button className="btn" onClick={() => openExternal(info.release.url)}>
          What's new
        </button>
      </div>
    </section>
  );
}

/** Settings › Rules & Updates: the automatic check and download, and a manual check. */
export function AppUpdateSettings() {
  const app = useApp();
  const [check, setCheck] = useState(autoCheck);
  const [dl, setDl] = useState(autoDownload);
  const [busy, setBusy] = useState(false);
  const last = useLastCheck();
  const running = useRunningVersion(last?.info);
  const available = !!last?.info && !!running && newer(last.info.latest, running);
  const checkNow = async () => {
    setBusy(true);
    try {
      const u = await checkForUpdate();
      const v = running || u.current;
      app.toast(newer(u.latest, v) ? `brainproxy ${u.latest} is available: see the Overview.` : `brainproxy ${v} is the latest version.`);
    } catch (e: any) {
      app.toast(`Update check failed: ${e.message}`, "error");
    }
    setBusy(false);
  };
  return (
    <>
      <div className="detail-head set-section">
        <h2>App updates</h2>
      </div>
      <p className="muted small">New versions come from GitHub releases and are checked against their published sha256. Nothing is installed for you.</p>
      <div className="set-checks">
        <label className="check">
          <input
            type="checkbox"
            checked={check}
            onChange={(e) => {
              setCheck(e.target.checked);
              setAutoCheck(e.target.checked);
            }}
          />
          Check for a new version once a day
        </label>
        <label className={`check${check ? "" : " off"}`}>
          <input
            type="checkbox"
            checked={dl}
            disabled={!check}
            onChange={(e) => {
              setDl(e.target.checked);
              setAutoDownload(e.target.checked);
            }}
          />
          Download it automatically to your Downloads folder
        </label>
      </div>
      <div className="toolbar flat">
        <button className="btn" disabled={busy} onClick={checkNow}>
          {busy ? "Checking…" : "Check now"}
        </button>
        {last && (
          <span className="muted small">
            Last checked {new Date(last.at).toLocaleString()}
            {available ? ` · ${last.info.latest} available` : " · up to date"}
          </span>
        )}
      </div>
    </>
  );
}
