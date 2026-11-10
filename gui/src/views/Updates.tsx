// Overview card: the ZAP rule data, brainproxy's signed checks, and the Nuclei templates, whether
// they're downloaded, and a one-click download. They live in the user's data folder (not the
// project), so one download serves every project. brainproxy's checks also update once a day
// with the daily version check (Settings › Rules & Updates).

import { useEffect, useRef, useState } from "react";
import { run } from "../api";
import { useApp } from "../store";
import { usePoll } from "../ui/usePoll";
import { autoCheck } from "./AppUpdate";
import type { Job } from "./Scanner";

interface DataStatus {
  embedded_commit: string;
  manifest: { commit: string; updated_unix: number } | null;
}

export interface ChecksStatus {
  nuclei: { commit: string; updated_unix: number; stored: number; templates: number } | null;
  brainproxy?: { commit: string; updated_unix: number; stored: number; signed_by: string } | null;
}

const DAY = 24 * 3600;

const date = (unix: number) => new Date(unix * 1000).toLocaleDateString(undefined, { day: "numeric", month: "short", year: "numeric" });

export function UpdatesCard() {
  const app = useApp();
  const [data, refreshData] = usePoll<DataStatus>(() => run(["scan", "data", "status"]), 60000);
  const [checks, refreshChecks] = usePoll<ChecksStatus>(() => run(["checks", "status"]), 60000);
  const [busy, setBusy] = useState<"" | "data" | "nuclei" | "feed">("");
  const [nucleiJob, setNucleiJob] = useState<number | null>(null);

  // The Nuclei download runs as a job; follow it until it ends.
  const [job] = usePoll<Job>(() => run(["job", "status", String(nucleiJob)]), 1500, nucleiJob != null);
  useEffect(() => {
    if (nucleiJob == null || !job || job.id !== nucleiJob || ["queued", "running", "stopping"].includes(job.state)) return;
    setNucleiJob(null);
    setBusy("");
    refreshChecks();
    if (job.state === "completed") app.toast("Nuclei templates downloaded. Scans can now use them.");
    else app.toast(`Nuclei download ${job.state}${job.error ? `: ${job.error}` : ""}`, "error");
  }, [job, nucleiJob, app, refreshChecks]);

  const updateData = async () => {
    setBusy("data");
    try {
      await run(["scan", "data", "update"]);
      refreshData();
      app.toast("ZAP rule data updated.");
    } catch (e: any) {
      app.toast(e.message, "error");
    }
    setBusy("");
  };

  const updateFeed = async (quiet = false) => {
    setBusy("feed");
    try {
      const m = await run<{ stored: number; changes?: { added: string[]; changed: string[]; removed: string[] } }>([
        "checks",
        "update",
        "--source",
        "brainproxy",
      ]);
      refreshChecks();
      // Say what arrived, also after the quiet daily update.
      const c = m.changes;
      const name = (p: string) => p.split("/").pop()!.replace(/\.ya?ml$/, "");
      const news = c ? [...c.added.map((p) => `new: ${name(p)}`), ...c.changed.map((p) => `updated: ${name(p)}`)] : [];
      if (news.length) app.toast(`brainproxy checks (signature verified): ${news.join(", ")}`);
      else if (!quiet) app.toast(`brainproxy checks are up to date: ${m.stored} checks, signature verified.`);
    } catch (e: any) {
      if (!quiet) app.toast(e.message, "error");
    }
    setBusy("");
  };

  // Once a day with the version check: new CVE checks arrive without a new app version.
  const autoFed = useRef(false);
  useEffect(() => {
    if (!checks || autoFed.current || !autoCheck()) return;
    autoFed.current = true;
    const f = checks.brainproxy;
    if (!f || Date.now() / 1000 - f.updated_unix > DAY) updateFeed(true);
  }, [checks]);

  const updateNuclei = async () => {
    setBusy("nuclei");
    try {
      const d = await run<{ job: number }>(["checks", "update", "--background"]);
      setNucleiJob(d.job);
    } catch (e: any) {
      app.toast(e.message, "error");
      setBusy("");
    }
  };

  if (!data || !checks) return null;
  const missing = !data.manifest || !checks.nuclei || !checks.brainproxy;
  const feed = checks.brainproxy;
  return (
    <section className={`dash-card updates ${missing ? "attention" : ""}`}>
      <header>
        <div>
          <div className="wiz-kicker">{missing ? "Recommended" : "Rules and checks"}</div>
          <h2>{missing ? "Download the latest scan rules and checks" : "Scan rules and checks are installed"}</h2>
        </div>
      </header>
      <div className="upd-rows">
        <div className="upd-row">
          <div className="upd-text">
            <b>ZAP rule data</b>
            <span className="muted">
              The patterns the scanners use to recognise error messages, leaked data, and sensitive files, from OWASP
              ZAP.
            </span>
            <span className={data.manifest ? "upd-ok" : "upd-warn"}>
              {data.manifest
                ? `Downloaded ${date(data.manifest.updated_unix)} (zap-extensions ${data.manifest.commit.slice(0, 7)})`
                : `Using the copy built into this version (${data.embedded_commit.slice(0, 7)}); download for the latest`}
            </span>
          </div>
          <button className={`btn ${data.manifest ? "" : "primary"}`} disabled={busy !== ""} onClick={updateData}>
            {busy === "data" ? "Downloading…" : data.manifest ? "Update" : "Download"}
          </button>
        </div>
        <div className="upd-row">
          <div className="upd-text">
            <b>brainproxy checks</b>
            <span className="muted">
              Checks for new CVEs from the brainproxy project, published between releases and signed. Passive ones look
              at the traffic you record; the others run in scans.
            </span>
            <span className={feed ? "upd-ok" : "upd-warn"}>
              {feed
                ? `${feed.stored} checks, signature verified, updated ${date(feed.updated_unix)}${feed.commit ? ` (${feed.commit.slice(0, 7)})` : ""}`
                : "Not installed"}
            </span>
          </div>
          <button className={`btn ${feed ? "" : "primary"}`} disabled={busy !== ""} onClick={() => updateFeed()}>
            {busy === "feed" ? "Updating…" : feed ? "Update" : "Download"}
          </button>
        </div>
        <div className="upd-row">
          <div className="upd-text">
            <b>Nuclei templates</b>
            <span className="muted">
              About 10,000 community checks for known CVEs, exposed admin panels, default logins, and misconfigurations,
              from ProjectDiscovery. The guided scan uses them once they're here.
            </span>
            <span className={checks.nuclei ? "upd-ok" : "upd-warn"}>
              {checks.nuclei
                ? `${checks.nuclei.stored.toLocaleString()} templates usable, downloaded ${date(checks.nuclei.updated_unix)} (${checks.nuclei.commit.slice(0, 7)})`
                : "Not installed"}
            </span>
          </div>
          <button className={`btn ${checks.nuclei ? "" : "primary"}`} disabled={busy !== ""} onClick={updateNuclei}>
            {busy === "nuclei" ? "Downloading…" : checks.nuclei ? "Update" : "Download"}
          </button>
        </div>
      </div>
      <p className="muted small">
        Downloads come from GitHub (zaproxy/zap-extensions, r4nd0mth1ngs/brainproxy, projectdiscovery/nuclei-templates) and
        are checked before use.
        They're stored once for your user and shared by all projects.
      </p>
    </section>
  );
}
