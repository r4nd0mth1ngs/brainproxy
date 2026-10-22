// Overview card: the ZAP rule data, brainproxy's checks feed and the Nuclei templates, whether
// they're downloaded, and a one-click download. They live in the user's data folder (not the
// project), so one download serves every project. With the daily update check on, the feed
// (signed, small) also updates itself once a day.

import { useEffect, useRef, useState } from "react";
import { run } from "../api";
import { useApp } from "../store";
import { usePoll } from "../ui/usePoll";
import { autoCheck } from "./AppUpdate";
import { describeUpdate, FEED_UPDATE, updateDue, type FeedStatus, type FeedUpdate } from "./feed";
import type { Job } from "./Scanner";

interface DataStatus {
  embedded_commit: string;
  manifest: { commit: string; updated_unix: number } | null;
}

export interface ChecksStatus {
  nuclei: { commit: string; updated_unix: number; stored: number; templates: number } | null;
  brainproxy?: FeedStatus;
}

const FEED_LAST = "feed-update-last";

function feedLast(): number | null {
  try {
    const v = Number(localStorage.getItem(FEED_LAST));
    return v > 0 ? v : null;
  } catch {
    return null;
  }
}

function setFeedLast(at: number) {
  try {
    localStorage.setItem(FEED_LAST, String(at));
  } catch {
    // Private mode or blocked storage: the check runs again next time.
  }
}

const date = (unix: number) => new Date(unix * 1000).toLocaleDateString(undefined, { day: "numeric", month: "short", year: "numeric" });

export function UpdatesCard() {
  const app = useApp();
  const [data, refreshData] = usePoll<DataStatus>(() => run(["scan", "data", "status"]), 60000);
  const [checks, refreshChecks] = usePoll<ChecksStatus>(() => run(["checks", "status"]), 60000);
  const [busy, setBusy] = useState<"" | "data" | "nuclei" | "feed">("");
  const [nucleiJob, setNucleiJob] = useState<number | null>(null);
  // The feed update job, and whether someone clicked for it (the daily one only speaks up on news).
  const [feedJob, setFeedJob] = useState<{ id: number; manual: boolean } | null>(null);
  const autoStarted = useRef(false);

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

  const [fjob] = usePoll<Job>(() => run(["job", "status", String(feedJob?.id)]), 1500, feedJob != null);
  useEffect(() => {
    if (feedJob == null || !fjob || fjob.id !== feedJob.id || ["queued", "running", "stopping"].includes(fjob.state)) return;
    setFeedJob(null);
    setBusy("");
    refreshChecks();
    const u = fjob.result as FeedUpdate | undefined;
    if (fjob.state === "completed" && u) {
      if (feedJob.manual || !u.unchanged) app.toast(describeUpdate(u));
    } else if (feedJob.manual || fjob.state === "failed") {
      app.toast(`brainproxy checks update ${fjob.state}${fjob.error ? `: ${fjob.error}` : ""}`, "error");
    }
  }, [fjob, feedJob, app, refreshChecks]);

  const updateFeed = async (manual: boolean) => {
    setBusy("feed");
    try {
      const d = await run<{ job: number }>([...FEED_UPDATE, "--background"]);
      setFeedJob({ id: d.job, manual });
    } catch (e: any) {
      if (manual) app.toast(e.message, "error");
      setBusy("");
    }
  };

  // The daily update check covers the feed: at most once a day, in the background.
  const feed = checks?.brainproxy;
  useEffect(() => {
    if (!feed || autoStarted.current || busy !== "" || !autoCheck() || feed.trusted_keys === 0) return;
    if (!updateDue(feedLast(), Date.now())) return;
    autoStarted.current = true;
    setFeedLast(Date.now());
    updateFeed(false);
  }, [feed, busy]);

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
  const installed = feed?.installed;
  const missing = !data.manifest || !checks.nuclei || (!installed && !!feed?.trusted_keys);
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
        {feed && (
          <div className="upd-row">
            <div className="upd-text">
              <b>brainproxy checks</b>
              <span className="muted">
                brainproxy's own checks for new vulnerabilities, signed by the brainproxy maintainers so new detections
                arrive without reinstalling. Guided scans and the passive scanner use them once they're here.
              </span>
              <span className={installed ? "upd-ok" : "upd-warn"}>
                {feed.trusted_keys === 0
                  ? "This version has no signing key for the feed yet; it arrives with a later release"
                  : installed
                    ? `${installed.checks} checks (${installed.passive} passive), downloaded ${date(installed.updated_unix)}${installed.commit ? ` (${installed.commit.slice(0, 7)})` : ""}`
                    : "Not installed"}
              </span>
            </div>
            <button
              className={`btn ${installed ? "" : "primary"}`}
              disabled={busy !== "" || feed.trusted_keys === 0}
              onClick={() => updateFeed(true)}
            >
              {busy === "feed" ? "Downloading…" : installed ? "Update" : "Download"}
            </button>
          </div>
        )}
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
        Downloads come from GitHub (zaproxy/zap-extensions, r4nd0mth1ngs/brainproxy, projectdiscovery/nuclei-templates)
        and are checked before use.
        They're stored once for your user and shared by all projects.
      </p>
    </section>
  );
}
