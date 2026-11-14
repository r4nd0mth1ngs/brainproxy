// The guided scan's job, as the Overview card follows it. Its id is kept in this app's storage,
// so it outlives a reload, and the project can have changed meanwhile.

/**
 * `job status` for the remembered id: "gone" when the project has no such job, or one that isn't
 * a scan (an id kept from another copy of the project).
 */
export function readWizardJob<J extends { kind: string }>(status: Promise<J>): Promise<J | "gone"> {
  return status.then(
    (j) => (j.kind === "active-scan" ? j : "gone"),
    (e) => {
      if (e?.kind === "not_found") return "gone";
      throw e;
    },
  );
}

const LIVE = ["queued", "running", "stopping"];

/** Whether the card reads the job again: only while the Overview shows and the job can still change. */
export function followsJob(job: { state: string } | "gone" | null, active: boolean): boolean {
  return active && job !== "gone" && (job == null || LIVE.includes(job.state));
}
