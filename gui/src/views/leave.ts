// Switch project: Replay's tabs are saved first, and if they can't be, the user is asked whether
// to close anyway. Only one switch runs at a time, and one that finishes after its shell is gone
// (or its project changed) closes nothing.

/** One switch at a time for a shell; `attach` while it is mounted on a project. */
export function leaver() {
  let running: Promise<void> | null = null;
  let attached = false;
  let generation = 0;
  return {
    /**
     * Runs `leave`, or while one runs returns that one (a second click joins it, so it can't
     * close the project after the first was told to keep it open). `stale()` turns true once
     * the shell unmounts or moves to another project.
     */
    run(leave: (stale: () => boolean) => Promise<void>): Promise<void> {
      if (running) return running;
      const mine = generation;
      const stale = () => !attached || generation !== mine;
      const p: Promise<void> = leave(stale).finally(() => {
        if (running === p) running = null;
      });
      running = p;
      return p;
    },
    /** Mounted on a project; the returned cleanup makes switches still running stale. */
    attach(): () => void {
      attached = true;
      generation++;
      return () => {
        attached = false;
        generation++;
        // The next project's first click starts its own switch.
        running = null;
      };
    },
  };
}

/** Saves the tabs (not for a temporary project, which is discarded), asks on failure, closes. */
export async function leaveProject(o: {
  temp: boolean;
  flush: () => Promise<void>;
  /** The tabs couldn't be saved: true to close anyway. */
  ask: (e: Error) => Promise<boolean>;
  close: () => unknown;
  stale: () => boolean;
}): Promise<void> {
  if (!o.temp) {
    const failed = await o.flush().then(
      () => null,
      (e: Error) => e,
    );
    if (o.stale()) return;
    if (failed && (!(await o.ask(failed)) || o.stale())) return;
  }
  // Awaited, so a click while a temporary project's discard question is open joins it.
  await o.close();
}
