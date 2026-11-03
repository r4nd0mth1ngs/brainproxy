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

/**
 * Asks whether to stop Replay's sends still running; saves the tabs, or for a temporary project
 * (which isn't saved) asks whether to discard it;
 * asks whether to close anyway if the save fails; closes. Every question is asked here, and
 * after each wait a switch whose shell or project has gone closes nothing, so `close` itself
 * never asks anything.
 */
export async function leaveProject(o: {
  temp: boolean;
  /** Replay sends still running, which closing stops: true to go on (or nothing running). */
  sends: () => Promise<boolean>;
  flush: () => Promise<void>;
  /** The tabs couldn't be saved: true to close anyway. */
  ask: (e: Error) => Promise<boolean>;
  /** A temporary project is about to be deleted: true to discard it. */
  discard: () => Promise<boolean>;
  close: () => unknown;
  stale: () => boolean;
}): Promise<void> {
  if (!(await o.sends()) || o.stale()) return;
  if (o.temp) {
    if (!(await o.discard()) || o.stale()) return;
  } else {
    const failed = await o.flush().then(
      () => null,
      (e: Error) => e,
    );
    if (o.stale()) return;
    if (failed && (!(await o.ask(failed)) || o.stale())) return;
  }
  await o.close();
}
