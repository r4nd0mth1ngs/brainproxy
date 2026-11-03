// What closing the window does: the questions it asks first, and what it stops. Kept apart from
// the shell so the order is testable: nothing is stopped until every question is answered yes.

export interface QuitSteps {
  /** A temporary project, deleted on quit once the user agrees. */
  temp: boolean;
  /** Whether Replay has sends in flight. */
  sending: () => boolean;
  /** Keeps the window open while a question is showing. */
  preventDefault: () => void;
  /** "Stop the sends still running?"; true to go on. */
  askSends: () => Promise<boolean>;
  /** "Discard this temporary engagement?"; true to go on. */
  askDiscard: () => Promise<boolean>;
  /** Cancels every send in flight and waits for it. */
  stopSends: () => Promise<void>;
  /** Discards the temporary project, or stops the proxy the app started. */
  leave: () => Promise<void>;
  destroy: () => Promise<void>;
}

/**
 * Handles a close request. Without anything to ask, it only runs `leave` and the window closes
 * by itself. Otherwise the window is held open, every question is asked, and only once all are
 * answered yes are the sends stopped (destroying the window doesn't unmount the app, so its
 * cleanup can't stop them), the project left and the window destroyed.
 */
export async function onCloseRequested(s: QuitSteps): Promise<void> {
  const sending = s.sending();
  if (!s.temp && !sending) return s.leave();
  s.preventDefault();
  if (sending && !(await s.askSends())) return;
  if (s.temp && !(await s.askDiscard())) return;
  await s.stopSends();
  await s.leave();
  await s.destroy();
}
