// Deleting a project from the welcome screen's Recent list (desktop app only): the shell stops
// what runs for it and deletes its file and what the CLI keeps beside it (`delete.rs`); this
// side then forgets what the app kept about it.

import type { ProjectDeleted } from "../api";

/** The app's own storage keys for a project's state: saved Traffic filters, the guided scan's, Import API's job. */
export function isProjectKey(key: string, project: string): boolean {
  if (!key.endsWith(`:${project}`)) return false;
  const kind = key.slice(0, key.length - project.length - 1);
  return kind === "traffic-filters" || kind === "api-import-job" || /^wizard-[a-z]+$/.test(kind);
}

/** Removes what this app keeps about the project in `storage` (the Recent list is the caller's). */
export function forgetProject(storage: Pick<Storage, "length" | "key" | "removeItem">, project: string): void {
  const keys: string[] = [];
  for (let i = 0; i < storage.length; i++) {
    const k = storage.key(i);
    if (k != null && isProjectKey(k, project)) keys.push(k);
  }
  for (const k of keys) storage.removeItem(k);
}

/** The file name a path ends in, for either separator. */
export const baseName = (path: string) => path.split(/[\\/]/).pop() || path;

/** What to tell the user after `deleteProject` (text "" when everything went), and whether something went wrong. */
export function deletedNotice(project: string, d: ProjectDeleted): { text: string; problem: boolean } {
  const name = baseName(project);
  if (d.state === "gone") return { text: `${name} was no longer there, so it was only taken off Recent.`, problem: false };
  if (d.state === "not_stopped") return { text: `${name} wasn't deleted: ${d.error}`, problem: true };
  const left = d.left;
  if (left.length === 0) return { text: "", problem: false };
  const first = left[0];
  const more = left.length > 1 ? ` and ${left.length - 1} more` : "";
  return {
    text: `${name} was deleted, but ${first.path}${more} couldn't be (${first.error}). Delete ${left.length > 1 ? "them" : "it"} by hand.`,
    problem: true,
  };
}
