// Settings › Rules & Updates › Checks and feed tools: check template files (`checks validate`),
// and look after a feed folder like the one `checks update --source brainproxy` downloads
// (`checks feed verify`, `keygen`, `sign`). The arguments and what the results say.

/**
 * Why a feed signed here doesn't verify: the keys a build trusts are compiled in. Signing is for
 * the maintainers' key and for trying the format out.
 */
export const OWN_KEY_NOTE =
  "A feed signed with a key made here won't verify, on this build or a release build: the keys brainproxy trusts are compiled in (TRUSTED_KEYS in crates/core/src/checks/feed.rs). Verify checks a folder against those keys.";

/** Most files `checks validate` lists. */
export const VALIDATE_LIMIT = 500;

// `--` before the paths: a path starting with `-` isn't read as a flag.
export const validateArgs = (paths: string[]) => ["checks", "validate", `--limit=${VALIDATE_LIMIT}`, "--", ...paths];
export const verifyArgs = (dir: string) => ["checks", "feed", "verify", "--", dir];
export const keygenArgs = (out: string) => ["checks", "feed", "keygen", `--out=${out}`];
export const signArgs = (dir: string, key: string) => ["checks", "feed", "sign", `--key=${key}`, "--", dir];

export interface ValidatedFile {
  file: string;
  id: string;
  ok: boolean;
  kind?: string;
  reason?: string;
}

export interface ValidateResult {
  ok: number;
  not_loaded: number;
  files: ValidatedFile[];
  truncated: boolean;
}

/** One line for a validation, and the files that didn't load with why. */
export function validateSummary(r: ValidateResult): { line: string; problems: ValidatedFile[] } {
  const total = r.ok + r.not_loaded;
  const line =
    total === 0
      ? "No templates found there."
      : r.not_loaded === 0
        ? `All ${total} ${total === 1 ? "template loads" : "templates load"}.`
        : `${r.ok} of ${total} ${total === 1 ? "template loads" : "templates load"}; ${r.not_loaded} ${r.not_loaded === 1 ? "doesn't" : "don't"}.`;
  const problems = r.files.filter((f) => !f.ok);
  const more = r.truncated ? ` Only the first ${VALIDATE_LIMIT} files are listed.` : "";
  return { line: line + more, problems };
}

export const verifyText = (r: { files: number; key_id: string }) => `${r.files} ${r.files === 1 ? "file" : "files"} verified, signed by ${r.key_id}.`;

export const signText = (r: { files: number; key_id: string; dir: string }) =>
  `Signed ${r.files} ${r.files === 1 ? "file" : "files"} in ${r.dir} with key ${r.key_id} (feed.json and feed.sig written).`;

export const keygenText = (r: { key: string; key_id: string; public_key: string }) =>
  `Private key saved to ${r.key} (only you can read it; keep it out of the repository and back it up). Public key ${r.key_id}: ${r.public_key}`;

/** What stops a sign, or null: both a folder and a key are needed. */
export function signProblem(dir: string, key: string): string | null {
  if (!dir.trim()) return "Choose the feed folder to sign";
  if (!key.trim()) return "Choose the private key to sign with";
  return null;
}
