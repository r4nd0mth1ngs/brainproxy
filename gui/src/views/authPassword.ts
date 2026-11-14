// An auth profile form's password, as `auth add` takes it.

export interface PasswordForm {
  passwordMode: "env" | "literal" | "none";
  passwordEnv: string;
  password: string;
  /** The profile being edited has a stored password, which `auth show` redacts. */
  passwordStored: boolean;
}

/**
 * `auth add`'s password flags. A typed password isn't one: it goes in the environment, never
 * on the command line, where `ps` shows it. `auth add` replaces the whole profile, so a stored
 * password left empty here (the form can't show it) is kept, not dropped.
 */
export function passwordArgs(f: PasswordForm): string[] {
  if (f.passwordMode === "env" && f.passwordEnv.trim()) return [`--password-env=${f.passwordEnv.trim()}`];
  const given = f.passwordMode === "literal" && !!f.password;
  if (f.passwordMode !== "none" && !given && f.passwordStored) return ["--keep-password"];
  return [];
}
