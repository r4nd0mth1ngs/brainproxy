// What the "Record a login" wizard asks the CLI for, and how it words the outcome. Pure
// functions, so they are tested without a browser.

export type RecordMode = "replay" | "browser" | "session";

/** The variable `auth record finish` and `auth add` read a stored TOTP secret from. */
export const TOTP_ENV = "BRAINPROXY_SECRET_TOTP";

/** `auth record start`: with a virtual authenticator when a passkey is asked for, holding the
 * passkeys the profile already has (to record a sign-in with one). */
export function startArgs(url: string, opts: { passkey: boolean; passkeysFrom?: string }): string[] {
  const args = ["auth", "record", "start"];
  if (opts.passkey) args.push(opts.passkeysFrom ? `--passkeys-from=${opts.passkeysFrom}` : "--passkey");
  args.push("--", url);
  return args;
}

export interface FinishOptions {
  save: boolean;
  /** An environment variable to read the password from, instead of storing the recorded one. */
  passwordEnv?: string;
  /** A TOTP secret typed in the wizard: it goes in the child's environment, never in its arguments. */
  totpSecret?: string;
  /** Replay the steps in a browser though plain requests could repeat the login. */
  inBrowser?: boolean;
}

/** `auth record finish` and the secrets its environment carries. */
export function finishCall(name: string, o: FinishOptions): { args: string[]; env?: Record<string, string> } {
  const args = ["auth", "record", "finish"];
  if (o.save) args.push("--save");
  if (o.passwordEnv?.trim()) args.push(`--password-env=${o.passwordEnv.trim()}`);
  if (o.inBrowser) args.push("--in-browser");
  args.push("--", name);
  const secret = o.totpSecret?.trim();
  return secret ? { args, env: { [TOTP_ENV]: secret } } : { args };
}

/** What a profile of this mode does when its session ends. */
export function modeText(mode: RecordMode): string {
  switch (mode) {
    case "replay":
      return "brainproxy can log in by itself, and again whenever the session ends.";
    case "browser":
      return "brainproxy can log in by itself by replaying your steps in a browser with no window, and again whenever the session ends.";
    case "session":
      return "brainproxy can't replay this login, so the profile carries your current session. Record again when it expires.";
  }
}

/** Whether brainproxy logs in by itself with such a profile (and so can test the login now). */
export const logsIn = (mode: RecordMode) => mode !== "session";

export interface PasskeyInfo {
  rp_id: string;
  credential_id: string;
  user_name: string | null;
  sign_count: number;
}

/** A passkey in a line: whose, for which site, and how often it has signed. Never the key. */
export function passkeyLine(k: PasskeyInfo): string {
  const who = k.user_name ? `${k.user_name} at ${k.rp_id}` : k.rp_id;
  return `${who} · used ${k.sign_count} time${k.sign_count === 1 ? "" : "s"}`;
}

export interface LoginResult {
  login: { success: boolean; reason: string };
}

/**
 * A test login that failed. `auth login` exits with an error then (the profile is saved all the
 * same), its message the reason: "login failed: REASON (requests: ...)", or why it couldn't try.
 */
export const failedLogin = (message: string): LoginResult => ({
  login: { success: false, reason: message.replace(/^(?:invalid input: )?login failed: /, "") },
});
