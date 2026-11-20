// Settings › TLS / CA › Install in system trust store: what `ca install-system` changes on this
// OS, and what its result means. The CLI installs only on Windows and Debian-family Linux; on
// macOS it refuses with the keychain command, so the app doesn't run it there and shows that
// command instead.

export type TrustOs = "windows" | "mac" | "linux";

/** What the app knows of the OS, from the webview: `navigator.userAgentData.platform`, `navigator.platform` or the user agent. */
export function trustOs(platform: string): TrustOs {
  // Mac first: "Darwin" has "win" in it.
  if (/mac|darwin/i.test(platform)) return "mac";
  if (/win/i.test(platform)) return "windows";
  return "linux";
}

/**
 * This webview's OS. In the desktop app the CLI runs on the same machine; under the dev bridge
 * it is the browser's, which may differ from the bridge's (a Windows browser on a WSL bridge).
 */
export function currentTrustOs(): TrustOs {
  if (typeof navigator === "undefined") return "linux";
  const nav = navigator as Navigator & { userAgentData?: { platform?: string } };
  return trustOs(nav.userAgentData?.platform || nav.platform || nav.userAgent || "");
}

/** The CA's subject common name (crates/core/src/proxy/ca.rs): every generation has the same one. */
export const CA_NAME = "brainproxy CA";
/** Where `ca install-system` puts the certificate outside Windows (crates/cli/src/proxy_cmd.rs). */
export const DEBIAN_DEST = "/usr/local/share/ca-certificates/brainproxy.crt";
/** Where the Fedora/RHEL line the dialog offers puts it. */
export const FEDORA_DEST = "/etc/pki/ca-trust/source/anchors/brainproxy.pem";

/** `s` as one word for a POSIX shell. */
export function shQuote(s: string): string {
  return `'${s.replaceAll("'", `'\\''`)}'`;
}

/** `s` as one literal argument for PowerShell: nothing is expanded in single quotes (`$`, backticks). */
export function psQuote(s: string): string {
  return `'${s.replaceAll("'", "''")}'`;
}

/** The DER bytes of the first certificate in `pem`. */
export function pemToDer(pem: string): Uint8Array {
  const m = pem.match(/-----BEGIN CERTIFICATE-----([\s\S]*?)-----END CERTIFICATE-----/);
  if (!m) throw new Error("no certificate in the PEM");
  const bin = atob(m[1].replace(/\s+/g, ""));
  return Uint8Array.from(bin, (c) => c.charCodeAt(0));
}

/**
 * The certificate's SHA-1 thumbprint in upper-case hex: what certutil and macOS's `security`
 * find one certificate by. The common name matches every generation of the CA.
 */
export async function thumbprint(pem: string): Promise<string> {
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-1", pemToDer(pem) as BufferSource));
  return Array.from(digest, (b) => b.toString(16).padStart(2, "0"))
    .join("")
    .toUpperCase();
}

export interface TrustPlan {
  os: TrustOs;
  /** The store it goes into, in words. */
  store: string;
  /** The CLI arguments the app runs, or null when it can't do this on this OS. */
  args: string[] | null;
  /** What changes, one point a line. */
  changes: string[];
  /** Who has to agree, and how (a dialog, root). */
  prompt: string;
  /** Where the commands below are run. */
  shell: string;
  /** The commands to run instead. */
  manual: string[];
  /** The commands that take it out again: the CLI has no remove. */
  undo: string[];
}

const TRUST_ALL = "Every program that uses this store will trust any certificate the brainproxy CA signs, for any site, until you take it out.";
const KEY = "Anyone who gets the CA's private key (ca.key, next to the certificate) could then intercept this machine's HTTPS without a warning.";

/** `sha1` is the CA's thumbprint, for undo commands that take out this CA and no other generation. */
export function trustPlan(os: TrustOs, certPath: string, sha1?: string): TrustPlan {
  if (os === "windows") {
    return {
      os,
      store: "your Windows user's Trusted Root store",
      args: ["ca", "install-system"],
      changes: [
        `Adds ${certPath} to your Windows user's Trusted Root Certification Authorities store (certutil -user -addstore Root). Other users of this PC are not affected.`,
        TRUST_ALL,
        KEY,
        "Firefox reads this store too by default (security.enterprise_roots.enabled), so it is likely to trust the CA as well.",
      ],
      prompt:
        "No administrator rights are needed. Windows shows its own security warning first, which may open behind this window; choose Yes there to add it.",
      shell: "PowerShell",
      manual: [`certutil -user -addstore Root ${psQuote(certPath)}`],
      undo: [`certutil -user -delstore Root ${sha1 ?? `'${CA_NAME}'`}`],
    };
  }
  if (os === "mac") {
    const cert = shQuote(certPath);
    return {
      os,
      store: "the macOS System keychain",
      args: null,
      changes: [
        `On macOS the app can't do this itself: brainproxy's ca install-system only installs on Windows and Debian-family Linux. Run the command below in Terminal to add ${certPath} to the System keychain as a trusted root.`,
        TRUST_ALL,
        KEY,
      ],
      prompt: "It needs an administrator: sudo asks for your password, and macOS may ask again to change the trust settings.",
      shell: "Terminal",
      manual: [`sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain ${cert}`],
      // The trust setting first, then the certificate: deleting the certificate alone leaves the setting.
      undo: [
        `sudo security remove-trusted-cert -d ${cert}`,
        `sudo security delete-certificate ${sha1 ? `-Z ${sha1}` : `-c '${CA_NAME}'`} /Library/Keychains/System.keychain`,
      ],
    };
  }
  const cert = shQuote(certPath);
  return {
    os,
    store: "the system's CA store",
    args: ["ca", "install-system"],
    changes: [
      `Copies the certificate to ${DEBIAN_DEST} and runs update-ca-certificates (Debian, Ubuntu, Kali), so it is in the store every user's programs share.`,
      TRUST_ALL,
      KEY,
      "Firefox, and Chromium on some systems, keep their own store and aren't changed.",
    ],
    prompt: "It needs root. The app runs as you, so unless it runs as root this fails, and the app shows the commands below to run with sudo instead.",
    shell: "a terminal",
    manual: [
      `sudo cp ${cert} ${DEBIAN_DEST} && sudo update-ca-certificates`,
      `# Fedora/RHEL instead: sudo cp ${cert} ${FEDORA_DEST} && sudo update-ca-trust`,
    ],
    undo: [
      `sudo rm ${DEBIAN_DEST} && sudo update-ca-certificates --fresh`,
      `# Fedora/RHEL: sudo rm ${FEDORA_DEST} && sudo update-ca-trust`,
    ],
  };
}

/** What `ca install-system` answers with `--format json`. */
export interface InstallResult {
  /** `CurrentUser\Root` on Windows, the certificate's path elsewhere. */
  installed: string;
  sha256: string;
}

export interface TrustOutcome {
  ok: boolean;
  /** One line to show first. */
  title: string;
  /** The CLI's own words, or what it reported. */
  detail: string;
  /** What to do next, said before `manual`. */
  hint?: string;
  /** Commands to run yourself: empty when it worked. */
  manual: string[];
  /** Set when the certificate installed is not the one the dialog was opened for. */
  mismatch?: string;
}

const sameSha = (a: string, b: string) => a.replaceAll(":", "").toLowerCase() === b.replaceAll(":", "").toLowerCase();

/** A reason not to run the install: the CA now on disk is not the one the dialog showed. */
export function changedSince(shown: string, now: string): string | null {
  return shown && now && !sameSha(shown, now)
    ? `The CA changed since this page loaded (SHA-256 ${now} now, ${shown} shown): it was regenerated, perhaps in a terminal. Nothing was installed; reopen TLS / CA to check the new one first.`
    : null;
}

/** The outcome of a run that succeeded. `shown` is the SHA-256 the dialog showed for the CA. */
export function installed(plan: TrustPlan, r: InstallResult, shown: string): TrustOutcome {
  const out: TrustOutcome = {
    ok: true,
    title: `Installed in ${plan.store}`,
    // Where the CLI says it put it, rather than where this OS would.
    detail: `brainproxy reports the CA (SHA-256 ${r.sha256}) is in ${r.installed}. Programs already running may need a restart to see it.`,
    manual: [],
  };
  if (shown && r.sha256 && !sameSha(r.sha256, shown)) {
    out.title = "Installed, but not the CA shown";
    out.mismatch = `The CA it installed is not the one this page showed (SHA-256 ${shown}): it was regenerated meanwhile. Check it in TLS / CA, and take out the one you didn't mean to trust.`;
  }
  return out;
}

/** The CLI's message without the kind it starts with ("invalid input: ..."). */
export function cliMessage(message: string): string {
  return message.trim().replace(/^invalid input:\s*/i, "");
}

/** The outcome of a run that failed, with the CLI's message and what to do instead. */
export function failed(plan: TrustPlan, message: string): TrustOutcome {
  const detail = cliMessage(message) || "brainproxy gave no reason.";
  const instead = `Run this in ${plan.shell} instead:`;
  if (plan.os === "windows") {
    // certutil's answer when the person chose No in Windows' warning (ERROR_CANCELLED).
    if (/0x800704c7|ERROR_CANCELLED|cancell?ed by the user/i.test(detail))
      return { ok: false, title: "Cancelled in Windows' warning", detail, hint: "Nothing was changed.", manual: [] };
    return { ok: false, title: "Not installed", detail, hint: instead, manual: plan.manual };
  }
  // The CLI ends every create and write error with "(run as root)", whatever the cause. A
  // permission error comes from opening the file, before a byte is written.
  if (/permission denied|os error 13/i.test(detail))
    return { ok: false, title: "This needs root", detail, hint: `Nothing was changed. ${instead}`, manual: plan.manual };
  if (/^cannot write/i.test(detail))
    return {
      ok: false,
      title: "Not installed",
      detail,
      hint: `${DEBIAN_DEST} may be left part-written, and the store wasn't updated. ${instead}`,
      manual: plan.manual,
    };
  // update-ca-certificates is missing or failed: the certificate's file may be written already.
  if (/update-ca-certificates/i.test(detail))
    return {
      ok: false,
      title: "Not installed",
      detail,
      hint: `The certificate may already be at ${DEBIAN_DEST}, but the store wasn't updated. If this system doesn't use update-ca-certificates, use the Fedora/RHEL line, or your distribution's way:`,
      manual: plan.manual,
    };
  return { ok: false, title: "Not installed", detail, hint: instead, manual: plan.manual };
}
