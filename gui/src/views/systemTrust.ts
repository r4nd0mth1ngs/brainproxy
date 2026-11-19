// Settings › TLS / CA › Install in system trust store: what `ca install-system` changes on this
// OS, and what its result means. The CLI writes the Debian store on every system but Windows,
// so on macOS the app doesn't run it (it would fail, or leave a stray file under a
// Homebrew-owned /usr/local) and gives the command to run instead.

export type TrustOs = "windows" | "mac" | "linux";

/** What the app knows of the OS, from the webview: `navigator.userAgentData.platform`, `navigator.platform` or the user agent. */
export function trustOs(platform: string): TrustOs {
  // Mac first: "Darwin" has "win" in it.
  if (/mac|darwin/i.test(platform)) return "mac";
  if (/win/i.test(platform)) return "windows";
  return "linux";
}

/** This webview's OS. */
export function currentTrustOs(): TrustOs {
  if (typeof navigator === "undefined") return "linux";
  const nav = navigator as Navigator & { userAgentData?: { platform?: string } };
  return trustOs(nav.userAgentData?.platform || nav.platform || nav.userAgent || "");
}

/** The CA's subject common name, which the undo commands find it by (crates/core/src/proxy/ca.rs). */
export const CA_NAME = "brainproxy CA";
/** Where `ca install-system` puts the certificate outside Windows (crates/cli/src/proxy_cmd.rs). */
export const DEBIAN_DEST = "/usr/local/share/ca-certificates/brainproxy.crt";

/** `s` as one word for a POSIX shell. */
export function shQuote(s: string): string {
  return `'${s.replaceAll("'", `'\\''`)}'`;
}

/** `s` as one argument for cmd and PowerShell; a Windows path can't hold `"`. */
export function winQuote(s: string): string {
  return `"${s.replaceAll('"', "")}"`;
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
  /** The commands to run instead, in a terminal. */
  manual: string[];
  /** The commands that take it out again: the CLI has no remove. */
  undo: string[];
}

const TRUST_ALL = "Every program that uses this store will trust any certificate the brainproxy CA signs, for any site, until you take it out.";
const KEY = "Anyone who gets the CA's private key (ca.key, next to the certificate) could then intercept this machine's HTTPS without a warning.";

export function trustPlan(os: TrustOs, certPath: string): TrustPlan {
  if (os === "windows") {
    const cert = winQuote(certPath);
    return {
      os,
      store: "your Windows user's Trusted Root Certification Authorities store",
      args: ["ca", "install-system"],
      changes: [
        `Adds ${certPath} to your Windows user's Trusted Root Certification Authorities store (certutil -user -addstore Root). Other users of this PC are not affected.`,
        TRUST_ALL,
        KEY,
        "Firefox keeps its own store and isn't changed.",
      ],
      prompt: "No administrator rights are needed. Windows shows its own security warning first; choose Yes there to add it.",
      manual: [`certutil -user -addstore Root ${cert}`],
      undo: [`certutil -user -delstore Root "${CA_NAME}"`],
    };
  }
  if (os === "mac") {
    const cert = shQuote(certPath);
    return {
      os,
      store: "the macOS System keychain",
      args: null,
      changes: [
        `On macOS the app can't do this itself: brainproxy's ca install-system only knows Windows and Debian-family Linux. Run the command below in Terminal to add ${certPath} to the System keychain as a trusted root.`,
        TRUST_ALL,
        KEY,
      ],
      prompt: "It needs an administrator: sudo asks for your password, and macOS may ask again to change the trust settings.",
      manual: [`sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain ${cert}`],
      undo: [`sudo security delete-certificate -c "${CA_NAME}" /Library/Keychains/System.keychain`],
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
    prompt:
      "It needs root. The app runs as you, so unless it runs as root this fails without changing anything, and the app shows the commands to run with sudo in a terminal.",
    manual: [
      `sudo cp ${cert} ${DEBIAN_DEST} && sudo update-ca-certificates`,
      `# Fedora/RHEL: sudo cp ${cert} /etc/pki/ca-trust/source/anchors/brainproxy.pem && sudo update-ca-trust`,
    ],
    undo: [`sudo rm ${DEBIAN_DEST} && sudo update-ca-certificates --fresh`],
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
  /** Set when the certificate installed is not the one the app shows (another CA home). */
  mismatch?: string;
}

/** The outcome of a run that succeeded. `shown` is the SHA-256 the app showed for the CA. */
export function installed(plan: TrustPlan, r: InstallResult, shown: string): TrustOutcome {
  const where = plan.os === "windows" ? "your user's Trusted Root store" : r.installed;
  const out: TrustOutcome = {
    ok: true,
    title: `Installed in ${plan.store}`,
    detail: `brainproxy reports the CA (SHA-256 ${r.sha256}) is in ${where}. Programs already running may need a restart to see it.`,
    manual: [],
  };
  if (shown && r.sha256 && r.sha256.toLowerCase() !== shown.toLowerCase())
    out.mismatch = `This is not the CA shown above (SHA-256 ${shown}): the CLI used another CA home.`;
  return out;
}

/** The outcome of a run that failed, with the CLI's message and what to do instead. */
export function failed(plan: TrustPlan, message: string): TrustOutcome {
  const detail = message.trim() || "brainproxy gave no reason.";
  if (plan.os === "windows") {
    // certutil's answer when the person chose No in Windows' warning (ERROR_CANCELLED).
    if (/0x800704c7|ERROR_CANCELLED|cancell?ed by the user/i.test(detail))
      return { ok: false, title: "Cancelled in Windows' warning", detail, hint: "Nothing was changed.", manual: [] };
    return { ok: false, title: "Not installed", detail, hint: "You can run certutil yourself:", manual: plan.manual };
  }
  // Without root the CLI stops at creating or writing the certificate's file, before anything
  // else: the messages end "(run as root)".
  if (/run as root/i.test(detail))
    return { ok: false, title: "This needs root", detail, hint: "Nothing was changed. Run this in a terminal:", manual: plan.manual };
  // update-ca-certificates is missing or failed: the certificate's file may be written already.
  if (/update-ca-certificates/i.test(detail))
    return {
      ok: false,
      title: "Not installed",
      detail,
      hint: `The certificate may already be at ${DEBIAN_DEST}, but the store wasn't updated. If this system doesn't use update-ca-certificates, use the Fedora/RHEL line, or your distribution's way:`,
      manual: plan.manual,
    };
  return { ok: false, title: "Not installed", detail, hint: "Run this in a terminal instead:", manual: plan.manual };
}
