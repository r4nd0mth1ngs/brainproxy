import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import {
  DEBIAN_DEST,
  FEDORA_DEST,
  changedSince,
  cliMessage,
  failed,
  installed,
  pemToDer,
  psQuote,
  shQuote,
  thumbprint,
  trustOs,
  trustPlan,
} from "./systemTrust.ts";

// A brainproxy CA certificate (no key); its SHA-1 from `openssl x509 -fingerprint -sha1`.
const PEM = `-----BEGIN CERTIFICATE-----
MIIBoTCCAUegAwIBAgIUPJI07uAKZATvXFKCUWgdX8J75UMwCgYIKoZIzj0EAwIw
LTEWMBQGA1UEAwwNYnJhaW5wcm94eSBDQTETMBEGA1UECgwKYnJhaW5wcm94eTAe
Fw0yNjExMTcwOTA2MjBaFw0zNjExMTYwOTA2MjBaMC0xFjAUBgNVBAMMDWJyYWlu
cHJveHkgQ0ExEzARBgNVBAoMCmJyYWlucHJveHkwWTATBgcqhkjOPQIBBggqhkjO
PQMBBwNCAATpaLPGC34cpnxasNrCO6zCyiW71t8FYlscSb8UcTETEFMOUctmnbpg
J7Ia+Il+o2hKSjGqdFQW3ExtuY4PaggOo0UwQzAOBgNVHQ8BAf8EBAMCAYYwHQYD
VR0OBBYEFGFBsF+4nOgcLEJNpwvTOyXB8LVtMBIGA1UdEwEB/wQIMAYBAf8CAQAw
CgYIKoZIzj0EAwIDSAAwRQIgCIHX1ZDCnv9WBGonApM++OtAeu5v+dvFYHiE+QFj
C/cCIQDK8IbaO1bGa/ma2o/L35jX2KcQ95bktIpLDRJzt04zVg==
-----END CERTIFICATE-----
`;
const SHA1 = "E2854FAFA3E84754B7C23B48537497B74EA74F5A";

test("the OS comes from what the webview reports", () => {
  assert.equal(trustOs("Windows"), "windows");
  assert.equal(trustOs("Win32"), "windows");
  assert.equal(trustOs("MacIntel"), "mac");
  assert.equal(trustOs("macOS"), "mac");
  // "Darwin" has "win" in it.
  assert.equal(trustOs("Darwin"), "mac");
  assert.equal(trustOs("Linux x86_64"), "linux");
  assert.equal(trustOs(""), "linux");
});

test("paths are quoted so the shell they are pasted into takes them literally", () => {
  assert.equal(shQuote("/home/a b/ca.pem"), "'/home/a b/ca.pem'");
  assert.equal(shQuote("/home/o'neil/$x/ca.pem"), `'/home/o'\\''neil/$x/ca.pem'`);
  // PowerShell expands $ and backticks in double quotes, not in single ones.
  assert.equal(psQuote("C:\\Users\\$me `x\\ca.pem"), "'C:\\Users\\$me `x\\ca.pem'");
  assert.equal(psQuote("C:\\Users\\o'neil\\ca.pem"), "'C:\\Users\\o''neil\\ca.pem'");
});

test("the thumbprint is the certificate's SHA-1, which certutil and security take", async () => {
  assert.equal(pemToDer(PEM)[0], 0x30);
  assert.equal(await thumbprint(PEM), SHA1);
  assert.throws(() => pemToDer("not a certificate"), /no certificate/);
});

test("Windows: the CLI runs, into the user's Root store, with Windows' own warning", () => {
  const p = trustPlan("windows", "C:\\Users\\t\\AppData\\Roaming\\brainproxy\\ca\\ca.pem", SHA1);
  assert.deepEqual(p.args, ["ca", "install-system"]);
  assert.match(p.changes[0], /Trusted Root/);
  assert.match(p.changes[0], /certutil -user -addstore Root/);
  assert.match(p.changes.join("\n"), /Firefox reads this store too/);
  assert.match(p.prompt, /No administrator/);
  assert.match(p.prompt, /choose Yes/);
  assert.equal(p.shell, "PowerShell");
  assert.deepEqual(p.manual, ["certutil -user -addstore Root 'C:\\Users\\t\\AppData\\Roaming\\brainproxy\\ca\\ca.pem'"]);
  // By thumbprint: every generation of the CA has the same name.
  assert.deepEqual(p.undo, [`certutil -user -delstore Root ${SHA1}`]);
  assert.deepEqual(trustPlan("windows", "C:\\ca.pem").undo, ["certutil -user -delstore Root 'brainproxy CA'"]);
});

test("Linux: the CLI runs, needs root, and the sudo commands go with their undo", () => {
  const p = trustPlan("linux", "/home/t/.local/share/brainproxy/ca/ca.pem");
  assert.deepEqual(p.args, ["ca", "install-system"]);
  assert.ok(p.changes[0].includes(DEBIAN_DEST));
  assert.match(p.changes[0], /update-ca-certificates/);
  assert.match(p.prompt, /needs root/);
  assert.equal(p.manual[0], `sudo cp '/home/t/.local/share/brainproxy/ca/ca.pem' ${DEBIAN_DEST} && sudo update-ca-certificates`);
  // The Fedora lines are comments, so pasting both runs only the Debian one; each install has its undo.
  assert.ok(p.manual[1].startsWith("# Fedora/RHEL instead: ") && p.manual[1].includes(FEDORA_DEST));
  assert.equal(p.undo[0], `sudo rm ${DEBIAN_DEST} && sudo update-ca-certificates --fresh`);
  assert.ok(p.undo[1].startsWith("# Fedora/RHEL: ") && p.undo[1].includes(`sudo rm ${FEDORA_DEST} && sudo update-ca-trust`));
});

test("macOS: the app doesn't run the CLI, which only knows Debian outside Windows", () => {
  const path = "/Users/t/Library/Application Support/brainproxy/ca/ca.pem";
  const p = trustPlan("mac", path, SHA1);
  assert.equal(p.args, null);
  assert.match(p.changes[0], /can't do this itself/);
  assert.deepEqual(p.manual, [`sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain '${path}'`]);
  // The trust setting goes first: deleting the certificate alone leaves it.
  assert.deepEqual(p.undo, [
    `sudo security remove-trusted-cert -d '${path}'`,
    `sudo security delete-certificate -Z ${SHA1} /Library/Keychains/System.keychain`,
  ]);
});

test("every plan says the CA is trusted for any site, and that its key matters", () => {
  for (const os of ["windows", "mac", "linux"] as const) {
    const all = trustPlan(os, "/ca.pem").changes.join("\n");
    assert.match(all, /any certificate the brainproxy CA signs, for any site/, os);
    assert.match(all, /private key/, os);
  }
});

test("the install doesn't run when the CA changed since the dialog showed it", () => {
  assert.equal(changedSince("AB:CD", "abcd"), null);
  assert.match(changedSince("abcd", "ffff") ?? "", /changed since this page loaded.*Nothing was installed/);
});

test("a success says where the CLI put it, and notices a CA other than the one shown", () => {
  const linux = trustPlan("linux", "/ca.pem");
  const ok = installed(linux, { installed: DEBIAN_DEST, sha256: "ABCD" }, "abcd");
  assert.equal(ok.ok, true);
  assert.equal(ok.title, "Installed in the system's CA store");
  assert.ok(ok.detail.includes(DEBIAN_DEST));
  assert.deepEqual(ok.manual, []);
  assert.equal(ok.mismatch, undefined);
  const other = installed(linux, { installed: DEBIAN_DEST, sha256: "ffff" }, "abcd");
  assert.equal(other.title, "Installed, but not the CA shown");
  assert.match(other.mismatch ?? "", /regenerated meanwhile/);
  // What the CLI reports, even if it differs from this OS's plan (the dev bridge on another OS).
  const win = installed(trustPlan("windows", "C:\\ca.pem"), { installed: "CurrentUser\\Root", sha256: "abcd" }, "abcd");
  assert.match(win.detail, /is in CurrentUser\\Root/);
});

test("the CLI's message is shown without its kind", () => {
  assert.equal(cliMessage("invalid input: cannot write x (run as root)"), "cannot write x (run as root)");
  assert.equal(cliMessage("certutil failed: x"), "certutil failed: x");
});

test("Linux without root: nothing changed, and the sudo commands are shown", () => {
  const p = trustPlan("linux", "/ca.pem");
  const msg = `invalid input: cannot write ${DEBIAN_DEST}: Permission denied (os error 13) (run as root)`;
  const o = failed(p, msg);
  assert.equal(o.ok, false);
  assert.equal(o.title, "This needs root");
  assert.equal(o.detail, msg.replace("invalid input: ", ""));
  assert.match(o.hint ?? "", /^Nothing was changed\. Run this in a terminal instead:/);
  assert.deepEqual(o.manual, p.manual);
  assert.equal(failed(p, "invalid input: cannot create /usr/local/share/ca-certificates: Permission denied (os error 13) (run as root)").title, "This needs root");
});

test("Linux: another write error is not called a root problem, and may leave the file part-written", () => {
  const p = trustPlan("linux", "/ca.pem");
  for (const msg of [
    `invalid input: cannot write ${DEBIAN_DEST}: No space left on device (os error 28) (run as root)`,
    `invalid input: cannot write ${DEBIAN_DEST}: Read-only file system (os error 30) (run as root)`,
  ]) {
    const o = failed(p, msg);
    assert.equal(o.title, "Not installed", msg);
    assert.match(o.hint ?? "", /part-written/, msg);
    assert.doesNotMatch(o.hint ?? "", /Nothing was changed/, msg);
    assert.deepEqual(o.manual, p.manual);
  }
});

test("Linux without update-ca-certificates: the file may be there, the store isn't updated", () => {
  const p = trustPlan("linux", "/ca.pem");
  const o = failed(p, "invalid input: update-ca-certificates: No such file or directory (os error 2)");
  assert.equal(o.title, "Not installed");
  assert.ok((o.hint ?? "").includes(DEBIAN_DEST));
  assert.deepEqual(o.manual, p.manual);
});

test("Windows: No in Windows' warning is a cancel, with nothing to run", () => {
  const p = trustPlan("windows", "C:\\ca.pem");
  const o = failed(p, "invalid input: certutil failed: CertUtil: -addstore command FAILED: 0x800704c7 (WIN32: 1223 ERROR_CANCELLED)");
  assert.equal(o.title, "Cancelled in Windows' warning");
  assert.deepEqual(o.manual, []);
  const other = failed(p, "invalid input: certutil: program not found");
  assert.equal(other.title, "Not installed");
  assert.match(other.hint ?? "", /in PowerShell/);
  assert.deepEqual(other.manual, p.manual);
});

test("an empty error still says something", () => {
  assert.equal(failed(trustPlan("linux", "/ca.pem"), "  ").detail, "brainproxy gave no reason.");
});

// No DOM here, so the markup is checked in the source.
test("the dialog is modal, keeps Tab inside, and Cancel, not Install, has focus first", () => {
  const src = readFileSync(new URL("./SystemTrust.tsx", import.meta.url), "utf8");
  assert.match(src, /role="dialog" aria-modal="true"/);
  assert.match(src, /useDialogFocus\(ref\)/);
  // useDialogFocus traps Tab from a document listener: a stopPropagation here would let Tab out.
  assert.doesNotMatch(src, /stopPropagation/);
  assert.match(src, /<button ref=\{closeButton\}[^>]*autoFocus/);
  // Close stays usable while the install runs (Windows' warning may be behind the window).
  assert.doesNotMatch(src.match(/<button ref=\{closeButton\}[^>]*>/)?.[0] ?? "", /disabled/);
  assert.doesNotMatch(src.match(/<button[^>]*onClick=\{install\}[^>]*>/)?.[0] ?? "", /autoFocus/);
  // The result is announced: the live region is there before it.
  assert.match(src, /<div aria-live="polite">/);
});

test("the dialogs' focus trap reaches a disclosure's summary", () => {
  const src = readFileSync(new URL("../ui/dialogFocus.ts", import.meta.url), "utf8");
  assert.match(src, /FOCUSABLE =[^;]*\bsummary\b/);
});
