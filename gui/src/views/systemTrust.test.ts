import { test } from "node:test";
import assert from "node:assert/strict";
import { DEBIAN_DEST, failed, installed, shQuote, trustOs, trustPlan, winQuote } from "./systemTrust.ts";

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

test("paths are quoted for the shell they are pasted into", () => {
  assert.equal(shQuote("/home/a b/ca.pem"), "'/home/a b/ca.pem'");
  assert.equal(shQuote("/home/o'neil/$x/ca.pem"), `'/home/o'\\''neil/$x/ca.pem'`);
  assert.equal(winQuote("C:\\Users\\a b\\ca.pem"), '"C:\\Users\\a b\\ca.pem"');
  assert.equal(winQuote('C:\\x"y'), '"C:\\xy"');
});

test("Windows: the CLI runs, into the user's Root store, with Windows' own warning", () => {
  const p = trustPlan("windows", "C:\\Users\\t\\AppData\\Roaming\\brainproxy\\ca\\ca.pem");
  assert.deepEqual(p.args, ["ca", "install-system"]);
  assert.match(p.changes[0], /Trusted Root/);
  assert.match(p.changes[0], /certutil -user -addstore Root/);
  assert.match(p.prompt, /No administrator/);
  assert.match(p.prompt, /choose Yes/);
  assert.deepEqual(p.manual, ['certutil -user -addstore Root "C:\\Users\\t\\AppData\\Roaming\\brainproxy\\ca\\ca.pem"']);
  assert.deepEqual(p.undo, ['certutil -user -delstore Root "brainproxy CA"']);
});

test("Linux: the CLI runs, needs root, and the sudo commands are offered", () => {
  const p = trustPlan("linux", "/home/t/.local/share/brainproxy/ca/ca.pem");
  assert.deepEqual(p.args, ["ca", "install-system"]);
  assert.ok(p.changes[0].includes(DEBIAN_DEST));
  assert.match(p.changes[0], /update-ca-certificates/);
  assert.match(p.prompt, /needs root/);
  assert.equal(p.manual[0], `sudo cp '/home/t/.local/share/brainproxy/ca/ca.pem' ${DEBIAN_DEST} && sudo update-ca-certificates`);
  // The second line is a comment, so pasting both runs only the Debian one.
  assert.ok(p.manual[1].startsWith("# Fedora/RHEL: "));
  assert.deepEqual(p.undo, [`sudo rm ${DEBIAN_DEST} && sudo update-ca-certificates --fresh`]);
});

test("macOS: the app doesn't run the CLI, which only knows Debian outside Windows", () => {
  const p = trustPlan("mac", "/Users/t/Library/Application Support/brainproxy/ca/ca.pem");
  assert.equal(p.args, null);
  assert.match(p.changes[0], /can't do this itself/);
  assert.deepEqual(p.manual, [
    "sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain '/Users/t/Library/Application Support/brainproxy/ca/ca.pem'",
  ]);
  assert.match(p.undo[0], /delete-certificate -c "brainproxy CA"/);
});

test("every plan says the CA is trusted for any site, and that its key matters", () => {
  for (const os of ["windows", "mac", "linux"] as const) {
    const all = trustPlan(os, "/ca.pem").changes.join("\n");
    assert.match(all, /any certificate the brainproxy CA signs, for any site/, os);
    assert.match(all, /private key/, os);
  }
});

test("a success says where it went, and notices a CA other than the one shown", () => {
  const linux = trustPlan("linux", "/ca.pem");
  const ok = installed(linux, { installed: DEBIAN_DEST, sha256: "ABCD" }, "abcd");
  assert.equal(ok.ok, true);
  assert.equal(ok.title, "Installed in the system's CA store");
  assert.ok(ok.detail.includes(DEBIAN_DEST));
  assert.deepEqual(ok.manual, []);
  assert.equal(ok.mismatch, undefined);
  const other = installed(linux, { installed: DEBIAN_DEST, sha256: "ffff" }, "abcd");
  assert.match(other.mismatch ?? "", /not the CA shown above/);
  const win = installed(trustPlan("windows", "C:\\ca.pem"), { installed: "CurrentUser\\Root", sha256: "abcd" }, "abcd");
  assert.match(win.detail, /your user's Trusted Root store/);
});

test("Linux without root: nothing changed, and the sudo commands are shown", () => {
  const p = trustPlan("linux", "/ca.pem");
  const msg = `cannot write ${DEBIAN_DEST}: Permission denied (os error 13) (run as root)`;
  const o = failed(p, msg);
  assert.equal(o.ok, false);
  assert.equal(o.title, "This needs root");
  assert.equal(o.detail, msg);
  assert.match(o.hint ?? "", /Nothing was changed/);
  assert.deepEqual(o.manual, p.manual);
  assert.equal(failed(p, "cannot create /usr/local/share/ca-certificates: Read-only file system (os error 30) (run as root)").title, "This needs root");
});

test("Linux without update-ca-certificates: the file may be there, the store isn't updated", () => {
  const p = trustPlan("linux", "/ca.pem");
  const o = failed(p, "update-ca-certificates: No such file or directory (os error 2)");
  assert.equal(o.title, "Not installed");
  assert.ok((o.hint ?? "").includes(DEBIAN_DEST));
  assert.deepEqual(o.manual, p.manual);
});

test("Windows: No in Windows' warning is a cancel, with nothing to run", () => {
  const p = trustPlan("windows", "C:\\ca.pem");
  const o = failed(p, "certutil failed: CertUtil: -addstore command FAILED: 0x800704c7 (WIN32: 1223 ERROR_CANCELLED)");
  assert.equal(o.title, "Cancelled in Windows' warning");
  assert.deepEqual(o.manual, []);
  const other = failed(p, "certutil: program not found");
  assert.equal(other.title, "Not installed");
  assert.deepEqual(other.manual, p.manual);
});

test("an empty error still says something", () => {
  assert.equal(failed(trustPlan("linux", "/ca.pem"), "  ").detail, "brainproxy gave no reason.");
});

// No DOM here, so the markup is checked in the source.
test("the dialog is modal and Cancel, not Install, has focus first", async () => {
  const { readFileSync } = await import("node:fs");
  const src = readFileSync(new URL("./SystemTrust.tsx", import.meta.url), "utf8");
  assert.match(src, /role="dialog" aria-modal="true"/);
  assert.match(src, /<button ref=\{closeButton\}[^>]*autoFocus/);
  assert.doesNotMatch(src.match(/<button[^>]*onClick=\{install\}[^>]*>/)?.[0] ?? "", /autoFocus/);
});
