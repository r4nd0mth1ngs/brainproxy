import { test } from "node:test";
import assert from "node:assert/strict";
import { readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

// The desktop app's macOS WKWebView returns null from window.prompt, and native dialogs look
// different on each OS, so questions go through ui/Confirm.tsx (confirm, ask). The uses left
// are browser-only fallbacks or older code; this list only shrinks.
const ALLOWED: Record<string, number> = {
  "ui/Confirm.tsx": 2, // fallbacks when no <ConfirmHost /> is mounted
  "views/Welcome.tsx": 1, // outside Tauri: the save dialog plugin isn't there
  "views/ApiWizard.tsx": 1, // outside Tauri: the open dialog plugin isn't there
  "views/Proxy.tsx": 1, // Traffic "Add note…"
  "views/Scanner.tsx": 1, // "Delete passive findings and rescan"
};

const SRC = fileURLToPath(new URL("..", import.meta.url));

test("native prompt, alert and confirm dialogs aren't used beyond the known ones", () => {
  const found: Record<string, number> = {};
  for (const f of readdirSync(SRC, { recursive: true }) as string[]) {
    if (!/\.tsx?$/.test(f) || /\.test\.ts$/.test(f)) continue;
    const n = readFileSync(join(SRC, f), "utf8").match(/\bwindow\.(prompt|alert|confirm)\s*\(/g)?.length ?? 0;
    if (n) found[f.split("\\").join("/")] = n;
  }
  assert.deepEqual(found, ALLOWED);
});

// No DOM here, so the markup is checked in the source: the in-app question's text is read with
// its field, and Traffic's saved-filter list and search status are announced.
test("the ask dialog and Traffic's search controls carry their accessible names", () => {
  const read = (f: string) => readFileSync(join(SRC, f), "utf8");
  const dialog = read("ui/Confirm.tsx");
  assert.match(dialog, /<p id="confirm-message">/);
  assert.match(dialog, /<input[^>]*aria-describedby="confirm-message"/s);
  const traffic = read("views/Proxy.tsx");
  assert.match(traffic, /<select[^>]*aria-label="Saved filters"/s);
  assert.match(traffic, /aria-live="polite">\s*\{note\}/);
});
