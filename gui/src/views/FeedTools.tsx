// Settings › Rules & Updates › Checks and feed tools. The logic is in feedTools.ts.

import { useState } from "react";
import { inTauri, run } from "../api";
import { chooseSave } from "../ui/chooseSave";
import { ask } from "../ui/Confirm";
import {
  OWN_KEY_NOTE,
  keygenArgs,
  keygenText,
  signArgs,
  signProblem,
  signText,
  validateArgs,
  validateSummary,
  verifyArgs,
  verifyText,
  type ValidateResult,
  type ValidatedFile,
} from "./feedTools.ts";

/** Files or a folder chosen with the dialog (typed in the browser build); empty if cancelled. */
async function choose(what: "files" | "folder" | "key", title: string): Promise<string[]> {
  if (inTauri) {
    const dialog = await import("@tauri-apps/plugin-dialog");
    const p =
      what === "folder"
        ? await dialog.open({ directory: true, multiple: false, title })
        : await dialog.open({ multiple: what === "files", title, filters: what === "files" ? [{ name: "Templates", extensions: ["yaml", "yml"] }] : undefined });
    return p == null ? [] : Array.isArray(p) ? p : [p];
  }
  const typed = (await ask(title, "Its full path on this computer.", "Choose", "Cancel"))?.trim();
  return typed ? [typed] : [];
}

export function FeedTools() {
  const [busy, setBusy] = useState("");
  const [result, setResult] = useState<{ text: string; problems: ValidatedFile[]; failed: boolean } | null>(null);
  const [feedDir, setFeedDir] = useState("");
  const [key, setKey] = useState("");

  const go = async <T,>(label: string, args: string[], text: (d: T) => { text: string; problems?: ValidatedFile[] }) => {
    setBusy(label);
    try {
      const r = text(await run<T>(args));
      setResult({ text: r.text, problems: r.problems ?? [], failed: false });
    } catch (e: any) {
      setResult({ text: e.message, problems: [], failed: true });
    }
    setBusy("");
  };

  const validate = async (what: "files" | "folder") => {
    const paths = await choose(what, what === "files" ? "Template files to check" : "A folder of templates to check");
    if (!paths.length) return;
    await go<ValidateResult>("validate", validateArgs(paths), (r) => {
      const s = validateSummary(r);
      return { text: s.line, problems: s.problems };
    });
  };
  const verify = async () => {
    const [dir] = await choose("folder", "The feed folder to verify");
    if (dir) await go<{ files: number; key_id: string }>("verify", verifyArgs(dir), (r) => ({ text: verifyText(r) }));
  };
  const keygen = async () => {
    const to = await chooseSave("brainproxy-feed.key", "Signing key", "key");
    if (!to) return;
    await go<{ key: string; key_id: string; public_key: string }>("keygen", keygenArgs(to.path), (r) => {
      setKey(r.key);
      return { text: keygenText(r) };
    });
  };
  const pick = async (what: "folder" | "key") => {
    const [p] = await choose(what, what === "folder" ? "The feed folder to sign" : "The private key to sign with");
    if (p) (what === "folder" ? setFeedDir : setKey)(p);
  };
  const problem = signProblem(feedDir, key);
  const sign = () => go<{ files: number; key_id: string; dir: string }>("sign", signArgs(feedDir, key), (r) => ({ text: signText(r) }));

  return (
    <>
      <div className="detail-head set-section">
        <h2>Checks and feed tools</h2>
      </div>
      <p className="muted small">
        Check that template files load (<span className="mono">checks validate</span>), and look after a feed folder: verify its signature, make a signing key,
        sign it. {OWN_KEY_NOTE}
      </p>
      <div className="toolbar flat">
        <button className="btn" disabled={!!busy} onClick={() => validate("files")}>
          {busy === "validate" ? "Checking…" : "Check template files…"}
        </button>
        <button className="btn" disabled={!!busy} onClick={() => validate("folder")}>
          Check a folder…
        </button>
        <button className="btn" disabled={!!busy} onClick={verify}>
          {busy === "verify" ? "Verifying…" : "Verify a feed folder…"}
        </button>
        <button className="btn" disabled={!!busy} onClick={keygen} title="Writes a new private key, readable only by you, and shows its public key">
          {busy === "keygen" ? "Making…" : "Make a signing key…"}
        </button>
      </div>
      <div className="toolbar flat">
        <button className="btn small" disabled={!!busy} onClick={() => pick("folder")}>
          Feed folder…
        </button>
        <span className="mono small grow">{feedDir || "no folder chosen"}</span>
        <button className="btn small" disabled={!!busy} onClick={() => pick("key")}>
          Key…
        </button>
        <span className="mono small grow">{key || "no key chosen"}</span>
        <button className="btn" disabled={!!busy || problem != null} title={problem ?? "Writes feed.json and feed.sig in the folder"} onClick={sign}>
          {busy === "sign" ? "Signing…" : "Sign"}
        </button>
      </div>
      {result && (
        <div role="status" className={result.failed ? "error small" : "small"}>
          <p className="mono">{result.text}</p>
          {result.problems.length > 0 && (
            <ul className="small">
              {result.problems.map((f) => (
                <li key={`${f.file}:${f.id}`}>
                  <span className="mono">{f.file}</span>: {f.reason} {f.kind ? <span className="muted">({f.kind})</span> : null}
                </li>
              ))}
            </ul>
          )}
        </div>
      )}
    </>
  );
}
