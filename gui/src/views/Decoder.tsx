// Stacked transform pipeline: the input, then one panel per step, each step applied to the
// previous panel's output by `brainproxy encode|decode|hash KIND -`. Smart decode asks
// `brainproxy decode auto -` which decodings apply and makes them the steps.

import { useEffect, useRef, useState } from "react";
import { bodyText, isBinary, run, textBytes, type Body } from "../api";
import { KINDS, smartNote, smartSteps, type Op, type Step } from "./codec";

export function DecoderView() {
  const [input, setInput] = useState("");
  const [steps, setSteps] = useState<Step[]>([{ op: "decode", kind: "url" }]);
  const [outputs, setOutputs] = useState<{ text: string; error?: string }[]>([]);
  const [note, setNote] = useState<{ text: string; error?: boolean } | null>(null);
  // Bumped on every Smart decode and input change, so an answer for an older input is dropped.
  const smartRun = useRef(0);

  const changeInput = (text: string) => {
    smartRun.current++;
    setInput(text);
    setNote(null);
  };

  useEffect(() => {
    let live = true;
    const t = setTimeout(async () => {
      const out: { text: string; error?: string }[] = [];
      let text = input;
      let binary = false; // text holds a binary step output, one char per byte
      for (const s of steps) {
        if (out.some((o) => o.error) || !text) {
          out.push({ text: "" });
          continue;
        }
        try {
          const d = await run<{ output: Body | unknown }>([s.op, s.kind, "-"], textBytes(text, binary));
          const o = d.output as Body;
          const body = o && typeof o === "object" && "content" in o;
          text = body ? bodyText(o) : JSON.stringify(d.output, null, 2);
          binary = body && isBinary(o);
          out.push({ text });
        } catch (e: any) {
          out.push({ text: "", error: e.message });
        }
      }
      if (live) setOutputs(out);
    }, 250);
    return () => {
      live = false;
      clearTimeout(t);
    };
  }, [input, steps]);

  const update = (i: number, s: Partial<Step>) =>
    setSteps((ss) =>
      ss.map((x, j) => {
        if (j !== i) return x;
        const next = { ...x, ...s };
        if (!KINDS[next.op].includes(next.kind)) next.kind = KINDS[next.op][0];
        return next;
      }),
    );

  const smartDecode = async () => {
    const id = ++smartRun.current;
    setNote(null);
    try {
      const d = await run<{ steps?: unknown }>(["decode", "auto", "-"], textBytes(input));
      if (id !== smartRun.current) return;
      const found = smartSteps(d.steps);
      if (found.length) setSteps(found);
      setNote({ text: smartNote(found) });
    } catch (e: any) {
      if (id === smartRun.current) setNote({ text: e.message, error: true });
    }
  };

  return (
    <div className="decoder">
      <div className="dec-panel">
        <div className="dec-head">
          <span className="label">Input</span>
          {note && <span className={note.error ? "error" : "muted small"}>{note.text}</span>}
          <span className="grow" />
          <button
            className="btn small"
            onClick={smartDecode}
            disabled={!input}
            title="Find the URL, Base64, hex, HTML, JWT, gzip, and zlib layers and make them the steps below"
          >
            Smart decode
          </button>
        </div>
        <textarea
          className="code dec-text"
          spellCheck={false}
          value={input}
          onChange={(e) => changeInput(e.target.value)}
          placeholder="Paste text to transform"
        />
      </div>
      {steps.map((s, i) => (
        <div className="dec-panel" key={i}>
          <div className="dec-head">
            <div className="seg">
              {(Object.keys(KINDS) as Op[]).map((op) => (
                <button key={op} className={s.op === op ? "on" : ""} onClick={() => update(i, { op })}>
                  {op === "encode" ? "Encode" : op === "decode" ? "Decode" : "Hash"}
                </button>
              ))}
            </div>
            <select className="input" value={s.kind} onChange={(e) => update(i, { kind: e.target.value })}>
              {KINDS[s.op].map((k) => (
                <option key={k}>{k}</option>
              ))}
            </select>
            <span className="grow" />
            <button className="btn small" onClick={() => navigator.clipboard.writeText(outputs[i]?.text ?? "")}>
              Copy
            </button>
            <button className="btn small" onClick={() => changeInput(outputs[i]?.text ?? "")} title="Use this output as the input">
              Use as input
            </button>
            <button className="btn small" onClick={() => setSteps((ss) => ss.filter((_, j) => j !== i))} disabled={steps.length === 1}>
              Remove
            </button>
          </div>
          {outputs[i]?.error ? <div className="error">{outputs[i].error}</div> : <pre className="code dec-text">{outputs[i]?.text}</pre>}
        </div>
      ))}
      <button className="btn" onClick={() => setSteps((ss) => [...ss, { op: "decode", kind: "base64" }])}>
        + Add step
      </button>
    </div>
  );
}
