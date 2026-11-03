// The Codec view's steps: what each op offers, and turning `decode auto`'s answer into steps
// the user can see and edit. The kinds are the CLI's (crates/core/src/codec.rs).

export type Op = "encode" | "decode" | "hash";

export interface Step {
  op: Op;
  kind: string;
}

// `decode auto` isn't offered as a step: Smart decode runs it and shows the steps it found.
export const KINDS: Record<Op, string[]> = {
  encode: ["base64", "base64url", "url", "url-all", "hex", "html", "gzip", "zlib", "deflate"],
  decode: ["base64", "base64url", "url", "percent", "hex", "html", "jwt", "gzip", "zlib", "deflate", "brotli"],
  hash: ["md5", "sha1", "sha256", "sha512"],
};

/** The `decode` steps from `decode auto`'s `steps`, skipping any kind the view doesn't offer. */
export function smartSteps(steps: unknown): Step[] {
  if (!Array.isArray(steps)) return [];
  return steps.filter((k): k is string => typeof k === "string" && KINDS.decode.includes(k)).map((kind) => ({ op: "decode", kind }));
}

/** Why `decode auto` stopped (its `stopped`): nothing more applied, it reached JSON, it hit
 * the layer limit, or the next layer was compressed data over the size limit. */
export type Stopped = "nothing" | "json" | "depth" | { refused: string; error: string };

/** `decode auto`'s `stopped`, or "nothing" when it is missing or not one the view knows. */
export function smartStopped(stopped: unknown): Stopped {
  if (stopped === "json" || stopped === "depth") return stopped;
  if (stopped && typeof stopped === "object") {
    const { refused, error } = stopped as { refused?: unknown; error?: unknown };
    if (typeof refused === "string" && typeof error === "string") return { refused, error };
  }
  return "nothing";
}

/** What Smart decode tells the user after a run. */
export function smartNote(steps: Step[], stopped: Stopped = "nothing"): string {
  const found = steps.length
    ? `Found ${steps.length === 1 ? "1 layer" : `${steps.length} layers`}: ${steps.map((s) => s.kind).join(" → ")}`
    : stopped === "json"
      ? // Smart decode keeps the user's steps when it finds no layer, so say they still apply.
        "Nothing to decode: Smart decode leaves JSON as it is. The steps below are unchanged."
      : "Nothing to decode: no URL, Base64, hex, HTML, JWT, gzip, or zlib layer found.";
  if (stopped === "depth") {
    return `${found}. Stopped at the layer limit: more may remain (use the last output as input and run it again).`;
  }
  if (typeof stopped === "object") return `${found}. Stopped before a layer it refused to unpack: ${stopped.error}`;
  return found;
}

/** Tells a Smart decode answer from a stale one. Any edit to the input or the steps after a
 * run starts makes its answer stale, so a slow CLI can't overwrite what the user just did. */
export class SmartRuns {
  private n = 0;
  /** Starts a run; check its id with `current` when the answer arrives. */
  start(): number {
    return ++this.n;
  }
  /** Drops the run in progress, if any. */
  edit(): void {
    this.n++;
  }
  current(id: number): boolean {
    return id === this.n;
  }
}
