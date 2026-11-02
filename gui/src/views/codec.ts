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

/** What Smart decode tells the user after a run. */
export function smartNote(steps: Step[]): string {
  if (!steps.length) return "Nothing to decode: no URL, Base64, hex, HTML, JWT, gzip, or zlib layer found.";
  return `Found ${steps.length === 1 ? "1 layer" : `${steps.length} layers`}: ${steps.map((s) => s.kind).join(" → ")}`;
}
