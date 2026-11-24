// The Fuzzer's payload sets as the Attack form holds them, the `-p` source each one becomes,
// which generators a mode allows, and what a run's state lets the person do with it.

export type Mode = "sniper" | "battering-ram" | "pitchfork" | "cluster-bomb";

export type Source = "builtin" | "list" | "range" | "file" | "generator";

export type GeneratorKind = "null" | "dates" | "brute" | "case" | "subst" | "bitflip" | "usernames" | "copy" | "extract" | "oob";

export interface Generator {
  kind: GeneratorKind;
  count: string; // null:N, oob:N
  dateFrom: string;
  dateTo: string;
  dateStep: string; // e.g. 1d, 2w, 1m, 1y
  dateFormat: string; // e.g. %Y%m%d
  charset: string; // brute: a-z0-9
  min: string;
  max: string;
  word: string; // case, subst
  map: string; // subst: a=4@,e=3 (empty: the default map)
  value: string; // bitflip VALUE, extract FIRST (empty: the position's value)
  names: string; // usernames: one full name per line
  position: string; // copy:N, counted from 1
  oobForm: "url" | "host";
}

export interface PayloadSet {
  source: Source;
  wordlist: string; // built-in list name (`brainproxy wordlists list`)
  list: string; // one payload per line
  from: string;
  to: string;
  step: string;
  file: string;
  process: string; // comma-separated chain, e.g. "url,base64"
  gen: Generator;
}

export const NEW_GENERATOR: Generator = {
  kind: "brute",
  count: "10",
  dateFrom: "2024-01-01",
  dateTo: "2024-12-31",
  dateStep: "1d",
  dateFormat: "%Y-%m-%d",
  charset: "a-z0-9",
  min: "1",
  max: "3",
  word: "",
  map: "",
  value: "",
  names: "",
  position: "1",
  oobForm: "url",
};

export const NEW_SET: PayloadSet = { source: "builtin", wordlist: "sqli", list: "", from: "1", to: "100", step: "1", file: "", process: "", gen: NEW_GENERATOR };

export const GENERATORS: { kind: GeneratorKind; label: string; help: string }[] = [
  { kind: "brute", label: "Brute force", help: "Every string over a character set, shortest first (at most 10,000,000)." },
  { kind: "dates", label: "Dates", help: "Dates from one day to another, in steps, in a format of your choice." },
  { kind: "null", label: "Null", help: "Empty payloads: the request as it is, sent this many times." },
  { kind: "case", label: "Case", help: "Every upper and lower case combination of a word (at most 20 letters)." },
  { kind: "subst", label: "Substitution", help: "Every way of substituting characters: a→4/@, e→3, i→1/!, o→0, s→5/$, or your own map." },
  { kind: "bitflip", label: "Bit flip", help: "One payload per bit of the value, with that bit flipped." },
  { kind: "usernames", label: "Usernames", help: "Usernames from full names: jsmith, john.smith, john_smith, smithj, and others." },
  { kind: "copy", label: "Copy", help: "Another position's value in the same request; adds no payloads of its own." },
  { kind: "extract", label: "Extract", help: "What the Extract regex captured from the previous response (recursive grep)." },
  { kind: "oob", label: "OOB tokens", help: "Fresh out-of-band payloads; an interaction names the run and payload that called back." },
];

/** `list:` with commas escaped; one item per non-empty line. */
function listOf(text: string): string {
  // ponytail: list: escapes commas as \, ; a payload ending in a backslash before the next one is misread.
  const items = text.split("\n").map((l) => l.replace(/\r$/, "")).filter((l) => l !== "");
  return items.map((p) => p.replace(/,/g, "\\,")).join(",");
}

export function generatorSpec(g: Generator): string {
  switch (g.kind) {
    case "null":
      return `null:${g.count.trim()}`;
    case "dates": {
      const step = g.dateStep.trim() && g.dateStep.trim() !== "1d" ? `:${g.dateStep.trim()}` : "";
      const format = g.dateFormat && g.dateFormat !== "%Y-%m-%d" ? `:${g.dateFormat}` : "";
      return `dates:${g.dateFrom.trim()}..${g.dateTo.trim()}${step}${format}`;
    }
    case "brute":
      return `brute:${g.charset}:${g.min.trim()}-${g.max.trim()}`;
    case "case":
      return `case:${g.word}`;
    case "subst":
      return `subst:${g.word}${g.map.trim() ? `:${g.map.trim()}` : ""}`;
    case "bitflip":
      return g.value === "" ? "bitflip" : `bitflip:${g.value}`;
    case "usernames":
      return `usernames:list:${listOf(g.names)}`;
    case "copy":
      return `copy:${g.position.trim()}`;
    case "extract":
      return g.value === "" ? "extract" : `extract:${g.value}`;
    case "oob":
      return `oob:${g.count.trim()}${g.oobForm === "host" ? ":host" : ""}`;
  }
}

export function payloadSpec(s: PayloadSet): string {
  if (s.source === "builtin") return `wordlist:${s.wordlist}`;
  if (s.source === "range") return `range:${s.from}-${s.to}${s.step && s.step !== "1" ? `:${s.step}` : ""}`;
  if (s.source === "file") return `file:${s.file}`;
  if (s.source === "generator") return generatorSpec(s.gen);
  return "list:" + listOf(s.list);
}

/** Why a generator can't be used here, or null when it can (as `fuzz run` checks it). */
export function generatorUnavailable(kind: GeneratorKind, mode: Mode, positions: number, oobRunning: boolean): string | null {
  const perPosition = mode === "pitchfork" || mode === "cluster-bomb";
  if (kind === "copy" && !perPosition) return "Copy needs one set per position: Pitchfork or Cluster bomb.";
  if (kind === "extract" && mode === "cluster-bomb") return "Extract follows one response to the next, so it has no place in Cluster bomb.";
  if (kind === "extract" && mode === "sniper" && positions > 1) return "Extract in Sniper needs a single position; use Battering ram or Pitchfork.";
  if (kind === "oob" && !oobRunning) return "Start the OOB listener (OOB tab) to use OOB tokens.";
  return null;
}

/** The generators to offer: those the mode allows, and OOB only while the listener runs. */
export function offeredGenerators(mode: Mode, positions: number, oobRunning: boolean) {
  return GENERATORS.filter((g) => generatorUnavailable(g.kind, mode, positions, oobRunning) === null);
}

export const usesExtract = (sets: PayloadSet[]) => sets.some((s) => s.source === "generator" && s.gen.kind === "extract");

/** A run made only of extract sets has no end of its own. */
export const onlyExtract = (sets: PayloadSet[]) =>
  sets.length > 0 && sets.every((s) => s.source === "generator" && (s.gen.kind === "extract" || s.gen.kind === "copy")) && usesExtract(sets);

/** What the Attack form must have before an extract set can run, or null. */
export function extractProblem(sets: PayloadSet[], extract: string, maxRequests: string): string | null {
  if (!usesExtract(sets)) return null;
  if (!extract.trim()) return "An Extract set sends what the Extract regex captured from the previous response: set the regex under Match.";
  if (onlyExtract(sets) && !maxRequests.trim()) return "With only Extract sets the run has no end of its own: set Max under Engine.";
  return null;
}

export const LIVE_STATES = new Set(["queued", "running", "paused", "stopping"]);

/** What a run in `state` can be asked to do. */
export function runControls(state: string | undefined) {
  return {
    pause: state === "running",
    // A paused run goes on; a stopped or failed one is relaunched from where it got to.
    resume: state === "paused" || state === "stopped" || state === "failed",
    resumeLabel: state === "paused" ? "Resume" : "Resume from here",
    stop: state === "queued" || state === "running" || state === "paused",
  };
}
