// CVSS 4.0 vectors as the issue CVSS dialog edits them: the same metrics and values the CLI
// accepts (crates/core/src/scan/cvss.rs), so a vector is checked as it is typed. The score
// is the CLI's to compute (`findings issue cvss` answers with it); it isn't repeated here.

const PREFIX = "CVSS:4.0/";

/** Every metric and the values it takes, in the specification's order; the first eleven are the base metrics. */
export const METRICS: readonly (readonly [string, readonly string[]])[] = [
  ["AV", ["N", "A", "L", "P"]],
  ["AC", ["L", "H"]],
  ["AT", ["N", "P"]],
  ["PR", ["N", "L", "H"]],
  ["UI", ["N", "P", "A"]],
  ["VC", ["H", "L", "N"]],
  ["VI", ["H", "L", "N"]],
  ["VA", ["H", "L", "N"]],
  ["SC", ["H", "L", "N"]],
  ["SI", ["H", "L", "N"]],
  ["SA", ["H", "L", "N"]],
  ["E", ["X", "A", "P", "U"]],
  ["CR", ["X", "H", "M", "L"]],
  ["IR", ["X", "H", "M", "L"]],
  ["AR", ["X", "H", "M", "L"]],
  ["MAV", ["X", "N", "A", "L", "P"]],
  ["MAC", ["X", "L", "H"]],
  ["MAT", ["X", "N", "P"]],
  ["MPR", ["X", "N", "L", "H"]],
  ["MUI", ["X", "N", "P", "A"]],
  ["MVC", ["X", "H", "L", "N"]],
  ["MVI", ["X", "H", "L", "N"]],
  ["MVA", ["X", "H", "L", "N"]],
  ["MSC", ["X", "H", "L", "N"]],
  ["MSI", ["X", "S", "H", "L", "N"]],
  ["MSA", ["X", "S", "H", "L", "N"]],
  ["S", ["X", "N", "P"]],
  ["AU", ["X", "N", "Y"]],
  ["R", ["X", "A", "U", "I"]],
  ["V", ["X", "D", "C"]],
  ["RE", ["X", "L", "M", "H"]],
  ["U", ["X", "Clear", "Green", "Amber", "Red"]],
];
const BASE = 11;
const VALUES = new Map(METRICS.map(([m, v]) => [m, v]));

/** The base metrics as the picker shows them: a name, and each value in words. */
export const BASE_PICKER: readonly { metric: string; name: string; values: readonly [string, string][] }[] = [
  { metric: "AV", name: "Attack vector", values: [["N", "Network"], ["A", "Adjacent"], ["L", "Local"], ["P", "Physical"]] },
  { metric: "AC", name: "Attack complexity", values: [["L", "Low"], ["H", "High"]] },
  { metric: "AT", name: "Attack requirements", values: [["N", "None"], ["P", "Present"]] },
  { metric: "PR", name: "Privileges required", values: [["N", "None"], ["L", "Low"], ["H", "High"]] },
  { metric: "UI", name: "User interaction", values: [["N", "None"], ["P", "Passive"], ["A", "Active"]] },
  { metric: "VC", name: "Confidentiality (vulnerable system)", values: [["H", "High"], ["L", "Low"], ["N", "None"]] },
  { metric: "VI", name: "Integrity (vulnerable system)", values: [["H", "High"], ["L", "Low"], ["N", "None"]] },
  { metric: "VA", name: "Availability (vulnerable system)", values: [["H", "High"], ["L", "Low"], ["N", "None"]] },
  { metric: "SC", name: "Confidentiality (subsequent systems)", values: [["H", "High"], ["L", "Low"], ["N", "None"]] },
  { metric: "SI", name: "Integrity (subsequent systems)", values: [["H", "High"], ["L", "Low"], ["N", "None"]] },
  { metric: "SA", name: "Availability (subsequent systems)", values: [["H", "High"], ["L", "Low"], ["N", "None"]] },
];

/** Where the picker starts when an issue has no rating: reachable over the network, no impact yet. */
export const START_VECTOR = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:N/SI:N/SA:N";

/**
 * Why the CLI would refuse `text` as a CVSS 4.0 vector, or "" when it would take it. An empty
 * text is fine: it removes the rating. The checks and their order follow `Cvss4::parse`.
 */
export function vectorProblem(text: string): string {
  const v = text.trim();
  if (v === "") return "";
  if (!v.startsWith(PREFIX)) return v.startsWith("CVSS:3") ? "CVSS 3 vectors aren't taken: rate it with CVSS 4.0" : "A CVSS 4.0 vector starts with CVSS:4.0/";
  const seen = new Set<string>();
  for (const part of v.slice(PREFIX.length).split("/")) {
    const at = part.indexOf(":");
    if (at < 0) return `"${part}" is not METRIC:VALUE`;
    const [k, val] = [part.slice(0, at), part.slice(at + 1)];
    const values = VALUES.get(k);
    if (!values) return `Unknown metric ${k}`;
    if (!values.includes(val)) return `${k} takes ${values.join(", ")}, not ${val}`;
    if (seen.has(k)) return `${k} is given twice`;
    seen.add(k);
  }
  const missing = METRICS.slice(0, BASE).find(([m]) => !seen.has(m));
  return missing ? `The base metric ${missing[0]} is missing` : "";
}

/** The metrics of `text` that are well formed (the picker reads them even while the rest is being typed). */
export function metricsOf(text: string): Map<string, string> {
  const out = new Map<string, string>();
  const v = text.trim();
  if (!v.startsWith(PREFIX)) return out;
  for (const part of v.slice(PREFIX.length).split("/")) {
    const at = part.indexOf(":");
    const [k, val] = [part.slice(0, at), part.slice(at + 1)];
    if (at > 0 && VALUES.get(k)?.includes(val) && !out.has(k)) out.set(k, val);
  }
  return out;
}

/** A vector of `metrics` in the specification's order, leaving out metrics at X (not defined), as the CLI stores it. */
export function vectorOf(metrics: ReadonlyMap<string, string>): string {
  const parts = METRICS.flatMap(([m]) => {
    const v = metrics.get(m);
    return v && v !== "X" ? [`${m}:${v}`] : [];
  });
  return ["CVSS:4.0", ...parts].join("/");
}

/**
 * `text` with one metric set by the picker. The metrics it already has are kept (threat and
 * environmental ones too); missing base metrics come from START_VECTOR so the result is whole.
 */
export function withMetric(text: string, metric: string, value: string): string {
  const metrics = metricsOf(text);
  for (const [m, v] of metricsOf(START_VECTOR)) if (!metrics.has(m)) metrics.set(m, v);
  metrics.set(metric, value);
  return vectorOf(metrics);
}

/** The metrics beyond the base ones that `text` sets (the picker leaves them as they are). */
export function extraMetrics(text: string): string[] {
  const base = new Set(METRICS.slice(0, BASE).map(([m]) => m));
  return [...metricsOf(text)].filter(([m, v]) => !base.has(m) && v !== "X").map(([m, v]) => `${m}:${v}`);
}

/** The command that sets an issue's vector; "" removes its rating. `--` so nothing in it is read as a flag. */
export function cvssCommand(issue: number, vector: string): string[] {
  return ["findings", "issue", "cvss", String(issue), "--", vector.trim()];
}
