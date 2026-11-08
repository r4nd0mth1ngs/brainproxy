// Saved scan policies (`scan policy list|show|save|remove`): which active rules run, at what
// strength, and how sure a rule must be to raise a finding (its threshold). A scan uses one
// with `scan active --policy NAME`; the flags given as well win over it.

export const STRENGTHS = ["low", "medium", "high", "insane"] as const;
export const THRESHOLDS = ["low", "medium", "high"] as const;
export type Strength = (typeof STRENGTHS)[number];
export type Threshold = (typeof THRESHOLDS)[number];

/** A rule's own settings; what it leaves out comes from the policy. */
export interface RuleSetting {
  enabled?: boolean;
  strength?: Strength;
  threshold?: Threshold;
}

/** A policy as `scan policy save --json` takes it. */
export interface Policy {
  /** Whether rules the policy doesn't turn on or off run. */
  enabled: boolean;
  strength: Strength;
  threshold: Threshold;
  rules: Record<string, RuleSetting>;
}

/** A policy as `scan policy list` shows it. */
export interface PolicySummary extends Policy {
  name: string;
  rules_enabled: number;
  rules_disabled: number;
}

export const DEFAULT_POLICY: Policy = { enabled: true, strength: "medium", threshold: "low", rules: {} };

/** What a threshold raises, for a label or a tooltip. */
export const THRESHOLD_TEXT: Record<Threshold, string> = {
  low: "every finding",
  medium: "findings of medium or high confidence",
  high: "high-confidence findings only",
};

/** The policy part of a saved policy (what the editor changes). */
export function policyOf(s: Policy): Policy {
  return { enabled: s.enabled, strength: s.strength, threshold: s.threshold, rules: { ...(s.rules ?? {}) } };
}

/** How the policy runs one rule. */
export function effective(p: Policy, id: number | string): { enabled: boolean; strength: Strength; threshold: Threshold; own: boolean } {
  const r = p.rules[String(id)] ?? {};
  return {
    enabled: r.enabled ?? p.enabled,
    strength: r.strength ?? p.strength,
    threshold: r.threshold ?? p.threshold,
    own: Object.keys(r).length > 0,
  };
}

/**
 * The policy with one rule's settings changed: a key set to undefined goes back to the
 * policy's (the entry is dropped once nothing is its own).
 */
export function setRule(p: Policy, id: number | string, patch: Partial<Record<keyof RuleSetting, unknown>>): Policy {
  const key = String(id);
  const next: Record<string, unknown> = { ...(p.rules[key] ?? {}), ...patch };
  for (const k of Object.keys(next)) if (next[k] === undefined || next[k] === "") delete next[k];
  const rules = { ...p.rules };
  if (Object.keys(next).length) rules[key] = next as RuleSetting;
  else delete rules[key];
  return { ...p, rules };
}

/** Turns one rule on or off; the same as the policy's default leaves nothing of its own. */
export function setEnabled(p: Policy, id: number | string, on: boolean): Policy {
  return setRule(p, id, { enabled: on === p.enabled ? undefined : on });
}

/** Rules the policy runs, out of `ids`. */
export function enabledCount(p: Policy, ids: (number | string)[]): number {
  return ids.filter((id) => effective(p, id).enabled).length;
}

/** What a policy name may be: what `scan policy save` takes. */
export function nameProblem(name: string): string | null {
  const n = name.trim();
  if (!n) return "Give the policy a name.";
  // 64 bytes, as `scan policy save` counts them.
  if (new TextEncoder().encode(n).length > 64) return "A name has at most 64 characters.";
  if (n.startsWith("-")) return "A name can't start with -.";
  return null;
}

/** `scan policy save` for the editor's policy: the policy goes as JSON on stdin. */
export function saveCommand(name: string, p: Policy): { args: string[]; stdin: string } {
  return { args: ["scan", "policy", "save", name.trim(), "--json", "-"], stdin: JSON.stringify(policyOf(p)) };
}

/**
 * The `scan active` flags for a picked policy and strength. With a policy, an empty strength
 * means the policy's; without one, the scan's default (medium) is given as before.
 */
export function policyScanArgs(policy: string, strength: string): string[] {
  if (!policy) return [`--strength=${strength || "medium"}`];
  return [`--policy=${policy}`, ...(strength ? [`--strength=${strength}`] : [])];
}

/** One line for a saved policy. */
export function describe(s: PolicySummary): string {
  const own = Object.keys(s.rules ?? {}).length;
  return `${s.rules_enabled} rules on, strength ${s.strength}, raises ${THRESHOLD_TEXT[s.threshold]}${own ? `, ${own} rule${own === 1 ? "" : "s"} set apart` : ""}`;
}

/** What a finished scan's result says about its policy and thresholds, as facts to show. */
export function policyFacts(r: { policy?: { name: string; strength: string; threshold: string; flags_over_policy?: string[] }; below_threshold?: Record<string, number> }): [string, string][] {
  const out: [string, string][] = [];
  if (r.policy) {
    const flags = r.policy.flags_over_policy ?? [];
    out.push(["Policy", `${r.policy.name}: strength ${r.policy.strength}, threshold ${r.policy.threshold}${flags.length ? ` (${flags.join(", ")} given as well)` : ""}`]);
  }
  const below = Object.values(r.below_threshold ?? {}).reduce((a, b) => a + b, 0);
  if (below) out.push(["Below threshold", `${below} finding${below === 1 ? "" : "s"} not raised`]);
  return out;
}
