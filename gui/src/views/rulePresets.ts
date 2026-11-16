// Response modification presets as Match & replace offers them: what `rules presets list` gives,
// how much of each the project has already, and the command that adds one.

import { defaultEngines, type Rule } from "./matchReplace.ts";

/** A preset as `rules presets list` gives it: the rules it adds have no id yet. */
export interface Preset {
  name: string;
  title: string;
  description: string;
  rules: Rule[];
}

/** What `rules presets add` answers besides the rules: what it added, and what was there already. */
export interface PresetAdded {
  rules: Rule[];
  added?: number[];
  present?: number[];
}

/**
 * Whether two rules do the same: the same place, match, replacement and conditions, whatever their
 * id, comment, origin and whether they are on. As `rules presets add` decides it.
 */
export function sameRule(a: Rule, b: Rule): boolean {
  const engines = (r: Rule) => (r.applies_to?.length ? r.applies_to : defaultEngines(r.location)).join();
  const key = (r: Rule) =>
    JSON.stringify([
      r.location,
      r.pattern,
      r.replace,
      r.matcher ?? "regex",
      r.name ?? "",
      r.action ?? "set",
      engines(r),
      r.host ?? "",
      r.content_type ?? "",
      r.replacer ?? "text",
      r.script?.file ?? "",
      r.script?.sha256 ?? "",
    ]);
  return key(a) === key(b);
}

/** How much of a preset the project has: all, some or none of its rules, and the ids of those switched off. */
export function presetState(preset: Preset, rules: Rule[]): { have: "all" | "some" | "none"; off: number[] } {
  const found = preset.rules.map((p) => rules.find((r) => sameRule(r, p)));
  const there = found.filter((r): r is Rule => !!r);
  const have = there.length === 0 ? "none" : there.length === found.length ? "all" : "some";
  return { have, off: there.filter((r) => !r.enabled).map((r) => r.id) };
}

/** A preset as the picker lists it: its title, and whether it is added already. */
export function presetLabel(preset: Preset, rules: Rule[]): string {
  const { have, off } = presetState(preset, rules);
  if (have === "none") return preset.title;
  if (have === "some") return `${preset.title} (partly added)`;
  if (!off.length) return `${preset.title} (added)`;
  return off.length < preset.rules.length ? `${preset.title} (added, partly switched off)` : `${preset.title} (added, switched off)`;
}

/** `rules presets add` for one preset. */
export const presetArgs = (name: string) => ["rules", "presets", "add", name];

/** What the app says once a preset is added: how many rules it added, and which were there already. */
export function presetNote(preset: Preset, result: PresetAdded): string {
  const added = result.added ?? [];
  const present = result.present ?? [];
  const off = result.rules.filter((r) => present.includes(r.id) && !r.enabled).map((r) => r.id);
  const switchedOff = off.length ? `; switched off: ${off.map((id) => `#${id}`).join(", ")}, which the table's On box turns on` : "";
  if (!added.length) return `${preset.title}: its rules are here already${switchedOff}.`;
  const rules = `${added.length} rule${added.length === 1 ? "" : "s"}`;
  return present.length ? `${preset.title}: added ${rules}; the rest were here already${switchedOff}.` : `${preset.title}: added ${rules}.`;
}
