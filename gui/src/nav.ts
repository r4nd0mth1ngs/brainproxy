// The app's views as the sidebar lists them, with their default Go to shortcuts.

import type { Tab } from "./store";

export interface NavItem {
  id: Tab;
  label: string;
  icon: string;
  /** The default chord of Go to this view. */
  keys?: string;
}

/** Sidebar: tools grouped by what you're doing. */
export const NAV: { group: string; items: NavItem[] }[] = [
  {
    group: "Recon",
    items: [
      { id: "dashboard", label: "Overview", icon: "overview", keys: "Mod+1" },
      { id: "target", label: "Site map", icon: "sitemap", keys: "Mod+2" },
    ],
  },
  { group: "Capture", items: [{ id: "proxy", label: "Proxy", icon: "proxy", keys: "Mod+3" }] },
  {
    group: "Attack",
    items: [
      { id: "repeater", label: "Replay", icon: "replay", keys: "Mod+4" },
      { id: "fuzzer", label: "Fuzzer", icon: "fuzzer", keys: "Mod+5" },
      { id: "scanner", label: "Scans", icon: "scans", keys: "Mod+6" },
      { id: "access", label: "Access", icon: "access", keys: "Mod+7" },
    ],
  },
  {
    group: "Results",
    items: [
      { id: "findings", label: "Findings", icon: "findings", keys: "Mod+8" },
      { id: "oob", label: "Callbacks", icon: "callbacks", keys: "Mod+9" },
    ],
  },
  {
    group: "Tools",
    items: [
      { id: "decoder", label: "Codec", icon: "codec" },
      { id: "comparer", label: "Diff", icon: "diff" },
    ],
  },
];

export const SETTINGS_NAV: NavItem = { id: "settings", label: "Settings", icon: "settings", keys: "Mod+," };

/** Where an action applies, in words ("In Replay"). */
export function whereLabel(where: string | undefined): string {
  if (!where || where === "global") return "Anywhere";
  if (where === "editor") return "In a message editor";
  if (where === "dialog") return "In a dialog";
  const item = [...NAV.flatMap((g) => g.items), SETTINGS_NAV].find((i) => i.id === where);
  return `In ${item?.label ?? where}`;
}
