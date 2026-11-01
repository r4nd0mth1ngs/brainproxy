// The guided scan's depths and what each one promises. The flags behind them are `scan active
// --preset`'s, defined in crates/cli/src/active_cmd.rs.

export type Depth = "quick" | "standard" | "thorough";

export const DEPTHS: { id: Depth; title: string; time: string; text: string; urlPath: boolean }[] = [
  {
    id: "quick",
    title: "Quick check",
    time: "a few minutes",
    text: "Explores the main pages and tries the most common attacks with few requests.",
    urlPath: false,
  },
  {
    id: "standard",
    title: "Standard",
    // Attacking path segments adds many requests, so a site that fills --max-targets can take half an hour.
    time: "about 5 to 30 minutes",
    text: "A balanced scan of the whole site, including IDs in its addresses. Good for a first assessment, but sends many requests.",
    urlPath: true,
  },
  {
    id: "thorough",
    title: "Thorough",
    time: "30 minutes or more",
    text: "Everything in Standard, but deeper, with many more attack variations. Sends a lot of requests.",
    urlPath: true,
  },
];

/** The `scan active` flags for a depth. */
export const depthArgs = (depth: Depth): string[] => ["--preset", depth];

/** Whether a depth attacks URL path segments, such as the ID in `/users/42` (`--url-path`). */
export const attacksPaths = (depth: Depth): boolean => DEPTHS.find((d) => d.id === depth)!.urlPath;
