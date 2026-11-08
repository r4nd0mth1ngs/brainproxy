// The guided scan's depths and what each one promises. The flags behind them are `scan active
// --preset`'s, defined in crates/cli/src/active_cmd.rs. The times are rough: a scan's length
// grows with the size of the site, so they say how long each depth usually takes, not a promise.

export type Depth = "quick" | "standard" | "thorough";

export const DEPTHS: { id: Depth; title: string; time: string; text: string; urlPath: boolean }[] = [
  {
    id: "quick",
    title: "Quick check",
    time: "usually 5 to 10 minutes",
    text: "Explores the main pages and tries the most common attacks with few requests.",
    urlPath: false,
  },
  {
    id: "standard",
    title: "Standard",
    time: "around an hour",
    text: "A balanced scan of the whole site, including IDs in its addresses. Good for a first assessment, but sends many requests.",
    urlPath: true,
  },
  {
    id: "thorough",
    title: "Thorough",
    time: "several hours, depending on the site's size",
    text: "Everything in Standard, but deeper, with many more attack variations. Sends a lot of requests.",
    urlPath: true,
  },
];

/** The `scan active` flags for a depth. */
export const depthArgs = (depth: Depth): string[] => ["--preset", depth];

/** Whether a depth attacks URL path segments, such as the ID in `/users/42` (`--url-path`). */
export const attacksPaths = (depth: Depth): boolean => DEPTHS.find((d) => d.id === depth)!.urlPath;
