// The guided scan's depths: what each one promises and the `scan active` flags behind it.

export type Depth = "quick" | "standard" | "thorough";

export const DEPTHS: { id: Depth; title: string; time: string; text: string; args: string[] }[] = [
  {
    id: "quick",
    title: "Quick check",
    time: "a few minutes",
    text: "Explores the main pages and tries the most common attacks with few requests.",
    // Medium, not low: low strength skips the SQL injection payloads that matter most.
    args: ["--strength", "medium", "--crawl-depth", "3", "--crawl-max-pages", "150"],
  },
  {
    id: "standard",
    title: "Standard",
    // Attacking path segments adds many requests, so a large site can take an hour.
    time: "about 10 to 60 minutes",
    text: "A balanced scan of the whole site, including IDs in its addresses. Good for a first assessment, but sends many requests.",
    args: ["--strength", "high", "--crawl-depth", "5", "--crawl-max-pages", "500", "--cookies", "--url-path"],
  },
  {
    id: "thorough",
    title: "Thorough",
    time: "30 minutes or more",
    text: "Everything in Standard, but deeper, with many more attack variations. Sends a lot of requests.",
    args: ["--strength", "insane", "--crawl-depth", "8", "--crawl-max-pages", "1500", "--cookies", "--url-path"],
  },
];

/** Whether a depth attacks URL path segments, such as the ID in `/users/42`. */
export const attacksPaths = (depth: Depth): boolean => DEPTHS.find((d) => d.id === depth)!.args.includes("--url-path");
