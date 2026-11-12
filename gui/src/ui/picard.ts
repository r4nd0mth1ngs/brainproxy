// For Jean-Luc Picard: what typing "engage" answers and shows (see Engage.tsx).

import { isTyping, type Target } from "./actions.ts";

export const WORD = "engage";
export const REPLY = "Make it so.";

export const SHIP = String.raw`
                                   ______________________________
   ____________________          .'                              ${"`"}.
  [____________________]===-----(________________________________)
            \ \                  ${"`"}-.____  NCC-1701-D  ____.-'
   __________\ \_______________________ ${"`"}--.______.--'
  [____________________________________]_/  /
            ${"`"}--.__________________________.-'
`;

export const MISSION =
  "Space: the final frontier. These are the voyages of the starship Enterprise. Its continuing mission: " +
  "to explore strange new worlds, to seek out new life and new civilizations, to boldly go where no one " +
  "has gone before.";

export const RIP = "Sir Patrick Stewart, 1940–2026. Rest in peace.";

/** The letters typed so far that could still spell the word, and whether `key` finished it. */
export function typed(sofar: string, key: string): [string, boolean] {
  const next = (sofar + key.toLowerCase()).slice(-WORD.length);
  if (next === WORD) return ["", true];
  for (let i = 0; i < next.length; i++) {
    if (WORD.startsWith(next.slice(i))) return [next.slice(i), false];
  }
  return ["", false];
}

/** Typing in a field (the same rule as shortcuts'), where the word isn't being spelt. */
export const editable = (t: EventTarget | null): boolean => isTyping(t as Target | null);
