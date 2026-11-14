// The CLI's similarity of two history entries loaded into Diff (`brainproxy diff`). It describes
// those two texts compared by the unit it was asked for, so it is kept with them rather than with
// their places in the list, which other items, removed or cleared, can hand to other texts.

export interface Similarity {
  /** The texts loaded as A and B: the history entries' part, which the texts already carry. */
  a: string;
  b: string;
  unit: string;
  value: number;
}

/** The similarity to show for the pair and unit on screen: only one worked out for exactly them. */
export function shownSimilarity(s: Similarity | null, a: string | undefined, b: string | undefined, unit: string): number | null {
  return s != null && a === s.a && b === s.b && unit === s.unit ? s.value : null;
}
