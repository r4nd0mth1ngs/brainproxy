// Fuzzy matching for the command palette: each word typed must appear in order, letters may be
// skipped ("tgi" finds "Toggle intercept"), and matches at the start of a word, in a run, or in
// the title rather than its group or keywords rank higher.

/** Whether q[i..] appears in order in t[from..]. */
function fits(q: string, i: number, t: string, from: number): boolean {
  for (; i < q.length; i++) {
    from = t.indexOf(q[i], from);
    if (from < 0) return false;
    from++;
  }
  return true;
}

/** Where `query`'s letters fall in `text` (case-insensitive) and how well, or null if they don't all. */
export function fuzzy(query: string, text: string): { score: number; at: number[] } | null {
  const q = query.toLowerCase();
  const t = text.toLowerCase();
  if (!q) return { score: 0, at: [] };
  // Take each letter at the earliest word start it can, else at the earliest place, keeping order.
  const at: number[] = [];
  let from = 0;
  for (let i = 0; i < q.length; i++) {
    const c = q[i];
    let j = -1;
    // Prefer continuing a run, then the start of a word.
    if (at.length && t[from] === c) j = from;
    else {
      for (let k = from; k < t.length; k++) {
        // A word start further on, if the rest of the query still fits after it.
        if (t[k] === c && (k === 0 || /[^a-z0-9]/.test(t[k - 1])) && fits(q, i + 1, t, k + 1)) {
          j = k;
          break;
        }
      }
      if (j < 0) j = t.indexOf(c, from);
    }
    if (j < 0) return null;
    at.push(j);
    from = j + 1;
  }
  let score = 0;
  for (let i = 0; i < at.length; i++) {
    const k = at[i];
    score += 1;
    if (k === 0 || /[^a-z0-9]/.test(t[k - 1])) score += 3;
    if (i > 0 && at[i - 1] === k - 1) score += 2;
  }
  if (at[0] === 0) score += 2;
  // Shorter texts with the same letters are closer.
  score -= (t.length - q.length) * 0.01;
  return { score, at };
}

export interface Ranked<T> {
  item: T;
  score: number;
  /** Positions in the title to highlight. */
  at: number[];
}

/**
 * The items matching every word of `query`, best first (ties keep their order). A word found in
 * the title counts more than one found only in the rest (`other`: group, keywords).
 */
export function rank<T>(query: string, items: T[], title: (t: T) => string, other: (t: T) => string = () => ""): Ranked<T>[] {
  const words = query.trim().split(/\s+/).filter(Boolean);
  const out: (Ranked<T> & { i: number })[] = [];
  items.forEach((item, i) => {
    const name = title(item);
    const rest = other(item);
    let score = 0;
    const at = new Set<number>();
    for (const w of words) {
      const inTitle = fuzzy(w, name);
      const inRest = fuzzy(w, rest);
      if (inTitle && (!inRest || inTitle.score * 2 >= inRest.score)) {
        score += inTitle.score * 2;
        inTitle.at.forEach((k) => at.add(k));
      } else if (inRest) score += inRest.score;
      else return;
    }
    out.push({ item, score, at: [...at].sort((a, b) => a - b), i });
  });
  return out.sort((a, b) => b.score - a.score || a.i - b.i).map(({ item, score, at }) => ({ item, score, at }));
}
