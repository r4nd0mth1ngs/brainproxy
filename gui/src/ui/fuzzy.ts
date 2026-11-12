// Fuzzy matching for the command palette: each word typed must appear in order, as the starts
// of words ("tio" finds "Turn intercept on") or a run inside one, and matches at the start of a
// word, in a run, or in the title rather than its group or keywords rank higher.

const wordStart = (t: string, k: number) => k === 0 || /[^a-z0-9]/.test(t[k - 1]);

/**
 * Where `query`'s letters fall in `text` (case-insensitive) and how well, or null if they
 * don't: in order, in runs that each start a word ("tio" finds "Turn intercept on"), or else
 * all together anywhere ("port" finds "Report"). Letters scattered inside words don't count, so
 * "send" doesn't find "Switch between light and dark".
 */
export function fuzzy(query: string, text: string): { score: number; at: number[] } | null {
  const q = query.toLowerCase();
  const t = text.toLowerCase();
  if (!q) return { score: 0, at: [] };
  // Each letter continues the run before it or starts a word; tried in that order, backing off.
  const failed = new Set<string>();
  const at: number[] = [];
  const place = (i: number, prev: number): boolean => {
    if (i === q.length) return true;
    const key = `${i}:${prev}`;
    if (failed.has(key)) return false;
    const c = q[i];
    const tries: number[] = [];
    if (prev >= 0 && t[prev + 1] === c) tries.push(prev + 1);
    for (let k = prev + 1; k < t.length; k++) if (t[k] === c && wordStart(t, k) && !tries.includes(k)) tries.push(k);
    for (const k of tries) {
      at.push(k);
      if (place(i + 1, k)) return true;
      at.pop();
    }
    failed.add(key);
    return false;
  };
  if (!place(0, -1)) {
    const k = t.indexOf(q);
    if (k < 0) return null;
    for (let i = 0; i < q.length; i++) at.push(k + i);
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
