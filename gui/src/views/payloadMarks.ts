// Where a finding's payload is in its attack request, so Replay can highlight it. The request
// the scan started from (its baseline) is the best guide: what the attack changed is the
// payload as it went on the wire, however it was encoded. Without one, the payload is looked
// for as typed and in the encodings a scan puts it in (percent-encoding with + or %20 for a
// space, a JSON string's escapes). Marks keep their text and where it was, so after an edit
// each is found again where it now is, or dropped: never a span that holds something else.
// Texts are as the editor shows them, line breaks as \n.

/** A highlighted part of a request: its text and where it started. */
export interface Mark {
  at: number;
  text: string;
}

/** Most marks a tab keeps; `replay tabs save` refuses more. */
export const MAX_MARKS = 20;
/** Longest mark text kept; `replay tabs save` refuses longer. */
export const MAX_MARK_TEXT = 2000;

const lf = (s: string) => s.replace(/\r\n/g, "\n");

/** The forms a payload takes in a request: as typed, percent-encoded, in a JSON string. */
export function encodedForms(payload: string): string[] {
  if (!payload) return [];
  const forms = [payload];
  const add = (f: string) => {
    if (f && !forms.includes(f)) forms.push(f);
  };
  let pct = "";
  try {
    pct = encodeURIComponent(payload);
  } catch {
    /* a lone surrogate */
  }
  if (pct) {
    // encodeURIComponent leaves !'()* alone; scans and forms often encode them.
    const strict = pct.replace(/[!'()*]/g, (c) => "%" + c.charCodeAt(0).toString(16).toUpperCase());
    for (const f of [pct, strict]) {
      add(f);
      add(f.replace(/%20/g, "+"));
      add(f.replace(/%[0-9A-F]{2}/g, (h) => h.toLowerCase()));
    }
  }
  add(JSON.stringify(payload).slice(1, -1));
  return forms;
}

function decodings(s: string): string[] {
  const out = [s];
  for (const plus of [false, true]) {
    try {
      out.push(decodeURIComponent(plus ? s.replace(/\+/g, " ") : s));
    } catch {
      /* not percent-encoded */
    }
  }
  try {
    const j = JSON.parse(`"${s}"`);
    if (typeof j === "string") out.push(j);
  } catch {
    /* not a JSON string's inside */
  }
  return out;
}

/** Whether `changed` is the payload or part of it, in any of the forms it is sent in. */
export function isPayloadPart(changed: string, payload: string): boolean {
  if (!changed || !payload) return false;
  return decodings(changed).some((d) => d !== "" && (payload.includes(d) || d.includes(payload)));
}

function middle(a: string, b: string): [number, number] {
  let pre = 0;
  while (pre < a.length && pre < b.length && a[pre] === b[pre]) pre++;
  let suf = 0;
  while (suf < a.length - pre && suf < b.length - pre && a[a.length - 1 - suf] === b[b.length - 1 - suf]) suf++;
  return [pre, b.length - suf];
}

const SKIPPED = /^(content-length|connection)\s*:/i;

/**
 * Where `attack` differs from `base`: each changed head line's changed part (Content-Length and
 * Connection left out: a payload changes the one, a scan the other) and the body's. Null when
 * the heads have different numbers of lines, so lines can't be paired.
 */
export function changedSpans(base: string, attack: string): [number, number][] | null {
  const split = (m: string) => {
    const i = m.indexOf("\n\n");
    return i < 0 ? { head: m, body: "", bodyAt: m.length } : { head: m.slice(0, i), body: m.slice(i + 2), bodyAt: i + 2 };
  };
  const b = split(base);
  const a = split(attack);
  const bl = b.head.split("\n");
  const al = a.head.split("\n");
  if (bl.length !== al.length) return null;
  const spans: [number, number][] = [];
  let at = 0;
  al.forEach((line, i) => {
    if (line !== bl[i] && !SKIPPED.test(line)) {
      const [s, e] = middle(bl[i], line);
      spans.push([at + s, at + e]);
    }
    at += line.length + 1;
  });
  if (a.body !== b.body) {
    const [s, e] = middle(b.body, a.body);
    spans.push([a.bodyAt + s, a.bodyAt + e]);
  }
  return spans;
}

function occurrences(text: string, needle: string): number[] {
  const out: number[] = [];
  if (!needle) return out;
  for (let i = text.indexOf(needle); i >= 0; i = text.indexOf(needle, i + needle.length)) out.push(i);
  return out;
}

/**
 * The payload's marks in `attackRaw`. With the baseline (`baseRaw`), what the attack changed
 * that is (part of) the payload, widened to the whole payload where it is there; else, or when
 * nothing changed looks like the payload, each place one of its forms appears.
 */
export function payloadMarks(attackRaw: string, payload: string, baseRaw?: string | null): Mark[] {
  const attack = lf(attackRaw);
  const marks: Mark[] = [];
  if (baseRaw != null) {
    const spans = changedSpans(lf(baseRaw), attack) ?? [];
    for (const [s, e] of spans) {
      if (e <= s) continue;
      const text = attack.slice(s, e);
      // Without a payload to check against, every change is what the scan did.
      if (payload && !isPayloadPart(text, payload)) continue;
      // An attack that kept the value's start (hi -> hi') changed only its end: the whole
      // payload, when it is there around the change, is what was injected.
      const whole = payload ? widen(attack, s, e, payload) : null;
      marks.push(whole ?? { at: s, text });
    }
    if (marks.length) return capped(marks);
  }
  if (!payload) return [];
  // The longest forms first, so a form inside another doesn't mark part of it again.
  const taken: [number, number][] = [];
  for (const form of [...encodedForms(payload)].sort((x, y) => y.length - x.length)) {
    for (const at of occurrences(attack, form)) {
      const end = at + form.length;
      if (taken.some(([s, e]) => at < e && end > s)) continue;
      taken.push([at, end]);
      marks.push({ at, text: form });
    }
  }
  return capped(marks.sort((x, y) => x.at - y.at));
}

/** The payload, in one of its forms, around [s, e) of `text`; null if it isn't there. */
function widen(text: string, s: number, e: number, payload: string): Mark | null {
  for (const form of encodedForms(payload)) {
    for (let at = Math.max(0, e - form.length); at <= s; at++) {
      if (text.startsWith(form, at)) return { at, text: form };
    }
  }
  return null;
}

function capped(marks: Mark[]): Mark[] {
  return marks.filter((m) => m.text.length <= MAX_MARK_TEXT).slice(0, MAX_MARKS);
}

/**
 * Each mark's range in `text` as it is now (line breaks as \n): where it was if its text is
 * still there, else the nearest place its text is, else none. Ranges don't overlap.
 */
export function markRanges(text: string, marks: Mark[] | undefined): [number, number][] {
  if (!marks?.length) return [];
  const out: [number, number][] = [];
  for (const m of marks) {
    if (!m.text) continue;
    let at = text.startsWith(m.text, m.at) ? m.at : -1;
    if (at < 0) {
      let best = Infinity;
      for (const i of occurrences(text, m.text)) {
        if (Math.abs(i - m.at) < best) {
          best = Math.abs(i - m.at);
          at = i;
        }
      }
    }
    const end = at + m.text.length;
    if (at >= 0 && !out.some(([s, e]) => at < e && end > s)) out.push([at, end]);
  }
  return out.sort((x, y) => x[0] - y[0]);
}

/** Marks from a saved tab: well-formed ones only, at most MAX_MARKS. */
export function marksFromSaved(v: unknown): Mark[] | undefined {
  if (!Array.isArray(v)) return undefined;
  const marks = v
    .filter((m): m is Mark => !!m && typeof m === "object" && typeof (m as Mark).text === "string" && Number.isInteger((m as Mark).at) && (m as Mark).at >= 0)
    .map((m) => ({ at: m.at, text: m.text }));
  return marks.length ? capped(marks) : undefined;
}
