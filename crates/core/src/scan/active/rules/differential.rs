//! The boolean differential the LDAP (40015) and XPath (90021) rules share: a pair of values
//! that differ only in a condition that is always true or always false once the value is
//! read as part of a query. Read as plain data, both are just two unknown values and give the
//! same page; read as a query, one of them gives the original page and the other doesn't.
//!
//! Pages are compared by the words they contain (a Dice score over word counts), with the
//! values sent stripped, also HTML or JSON escaped and with HTML entities decoded (an app that
//! echoes its whole query, entity-encoded, echoes the attack too). The original page is
//! requested twice first: how much it changes by itself is the noise every other comparison
//! is measured against, and a page that changes too much is not tested. When the two differ
//! less with every word that has a digit in it taken as the same word (a clock, a counter, a
//! session or CSRF token), pages are compared that way. A pair that passes is sent again,
//! with the original, and must give the same answer.

use std::collections::HashMap;

use crate::scan::active::{Cx, Response};

use super::injection::common::{strip_off_both, unescape_html4};

/// Above this distance between two requests for the original page, nothing is comparable.
const MAX_NOISE: f64 = 0.15;
/// How far above the noise a page may be and still be "the same page".
const SAME_SLACK: f64 = 0.01;
/// The least distance, besides twice the noise, that makes a page "a different page".
const DIFF_MIN: f64 = 0.03;

/// Which value of the pair gave the original page.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Kept {
    /// The always-true condition: it was ANDed with the original condition.
    ByTrue,
    /// The always-false condition: it was ORed with the original condition.
    ByFalse,
}

/// `body` with the values sent taken out, in the forms an app may echo them. Entities are
/// decoded first: stripping the original value out of an entity-encoded attack would leave
/// the rest of the attack behind.
fn normalize(body: &str, a: &str, b: &str) -> String {
    strip_off_both(&unescape_html4(body), a, b)
}

/// How pages are compared for one insertion point.
#[derive(Debug, Clone, Copy, PartialEq)]
struct Scale {
    /// The distance between two requests for the original page.
    noise: f64,
    /// Words with a digit in them all count as the same word.
    mask: bool,
}

fn words(s: &str, mask: bool) -> HashMap<&str, u32> {
    let mut m = HashMap::new();
    for w in s.split(|c: char| !c.is_alphanumeric()).filter(|w| !w.is_empty()) {
        let w = if mask && w.contains(|c: char| c.is_ascii_digit()) { "0" } else { w };
        *m.entry(w).or_insert(0) += 1;
    }
    m
}

/// 1 minus the Dice score of the two texts' word counts: 0 for the same words, 1 for none shared.
fn word_distance(a: &str, b: &str, mask: bool) -> f64 {
    let (wa, wb) = (words(a, mask), words(b, mask));
    let total: u32 = wa.values().sum::<u32>() + wb.values().sum::<u32>();
    if total == 0 {
        return 0.0;
    }
    let shared: u32 = wa.iter().map(|(w, n)| (*n).min(wb.get(w).copied().unwrap_or(0))).sum();
    1.0 - f64::from(2 * shared) / f64::from(total)
}

/// How different two pages are, with the values sent for each stripped from both. A different
/// status is a different page.
fn distance(a: &Response, a_sent: &str, b: &Response, b_sent: &str, mask: bool) -> f64 {
    if a.status != b.status {
        return 1.0;
    }
    word_distance(&normalize(a.body_str(), a_sent, b_sent), &normalize(b.body_str(), a_sent, b_sent), mask)
}

/// How to compare pages, from two requests for the original page (sent `orig`); None when
/// they differ too much to compare anything.
fn scale(one: &Response, two: &Response, orig: &str) -> Option<Scale> {
    let raw = distance(one, orig, two, orig, false);
    let masked = distance(one, orig, two, orig, true);
    let scale = if masked < raw { Scale { noise: masked, mask: true } } else { Scale { noise: raw, mask: false } };
    (scale.noise <= MAX_NOISE).then_some(scale)
}

/// An answer the app gave on purpose: not a server error or a rate limit.
fn ordinary(r: &Response) -> bool {
    r.status < 500 && r.status != 429
}

/// Which of the pair kept the original page (`base`, for `orig`) while the other clearly
/// changed it, if one did. "The same" and "different" are both measured against the noise.
fn verdict(sc: Scale, orig: &str, base: &Response, t: (&Response, &str), f: (&Response, &str)) -> Option<Kept> {
    if !ordinary(t.0) || !ordinary(f.0) {
        return None;
    }
    let same = |d: f64| d <= sc.noise + SAME_SLACK;
    let differs = |d: f64| d >= 2.0 * sc.noise + DIFF_MIN;
    if !differs(distance(t.0, t.1, f.0, f.1, sc.mask)) {
        return None;
    }
    let dt = distance(base, orig, t.0, t.1, sc.mask);
    let df = distance(base, orig, f.0, f.1, sc.mask);
    if same(dt) && differs(df) {
        Some(Kept::ByTrue)
    } else if same(df) && differs(dt) {
        Some(Kept::ByFalse)
    } else {
        None
    }
}

/// The original page and how much it changes by itself, for one insertion point.
pub(super) struct Differential<'a> {
    cx: &'a Cx,
    orig: String,
    scale: Scale,
}

impl<'a> Differential<'a> {
    /// Requests the original page twice; None when it fails, is an error, or is too unstable.
    pub(super) async fn new(cx: &'a Cx) -> Option<Differential<'a>> {
        let orig = cx.point().value.clone();
        let one = cx.send(cx.base_request().to_vec()).await.ok()?;
        let two = cx.send(cx.base_request().to_vec()).await.ok()?;
        if !ordinary(&one) || !ordinary(&two) {
            return None;
        }
        let scale = scale(&one, &two, &orig)?;
        Some(Differential { cx, orig, scale })
    }

    /// Which value kept the original page while the other clearly changed it, if one did.
    fn verdict(&self, base: &Response, t: (&Response, &str), f: (&Response, &str)) -> Option<Kept> {
        verdict(self.scale, &self.orig, base, t, f)
    }

    /// Sends the pair, and when one value keeps the original page and the other changes it,
    /// sends the original and the pair again: the second round must agree. Returns which
    /// kept it and the response to the always-true value.
    pub(super) async fn test(&self, t: &str, f: &str) -> Option<(Kept, Response)> {
        let base = self.cx.send(self.cx.base_request().to_vec()).await.ok()?;
        let tr = self.cx.send_payload(t).await.ok()?;
        let fr = self.cx.send_payload(f).await.ok()?;
        let kept = self.verdict(&base, (&tr, t), (&fr, f))?;
        if self.cx.stopped() {
            return None;
        }
        let base2 = self.cx.send(self.cx.base_request().to_vec()).await.ok()?;
        let tr2 = self.cx.send_payload(t).await.ok()?;
        let fr2 = self.cx.send_payload(f).await.ok()?;
        (self.verdict(&base2, (&tr2, t), (&fr2, f)) == Some(kept)).then_some((kept, tr))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn resp(status: u16, body: &str) -> Response {
        Response::recorded(status, vec![], body.as_bytes().to_vec())
    }

    #[test]
    fn word_distance_scores() {
        assert_eq!(word_distance("", "", false), 0.0);
        assert_eq!(word_distance("<p>a b</p>", "<p>a b</p>", false), 0.0);
        assert_eq!(word_distance("a b", "c d", false), 1.0);
        // Words are counted: a repeated row is a difference.
        assert!(word_distance("<li>x</li>", "<li>x</li><li>x</li>", false) > 0.2);
        // Masked, words with digits are one word.
        assert_eq!(word_distance("at 10:31 token a9f3", "at 10:32 token 77bc", true), 0.0);
        assert!(word_distance("at 10:31 token a9f3", "at 10:32 token 77bc", false) > 0.3);
    }

    #[test]
    fn echoed_values_are_stripped_also_entity_encoded() {
        let orig = "alice";
        let attack = "alice)(objectClass=*";
        let a = resp(200, "nothing found for (uid=alice)");
        let b = resp(200, "nothing found for &#x28;uid&#x3d;alice&#x29;&#x28;objectClass&#x3d;&#x2a;&#x29;");
        assert_eq!(distance(&a, orig, &b, attack, false), 0.0);
        let c = resp(500, "nothing found for (uid=alice)");
        assert_eq!(distance(&a, orig, &c, orig, false), 1.0);
    }

    fn diff(noise: f64, mask: bool) -> impl Fn(&Response, (&Response, &str), (&Response, &str)) -> Option<Kept> {
        move |base, t, f| verdict(Scale { noise, mask }, "alice", base, t, f)
    }

    #[test]
    fn verdicts() {
        let v = diff(0.0, false);
        let found = resp(200, "<p>alice: Alice Smith, 1 Main St</p>");
        let none = resp(200, "<p>nothing found</p>");
        let all = resp(200, "<p>alice: Alice Smith, 1 Main St</p><p>bob: Bob Jones, 2 High St</p>");
        // ANDed: true keeps the record, false loses it.
        assert_eq!(v(&found, (&found, "t"), (&none, "f")), Some(Kept::ByTrue));
        // ORed: true finds everyone, false keeps the record.
        assert_eq!(v(&found, (&all, "t"), (&found, "f")), Some(Kept::ByFalse));
        // Read as data: both unknown values find nothing.
        assert_eq!(v(&found, (&none, "t"), (&none, "f")), None);
        assert_eq!(v(&none, (&none, "t"), (&none, "f")), None);
        // An error is not an answer.
        assert_eq!(v(&found, (&found, "t"), (&resp(500, "<p>nothing found</p>"), "f")), None);
        assert_eq!(v(&found, (&found, "t"), (&resp(429, "<p>slow down</p>"), "f")), None);
    }

    fn page(n: u32, rows: &str) -> Response {
        resp(200, &format!("<html><title>Directory</title><p>Rendered at {n}</p><p>Search results</p>{rows}</html>"))
    }

    #[test]
    fn noise_raises_the_bar() {
        let base = page(1, "<p>alice Alice Smith</p>");
        let t = page(2, "<p>alice Alice Smith</p>");
        let f = page(3, "");
        let noise = distance(&page(1, ""), "alice", &page(9, ""), "alice", false);
        assert!(noise > 0.0 && noise < MAX_NOISE, "{noise}");
        assert_eq!(diff(noise, false)(&base, (&t, "t"), (&f, "f")), Some(Kept::ByTrue));
        // The clock alone is no difference.
        assert_eq!(diff(noise, false)(&base, (&t, "t"), (&page(4, "<p>alice Alice Smith</p>"), "f")), None);
    }

    #[test]
    fn a_clock_is_masked() {
        let sc = scale(&page(1, ""), &page(9, ""), "alice").expect("stable once masked");
        assert_eq!(sc, Scale { noise: 0.0, mask: true });
        // Static pages compare every word.
        assert_eq!(scale(&page(1, ""), &page(1, ""), "alice"), Some(Scale { noise: 0.0, mask: false }));
        // Too different to compare.
        assert_eq!(scale(&resp(200, "a b c d"), &resp(200, "e f g h"), "alice"), None);
    }
}
