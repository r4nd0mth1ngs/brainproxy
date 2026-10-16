//! Comparer: line, word, or byte diffs between two messages.

use serde::Serialize;
use similar::{ChangeTag, TextDiffConfig};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DiffMode {
    Lines,
    Words,
    Bytes,
}

#[derive(Debug, Clone, Serialize)]
pub struct Change {
    /// "delete" (only in A) or "insert" (only in B).
    pub op: &'static str,
    /// 1-based line in A (deletes) or B (inserts); line mode only.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub line: Option<usize>,
    pub text: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct DiffResult {
    pub identical: bool,
    /// Similarity ratio from 0.0 to 1.0.
    pub similarity: f32,
    pub deletions: usize,
    pub insertions: usize,
    pub changes: Vec<Change>,
    pub truncated: bool,
    /// Unified diff text (line mode) for humans and models that read patches well.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub unified: Option<String>,
}

pub fn diff(a: &[u8], b: &[u8], mode: DiffMode, max_changes: usize, context: usize) -> DiffResult {
    let (a, b) = (String::from_utf8_lossy(a), String::from_utf8_lossy(b));
    let mut cfg = TextDiffConfig::default();
    cfg.timeout(std::time::Duration::from_secs(5));
    let d = match mode {
        DiffMode::Lines => cfg.diff_lines(&a, &b),
        DiffMode::Words => cfg.diff_words(&a, &b),
        DiffMode::Bytes => cfg.diff_chars(&a, &b),
    };
    let mut changes = Vec::new();
    let (mut deletions, mut insertions) = (0, 0);
    let mut truncated = false;
    let mut prev = ChangeTag::Equal;
    for change in d.iter_all_changes() {
        let adjacent = prev == change.tag();
        prev = change.tag();
        let op = match change.tag() {
            ChangeTag::Equal => continue,
            ChangeTag::Delete => {
                deletions += 1;
                "delete"
            }
            ChangeTag::Insert => {
                insertions += 1;
                "insert"
            }
        };
        if changes.len() >= max_changes {
            truncated = true;
            continue;
        }
        // Merge consecutive word/char changes of the same kind into one run.
        let text = change.value().to_string();
        if mode != DiffMode::Lines {
            if let Some(last) = changes.last_mut().filter(|c: &&mut Change| adjacent && c.op == op) {
                last.text.push_str(&text);
                continue;
            }
        }
        let line = (mode == DiffMode::Lines)
            .then(|| if op == "delete" { change.old_index() } else { change.new_index() }.map(|i| i + 1))
            .flatten();
        changes.push(Change { op, line, text: text.trim_end_matches(['\r', '\n']).to_string() });
    }
    DiffResult {
        identical: deletions == 0 && insertions == 0,
        similarity: d.ratio(),
        deletions,
        insertions,
        truncated,
        unified: (mode == DiffMode::Lines && !(deletions == 0 && insertions == 0))
            .then(|| d.unified_diff().context_radius(context).header("a", "b").to_string()),
        changes,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn line_and_word_diffs() {
        let a = b"HTTP/1.1 200 OK\r\nSet-Cookie: s=1\r\n\r\nhello world";
        let b = b"HTTP/1.1 200 OK\r\nSet-Cookie: s=2\r\n\r\nhello there world";
        let d = diff(a, b, DiffMode::Lines, 100, 1);
        assert!(!d.identical);
        assert_eq!((d.deletions, d.insertions), (2, 2));
        assert_eq!(d.changes[0].line, Some(2));
        assert!(d.unified.unwrap().contains("-Set-Cookie: s=1"));

        let d = diff(a, b, DiffMode::Words, 100, 1);
        let inserted: Vec<&str> = d.changes.iter().filter(|c| c.op == "insert").map(|c| c.text.as_str()).collect();
        assert!(inserted.contains(&"s=2"), "{:?}", d.changes);
        assert!(diff(a, a, DiffMode::Bytes, 10, 1).identical);
    }
}
