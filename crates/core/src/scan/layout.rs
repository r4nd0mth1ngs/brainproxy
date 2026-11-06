//! How a report looks: which sections it has (an audience preset, or a list of its own),
//! and the branding on its cover. Saved layouts are report profiles, kept in the project.

use std::str::FromStr;

use rusqlite::{params, OptionalExtension};
use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};
use crate::store::Store;

/// Schema v16: saved report layouts, and a CVSS 4.0 vector on each issue.
pub(crate) fn migrate_v16(conn: &rusqlite::Connection) -> Result<()> {
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS report_profiles (
            name TEXT PRIMARY KEY,
            layout TEXT NOT NULL,
            updated TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
        );",
    )?;
    for (column, kind) in [("cvss_vector", "TEXT"), ("cvss_score", "REAL")] {
        if !crate::store::has_column(conn, "issues", column)? {
            conn.execute_batch(&format!("ALTER TABLE issues ADD COLUMN {column} {kind};"))?;
        }
    }
    Ok(())
}

pub const PROFILE_COLUMNS: &[(&str, &str, &str)] = &[
    ("name", "TEXT", "Profile name (`report --profile NAME`)"),
    ("layout", "TEXT", "JSON: preset, sections, company, accent, logo (a data: URI), since"),
    ("updated", "TEXT", "UTC time it was last saved"),
];

/// Who a report is for, which picks its sections.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Preset {
    /// Everything: summary, priorities, every issue with its evidence.
    #[default]
    Technical,
    /// Two pages for management: verdict, priorities, posture, the list of issues.
    Executive,
    /// One section per issue with what to fix, the evidence and how to reproduce it.
    Developer,
    /// What changed since a date: fixed, still there, come back, with the retests as proof.
    Retest,
}

impl Preset {
    pub fn as_str(self) -> &'static str {
        match self {
            Preset::Technical => "technical",
            Preset::Executive => "executive",
            Preset::Developer => "developer",
            Preset::Retest => "retest",
        }
    }

    pub fn sections(self) -> &'static [Section] {
        use Section::*;
        match self {
            Preset::Technical => &[Summary, FixFirst, List, Issues, Evidence, About],
            Preset::Executive => &[Summary, FixFirst, Posture, List, About],
            Preset::Developer => &[List, Issues, Evidence, Reproduce],
            Preset::Retest => &[Retest, About],
        }
    }
}

impl FromStr for Preset {
    type Err = Error;
    fn from_str(s: &str) -> Result<Self> {
        match s {
            "technical" => Ok(Preset::Technical),
            "executive" => Ok(Preset::Executive),
            "developer" => Ok(Preset::Developer),
            "retest" => Ok(Preset::Retest),
            _ => Err(Error::InvalidInput(format!("unknown preset {s:?}: technical, executive, developer or retest"))),
        }
    }
}

/// A part of a report.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Section {
    /// At a glance: the verdict, counts by risk, what was tested.
    Summary,
    /// Fix these first: the ten most serious issues and their fixes.
    #[serde(rename = "fixfirst")]
    FixFirst,
    /// Open issues by risk, what recent scans found new and no longer found, retests.
    Posture,
    /// The table of every issue.
    List,
    /// A section per issue: what it means, how to fix it, where it was found.
    Issues,
    /// Each finding's technical details and the request and response that show it.
    Evidence,
    /// A curl command per finding to send its request again.
    Reproduce,
    /// What changed since `since`: fixed, still there, come back.
    Retest,
    /// How to read the report.
    About,
}

pub const SECTIONS: &[(&str, Section)] = &[
    ("summary", Section::Summary),
    ("fixfirst", Section::FixFirst),
    ("posture", Section::Posture),
    ("list", Section::List),
    ("issues", Section::Issues),
    ("evidence", Section::Evidence),
    ("reproduce", Section::Reproduce),
    ("retest", Section::Retest),
    ("about", Section::About),
];

impl FromStr for Section {
    type Err = Error;
    fn from_str(s: &str) -> Result<Self> {
        SECTIONS.iter().find(|(n, _)| *n == s).map(|(_, x)| *x).ok_or_else(|| {
            let names: Vec<&str> = SECTIONS.iter().map(|(n, _)| *n).collect();
            Error::InvalidInput(format!("unknown section {s:?}: {}", names.join(", ")))
        })
    }
}

/// Largest logo, in bytes of the image.
pub const MAX_LOGO: usize = 256 * 1024;

/// A report's layout and branding.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Layout {
    #[serde(default)]
    pub preset: Preset,
    /// Sections in place of the preset's, in the report's own order.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sections: Option<Vec<Section>>,
    /// Who the report is from, on the cover.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub company: Option<String>,
    /// A `data:image/...;base64,` URI for the cover.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub logo: Option<String>,
    /// `#rrggbb` for headings and the cover.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub accent: Option<String>,
    /// For the retest section: changes from this day (YYYY-MM-DD) or time on.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub since: Option<String>,
}

impl Layout {
    /// Whether the report has `s`. Evidence and reproduction lines sit in the issue
    /// sections, so either brings them in.
    pub fn has(&self, s: Section) -> bool {
        let listed = |x: Section| match &self.sections {
            Some(list) => list.contains(&x),
            None => self.preset.sections().contains(&x),
        };
        match s {
            Section::Issues => listed(Section::Issues) || listed(Section::Evidence) || listed(Section::Reproduce),
            _ => listed(s),
        }
    }

    /// Checks what came from the user: an accent colour, a logo, a date.
    pub fn validate(&self) -> Result<()> {
        if let Some(a) = &self.accent {
            let hex = a.strip_prefix('#').unwrap_or("");
            if hex.len() != 6 || !hex.chars().all(|c| c.is_ascii_hexdigit()) {
                return Err(Error::InvalidInput(format!("accent {a:?}: give a colour as #rrggbb")));
            }
        }
        if let Some(l) = &self.logo {
            let ok = [
                "data:image/png;base64,",
                "data:image/jpeg;base64,",
                "data:image/gif;base64,",
                "data:image/webp;base64,",
            ]
            .iter()
            .any(|p| l.starts_with(p));
            let b64 = l.split_once(',').map(|(_, b)| b).unwrap_or("");
            if !ok || !b64.chars().all(|c| c.is_ascii_alphanumeric() || "+/=".contains(c)) {
                return Err(Error::InvalidInput("logo: a PNG, JPEG, GIF or WebP image".into()));
            }
        }
        if let Some(d) = &self.since {
            let b = d.as_bytes();
            let num = |r: std::ops::Range<usize>| d.get(r).and_then(|x| x.parse::<u32>().ok()).unwrap_or(0);
            let shaped = b.len() == 10
                && b[4] == b'-'
                && b[7] == b'-'
                && b.iter().enumerate().all(|(i, c)| i == 4 || i == 7 || c.is_ascii_digit())
                && (1..=12).contains(&num(5..7))
                && (1..=31).contains(&num(8..10));
            if !shaped {
                return Err(Error::InvalidInput(format!("since {d:?}: give a day as YYYY-MM-DD")));
            }
        }
        if let Some(c) = &self.company {
            if c.chars().count() > 200 {
                return Err(Error::InvalidInput("company: at most 200 characters".into()));
            }
        }
        Ok(())
    }

    /// `other`'s settings over this one's, where it has them.
    pub fn overlay(mut self, other: &LayoutArgs) -> Self {
        if let Some(p) = other.preset {
            self.preset = p;
            // A preset named now picks its own sections, unless sections are named too.
            self.sections = None;
        }
        if let Some(s) = &other.sections {
            self.sections = Some(s.clone());
        }
        // Given empty, a setting is cleared rather than left as the base has it.
        for (mine, theirs) in [
            (&mut self.company, &other.company),
            (&mut self.logo, &other.logo),
            (&mut self.accent, &other.accent),
            (&mut self.since, &other.since),
        ] {
            if let Some(v) = theirs {
                *mine = Some(v.clone()).filter(|v| !v.trim().is_empty());
            }
        }
        self
    }
}

/// Layout settings given for one report, each optional.
#[derive(Debug, Clone, Default)]
pub struct LayoutArgs {
    pub preset: Option<Preset>,
    pub sections: Option<Vec<Section>>,
    pub company: Option<String>,
    pub logo: Option<String>,
    pub accent: Option<String>,
    pub since: Option<String>,
}

/// A logo file as a data URI, checked by its first bytes.
pub fn logo_data_uri(bytes: &[u8]) -> Result<String> {
    use base64::Engine;
    if bytes.len() > MAX_LOGO {
        return Err(Error::InvalidInput(format!("logo: at most {} KiB", MAX_LOGO / 1024)));
    }
    let mime = if bytes.starts_with(b"\x89PNG\r\n\x1a\n") {
        "image/png"
    } else if bytes.starts_with(&[0xff, 0xd8, 0xff]) {
        "image/jpeg"
    } else if bytes.starts_with(b"GIF87a") || bytes.starts_with(b"GIF89a") {
        "image/gif"
    } else if bytes.len() > 12 && &bytes[..4] == b"RIFF" && &bytes[8..12] == b"WEBP" {
        "image/webp"
    } else {
        // SVG can carry script and links; a raster image can't.
        return Err(Error::InvalidInput("logo: a PNG, JPEG, GIF or WebP image".into()));
    };
    Ok(format!("data:{mime};base64,{}", base64::engine::general_purpose::STANDARD.encode(bytes)))
}

impl Store {
    pub fn report_profile_save(&self, name: &str, layout: &Layout) -> Result<()> {
        let name = name.trim();
        if name.is_empty() || name.len() > 64 {
            return Err(Error::InvalidInput("a profile name has 1 to 64 characters".into()));
        }
        layout.validate()?;
        let json = serde_json::to_string(layout).map_err(|e| Error::InvalidInput(e.to_string()))?;
        self.conn.execute(
            "INSERT INTO report_profiles (name, layout) VALUES (?1, ?2)
             ON CONFLICT(name) DO UPDATE SET layout = excluded.layout,
                updated = strftime('%Y-%m-%dT%H:%M:%fZ','now')",
            params![name, json],
        )?;
        Ok(())
    }

    pub fn report_profile(&self, name: &str) -> Result<Layout> {
        let json: String = self
            .conn
            .query_row("SELECT layout FROM report_profiles WHERE name = ?1", [name], |r| r.get(0))
            .optional()?
            .ok_or_else(|| Error::NotFound(format!("report profile {name:?}")))?;
        serde_json::from_str(&json).map_err(|e| Error::InvalidInput(format!("report profile {name:?}: {e}")))
    }

    /// Every profile: (name, layout, updated), by name.
    pub fn report_profiles(&self) -> Result<Vec<(String, Layout, String)>> {
        let mut stmt = self.conn.prepare("SELECT name, layout, updated FROM report_profiles ORDER BY name")?;
        let rows =
            stmt.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?, r.get::<_, String>(2)?)))?;
        let mut out = Vec::new();
        for row in rows {
            let (name, json, updated) = row?;
            out.push((name, serde_json::from_str(&json).unwrap_or_default(), updated));
        }
        Ok(out)
    }

    pub fn report_profile_remove(&self, name: &str) -> Result<()> {
        if self.conn.execute("DELETE FROM report_profiles WHERE name = ?1", [name])? == 0 {
            return Err(Error::NotFound(format!("report profile {name:?}")));
        }
        Ok(())
    }

    /// Sets (or with "" clears) an issue's CVSS 4.0 vector; returns its score.
    pub fn issue_set_cvss(&mut self, id: i64, vector: &str) -> Result<Option<f64>> {
        let parsed = match vector.trim() {
            "" => None,
            v => Some(crate::scan::cvss::Cvss4::parse(v)?),
        };
        let tx = self.write_tx()?;
        let old: Option<String> = tx
            .query_row("SELECT cvss_vector FROM issues WHERE id = ?1", [id], |r| r.get(0))
            .optional()?
            .ok_or_else(|| Error::NotFound(format!("issue {id}")))?;
        let (vector, score) = match &parsed {
            Some(c) => (Some(c.vector()), Some(c.score())),
            None => (None, None),
        };
        tx.execute("UPDATE issues SET cvss_vector = ?1, cvss_score = ?2 WHERE id = ?3", params![vector, score, id])?;
        crate::scan::issues::record(
            &tx,
            &crate::scan::issues::Event {
                issue: Some(id),
                kind: "cvss",
                old: old.as_deref(),
                new: vector.as_deref(),
                ..Default::default()
            },
        )?;
        tx.commit()?;
        Ok(score)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn presets_pick_sections_and_flags_override() {
        let l = Layout::default();
        assert!(l.has(Section::Evidence) && !l.has(Section::Posture));
        let exec = l.clone().overlay(&LayoutArgs { preset: Some(Preset::Executive), ..Default::default() });
        assert!(exec.has(Section::Posture) && !exec.has(Section::Evidence));
        let own = exec.overlay(&LayoutArgs { sections: Some(vec![Section::List]), ..Default::default() });
        assert!(own.has(Section::List) && !own.has(Section::Summary));
        // Evidence lives in the issue sections, so it brings them.
        let ev = own.overlay(&LayoutArgs { sections: Some(vec![Section::Evidence]), ..Default::default() });
        assert!(ev.has(Section::Issues) && ev.has(Section::Evidence));
        assert_eq!("fixfirst".parse::<Section>().unwrap(), Section::FixFirst);
        assert!("cover".parse::<Section>().is_err());
        // An empty setting clears what the base had.
        let branded = Layout { company: Some("Acme".into()), accent: Some("#000000".into()), ..Default::default() };
        let cleared = branded.overlay(&LayoutArgs { company: Some(String::new()), ..Default::default() });
        assert_eq!((cleared.company, cleared.accent.as_deref()), (None, Some("#000000")));
    }

    #[test]
    fn branding_is_checked() {
        let bad = |l: Layout| l.validate().is_err();
        assert!(bad(Layout { accent: Some("red".into()), ..Default::default() }));
        assert!(bad(Layout { accent: Some("#12345g".into()), ..Default::default() }));
        assert!(Layout { accent: Some("#1a2B3c".into()), ..Default::default() }.validate().is_ok());
        assert!(bad(Layout { logo: Some("data:image/svg+xml;base64,PHN2Zy8+".into()), ..Default::default() }));
        assert!(bad(Layout { logo: Some("data:image/png;base64,AA\"><script>".into()), ..Default::default() }));
        assert!(bad(Layout { since: Some("last week".into()), ..Default::default() }));
        assert!(bad(Layout { since: Some("2026-11-01<script>".into()), ..Default::default() }));
        assert!(bad(Layout { since: Some("2026-13-01".into()), ..Default::default() }));
        assert!(Layout { since: Some("2026-11-01".into()), ..Default::default() }.validate().is_ok());
        assert!(logo_data_uri(b"<svg onload=alert(1)>").is_err());
        let png = logo_data_uri(b"\x89PNG\r\n\x1a\nrest").unwrap();
        assert!(png.starts_with("data:image/png;base64,"));
        assert!(Layout { logo: Some(png), ..Default::default() }.validate().is_ok());
    }

    #[test]
    fn profiles_and_cvss_are_kept() {
        let mut s = Store::open_in_memory().unwrap();
        let l = Layout { preset: Preset::Executive, company: Some("Acme".into()), ..Default::default() };
        s.report_profile_save("board", &l).unwrap();
        assert_eq!(s.report_profile("board").unwrap(), l);
        assert_eq!(s.report_profiles().unwrap().len(), 1);
        assert!(s.report_profile_save("bad", &Layout { accent: Some("x".into()), ..Default::default() }).is_err());
        s.report_profile_remove("board").unwrap();
        assert!(matches!(s.report_profile("board"), Err(Error::NotFound(_))));
        s.conn.execute("INSERT INTO issues (alert_ref, host) VALUES ('x', 'a.test')", []).unwrap();
        let id = s.conn.last_insert_rowid();
        let score = s.issue_set_cvss(id, "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N").unwrap();
        assert_eq!(score, Some(9.3));
        assert!(s.issue_set_cvss(id, "CVSS:3.1/AV:N").is_err());
        assert_eq!(s.issue_set_cvss(id, "").unwrap(), None);
    }
}
