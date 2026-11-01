//! Findings against a baseline: new, unchanged, or fixed. Two ways to get there:
//!
//! - Against one scan in the project (`compare_scan`): what it found first, what it found
//!   again, and what it covered but no longer finds. A finding's last sighting is the time
//!   of its `last_history_id` exchange.
//! - Between two sets of findings (`compare_sets`), such as a saved `report json` and this
//!   run, matched by the identity findings are de-duplicated by (alert, method, URL without
//!   its query, parameter).

use std::collections::{HashMap, HashSet};
use std::path::Path;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::error::{Error, Result};
use crate::scan::findings_db::dedupe_key;
use crate::scan::Risk;
use crate::store::Store;

const FALSE_POSITIVE: &str = "false_positive";

/// One finding in a comparison. `id` is set only for findings of the open project.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Item {
    pub id: Option<i64>,
    pub alert_ref: String,
    pub name: String,
    pub risk: String,
    pub confidence: String,
    pub source: String,
    pub method: String,
    pub url: String,
    pub param: String,
    pub state: String,
}

impl Item {
    fn key(&self) -> String {
        dedupe_key(&self.alert_ref, &self.method, &self.url, &self.param)
    }

    pub fn false_positive(&self) -> bool {
        self.state == FALSE_POSITIVE
    }

    /// A risk this build doesn't know (from a file) counts as the highest, so a gate can't miss it.
    pub fn at_least(&self, risk: Risk) -> bool {
        Risk::parse(&self.risk).unwrap_or(Risk::High).level() >= risk.level()
    }
}

#[derive(Debug, Default, Clone, PartialEq)]
pub struct Comparison {
    pub new: Vec<Item>,
    pub unchanged: Vec<Item>,
    pub fixed: Vec<Item>,
    /// Findings a scan comparison says nothing about: outside what the scan covered.
    pub other: usize,
}

impl Comparison {
    /// What a severity gate fails on: open or confirmed findings at or above `risk` that are
    /// still there, or only the new ones. A fixed finding never counts.
    pub fn gate(&self, risk: Risk, new_only: bool) -> Vec<&Item> {
        let still: &[Item] = if new_only { &[] } else { &self.unchanged };
        self.new.iter().chain(still).filter(|f| !f.false_positive() && f.at_least(risk)).collect()
    }

    fn sort(mut self) -> Self {
        for list in [&mut self.new, &mut self.unchanged, &mut self.fixed] {
            let level = |f: &Item| Risk::parse(&f.risk).map_or(Risk::High.level(), Risk::level);
            list.sort_by(|a, b| {
                level(b).cmp(&level(a)).then_with(|| (&a.alert_ref, &a.url).cmp(&(&b.alert_ref, &b.url)))
            });
        }
        self
    }
}

/// Compares two sets by finding identity. A false-positive mark on either side stays with the
/// finding: rediscovering a finding triaged in the baseline doesn't reopen it, and one marked
/// here isn't "fixed" just because it is hidden.
pub fn compare_sets(baseline: Vec<Item>, current: Vec<Item>) -> Comparison {
    let mut base: HashMap<String, Item> = baseline.into_iter().map(|f| (f.key(), f)).collect();
    let mut out = Comparison::default();
    let mut seen = HashSet::new();
    for mut f in current {
        let key = f.key();
        if !seen.insert(key.clone()) {
            continue;
        }
        match base.remove(&key) {
            Some(old) => {
                if old.false_positive() {
                    f.state = FALSE_POSITIVE.into();
                }
                out.unchanged.push(f);
            }
            None => out.new.push(f),
        }
    }
    out.fixed = base.into_values().collect();
    out.sort()
}

/// What a scan covered. `origins`: its sites (None = everything recorded, empty = only requests
/// picked by a filter, so no whole site). `rules`: the ported rules it ran (None = all of them,
/// less `exclude_rules`). `check_ids`: the declarative checks known to have run: those named by
/// id. Without ids, which checks ran depends on their severity and tags, which findings don't
/// record, so no check finding is taken as covered. `end` is None while the scan runs.
/// `new_since`, before `start`, widens "new" to a finding the scan found again that was first
/// seen since then: by a scan that failed in between, say, whose findings no gate looked at.
#[derive(Debug, Clone, Default, PartialEq, Serialize)]
pub struct ScanScope {
    pub start: String,
    pub end: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub new_since: Option<String>,
    pub origins: Option<Vec<String>>,
    pub rules: Option<Vec<i64>>,
    pub exclude_rules: Vec<i64>,
    pub ported_rules: bool,
    pub check_ids: Vec<String>,
    pub crawled: bool,
}

/// How one finding relates to a scan.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Seen {
    New,
    Still,
    Gone,
    Other,
}

/// The facts about a finding that a scan comparison needs.
#[derive(Debug, Clone, Copy)]
pub struct Sighting<'a> {
    pub time: &'a str,
    /// When last seen: the time of its last exchange, or `time` without one.
    pub last: &'a str,
    pub source: &'a str,
    pub rule_id: i64,
    pub alert_ref: &'a str,
    pub url: &'a str,
}

impl ScanScope {
    /// "Gone" needs the scan to have covered the finding: its site, and its rule for an active
    /// finding. A passive finding (headers, cookies, ...) only counts when the scan crawled,
    /// since the attack requests themselves aren't passively scanned.
    fn covers(&self, f: &Sighting) -> bool {
        // The finding's URL starts with a scanned origin and a "/" (so :80 doesn't match :8080).
        let site = self.origins.as_ref().is_none_or(|origins| {
            origins.iter().any(|o| f.url.strip_prefix(o.as_str()).is_some_and(|rest| rest.starts_with('/')))
        });
        site && match f.source {
            "active" => match f.alert_ref.strip_prefix("check:") {
                Some(id) => self.check_ids.iter().any(|c| c == id),
                None => {
                    self.ported_rules
                        && self.rules.as_ref().is_none_or(|r| r.contains(&f.rule_id))
                        && !self.exclude_rules.contains(&f.rule_id)
                }
            },
            "passive" => self.crawled && self.rules.is_none(),
            _ => false,
        }
    }

    /// Timestamps are all the same UTC format, so they compare as text.
    pub fn classify(&self, f: &Sighting) -> Seen {
        if self.end.as_deref().is_some_and(|end| f.time > end) {
            Seen::Other
        } else if f.time >= self.start.as_str() {
            Seen::New
        } else if f.last >= self.start.as_str() {
            if self.new_since.as_deref().is_some_and(|since| f.time >= since) {
                Seen::New
            } else {
                Seen::Still
            }
        } else if self.covers(f) {
            Seen::Gone
        } else {
            Seen::Other
        }
    }
}

/// Every finding of the project against one scan.
pub fn compare_scan(store: &Store, scope: &ScanScope) -> Result<Comparison> {
    let mut stmt = store.conn.prepare(
        "SELECT f.id, f.alert_ref, f.name, f.risk, f.confidence, f.source, f.method, f.url, f.param, f.state,
            f.time, coalesce(h.time, f.time), f.rule_id
         FROM findings f LEFT JOIN history h ON h.id = f.last_history_id",
    )?;
    let mut rows = stmt.query([])?;
    let mut out = Comparison::default();
    while let Some(r) = rows.next()? {
        let f = item(r)?;
        let (time, last): (String, String) = (r.get(10)?, r.get(11)?);
        let sighting = Sighting {
            time: &time,
            last: &last,
            source: &f.source,
            rule_id: r.get(12)?,
            alert_ref: &f.alert_ref,
            url: &f.url,
        };
        match scope.classify(&sighting) {
            Seen::New => out.new.push(f),
            Seen::Still => out.unchanged.push(f),
            Seen::Gone => out.fixed.push(f),
            Seen::Other => out.other += 1,
        }
    }
    Ok(out.sort())
}

fn item(r: &rusqlite::Row) -> rusqlite::Result<Item> {
    Ok(Item {
        id: r.get(0)?,
        alert_ref: r.get(1)?,
        name: r.get(2)?,
        risk: r.get(3)?,
        confidence: r.get(4)?,
        source: r.get(5)?,
        method: r.get(6)?,
        url: r.get(7)?,
        param: r.get(8)?,
        state: r.get(9)?,
    })
}

/// Every finding of a project, false positives included.
pub fn project_items(store: &Store) -> Result<Vec<Item>> {
    let mut stmt = store
        .conn
        .prepare("SELECT id, alert_ref, name, risk, confidence, source, method, url, param, state FROM findings")?;
    let rows = stmt.query_map([], item)?;
    Ok(rows.collect::<std::result::Result<_, _>>()?)
}

/// A findings set read from a file.
#[derive(Debug, Default)]
pub struct LoadedSet {
    pub items: Vec<Item>,
    /// Why the set may be narrower than it looks.
    pub warnings: Vec<String>,
}

/// Loads a findings set from `report json` output: the file `--output` writes or a captured JSON
/// envelope. Project files are refused: read-only, a project's latest captures may not have been
/// passively scanned, and over MCP it would reach past the project the server was given. Error
/// messages never quote the file, since over MCP this reads a path an agent chose.
pub fn load_set(path: &Path) -> Result<LoadedSet> {
    let bytes = match std::fs::read(path) {
        Ok(b) => b,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Err(Error::NotFound(format!("findings file {}", path.display())));
        }
        Err(e) => return Err(e.into()),
    };
    if bytes.starts_with(b"SQLite format 3\0") {
        return Err(Error::InvalidInput(format!(
            "{} is a project file; write its findings with `report json --state all --output FILE`",
            path.display()
        )));
    }
    let not_report = || Error::InvalidInput(format!("{} is not `report json` output", path.display()));
    let mut v: Value = serde_json::from_slice(&bytes).map_err(|_| not_report())?;
    // `report json > file` when stdout isn't a terminal: the report is the envelope's data.
    if v.get("ok").is_some() && v.get("data").is_some() {
        v = v["data"].take();
    }
    let report: SavedReport = serde_json::from_value(v).map_err(|_| not_report())?;
    if report.summary.truncated {
        return Err(Error::InvalidInput(format!(
            "{} holds only part of its findings, so the rest would look new or fixed; \
             write it again with a higher `report --limit`",
            path.display()
        )));
    }
    let mut warnings = Vec::new();
    let mut narrowed: Vec<&str> = ["min_risk", "min_confidence", "host", "alert", "source"]
        .into_iter()
        .filter(|k| !report.filters[k].is_null())
        .collect();
    // `report` shows open and confirmed findings by default, and false positives only add to that.
    if !matches!(report.filters["state"].as_str(), None | Some("open,confirmed" | "all")) {
        narrowed.push("state");
    }
    if !narrowed.is_empty() {
        warnings.push(format!(
            "{} was written with filters ({}): findings they left out count as absent from it",
            path.display(),
            narrowed.join(", ")
        ));
    }
    let items = report
        .alerts
        .into_iter()
        .flat_map(|a| {
            let (alert_ref, name) = (a.alert_ref, a.name);
            a.instances.into_iter().map(move |i| Item {
                id: None,
                alert_ref: alert_ref.clone(),
                name: name.clone(),
                risk: i.risk,
                confidence: i.confidence,
                source: i.source,
                method: i.method,
                url: i.url,
                param: i.param,
                state: i.state,
            })
        })
        .collect();
    Ok(LoadedSet { items, warnings })
}

/// The parts of a `report json` that identify its findings.
#[derive(Deserialize)]
struct SavedReport {
    #[serde(default)]
    filters: Value,
    summary: SavedSummary,
    alerts: Vec<SavedAlert>,
}

#[derive(Deserialize)]
struct SavedSummary {
    truncated: bool,
}

#[derive(Deserialize)]
struct SavedAlert {
    alert_ref: String,
    name: String,
    instances: Vec<SavedInstance>,
}

#[derive(Deserialize)]
struct SavedInstance {
    risk: String,
    confidence: String,
    source: String,
    method: String,
    url: String,
    param: String,
    state: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capture::Capture;
    use crate::http::Target;
    use crate::scan::passive;
    use crate::scan::report::{self, ReportKind, ReportOptions};

    fn f(alert_ref: &str, url: &str, risk: &str, state: &str) -> Item {
        Item {
            id: None,
            alert_ref: alert_ref.into(),
            name: alert_ref.into(),
            risk: risk.into(),
            confidence: "medium".into(),
            source: "active".into(),
            method: "GET".into(),
            url: url.into(),
            param: String::new(),
            state: state.into(),
        }
    }

    fn urls(list: &[Item]) -> Vec<&str> {
        list.iter().map(|f| f.url.as_str()).collect()
    }

    #[test]
    fn sets_compare_by_identity() {
        let c = compare_sets(
            vec![f("1", "http://a/same?x=1", "high", "open"), f("1", "http://a/gone", "low", "open")],
            vec![
                f("1", "http://a/same?x=2", "high", "open"), // The query isn't part of the identity.
                f("1", "http://a/fresh", "medium", "open"),
                f("2", "http://a/same", "low", "open"), // Another alert on the same URL.
            ],
        );
        assert_eq!(urls(&c.unchanged), ["http://a/same?x=2"]);
        assert_eq!(urls(&c.new), ["http://a/fresh", "http://a/same"]);
        assert_eq!(urls(&c.fixed), ["http://a/gone"]);
    }

    #[test]
    fn false_positive_marks_survive_either_side() {
        // Triaged in the baseline, rediscovered open here: stays a false positive.
        let c =
            compare_sets(vec![f("1", "http://a/", "high", FALSE_POSITIVE)], vec![f("1", "http://a/", "high", "open")]);
        assert!(c.unchanged[0].false_positive());
        assert!(c.gate(Risk::Info, false).is_empty());
        // Marked here: still found, so not fixed.
        let c =
            compare_sets(vec![f("1", "http://a/", "high", "open")], vec![f("1", "http://a/", "high", FALSE_POSITIVE)]);
        assert!(c.fixed.is_empty());
        assert!(c.unchanged[0].false_positive());
        assert!(c.gate(Risk::Info, false).is_empty());
    }

    #[test]
    fn gate_is_at_or_above_and_can_be_new_only() {
        let c = compare_sets(
            vec![f("1", "http://a/old", "high", "open"), f("1", "http://a/fixed", "high", "open")],
            vec![
                f("1", "http://a/old", "high", "open"),
                f("1", "http://a/m", "medium", "confirmed"),
                f("1", "http://a/l", "low", "open"),
                f("1", "http://a/fp", "high", FALSE_POSITIVE),
            ],
        );
        let hits = |risk, new_only| c.gate(risk, new_only).iter().map(|f| f.url.as_str()).collect::<Vec<_>>();
        assert_eq!(hits(Risk::High, false), ["http://a/old"]);
        assert!(hits(Risk::High, true).is_empty());
        assert_eq!(hits(Risk::Medium, true), ["http://a/m"]);
        assert_eq!(hits(Risk::Low, true), ["http://a/m", "http://a/l"]);
        // A risk from a file that this build doesn't know can't slip through.
        let odd = compare_sets(vec![], vec![f("1", "http://a/", "critical", "open")]);
        assert_eq!(odd.gate(Risk::High, true).len(), 1);
    }

    fn scope() -> ScanScope {
        ScanScope {
            start: "2026-10-22T10:00:00.000Z".into(),
            end: Some("2026-10-22T11:00:00.000Z".into()),
            origins: Some(vec!["http://a.test".into()]),
            rules: Some(vec![40018]),
            ported_rules: true,
            ..Default::default()
        }
    }

    // id, first seen, last seen, source, rule, alert, url.
    const BEFORE: &str = "2026-10-21T09:00:00.000Z";
    const DURING: &str = "2026-10-22T10:10:00.000Z";
    const AFTER: &str = "2026-10-22T12:00:00.000Z";
    const ROWS: &[(i64, &str, &str, &str, i64, &str, &str)] = &[
        (1, DURING, DURING, "active", 40018, "40018", "http://a.test/x"), // First seen by the scan.
        (2, BEFORE, DURING, "active", 40018, "40018", "http://a.test/"),  // Seen before and again.
        (3, BEFORE, BEFORE, "active", 40018, "40018", "http://a.test/y?q=1"), // Not seen again: gone.
        (4, BEFORE, BEFORE, "active", 40018, "40018", "http://a.test:8080/"), // Another service on the host.
        (5, BEFORE, BEFORE, "active", 10020, "10020", "http://a.test/"),  // A rule the scan didn't run.
        (6, BEFORE, BEFORE, "passive", 10020, "10020", "http://a.test/"), // Passive, scan didn't crawl.
        (7, AFTER, AFTER, "active", 40018, "40018", "http://a.test/"),    // After the scan.
        (8, BEFORE, BEFORE, "active", 0, "check:cve-1", "http://a.test/"), // A declarative check.
    ];

    fn seen(s: &ScanScope, id: i64) -> Seen {
        let r = ROWS.iter().find(|r| r.0 == id).unwrap();
        s.classify(&Sighting { time: r.1, last: r.2, source: r.3, rule_id: r.4, alert_ref: r.5, url: r.6 })
    }

    fn all(s: &ScanScope) -> Vec<Seen> {
        ROWS.iter().map(|r| seen(s, r.0)).collect()
    }

    #[test]
    fn findings_are_new_still_gone_or_outside_the_scan() {
        use Seen::*;
        assert_eq!(all(&scope()), [New, Still, Gone, Other, Other, Other, Other, Other]);
        // A crawl with every rule covers passive findings and every active rule on the site,
        // not checks it didn't run.
        let crawl = ScanScope { rules: None, crawled: true, ..scope() };
        assert_eq!(all(&crawl), [New, Still, Gone, Other, Gone, Gone, Other, Other]);
        // Excluded rules, and ported rules under --no-rules, aren't covered; the checks named are.
        assert_eq!(seen(&ScanScope { rules: None, exclude_rules: vec![40018], ..scope() }, 3), Other);
        let checks_only = ScanScope { rules: None, ported_rules: false, check_ids: vec!["cve-1".into()], ..scope() };
        assert_eq!([seen(&checks_only, 3), seen(&checks_only, 5), seen(&checks_only, 8)], [Other, Other, Gone]);
        // A scan of picked requests covers no site; one of everything recorded covers every site.
        assert_eq!(seen(&ScanScope { origins: Some(vec![]), ..scope() }, 3), Other);
        assert_eq!(seen(&ScanScope { origins: None, ..scope() }, 4), Gone);
        // While a scan runs nothing is after its end.
        assert_eq!(seen(&ScanScope { end: None, ..scope() }, 7), New);
    }

    #[test]
    fn new_since_an_earlier_scan_counts_what_a_failed_run_saw_first() {
        use Seen::*;
        let after = |since: &str| ScanScope { new_since: Some(since.into()), ..scope() };
        // Since before /'s first sighting: found again, it is new; not found again, still gone.
        assert_eq!(all(&after("2026-10-21T08:00:00.000Z")), [New, New, Gone, Other, Other, Other, Other, Other]);
        // At the very time it was first seen, too.
        assert_eq!(seen(&after(BEFORE), 2), New);
        // Since after it: unchanged, as without.
        assert_eq!(all(&after("2026-10-21T10:00:00.000Z")), all(&scope()));
    }

    fn store_with_findings() -> Store {
        let mut s = Store::open_in_memory().unwrap();
        let target = Target { scheme: "http".into(), host: "app.test".into(), port: 80 };
        let req = b"GET /a?q=1 HTTP/1.1\r\nHost: app.test\r\n\r\n";
        let resp = b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nX-Powered-By: PHP/5.1\r\nContent-Length: 13\r\n\r\n<html></html>";
        s.record(&Capture::new("send", &target, req, Some(resp), Some(5), None)).unwrap();
        passive::scan_pending(&mut s).unwrap();
        s
    }

    fn temp(name: &str, content: &[u8]) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("bp-compare-{}-{name}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("f");
        std::fs::write(&path, content).unwrap();
        path
    }

    #[test]
    fn a_saved_report_loads_as_the_same_findings() {
        let s = store_with_findings();
        let live = project_items(&s).unwrap();
        assert!(!live.is_empty());
        let r = report::build(&s, &ReportOptions::default()).unwrap();
        let text = report::render(&r, ReportKind::Json);

        // Both the file `report --output` writes and a captured envelope.
        let file = temp("report", text.as_bytes());
        let envelope = format!(r#"{{"ok":true,"command":"report","data":{text}}}"#);
        for path in [file, temp("envelope", envelope.as_bytes())] {
            let set = load_set(&path).unwrap();
            assert!(set.warnings.is_empty(), "{:?}", set.warnings);
            let c = compare_sets(set.items, live.clone());
            assert!(c.new.is_empty() && c.fixed.is_empty(), "{c:?}");
            assert_eq!(c.unchanged.len(), live.len());
        }
    }

    #[test]
    fn a_cut_or_narrowed_report_is_not_taken_at_face_value() {
        let s = store_with_findings();
        let cut = report::build(&s, &ReportOptions { limit: 1, ..Default::default() }).unwrap();
        assert!(cut.summary.truncated);
        let path = temp("cut", report::render(&cut, ReportKind::Json).as_bytes());
        assert!(matches!(load_set(&path), Err(Error::InvalidInput(_))));

        let mut opts = ReportOptions::default();
        opts.filter.min_risk = Some(Risk::Low);
        let narrowed = report::build(&s, &opts).unwrap();
        let path = temp("narrowed", report::render(&narrowed, ReportKind::Json).as_bytes());
        assert!(load_set(&path).unwrap().warnings[0].contains("min_risk"));

        let mut opts = ReportOptions::default();
        opts.filter.state = Some("confirmed".into());
        let path = temp("state", report::render(&report::build(&s, &opts).unwrap(), ReportKind::Json).as_bytes());
        assert!(load_set(&path).unwrap().warnings[0].contains("state"));
        opts.filter.state = Some("all".into());
        let path = temp("state-all", report::render(&report::build(&s, &opts).unwrap(), ReportKind::Json).as_bytes());
        assert!(load_set(&path).unwrap().warnings.is_empty());
    }

    #[test]
    fn bad_files_fail_without_quoting_them() {
        for (name, content) in
            [("empty", ""), ("text", "secret"), ("string", "\"secret\""), ("other", r#"{"a":"secret"}"#)]
        {
            let e = load_set(&temp(name, content.as_bytes())).unwrap_err();
            assert!(matches!(e, Error::InvalidInput(_)), "{e}");
            assert!(!e.to_string().contains("secret"), "{e}");
        }
        assert!(matches!(load_set(Path::new("/no/such/file")), Err(Error::NotFound(_))));
        let e = load_set(&temp("sqlite", b"SQLite format 3\0rest")).unwrap_err();
        assert!(e.to_string().contains("report json"), "{e}");
    }

    #[test]
    fn compare_scan_reads_the_project() {
        let s = store_with_findings();
        let total = project_items(&s).unwrap().len();
        // Everything recorded so far is before a scan starting in the future, and passive
        // findings count as covered when it crawled.
        let later = ScanScope {
            start: "2999-01-01T00:00:00.000Z".into(),
            crawled: true,
            ported_rules: true,
            ..Default::default()
        };
        let c = compare_scan(&s, &later).unwrap();
        assert_eq!((c.new.len(), c.unchanged.len(), c.fixed.len(), c.other), (0, 0, total, 0));
        assert!(c.fixed[0].id.is_some());
        // And all of it is inside a window from the start of time.
        let c =
            compare_scan(&s, &ScanScope { start: "2000-01-01T00:00:00.000Z".into(), ..Default::default() }).unwrap();
        assert_eq!((c.new.len(), c.fixed.len()), (total, 0));
    }
}
