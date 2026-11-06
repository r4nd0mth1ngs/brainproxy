//! CVSS 4.0 vectors: parsing, the base/threat/environmental score, and its severity.
//!
//! The score is FIRST's macrovector method: a vector falls in one of 270 macrovectors (six
//! equivalence classes, EQ1 to EQ6), each scored by experts, and is then moved down within its
//! macrovector by how far it sits from the macrovector's most severe vectors. The table and
//! the method follow FIRST's reference calculator (github.com/FIRSTdotorg/cvss-v4-calculator,
//! BSD-2-Clause, Copyright FIRST, Red Hat, and contributors).

use std::collections::HashMap;

use crate::error::{Error, Result};

/// CVSS 4.0 macrovector scores (EQ1..EQ6 digits), from FIRST's reference calculator
/// (cvss_lookup.js, BSD-2-Clause, Copyright FIRST, Red Hat, and contributors).
const LOOKUP: [(&str, f64); 270] = [
    ("000000", 10.0),
    ("000001", 9.9),
    ("000010", 9.8),
    ("000011", 9.5),
    ("000020", 9.5),
    ("000021", 9.2),
    ("000100", 10.0),
    ("000101", 9.6),
    ("000110", 9.3),
    ("000111", 8.7),
    ("000120", 9.1),
    ("000121", 8.1),
    ("000200", 9.3),
    ("000201", 9.0),
    ("000210", 8.9),
    ("000211", 8.0),
    ("000220", 8.1),
    ("000221", 6.8),
    ("001000", 9.8),
    ("001001", 9.5),
    ("001010", 9.5),
    ("001011", 9.2),
    ("001020", 9.0),
    ("001021", 8.4),
    ("001100", 9.3),
    ("001101", 9.2),
    ("001110", 8.9),
    ("001111", 8.1),
    ("001120", 8.1),
    ("001121", 6.5),
    ("001200", 8.8),
    ("001201", 8.0),
    ("001210", 7.8),
    ("001211", 7.0),
    ("001220", 6.9),
    ("001221", 4.8),
    ("002001", 9.2),
    ("002011", 8.2),
    ("002021", 7.2),
    ("002101", 7.9),
    ("002111", 6.9),
    ("002121", 5.0),
    ("002201", 6.9),
    ("002211", 5.5),
    ("002221", 2.7),
    ("010000", 9.9),
    ("010001", 9.7),
    ("010010", 9.5),
    ("010011", 9.2),
    ("010020", 9.2),
    ("010021", 8.5),
    ("010100", 9.5),
    ("010101", 9.1),
    ("010110", 9.0),
    ("010111", 8.3),
    ("010120", 8.4),
    ("010121", 7.1),
    ("010200", 9.2),
    ("010201", 8.1),
    ("010210", 8.2),
    ("010211", 7.1),
    ("010220", 7.2),
    ("010221", 5.3),
    ("011000", 9.5),
    ("011001", 9.3),
    ("011010", 9.2),
    ("011011", 8.5),
    ("011020", 8.5),
    ("011021", 7.3),
    ("011100", 9.2),
    ("011101", 8.2),
    ("011110", 8.0),
    ("011111", 7.2),
    ("011120", 7.0),
    ("011121", 5.9),
    ("011200", 8.4),
    ("011201", 7.0),
    ("011210", 7.1),
    ("011211", 5.2),
    ("011220", 5.0),
    ("011221", 3.0),
    ("012001", 8.6),
    ("012011", 7.5),
    ("012021", 5.2),
    ("012101", 7.1),
    ("012111", 5.2),
    ("012121", 2.9),
    ("012201", 6.3),
    ("012211", 2.9),
    ("012221", 1.7),
    ("100000", 9.8),
    ("100001", 9.5),
    ("100010", 9.4),
    ("100011", 8.7),
    ("100020", 9.1),
    ("100021", 8.1),
    ("100100", 9.4),
    ("100101", 8.9),
    ("100110", 8.6),
    ("100111", 7.4),
    ("100120", 7.7),
    ("100121", 6.4),
    ("100200", 8.7),
    ("100201", 7.5),
    ("100210", 7.4),
    ("100211", 6.3),
    ("100220", 6.3),
    ("100221", 4.9),
    ("101000", 9.4),
    ("101001", 8.9),
    ("101010", 8.8),
    ("101011", 7.7),
    ("101020", 7.6),
    ("101021", 6.7),
    ("101100", 8.6),
    ("101101", 7.6),
    ("101110", 7.4),
    ("101111", 5.8),
    ("101120", 5.9),
    ("101121", 5.0),
    ("101200", 7.2),
    ("101201", 5.7),
    ("101210", 5.7),
    ("101211", 5.2),
    ("101220", 5.2),
    ("101221", 2.5),
    ("102001", 8.3),
    ("102011", 7.0),
    ("102021", 5.4),
    ("102101", 6.5),
    ("102111", 5.8),
    ("102121", 2.6),
    ("102201", 5.3),
    ("102211", 2.1),
    ("102221", 1.3),
    ("110000", 9.5),
    ("110001", 9.0),
    ("110010", 8.8),
    ("110011", 7.6),
    ("110020", 7.6),
    ("110021", 7.0),
    ("110100", 9.0),
    ("110101", 7.7),
    ("110110", 7.5),
    ("110111", 6.2),
    ("110120", 6.1),
    ("110121", 5.3),
    ("110200", 7.7),
    ("110201", 6.6),
    ("110210", 6.8),
    ("110211", 5.9),
    ("110220", 5.2),
    ("110221", 3.0),
    ("111000", 8.9),
    ("111001", 7.8),
    ("111010", 7.6),
    ("111011", 6.7),
    ("111020", 6.2),
    ("111021", 5.8),
    ("111100", 7.4),
    ("111101", 5.9),
    ("111110", 5.7),
    ("111111", 5.7),
    ("111120", 4.7),
    ("111121", 2.3),
    ("111200", 6.1),
    ("111201", 5.2),
    ("111210", 5.7),
    ("111211", 2.9),
    ("111220", 2.4),
    ("111221", 1.6),
    ("112001", 7.1),
    ("112011", 5.9),
    ("112021", 3.0),
    ("112101", 5.8),
    ("112111", 2.6),
    ("112121", 1.5),
    ("112201", 2.3),
    ("112211", 1.3),
    ("112221", 0.6),
    ("200000", 9.3),
    ("200001", 8.7),
    ("200010", 8.6),
    ("200011", 7.2),
    ("200020", 7.5),
    ("200021", 5.8),
    ("200100", 8.6),
    ("200101", 7.4),
    ("200110", 7.4),
    ("200111", 6.1),
    ("200120", 5.6),
    ("200121", 3.4),
    ("200200", 7.0),
    ("200201", 5.4),
    ("200210", 5.2),
    ("200211", 4.0),
    ("200220", 4.0),
    ("200221", 2.2),
    ("201000", 8.5),
    ("201001", 7.5),
    ("201010", 7.4),
    ("201011", 5.5),
    ("201020", 6.2),
    ("201021", 5.1),
    ("201100", 7.2),
    ("201101", 5.7),
    ("201110", 5.5),
    ("201111", 4.1),
    ("201120", 4.6),
    ("201121", 1.9),
    ("201200", 5.3),
    ("201201", 3.6),
    ("201210", 3.4),
    ("201211", 1.9),
    ("201220", 1.9),
    ("201221", 0.8),
    ("202001", 6.4),
    ("202011", 5.1),
    ("202021", 2.0),
    ("202101", 4.7),
    ("202111", 2.1),
    ("202121", 1.1),
    ("202201", 2.4),
    ("202211", 0.9),
    ("202221", 0.4),
    ("210000", 8.8),
    ("210001", 7.5),
    ("210010", 7.3),
    ("210011", 5.3),
    ("210020", 6.0),
    ("210021", 5.0),
    ("210100", 7.3),
    ("210101", 5.5),
    ("210110", 5.9),
    ("210111", 4.0),
    ("210120", 4.1),
    ("210121", 2.0),
    ("210200", 5.4),
    ("210201", 4.3),
    ("210210", 4.5),
    ("210211", 2.2),
    ("210220", 2.0),
    ("210221", 1.1),
    ("211000", 7.5),
    ("211001", 5.5),
    ("211010", 5.8),
    ("211011", 4.5),
    ("211020", 4.0),
    ("211021", 2.1),
    ("211100", 6.1),
    ("211101", 5.1),
    ("211110", 4.8),
    ("211111", 1.8),
    ("211120", 2.0),
    ("211121", 0.9),
    ("211200", 4.6),
    ("211201", 1.8),
    ("211210", 1.7),
    ("211211", 0.7),
    ("211220", 0.8),
    ("211221", 0.2),
    ("212001", 5.3),
    ("212011", 2.4),
    ("212021", 1.4),
    ("212101", 2.4),
    ("212111", 1.2),
    ("212121", 0.5),
    ("212201", 1.0),
    ("212211", 0.3),
    ("212221", 0.1),
];

/// The most severe vectors of each EQ level (`max_composed.js`).
fn max_composed(eq: usize, level: u8, eq6: u8) -> &'static [&'static str] {
    match (eq, level, eq6) {
        (1, 0, _) => &["AV:N/PR:N/UI:N/"],
        (1, 1, _) => &["AV:A/PR:N/UI:N/", "AV:N/PR:L/UI:N/", "AV:N/PR:N/UI:P/"],
        (1, 2, _) => &["AV:P/PR:N/UI:N/", "AV:A/PR:L/UI:P/"],
        (2, 0, _) => &["AC:L/AT:N/"],
        (2, 1, _) => &["AC:H/AT:N/", "AC:L/AT:P/"],
        (3, 0, 0) => &["VC:H/VI:H/VA:H/CR:H/IR:H/AR:H/"],
        (3, 0, 1) => &["VC:H/VI:H/VA:L/CR:M/IR:M/AR:H/", "VC:H/VI:H/VA:H/CR:M/IR:M/AR:M/"],
        (3, 1, 0) => &["VC:L/VI:H/VA:H/CR:H/IR:H/AR:H/", "VC:H/VI:L/VA:H/CR:H/IR:H/AR:H/"],
        (3, 1, 1) => &[
            "VC:L/VI:H/VA:L/CR:H/IR:M/AR:H/",
            "VC:L/VI:H/VA:H/CR:H/IR:M/AR:M/",
            "VC:H/VI:L/VA:H/CR:M/IR:H/AR:M/",
            "VC:H/VI:L/VA:L/CR:M/IR:H/AR:H/",
            "VC:L/VI:L/VA:H/CR:H/IR:H/AR:M/",
        ],
        (3, 2, 1) => &["VC:L/VI:L/VA:L/CR:H/IR:H/AR:H/"],
        (4, 0, _) => &["SC:H/SI:S/SA:S/"],
        (4, 1, _) => &["SC:H/SI:H/SA:H/"],
        (4, 2, _) => &["SC:L/SI:L/SA:L/"],
        (5, 0, _) => &["E:A/"],
        (5, 1, _) => &["E:P/"],
        (5, 2, _) => &["E:U/"],
        _ => &[],
    }
}

/// The largest severity distance within each EQ level, plus one (`max_severity.js`), in steps of 0.1.
fn max_severity(eq: &str, level: u8, eq6: u8) -> f64 {
    let n = match (eq, level, eq6) {
        ("eq1", 0, _) => 1,
        ("eq1", 1, _) => 4,
        ("eq1", 2, _) => 5,
        ("eq2", 0, _) => 1,
        ("eq2", 1, _) => 2,
        ("eq3eq6", 0, 0) => 7,
        ("eq3eq6", 0, 1) => 6,
        ("eq3eq6", 1, _) => 8,
        ("eq3eq6", 2, _) => 10,
        ("eq4", 0, _) => 6,
        ("eq4", 1, _) => 5,
        ("eq4", 2, _) => 4,
        _ => 1,
    };
    f64::from(n) * 0.1
}

/// Metrics and the values each takes; the first eleven are the base metrics every vector has.
const METRICS: &[(&str, &[&str])] = &[
    ("AV", &["N", "A", "L", "P"]),
    ("AC", &["L", "H"]),
    ("AT", &["N", "P"]),
    ("PR", &["N", "L", "H"]),
    ("UI", &["N", "P", "A"]),
    ("VC", &["H", "L", "N"]),
    ("VI", &["H", "L", "N"]),
    ("VA", &["H", "L", "N"]),
    ("SC", &["H", "L", "N"]),
    ("SI", &["H", "L", "N"]),
    ("SA", &["H", "L", "N"]),
    ("E", &["X", "A", "P", "U"]),
    ("CR", &["X", "H", "M", "L"]),
    ("IR", &["X", "H", "M", "L"]),
    ("AR", &["X", "H", "M", "L"]),
    ("MAV", &["X", "N", "A", "L", "P"]),
    ("MAC", &["X", "L", "H"]),
    ("MAT", &["X", "N", "P"]),
    ("MPR", &["X", "N", "L", "H"]),
    ("MUI", &["X", "N", "P", "A"]),
    ("MVC", &["X", "H", "L", "N"]),
    ("MVI", &["X", "H", "L", "N"]),
    ("MVA", &["X", "H", "L", "N"]),
    ("MSC", &["X", "H", "L", "N"]),
    ("MSI", &["X", "S", "H", "L", "N"]),
    ("MSA", &["X", "S", "H", "L", "N"]),
    ("S", &["X", "N", "P"]),
    ("AU", &["X", "N", "Y"]),
    ("R", &["X", "A", "U", "I"]),
    ("V", &["X", "D", "C"]),
    ("RE", &["X", "L", "M", "H"]),
    ("U", &["X", "Clear", "Green", "Amber", "Red"]),
];
const BASE: usize = 11;

/// A parsed CVSS 4.0 vector.
#[derive(Debug, Clone, PartialEq)]
pub struct Cvss4 {
    metrics: HashMap<&'static str, String>,
}

impl Cvss4 {
    /// Parses `CVSS:4.0/AV:N/...`: every base metric once, others at most once, in any order.
    pub fn parse(vector: &str) -> Result<Self> {
        let bad = |why: String| Error::InvalidInput(format!("CVSS vector {vector:?}: {why}"));
        let rest = vector
            .trim()
            .strip_prefix("CVSS:4.0/")
            .ok_or_else(|| bad("a CVSS 4.0 vector starts with CVSS:4.0/".into()))?;
        let mut metrics = HashMap::new();
        for part in rest.split('/') {
            let (k, v) = part.split_once(':').ok_or_else(|| bad(format!("{part:?} is not METRIC:VALUE")))?;
            let (name, values) =
                METRICS.iter().find(|(m, _)| *m == k).ok_or_else(|| bad(format!("unknown metric {k}")))?;
            if !values.contains(&v) {
                return Err(bad(format!("{k} takes {}, not {v}", values.join(", "))));
            }
            if metrics.insert(*name, v.to_string()).is_some() {
                return Err(bad(format!("{k} is given twice")));
            }
        }
        if let Some((m, _)) = METRICS[..BASE].iter().find(|(m, _)| !metrics.contains_key(m)) {
            return Err(bad(format!("the base metric {m} is missing")));
        }
        Ok(Self { metrics })
    }

    /// The vector in the specification's order, without metrics left at X (not defined).
    pub fn vector(&self) -> String {
        let mut out = String::from("CVSS:4.0");
        for (m, _) in METRICS {
            if let Some(v) = self.metrics.get(m).filter(|v| *v != "X") {
                out.push_str(&format!("/{m}:{v}"));
            }
        }
        out
    }

    /// The value scoring uses: the modified metric when given, X defaults filled in.
    fn m(&self, metric: &str) -> &str {
        let given = |k: &str| self.metrics.get(k).map(String::as_str).filter(|v| *v != "X");
        match metric {
            "E" => given("E").unwrap_or("A"),
            "CR" | "IR" | "AR" => given(metric).unwrap_or("H"),
            _ => {
                let modified = format!("M{metric}");
                given(&modified).or_else(|| given(metric)).unwrap_or("X")
            }
        }
    }

    /// The macrovector: the EQ1 to EQ6 levels.
    fn macro_vector(&self) -> [u8; 6] {
        let m = |k| self.m(k);
        let (av, pr, ui) = (m("AV"), m("PR"), m("UI"));
        let eq1 = if av == "N" && pr == "N" && ui == "N" {
            0
        } else if (av == "N" || pr == "N" || ui == "N") && av != "P" {
            1
        } else {
            2
        };
        let eq2 = if m("AC") == "L" && m("AT") == "N" { 0 } else { 1 };
        let (vc, vi, va) = (m("VC"), m("VI"), m("VA"));
        let eq3 = if vc == "H" && vi == "H" {
            0
        } else if vc == "H" || vi == "H" || va == "H" {
            1
        } else {
            2
        };
        let eq4 = if m("MSI") == "S" || m("MSA") == "S" {
            0
        } else if m("SC") == "H" || m("SI") == "H" || m("SA") == "H" {
            1
        } else {
            2
        };
        let eq5 = match m("E") {
            "A" => 0,
            "P" => 1,
            _ => 2,
        };
        let eq6 = if (m("CR") == "H" && vc == "H") || (m("IR") == "H" && vi == "H") || (m("AR") == "H" && va == "H") {
            0
        } else {
            1
        };
        [eq1, eq2, eq3, eq4, eq5, eq6]
    }

    /// The score, 0.0 to 10.0, rounded to one decimal.
    pub fn score(&self) -> f64 {
        if ["VC", "VI", "VA", "SC", "SI", "SA"].iter().all(|k| self.m(k) == "N") {
            return 0.0;
        }
        let mv = self.macro_vector();
        let key = |v: [u8; 6]| v.iter().map(|d| char::from(b'0' + d)).collect::<String>();
        let lookup = |v: [u8; 6]| LOOKUP.iter().find(|(k, _)| *k == key(v)).map(|(_, s)| *s);
        let Some(value) = lookup(mv) else { return 0.0 };
        let [eq1, eq2, eq3, eq4, eq5, eq6] = mv;
        let lower = |i: usize| {
            let mut v = mv;
            v[i] += 1;
            lookup(v)
        };
        let eq3eq6_lower = match (eq3, eq6) {
            (0, 0) => {
                let left = lookup([eq1, eq2, eq3, eq4, eq5, eq6 + 1]);
                let right = lookup([eq1, eq2, eq3 + 1, eq4, eq5, eq6]);
                // As the reference does: the right one unless the left is higher, and
                // nothing when the one taken doesn't exist.
                match (left, right) {
                    (Some(l), Some(r)) => Some(l.max(r)),
                    (_, r) => r,
                }
            }
            (1, 0) => lookup([eq1, eq2, eq3, eq4, eq5, eq6 + 1]),
            (0 | 1, 1) => lookup([eq1, eq2, eq3 + 1, eq4, eq5, eq6]),
            _ => lookup([eq1, eq2, eq3 + 1, eq4, eq5, eq6 + 1]),
        };

        // The first most-severe vector of the macrovector that this vector doesn't exceed.
        let level = |metric: &str, v: &str| -> f64 {
            match (metric, v) {
                ("AV", "N") | ("PR", "N") | ("UI", "N") | ("AC", "L") | ("AT", "N") => 0.0,
                ("AV", "A") | ("PR", "L") | ("UI", "P") | ("AC", "H") | ("AT", "P") => 0.1,
                ("AV", "L") | ("PR", "H") | ("UI", "A") => 0.2,
                ("AV", "P") => 0.3,
                ("VC" | "VI" | "VA" | "CR" | "IR" | "AR", "H") => 0.0,
                ("VC" | "VI" | "VA", "L") | ("CR" | "IR" | "AR", "M") => 0.1,
                ("VC" | "VI" | "VA", "N") | ("CR" | "IR" | "AR", "L") => 0.2,
                ("SC", "H") => 0.1,
                ("SC", "L") => 0.2,
                ("SC", "N") => 0.3,
                ("SI" | "SA", "S") => 0.0,
                ("SI" | "SA", "H") => 0.1,
                ("SI" | "SA", "L") => 0.2,
                ("SI" | "SA", "N") => 0.3,
                _ => 0.0,
            }
        };
        let extract = |metric: &str, max: &str| -> String {
            max.split('/').find_map(|p| p.strip_prefix(&format!("{metric}:"))).unwrap_or("").to_string()
        };
        const DIST: [&str; 14] = ["AV", "PR", "UI", "AC", "AT", "VC", "VI", "VA", "SC", "SI", "SA", "CR", "IR", "AR"];
        let mut maxes = Vec::new();
        for a in max_composed(1, eq1, 0) {
            for b in max_composed(2, eq2, 0) {
                for c in max_composed(3, eq3, eq6) {
                    for d in max_composed(4, eq4, 0) {
                        for e in max_composed(5, eq5, 0) {
                            maxes.push(format!("{a}{b}{c}{d}{e}"));
                        }
                    }
                }
            }
        }
        let mut dist: HashMap<&str, f64> = HashMap::new();
        for max in &maxes {
            dist = DIST.iter().map(|&k| (k, level(k, self.m(k)) - level(k, &extract(k, max)))).collect();
            if dist.values().all(|d| *d >= 0.0) {
                break;
            }
        }
        let d = |k: &str| dist.get(k).copied().unwrap_or(0.0);
        let current = [
            d("AV") + d("PR") + d("UI"),
            d("AC") + d("AT"),
            d("VC") + d("VI") + d("VA") + d("CR") + d("IR") + d("AR"),
            d("SC") + d("SI") + d("SA"),
        ];
        let max_sev = [
            max_severity("eq1", eq1, 0),
            max_severity("eq2", eq2, 0),
            max_severity("eq3eq6", eq3, eq6),
            max_severity("eq4", eq4, 0),
        ];
        let lowers = [lower(0), lower(1), eq3eq6_lower, lower(3)];
        let mut n = 0;
        let mut total = 0.0;
        for i in 0..4 {
            if let Some(next) = lowers[i] {
                n += 1;
                total += (value - next) * (current[i] / max_sev[i]);
            }
        }
        // EQ5 moves the score only between macrovectors.
        if lower(4).is_some() {
            n += 1;
        }
        let mean = if n == 0 { 0.0 } else { total / f64::from(n) };
        let score = (value - mean).clamp(0.0, 10.0);
        (score * 10.0).round() / 10.0
    }
}

/// The severity a score falls in: none, low, medium, high or critical.
pub fn severity(score: f64) -> &'static str {
    match score {
        s if s >= 9.0 => "critical",
        s if s >= 7.0 => "high",
        s if s >= 4.0 => "medium",
        s if s > 0.0 => "low",
        _ => "none",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn score(v: &str) -> f64 {
        Cvss4::parse(v).unwrap().score()
    }

    #[test]
    fn scores_match_published_examples() {
        // Scores as FIRST's calculator and NVD give them.
        for (v, want) in [
            ("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N", 9.3),
            ("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H", 10.0),
            ("CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N", 8.7),
            ("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N", 6.9),
            ("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:H/SC:N/SI:N/SA:N", 8.7),
            // Reflected XSS: a click (passive) or an active interaction.
            ("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:A/VC:N/VI:N/VA:N/SC:L/SI:L/SA:N", 5.1),
            ("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:P/VC:N/VI:N/VA:N/SC:L/SI:L/SA:N", 5.3),
            ("CVSS:4.0/AV:L/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N", 8.5),
            ("CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N", 5.3),
            ("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:N/SI:N/SA:N", 0.0),
        ] {
            assert_eq!(score(v), want, "{v}");
        }
        assert_eq!(severity(9.3), "critical");
        assert_eq!(severity(5.1), "medium");
        assert_eq!(severity(0.0), "none");
    }

    #[test]
    fn threat_and_environment_move_the_score_down() {
        let base = score("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N");
        let unreported = score("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/E:U");
        assert!(unreported < base, "{unreported} < {base}");
        let low_value = score("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/CR:L/IR:L/AR:L");
        assert!(low_value < base);
    }

    #[test]
    fn vectors_are_checked_and_normalised() {
        assert!(Cvss4::parse("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H").is_err());
        assert!(Cvss4::parse("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N").is_err());
        assert!(Cvss4::parse("CVSS:4.0/AV:Q/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N").is_err());
        assert!(Cvss4::parse("CVSS:4.0/AV:N/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N").is_err());
        let v = Cvss4::parse("CVSS:4.0/SA:N/SI:N/SC:N/VA:H/VI:H/VC:H/UI:N/PR:N/AT:N/AC:L/AV:N/E:X/CR:H").unwrap();
        assert_eq!(v.vector(), "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/CR:H");
    }
}
