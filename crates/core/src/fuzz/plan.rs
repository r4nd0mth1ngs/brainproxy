//! Request templates with payload positions, payload sets, and the four attack
//! modes (Intruder-style). Every request of an attack is addressable by index,
//! so attacks can be generated lazily and split between workers.

use serde::{Deserialize, Serialize};

use crate::codec;
use crate::error::{Error, Result};

pub const DEFAULT_MARKER: &str = "§";

/// A request with payload positions. `parts` has one more element than `defaults`:
/// part0 default0 part1 default1 ... partN.
#[derive(Debug, Clone)]
pub struct Template {
    parts: Vec<Vec<u8>>,
    defaults: Vec<Vec<u8>>,
}

impl Template {
    pub fn parse(bytes: &[u8], marker: &str) -> Result<Self> {
        let m = marker.as_bytes();
        if m.is_empty() {
            return Err(Error::InvalidInput("marker must not be empty".into()));
        }
        let mut pieces = Vec::new();
        let mut rest = bytes;
        while let Some(i) = crate::http::request::find(rest, m) {
            pieces.push(rest[..i].to_vec());
            rest = &rest[i + m.len()..];
        }
        pieces.push(rest.to_vec());
        if pieces.len() % 2 == 0 {
            return Err(Error::InvalidInput(format!(
                "unbalanced {marker} markers: positions need an opening and closing marker"
            )));
        }
        if pieces.len() == 1 {
            return Err(Error::InvalidInput(format!(
                "no payload positions; wrap values in {marker}...{marker} (e.g. id={marker}1{marker})"
            )));
        }
        let mut parts = Vec::new();
        let mut defaults = Vec::new();
        for (i, p) in pieces.into_iter().enumerate() {
            if i % 2 == 0 {
                parts.push(p);
            } else {
                defaults.push(p);
            }
        }
        Ok(Self { parts, defaults })
    }

    pub fn positions(&self) -> usize {
        self.defaults.len()
    }

    pub fn defaults(&self) -> &[Vec<u8>] {
        &self.defaults
    }

    /// The template with each position replaced by `values[i]`.
    pub fn render(&self, values: &[&[u8]]) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.parts.iter().map(Vec::len).sum::<usize>() + 64);
        for (i, part) in self.parts.iter().enumerate() {
            out.extend_from_slice(part);
            if let Some(v) = values.get(i) {
                out.extend_from_slice(v);
            }
        }
        out
    }

    /// Applies `f` to every literal part, leaving positions alone (e.g. to fix
    /// line endings without touching payload values).
    pub fn map_parts(mut self, f: impl Fn(&[u8]) -> Vec<u8>) -> Self {
        self.parts = self.parts.iter().map(|p| f(p)).collect();
        self
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum Mode {
    /// One payload set; each position in turn, others keep their default.
    Sniper,
    /// One payload set; the same payload in every position.
    BatteringRam,
    /// One set per position, advanced together; stops at the shortest set.
    Pitchfork,
    /// One set per position; every combination.
    ClusterBomb,
}

impl Mode {
    pub const ALL: &'static [&'static str] = &["sniper", "battering-ram", "pitchfork", "cluster-bomb"];

    pub fn parse(s: &str) -> Result<Self> {
        serde_json::from_value(serde_json::Value::String(s.to_string()))
            .map_err(|_| Error::InvalidInput(format!("unknown mode {s:?}; valid: {}", Self::ALL.join(", "))))
    }
}

/// One generated request: the payloads used and the value for every position.
#[derive(Debug, Clone, PartialEq)]
pub struct Item {
    /// For sniper, the position being attacked; otherwise None.
    pub position: Option<usize>,
    pub payloads: Vec<Vec<u8>>,
    pub values: Vec<Vec<u8>>,
}

#[derive(Debug, Clone)]
pub struct Plan {
    mode: Mode,
    defaults: Vec<Vec<u8>>,
    sets: Vec<Vec<Vec<u8>>>,
    total: u64,
}

impl Plan {
    pub fn new(mode: Mode, template: &Template, sets: Vec<Vec<Vec<u8>>>) -> Result<Self> {
        let n = template.positions();
        let want = match mode {
            Mode::Sniper | Mode::BatteringRam => 1,
            Mode::Pitchfork | Mode::ClusterBomb => n,
        };
        if sets.len() != want {
            return Err(Error::InvalidInput(format!(
                "{} mode with {n} position(s) needs {want} payload set(s), got {}",
                serde_json::to_value(mode).unwrap().as_str().unwrap_or(""),
                sets.len()
            )));
        }
        if let Some(i) = sets.iter().position(Vec::is_empty) {
            return Err(Error::InvalidInput(format!("payload set {} is empty", i + 1)));
        }
        let total = match mode {
            Mode::Sniper => (n as u64) * sets[0].len() as u64,
            Mode::BatteringRam => sets[0].len() as u64,
            Mode::Pitchfork => sets.iter().map(|s| s.len() as u64).min().unwrap_or(0),
            Mode::ClusterBomb => sets
                .iter()
                .try_fold(1u64, |acc, s| acc.checked_mul(s.len() as u64))
                .ok_or_else(|| Error::InvalidInput("cluster bomb has too many combinations".into()))?,
        };
        Ok(Self { mode, defaults: template.defaults().to_vec(), sets, total })
    }

    pub fn total(&self) -> u64 {
        self.total
    }

    pub fn item(&self, index: u64) -> Item {
        match self.mode {
            Mode::Sniper => {
                let set = &self.sets[0];
                let pos = (index / set.len() as u64) as usize;
                let payload = set[(index % set.len() as u64) as usize].clone();
                let mut values = self.defaults.clone();
                values[pos] = payload.clone();
                Item { position: Some(pos), payloads: vec![payload], values }
            }
            Mode::BatteringRam => {
                let payload = self.sets[0][index as usize].clone();
                Item { position: None, payloads: vec![payload.clone()], values: vec![payload; self.defaults.len()] }
            }
            Mode::Pitchfork => {
                let values: Vec<Vec<u8>> = self.sets.iter().map(|s| s[index as usize].clone()).collect();
                Item { position: None, payloads: values.clone(), values }
            }
            Mode::ClusterBomb => {
                // Mixed radix; the last position changes fastest.
                let mut rem = index;
                let mut values = vec![Vec::new(); self.sets.len()];
                for (i, set) in self.sets.iter().enumerate().rev() {
                    values[i] = set[(rem % set.len() as u64) as usize].clone();
                    rem /= set.len() as u64;
                }
                Item { position: None, payloads: values.clone(), values }
            }
        }
    }
}

/// Parses a payload source:
/// `list:a,b,c` (comma-separated; `\,` for a literal comma), `file:PATH` (one per
/// line; `file:-` for stdin), or `range:FROM-TO[:STEP]` (zero padding kept, e.g. 001-100).
pub fn load_payloads(spec: &str, stdin: &mut dyn FnMut() -> Result<Vec<u8>>) -> Result<Vec<Vec<u8>>> {
    let (kind, arg) = spec.split_once(':').ok_or_else(|| bad_spec(spec))?;
    match kind {
        "list" => {
            let mut out = Vec::new();
            let mut cur = String::new();
            let mut chars = arg.chars().peekable();
            while let Some(c) = chars.next() {
                match c {
                    '\\' if chars.peek() == Some(&',') => {
                        cur.push(',');
                        chars.next();
                    }
                    ',' => out.push(std::mem::take(&mut cur).into_bytes()),
                    c => cur.push(c),
                }
            }
            out.push(cur.into_bytes());
            Ok(out)
        }
        "file" => {
            let data = if arg == "-" {
                stdin()?
            } else {
                std::fs::read(arg).map_err(|e| Error::InvalidInput(format!("payload file {arg:?}: {e}")))?
            };
            Ok(data
                .split(|&b| b == b'\n')
                .map(|l| l.strip_suffix(b"\r").unwrap_or(l).to_vec())
                .filter(|l| !l.is_empty())
                .collect())
        }
        "range" => {
            let (bounds, step) = match arg.rsplit_once(':') {
                Some((b, s)) => (b, s.parse::<i64>().map_err(|_| bad_spec(spec))?),
                None => (arg, 1),
            };
            let (from, to) = bounds
                .strip_prefix('-')
                .map(|rest| rest.split_once('-').map(|(a, b)| (format!("-{a}"), b.to_string())))
                .unwrap_or_else(|| bounds.split_once('-').map(|(a, b)| (a.to_string(), b.to_string())))
                .ok_or_else(|| bad_spec(spec))?;
            let width = if from.starts_with('0') && from.len() > 1 { from.len() } else { 0 };
            let (a, b): (i64, i64) =
                (from.parse().map_err(|_| bad_spec(spec))?, to.parse().map_err(|_| bad_spec(spec))?);
            if step <= 0 {
                return Err(Error::InvalidInput("range step must be positive".into()));
            }
            let count = ((a - b).abs() / step + 1) as u64;
            if count > 10_000_000 {
                return Err(Error::InvalidInput(format!("range {spec:?} has {count} values; max 10,000,000")));
            }
            let dir = if b >= a { 1 } else { -1 };
            Ok((0..count as i64).map(|i| format!("{:0width$}", a + dir * i * step).into_bytes()).collect())
        }
        _ => Err(bad_spec(spec)),
    }
}

fn bad_spec(spec: &str) -> Error {
    Error::InvalidInput(format!("bad payload source {spec:?}; use list:a,b,c | file:PATH | range:1-100[:step]"))
}

pub const PROCESSORS: &[&str] = &[
    "url",
    "url-all",
    "base64",
    "base64url",
    "hex",
    "html",
    "md5",
    "sha1",
    "sha256",
    "sha512",
    "upper",
    "lower",
    "prefix:TEXT",
    "suffix:TEXT",
];

/// Applies a comma-separated processing chain to a payload, left to right.
pub fn process(chain: &str, payload: &[u8]) -> Result<Vec<u8>> {
    let mut v = payload.to_vec();
    for step in split_chain(chain) {
        v = match step.split_once(':') {
            Some(("prefix", x)) => [x.as_bytes(), &v].concat(),
            Some(("suffix", x)) => [&v[..], x.as_bytes()].concat(),
            _ => match step.as_str() {
                "upper" => v.to_ascii_uppercase(),
                "lower" => v.to_ascii_lowercase(),
                "md5" | "sha1" | "sha256" | "sha512" => codec::hash(&step, &v)?.into_bytes(),
                other => codec::encode(other, &v).map_err(|_| {
                    Error::InvalidInput(format!("unknown processor {other:?}; valid: {}", PROCESSORS.join(", ")))
                })?,
            },
        };
    }
    Ok(v)
}

/// Splits on commas, except inside prefix:/suffix: arguments where `\,` escapes a comma.
fn split_chain(chain: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut chars = chain.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '\\' if chars.peek() == Some(&',') => {
                cur.push(',');
                chars.next();
            }
            ',' => out.push(std::mem::take(&mut cur)),
            c => cur.push(c),
        }
    }
    out.push(cur);
    out.into_iter().filter(|s| !s.is_empty()).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn t(s: &str) -> Template {
        Template::parse(s.as_bytes(), DEFAULT_MARKER).unwrap()
    }

    fn sets(v: &[&[&str]]) -> Vec<Vec<Vec<u8>>> {
        v.iter().map(|s| s.iter().map(|p| p.as_bytes().to_vec()).collect()).collect()
    }

    fn rendered(plan: &Plan, tpl: &Template) -> Vec<String> {
        (0..plan.total())
            .map(|i| {
                let item = plan.item(i);
                let refs: Vec<&[u8]> = item.values.iter().map(Vec::as_slice).collect();
                String::from_utf8(tpl.render(&refs)).unwrap()
            })
            .collect()
    }

    #[test]
    fn parses_templates() {
        let tpl = t("a=§1§&b=§x§");
        assert_eq!(tpl.positions(), 2);
        assert_eq!(tpl.render(&[b"9", b"y"]), b"a=9&b=y");
        assert!(Template::parse(b"a=1", "§").is_err());
        assert!(Template::parse("a=§1".as_bytes(), "§").is_err());
        assert_eq!(Template::parse(b"q=^^v^^", "^^").unwrap().defaults(), [b"v".to_vec()]);
    }

    #[test]
    fn modes() {
        let tpl = t("§a§-§b§");
        let p = Plan::new(Mode::Sniper, &tpl, sets(&[&["1", "2"]])).unwrap();
        assert_eq!(rendered(&p, &tpl), ["1-b", "2-b", "a-1", "a-2"]);
        let p = Plan::new(Mode::BatteringRam, &tpl, sets(&[&["1", "2"]])).unwrap();
        assert_eq!(rendered(&p, &tpl), ["1-1", "2-2"]);
        let p = Plan::new(Mode::Pitchfork, &tpl, sets(&[&["1", "2", "3"], &["x", "y"]])).unwrap();
        assert_eq!(rendered(&p, &tpl), ["1-x", "2-y"]);
        let p = Plan::new(Mode::ClusterBomb, &tpl, sets(&[&["1", "2"], &["x", "y"]])).unwrap();
        assert_eq!(rendered(&p, &tpl), ["1-x", "1-y", "2-x", "2-y"]);
        assert!(Plan::new(Mode::Pitchfork, &tpl, sets(&[&["1"]])).is_err());
    }

    #[test]
    fn payload_sources_and_processing() {
        let mut no_stdin = || -> Result<Vec<u8>> { unreachable!() };
        assert_eq!(load_payloads(r"list:a,b\,c", &mut no_stdin).unwrap(), [b"a".to_vec(), b"b,c".to_vec()]);
        let r = load_payloads("range:008-011", &mut no_stdin).unwrap();
        assert_eq!(r, ["008", "009", "010", "011"].map(|s| s.as_bytes().to_vec()));
        assert_eq!(load_payloads("range:10-0:5", &mut no_stdin).unwrap().len(), 3);
        let mut stdin = || Ok(b"x\r\n\ny\n".to_vec());
        assert_eq!(load_payloads("file:-", &mut stdin).unwrap(), [b"x".to_vec(), b"y".to_vec()]);
        assert!(load_payloads("nope", &mut no_stdin).is_err());

        assert_eq!(process("prefix:a\\,b,suffix:!,base64", b"x").unwrap(), b"YSxieCE=");
        assert_eq!(process("upper,md5", b"a").unwrap(), b"7fc56270e7a70fa81a5935b72eacbe29");
        assert!(process("bogus", b"x").is_err());
    }
}
