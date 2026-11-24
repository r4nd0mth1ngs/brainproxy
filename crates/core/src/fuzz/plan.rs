//! Request templates with payload positions, payload sets, and the four attack
//! modes (Intruder-style). Every request of an attack is addressable by index,
//! so attacks can be generated lazily and split between workers.

use serde::{Deserialize, Serialize};

use crate::codec;
use crate::error::{Error, Result};
use crate::fuzz::sets::{self, Gen, Set};

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

    /// For each position, whether it sits in the request line or in a form-encoded body,
    /// where payloads must be URL-safe (see `codec::encode_loose`).
    pub fn url_positions(&self) -> Vec<bool> {
        let mut prefix = Vec::new();
        let form = {
            let all = self.render(&self.defaults.iter().map(Vec::as_slice).collect::<Vec<_>>());
            let head = crate::http::request::split_head_body(&all).0.to_ascii_lowercase();
            let head = String::from_utf8_lossy(&head).into_owned();
            head.lines().any(|l| {
                l.strip_prefix("content-type:")
                    .is_some_and(|v| v.trim().starts_with("application/x-www-form-urlencoded"))
            })
        };
        (0..self.defaults.len())
            .map(|i| {
                prefix.extend_from_slice(&self.parts[i]);
                let in_line = !prefix.contains(&b'\n');
                let in_body = crate::http::request::find(&prefix, b"\r\n\r\n").is_some()
                    || crate::http::request::find(&prefix, b"\n\n").is_some();
                prefix.extend_from_slice(&self.defaults[i]);
                in_line || (form && in_body)
            })
            .collect()
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
    sets: Vec<Set>,
    /// None when every set that counts is unbounded (extract): the run's --max-requests ends it.
    total: Option<u64>,
}

impl Plan {
    pub fn new(mode: Mode, template: &Template, mut sets: Vec<Set>) -> Result<Self> {
        let n = template.positions();
        let defaults = template.defaults();
        let name = serde_json::to_value(mode).ok().and_then(|v| v.as_str().map(String::from)).unwrap_or_default();
        let want = match mode {
            Mode::Sniper | Mode::BatteringRam => 1,
            Mode::Pitchfork | Mode::ClusterBomb => n,
        };
        if sets.len() != want {
            return Err(Error::InvalidInput(format!(
                "{name} mode with {n} position(s) needs {want} payload set(s), got {}",
                sets.len()
            )));
        }
        let per_position = matches!(mode, Mode::Pitchfork | Mode::ClusterBomb);
        let copies: Vec<bool> = sets.iter().map(|s| matches!(s, Set::Copy(_))).collect();
        for (i, set) in sets.iter_mut().enumerate() {
            let set_no = i + 1;
            // The position whose value a set without one of its own takes.
            let position = if per_position { Some(i) } else { (n == 1).then_some(0) };
            match set {
                Set::Copy(from) => {
                    if !per_position {
                        return Err(Error::InvalidInput(format!(
                            "payload set {set_no}: copy: needs one set per position (pitchfork or cluster-bomb)"
                        )));
                    }
                    if *from >= n || *from == i || copies[*from] {
                        return Err(Error::InvalidInput(format!(
                            "payload set {set_no}: copy:{} must name another position, 1 to {n}, that isn't a copy",
                            *from + 1
                        )));
                    }
                }
                Set::Extract { first, .. } => {
                    if mode == Mode::ClusterBomb {
                        return Err(Error::InvalidInput(format!(
                            "payload set {set_no}: extract: follows one response to the next, so it has no place in \
                             cluster-bomb's combinations; use pitchfork"
                        )));
                    }
                    if mode == Mode::Sniper && n > 1 {
                        return Err(Error::InvalidInput(
                            "extract: in sniper mode needs a single position; use battering-ram or pitchfork".into(),
                        ));
                    }
                    if first.is_none() {
                        *first = Some(defaults[position.unwrap_or(0)].clone());
                    }
                }
                Set::Lazy { gen: Gen::BitFlip(value), .. } if value.is_none() => match position {
                    Some(p) => *value = Some(defaults[p].clone()),
                    None => {
                        return Err(Error::InvalidInput(format!(
                            "payload set {set_no}: bitflip without a value flips the position's value, so it needs a \
                             single position or one set per position; give it one: bitflip:VALUE"
                        )))
                    }
                },
                _ => {}
            }
            if set.count() == Some(0) {
                return Err(Error::InvalidInput(format!("payload set {set_no} is empty")));
            }
        }
        let lens: Vec<u64> = sets.iter().filter_map(Set::count).collect();
        let total = match mode {
            Mode::Sniper => lens.first().map(|l| (n as u64).saturating_mul(*l)),
            Mode::BatteringRam => lens.first().copied(),
            Mode::Pitchfork => lens.iter().min().copied(),
            Mode::ClusterBomb => Some(
                lens.iter()
                    .try_fold(1u64, |acc, l| acc.checked_mul(*l))
                    .ok_or_else(|| Error::InvalidInput("cluster bomb has too many combinations".into()))?,
            ),
        };
        Ok(Self { mode, defaults: defaults.to_vec(), sets, total })
    }

    /// The requests the plan makes; `u64::MAX` for an unbounded one (see [`Plan::bounded`]).
    pub fn total(&self) -> u64 {
        self.total.unwrap_or(u64::MAX)
    }

    /// Whether the plan ends by itself: one made only of extract sets runs until nothing is
    /// extracted, or to --max-requests.
    pub fn bounded(&self) -> bool {
        self.total.is_some()
    }

    /// Whether a set follows the previous response (`extract`): requests go one at a time.
    pub fn feedback(&self) -> bool {
        self.sets.iter().any(|s| matches!(s, Set::Extract { .. }))
    }

    pub fn sets(&self) -> &[Set] {
        &self.sets
    }

    pub fn item(&self, index: u64) -> Item {
        self.item_with(index, None)
    }

    /// Request `index`, with `extracted` (what the previous response gave) in the extract
    /// sets' positions; their first value when None.
    pub fn item_with(&self, index: u64, extracted: Option<&[u8]>) -> Item {
        let value = |set: &Set, i: u64| match set {
            Set::Extract { first, each } => {
                sets::apply_each(each, extracted.map(<[u8]>::to_vec).or_else(|| first.clone()).unwrap_or_default())
            }
            set => set.get(i),
        };
        let mut item = match self.mode {
            Mode::Sniper => {
                let set = &self.sets[0];
                let len = set.count().unwrap_or(u64::MAX).max(1);
                let pos = ((index / len) as usize).min(self.defaults.len().saturating_sub(1));
                let payload = value(set, index % len);
                let mut values = self.defaults.clone();
                values[pos] = payload.clone();
                Item { position: Some(pos), payloads: vec![payload], values }
            }
            Mode::BatteringRam => {
                let payload = value(&self.sets[0], index);
                Item { position: None, payloads: vec![payload.clone()], values: vec![payload; self.defaults.len()] }
            }
            Mode::Pitchfork => {
                let values: Vec<Vec<u8>> = self.sets.iter().map(|s| value(s, index)).collect();
                Item { position: None, payloads: Vec::new(), values }
            }
            Mode::ClusterBomb => {
                // Mixed radix over the sets that have payloads; the last position changes fastest.
                let mut rem = index;
                let mut values = vec![Vec::new(); self.sets.len()];
                for (i, set) in self.sets.iter().enumerate().rev() {
                    if let Some(len) = set.count().filter(|l| *l > 0) {
                        values[i] = set.get(rem % len);
                        rem /= len;
                    }
                }
                Item { position: None, payloads: Vec::new(), values }
            }
        };
        // A copy takes its position's value once every other is known.
        for (i, set) in self.sets.iter().enumerate() {
            if let Set::Copy(from) = set {
                item.values[i] = item.values[*from].clone();
            }
        }
        if matches!(self.mode, Mode::Pitchfork | Mode::ClusterBomb) {
            item.payloads = item.values.clone();
        }
        item
    }
}

pub const PROCESSORS: &[&str] = &[
    "url",
    "url-all",
    "base64",
    "base64url",
    "hex",
    "html",
    "gzip",
    "zlib",
    "deflate",
    "md5",
    "sha1",
    "sha256",
    "sha512",
    "upper",
    "lower",
    "prefix:TEXT",
    "suffix:TEXT",
    "script:FILE",
];

/// One built-in step of a processing chain, applied to a payload.
pub(crate) fn step(step: &str, v: Vec<u8>) -> Result<Vec<u8>> {
    Ok(match step.split_once(':') {
        Some(("prefix", x)) => [x.as_bytes(), &v].concat(),
        Some(("suffix", x)) => [&v[..], x.as_bytes()].concat(),
        _ => match step {
            "upper" => v.to_ascii_uppercase(),
            "lower" => v.to_ascii_lowercase(),
            "md5" | "sha1" | "sha256" | "sha512" => codec::hash(step, &v)?.into_bytes(),
            other => codec::encode(other, &v).map_err(|_| {
                Error::InvalidInput(format!("unknown processor {other:?}; valid: {}", PROCESSORS.join(", ")))
            })?,
        },
    })
}

/// Applies a comma-separated chain of the built-in processors to a payload, left to right. A
/// chain with a script step is a [`Chain`]: a script is handed a set's payloads together.
pub fn process(chain: &str, payload: &[u8]) -> Result<Vec<u8>> {
    let mut v = payload.to_vec();
    for name in split_chain(chain) {
        if name.starts_with("script:") {
            return Err(Error::InvalidInput("a script step processes a payload set, not one payload".into()));
        }
        v = step(&name, v)?;
    }
    Ok(v)
}

/// Whether a processing chain has a script step (`script:FILE`), which runs code from a file.
pub fn names_script(chain: &str) -> bool {
    split_chain(chain).iter().any(|s| s.starts_with("script:"))
}

/// A processing chain, read once for a run: its built-in steps and its scripts, each a file
/// defining `process(payload, ctx)` (see [`crate::hooks`]), read and pinned when the chain is.
#[derive(Debug, Clone)]
pub struct Chain {
    steps: Vec<ChainStep>,
}

#[derive(Debug, Clone)]
enum ChainStep {
    Builtin(String),
    Script(crate::hooks::ScriptRef, crate::hooks::Hook),
}

impl Chain {
    /// Reads `chain`. A `script:FILE` step's file is read and checked to parse; nothing runs.
    pub fn parse(chain: &str) -> Result<Chain> {
        let mut steps = Vec::new();
        for name in split_chain(chain) {
            steps.push(match name.strip_prefix("script:") {
                Some(file) => {
                    let script = crate::hooks::ScriptRef::pin(std::path::Path::new(file), None)?;
                    let hook = crate::hooks::Hook::load(crate::hooks::HookKind::Process, &script)
                        .map_err(Error::InvalidInput)?;
                    ChainStep::Script(script, hook)
                }
                None => ChainStep::Builtin(name),
            });
        }
        Ok(Chain { steps })
    }

    /// The scripts the chain runs, as they were read: a run records them.
    pub fn scripts(&self) -> Vec<&crate::hooks::ScriptRef> {
        self.steps
            .iter()
            .filter_map(|s| match s {
                ChainStep::Script(script, _) => Some(script),
                ChainStep::Builtin(_) => None,
            })
            .collect()
    }

    /// Applies the chain to every payload of set `set` (counted from 1), left to right. A script
    /// that fails on a payload (it throws, runs past its time limit, or returns something that
    /// isn't a payload) fails the chain: no run starts on half-processed payloads.
    /// Applies the chain to set `set_no` (counted from 1): a list's payloads now; a generated
    /// set's, and an extracted value, as each is made (built-in steps only; a script is handed a
    /// generated set of at most [`sets::MAX_COMBOS`] made in full). A copy is its position's
    /// value as sent, so it has no processing of its own.
    pub fn apply_set(&self, set_no: usize, set: &mut Set) -> Result<()> {
        for s in &self.steps {
            match (s, &mut *set) {
                (_, Set::Copy(_)) => {
                    return Err(Error::InvalidInput(format!(
                        "payload set {set_no} is a copy of another position's value as sent; process that set instead"
                    )))
                }
                (ChainStep::Builtin(name), Set::List(payloads)) => {
                    for p in payloads.iter_mut() {
                        *p = step(name, std::mem::take(p))?;
                    }
                }
                (ChainStep::Builtin(name), Set::Lazy { each, .. } | Set::Extract { each, .. }) => {
                    // Checked now, so a step that doesn't exist fails before the run.
                    step(name, b"x".to_vec())?;
                    each.push(name.clone());
                }
                (ChainStep::Script(_, hook), set) => hook.process(set_no, set.materialise(set_no)?)?,
            }
        }
        Ok(())
    }

    pub fn apply(&self, set: usize, payloads: &mut [Vec<u8>]) -> Result<()> {
        for s in &self.steps {
            match s {
                ChainStep::Builtin(name) => {
                    for p in payloads.iter_mut() {
                        *p = step(name, std::mem::take(p))?;
                    }
                }
                ChainStep::Script(_, hook) => hook.process(set, payloads)?,
            }
        }
        Ok(())
    }
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
    use crate::fuzz::sets::load_payloads;

    fn list(set: Set) -> Vec<Vec<u8>> {
        match set {
            Set::List(v) => v,
            other => panic!("not a list: {other:?}"),
        }
    }

    fn t(s: &str) -> Template {
        Template::parse(s.as_bytes(), DEFAULT_MARKER).unwrap()
    }

    #[test]
    fn url_positions_are_the_request_line_and_form_bodies() {
        let req = "GET /s?q=§a§ HTTP/1.1\r\nX-H: §b§\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\nu=§c§";
        assert_eq!(t(req).url_positions(), [true, false, true]);
        let json = "POST /§p§ HTTP/1.1\nContent-Type: application/json\n\n{\"a\": \"§x§\"}";
        assert_eq!(t(json).url_positions(), [true, false]);
    }

    #[test]
    fn wordlist_payloads() {
        let mut no_stdin = || Ok(vec![]);
        let sqli = list(load_payloads("wordlist:sqli", &mut no_stdin).unwrap());
        assert!(sqli.len() > 100 && sqli.contains(&b"'".to_vec()));
        assert!(load_payloads("wordlist:nope", &mut no_stdin).unwrap_err().to_string().contains("content-discovery"));
    }

    fn sets(v: &[&[&str]]) -> Vec<Set> {
        v.iter().map(|s| Set::List(s.iter().map(|p| p.as_bytes().to_vec()).collect())).collect()
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

    fn spec(s: &str) -> Set {
        load_payloads(s, &mut || -> Result<Vec<u8>> { unreachable!() }).unwrap()
    }

    #[test]
    fn a_copy_takes_its_positions_value_and_adds_no_dimension() {
        let tpl = t("u=§a§&p=§b§&c=§c§");
        let p = Plan::new(Mode::Pitchfork, &tpl, vec![spec("list:x,y"), spec("list:1,2,3"), spec("copy:2")]).unwrap();
        assert_eq!(rendered(&p, &tpl), ["u=x&p=1&c=1", "u=y&p=2&c=2"]);
        let p = Plan::new(Mode::ClusterBomb, &tpl, vec![spec("list:x,y"), spec("copy:1"), spec("list:1,2")]).unwrap();
        assert_eq!(rendered(&p, &tpl), ["u=x&p=x&c=1", "u=x&p=x&c=2", "u=y&p=y&c=1", "u=y&p=y&c=2"]);
        assert_eq!(p.item(1).payloads, [b"x".to_vec(), b"x".to_vec(), b"2".to_vec()]);
        let e = |sets: Vec<Set>, mode| Plan::new(mode, &tpl, sets).unwrap_err().to_string();
        assert!(e(vec![spec("list:x"), spec("copy:2"), spec("list:1")], Mode::Pitchfork).contains("another position"));
        assert!(e(vec![spec("list:x"), spec("copy:3"), spec("copy:2")], Mode::Pitchfork).contains("isn't a copy"));
        assert!(e(vec![spec("list:x"), spec("copy:9"), spec("list:1")], Mode::Pitchfork).contains("1 to 3"));
        assert!(e(vec![spec("copy:1")], Mode::Sniper).contains("one set per position"));
    }

    #[test]
    fn extract_and_bitflip_take_the_positions_value() {
        let tpl = t("GET /?t=§start§&n=§1§");
        let p = Plan::new(Mode::Pitchfork, &tpl, vec![spec("extract"), spec("range:1-3")]).unwrap();
        assert!(p.bounded() && p.feedback() && p.total() == 3);
        assert_eq!(p.item(0).values, [b"start".to_vec(), b"1".to_vec()]);
        assert_eq!(p.item_with(1, Some(b"tok")).values, [b"tok".to_vec(), b"2".to_vec()]);
        let p = Plan::new(Mode::Pitchfork, &tpl, vec![spec("extract:go"), spec("extract")]).unwrap();
        assert!(!p.bounded() && p.total() == u64::MAX);
        assert_eq!(p.item(0).values, [b"go".to_vec(), b"1".to_vec()]);
        let e = Plan::new(Mode::ClusterBomb, &tpl, vec![spec("extract"), spec("list:a")]).unwrap_err();
        assert!(e.to_string().contains("cluster-bomb"), "{e}");
        assert!(Plan::new(Mode::Sniper, &tpl, vec![spec("extract")]).is_err());
        let one = t("GET /?t=§AB§");
        let p = Plan::new(Mode::Sniper, &one, vec![spec("bitflip")]).unwrap();
        assert_eq!(p.total(), 16);
        assert_eq!(p.item(0).values, [b"@B".to_vec()]);
        let p = Plan::new(Mode::Pitchfork, &tpl, vec![spec("bitflip"), spec("bitflip:z")]).unwrap();
        assert_eq!(p.total(), 8);
        let e = Plan::new(Mode::Sniper, &tpl, vec![spec("bitflip")]).unwrap_err().to_string();
        assert!(e.contains("bitflip:VALUE"), "{e}");
        assert!(Plan::new(Mode::Sniper, &t("a=§§"), vec![spec("bitflip")]).unwrap_err().to_string().contains("empty"));
    }

    #[test]
    fn a_generated_set_is_processed_as_each_payload_is_made() {
        let tpl = t("q=§x§");
        let mut lazy = spec("brute:ab:1-2");
        let mut eager = Set::List((0..6).map(|i| spec("brute:ab:1-2").get(i)).collect());
        let chain = Chain::parse("upper,prefix:-").unwrap();
        chain.apply_set(1, &mut lazy).unwrap();
        chain.apply_set(1, &mut eager).unwrap();
        assert!(matches!(lazy, Set::Lazy { .. }));
        let (a, b) =
            (Plan::new(Mode::Sniper, &tpl, vec![lazy]).unwrap(), Plan::new(Mode::Sniper, &tpl, vec![eager]).unwrap());
        assert_eq!(rendered(&a, &tpl), rendered(&b, &tpl));
        assert_eq!(rendered(&a, &tpl)[3], "q=-AB");
        // A step that doesn't exist fails before any payload is made, and a copy has no chain.
        assert!(Chain::parse("bogus").unwrap().apply_set(1, &mut spec("null:2")).is_err());
        assert!(chain.apply_set(1, &mut Set::Copy(0)).unwrap_err().to_string().contains("process that set"));
        // A script is handed a generated set made in full, up to a million payloads.
        let mut big = spec("brute:a-z0-9:1-4");
        let e = big.materialise(1).unwrap_err().to_string();
        assert!(e.contains("at most 1000000"), "{e}");
        assert_eq!(spec("null:3").materialise(1).unwrap().len(), 3);
    }

    #[test]
    fn payload_sources_and_processing() {
        let mut no_stdin = || -> Result<Vec<u8>> { unreachable!() };
        assert_eq!(list(load_payloads(r"list:a,b\,c", &mut no_stdin).unwrap()), [b"a".to_vec(), b"b,c".to_vec()]);
        let r = list(load_payloads("range:008-011", &mut no_stdin).unwrap());
        assert_eq!(r, ["008", "009", "010", "011"].map(|s| s.as_bytes().to_vec()));
        assert_eq!(load_payloads("range:10-0:5", &mut no_stdin).unwrap().count(), Some(3));
        let mut stdin = || Ok(b"x\r\n\ny\n".to_vec());
        assert_eq!(list(load_payloads("file:-", &mut stdin).unwrap()), [b"x".to_vec(), b"y".to_vec()]);
        assert!(load_payloads("nope", &mut no_stdin).is_err());

        assert_eq!(process("prefix:a\\,b,suffix:!,base64", b"x").unwrap(), b"YSxieCE=");
        assert_eq!(process("upper,md5", b"a").unwrap(), b"7fc56270e7a70fa81a5935b72eacbe29");
        assert!(process("bogus", b"x").is_err());
        // Compression works as a step, as in `encode`, so payloads can be packed then wrapped.
        assert_eq!(
            process("gzip,base64", b"x").unwrap(),
            codec::encode("base64", &codec::encode("gzip", b"x").unwrap()).unwrap()
        );
        // Every encoding the Codec offers is a listed processor.
        for kind in codec::ENCODINGS {
            assert!(PROCESSORS.contains(kind), "{kind}");
        }
    }

    #[test]
    fn a_script_is_a_step_of_a_chain() {
        let (script, dir) = crate::hooks::tests::script_file(
            "function process(payload, ctx) {
                if (payload === 'BAD') throw new Error('no ' + payload);
                return ctx.set + '.' + ctx.index + ':' + CryptoJS.MD5(payload).toString().slice(0, 4) + payload;
            }",
        );
        crate::sandbox::tests::use_test_runner();
        let file = script.file.display().to_string();
        // A comma in the path is escaped, as in prefix: and suffix:.
        assert!(names_script(&format!("upper,script:{}", file.replace(',', "\\,"))) && !names_script("upper,md5"));
        let chain = Chain::parse(&format!("upper,script:{file},base64")).unwrap();
        assert_eq!(chain.scripts(), [&script]);
        let mut set = vec![b"a".to_vec(), b"b".to_vec()];
        chain.apply(2, &mut set).unwrap();
        let want = |i: usize, p: &str| {
            let md5 = codec::hash("md5", p.as_bytes()).unwrap();
            codec::encode("base64", format!("2.{i}:{}{p}", &md5[..4]).as_bytes()).unwrap()
        };
        assert_eq!(set, [want(0, "A"), want(1, "B")]);
        // A payload the script fails on fails the chain, and says which.
        let mut set = vec![b"a".to_vec(), b"bad".to_vec()];
        let e = chain.apply(1, &mut set).unwrap_err().to_string();
        assert!(e.contains("payload 2 of set 1") && e.contains("no BAD"), "{e}");
        // One payload alone has no script step, and a script that isn't there is no chain.
        assert!(process(&format!("script:{file}"), b"x").is_err());
        assert!(Chain::parse("script:/nonexistent/x.js").unwrap_err().to_string().contains("can't be read"));
        let _ = std::fs::remove_dir_all(dir);
        // A script with no process function fails the chain before any payload is changed.
        let (script, dir) = crate::hooks::tests::script_file("function replace(m) { return 'x'; }");
        let chain = Chain::parse(&format!("script:{}", script.file.display())).unwrap();
        let mut set = vec![b"a".to_vec()];
        assert!(chain.apply(1, &mut set).unwrap_err().to_string().contains("it defines no process function"));
        assert_eq!(set, [b"a".to_vec()]);
        let _ = std::fs::remove_dir_all(dir);
    }
}
