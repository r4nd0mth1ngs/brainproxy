//! Payload sets and the `-p` sources they come from. A set is a list, or a generator whose
//! payloads are made when they are asked for (a ten-million-value brute force isn't held in
//! memory), or a slot the request fills itself: a copy of another position's value, or what
//! the previous response gave (`extract`).

use crate::error::{Error, Result};

/// The most payloads one generated set may have, as for `range`.
pub const MAX_SET: u64 = 10_000_000;
/// The most payloads a set made by combining (case, substitution) may have, and the most a
/// lazy set may have for a script to process it: a script is handed the whole set.
pub const MAX_COMBOS: u64 = 1_000_000;
/// The most letters `case:` takes: 2^20 combinations.
const MAX_CASE_LETTERS: usize = 20;
/// The longest brute-force payload.
const MAX_BRUTE_LEN: u32 = 256;

/// One payload set of an attack.
#[derive(Debug, Clone, PartialEq)]
pub enum Set {
    List(Vec<Vec<u8>>),
    /// Made on demand; `each` is the built-in processing applied to every payload made.
    Lazy {
        gen: Gen,
        each: Vec<String>,
    },
    /// The value of position N (from 0) in the same request: adds no dimension.
    Copy(usize),
    /// What `--extract` captured from the previous response; the first request gets `first`
    /// (the position's default when None). The engine fills it in.
    Extract {
        first: Option<Vec<u8>>,
        each: Vec<String>,
    },
}

/// A generator of payloads, addressable by index.
#[derive(Debug, Clone, PartialEq)]
pub enum Gen {
    /// N empty payloads.
    Null(u64),
    Brute(Brute),
    /// One payload per bit of the value, with that bit flipped; None until the plan gives it
    /// the position's default.
    BitFlip(Option<Vec<u8>>),
}

/// Every string over `charset` of length `min` to `max`: shorter first, then in charset order.
#[derive(Debug, Clone, PartialEq)]
pub struct Brute {
    charset: Vec<char>,
    min: u32,
    max: u32,
    total: u64,
}

impl Gen {
    pub fn len(&self) -> u64 {
        match self {
            Gen::Null(n) => *n,
            Gen::Brute(b) => b.total,
            Gen::BitFlip(v) => v.as_ref().map_or(0, |v| v.len() as u64 * 8),
        }
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Payload `i` (`i < len()`).
    pub fn get(&self, i: u64) -> Vec<u8> {
        match self {
            Gen::Null(_) => Vec::new(),
            Gen::Brute(b) => b.get(i),
            Gen::BitFlip(v) => {
                let mut v = v.clone().unwrap_or_default();
                if let Some(byte) = v.get_mut((i / 8) as usize) {
                    *byte ^= 1 << (i % 8);
                }
                v
            }
        }
    }
}

impl Brute {
    fn get(&self, mut i: u64) -> Vec<u8> {
        let n = self.charset.len() as u64;
        let mut k = self.min;
        // The lengths come in blocks of n^k; within one, i is a k-digit number in base n.
        while k < self.max {
            let block = n.checked_pow(k).unwrap_or(u64::MAX);
            if i < block {
                break;
            }
            i -= block;
            k += 1;
        }
        let mut out = vec!['\0'; k as usize];
        for slot in out.iter_mut().rev() {
            *slot = self.charset[(i % n) as usize];
            i /= n;
        }
        out.into_iter().collect::<String>().into_bytes()
    }
}

impl Set {
    /// How many payloads the set has; None for one that adds no dimension (copy, extract).
    pub fn count(&self) -> Option<u64> {
        match self {
            Set::List(v) => Some(v.len() as u64),
            Set::Lazy { gen, .. } => Some(gen.len()),
            Set::Copy(_) | Set::Extract { .. } => None,
        }
    }

    /// Payload `i` of a list or generator, processed (`i < len()`); empty for copy and extract,
    /// whose values the request gives.
    pub fn get(&self, i: u64) -> Vec<u8> {
        match self {
            Set::List(v) => v.get(i as usize).cloned().unwrap_or_default(),
            Set::Lazy { gen, each } => apply_each(each, gen.get(i)),
            Set::Copy(_) | Set::Extract { .. } => Vec::new(),
        }
    }

    /// A generated set as a list, for a script to process: refused over [`MAX_COMBOS`].
    pub fn materialise(&mut self, set: usize) -> Result<&mut Vec<Vec<u8>>> {
        if let Set::Lazy { gen, each } = self {
            let n = gen.len();
            if n > MAX_COMBOS {
                return Err(Error::InvalidInput(format!(
                    "payload set {set} has {n} payloads; a script processes at most {MAX_COMBOS} (it is handed them all)"
                )));
            }
            *self = Set::List((0..n).map(|i| apply_each(each, gen.get(i))).collect());
        }
        match self {
            Set::List(v) => Ok(v),
            _ => Err(Error::InvalidInput(format!(
                "payload set {set} has no payloads before the run (a copy: or extract: set), so a script can't \
                 process it; use --process N=... to pick the sets"
            ))),
        }
    }

    /// Whether a payload of the set could hold a CR or LF (see the CLI's check for raw line
    /// breaks in the head). An extracted value is checked as each request goes out instead.
    pub fn may_break_line(&self) -> bool {
        let breaks = |b: &u8| *b == b'\r' || *b == b'\n';
        match self {
            Set::List(v) => v.iter().any(|p| p.iter().any(breaks)),
            Set::Lazy { gen, each } => {
                each.iter().any(|s| step_may_break(s))
                    || match gen {
                        Gen::Null(_) => false,
                        Gen::Brute(b) => b.charset.iter().any(|c| *c == '\r' || *c == '\n'),
                        // A flipped bit makes a line break of a byte one bit away from one.
                        Gen::BitFlip(v) => v
                            .iter()
                            .flatten()
                            .any(|b| breaks(b) || (b ^ b'\n').count_ones() == 1 || (b ^ b'\r').count_ones() == 1),
                    }
            }
            Set::Copy(_) => false,
            Set::Extract { each, .. } => each.iter().any(|s| step_may_break(s)),
        }
    }
}

/// Whether a built-in processing step can put a CR or LF into a payload that had none.
fn step_may_break(step: &str) -> bool {
    match step.split_once(':') {
        Some(("prefix" | "suffix", text)) => text.contains(['\r', '\n']),
        _ => matches!(step, "gzip" | "zlib" | "deflate"),
    }
}

/// Applies built-in steps that were checked when they were added (see `Chain::apply_set`).
pub(crate) fn apply_each(each: &[String], mut v: Vec<u8>) -> Vec<u8> {
    for name in each {
        v = match super::plan::step(name, std::mem::take(&mut v)) {
            Ok(out) => out,
            // ponytail: a step that failed on its check value can't get here; one that fails on
            // a particular payload sends it unprocessed rather than stopping the run.
            Err(_) => continue,
        };
    }
    v
}

/// How a `oob:` source puts each payload: as the payload's host or its URL.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OobForm {
    Host,
    Url,
}

/// Reads `oob:N[:host|url]`: how many payloads, and in which form (URL by default).
pub fn parse_oob(arg: &str) -> Result<(u64, OobForm)> {
    let (n, form) = match arg.split_once(':') {
        Some((n, "host")) => (n, OobForm::Host),
        Some((n, "url")) => (n, OobForm::Url),
        Some((_, f)) => return Err(Error::InvalidInput(format!("oob:N:{f}: the form is host or url"))),
        None => (arg, OobForm::Url),
    };
    let n: u64 = n.parse().map_err(|_| Error::InvalidInput(format!("oob:{arg}: N is a number of payloads")))?;
    if !(1..=10_000).contains(&n) {
        return Err(Error::InvalidInput("oob:N takes 1 to 10,000 payloads".into()));
    }
    Ok((n, form))
}

/// The file a source reads, when it reads one (not stdin): its hash is what a resumed run
/// checks.
pub fn source_file(spec: &str) -> Option<&str> {
    let path = spec.strip_prefix("file:").or_else(|| spec.strip_prefix("usernames:file:"))?;
    (path != "-").then_some(path)
}

/// Parses a payload source:
/// `list:a,b,c` (comma-separated; `\,` for a literal comma), `file:PATH` (one per line; `file:-`
/// for stdin), `range:FROM-TO[:STEP]` (zero padding kept, e.g. 001-100), `wordlist:NAME` (a
/// built-in list; see `brainproxy wordlists list`), and the generators: `null:N`,
/// `dates:FROM..TO[:STEP][:FORMAT]`, `brute:CHARSET:MIN-MAX`, `case:WORD`, `subst:WORD[:MAP]`,
/// `bitflip[:VALUE]`, `usernames:list:NAMES` or `usernames:file:PATH`, `copy:N` and
/// `extract[:FIRST]`. `oob:` and `script:` need the project and are the caller's to read.
pub fn load_payloads(spec: &str, stdin: &mut dyn FnMut() -> Result<Vec<u8>>) -> Result<Set> {
    let (kind, arg) = match spec.split_once(':') {
        Some(parts) => parts,
        None if spec == "bitflip" || spec == "extract" => (spec, ""),
        None => return Err(bad_spec(spec)),
    };
    let list = |v: Vec<Vec<u8>>| Ok(Set::List(v));
    match kind {
        "list" => list(split_list(arg)),
        "file" => {
            let data = if arg == "-" { stdin()? } else { read_file(arg)? };
            list(lines(&data))
        }
        "range" => list(range(spec, arg)?),
        "wordlist" => {
            crate::wordlists::get(arg).map(|l| Set::List(l.map(|e| e.as_bytes().to_vec()).collect())).ok_or_else(|| {
                let names: Vec<&str> = crate::wordlists::names().collect();
                Error::NotFound(format!("wordlist {arg:?}; built-in lists: {}", names.join(", ")))
            })
        }
        "null" => {
            let n: u64 = arg.parse().map_err(|_| bad_spec(spec))?;
            if n == 0 || n > MAX_SET {
                return Err(Error::InvalidInput(format!("null:N takes 1 to {MAX_SET} payloads")));
            }
            Ok(Set::Lazy { gen: Gen::Null(n), each: Vec::new() })
        }
        "dates" => list(dates(arg)?),
        "brute" => Ok(Set::Lazy { gen: Gen::Brute(brute(arg)?), each: Vec::new() }),
        "case" => list(case(arg)?),
        "subst" => list(subst(arg)?),
        "bitflip" => {
            let value = (!arg.is_empty() || spec.ends_with(':')).then(|| arg.as_bytes().to_vec());
            if value.as_ref().is_some_and(|v| v.len() as u64 * 8 > MAX_SET) {
                return Err(Error::InvalidInput(format!("bitflip: the value is over {} bytes", MAX_SET / 8)));
            }
            Ok(Set::Lazy { gen: Gen::BitFlip(value), each: Vec::new() })
        }
        "usernames" => list(usernames(spec, arg)?),
        "copy" => match arg.parse::<usize>() {
            Ok(n) if n >= 1 => Ok(Set::Copy(n - 1)),
            _ => Err(Error::InvalidInput(format!("copy:{arg}: N is a position, counted from 1"))),
        },
        "extract" => Ok(Set::Extract {
            first: (!arg.is_empty() || spec.ends_with(':')).then(|| arg.as_bytes().to_vec()),
            each: Vec::new(),
        }),
        "oob" | "script" => Err(Error::InvalidInput(format!("{kind}: payloads are made by the fuzz command"))),
        _ => Err(bad_spec(spec)),
    }
}

fn bad_spec(spec: &str) -> Error {
    Error::InvalidInput(format!(
        "bad payload source {spec:?}; use list:a,b,c | file:PATH | range:1-100[:step] | wordlist:NAME | null:N | \
         dates:FROM..TO[:STEP][:FORMAT] | brute:CHARSET:MIN-MAX | case:WORD | subst:WORD[:MAP] | bitflip[:VALUE] | \
         usernames:list:NAMES | usernames:file:PATH | copy:N | extract[:FIRST] | oob:N[:host|url] | script:FILE"
    ))
}

fn read_file(path: &str) -> Result<Vec<u8>> {
    std::fs::read(path).map_err(|e| Error::InvalidInput(format!("payload file {path:?}: {e}")))
}

/// Non-empty lines, without their CR.
fn lines(data: &[u8]) -> Vec<Vec<u8>> {
    data.split(|&b| b == b'\n').map(|l| l.strip_suffix(b"\r").unwrap_or(l).to_vec()).filter(|l| !l.is_empty()).collect()
}

fn split_list(arg: &str) -> Vec<Vec<u8>> {
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
    out
}

fn range(spec: &str, arg: &str) -> Result<Vec<Vec<u8>>> {
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
    let (a, b): (i64, i64) = (from.parse().map_err(|_| bad_spec(spec))?, to.parse().map_err(|_| bad_spec(spec))?);
    if step <= 0 {
        return Err(Error::InvalidInput("range step must be positive".into()));
    }
    let span = a.abs_diff(b) / step as u64;
    if span >= MAX_SET {
        return Err(Error::InvalidInput(format!(
            "range {spec:?} has {} values; max 10,000,000",
            span.saturating_add(1)
        )));
    }
    let count = span as i64 + 1;
    let dir = if b >= a { 1 } else { -1 };
    Ok((0..count).map(|i| format!("{:0width$}", a + dir * i * step).into_bytes()).collect())
}

/// `CHARSET:MIN-MAX` (or `CHARSET:N`); the charset takes ranges (`a-z0-9`), `\` escapes the
/// next character, and a `-` first or last is itself.
fn brute(arg: &str) -> Result<Brute> {
    let bad = || Error::InvalidInput(format!("brute:{arg}: use brute:CHARSET:MIN-MAX, e.g. brute:a-z0-9:1-4"));
    let (set, lens) = arg.rsplit_once(':').ok_or_else(bad)?;
    let (min, max) = match lens.split_once('-') {
        Some((a, b)) => (a.parse::<u32>().map_err(|_| bad())?, b.parse::<u32>().map_err(|_| bad())?),
        None => {
            let n = lens.parse::<u32>().map_err(|_| bad())?;
            (n, n)
        }
    };
    if min == 0 || min > max || max > MAX_BRUTE_LEN {
        return Err(Error::InvalidInput(format!("brute:{arg}: lengths are 1 to {MAX_BRUTE_LEN}, the smaller first")));
    }
    let mut charset: Vec<char> = Vec::new();
    let chars: Vec<char> = set.chars().collect();
    let mut i = 0;
    let add = |c: char, charset: &mut Vec<char>| {
        if !charset.contains(&c) {
            charset.push(c);
        }
    };
    while i < chars.len() {
        let c = chars[i];
        if c == '\\' && i + 1 < chars.len() {
            add(chars[i + 1], &mut charset);
            i += 2;
        } else if i + 2 < chars.len() && chars[i + 1] == '-' {
            let (a, b) = (c, chars[i + 2]);
            if a > b {
                return Err(Error::InvalidInput(format!("brute:{arg}: the range {a}-{b} runs backwards")));
            }
            for c in a..=b {
                add(c, &mut charset);
            }
            i += 3;
        } else {
            add(c, &mut charset);
            i += 1;
        }
    }
    if charset.is_empty() {
        return Err(bad());
    }
    let n = charset.len() as u64;
    let mut total: u64 = 0;
    for k in min..=max {
        total = n.checked_pow(k).and_then(|c| total.checked_add(c)).filter(|t| *t <= MAX_SET).ok_or_else(|| {
            Error::InvalidInput(format!(
                "brute:{arg} has over {MAX_SET} values ({n} characters, lengths {min}-{max}); narrow it"
            ))
        })?;
    }
    Ok(Brute { charset, min, max, total })
}

/// Every upper and lower case combination of the word's letters, the word as given first.
fn case(word: &str) -> Result<Vec<Vec<u8>>> {
    let chars: Vec<char> = word.chars().collect();
    let letters: Vec<usize> =
        (0..chars.len()).filter(|&i| chars[i].to_uppercase().ne(chars[i].to_lowercase())).collect();
    if letters.len() > MAX_CASE_LETTERS {
        return Err(Error::InvalidInput(format!("case: takes at most {MAX_CASE_LETTERS} letters")));
    }
    if word.is_empty() {
        return Err(Error::InvalidInput("case: needs a word".into()));
    }
    let mut out = Vec::new();
    let mut seen = std::collections::HashSet::new();
    for mask in 0u32..(1u32 << letters.len()) {
        let mut s = String::with_capacity(word.len());
        for (i, c) in chars.iter().enumerate() {
            match letters.iter().position(|&l| l == i) {
                // Bit set: the other case from the one given; the last letter changes fastest.
                Some(k) if mask & (1 << (letters.len() - 1 - k)) != 0 => {
                    if c.is_uppercase() {
                        s.extend(c.to_lowercase());
                    } else {
                        s.extend(c.to_uppercase());
                    }
                }
                _ => s.push(*c),
            }
        }
        if seen.insert(s.clone()) {
            out.push(s.into_bytes());
        }
    }
    Ok(out)
}

/// `WORD[:MAP]`: every way of substituting characters (a→4/@, e→3, i→1/!, o→0, s→5/$ unless a
/// map such as `a=4@,e=3` is given), the word as given first.
fn subst(arg: &str) -> Result<Vec<Vec<u8>>> {
    let (word, map) = arg.split_once(':').unwrap_or((arg, "a=4@,e=3,i=1!,o=0,s=5$"));
    if word.is_empty() {
        return Err(Error::InvalidInput("subst: needs a word".into()));
    }
    let mut table: Vec<(char, Vec<char>)> = Vec::new();
    for entry in map.split(',').filter(|e| !e.is_empty()) {
        let mut chars = entry.chars();
        let (Some(from), Some('=')) = (chars.next(), chars.next()) else {
            return Err(Error::InvalidInput(format!("subst: map entry {entry:?}; use a=4@,e=3")));
        };
        let to: Vec<char> = chars.collect();
        if to.is_empty() {
            return Err(Error::InvalidInput(format!("subst: map entry {entry:?} substitutes nothing")));
        }
        table.push((from.to_lowercase().next().unwrap_or(from), to));
    }
    let options: Vec<Vec<char>> = word
        .chars()
        .map(|c| {
            let key = c.to_lowercase().next().unwrap_or(c);
            let mut o = vec![c];
            for (_, to) in table.iter().filter(|(f, _)| *f == key) {
                o.extend(to.iter().filter(|t| **t != c));
            }
            o
        })
        .collect();
    let count = options.iter().try_fold(1u64, |acc, o| acc.checked_mul(o.len() as u64).filter(|n| *n <= MAX_COMBOS));
    let count = count.ok_or_else(|| Error::InvalidInput(format!("subst:{word} has over {MAX_COMBOS} combinations")))?;
    Ok((0..count)
        .map(|mut i| {
            let mut s = vec!['\0'; options.len()];
            for (slot, o) in s.iter_mut().zip(&options).rev() {
                *slot = o[(i % o.len() as u64) as usize];
                i /= o.len() as u64;
            }
            s.into_iter().collect::<String>().into_bytes()
        })
        .collect())
}

/// `FROM..TO[:STEP][:FORMAT]`: dates YYYY-MM-DD, STEP as Nd, Nw, Nm or Ny (1d by default),
/// FORMAT with %Y %y %m %d %e %j %b %B %a %A %% (%Y-%m-%d by default).
fn dates(arg: &str) -> Result<Vec<Vec<u8>>> {
    use time::{Date, Duration, Month};
    let bad = || Error::InvalidInput(format!("dates:{arg}: use dates:2024-01-01..2024-12-31[:1d][:%Y%m%d]"));
    let (range, rest) = arg.split_once(':').map_or((arg, None), |(r, s)| (r, Some(s)));
    let (from, to) = range.split_once("..").ok_or_else(bad)?;
    let parse = |s: &str| -> Result<Date> {
        let mut p = s.splitn(3, '-');
        let (y, m, d) = (p.next(), p.next(), p.next());
        let (Some(y), Some(m), Some(d)) = (y, m, d) else { return Err(bad()) };
        let y: i32 = y.parse().map_err(|_| bad())?;
        let m: u8 = m.parse().map_err(|_| bad())?;
        let d: u8 = d.parse().map_err(|_| bad())?;
        let m = Month::try_from(m).map_err(|_| bad())?;
        Date::from_calendar_date(y, m, d).map_err(|_| Error::InvalidInput(format!("dates: {s} is no date")))
    };
    let (from, to) = (parse(from)?, parse(to)?);
    let is_step = |s: &str| {
        s.len() > 1 && s[..s.len() - 1].bytes().all(|b| b.is_ascii_digit()) && s.ends_with(['d', 'w', 'm', 'y'])
    };
    let (step, format) = match rest {
        None => ("1d", "%Y-%m-%d"),
        Some(r) => match r.split_once(':') {
            Some((s, f)) if is_step(s) => (s, f),
            _ if is_step(r) => (r, "%Y-%m-%d"),
            _ => ("1d", r),
        },
    };
    let n: i64 = step[..step.len() - 1].parse().map_err(|_| bad())?;
    if n == 0 {
        return Err(Error::InvalidInput("dates: the step must be at least 1".into()));
    }
    let unit = step.as_bytes()[step.len() - 1];
    let back = to < from;
    let months_of = |d: Date| d.year() as i64 * 12 + (d.month() as i64 - 1);
    let mut out = Vec::new();
    for k in 0i64.. {
        let k = if back { -k } else { k };
        let date = match unit {
            b'd' | b'w' => {
                let days = k.checked_mul(n * if unit == b'w' { 7 } else { 1 });
                days.and_then(|days| from.checked_add(Duration::days(days)))
            }
            _ => {
                // A month or year on: the same day, or the month's last if it has fewer days.
                let months = k.checked_mul(n * if unit == b'y' { 12 } else { 1 }).map(|m| months_of(from) + m);
                months.and_then(|m| {
                    let (y, mo) =
                        (i32::try_from(m.div_euclid(12)).ok()?, Month::try_from(m.rem_euclid(12) as u8 + 1).ok()?);
                    Date::from_calendar_date(y, mo, from.day().min(mo.length(y))).ok()
                })
            }
        };
        let Some(date) = date.filter(|d| if back { *d >= to } else { *d <= to }) else { break };
        out.push(format_date(date, format)?.into_bytes());
        if out.len() as u64 > MAX_SET {
            return Err(Error::InvalidInput(format!("dates:{arg} has over {MAX_SET} values")));
        }
    }
    Ok(out)
}

fn format_date(d: time::Date, format: &str) -> Result<String> {
    const MONTHS: [&str; 12] = [
        "January",
        "February",
        "March",
        "April",
        "May",
        "June",
        "July",
        "August",
        "September",
        "October",
        "November",
        "December",
    ];
    const DAYS: [&str; 7] = ["Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", "Sunday"];
    let mut s = String::new();
    let mut chars = format.chars();
    while let Some(c) = chars.next() {
        if c != '%' {
            s.push(c);
            continue;
        }
        let month = MONTHS[d.month() as usize - 1];
        let day = DAYS[d.weekday().number_days_from_monday() as usize];
        match chars.next() {
            Some('Y') => s.push_str(&format!("{:04}", d.year())),
            Some('y') => s.push_str(&format!("{:02}", d.year().rem_euclid(100))),
            Some('m') => s.push_str(&format!("{:02}", d.month() as u8)),
            Some('d') => s.push_str(&format!("{:02}", d.day())),
            Some('e') => s.push_str(&d.day().to_string()),
            Some('j') => s.push_str(&format!("{:03}", d.ordinal())),
            Some('b') => s.push_str(month.get(..3).unwrap_or(month)),
            Some('B') => s.push_str(month),
            Some('a') => s.push_str(day.get(..3).unwrap_or(day)),
            Some('A') => s.push_str(day),
            Some('%') => s.push('%'),
            other => {
                return Err(Error::InvalidInput(format!(
                    "dates: unknown format %{}; use %Y %y %m %d %e %j %b %B %a %A %%",
                    other.map(String::from).unwrap_or_default()
                )))
            }
        }
    }
    Ok(s)
}

/// Usernames from full names ("John Smith"): jsmith, john.smith, john_smith, johns, smithj,
/// j.smith, john, smith, johnsmith, smith.john. A one-word name is itself.
fn usernames(spec: &str, arg: &str) -> Result<Vec<Vec<u8>>> {
    let names: Vec<String> = match arg.split_once(':') {
        Some(("list", names)) => {
            split_list(names).into_iter().map(|n| String::from_utf8_lossy(&n).into_owned()).collect()
        }
        Some(("file", path)) => {
            lines(&read_file(path)?).into_iter().map(|n| String::from_utf8_lossy(&n).into_owned()).collect()
        }
        _ => return Err(bad_spec(spec)),
    };
    let mut out: Vec<Vec<u8>> = Vec::new();
    let mut push = |s: String| {
        let s = s.into_bytes();
        if !s.is_empty() && !out.contains(&s) {
            out.push(s);
        }
    };
    for name in &names {
        let parts: Vec<String> = name.split_whitespace().map(str::to_lowercase).collect();
        let (Some(first), Some(last)) = (parts.first(), parts.last()) else { continue };
        if parts.len() == 1 {
            push(first.clone());
            continue;
        }
        let initial = |s: &str| s.chars().next().map(String::from).unwrap_or_default();
        let (f, l) = (initial(first), initial(last));
        for u in [
            format!("{f}{last}"),
            format!("{first}.{last}"),
            format!("{first}_{last}"),
            format!("{first}{l}"),
            format!("{last}{f}"),
            format!("{f}.{last}"),
            first.clone(),
            last.clone(),
            format!("{first}{last}"),
            format!("{last}.{first}"),
        ] {
            push(u);
        }
    }
    if out.is_empty() {
        return Err(Error::InvalidInput(format!("{spec:?} gives no usernames")));
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn load(spec: &str) -> Set {
        load_payloads(spec, &mut || -> Result<Vec<u8>> { unreachable!() }).unwrap()
    }

    fn strings(set: &Set) -> Vec<String> {
        (0..set.count().unwrap()).map(|i| String::from_utf8(set.get(i)).unwrap()).collect()
    }

    fn err(spec: &str) -> String {
        load_payloads(spec, &mut || -> Result<Vec<u8>> { unreachable!() }).unwrap_err().to_string()
    }

    #[test]
    fn null_payloads_are_empty_and_capped() {
        let s = load("null:3");
        assert_eq!(strings(&s), ["", "", ""]);
        assert!(matches!(s, Set::Lazy { .. }));
        assert!(err("null:0").contains("1 to"));
        assert!(err("null:10000001").contains("1 to"));
    }

    #[test]
    fn dates_step_and_format() {
        assert_eq!(
            strings(&load("dates:2024-02-27..2024-03-01")),
            ["2024-02-27", "2024-02-28", "2024-02-29", "2024-03-01"]
        );
        assert_eq!(strings(&load("dates:2024-01-01..2024-01-15:1w:%Y%m%d")), ["20240101", "20240108", "20240115"]);
        assert_eq!(
            strings(&load("dates:2024-01-31..2024-04-30:1m")),
            ["2024-01-31", "2024-02-29", "2024-03-31", "2024-04-30"]
        );
        assert_eq!(strings(&load("dates:2024-01-03..2024-01-01:%d/%m/%y")), ["03/01/24", "02/01/24", "01/01/24"]);
        assert_eq!(
            strings(&load("dates:2023-03-05..2025-03-05:1y:%a %e %b %Y, day %j")),
            ["Sun 5 Mar 2023, day 064", "Tue 5 Mar 2024, day 065", "Wed 5 Mar 2025, day 064"]
        );
        assert_eq!(load("dates:2000-01-01..2000-12-31").count(), Some(366));
        assert!(err("dates:2024-02-30..2024-03-01").contains("no date"));
        assert!(err("dates:2024-01-01..2024-01-02:%Q").contains("unknown format %Q"));
        assert!(err("dates:2024-01-01").contains("use dates:"));
    }

    #[test]
    fn brute_force_is_lazy_counted_and_capped() {
        let s = load("brute:ab:1-2");
        assert_eq!(strings(&s), ["a", "b", "aa", "ab", "ba", "bb"]);
        let s = load("brute:a-c0-1\\-:2");
        let Set::Lazy { gen: Gen::Brute(b), .. } = &s else { panic!() };
        assert_eq!(b.charset, ['a', 'b', 'c', '0', '1', '-']);
        assert_eq!(s.count(), Some(36));
        // Lazy get matches a build that counts in base n, length by length.
        let s = load("brute:a-z0-9:1-4");
        assert_eq!(s.count(), Some(36 + 36 * 36 + 36u64.pow(3) + 36u64.pow(4)));
        let chars: Vec<char> = ('a'..='z').chain('0'..='9').collect();
        let mut eager = Vec::new();
        for k in 1..=3u32 {
            for i in 0..36u64.pow(k) {
                let mut v = vec!['\0'; k as usize];
                let mut x = i;
                for slot in v.iter_mut().rev() {
                    *slot = chars[(x % 36) as usize];
                    x /= 36;
                }
                eager.push(v.into_iter().collect::<String>());
            }
        }
        for (i, want) in eager.iter().enumerate() {
            assert_eq!(&String::from_utf8(s.get(i as u64)).unwrap(), want);
        }
        assert_eq!(s.get(s.count().unwrap() - 1), b"9999");
        // A dash first or last is itself.
        assert_eq!(strings(&load("brute:-a:1")), ["-", "a"]);
        assert!(err("brute:a-z0-9:1-5").contains("over 10000000"));
        assert!(err("brute:z-a:1").contains("backwards"));
        assert!(err("brute:ab:3-2").contains("smaller first"));
        assert!(err("brute:ab").contains("use brute:"));
    }

    #[test]
    fn case_combinations() {
        assert_eq!(strings(&load("case:ab1")), ["ab1", "aB1", "Ab1", "AB1"]);
        assert_eq!(load("case:Admin").count(), Some(32));
        assert_eq!(strings(&load("case:Ab"))[0], "Ab");
        assert!(err(&format!("case:{}", "a".repeat(21))).contains("at most 20"));
        assert_eq!(load(&format!("case:{}", "a".repeat(20))).count(), Some(1 << 20));
    }

    #[test]
    fn character_substitution() {
        let s = strings(&load("subst:pass"));
        assert_eq!(s.len(), 27);
        assert_eq!(s[0], "pass");
        assert!(s.contains(&"p@5$".to_string()) && s.contains(&"p4ss".to_string()));
        assert_eq!(strings(&load("subst:Ae:a=4@,e=3")), ["Ae", "A3", "4e", "43", "@e", "@3"]);
        assert!(err("subst:a:a").contains("map entry"));
        assert!(err(&format!("subst:{}", "s".repeat(13))).contains("over 1000000"));
    }

    #[test]
    fn bit_flips() {
        let s = load("bitflip:AB");
        assert_eq!(s.count(), Some(16));
        assert_eq!(s.get(0), b"@B");
        assert_eq!(s.get(15), [b'A', b'B' ^ 0x80]);
        // Without a value it waits for the position's (see the plan).
        assert_eq!(load("bitflip"), Set::Lazy { gen: Gen::BitFlip(None), each: vec![] });
        // A flip can make a line break of a byte one bit away from one.
        assert!(load("bitflip:\x0b").may_break_line());
        assert!(!load("bitflip:a").may_break_line());
    }

    #[test]
    fn usernames_from_names() {
        let s = strings(&load("usernames:list:John Smith,alice"));
        assert_eq!(
            s,
            [
                "jsmith",
                "john.smith",
                "john_smith",
                "johns",
                "smithj",
                "j.smith",
                "john",
                "smith",
                "johnsmith",
                "smith.john",
                "alice"
            ]
        );
        let dir = std::env::temp_dir().join(format!("bp-usernames-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let file = dir.join("names.txt");
        std::fs::write(&file, "Ann Lee\r\n\nAnn Lee\n").unwrap();
        let spec = format!("usernames:file:{}", file.display());
        assert_eq!(load(&spec).count(), Some(10));
        assert_eq!(source_file(&spec), Some(file.to_str().unwrap()));
        let _ = std::fs::remove_dir_all(dir);
        assert!(err("usernames:Ann").contains("bad payload source"));
    }

    #[test]
    fn copy_extract_and_others() {
        assert_eq!(load("copy:2"), Set::Copy(1));
        assert!(err("copy:0").contains("from 1"));
        assert_eq!(load("extract"), Set::Extract { first: None, each: vec![] });
        assert_eq!(load("extract:go"), Set::Extract { first: Some(b"go".to_vec()), each: vec![] });
        assert_eq!(load("extract:"), Set::Extract { first: Some(vec![]), each: vec![] });
        assert!(err("oob:3").contains("made by the fuzz command"));
        assert_eq!(parse_oob("3").unwrap(), (3, OobForm::Url));
        assert_eq!(parse_oob("2:host").unwrap(), (2, OobForm::Host));
        assert!(parse_oob("0").is_err() && parse_oob("1:dns").is_err());
        assert_eq!(source_file("file:-"), None);
        assert!(err("nope:1").contains("brute:CHARSET"));
    }
}
