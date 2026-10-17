//! A subset of the Nuclei DSL (govaluate expressions plus helper functions) for
//! `type: dsl` matchers and extractors. Expressions are parsed when a template
//! loads, so an unknown function or bad syntax makes the template unsupported
//! instead of failing at scan time. Evaluation is pure: functions only compute
//! over their arguments (strings, numbers, booleans); none does I/O.

use std::sync::{Arc, OnceLock};

use base64::Engine;
use regex::Regex;

/// Expressions longer than this are rejected (templates are data).
const MAX_EXPR: usize = 16 << 10;
/// Nesting (parentheses, calls, unary operators); the parser recurses this deep.
const MAX_DEPTH: usize = 32;
/// Binary operators per expression. Chains nest to the left, so this bounds
/// how deep evaluation recurses.
const MAX_OPS: usize = 512;
/// Values bigger than this make the evaluation fail (`concat`/`+` on bodies).
const MAX_VALUE: usize = 32 << 20;

#[derive(Debug, Clone, PartialEq)]
pub(crate) enum Value {
    Str(String),
    Num(f64),
    Bool(bool),
}

impl Value {
    pub fn into_string(self) -> String {
        match self {
            Value::Str(s) => s,
            Value::Num(n) => fmt_num(n),
            Value::Bool(b) => b.to_string(),
        }
    }

    fn as_str(&self) -> std::borrow::Cow<'_, str> {
        match self {
            Value::Str(s) => s.as_str().into(),
            v => v.clone().into_string().into(),
        }
    }

    fn as_num(&self) -> Option<f64> {
        match self {
            Value::Num(n) => Some(*n),
            Value::Str(s) => s.trim().parse().ok(),
            Value::Bool(_) => None,
        }
    }
}

fn fmt_num(n: f64) -> String {
    if n.fract() == 0.0 && n.abs() < 1e15 {
        format!("{}", n as i64)
    } else {
        n.to_string()
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub(crate) enum Op {
    Or,
    And,
    Eq,
    Ne,
    Lt,
    Le,
    Gt,
    Ge,
    Add,
    Sub,
    Mul,
    Div,
    Rem,
}

#[derive(Debug, Clone)]
pub(crate) enum Expr {
    Lit(Value),
    Var(String),
    Not(Box<Expr>),
    Neg(Box<Expr>),
    Bin(Op, Box<Expr>, Box<Expr>),
    Call(Func, Vec<Expr>, LazyRegex),
}

/// The regex argument of `regex`/`replace_regex` when it is a literal, compiled
/// on first use (some templates carry many).
#[derive(Debug, Clone, Default)]
pub(crate) struct LazyRegex(Option<(String, Arc<OnceLock<Option<Regex>>>)>);

impl LazyRegex {
    fn get(&self) -> Option<Option<&Regex>> {
        self.0.as_ref().map(|(src, cell)| cell.get_or_init(|| build_regex(src)).as_ref())
    }
}

fn build_regex(src: &str) -> Option<Regex> {
    regex::RegexBuilder::new(src).size_limit(1 << 22).build().ok()
}

/// Supported functions with their argument counts (min, max; None = any).
#[derive(Debug, Clone, Copy, PartialEq)]
pub(crate) enum Func {
    Contains,
    ContainsAll,
    ContainsAny,
    StartsWith,
    EndsWith,
    ToLower,
    ToUpper,
    Len,
    Regex,
    ReplaceRegex,
    Replace,
    Concat,
    Trim,
    TrimSpace,
    TrimLeft,
    TrimRight,
    TrimPrefix,
    TrimSuffix,
    ToString,
    ToNumber,
    Substr,
    Md5,
    Sha1,
    Sha256,
    Base64,
    Base64Py,
    Base64Decode,
    HexEncode,
    HexDecode,
    UrlEncode,
    UrlDecode,
    Mmh3,
    Repeat,
    RandBase,
    RandTextAlpha,
    RandTextAlphanumeric,
    RandTextNumeric,
    RandInt,
    UnixTime,
    CompareVersions,
}

fn func(name: &str) -> Option<(Func, usize, Option<usize>)> {
    use Func::*;
    Some(match name {
        "contains" => (Contains, 2, Some(2)),
        "contains_all" => (ContainsAll, 2, None),
        "contains_any" => (ContainsAny, 2, None),
        "starts_with" | "startswith" => (StartsWith, 2, None),
        "ends_with" | "endswith" => (EndsWith, 2, None),
        "to_lower" | "tolower" => (ToLower, 1, Some(1)),
        "to_upper" | "toupper" => (ToUpper, 1, Some(1)),
        "len" => (Len, 1, Some(1)),
        "regex" => (Regex, 2, Some(2)),
        "replace_regex" => (ReplaceRegex, 3, Some(3)),
        "replace" => (Replace, 3, Some(3)),
        "concat" => (Concat, 1, None),
        "trim" => (Trim, 2, Some(2)),
        "trim_space" => (TrimSpace, 1, Some(1)),
        "trim_left" => (TrimLeft, 2, Some(2)),
        "trim_right" => (TrimRight, 2, Some(2)),
        "trim_prefix" => (TrimPrefix, 2, Some(2)),
        "trim_suffix" => (TrimSuffix, 2, Some(2)),
        "to_string" | "tostring" => (ToString, 1, Some(1)),
        "to_number" => (ToNumber, 1, Some(1)),
        "substr" => (Substr, 2, Some(3)),
        "md5" => (Md5, 1, Some(1)),
        "sha1" => (Sha1, 1, Some(1)),
        "sha256" => (Sha256, 1, Some(1)),
        "base64" => (Base64, 1, Some(1)),
        "base64_py" => (Base64Py, 1, Some(1)),
        "base64_decode" => (Base64Decode, 1, Some(1)),
        "hex_encode" => (HexEncode, 1, Some(1)),
        "hex_decode" => (HexDecode, 1, Some(1)),
        "url_encode" => (UrlEncode, 1, Some(1)),
        "url_decode" => (UrlDecode, 1, Some(1)),
        "mmh3" => (Mmh3, 1, Some(1)),
        "repeat" => (Repeat, 2, Some(2)),
        "rand_base" => (RandBase, 1, Some(2)),
        "rand_text_alpha" => (RandTextAlpha, 1, Some(2)),
        "rand_text_alphanumeric" => (RandTextAlphanumeric, 1, Some(2)),
        "rand_text_numeric" => (RandTextNumeric, 1, Some(2)),
        "rand_int" => (RandInt, 0, Some(2)),
        "unix_time" => (UnixTime, 0, Some(1)),
        "compare_versions" => (CompareVersions, 2, None),
        _ => return None,
    })
}

/// Why an expression can't be used: `Unsupported` for valid Nuclei outside the
/// subset, `Invalid` for syntax errors.
#[derive(Debug, PartialEq)]
pub(crate) enum ParseError {
    Unsupported(String),
    Invalid(String),
}

type PResult<T> = std::result::Result<T, ParseError>;

#[derive(Debug, Clone, PartialEq)]
enum Tok {
    Str(String),
    Num(f64),
    Ident(String),
    Op(&'static str),
    LParen,
    RParen,
    Comma,
}

fn lex(src: &str) -> PResult<Vec<Tok>> {
    const OPS: &[&str] = &[
        "&&", "||", "==", "!=", "<=", ">=", "=~", "!~", "**", "<<", ">>", "<", ">", "+", "-", "*", "/", "%", "!", "?",
        ":", "&", "|", "^", "~",
    ];
    let b = src.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i < b.len() {
        let c = b[i];
        match c {
            _ if c.is_ascii_whitespace() => i += 1,
            b'(' => (out.push(Tok::LParen), i += 1).1,
            b')' => (out.push(Tok::RParen), i += 1).1,
            b',' => (out.push(Tok::Comma), i += 1).1,
            b'"' | b'\'' => {
                // `\\` and an escaped quote unescape; other backslashes are kept
                // (templates write regexes both as "\\d" and "\d").
                let mut s = Vec::new();
                i += 1;
                loop {
                    match b.get(i) {
                        None => return Err(ParseError::Invalid("unterminated string".into())),
                        Some(&q) if q == c => break,
                        Some(b'\\') if matches!(b.get(i + 1), Some(b'\\' | b'"' | b'\'')) => {
                            s.push(b[i + 1]);
                            i += 2;
                            continue;
                        }
                        Some(&x) => s.push(x),
                    }
                    i += 1;
                }
                i += 1;
                out.push(Tok::Str(String::from_utf8_lossy(&s).into_owned()));
            }
            b'0'..=b'9' => {
                let start = i;
                while i < b.len() && (b[i].is_ascii_digit() || b[i] == b'.') {
                    i += 1;
                }
                let n = src[start..i].parse().map_err(|_| ParseError::Invalid("bad number".into()))?;
                out.push(Tok::Num(n));
            }
            _ if c.is_ascii_alphabetic() || c == b'_' => {
                let start = i;
                while i < b.len() && (b[i].is_ascii_alphanumeric() || b[i] == b'_') {
                    i += 1;
                }
                out.push(Tok::Ident(src[start..i].to_string()));
            }
            _ => {
                let Some(op) = OPS.iter().find(|o| src[i..].starts_with(**o)) else {
                    return Err(ParseError::Invalid(format!("unexpected character {:?}", c as char)));
                };
                out.push(Tok::Op(op));
                i += op.len();
            }
        }
    }
    Ok(out)
}

struct Parser {
    toks: Vec<Tok>,
    pos: usize,
    depth: usize,
    ops: usize,
}

/// Parses one expression.
pub(crate) fn parse(src: &str) -> PResult<Expr> {
    if src.len() > MAX_EXPR {
        return Err(ParseError::Invalid("expression too long".into()));
    }
    let mut p = Parser { toks: lex(src)?, pos: 0, depth: 0, ops: 0 };
    let e = p.binary(0)?;
    match p.toks.get(p.pos) {
        None => Ok(e),
        Some(Tok::Op(op)) => Err(ParseError::Unsupported(format!("DSL operator `{op}`"))),
        Some(t) => Err(ParseError::Invalid(format!("unexpected {t:?}"))),
    }
}

/// Binary operators by precedence level (lowest first), like govaluate.
const LEVELS: &[&[(&str, Op)]] = &[
    &[("||", Op::Or)],
    &[("&&", Op::And)],
    &[("==", Op::Eq), ("!=", Op::Ne), ("<=", Op::Le), (">=", Op::Ge), ("<", Op::Lt), (">", Op::Gt)],
    &[("+", Op::Add), ("-", Op::Sub)],
    &[("*", Op::Mul), ("/", Op::Div), ("%", Op::Rem)],
];

impl Parser {
    fn peek(&self) -> Option<&Tok> {
        self.toks.get(self.pos)
    }

    fn next(&mut self) -> Option<Tok> {
        let t = self.toks.get(self.pos).cloned();
        self.pos += 1;
        t
    }

    fn enter(&mut self) -> PResult<()> {
        self.depth += 1;
        if self.depth > MAX_DEPTH {
            return Err(ParseError::Invalid("expression nested too deeply".into()));
        }
        Ok(())
    }

    fn binary(&mut self, level: usize) -> PResult<Expr> {
        if level == LEVELS.len() {
            return self.unary();
        }
        let mut left = self.binary(level + 1)?;
        while let Some(Tok::Op(op)) = self.peek() {
            let Some(&(_, o)) = LEVELS[level].iter().find(|(s, _)| s == op) else { break };
            self.pos += 1;
            self.ops += 1;
            if self.ops > MAX_OPS {
                return Err(ParseError::Invalid("expression too long".into()));
            }
            let right = self.binary(level + 1)?;
            left = Expr::Bin(o, Box::new(left), Box::new(right));
        }
        Ok(left)
    }

    fn unary(&mut self) -> PResult<Expr> {
        self.enter()?;
        let e = match self.peek() {
            Some(Tok::Op("!")) => {
                self.pos += 1;
                Expr::Not(Box::new(self.unary()?))
            }
            Some(Tok::Op("-")) => {
                self.pos += 1;
                Expr::Neg(Box::new(self.unary()?))
            }
            _ => self.primary()?,
        };
        self.depth -= 1;
        Ok(e)
    }

    fn primary(&mut self) -> PResult<Expr> {
        match self.next() {
            Some(Tok::Str(s)) => Ok(Expr::Lit(Value::Str(s))),
            Some(Tok::Num(n)) => Ok(Expr::Lit(Value::Num(n))),
            Some(Tok::LParen) => {
                let e = self.binary(0)?;
                match self.next() {
                    Some(Tok::RParen) => Ok(e),
                    _ => Err(ParseError::Invalid("missing `)`".into())),
                }
            }
            Some(Tok::Ident(name)) if self.peek() == Some(&Tok::LParen) => {
                self.pos += 1;
                let mut args = Vec::new();
                if self.peek() == Some(&Tok::RParen) {
                    self.pos += 1;
                } else {
                    loop {
                        args.push(self.binary(0)?);
                        match self.next() {
                            Some(Tok::Comma) => {}
                            Some(Tok::RParen) => break,
                            _ => return Err(ParseError::Invalid(format!("bad arguments to `{name}`"))),
                        }
                    }
                }
                let Some((f, min, max)) = func(&name) else {
                    return Err(ParseError::Unsupported(format!("DSL function `{name}`")));
                };
                if args.len() < min || max.is_some_and(|m| args.len() > m) {
                    return Err(ParseError::Invalid(format!("wrong number of arguments to `{name}`")));
                }
                let mut re = LazyRegex::default();
                let pattern = match f {
                    Func::Regex => args.first(),
                    Func::ReplaceRegex => args.get(1),
                    _ => None,
                };
                if let Some(Expr::Lit(Value::Str(src))) = pattern {
                    // Lookaround and backreferences (RE2 lacks them too) fail here.
                    if regex_syntax::ast::parse::Parser::new().parse(src).is_err() {
                        return Err(ParseError::Unsupported("regex syntax (lookaround/backreference)".into()));
                    }
                    re = LazyRegex(Some((src.clone(), Default::default())));
                }
                Ok(Expr::Call(f, args, re))
            }
            Some(Tok::Ident(name)) => Ok(match name.as_str() {
                "true" => Expr::Lit(Value::Bool(true)),
                "false" => Expr::Lit(Value::Bool(false)),
                _ => Expr::Var(name),
            }),
            Some(t) => Err(ParseError::Invalid(format!("unexpected {t:?}"))),
            None => Err(ParseError::Invalid("unexpected end of expression".into())),
        }
    }
}

impl Expr {
    /// Every variable the expression reads.
    pub fn vars<'a>(&'a self, out: &mut Vec<&'a str>) {
        match self {
            Expr::Lit(_) => {}
            Expr::Var(v) => out.push(v),
            Expr::Not(e) | Expr::Neg(e) => e.vars(out),
            Expr::Bin(_, a, b) => {
                a.vars(out);
                b.vars(out);
            }
            Expr::Call(_, args, _) => args.iter().for_each(|a| a.vars(out)),
        }
    }

    /// Evaluates the expression; None when a variable is missing or a value has
    /// the wrong type (Nuclei treats such an evaluation as no match).
    pub fn eval(&self, env: &dyn Fn(&str) -> Option<Value>) -> Option<Value> {
        let v = match self {
            Expr::Lit(v) => v.clone(),
            Expr::Var(name) => env(name)?,
            Expr::Not(e) => match e.eval(env)? {
                Value::Bool(b) => Value::Bool(!b),
                _ => return None,
            },
            Expr::Neg(e) => Value::Num(-e.eval(env)?.as_num()?),
            Expr::Bin(Op::And, a, b) => Value::Bool(truthy(a.eval(env)?)? && truthy(b.eval(env)?)?),
            Expr::Bin(Op::Or, a, b) => Value::Bool(truthy(a.eval(env)?)? || truthy(b.eval(env)?)?),
            Expr::Bin(op, a, b) => binop(*op, a.eval(env)?, b.eval(env)?)?,
            Expr::Call(f, args, re) => {
                let vals = args.iter().map(|a| a.eval(env)).collect::<Option<Vec<_>>>()?;
                call(*f, vals, re)?
            }
        };
        match &v {
            Value::Str(s) if s.len() > MAX_VALUE => None,
            _ => Some(v),
        }
    }

    /// Evaluates a matcher expression: true only for a boolean `true`.
    pub fn matches(&self, env: &dyn Fn(&str) -> Option<Value>) -> bool {
        self.eval(env) == Some(Value::Bool(true))
    }
}

fn truthy(v: Value) -> Option<bool> {
    match v {
        Value::Bool(b) => Some(b),
        _ => None,
    }
}

fn binop(op: Op, a: Value, b: Value) -> Option<Value> {
    let nums = || Some((a.as_num()?, b.as_num()?));
    Some(match op {
        Op::Eq | Op::Ne => {
            let eq = match (&a, &b) {
                (Value::Num(x), Value::Num(y)) => x == y,
                (Value::Num(_), Value::Str(_)) | (Value::Str(_), Value::Num(_)) => match nums() {
                    Some((x, y)) => x == y,
                    None => a.as_str() == b.as_str(),
                },
                _ => a.as_str() == b.as_str(),
            };
            Value::Bool(eq == (op == Op::Eq))
        }
        Op::Lt | Op::Le | Op::Gt | Op::Ge => {
            let ord = match (nums(), &a, &b) {
                (Some((x, y)), _, _) => x.partial_cmp(&y)?,
                (None, Value::Str(x), Value::Str(y)) => x.cmp(y),
                _ => return None,
            };
            Value::Bool(match op {
                Op::Lt => ord.is_lt(),
                Op::Le => ord.is_le(),
                Op::Gt => ord.is_gt(),
                _ => ord.is_ge(),
            })
        }
        Op::Add => match (&a, &b) {
            (Value::Num(x), Value::Num(y)) => Value::Num(x + y),
            _ if a.as_str().len() + b.as_str().len() > MAX_VALUE => return None,
            _ => Value::Str(format!("{}{}", a.as_str(), b.as_str())),
        },
        Op::Sub | Op::Mul | Op::Div | Op::Rem => {
            let (x, y) = nums()?;
            Value::Num(match op {
                Op::Sub => x - y,
                Op::Mul => x * y,
                Op::Div => x / y,
                _ => x % y,
            })
        }
        Op::And | Op::Or => unreachable!("short-circuited in eval"),
    })
}

fn call(f: Func, args: Vec<Value>, re: &LazyRegex) -> Option<Value> {
    use Func::*;
    let s = |i: usize| args[i].as_str();
    let str_v = |x: String| Some(Value::Str(x));
    let rest = || args[1..].iter().map(|a| a.as_str());
    let regex_at = |i: usize| -> Option<std::borrow::Cow<'_, regex::Regex>> {
        match re.get() {
            Some(r) => r.map(std::borrow::Cow::Borrowed),
            None => build_regex(&s(i)).map(std::borrow::Cow::Owned),
        }
    };
    match f {
        Contains => Some(Value::Bool(s(0).contains(&*s(1)))),
        ContainsAll => Some(Value::Bool(rest().all(|x| s(0).contains(&*x)))),
        ContainsAny => Some(Value::Bool(rest().any(|x| s(0).contains(&*x)))),
        StartsWith => Some(Value::Bool(rest().any(|x| s(0).starts_with(&*x)))),
        EndsWith => Some(Value::Bool(rest().any(|x| s(0).ends_with(&*x)))),
        ToLower => str_v(s(0).to_lowercase()),
        ToUpper => str_v(s(0).to_uppercase()),
        Len => Some(Value::Num(s(0).len() as f64)),
        Regex => Some(Value::Bool(regex_at(0)?.is_match(&s(1)))),
        ReplaceRegex => str_v(regex_at(1)?.replace_all(&s(0), &*s(2)).into_owned()),
        Replace => str_v(s(0).replace(&*s(1), &s(2))),
        Concat => {
            let out: String = args.iter().map(|a| a.as_str()).collect();
            (out.len() <= MAX_VALUE).then_some(Value::Str(out))
        }
        Trim => {
            let cut = s(1);
            str_v(s(0).trim_matches(|c| cut.contains(c)).to_string())
        }
        TrimSpace => str_v(s(0).trim().to_string()),
        TrimLeft => {
            let cut = s(1);
            str_v(s(0).trim_start_matches(|c| cut.contains(c)).to_string())
        }
        TrimRight => {
            let cut = s(1);
            str_v(s(0).trim_end_matches(|c| cut.contains(c)).to_string())
        }
        TrimPrefix => str_v(s(0).strip_prefix(&*s(1)).map(str::to_string).unwrap_or_else(|| s(0).into_owned())),
        TrimSuffix => str_v(s(0).strip_suffix(&*s(1)).map(str::to_string).unwrap_or_else(|| s(0).into_owned())),
        ToString => str_v(s(0).into_owned()),
        ToNumber => Some(Value::Num(args[0].as_num()?)),
        Substr => {
            // Byte offsets like Go; an end of 0 or past the string means its end.
            let text = s(0);
            let start = args[1].as_num()? as usize;
            let end = match args.get(2) {
                Some(e) => e.as_num()? as usize,
                None => text.len(),
            };
            let end = if end == 0 || end > text.len() { text.len() } else { end };
            str_v(text.get(start..end)?.to_string())
        }
        Md5 => {
            use md5::Digest;
            str_v(hex::encode(md5::Md5::digest(s(0).as_bytes())))
        }
        Sha1 => {
            use sha1::Digest;
            str_v(hex::encode(sha1::Sha1::digest(s(0).as_bytes())))
        }
        Sha256 => {
            use sha2::Digest;
            str_v(hex::encode(sha2::Sha256::digest(s(0).as_bytes())))
        }
        Base64 => str_v(base64::engine::general_purpose::STANDARD.encode(s(0).as_bytes())),
        Base64Py => str_v(base64_py(s(0).as_bytes())),
        Base64Decode => {
            let b = base64::engine::general_purpose::STANDARD.decode(s(0).trim().as_bytes()).ok()?;
            str_v(String::from_utf8_lossy(&b).into_owned())
        }
        HexEncode => str_v(hex::encode(s(0).as_bytes())),
        HexDecode => str_v(String::from_utf8_lossy(&hex::decode(s(0).as_bytes()).ok()?).into_owned()),
        UrlEncode => {
            str_v(percent_encoding::utf8_percent_encode(&s(0), percent_encoding::NON_ALPHANUMERIC).to_string())
        }
        UrlDecode => {
            str_v(percent_encoding::percent_decode_str(&s(0).replace('+', " ")).decode_utf8_lossy().into_owned())
        }
        Mmh3 => str_v((mmh3_32(s(0).as_bytes(), 0) as i32).to_string()),
        Repeat => {
            let n = args[1].as_num()?.max(0.0) as usize;
            (s(0).len().saturating_mul(n) <= MAX_VALUE).then(|| Value::Str(s(0).repeat(n)))
        }
        RandBase | RandTextAlpha | RandTextAlphanumeric | RandTextNumeric => {
            const ALPHA: &str = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
            const DIGITS: &str = "0123456789";
            let n = (args[0].as_num()?.max(0.0) as usize).min(4096);
            let charset: String = match f {
                RandBase => args.get(1).map(|a| a.as_str().into_owned()).unwrap_or_else(|| format!("{ALPHA}{DIGITS}")),
                RandTextAlpha => ALPHA.into(),
                RandTextNumeric => DIGITS.into(),
                _ => format!("{ALPHA}{DIGITS}"),
            };
            // The optional second argument of rand_text_* lists characters to leave out.
            let bad = if f == RandBase {
                String::new()
            } else {
                args.get(1).map(|a| a.as_str().into_owned()).unwrap_or_default()
            };
            let chars: Vec<char> = charset.chars().filter(|c| !bad.contains(*c)).collect();
            if chars.is_empty() {
                return None;
            }
            str_v((0..n).map(|_| chars[(rand_u64() % chars.len() as u64) as usize]).collect())
        }
        RandInt => {
            let min = args.first().map(|a| a.as_num()).unwrap_or(Some(0.0))? as i64;
            let max = args.get(1).map(|a| a.as_num()).unwrap_or(Some(i32::MAX as f64))? as i64;
            if max < min {
                return None;
            }
            Some(Value::Num((min + (rand_u64() % (max - min + 1) as u64) as i64) as f64))
        }
        CompareVersions => {
            let v = version(&s(0))?;
            let mut ok = true;
            for c in rest() {
                for part in c.split(',') {
                    ok &= constraint(&v, part.trim())?;
                }
            }
            Some(Value::Bool(ok))
        }
        UnixTime => {
            let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).ok()?.as_secs() as f64;
            Some(Value::Num(now + args.first().map(|a| a.as_num()).unwrap_or(Some(0.0))?))
        }
    }
}

/// A version like hashicorp/go-version reads it: optional `v`, numeric
/// segments, an optional `-prerelease`, ignored `+metadata`.
#[derive(Debug, PartialEq)]
struct Version {
    segments: Vec<u64>,
    pre: String,
}

fn version(s: &str) -> Option<Version> {
    let s = s.trim().trim_start_matches(['v', 'V']);
    let s = s.split('+').next()?;
    let (nums, pre) = match s.find('-') {
        Some(i) => (&s[..i], &s[i + 1..]),
        None => (s, ""),
    };
    let segments = nums.split('.').map(|x| x.parse().ok()).collect::<Option<Vec<u64>>>()?;
    Some(Version { segments, pre: pre.to_string() })
}

fn cmp_versions(a: &Version, b: &Version) -> std::cmp::Ordering {
    let n = a.segments.len().max(b.segments.len());
    let seg = |v: &Version, i: usize| v.segments.get(i).copied().unwrap_or(0);
    (0..n).map(|i| seg(a, i).cmp(&seg(b, i))).find(|o| o.is_ne()).unwrap_or_else(|| {
        match (a.pre.is_empty(), b.pre.is_empty()) {
            (true, true) => std::cmp::Ordering::Equal,
            (true, false) => std::cmp::Ordering::Greater,
            (false, true) => std::cmp::Ordering::Less,
            (false, false) => a.pre.cmp(&b.pre),
        }
    })
}

/// One go-version constraint (`>= 1.2`, `< 2`, `!= 1.0`, `~> 1.2`, `1.0`).
fn constraint(v: &Version, c: &str) -> Option<bool> {
    let op_len = c.find(|ch: char| ch.is_ascii_alphanumeric()).unwrap_or(c.len());
    let (op, want) = (c[..op_len].trim(), version(&c[op_len..])?);
    let ord = cmp_versions(v, &want);
    Some(match op {
        "" | "=" | "==" => ord.is_eq(),
        "!=" => ord.is_ne(),
        ">" => ord.is_gt(),
        ">=" => ord.is_ge(),
        "<" => ord.is_lt(),
        "<=" => ord.is_le(),
        "~>" => {
            // At least `want`, and the same up to its second-to-last segment.
            let keep = want.segments.len().saturating_sub(1).max(1);
            ord.is_ge() && (0..keep).all(|i| v.segments.get(i).copied().unwrap_or(0) == want.segments[i])
        }
        _ => return None,
    })
}

/// Random bits for the `rand_*` helpers (not for anything secret).
fn rand_u64() -> u64 {
    use std::hash::{BuildHasher, Hasher};
    let mut h = std::collections::hash_map::RandomState::new().build_hasher();
    h.write_u128(std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_nanos());
    h.finish()
}

/// Python's `base64.encodebytes` (lines of 76 characters, each ending in a
/// newline), which Shodan-style favicon hashes are computed over.
fn base64_py(data: &[u8]) -> String {
    let enc = base64::engine::general_purpose::STANDARD.encode(data);
    let mut out = String::with_capacity(enc.len() + enc.len() / 76 + 1);
    for chunk in enc.as_bytes().chunks(76) {
        out.push_str(std::str::from_utf8(chunk).unwrap_or_default());
        out.push('\n');
    }
    out
}

/// MurmurHash3 x86 32-bit.
fn mmh3_32(data: &[u8], seed: u32) -> u32 {
    const C1: u32 = 0xcc9e_2d51;
    const C2: u32 = 0x1b87_3593;
    let mut h = seed;
    let mut chunks = data.chunks_exact(4);
    for c in &mut chunks {
        let mut k = u32::from_le_bytes([c[0], c[1], c[2], c[3]]);
        k = k.wrapping_mul(C1).rotate_left(15).wrapping_mul(C2);
        h ^= k;
        h = h.rotate_left(13).wrapping_mul(5).wrapping_add(0xe654_6b64);
    }
    let tail = chunks.remainder();
    if !tail.is_empty() {
        let mut k = 0u32;
        for (i, b) in tail.iter().enumerate() {
            k |= (*b as u32) << (8 * i);
        }
        h ^= k.wrapping_mul(C1).rotate_left(15).wrapping_mul(C2);
    }
    h ^= data.len() as u32;
    h ^= h >> 16;
    h = h.wrapping_mul(0x85eb_ca6b);
    h ^= h >> 13;
    h = h.wrapping_mul(0xc2b2_ae35);
    h ^ (h >> 16)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ops::Add;

    fn eval(src: &str) -> Option<Value> {
        let env = |name: &str| match name {
            "status_code" => Some(Value::Num(200.0)),
            "body" => Some(Value::Str("<title>Admin Panel</title> version 1.2".into())),
            "content_type" => Some(Value::Str("text/html".into())),
            _ => None,
        };
        parse(src).unwrap().eval(&env)
    }

    fn yes(src: &str) -> bool {
        eval(src) == Some(Value::Bool(true))
    }

    #[test]
    fn operators_and_precedence() {
        assert!(yes("status_code == 200 && contains(body, 'Admin')"));
        assert!(yes("status_code==404 || status_code==200"));
        assert!(yes("!(status_code != 200)"));
        assert!(yes("1 + 2 * 3 == 7"));
        assert!(yes("(1 + 2) * 3 == 9"));
        assert!(yes("len(body) > 10 && len(body) <= 100"));
        assert!(yes("status_code >= 200 && status_code < 300"));
        assert!(yes("\"200\" == status_code"));
        assert!(yes("'a' + \"b\" == 'ab'"));
        assert!(yes("-1 < 0"));
        assert!(yes("true && !false"));
    }

    #[test]
    fn functions() {
        assert!(yes("contains_all(body, 'Admin', 'version')"));
        assert!(!yes("contains_all(body, 'Admin', 'nope')"));
        assert!(yes("contains_any(tolower(body), 'nope', 'admin panel')"));
        assert!(yes("regex('(?i)<title>admin', body)"));
        assert!(yes("regex(\"version\\\\s[0-9.]+\", body)"));
        assert!(yes(r#"regex("version\s[0-9.]+", body)"#));
        assert!(yes("starts_with(content_type, 'text/', 'application/')"));
        assert!(yes("to_upper(substr('abcdef', 1, 3)) == 'BC'"));
        assert!(yes("concat('a', 1, true) == 'a1true'"));
        assert!(yes("replace_regex('v1.2.3', '[0-9]', 'N') == 'vN.N.N'"));
        assert!(yes("trim('xxhixx', 'x') == 'hi' && trim_space('  a ') == 'a'"));
        assert!(yes("md5('abc') == '900150983cd24fb0d6963f7d28e17f72'"));
        assert!(yes("base64_decode(base64('hi')) == 'hi'"));
        assert!(yes("to_number('42') + 1 == 43"));
        assert!(yes(r#"contains("say \"hi\"", '"hi"')"#));
        assert!(yes("repeat('ab', 3) == 'ababab'"));
        assert!(yes("len(rand_base(8)) == 8 && len(rand_text_numeric(5)) == 5"));
        assert!(yes("regex('^[a-z]{6}$', rand_base(6, 'abcdefghijklmnopqrstuvwxyz'))"));
        assert!(yes("!contains(rand_text_alpha(200, 'aeiou'), 'a')"));
        assert!(yes("rand_int(5, 7) >= 5 && rand_int(5, 7) <= 7"));
        assert!(yes("unix_time() > 1700000000"));
        assert!(yes("compare_versions('2.4.4', '<= 2.4.4')"));
        assert!(yes("compare_versions('v3.1', '>= 3.0', '< 4.8')"));
        assert!(yes("compare_versions('8.9.1', '>= 8.0.0, < 8.10.2')"));
        assert!(!yes("compare_versions('8.10.2', '>= 8.0.0', '< 8.10.2')"));
        assert!(yes("compare_versions('1.0.0-beta', '< 1.0.0') && compare_versions('9.0', '9.0.0')"));
        assert!(yes("compare_versions('1.2.7', '~> 1.2.3') && !compare_versions('1.3.0', '~> 1.2.3')"));
        assert_eq!(eval("compare_versions('not a version', '< 1')"), None);
    }

    #[test]
    fn hashes_match_reference_values() {
        // Values from Python's mmh3 and base64 modules.
        assert_eq!(mmh3_32(b"", 0), 0);
        assert_eq!(mmh3_32(b"hello", 0) as i32, 613153351);
        assert_eq!(mmh3_32(b"foo", 0) as i32, -156908512);
        assert_eq!(base64_py(b"hi"), "aGk=\n");
        assert_eq!(base64_py(&[0u8; 60]).lines().next().unwrap().len(), 76);
    }

    #[test]
    fn missing_values_and_type_errors_do_not_match() {
        assert_eq!(eval("contains(server, 'x')"), None);
        assert_eq!(eval("status_code && true"), None);
        assert!(!yes("contains(server, 'x') || false"));
        assert!(!yes("body"));
    }

    #[test]
    fn unsupported_and_invalid() {
        let unsupported = |s: &str| matches!(parse(s), Err(ParseError::Unsupported(_)));
        let invalid = |s: &str| matches!(parse(s), Err(ParseError::Invalid(_)));
        assert!(unsupported("date_time('%Y')"));
        assert!(unsupported("status_code == 200 ? true : false"));
        assert!(unsupported("body =~ 'x'"));
        assert!(unsupported("regex('(?=x)', body)"));
        assert!(invalid("contains(body"));
        assert!(invalid("contains(body, 'x'"));
        assert!(invalid("'abc"));
        assert!(invalid("contains(body)"));
        assert!(invalid("status_code == "));
        assert!(invalid("a $ b"));
        assert!(invalid(&"(".repeat(100)));
        assert!(invalid(&"1 + ".repeat(600).add("1")));
        assert!(yes(&format!("{}true", "true && ".repeat(300))));
        let e = parse("contains(header, x) && status_code == 200").unwrap();
        let mut vars = Vec::new();
        e.vars(&mut vars);
        assert_eq!(vars, ["header", "x", "status_code"]);
    }
}
