//! GraphQL introspection results to requests: one operation per query (and,
//! optionally, mutation) field, arguments passed as variables so the active
//! scanner's JSON insertion points reach them.

use std::collections::HashMap;

use serde_json::{json, Map, Value};

use super::{ApiRequest, Built};
use crate::error::{Error, Result};

/// Standard introspection query (types, fields, arguments, input fields, enums).
pub const INTROSPECTION_QUERY: &str = "query IntrospectionQuery { __schema { \
queryType { name } mutationType { name } \
types { kind name \
fields(includeDeprecated: true) { name args { name type { ...TypeRef } } type { ...TypeRef } } \
inputFields { name type { ...TypeRef } } \
enumValues(includeDeprecated: true) { name } } } } \
fragment TypeRef on __Type { kind name ofType { kind name ofType { kind name ofType { kind name ofType { kind name \
ofType { kind name ofType { kind name ofType { kind name } } } } } } } }";

/// Selection depth below the root field.
const MAX_SELECTION_DEPTH: usize = 3;
const MAX_INPUT_DEPTH: usize = 4;

/// Body for the introspection request.
pub fn introspection_body() -> Vec<u8> {
    serde_json::to_vec(&json!({"query": INTROSPECTION_QUERY, "operationName": "IntrospectionQuery"}))
        .unwrap_or_default()
}

struct Schema<'a> {
    types: HashMap<&'a str, &'a Value>,
}

/// Builds a POST per root field from an introspection result (`{data: {__schema}}`
/// or `{__schema}`), sent to `endpoint`.
pub fn build(result: &Value, endpoint: &str, mutations: bool) -> Result<Built> {
    let schema = result.pointer("/data/__schema").or_else(|| result.get("__schema")).ok_or_else(|| {
        let errors = result.get("errors").map(|e| format!(" (server said: {})", truncate(&e.to_string())));
        Error::InvalidInput(format!("no __schema in the introspection result{}", errors.unwrap_or_default()))
    })?;
    let types: HashMap<&str, &Value> = schema
        .get("types")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|t| Some((t.get("name")?.as_str()?, t)))
        .collect();
    let s = Schema { types };
    let mut out = Built::default();
    let mut roots = vec![("query", schema.pointer("/queryType/name"))];
    if mutations {
        roots.push(("mutation", schema.pointer("/mutationType/name")));
    }
    for (kind, name) in roots {
        let Some(name) = name.and_then(Value::as_str) else { continue };
        let Some(root) = s.types.get(name) else {
            out.warn(format!("{kind} type {name} is not in the schema"));
            continue;
        };
        for f in root.get("fields").and_then(Value::as_array).into_iter().flatten() {
            let Some(field) = f.get("name").and_then(Value::as_str) else { continue };
            let mut defs = Vec::new();
            let mut call = Vec::new();
            let mut vars = Map::new();
            for a in f.get("args").and_then(Value::as_array).into_iter().flatten() {
                let Some(an) = a.get("name").and_then(Value::as_str) else { continue };
                let ty = &a["type"];
                defs.push(format!("${an}: {}", type_string(ty)));
                call.push(format!("{an}: ${an}"));
                vars.insert(an.to_string(), s.value(ty, 0));
            }
            let mut q = format!("{kind} {field}");
            if !defs.is_empty() {
                q.push_str(&format!("({})", defs.join(", ")));
            }
            q.push_str(&format!(" {{ {field}"));
            if !call.is_empty() {
                q.push_str(&format!("({})", call.join(", ")));
            }
            q.push_str(&s.selection(&f["type"], 0));
            q.push_str(" }");
            let body = json!({"query": q, "operationName": field, "variables": vars});
            out.requests.push(ApiRequest {
                name: format!("{kind} {field}"),
                method: "POST".into(),
                url: endpoint.to_string(),
                headers: vec![("Content-Type".into(), "application/json".into())],
                body: serde_json::to_vec(&body).unwrap_or_default(),
            });
        }
    }
    if out.requests.is_empty() && out.warnings.is_empty() {
        out.warn("the schema has no query fields".into());
    }
    Ok(out)
}

fn truncate(s: &str) -> String {
    s.chars().take(300).collect()
}

/// Innermost named type of a type reference.
fn named(ty: &Value) -> &Value {
    let mut t = ty;
    for _ in 0..16 {
        match t.get("ofType") {
            Some(inner) if !inner.is_null() => t = inner,
            _ => break,
        }
    }
    t
}

fn type_string(ty: &Value) -> String {
    match ty.get("kind").and_then(Value::as_str) {
        Some("NON_NULL") => format!("{}!", type_string(&ty["ofType"])),
        Some("LIST") => format!("[{}]", type_string(&ty["ofType"])),
        _ => ty.get("name").and_then(Value::as_str).unwrap_or("String").to_string(),
    }
}

impl Schema<'_> {
    /// Example variable value for an input type reference.
    fn value(&self, ty: &Value, depth: usize) -> Value {
        match ty.get("kind").and_then(Value::as_str) {
            Some("NON_NULL") => return self.value(&ty["ofType"], depth),
            Some("LIST") => return json!([self.value(&ty["ofType"], depth)]),
            _ => {}
        }
        let name = ty.get("name").and_then(Value::as_str).unwrap_or("");
        let def = self.types.get(name);
        match ty.get("kind").and_then(Value::as_str) {
            Some("ENUM") => def.and_then(|d| d.pointer("/enumValues/0/name")).cloned().unwrap_or(Value::Null),
            Some("INPUT_OBJECT") => {
                if depth >= MAX_INPUT_DEPTH {
                    return json!({});
                }
                let mut m = Map::new();
                for f in def.and_then(|d| d.get("inputFields")).and_then(Value::as_array).into_iter().flatten() {
                    if let Some(n) = f.get("name").and_then(Value::as_str) {
                        // Optional fields that recurse past the depth limit are left out.
                        let required = f.pointer("/type/kind").and_then(Value::as_str) == Some("NON_NULL");
                        if depth + 1 < MAX_INPUT_DEPTH || required {
                            m.insert(n.to_string(), self.value(&f["type"], depth + 1));
                        }
                    }
                }
                Value::Object(m)
            }
            _ => match name {
                "Int" => json!(1),
                "Float" => json!(1.5),
                "Boolean" => json!(true),
                "ID" => json!("1"),
                _ => json!("test"),
            },
        }
    }

    /// Selection set for an output type: scalar fields, nested objects up to
    /// a depth, `__typename` where nothing else is selectable.
    fn selection(&self, ty: &Value, depth: usize) -> String {
        let n = named(ty);
        let kind = n.get("kind").and_then(Value::as_str).unwrap_or("");
        if !matches!(kind, "OBJECT" | "INTERFACE" | "UNION") {
            return String::new();
        }
        let name = n.get("name").and_then(Value::as_str).unwrap_or("");
        let mut picked = Vec::new();
        if kind != "UNION" {
            for f in self.types.get(name).and_then(|d| d.get("fields")).and_then(Value::as_array).into_iter().flatten()
            {
                let Some(fname) = f.get("name").and_then(Value::as_str) else { continue };
                // Fields with required arguments can't be selected without values.
                let required_args = f.get("args").and_then(Value::as_array).is_some_and(|a| {
                    a.iter().any(|a| a.pointer("/type/kind").and_then(Value::as_str) == Some("NON_NULL"))
                });
                if required_args {
                    continue;
                }
                let inner = named(&f["type"]);
                match inner.get("kind").and_then(Value::as_str) {
                    Some("SCALAR" | "ENUM") => picked.push(fname.to_string()),
                    _ if depth + 1 < MAX_SELECTION_DEPTH => {
                        let sub = self.selection(&f["type"], depth + 1);
                        if !sub.is_empty() {
                            picked.push(format!("{fname}{sub}"));
                        }
                    }
                    _ => {}
                }
            }
        }
        if picked.is_empty() {
            picked.push("__typename".into());
        }
        format!(" {{ {} }}", picked.join(" "))
    }
}

/// Whether `text` reads as GraphQL SDL rather than JSON or YAML.
pub fn looks_like_sdl(text: &str) -> bool {
    let mut t = text.trim_start_matches('\u{feff}').trim_start();
    while let Some(rest) = t.strip_prefix('#') {
        t = rest.split_once('\n').map_or("", |(_, r)| r).trim_start();
    }
    let first = t.split_whitespace().next().unwrap_or_default();
    (t.starts_with("\"\"\"")
        || ["type", "schema", "scalar", "input", "enum", "interface", "union", "directive", "extend"].contains(&first))
        && t.contains('{')
}

#[derive(Debug, Clone, PartialEq)]
enum Tok {
    Name(String),
    Punct(char),
    /// A string or number: only ever a value to step over.
    Value,
}

fn tokens(text: &str) -> Result<Vec<Tok>> {
    let chars: Vec<char> = text.chars().collect();
    let mut out = Vec::new();
    let mut i = 0;
    while i < chars.len() {
        let c = chars[i];
        match c {
            '\u{feff}' | ',' | '.' => i += 1,
            _ if c.is_whitespace() => i += 1,
            '#' => {
                while i < chars.len() && chars[i] != '\n' {
                    i += 1;
                }
            }
            '"' if chars[i..].starts_with(&['"', '"', '"']) => {
                i += 3;
                while i < chars.len() && !chars[i..].starts_with(&['"', '"', '"']) {
                    i += if chars[i] == '\\' { 2 } else { 1 };
                }
                if i >= chars.len() {
                    return Err(Error::InvalidInput("the GraphQL schema has an unclosed description".into()));
                }
                i += 3;
                out.push(Tok::Value);
            }
            '"' => {
                i += 1;
                while i < chars.len() && chars[i] != '"' && chars[i] != '\n' {
                    i += if chars[i] == '\\' { 2 } else { 1 };
                }
                i += 1;
                out.push(Tok::Value);
            }
            _ if c == '_' || c.is_ascii_alphabetic() => {
                let start = i;
                while i < chars.len() && (chars[i] == '_' || chars[i].is_ascii_alphanumeric()) {
                    i += 1;
                }
                out.push(Tok::Name(chars[start..i].iter().collect()));
            }
            _ if c == '-' || c.is_ascii_digit() => {
                i += 1;
                while i < chars.len() && (chars[i].is_ascii_alphanumeric() || matches!(chars[i], '.' | '+' | '-')) {
                    i += 1;
                }
                out.push(Tok::Value);
            }
            '!' | '$' | '(' | ')' | ':' | '=' | '@' | '[' | ']' | '{' | '}' | '|' | '&' => {
                out.push(Tok::Punct(c));
                i += 1;
            }
            _ => return Err(Error::InvalidInput(format!("the GraphQL schema has an unexpected {c:?}"))),
        }
    }
    Ok(out)
}

struct Sdl {
    toks: Vec<Tok>,
    at: usize,
}

impl Sdl {
    fn peek(&self) -> Option<&Tok> {
        self.toks.get(self.at)
    }

    fn eat(&mut self, c: char) -> bool {
        let hit = self.peek() == Some(&Tok::Punct(c));
        self.at += usize::from(hit);
        hit
    }

    fn name(&mut self) -> Result<String> {
        match self.peek() {
            Some(Tok::Name(n)) => {
                let n = n.clone();
                self.at += 1;
                Ok(n)
            }
            _ => Err(Error::InvalidInput("the GraphQL schema has something else where a name belongs".into())),
        }
    }

    fn descriptions(&mut self) {
        while self.peek() == Some(&Tok::Value) {
            self.at += 1;
        }
    }

    /// Steps over a value or a bracketed group of anything.
    fn skip_value(&mut self) {
        let mut depth = 0usize;
        while let Some(t) = self.peek().cloned() {
            self.at += 1;
            match t {
                Tok::Punct('[' | '{' | '(') => depth += 1,
                Tok::Punct(']' | '}' | ')') => depth = depth.saturating_sub(1),
                _ => {}
            }
            if depth == 0 {
                break;
            }
        }
    }

    fn directives(&mut self) {
        while self.eat('@') {
            self.at += 1;
            if self.peek() == Some(&Tok::Punct('(')) {
                self.skip_value();
            }
        }
    }

    /// Steps over `A & B` or `A | B`, stopping at the next definition.
    fn skip_names(&mut self) {
        loop {
            if self.eat('&') || self.eat('|') {
                continue;
            }
            match self.peek() {
                Some(Tok::Name(n)) if !is_definition(n) => self.at += 1,
                _ => break,
            }
        }
    }

    fn type_ref(&mut self) -> Result<Value> {
        let inner = if self.eat('[') {
            let of = self.type_ref()?;
            if !self.eat(']') {
                return Err(Error::InvalidInput("the GraphQL schema has an unclosed list type".into()));
            }
            json!({"kind": "LIST", "name": null, "ofType": of})
        } else {
            json!({"kind": "NAMED", "name": self.name()?, "ofType": null})
        };
        Ok(if self.eat('!') { json!({"kind": "NON_NULL", "name": null, "ofType": inner}) } else { inner })
    }

    /// `name: Type = default @directive`, the shape of arguments and input fields.
    fn input_value(&mut self) -> Result<Value> {
        self.descriptions();
        let name = self.name()?;
        if !self.eat(':') {
            return Err(Error::InvalidInput(format!("the GraphQL schema has no type for {name}")));
        }
        let ty = self.type_ref()?;
        if self.eat('=') {
            self.skip_value();
        }
        self.directives();
        Ok(json!({"name": name, "type": ty}))
    }

    /// The items of a `{ ... }` block, if there is one.
    fn block(&mut self, what: &str, mut item: impl FnMut(&mut Self) -> Result<Value>) -> Result<Vec<Value>> {
        let mut out = Vec::new();
        if !self.eat('{') {
            return Ok(out);
        }
        while !self.eat('}') {
            if self.peek().is_none() {
                return Err(Error::InvalidInput(format!("the GraphQL schema has an unclosed {what}")));
            }
            out.push(item(self)?);
        }
        Ok(out)
    }

    fn field(&mut self) -> Result<Value> {
        self.descriptions();
        let name = self.name()?;
        let mut args = Vec::new();
        if self.eat('(') {
            while !self.eat(')') {
                if self.peek().is_none() {
                    return Err(Error::InvalidInput("the GraphQL schema has unclosed arguments".into()));
                }
                args.push(self.input_value()?);
            }
        }
        if !self.eat(':') {
            return Err(Error::InvalidInput(format!("the GraphQL schema has no type for {name}")));
        }
        let ty = self.type_ref()?;
        self.directives();
        Ok(json!({"name": name, "args": args, "type": ty}))
    }

    fn enum_value(&mut self) -> Result<Value> {
        self.descriptions();
        let name = self.name()?;
        self.directives();
        Ok(json!({"name": name}))
    }
}

/// Gives every named reference in `v` the kind of the type it names.
fn set_kinds(v: &mut Value, kinds: &HashMap<String, &'static str>) {
    match v {
        Value::Object(m) => {
            if m.get("kind").and_then(Value::as_str) == Some("NAMED") {
                let kind = m.get("name").and_then(Value::as_str).and_then(|n| kinds.get(n)).copied();
                m.insert("kind".into(), kind.unwrap_or("SCALAR").into());
            }
            m.values_mut().for_each(|x| set_kinds(x, kinds));
        }
        Value::Array(a) => a.iter_mut().for_each(|x| set_kinds(x, kinds)),
        _ => {}
    }
}

fn is_definition(word: &str) -> bool {
    matches!(word, "type" | "interface" | "input" | "enum" | "union" | "scalar" | "directive" | "schema" | "extend")
}

/// Adds a type, or its members to the type of that name (`extend type`).
fn merge(types: &mut Vec<Value>, new: Value, key: &str) {
    let same = types.iter_mut().find(|t| t["name"] == new["name"]);
    match same.and_then(|t| t.get_mut(key)).and_then(Value::as_array_mut) {
        Some(old) => old.extend(new[key].as_array().cloned().unwrap_or_default()),
        None => types.push(new),
    }
}

/// A schema in GraphQL's schema language, as an introspection result for [`build`].
pub fn parse_sdl(text: &str) -> Result<Value> {
    let mut p = Sdl { toks: tokens(text)?, at: 0 };
    let mut types: Vec<Value> = Vec::new();
    let mut kinds: HashMap<String, &'static str> = HashMap::new();
    let (mut query, mut mutation) = ("Query".to_string(), "Mutation".to_string());
    loop {
        p.descriptions();
        if p.peek().is_none() {
            break;
        }
        let mut word = p.name()?;
        if word == "extend" {
            word = p.name()?;
        }
        match word.as_str() {
            "schema" => {
                p.directives();
                if !p.eat('{') {
                    continue;
                }
                while !p.eat('}') {
                    if p.peek().is_none() {
                        return Err(Error::InvalidInput("the GraphQL schema block is unclosed".into()));
                    }
                    let op = p.name()?;
                    p.eat(':');
                    let ty = p.name()?;
                    match op.as_str() {
                        "query" => query = ty,
                        "mutation" => mutation = ty,
                        _ => {}
                    }
                }
            }
            "type" | "interface" => {
                let name = p.name()?;
                if p.peek() == Some(&Tok::Name("implements".into())) {
                    p.at += 1;
                    p.skip_names();
                }
                p.directives();
                let kind = if word == "type" { "OBJECT" } else { "INTERFACE" };
                kinds.insert(name.clone(), kind);
                let fields = p.block("type", Sdl::field)?;
                merge(&mut types, json!({"kind": kind, "name": name, "fields": fields}), "fields");
            }
            "input" => {
                let name = p.name()?;
                p.directives();
                kinds.insert(name.clone(), "INPUT_OBJECT");
                let fields = p.block("input type", Sdl::input_value)?;
                merge(&mut types, json!({"kind": "INPUT_OBJECT", "name": name, "inputFields": fields}), "inputFields");
            }
            "enum" => {
                let name = p.name()?;
                p.directives();
                kinds.insert(name.clone(), "ENUM");
                let values = p.block("enum", Sdl::enum_value)?;
                merge(&mut types, json!({"kind": "ENUM", "name": name, "enumValues": values}), "enumValues");
            }
            "union" => {
                let name = p.name()?;
                p.directives();
                kinds.insert(name.clone(), "UNION");
                if p.eat('=') {
                    p.skip_names();
                }
                types.push(json!({"kind": "UNION", "name": name}));
            }
            "scalar" => {
                let name = p.name()?;
                p.directives();
                kinds.insert(name.clone(), "SCALAR");
                types.push(json!({"kind": "SCALAR", "name": name}));
            }
            "directive" => {
                // `directive @name(args) on A | B`: nothing a request needs.
                p.eat('@');
                p.at += 1;
                if p.peek() == Some(&Tok::Punct('(')) {
                    p.skip_value();
                }
                p.skip_names();
            }
            other => {
                return Err(Error::InvalidInput(format!("the GraphQL schema has an unknown definition {other:?}")));
            }
        }
    }
    if !kinds.contains_key(&query) {
        return Err(Error::InvalidInput(format!("the GraphQL schema has no {query} type")));
    }
    let mut schema = json!({
        "queryType": {"name": query},
        "mutationType": if kinds.contains_key(&mutation) { json!({"name": mutation}) } else { Value::Null },
        "types": types,
    });
    set_kinds(&mut schema, &kinds);
    Ok(json!({"__schema": schema}))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn t(kind: &str, name: &str) -> Value {
        json!({"kind": kind, "name": name, "ofType": null})
    }
    fn nn(inner: Value) -> Value {
        json!({"kind": "NON_NULL", "name": null, "ofType": inner})
    }
    fn list(inner: Value) -> Value {
        json!({"kind": "LIST", "name": null, "ofType": inner})
    }

    #[test]
    fn builds_operations_from_introspection() {
        let schema = json!({"data": {"__schema": {
        "queryType": {"name": "Query"}, "mutationType": {"name": "Mutation"},
        "types": [
            {"kind": "OBJECT", "name": "Query", "fields": [
                {"name": "user", "args": [{"name": "id", "type": nn(t("SCALAR", "ID"))}], "type": t("OBJECT", "User")},
                {"name": "search", "args": [
                    {"name": "filter", "type": t("INPUT_OBJECT", "Filter")},
                    {"name": "limit", "type": t("SCALAR", "Int")}], "type": list(t("UNION", "Result"))},
                {"name": "version", "args": [], "type": t("SCALAR", "String")},
            ]},
            {"kind": "OBJECT", "name": "Mutation", "fields": [
                {"name": "deleteUser", "args": [{"name": "id", "type": nn(t("SCALAR", "ID"))}], "type": t("SCALAR", "Boolean")}]},
            {"kind": "OBJECT", "name": "User", "fields": [
                {"name": "id", "args": [], "type": nn(t("SCALAR", "ID"))},
                {"name": "role", "args": [], "type": t("ENUM", "Role")},
                {"name": "friends", "args": [], "type": list(t("OBJECT", "User"))},
                {"name": "posts", "args": [{"name": "first", "type": nn(t("SCALAR", "Int"))}], "type": list(t("OBJECT", "Post"))},
            ]},
            {"kind": "INPUT_OBJECT", "name": "Filter", "inputFields": [
                {"name": "q", "type": nn(t("SCALAR", "String"))},
                {"name": "role", "type": t("ENUM", "Role")},
                {"name": "score", "type": t("SCALAR", "Float")}]},
            {"kind": "ENUM", "name": "Role", "enumValues": [{"name": "ADMIN"}, {"name": "USER"}]},
            {"kind": "UNION", "name": "Result"},
        ]}}});
        let b = build(&schema, "http://g.test/graphql", false).unwrap();
        assert_eq!(b.requests.len(), 3);
        let body: Value = serde_json::from_slice(&b.requests[0].body).unwrap();
        assert_eq!(
            body["query"],
            "query user($id: ID!) { user(id: $id) { id role friends { id role friends { id role } } } }"
        );
        assert_eq!(body["variables"], json!({"id": "1"}));
        let body: Value = serde_json::from_slice(&b.requests[1].body).unwrap();
        assert_eq!(
            body["query"],
            "query search($filter: Filter, $limit: Int) { search(filter: $filter, limit: $limit) { __typename } }"
        );
        assert_eq!(body["variables"], json!({"filter": {"q": "test", "role": "ADMIN", "score": 1.5}, "limit": 1}));
        let body: Value = serde_json::from_slice(&b.requests[2].body).unwrap();
        assert_eq!(body["query"], "query version { version }");

        let b = build(&schema, "http://g.test/graphql", true).unwrap();
        assert_eq!(b.requests.len(), 4);
        assert_eq!(b.requests[3].name, "mutation deleteUser");

        let err = build(&json!({"errors": [{"message": "introspection disabled"}]}), "http://g.test/", false);
        assert!(err.unwrap_err().to_string().contains("introspection disabled"));
    }

    #[test]
    fn a_schema_file_builds_the_same_operations() {
        let sdl = r#"
            # A comment
            """A described schema"""
            schema { query: Root mutation: Change }
            directive @auth(role: String = "x") on FIELD_DEFINITION | OBJECT
            scalar Date
            enum Role { "first" ADMIN USER @deprecated(reason: "old") }
            interface Node { id: ID! }
            union Result = User | Post
            input Filter { q: String!, role: Role = ADMIN, tags: [String!] }
            type Post implements Node { id: ID! }
            type User implements Node & Other @auth(role: "a") {
                id: ID!
                role: Role
                posts(first: Int!): [Post]
            }
            type Root {
                "find one"
                user(id: ID!): User
                search(filter: Filter, at: Date): [Result!]!
            }
            extend type Root { version: String }
            type Change { deleteUser(id: ID!): Boolean @auth(role: "root") }
        "#;
        assert!(looks_like_sdl(sdl));
        assert!(!looks_like_sdl("{\"openapi\": \"3.0.0\"}"));
        let b = build(&parse_sdl(sdl).unwrap(), "http://g.test/graphql", true).unwrap();
        let names: Vec<&str> = b.requests.iter().map(|r| r.name.as_str()).collect();
        assert_eq!(names, ["query user", "query search", "query version", "mutation deleteUser"]);
        let body: Value = serde_json::from_slice(&b.requests[0].body).unwrap();
        assert_eq!(body["query"], "query user($id: ID!) { user(id: $id) { id role } }");
        let body: Value = serde_json::from_slice(&b.requests[1].body).unwrap();
        assert_eq!(body["variables"]["filter"], json!({"q": "test", "role": "ADMIN", "tags": ["test"]}));
        assert_eq!(body["variables"]["at"], "test");
        for bad in ["type Query {", "type Other { a: String }", "type Query { a }", "widget Query { a: String }"] {
            assert!(parse_sdl(bad).is_err(), "{bad}");
        }
    }
}
