//! Example values from JSON Schema (OpenAPI/Swagger flavour) and body encoders.

use std::collections::HashSet;

use serde_json::{json, Map, Value};

/// Deepest schema nesting followed; deeper objects become `{}`.
const MAX_DEPTH: usize = 8;

/// Schema nodes followed for one example. Depth alone doesn't stop a few wide schemas
/// that refer to each other from growing to billions of values.
const MAX_NODES: usize = 10_000;

pub const MULTIPART_BOUNDARY: &str = "----brainproxyBoundary7MA4YWxkTrZu0gW";

/// Resolves a local `$ref` ("#/components/schemas/Pet"). Remote refs aren't fetched.
pub fn resolve<'a>(root: &'a Value, v: &'a Value) -> &'a Value {
    let mut cur = v;
    for _ in 0..16 {
        match cur.get("$ref").and_then(Value::as_str) {
            Some(r) if r.starts_with('#') => match root.pointer(&r[1..]) {
                Some(t) => cur = t,
                None => return &Value::Null,
            },
            Some(_) => return &Value::Null,
            None => return cur,
        }
    }
    &Value::Null
}

/// Whether `text` appears in any string, or object key, of `v`.
pub fn mentions(v: &Value, text: &str) -> bool {
    match v {
        Value::String(s) => s.contains(text),
        Value::Array(a) => a.iter().any(|x| mentions(x, text)),
        Value::Object(m) => m.iter().any(|(k, x)| k.contains(text) || mentions(x, text)),
        _ => false,
    }
}

/// The `$ref`s reachable from `v` that [`resolve`] can't follow: external ones
/// and local ones that point nowhere.
pub fn ref_problems(root: &Value, v: &Value) -> Vec<String> {
    // A stack of its own: a chain of refs is as long as the document allows, not as deep as the parser's limit.
    let mut stack = vec![v];
    let mut seen = HashSet::new();
    let mut out = Vec::new();
    while let Some(v) = stack.pop() {
        match v {
            Value::Array(a) => stack.extend(a.iter().rev()),
            Value::Object(m) => {
                stack.extend(m.iter().filter(|(k, _)| *k != "$ref").map(|(_, x)| x));
                let Some(r) = m.get("$ref").and_then(Value::as_str) else { continue };
                // Already reported, or a circular type.
                if !seen.insert(r) {
                    continue;
                }
                match r.strip_prefix('#').map(|p| root.pointer(p)) {
                    Some(Some(target)) => stack.push(target),
                    Some(None) => out.push(format!("broken $ref {r:?}")),
                    None => out.push(format!("external $ref {r:?} is not followed")),
                }
            }
            _ => {}
        }
    }
    out
}

/// An example value for `schema`: its example/default/enum/const if present,
/// otherwise a typed default.
pub fn example(root: &Value, schema: &Value) -> Value {
    gen(root, schema, 0, &mut Walk { refs: Vec::new(), nodes: 0 })
}

/// Where an example's walk has been.
struct Walk {
    refs: Vec<String>,
    nodes: usize,
}

fn gen(root: &Value, schema: &Value, depth: usize, refs: &mut Walk) -> Value {
    refs.nodes += 1;
    if refs.nodes > MAX_NODES {
        return Value::Null;
    }
    if let Some(r) = schema.get("$ref").and_then(Value::as_str) {
        if refs.refs.iter().any(|x| x == r) || depth > MAX_DEPTH {
            return Value::Null; // recursive type: stop here
        }
        refs.refs.push(r.to_string());
        let v = gen(root, resolve(root, schema), depth + 1, refs);
        refs.refs.pop();
        return v;
    }
    if let Some(v) = explicit(schema) {
        return v;
    }
    if depth > MAX_DEPTH {
        return Value::Null;
    }
    if let Some(all) = schema.get("allOf").and_then(Value::as_array) {
        let mut out = Map::new();
        let mut other = None;
        for s in all {
            match gen(root, s, depth + 1, refs) {
                Value::Object(m) => out.extend(m),
                v => other = Some(v),
            }
        }
        if let Some(Value::Object(m)) = object(root, schema, depth, refs) {
            out.extend(m);
        }
        return if out.is_empty() { other.unwrap_or(Value::Object(out)) } else { Value::Object(out) };
    }
    for key in ["oneOf", "anyOf"] {
        if let Some(first) = schema.get(key).and_then(Value::as_array).and_then(|a| a.first()) {
            return gen(root, first, depth + 1, refs);
        }
    }
    let ty = match schema.get("type") {
        Some(Value::String(t)) => t.as_str(),
        // OpenAPI 3.1: type: [string, "null"]
        Some(Value::Array(ts)) => ts.iter().filter_map(Value::as_str).find(|t| *t != "null").unwrap_or("null"),
        _ if schema.get("properties").is_some() => "object",
        _ if schema.get("items").is_some() => "array",
        _ => "string",
    };
    match ty {
        "object" => object(root, schema, depth, refs).unwrap_or_else(|| json!({})),
        "array" => match schema.get("items") {
            Some(items) => match gen(root, items, depth + 1, refs) {
                Value::Null => json!([]),
                v => json!([v]),
            },
            None => json!(["test"]),
        },
        "integer" => json!(schema.get("minimum").and_then(Value::as_i64).filter(|m| *m > 1).unwrap_or(1)),
        "number" => {
            schema.get("minimum").cloned().filter(|m| m.as_f64().is_some_and(|m| m > 1.5)).unwrap_or(json!(1.5))
        }
        "boolean" => json!(true),
        "null" => Value::Null,
        // "file" (Swagger 2 formData) is handled by the multipart encoder.
        _ => json!(string_for(schema.get("format").and_then(Value::as_str).unwrap_or(""))),
    }
}

fn object(root: &Value, schema: &Value, depth: usize, refs: &mut Walk) -> Option<Value> {
    let props = schema.get("properties")?.as_object()?;
    let mut out = Map::new();
    for (k, s) in props {
        if refs.nodes > MAX_NODES {
            break;
        }
        if resolve(root, s).get("readOnly").and_then(Value::as_bool) == Some(true) {
            continue;
        }
        out.insert(k.clone(), gen(root, s, depth + 1, refs));
    }
    Some(Value::Object(out))
}

/// An example given in the schema itself.
pub fn explicit(schema: &Value) -> Option<Value> {
    if let Some(v) = schema.get("example") {
        return Some(v.clone());
    }
    if let Some(v) = schema.get("examples").and_then(Value::as_array).and_then(|a| a.first()) {
        return Some(v.clone());
    }
    if let Some(v) = schema.get("default").or(schema.get("const")) {
        return Some(v.clone());
    }
    schema.get("enum").and_then(Value::as_array).and_then(|a| a.first()).cloned()
}

fn string_for(format: &str) -> &'static str {
    match format {
        "date" => "2024-01-01",
        "date-time" => "2024-01-01T00:00:00Z",
        "time" => "00:00:00",
        "email" => "user@example.com",
        "uuid" => "00000000-0000-4000-8000-000000000000",
        "uri" | "url" => "https://example.com/",
        "hostname" => "example.com",
        "ipv4" => "127.0.0.1",
        "ipv6" => "::1",
        "byte" => "dGVzdA==",
        "binary" => "test",
        "password" => "Passw0rd!",
        _ => "test",
    }
}

/// A value as it appears in a path, query, header, or form field.
pub fn scalar(v: &Value) -> String {
    match v {
        Value::String(s) => s.clone(),
        Value::Null => String::new(),
        Value::Array(a) => a.iter().map(scalar).collect::<Vec<_>>().join(","),
        other => other.to_string(),
    }
}

/// application/x-www-form-urlencoded body from an object.
pub fn form(fields: &[(String, String)]) -> Vec<u8> {
    let mut s = url::form_urlencoded::Serializer::new(String::new());
    for (k, v) in fields {
        s.append_pair(k, v);
    }
    s.finish().into_bytes()
}

/// Object fields as form fields; arrays repeat the key.
pub fn fields(v: &Value) -> Vec<(String, String)> {
    let mut out = Vec::new();
    if let Value::Object(m) = v {
        for (k, v) in m {
            match v {
                Value::Array(items) => out.extend(items.iter().map(|i| (k.clone(), scalar(i)))),
                Value::Object(_) => out.push((k.clone(), v.to_string())),
                _ => out.push((k.clone(), scalar(v))),
            }
        }
    }
    out
}

/// One multipart/form-data part.
pub struct Part {
    pub name: String,
    pub value: String,
    /// Some(filename) for file parts.
    pub file: Option<String>,
}

pub fn multipart(parts: &[Part]) -> Vec<u8> {
    let mut out = String::new();
    for p in parts {
        out.push_str(&format!("--{MULTIPART_BOUNDARY}\r\nContent-Disposition: form-data; name=\"{}\"", quote(&p.name)));
        match &p.file {
            Some(f) => {
                out.push_str(&format!("; filename=\"{}\"\r\nContent-Type: application/octet-stream\r\n\r\n", quote(f)))
            }
            None => out.push_str("\r\n\r\n"),
        }
        out.push_str(&p.value);
        out.push_str("\r\n");
    }
    out.push_str(&format!("--{MULTIPART_BOUNDARY}--\r\n"));
    out.into_bytes()
}

fn quote(s: &str) -> String {
    s.replace(['"', '\r', '\n'], "_")
}

/// Minimal XML for an example value: objects become elements, arrays repeat.
pub fn xml(root_name: &str, v: &Value) -> Vec<u8> {
    // An example given as a whole document.
    if let Some(text) = v.as_str().filter(|t| t.trim_start().starts_with('<')) {
        return text.as_bytes().to_vec();
    }
    fn el(name: &str, v: &Value, out: &mut String) {
        match v {
            Value::Array(items) => items.iter().for_each(|i| el(name, i, out)),
            Value::Object(m) => {
                out.push_str(&format!("<{name}>"));
                for (k, v) in m {
                    el(k, v, out);
                }
                out.push_str(&format!("</{name}>"));
            }
            other => {
                let text = scalar(other).replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;");
                out.push_str(&format!("<{name}>{text}</{name}>"));
            }
        }
    }
    let mut out = String::from("<?xml version=\"1.0\" encoding=\"UTF-8\"?>");
    el(root_name, v, &mut out);
    out.into_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn examples_refs_and_types() {
        let root = json!({"components": {"schemas": {
            "Pet": {"type": "object", "required": ["name"], "properties": {
                "id": {"type": "integer", "readOnly": true},
                "name": {"type": "string", "example": "doggie"},
                "status": {"type": "string", "enum": ["available", "sold"]},
                "born": {"type": "string", "format": "date"},
                "tags": {"type": "array", "items": {"$ref": "#/components/schemas/Tag"}},
                "parent": {"$ref": "#/components/schemas/Pet"},
            }},
            "Tag": {"properties": {"id": {"type": "integer", "minimum": 5}, "w": {"type": ["number", "null"]}}},
        }}});
        let v = example(&root, &json!({"$ref": "#/components/schemas/Pet"}));
        assert_eq!(
            v,
            json!({"name": "doggie", "status": "available", "born": "2024-01-01",
                   "tags": [{"id": 5, "w": 1.5}], "parent": null})
        );
        let all = json!({"allOf": [{"$ref": "#/components/schemas/Tag"}, {"properties": {"x": {"type": "boolean"}}}]});
        assert_eq!(example(&root, &all), json!({"id": 5, "w": 1.5, "x": true}));
        assert_eq!(example(&root, &json!({"oneOf": [{"type": "integer"}, {"type": "string"}]})), json!(1));
    }

    #[test]
    fn encoders() {
        let f = fields(&json!({"a": "x y", "b": [1, 2], "c": {"d": 1}}));
        assert_eq!(String::from_utf8(form(&f)).unwrap(), "a=x+y&b=1&b=2&c=%7B%22d%22%3A1%7D");
        let m = String::from_utf8(multipart(&[
            Part { name: "n".into(), value: "v".into(), file: None },
            Part { name: "f".into(), value: "test".into(), file: Some("a.txt".into()) },
        ]))
        .unwrap();
        assert!(m.contains("name=\"f\"; filename=\"a.txt\"") && m.ends_with(&format!("--{MULTIPART_BOUNDARY}--\r\n")));
        let x = String::from_utf8(xml("Pet", &json!({"name": "<a>", "tags": ["t1", "t2"]}))).unwrap();
        assert!(x.ends_with("<Pet><name>&lt;a&gt;</name><tags>t1</tags><tags>t2</tags></Pet>"), "{x}");
    }
}
