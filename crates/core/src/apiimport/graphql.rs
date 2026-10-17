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
}
