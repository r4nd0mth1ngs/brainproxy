//! OpenAPI 3.x and Swagger 2.0 documents to requests.

use percent_encoding::{utf8_percent_encode, AsciiSet, CONTROLS};
use serde_json::{json, Value};

use super::values::{self, example, explicit, resolve, scalar, Part, MULTIPART_BOUNDARY};
use super::{parse_base, rebase, ApiRequest, Built};
use crate::error::{Error, Result};

const METHODS: &[&str] = &["get", "put", "post", "delete", "options", "head", "patch", "trace"];

/// Characters escaped in a path parameter value (RFC 3986 segment, minus sub-delims kept by most servers).
const SEGMENT: &AsciiSet = &CONTROLS
    .add(b' ')
    .add(b'"')
    .add(b'#')
    .add(b'<')
    .add(b'>')
    .add(b'?')
    .add(b'`')
    .add(b'{')
    .add(b'}')
    .add(b'/')
    .add(b'%')
    .add(b'\\')
    .add(b'^')
    .add(b'|');

#[derive(Debug, Default, Clone)]
pub struct Options {
    /// Replaces the server: with a path (other than "/") the whole server URL,
    /// otherwise only its scheme/host/port.
    pub base_url: Option<String>,
    /// Where the document was fetched from; relative server URLs resolve against it.
    pub spec_url: Option<String>,
}

pub fn build(doc: &Value, opts: &Options) -> Result<Built> {
    let v2 = match (doc.get("swagger").and_then(Value::as_str), doc.get("openapi").and_then(Value::as_str)) {
        (Some(s), _) if s.starts_with('2') => true,
        (_, Some(s)) if s.starts_with('3') => false,
        _ => {
            return Err(Error::InvalidInput(
                "not an OpenAPI 3.x or Swagger 2.0 document (no \"openapi\": \"3...\" or \"swagger\": \"2.0\")".into(),
            ))
        }
    };
    let mut out = Built::default();
    let root_base = if v2 { Some(swagger_base(doc, opts)?) } else { None };
    let Some(paths) = doc.get("paths").and_then(Value::as_object) else {
        out.warn("document has no paths".into());
        return Ok(out);
    };
    for (path, item) in paths {
        let item = resolve(doc, item);
        for method in METHODS {
            let Some(op) = item.get(*method) else { continue };
            let base = match &root_base {
                Some(b) => b.clone(),
                None => {
                    // Operation servers override path servers, which override the document's.
                    let server = [op, item, doc].iter().find_map(|v| server_url(v.get("servers")));
                    match server_base(server, opts) {
                        Ok(b) => b,
                        Err(e) => {
                            out.warn(format!("{} {path}: {e}", method.to_uppercase()));
                            continue;
                        }
                    }
                }
            };
            match operation(doc, v2, &base, path, method, item, op) {
                Ok((req, mut warnings)) => {
                    warnings.drain(..).for_each(|w| out.warn(w));
                    out.requests.push(req);
                }
                Err(e) => out.warn(format!("{} {path}: {e}", method.to_uppercase())),
            }
        }
    }
    Ok(out)
}

fn server_url(servers: Option<&Value>) -> Option<String> {
    let s = servers?.as_array()?.first()?;
    let mut url = s.get("url")?.as_str()?.to_string();
    if let Some(vars) = s.get("variables").and_then(Value::as_object) {
        for (k, v) in vars {
            let val = v.get("default").or_else(|| v.get("enum").and_then(|e| e.get(0))).map(scalar).unwrap_or_default();
            url = url.replace(&format!("{{{k}}}"), &val);
        }
    }
    Some(url)
}

fn server_base(server: Option<String>, opts: &Options) -> Result<String> {
    let server = server.unwrap_or_else(|| "/".into());
    let absolute = server.contains("://");
    if let Some(b) = &opts.base_url {
        let bu = parse_base(b)?;
        if !matches!(bu.path(), "" | "/") {
            return Ok(bu.to_string());
        }
        return if absolute { rebase(&server, b) } else { join(bu.as_str(), &server) };
    }
    if absolute {
        return Ok(server);
    }
    match &opts.spec_url {
        Some(s) => join(s, &server),
        None => Err(Error::InvalidInput(format!("server URL {server:?} is relative; pass --base-url"))),
    }
}

fn join(base: &str, rel: &str) -> Result<String> {
    url::Url::parse(base)
        .and_then(|b| b.join(rel))
        .map(|u| u.to_string())
        .map_err(|e| Error::InvalidInput(format!("cannot resolve {rel:?} against {base:?}: {e}")))
}

fn swagger_base(doc: &Value, opts: &Options) -> Result<String> {
    let base_path = doc.get("basePath").and_then(Value::as_str).unwrap_or("/");
    let spec = opts.spec_url.as_deref().and_then(|s| url::Url::parse(s).ok());
    if let Some(b) = &opts.base_url {
        let bu = parse_base(b)?;
        if !matches!(bu.path(), "" | "/") {
            return Ok(bu.to_string());
        }
        return join(bu.as_str(), base_path);
    }
    let schemes: Vec<&str> =
        doc.get("schemes").and_then(Value::as_array).into_iter().flatten().filter_map(Value::as_str).collect();
    let scheme = schemes
        .iter()
        .find(|s| matches!(**s, "https" | "http"))
        .map(|s| s.to_string())
        .or_else(|| spec.as_ref().map(|u| u.scheme().to_string()))
        .unwrap_or_else(|| "https".into());
    let host = match (doc.get("host").and_then(Value::as_str), &spec) {
        (Some(h), _) => h.to_string(),
        (None, Some(u)) => u[url::Position::BeforeHost..url::Position::AfterPort].to_string(),
        (None, None) => return Err(Error::InvalidInput("Swagger document has no host; pass --base-url".into())),
    };
    Ok(format!("{scheme}://{host}{base_path}"))
}

fn operation(
    doc: &Value,
    v2: bool,
    base: &str,
    path: &str,
    method: &str,
    item: &Value,
    op: &Value,
) -> Result<(ApiRequest, Vec<String>)> {
    let mut warnings = Vec::new();
    // Path-level parameters, overridden by operation parameters with the same name + location.
    let mut params: Vec<&Value> = Vec::new();
    for p in [item, op].iter().filter_map(|v| v.get("parameters")).filter_map(Value::as_array).flatten() {
        let p = resolve(doc, p);
        let key = |p: &Value| (p.get("name").cloned(), p.get("in").cloned());
        params.retain(|q| key(q) != key(p));
        params.push(p);
    }
    let mut url_path = path.to_string();
    let mut query: Vec<(String, String)> = Vec::new();
    let mut headers: Vec<(String, String)> = Vec::new();
    let mut cookies: Vec<String> = Vec::new();
    let mut body_param = None;
    let mut form_params: Vec<&Value> = Vec::new();
    for p in &params {
        let name = p.get("name").and_then(Value::as_str).unwrap_or("");
        let loc = p.get("in").and_then(Value::as_str).unwrap_or("");
        if loc == "body" {
            body_param = Some(*p);
            continue;
        }
        if loc == "formData" {
            form_params.push(p);
            continue;
        }
        let value = param_value(doc, v2, p);
        match loc {
            "path" => {
                let enc = utf8_percent_encode(&scalar(&value), SEGMENT).to_string();
                url_path = url_path.replace(&format!("{{{name}}}"), &enc);
            }
            "query" => {
                let explode = if v2 {
                    p.get("collectionFormat").and_then(Value::as_str) == Some("multi")
                } else {
                    p.get("explode").and_then(Value::as_bool).unwrap_or(true)
                };
                match &value {
                    Value::Array(items) if explode => query.extend(items.iter().map(|i| (name.to_string(), scalar(i)))),
                    Value::Object(m) if !v2 && p.get("style").and_then(Value::as_str) == Some("deepObject") => {
                        query.extend(m.iter().map(|(k, v)| (format!("{name}[{k}]"), scalar(v))))
                    }
                    Value::Object(m) if !v2 && explode => query.extend(m.iter().map(|(k, v)| (k.clone(), scalar(v)))),
                    v => query.push((name.to_string(), scalar(v))),
                }
            }
            "header" if !["accept", "content-type", "authorization"].contains(&name.to_ascii_lowercase().as_str()) => {
                headers.push((name.to_string(), scalar(&value)))
            }
            "cookie" => cookies.push(format!("{name}={}", scalar(&value))),
            _ => {}
        }
    }
    // Template variables without a declared parameter.
    while let Some(start) = url_path.find('{') {
        let Some(end) = url_path[start..].find('}') else { break };
        warnings.push(format!(
            "{} {path}: undeclared path parameter {}",
            method.to_uppercase(),
            &url_path[start..=start + end]
        ));
        url_path.replace_range(start..=start + end, "1");
    }
    if !cookies.is_empty() {
        headers.push(("Cookie".into(), cookies.join("; ")));
    }
    let (content_type, body) = if v2 { swagger_body(doc, op, body_param, &form_params) } else { openapi_body(doc, op) };
    if let Some(ct) = content_type {
        headers.push(("Content-Type".into(), ct));
    }
    let mut url = format!("{}{}", base.trim_end_matches('/'), url_path);
    if !query.is_empty() {
        url.push(if url.contains('?') { '&' } else { '?' });
        url.push_str(&String::from_utf8_lossy(&values::form(&query)));
    }
    let name = op
        .get("operationId")
        .and_then(Value::as_str)
        .map(str::to_string)
        .unwrap_or_else(|| format!("{} {path}", method.to_uppercase()));
    Ok((ApiRequest { name, method: method.to_uppercase(), url, headers, body }, warnings))
}

fn param_value(doc: &Value, v2: bool, p: &Value) -> Value {
    if v2 {
        return explicit(p).or_else(|| p.get("x-example").cloned()).unwrap_or_else(|| example(doc, p));
    }
    if let Some(v) = p.get("example") {
        return v.clone();
    }
    if let Some(v) = first_example(doc, p.get("examples")) {
        return v;
    }
    if let Some(schema) = p.get("schema") {
        return example(doc, schema);
    }
    // `content` instead of `schema`: the value is a serialized document.
    if let Some((_, media)) = p.get("content").and_then(Value::as_object).and_then(|c| c.iter().next()) {
        return json!(media_value(doc, media).to_string());
    }
    json!("test")
}

fn first_example(doc: &Value, examples: Option<&Value>) -> Option<Value> {
    let (_, ex) = examples?.as_object()?.iter().next()?;
    resolve(doc, ex).get("value").cloned()
}

fn media_value(doc: &Value, media: &Value) -> Value {
    media
        .get("example")
        .cloned()
        .or_else(|| first_example(doc, media.get("examples")))
        .unwrap_or_else(|| media.get("schema").map(|s| example(doc, s)).unwrap_or(Value::Null))
}

/// Picks the content type to send, preferring JSON, then forms, XML, and text.
fn pick<'a>(types: impl Iterator<Item = &'a str> + Clone) -> Option<&'a str> {
    let rank = |t: &str| {
        let t = t.to_ascii_lowercase();
        if t.contains("json") {
            0
        } else if t.starts_with("application/x-www-form-urlencoded") {
            1
        } else if t.starts_with("multipart/form-data") {
            2
        } else if t.contains("xml") {
            3
        } else if t.starts_with("text/") {
            4
        } else {
            5
        }
    };
    types.min_by_key(|t| rank(t))
}

fn openapi_body(doc: &Value, op: &Value) -> (Option<String>, Vec<u8>) {
    let Some(rb) = op.get("requestBody").map(|b| resolve(doc, b)) else { return (None, Vec::new()) };
    let Some(content) = rb.get("content").and_then(Value::as_object) else { return (None, Vec::new()) };
    let Some(ct) = pick(content.keys().map(String::as_str)) else { return (None, Vec::new()) };
    let media = &content[ct];
    let value = media_value(doc, media);
    let schema = media.get("schema").map(|s| resolve(doc, s)).unwrap_or(&Value::Null);
    let file_field = |name: &str| {
        let prop = schema.get("properties").and_then(|p| p.get(name)).map(|s| resolve(doc, s));
        prop.and_then(|s| s.get("format")).and_then(Value::as_str).is_some_and(|f| f == "binary" || f == "base64")
    };
    encode(ct, value, &xml_name(doc, media.get("schema")), file_field)
}

fn xml_name(doc: &Value, schema: Option<&Value>) -> String {
    let Some(s) = schema else { return "root".into() };
    if let Some(n) = resolve(doc, s).pointer("/xml/name").and_then(Value::as_str) {
        return n.to_string();
    }
    s.get("$ref").and_then(Value::as_str).and_then(|r| r.rsplit('/').next()).unwrap_or("root").to_string()
}

fn encode(ct: &str, value: Value, xml_root: &str, file_field: impl Fn(&str) -> bool) -> (Option<String>, Vec<u8>) {
    let lower = ct.to_ascii_lowercase();
    if lower.contains("json") || lower.contains('*') {
        let ct = if lower.contains('*') { "application/json" } else { ct };
        return (Some(ct.to_string()), serde_json::to_vec(&value).unwrap_or_default());
    }
    if lower.starts_with("application/x-www-form-urlencoded") {
        return (Some(ct.to_string()), values::form(&values::fields(&value)));
    }
    if lower.starts_with("multipart/form-data") {
        let parts: Vec<Part> = values::fields(&value)
            .into_iter()
            .map(|(name, value)| {
                let file = file_field(&name).then(|| "test.txt".to_string());
                Part { name, value, file }
            })
            .collect();
        return (Some(format!("multipart/form-data; boundary={MULTIPART_BOUNDARY}")), values::multipart(&parts));
    }
    if lower.contains("xml") {
        return (Some(ct.to_string()), values::xml(xml_root, &value));
    }
    let body = match value {
        Value::String(s) => s.into_bytes(),
        Value::Null => b"test".to_vec(),
        v => v.to_string().into_bytes(),
    };
    (Some(ct.to_string()), body)
}

fn swagger_body(doc: &Value, op: &Value, body: Option<&Value>, form: &[&Value]) -> (Option<String>, Vec<u8>) {
    let consumes: Vec<&str> = op
        .get("consumes")
        .or_else(|| doc.get("consumes"))
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .collect();
    if let Some(p) = body {
        let schema = p.get("schema").cloned().unwrap_or(Value::Null);
        let value = p.get("x-example").cloned().unwrap_or_else(|| example(doc, &schema));
        let ct = pick(consumes.iter().copied().filter(|c| !c.contains("form"))).unwrap_or("application/json");
        return encode(ct, value, &xml_name(doc, Some(&schema)), |_| false);
    }
    if form.is_empty() {
        return (None, Vec::new());
    }
    let is_file = |p: &Value| p.get("type").and_then(Value::as_str) == Some("file");
    let multipart = form.iter().any(|p| is_file(p)) || consumes.iter().any(|c| c.starts_with("multipart/form-data"));
    let mut obj = serde_json::Map::new();
    for p in form {
        let name = p.get("name").and_then(Value::as_str).unwrap_or("").to_string();
        let v = if is_file(p) { json!("test") } else { param_value(doc, true, p) };
        obj.insert(name, v);
    }
    let files: Vec<String> = form
        .iter()
        .filter(|p| is_file(p))
        .filter_map(|p| p.get("name").and_then(Value::as_str))
        .map(str::to_string)
        .collect();
    let ct = if multipart { "multipart/form-data" } else { "application/x-www-form-urlencoded" };
    encode(ct, Value::Object(obj), "root", |n| files.iter().any(|f| f == n))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn body(r: &ApiRequest) -> String {
        String::from_utf8(r.body.clone()).unwrap()
    }

    fn header<'a>(r: &'a ApiRequest, name: &str) -> Option<&'a str> {
        r.headers.iter().find(|(k, _)| k.eq_ignore_ascii_case(name)).map(|(_, v)| v.as_str())
    }

    #[test]
    fn openapi3_requests() {
        let doc = super::super::parse_document(
            r##"
openapi: 3.0.3
servers:
  - url: "{scheme}://api.example.com/v{ver}"
    variables:
      scheme: {default: https}
      ver: {enum: ["2", "1"], default: "1"}
paths:
  /pets/{petId}:
    parameters:
      - {name: petId, in: path, required: true, schema: {type: integer}}
    get:
      operationId: getPet
      parameters:
        - {name: fields, in: query, schema: {type: array, items: {type: string, enum: [name, tag]}}}
        - {name: X-Trace, in: header, schema: {type: string, format: uuid}}
        - {name: sid, in: cookie, example: abc}
        - {name: filter, in: query, style: deepObject, schema: {type: object, properties: {kind: {type: string}}}}
    delete:
      responses: {}
  /pets:
    post:
      servers: [{url: "http://other.test/"}]
      requestBody:
        $ref: "#/components/requestBodies/Pet"
  /upload:
    post:
      requestBody:
        content:
          multipart/form-data:
            schema:
              properties:
                file: {type: string, format: binary}
                note: {type: string, default: hi}
  /xml:
    put:
      requestBody:
        content:
          application/xml:
            schema: {$ref: "#/components/schemas/Pet"}
components:
  requestBodies:
    Pet:
      content:
        application/x-www-form-urlencoded:
          schema: {$ref: "#/components/schemas/Pet"}
        application/json:
          schema: {$ref: "#/components/schemas/Pet"}
  schemas:
    Pet:
      xml: {name: pet}
      properties:
        name: {type: string, example: "rex"}
        age: {type: integer}
"##,
        )
        .unwrap();
        let b = build(&doc, &Options::default()).unwrap();
        assert!(b.warnings.is_empty(), "{:?}", b.warnings);
        let r = &b.requests;
        assert_eq!(r.len(), 5);
        assert_eq!(r[0].name, "getPet");
        assert_eq!(r[0].url, "https://api.example.com/v1/pets/1?fields=name&filter%5Bkind%5D=test");
        assert_eq!(header(&r[0], "X-Trace"), Some("00000000-0000-4000-8000-000000000000"));
        assert_eq!(header(&r[0], "Cookie"), Some("sid=abc"));
        assert_eq!((r[1].method.as_str(), r[1].name.as_str()), ("DELETE", "DELETE /pets/{petId}"));
        assert_eq!(r[2].url, "http://other.test/pets");
        assert_eq!(header(&r[2], "Content-Type"), Some("application/json"));
        assert_eq!(body(&r[2]), r#"{"name":"rex","age":1}"#);
        assert!(body(&r[3]).contains("name=\"file\"; filename=\"test.txt\""));
        assert!(header(&r[3], "Content-Type").unwrap().starts_with("multipart/form-data; boundary="));
        assert!(body(&r[4]).ends_with("<pet><name>rex</name><age>1</age></pet>"));

        let o = Options { base_url: Some("http://127.0.0.1:9000".into()), ..Default::default() };
        assert_eq!(build(&doc, &o).unwrap().requests[2].url, "http://127.0.0.1:9000/pets");
        let o = Options { base_url: Some("http://127.0.0.1:9000/mock".into()), ..Default::default() };
        assert!(build(&doc, &o).unwrap().requests[0].url.starts_with("http://127.0.0.1:9000/mock/pets/1?"));
    }

    #[test]
    fn relative_servers_need_a_base() {
        let doc = json!({"openapi": "3.1.0", "servers": [{"url": "/api"}], "paths": {"/a": {"get": {}}}});
        let b = build(&doc, &Options::default()).unwrap();
        assert!(b.requests.is_empty() && b.warnings[0].contains("--base-url"));
        let o = Options { spec_url: Some("http://h.test:81/docs/openapi.json".into()), ..Default::default() };
        assert_eq!(build(&doc, &o).unwrap().requests[0].url, "http://h.test:81/api/a");
        let o = Options { base_url: Some("http://x.test".into()), ..Default::default() };
        assert_eq!(build(&doc, &o).unwrap().requests[0].url, "http://x.test/api/a");
    }

    #[test]
    fn swagger2_requests() {
        let doc = json!({
            "swagger": "2.0", "host": "petstore.test:8080", "basePath": "/v2", "schemes": ["http"],
            "consumes": ["application/json"],
            "paths": {
                "/pet/{id}/uploadImage": {"post": {
                    "operationId": "uploadFile", "consumes": ["multipart/form-data"],
                    "parameters": [
                        {"name": "id", "in": "path", "type": "integer", "format": "int64"},
                        {"name": "meta", "in": "formData", "type": "string"},
                        {"name": "file", "in": "formData", "type": "file"}]}},
                "/pet": {"put": {"parameters": [{"in": "body", "name": "body", "schema": {"$ref": "#/definitions/Pet"}}]}},
                "/find": {"get": {"parameters": [
                    {"name": "status", "in": "query", "type": "array", "items": {"type": "string", "enum": ["a", "b"]},
                     "collectionFormat": "multi"},
                    {"name": "tags", "in": "query", "type": "array", "items": {"type": "string"}},
                    {"name": "q", "in": "query", "type": "string", "x-example": "x y"}]}},
                "/login": {"post": {"consumes": ["application/x-www-form-urlencoded"], "parameters": [
                    {"name": "user", "in": "formData", "type": "string", "default": "admin"}]}}
            },
            "definitions": {"Pet": {"properties": {"name": {"type": "string"}}}}
        });
        let b = build(&doc, &Options::default()).unwrap();
        let r = &b.requests;
        assert_eq!(r[0].url, "http://petstore.test:8080/v2/pet/1/uploadImage");
        assert!(body(&r[0]).contains("filename=\"test.txt\"") && body(&r[0]).contains("name=\"meta\""));
        assert_eq!(body(&r[1]), r#"{"name":"test"}"#);
        assert_eq!(r[2].url, "http://petstore.test:8080/v2/find?status=a&tags=test&q=x+y");
        assert_eq!(body(&r[3]), "user=admin");
        assert_eq!(header(&r[3], "Content-Type"), Some("application/x-www-form-urlencoded"));

        let o = Options { base_url: Some("https://127.0.0.1:4443".into()), ..Default::default() };
        assert_eq!(build(&doc, &o).unwrap().requests[1].url, "https://127.0.0.1:4443/v2/pet");
        let nohost = json!({"swagger": "2.0", "paths": {"/a": {"get": {}}}});
        assert!(build(&nohost, &Options::default()).is_err());
        let o = Options { spec_url: Some("http://h.test:81/swagger.json".into()), ..Default::default() };
        assert_eq!(build(&nohost, &o).unwrap().requests[0].url, "http://h.test:81/a");
        assert!(build(&json!({"info": {}}), &Options::default()).is_err());
    }
}
