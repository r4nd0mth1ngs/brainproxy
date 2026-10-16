//! Helpers shared by the parameter rules.
//!
//! - [`Dom`]: a lenient element tree standing in for the Jericho HTML parser ZAP uses
//!   (`Source.fullSequentialParse`, `getEnclosingElement`, `getParentElement`,
//!   `getChildElements`). Jericho is not available here, so its behaviour is
//!   reconstructed: element names are lower-cased, an element spans from its start tag
//!   to the end of its end tag, void elements are just their start tag, elements whose
//!   end tag is optional in HTML end where they are implicitly closed, and elements
//!   with a required end tag that is missing span only their start tag (their would-be
//!   children belong to the parent). Tags inside `<script>`/`<style>` are not parsed.
//! - [`HtmlContextAnalyser`] / [`HtmlContext`]: ported from ZAP's
//!   `httputils.HtmlContextAnalyser` and `HtmlContext` (ascanrules, Apache License 2.0).
//! - [`ComparableResponse`]: ported from commonlib's `http.ComparableResponse`
//!   (Apache License 2.0), used by the SSTI rule at LOW strength.

use std::collections::HashMap;
use std::sync::Arc;

use crate::http::RawRequest;
use crate::scan::active::points;
use crate::scan::active::{Cx, Response};
use crate::scan::passive::util::decode_entities;

/// ZAP `Constant.getEyeCatcher()`.
pub const EYE_CATCHER: &str = "0W45pz4p";
/// ascanrules `Constants.NULL_BYTE_CHARACTER`.
pub const NULL_BYTE: &str = "\0";

// ---------------------------------------------------------------------------
// Requests

/// `setParameter` + `sendAndReceive(msg)`: the payload escaped for its context,
/// following redirects like ZAP's default.
pub async fn send_following(cx: &Cx, value: &str) -> crate::error::Result<Response> {
    cx.send_following(points::inject(cx.base_request(), cx.point(), value, true)).await
}

/// `setParameter` + `sendAndReceive(msg, false)`: no redirect following.
pub async fn send_no_follow(cx: &Cx, value: &str) -> crate::error::Result<Response> {
    cx.send_payload(value).await
}

/// The URL of the request behind `resp` (ZAP `getRequestHeader().getURI().toString()`).
pub fn request_url(cx: &Cx, resp: &Response) -> String {
    let target = RawRequest::from_bytes(resp.request.clone()).head().map(|h| h.target).unwrap_or_default();
    if target.contains("://") {
        target
    } else {
        format!("{}{}", cx.target().origin(), target)
    }
}

/// ZAP `HttpResponseHeader.isHtml()`.
pub fn is_html(resp: &Response) -> bool {
    resp.content_type().contains("html")
}

/// ZAP `HttpHeader.getHeadersAsString()`: every header line without the status line.
pub fn headers_as_string(resp: &Response) -> String {
    resp.headers.iter().map(|(k, v)| format!("{k}: {v}\r\n")).collect()
}

/// `URLDecoder.decode(s, UTF-8)`.
pub fn url_decode(s: &str) -> String {
    crate::scan::message::url_decode(s)
}

/// `URLEncoder.encode(s, UTF-8)`.
pub fn url_encode(s: &str) -> String {
    points::form_encode(s)
}

/// Java `String.indexOf(needle, from)` on byte offsets; `None` for -1.
pub fn index_of(hay: &str, needle: &str, from: usize) -> Option<usize> {
    hay.get(from..).and_then(|h| h.find(needle)).map(|i| from + i)
}

// ---------------------------------------------------------------------------
// Jericho-like element tree

#[derive(Debug, Clone)]
pub struct Attr {
    /// Name as written in the source.
    pub name: String,
    /// Entity-decoded value; `None` for a bare attribute.
    pub value: Option<String>,
    /// Byte range of the value inside the document (without quotes).
    pub value_start: usize,
    pub value_end: usize,
    /// `"`, `'`, or ' ' when unquoted (Jericho `getQuoteChar`).
    pub quote: char,
}

#[derive(Debug, Clone)]
pub struct Element {
    /// Lower-case name.
    pub name: String,
    pub begin: usize,
    pub end: usize,
    pub start_tag_end: usize,
    /// Byte range of the content (between start and end tags).
    pub content: (usize, usize),
    pub attrs: Vec<Attr>,
    pub parent: Option<usize>,
}

impl Element {
    #[cfg(test)]
    pub fn attr(&self, name: &str) -> Option<&str> {
        self.attrs.iter().find(|a| a.name.eq_ignore_ascii_case(name)).and_then(|a| a.value.as_deref())
    }
}

#[derive(Debug, Default)]
pub struct Dom {
    /// Elements in document order (by start position).
    pub elements: Vec<Element>,
}

const VOID: &[&str] = &[
    "area", "base", "basefont", "br", "col", "command", "embed", "frame", "hr", "img", "input", "isindex", "keygen",
    "link", "meta", "param", "source", "track", "wbr",
];
const OPTIONAL_END: &[&str] = &[
    "html", "head", "body", "p", "li", "dt", "dd", "option", "optgroup", "tr", "td", "th", "thead", "tbody", "tfoot",
    "colgroup", "rt", "rp",
];
const P_CLOSERS: &[&str] = &[
    "address",
    "article",
    "aside",
    "blockquote",
    "dir",
    "div",
    "dl",
    "fieldset",
    "footer",
    "form",
    "h1",
    "h2",
    "h3",
    "h4",
    "h5",
    "h6",
    "header",
    "hr",
    "menu",
    "nav",
    "ol",
    "p",
    "pre",
    "section",
    "table",
    "ul",
];

/// Whether a start tag `new` implicitly ends the open optional-end element `open`.
fn implicitly_closes(open: &str, new: &str) -> bool {
    let sections = ["thead", "tbody", "tfoot"];
    match open {
        "p" => P_CLOSERS.contains(&new),
        "li" => new == "li",
        "dt" | "dd" => new == "dt" || new == "dd",
        "option" => new == "option" || new == "optgroup",
        "optgroup" => new == "optgroup",
        "tr" => new == "tr" || sections.contains(&new),
        "td" | "th" => new == "td" || new == "th" || new == "tr" || sections.contains(&new),
        "thead" | "tbody" | "tfoot" => sections.contains(&new),
        "colgroup" => new != "col",
        "head" => new == "body",
        "rt" | "rp" => new == "rt" || new == "rp",
        _ => false,
    }
}

fn is_name_start(c: u8) -> bool {
    c.is_ascii_alphabetic() || c == b'_' || c == b':'
}

fn is_name_char(c: u8) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, b'-' | b':' | b'_' | b'.')
}

impl Dom {
    pub fn parse(html: &str) -> Self {
        let b = html.as_bytes();
        let mut elements: Vec<Element> = Vec::new();
        let mut stack: Vec<usize> = Vec::new();
        // Closes an open element: optional-end elements end at `at`, others (end tag
        // missing) shrink to their start tag.
        let close_implicit = |el: &mut Element, at: usize| {
            if OPTIONAL_END.contains(&el.name.as_str()) {
                el.end = at;
                el.content = (el.start_tag_end, at.max(el.start_tag_end));
            } else {
                el.end = el.start_tag_end;
                el.content = (el.start_tag_end, el.start_tag_end);
            }
        };
        let mut i = 0;
        while let Some(off) = html[i..].find('<') {
            let start = i + off;
            let rest = &html[start..];
            if rest.starts_with("<!--") {
                i = rest.find("-->").map(|e| start + e + 3).unwrap_or(b.len());
                continue;
            }
            if rest.starts_with("<!") || rest.starts_with("<?") {
                i = rest.find('>').map(|e| start + e + 1).unwrap_or(b.len());
                continue;
            }
            if let Some(r) = rest.strip_prefix("</") {
                let n = r.bytes().take_while(|c| is_name_char(*c)).count();
                if n == 0 || !is_name_start(r.as_bytes()[0]) {
                    i = start + 1;
                    continue;
                }
                let name = r[..n].to_ascii_lowercase();
                let Some(gt) = rest.find('>') else {
                    i = start + 1;
                    continue;
                };
                let tag_end = start + gt + 1;
                if let Some(pos) = stack.iter().rposition(|&e| elements[e].name == name) {
                    for &open in &stack[pos + 1..] {
                        close_implicit(&mut elements[open], start);
                    }
                    let el = &mut elements[stack[pos]];
                    el.end = tag_end;
                    el.content = (el.start_tag_end, start);
                    stack.truncate(pos);
                }
                i = tag_end;
                continue;
            }
            let r = &rest[1..];
            if r.is_empty() || !is_name_start(r.as_bytes()[0]) {
                i = start + 1;
                continue;
            }
            let n = r.bytes().take_while(|c| is_name_char(*c)).count();
            let name = r[..n].to_ascii_lowercase();
            let Some((attrs, tag_end, self_closing)) = parse_attrs(html, start + 1 + n) else {
                i = start + 1;
                continue;
            };
            while let Some(&top) = stack.last() {
                if OPTIONAL_END.contains(&elements[top].name.as_str()) && implicitly_closes(&elements[top].name, &name)
                {
                    close_implicit(&mut elements[top], start);
                    stack.pop();
                } else {
                    break;
                }
            }
            let idx = elements.len();
            let known = VOID.contains(&name.as_str()) || OPTIONAL_END.contains(&name.as_str()) || is_known(&name);
            let empty = VOID.contains(&name.as_str()) || (self_closing && !known);
            elements.push(Element {
                name: name.clone(),
                begin: start,
                end: tag_end,
                start_tag_end: tag_end,
                content: (tag_end, tag_end),
                attrs,
                parent: None,
            });
            i = tag_end;
            if empty {
                continue;
            }
            if name == "script" || name == "style" {
                match crate::scan::passive::util::find_ci(html, &format!("</{name}"), tag_end) {
                    Some(close) => {
                        let gt = html[close..].find('>').map(|g| close + g + 1).unwrap_or(b.len());
                        let el = &mut elements[idx];
                        el.end = gt;
                        el.content = (tag_end, close);
                        i = gt;
                    }
                    None => i = b.len(),
                }
                continue;
            }
            stack.push(idx);
        }
        for &open in &stack {
            close_implicit(&mut elements[open], b.len());
        }
        // Parents by span containment (Jericho builds the hierarchy from spans).
        let mut open: Vec<usize> = Vec::new();
        for idx in 0..elements.len() {
            while let Some(&top) = open.last() {
                if elements[top].end <= elements[idx].begin {
                    open.pop();
                } else {
                    break;
                }
            }
            elements[idx].parent = open.last().copied();
            open.push(idx);
        }
        Dom { elements }
    }

    /// Jericho `Source.getEnclosingElement(pos)`: the innermost element whose span
    /// contains `pos`.
    pub fn enclosing(&self, pos: usize) -> Option<usize> {
        self.elements.iter().rposition(|e| e.begin <= pos && pos < e.end)
    }

    pub fn children(&self, parent: Option<usize>) -> impl Iterator<Item = usize> + '_ {
        self.elements.iter().enumerate().filter(move |(_, e)| e.parent == parent).map(|(i, _)| i)
    }

    #[cfg(test)]
    pub fn named<'a>(&'a self, name: &'a str) -> impl Iterator<Item = &'a Element> + 'a {
        self.elements.iter().filter(move |e| e.name == name)
    }
}

/// HTML elements with a required end tag (others, e.g. custom tags, are treated alike).
fn is_known(name: &str) -> bool {
    matches!(
        name,
        "a" | "abbr"
            | "address"
            | "b"
            | "blockquote"
            | "button"
            | "div"
            | "form"
            | "h1"
            | "h2"
            | "h3"
            | "h4"
            | "h5"
            | "h6"
            | "i"
            | "iframe"
            | "label"
            | "ol"
            | "pre"
            | "script"
            | "select"
            | "span"
            | "style"
            | "table"
            | "textarea"
            | "title"
            | "ul"
    )
}

/// Attributes of a start tag from `i` (just past the name) to `>`. Returns `None`
/// when the tag is not terminated.
fn parse_attrs(html: &str, mut i: usize) -> Option<(Vec<Attr>, usize, bool)> {
    let b = html.as_bytes();
    let mut attrs = Vec::new();
    let mut self_closing = false;
    loop {
        while i < b.len() && (b[i].is_ascii_whitespace() || b[i] == b'/') {
            self_closing = b[i] == b'/';
            i += 1;
        }
        if i >= b.len() {
            return None;
        }
        if b[i] == b'>' {
            return Some((attrs, i + 1, self_closing));
        }
        self_closing = false;
        let ns = i;
        while i < b.len()
            && !b[i].is_ascii_whitespace()
            && b[i] != b'='
            && b[i] != b'>'
            && !(b[i] == b'/' && b.get(i + 1) == Some(&b'>'))
        {
            i += 1;
        }
        let name = html[ns..i].to_string();
        let mut j = i;
        while j < b.len() && b[j].is_ascii_whitespace() {
            j += 1;
        }
        let mut attr = Attr { name, value: None, value_start: i, value_end: i, quote: ' ' };
        if j < b.len() && b[j] == b'=' {
            i = j + 1;
            while i < b.len() && b[i].is_ascii_whitespace() {
                i += 1;
            }
            if i < b.len() && (b[i] == b'"' || b[i] == b'\'') {
                let q = b[i];
                let vs = i + 1;
                let ve = b[vs..].iter().position(|&c| c == q).map(|o| vs + o)?;
                attr.value = Some(decode_entities(&html[vs..ve]));
                attr.value_start = vs;
                attr.value_end = ve;
                attr.quote = q as char;
                i = ve + 1;
            } else {
                let vs = i;
                while i < b.len() && !b[i].is_ascii_whitespace() && b[i] != b'>' {
                    i += 1;
                }
                attr.value = Some(decode_entities(&html[vs..i]));
                attr.value_start = vs;
                attr.value_end = i;
            }
        }
        if !attr.name.is_empty() {
            attrs.push(attr);
        }
    }
}

// ---------------------------------------------------------------------------
// HtmlContext / HtmlContextAnalyser

pub const IGNORE_PARENT: u32 = 0x0001;
pub const IGNORE_TAG: u32 = 0x0002;
pub const IGNORE_QUOTES: u32 = 0x0004;
pub const IGNORE_IN_SCRIPT: u32 = 0x0008;
pub const IGNORE_IN_URL: u32 = 0x0010;
pub const IGNORE_WITH_SRC: u32 = 0x0020;
pub const IGNORE_HTML_COMMENT: u32 = 0x0040;
pub const IGNORE_IN_SAFE: u32 = 0x0080;

/// Where a reflected string sits in an HTML page.
#[derive(Debug, Clone)]
pub struct HtmlContext {
    pub resp: Arc<Response>,
    pub target: String,
    pub start: usize,
    pub end: usize,
    /// Outermost first; the last is the enclosing element.
    pub parent_tags: Vec<String>,
    pub tag_attribute: Option<String>,
    pub tag_attribute_value: Option<String>,
    /// Insertion-ordered map (ZAP uses a HashMap).
    pub tag_attributes: Vec<(String, Option<String>)>,
    pub in_script_attribute: bool,
    pub in_url_attribute: bool,
    pub in_tag_with_src: bool,
    pub in_attribute_name: bool,
    pub surrounding_quote: String,
    pub element_name: Option<String>,
    pub in_element_name: bool,
    pub html_comment: bool,
}

impl HtmlContext {
    fn new(resp: Arc<Response>, target: &str, start: usize, end: usize) -> Self {
        Self {
            resp,
            target: target.to_string(),
            start,
            end,
            parent_tags: Vec::new(),
            tag_attribute: None,
            tag_attribute_value: None,
            tag_attributes: Vec::new(),
            in_script_attribute: false,
            in_url_attribute: false,
            in_tag_with_src: false,
            in_attribute_name: false,
            surrounding_quote: String::new(),
            element_name: None,
            in_element_name: false,
            html_comment: false,
        }
    }

    pub fn parent_tag(&self) -> Option<&str> {
        self.parent_tags.last().map(String::as_str)
    }

    /// 'Safe' parents are ones in which script is not executed (only textarea).
    pub fn in_safe_parent_tag(&self) -> bool {
        self.parent_tags.iter().any(|t| t.eq_ignore_ascii_case("textarea"))
    }

    fn set_tag_attributes(&mut self, name: &str, value: Option<String>) {
        match self.tag_attributes.iter_mut().find(|(k, _)| k == name) {
            Some(slot) => slot.1 = value,
            None => self.tag_attributes.push((name.to_string(), value)),
        }
    }

    pub fn has_attribute(&self, name: &str, value: &str) -> bool {
        self.tag_attributes.iter().any(|(k, v)| k == name && v.as_deref() == Some(value))
    }

    /// HtmlContext.matches: whether `other` is in the same context as `self`.
    pub fn matches(&self, other: &HtmlContext, ignore: u32) -> bool {
        if ignore & IGNORE_TAG == 0 && self.tag_attribute != other.tag_attribute {
            return false;
        }
        if ignore & IGNORE_QUOTES == 0 && self.surrounding_quote != other.surrounding_quote {
            return false;
        }
        if ignore & IGNORE_PARENT == 0 && self.parent_tag() != other.parent_tag() {
            return false;
        }
        if ignore & IGNORE_IN_SCRIPT == 0 && self.in_script_attribute != other.in_script_attribute {
            return false;
        }
        if ignore & IGNORE_IN_SAFE == 0 && self.in_safe_parent_tag() != other.in_safe_parent_tag() {
            return false;
        }
        if ignore & IGNORE_WITH_SRC == 0 && self.in_tag_with_src != other.in_tag_with_src {
            return false;
        }
        if ignore & IGNORE_IN_URL == 0 && self.in_url_attribute != other.in_url_attribute {
            return false;
        }
        if ignore & IGNORE_HTML_COMMENT == 0 && self.html_comment != other.html_comment {
            return false;
        }
        true
    }
}

const SCRIPT_ATTRIBUTES: &[&str] = &[
    "onBlur",
    "onChange",
    "onClick",
    "onDblClick",
    "onFocus",
    "onKeydown",
    "onKeyup",
    "onKeypress",
    "onLoad",
    "onMousedown",
    "onMouseup",
    "onMouseover",
    "onMousemove",
    "onMouseout",
    "onReset",
    "onSelect",
    "onSubmit",
    "onUnload",
];
const URL_ATTRIBUTES: &[&str] = &[
    "action",
    "background",
    "cite",
    "classid",
    "codebase",
    "data",
    "data-src",
    "formaction",
    "href",
    "icon",
    "longdesc",
    "manifest",
    "poster",
    "profile",
    "src",
    "usemap",
];
const TAGS_WITH_SRC: &[&str] = &["frame", "iframe", "img", "input", "script", "src"];

fn eq_any(list: &[&str], s: &str) -> bool {
    list.iter().any(|x| x.eq_ignore_ascii_case(s))
}

pub struct HtmlContextAnalyser {
    resp: Arc<Response>,
    dom: Dom,
}

impl HtmlContextAnalyser {
    pub fn new(resp: Arc<Response>) -> Self {
        let dom = Dom::parse(resp.body_str());
        Self { resp, dom }
    }

    /// getHtmlContexts(target, targetContext, ignoreFlags, ignoreSafeParents).
    pub fn contexts(
        &self,
        target: &str,
        target_ctx: Option<&HtmlContext>,
        ignore: u32,
        ignore_safe_parents: bool,
    ) -> Vec<HtmlContext> {
        let page = self.resp.body_str();
        let b = page.as_bytes();
        let mut out = Vec::new();
        if target.is_empty() {
            return out;
        }
        let mut offset = 0;
        while let Some(start) = index_of(page, target, offset) {
            let end = start + target.len();
            offset = end;
            let mut ctx = HtmlContext::new(self.resp.clone(), target, start, end);

            // Is it in quotes? (ZAP scans back to index 1, not 0.)
            let mut left_quote = 0u8;
            let mut i = start;
            while i > 1 {
                i -= 1;
                let c = b[i];
                if c == b'\'' || c == b'"' {
                    left_quote = c;
                    break;
                } else if c == b'>' {
                    break;
                }
            }
            if left_quote != 0 {
                for &c in &b[end..] {
                    if c == left_quote {
                        ctx.surrounding_quote = (left_quote as char).to_string();
                        break;
                    } else if c == b'\'' || c == b'"' || c == b'<' {
                        break;
                    }
                }
            }

            // Is it in an HTML comment?
            let prefix = &page[..start];
            let last_open = prefix.rfind("<!--").map(|p| p as isize).unwrap_or(-1);
            let last_close = prefix.rfind('>').map(|p| p as isize).unwrap_or(-1);
            if last_open > last_close {
                ctx.html_comment = true;
            }

            // Work out the location in the DOM.
            if let Some(ei) = self.dom.enclosing(start) {
                let el = &self.dom.elements[ei];
                let is_input = el.name.eq_ignore_ascii_case("input");
                let mut is_image_input = false;
                let content = page[el.content.0..el.content.1].trim();
                if content.contains(target) {
                    for (tag_name, atts) in parse_tag(content) {
                        if target.contains(tag_name.as_str()) {
                            ctx.in_element_name = true;
                            ctx.element_name = Some(tag_name.clone());
                            for (an, av) in atts {
                                if target.contains(an.as_str()) {
                                    ctx.set_tag_attributes(&an, Some(av));
                                }
                            }
                        }
                    }
                }
                for att in &el.attrs {
                    if injection_in_attribute_value(&ctx, att) {
                        if ctx.surrounding_quote != att.quote.to_string() && att.quote != ' ' {
                            ctx.surrounding_quote = att.quote.to_string();
                        }
                        ctx.tag_attribute = Some(att.name.clone());
                        ctx.tag_attribute_value = att.value.clone();
                        ctx.in_url_attribute = eq_any(URL_ATTRIBUTES, &att.name);
                        ctx.in_script_attribute = eq_any(SCRIPT_ATTRIBUTES, &att.name);
                    } else if att.name.eq_ignore_ascii_case(target)
                        || (target.contains(att.name.as_str()) && !ctx.in_element_name)
                    {
                        ctx.in_attribute_name = true;
                        ctx.set_tag_attributes(&att.name, att.value.clone());
                    }
                    if is_input
                        && att.name.eq_ignore_ascii_case("type")
                        && att.value.as_deref().is_some_and(|v| v.eq_ignore_ascii_case("image"))
                    {
                        is_image_input = true;
                    }
                }
                ctx.parent_tags.insert(0, el.name.clone());
                if !is_input || is_image_input {
                    ctx.in_tag_with_src = eq_any(TAGS_WITH_SRC, &el.name);
                }
                let mut p = el.parent;
                while let Some(pi) = p {
                    ctx.parent_tags.insert(0, self.dom.elements[pi].name.clone());
                    p = self.dom.elements[pi].parent;
                }
            }
            if target_ctx.is_none_or(|t| t.matches(&ctx, ignore)) && (!ignore_safe_parents || !ctx.in_safe_parent_tag())
            {
                out.push(ctx);
            }
        }
        out
    }
}

fn injection_in_attribute_value(ctx: &HtmlContext, att: &Attr) -> bool {
    match &att.value {
        Some(v) => {
            ctx.start >= att.value_start
                && ctx.end <= att.value_end
                && v.to_lowercase().contains(&ctx.target.to_lowercase())
        }
        None => false,
    }
}

/// HtmlContextAnalyser.parseTag: a crude left-to-right tag scanner used where the
/// parser does not see injected markup as tags. Ported with its quirks (the attribute
/// map carries over between tags without attributes; names are cut from the input
/// using offsets of the trimmed tag text). Returns tag name -> attributes, in
/// insertion order.
pub fn parse_tag(input: &str) -> Vec<(String, Vec<(String, String)>)> {
    let mut map: Vec<(String, Vec<(String, String)>)> = Vec::new();
    let mut att_map: Vec<(String, String)> = Vec::new();
    let mut input = input;
    while !input.is_empty() {
        let Some(ts) = input.find('<') else { break };
        let Some(te) = index_of(input, ">", ts) else { break };
        let tag_string = input[ts + 1..te].trim();
        let tag_name: Option<String>;
        if tag_string.starts_with("!--") {
            input = &input[te + 1..];
            continue;
        } else if tag_string.is_empty() {
            // Java would throw StringIndexOutOfBoundsException here and abandon the analysis.
            break;
        } else if !tag_string.starts_with('/') {
            match tag_string.find(' ') {
                Some(fs) => {
                    tag_name = input.get(ts + 1..ts + fs + 1).map(|s| s.trim().to_string());
                    let attr = input.get(ts + fs + 1..te).unwrap_or("").trim();
                    att_map = parse_attributes(attr);
                }
                None => tag_name = Some(tag_string.to_string()),
            }
        } else {
            tag_name = Some(input[ts + 1..te].trim().to_string());
        }
        if let Some(name) = tag_name.as_ref().filter(|n| !n.is_empty() && !n.starts_with('/')) {
            match map.iter_mut().find(|(k, _)| k == name) {
                Some(slot) => slot.1 = att_map.clone(),
                None => map.push((name.clone(), att_map.clone())),
            }
        }
        input = &input[te + 1..];
    }
    map
}

/// HtmlContextAnalyser.parseAttributes, ported with its quirks.
pub fn parse_attributes(attr: &str) -> Vec<(String, String)> {
    let mut map: Vec<(String, String)> = Vec::new();
    let mut content = attr.to_string();
    while !content.is_empty() {
        let Some(i) = content.find('=') else { break };
        let name = content[..i].trim().to_string();
        content = content[i + 1..].trim().to_string();
        let find = |c: char, from: isize| -> isize {
            let from = from.max(0) as usize;
            content.get(from..).and_then(|s| s.find(c)).map(|p| (from + p) as isize).unwrap_or(-1)
        };
        let mut qs = find('"', 0);
        let mut qe = find('"', qs + 1);
        if qs != 0 || qe == -1 {
            qs = find('\'', 0);
            qe = find('\'', qs + 1);
            if qs != 0 || qe == -1 {
                qs = -1;
                qe = find(' ', qs + 2);
                if qe == -1 {
                    break;
                }
            }
        }
        let value = content[(qs + 1) as usize..qe as usize].to_string();
        match map.iter_mut().find(|(k, _)| *k == name) {
            Some(slot) => slot.1 = value,
            None => map.push((name, value)),
        }
        content = content[(qe + 1) as usize..].to_string();
    }
    map
}

// ---------------------------------------------------------------------------
// ComparableResponse

const STATUS_CODE_WEIGHT: f32 = 1.0;
const HEADERS_WEIGHT: f32 = 0.15;
const HTML_STRUCTURE_WEIGHT: f32 = 0.5;
const NUMBER_LINES_WEIGHT: f32 = 0.25;
const NUMBER_WORDS_WEIGHT: f32 = 0.5;
const REFLECTION_WEIGHT: f32 = 0.5;
const RELEVANT_KEYWORDS_WEIGHT: f32 = 0.5;
const DYNAMIC_HEADERS: &[&str] = &["Expires", "Date"];
const RELEVANT_KEYWORDS: &[&str] =
    &["error", "problem", "unexpected", "template", "line", "syntax", "warning", "unknown", "token"];

/// A response reduced to features that can be compared for similarity (0..1).
pub struct ComparableResponse {
    status: u16,
    body: String,
    /// Case-insensitive map (last value wins), keyed by lower-case name with the
    /// original name kept for the dynamic-header check.
    headers: Vec<(String, String, String)>,
    value_sent: String,
    paths: Option<(HashMap<String, usize>, usize)>,
}

impl ComparableResponse {
    pub fn new(resp: &Response, value_sent: &str) -> Self {
        let mut headers: Vec<(String, String, String)> = Vec::new();
        for (k, v) in &resp.headers {
            let lk = k.to_ascii_lowercase();
            match headers.iter_mut().find(|(l, _, _)| *l == lk) {
                Some(slot) => slot.2 = v.clone(),
                None => headers.push((lk, k.clone(), v.clone())),
            }
        }
        let mut c = Self {
            status: resp.status,
            body: resp.body_str().to_string(),
            headers,
            value_sent: value_sent.to_string(),
            paths: None,
        };
        c.paths = Some(c.all_paths());
        c
    }

    fn header(&self, lower: &str) -> Option<&str> {
        self.headers.iter().find(|(l, _, _)| l == lower).map(|(_, _, v)| v.as_str())
    }

    fn content_type(&self) -> Option<String> {
        self.header("content-type").map(|v| v.to_lowercase().split(';').next().unwrap_or("").to_string())
    }

    pub fn compare_with(&self, other: &ComparableResponse) -> f32 {
        let mut total = 1f32;
        total *= status_code_heuristic(self, other) * STATUS_CODE_WEIGHT + (1.0 - STATUS_CODE_WEIGHT);
        if total == 0.0 {
            return 0.0;
        }
        total *= body_trees_structure_heuristic(self, other) * HTML_STRUCTURE_WEIGHT + (1.0 - HTML_STRUCTURE_WEIGHT);
        total *= headers_compare_heuristic(self, other) * HEADERS_WEIGHT + (1.0 - HEADERS_WEIGHT);
        total *= line_count_heuristic(self, other) * NUMBER_LINES_WEIGHT + (1.0 - NUMBER_LINES_WEIGHT);
        total *= word_count_heuristic(self, other) * NUMBER_WORDS_WEIGHT + (1.0 - NUMBER_WORDS_WEIGHT);
        total *= input_reflection_heuristic(self, other) * REFLECTION_WEIGHT + (1.0 - REFLECTION_WEIGHT);
        total *= relevant_keywords_count_heuristic(self, other) * RELEVANT_KEYWORDS_WEIGHT
            + (1.0 - RELEVANT_KEYWORDS_WEIGHT);
        total
    }

    fn all_paths(&self) -> (HashMap<String, usize>, usize) {
        let mut paths = HashMap::new();
        let mut n = 0;
        let Some(ct) = self.content_type() else { return (paths, 0) };
        if ct.contains("text/html") {
            let dom = Dom::parse(&self.body);
            for child in dom.children(None) {
                for p in html_element_paths(&dom, child) {
                    *paths.entry(p).or_insert(0) += 1;
                    n += 1;
                }
            }
        }
        if ct.contains("json") {
            let v = serde_json::from_str::<serde_json::Value>(&self.body)
                .unwrap_or_else(|_| serde_json::Value::String(self.body.clone()));
            for p in json_element_paths(&v) {
                *paths.entry(p).or_insert(0) += 1;
                n += 1;
            }
        }
        (paths, n)
    }
}

fn ratio(a: f32, b: f32) -> f32 {
    if a > b {
        b / a
    } else if a < b {
        a / b
    } else {
        1.0
    }
}

fn status_code_heuristic(a: &ComparableResponse, b: &ComparableResponse) -> f32 {
    if a.status != b.status {
        0.0
    } else {
        1.0
    }
}

fn count_matches(hay: &str, needle: &str) -> usize {
    if needle.is_empty() {
        0
    } else {
        hay.matches(needle).count()
    }
}

fn relevant_keywords_count_heuristic(a: &ComparableResponse, b: &ComparableResponse) -> f32 {
    let (mut n1, mut n2) = (0f32, 0f32);
    let (b1, b2) = (a.body.to_lowercase(), b.body.to_lowercase());
    for k in RELEVANT_KEYWORDS {
        if k.eq_ignore_ascii_case(&a.value_sent) || k.eq_ignore_ascii_case(&b.value_sent) {
            continue;
        }
        n1 += count_matches(&b1, k) as f32;
        n2 += count_matches(&b2, k) as f32;
    }
    ratio(n1, n2)
}

/// commons-text `StringEscapeUtils.escapeHtml4` for the characters that matter here.
fn escape_html4(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            c => out.push(c),
        }
    }
    out
}

fn input_reflection_heuristic(a: &ComparableResponse, b: &ComparableResponse) -> f32 {
    let (v1, v2) = (a.value_sent.as_str(), b.value_sent.as_str());
    let (e1, e2) = (escape_html4(v1), escape_html4(v2));
    let mut body1 = a.body.clone();
    let mut body2 = b.body.clone();
    let p1in1 = count_matches(&body1, v1) + count_matches(&body1, &e1);
    let p2in2 = count_matches(&body2, v2) + count_matches(&body2, &e2);
    if v2.contains(v1) && !v2.is_empty() {
        body2 = body2.replace(v2, "");
    }
    let mut p1in2 = count_matches(&body2, v1);
    if e1 != v1 {
        p1in2 += count_matches(&body2, &e1);
    }
    if v1.contains(v2) && !v1.is_empty() {
        body1 = body1.replace(v1, "");
    }
    let mut p2in1 = count_matches(&body1, v2);
    if e2 != v2 {
        p2in1 += count_matches(&body1, &e2);
    }
    let n1 = 1.0 + (p1in1 as f32 - p1in2 as f32).abs();
    let n2 = 1.0 + (p2in1 as f32 - p2in2 as f32).abs();
    ratio(n1, n2)
}

/// Java `Pattern.split(s).length`: trailing empty strings are dropped, and an input
/// without any match is one element.
fn java_split_len(s: &str, is_sep: impl Fn(char) -> bool) -> usize {
    let parts: Vec<&str> = s.split(&is_sep).collect();
    if parts.len() == 1 {
        return 1;
    }
    // Consecutive separators form one match for `\s+`-style patterns.
    let mut merged: Vec<&str> = Vec::new();
    for (i, p) in parts.iter().enumerate() {
        if p.is_empty() && i > 0 && i < parts.len() - 1 {
            continue;
        }
        merged.push(p);
    }
    while merged.last().is_some_and(|p| p.is_empty()) {
        merged.pop();
    }
    merged.len()
}

fn word_count_heuristic(a: &ComparableResponse, b: &ComparableResponse) -> f32 {
    let n = |s: &str| java_split_len(s, char::is_whitespace) as f32;
    ratio(n(&a.body), n(&b.body))
}

fn line_count_heuristic(a: &ComparableResponse, b: &ComparableResponse) -> f32 {
    let n = |s: &str| {
        let parts: Vec<&str> = s.split("\r\n").flat_map(|p| p.split(['\r', '\n'])).collect();
        let mut len = parts.len();
        if len > 1 {
            while len > 0 && parts[len - 1].is_empty() {
                len -= 1;
            }
        }
        len as f32
    };
    ratio(n(&a.body), n(&b.body))
}

fn headers_compare_heuristic(a: &ComparableResponse, b: &ComparableResponse) -> f32 {
    if a.headers.is_empty() && b.headers.is_empty() {
        return 1.0;
    }
    if a.headers.is_empty() || b.headers.is_empty() {
        return 0.0;
    }
    let (larger, smaller) = if b.headers.len() > a.headers.len() { (b, a) } else { (a, b) };
    let mut number = larger.headers.len().max(smaller.headers.len()) as f32;
    let mut equal = 0f32;
    for (lk, orig, v) in &larger.headers {
        if DYNAMIC_HEADERS.contains(&orig.as_str()) {
            number -= 1.0;
            continue;
        }
        if smaller.header(lk) == Some(v.as_str()) {
            equal += 1.0;
        }
    }
    equal / number
}

fn body_trees_structure_heuristic(a: &ComparableResponse, b: &ComparableResponse) -> f32 {
    match (a.content_type(), b.content_type()) {
        (Some(c1), Some(c2)) => {
            if c1 != c2 {
                return 0.0;
            }
            if c1.contains("text/html") || c1.contains("json") {
                let empty = (HashMap::new(), 0);
                let (p1, n1) = a.paths.as_ref().unwrap_or(&empty);
                let (p2, n2) = b.paths.as_ref().unwrap_or(&empty);
                if *n1 == 0 && *n2 == 0 {
                    return 1.0;
                }
                if *n1 == 0 || *n2 == 0 {
                    return 0.0;
                }
                let common: usize = p1.iter().filter(|(k, v)| p2.get(*k) == Some(v)).map(|(_, v)| *v).sum();
                let f1 = common as f32 / *n1 as f32;
                let f2 = common as f32 / *n2 as f32;
                return (f1 + f2) / 2.0;
            }
            1.0
        }
        (None, None) => 1.0,
        _ => 0.0,
    }
}

fn html_element_paths(dom: &Dom, node: usize) -> Vec<String> {
    let mut out = Vec::new();
    for child in dom.children(Some(node)) {
        for p in html_element_paths(dom, child) {
            out.push(p + &dom.elements[node].name);
        }
    }
    if out.is_empty() {
        out.push(dom.elements[node].name.clone());
    }
    out
}

fn json_element_paths(v: &serde_json::Value) -> Vec<String> {
    let mut out = Vec::new();
    match v {
        serde_json::Value::Object(m) => {
            for (k, child) in m {
                for p in json_element_paths(child) {
                    out.push(p + k);
                }
            }
        }
        serde_json::Value::Array(a) => {
            for child in a {
                out.extend(json_element_paths(child));
            }
        }
        _ => {}
    }
    if out.is_empty() {
        out.push(String::new());
    }
    out
}

#[cfg(test)]
pub mod testing {
    //! Builders for rule unit tests.
    use super::*;
    use std::time::Duration;

    /// A parsed response from raw HTTP bytes.
    pub fn response(raw: &str) -> Response {
        Response::parse(b"GET / HTTP/1.1\r\n\r\n".to_vec(), raw.as_bytes().to_vec(), Duration::ZERO).unwrap()
    }

    /// A 200 text/html response with `body`.
    pub fn html(body: &str) -> Arc<Response> {
        Arc::new(response(&format!(
            "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: {}\r\n\r\n{body}",
            body.len()
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::testing::*;
    use super::*;

    fn names(dom: &Dom, pos: usize) -> Vec<String> {
        let mut out = Vec::new();
        let mut p = dom.enclosing(pos);
        while let Some(i) = p {
            out.insert(0, dom.elements[i].name.clone());
            p = dom.elements[i].parent;
        }
        out
    }

    #[test]
    fn dom_builds_jericho_like_tree() {
        let html =
            "<html><body><p>one<p>two <b>x</b><div>unclosed<img src=a><script>if (a<b) {}</script></body></html>";
        let dom = Dom::parse(html);
        assert_eq!(names(&dom, html.find("one").unwrap()), ["html", "body", "p"]);
        assert_eq!(names(&dom, html.find("x</b>").unwrap()), ["html", "body", "p", "b"]);
        // The unclosed div spans only its start tag; the p was implicitly closed by it.
        assert_eq!(names(&dom, html.find("unclosed").unwrap()), ["html", "body"]);
        assert_eq!(names(&dom, html.find("a<b").unwrap()), ["html", "body", "script"]);
        assert_eq!(dom.named("img").count(), 1);
        assert_eq!(dom.named("b").count(), 1);
        let img = dom.named("img").next().unwrap();
        assert_eq!(img.attr("src"), Some("a"));
        // Content of an element.
        let script = dom.named("script").next().unwrap();
        assert_eq!(&html[script.content.0..script.content.1], "if (a<b) {}");
    }

    #[test]
    fn contexts_in_attribute_and_text() {
        let resp = html(
            r#"<html><body><input value="0W45pz4p" type=text><a href='x0W45pz4p'>t</a>0W45pz4p<!-- 0W45pz4p --><textarea>0W45pz4p</textarea></body></html>"#,
        );
        let a = HtmlContextAnalyser::new(resp);
        let c = a.contexts(EYE_CATCHER, None, 0, false);
        assert_eq!(c.len(), 5);
        assert_eq!(c[0].tag_attribute.as_deref(), Some("value"));
        assert_eq!(c[0].surrounding_quote, "\"");
        assert!(!c[0].in_tag_with_src, "input without type=image");
        assert_eq!(c[1].tag_attribute.as_deref(), Some("href"));
        assert!(c[1].in_url_attribute);
        assert_eq!(c[1].surrounding_quote, "'");
        assert_eq!(c[2].parent_tag(), Some("body"));
        assert_eq!(c[2].tag_attribute, None);
        assert!(c[3].html_comment);
        assert!(c[4].in_safe_parent_tag());
        // Ignored safe parents and matching against a target context.
        assert_eq!(a.contexts(EYE_CATCHER, None, 0, true).len(), 4);
        assert_eq!(a.contexts(EYE_CATCHER, Some(&c[2]), 0, false).len(), 1);
        assert_eq!(a.contexts(EYE_CATCHER, Some(&c[2]), IGNORE_HTML_COMMENT, false).len(), 2);
    }

    #[test]
    fn contexts_for_injected_attributes() {
        let resp = html("<html><body><tag accesskey='x' onclick='alert(1)' b>t</tag></body></html>");
        let a = HtmlContextAnalyser::new(resp);
        let c = a.contexts("tag accesskey='x' onclick='alert(1)' b", None, 0, false);
        assert_eq!(c.len(), 1);
        assert!(c[0].in_attribute_name);
        assert!(c[0].has_attribute("accesskey", "x") && c[0].has_attribute("onclick", "alert(1)"));
        assert_eq!(c[0].parent_tag(), Some("tag"));
        let resp = html("<html><body><p>a<b onMouseOver=alert(1);>test</b></p></body></html>");
        // The injected element itself encloses the reflection (hence ZAP's check for "b").
        let c = HtmlContextAnalyser::new(resp).contexts("<b onMouseOver=alert(1);>test</b>", None, 0, false);
        assert_eq!(c[0].parent_tags, ["html", "body", "p", "b"]);
    }

    #[test]
    fn parse_tag_quirks() {
        let m = parse_tag("hi <a href=\"x\" id='y' z=1 >t</a><br><!-- c -->");
        assert_eq!(m[0].0, "a");
        assert_eq!(m[0].1, vec![("href".to_string(), "x".to_string()), ("id".into(), "y".into())]);
        // <br> has no space: it reuses the previous attribute map (as ZAP does).
        assert_eq!(m[1].0, "br");
        // A trailing unquoted value is dropped (no space after it), as in ZAP.
        assert_eq!(m[1].1.len(), 2);
        assert_eq!(parse_attributes("a=b"), Vec::<(String, String)>::new());
        assert!(parse_tag("<>").is_empty());
    }

    #[test]
    fn comparable_responses() {
        let a = response(
            "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nX: 1\r\n\r\n<html><body><p>hello abc</p></body></html>",
        );
        let b = response(
            "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nX: 1\r\n\r\n<html><body><p>hello xyz</p></body></html>",
        );
        let c = response("HTTP/1.1 500 Oops\r\nContent-Type: text/html\r\n\r\nsyntax error");
        let d = response("HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nX: 1\r\n\r\n<html><body><h1>Template error</h1><pre>unexpected token on line 1</pre></body></html>");
        let ra = ComparableResponse::new(&a, "abc");
        assert_eq!(ra.compare_with(&ComparableResponse::new(&b, "xyz")), 1.0);
        assert_eq!(ra.compare_with(&ComparableResponse::new(&c, "{{")), 0.0);
        let s = ra.compare_with(&ComparableResponse::new(&d, "{{"));
        assert!(s > 0.0 && s < 0.75, "{s}");
        assert_eq!(java_split_len("", char::is_whitespace), 1);
        assert_eq!(java_split_len("a  b c ", char::is_whitespace), 3);
        assert_eq!(java_split_len(" a", char::is_whitespace), 2);
    }
}
