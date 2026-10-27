//! JSON in and out. In: `serde_json::Value`, parsed with a size cap (and
//! serde_json's own depth cap of 128), walked by hand with the helpers here.
//! Out: [`J`], an ordered value printed exactly as Python's `json.dumps`
//! prints (key order kept, ASCII only), so both implementations' output can
//! be diffed byte for byte.

use crate::error::{Error, Result};
use serde_json::Value;
use std::fmt::Write as _;

/// The largest JSON document read from a file or a response (S7).
pub const MAX_DOCUMENT: usize = 128 << 20;

/// Parse `bytes`, refusing anything over `max` bytes or nested deeper than
/// serde_json's recursion limit.
pub fn parse(bytes: &[u8], max: usize) -> Result<Value> {
    if bytes.len() > max {
        return Err(Error::Invalid(format!("JSON over {} bytes", max)));
    }
    serde_json::from_slice(bytes).map_err(|e| Error::Invalid(format!("malformed JSON: {e}")))
}

/// The string at `key`, or "" when it is missing or not a string.
pub fn str_at<'a>(v: &'a Value, key: &str) -> &'a str {
    v.get(key).and_then(Value::as_str).unwrap_or("")
}

/// The array at `key`, or an empty slice.
pub fn arr_at<'a>(v: &'a Value, key: &str) -> &'a [Value] {
    v.get(key).and_then(Value::as_array).map(Vec::as_slice).unwrap_or(&[])
}

/// The strings in the array at `key` (other items skipped).
pub fn strs_at(v: &Value, key: &str) -> Vec<String> {
    arr_at(v, key).iter().filter_map(Value::as_str).map(str::to_string).collect()
}

/// An ordered JSON value for output.
#[derive(Clone, Debug, PartialEq)]
pub enum J {
    Null,
    Bool(bool),
    Int(i64),
    Float(f64),
    Str(String),
    Arr(Vec<J>),
    Obj(Vec<(String, J)>),
}

impl From<&str> for J {
    fn from(s: &str) -> J {
        J::Str(s.to_string())
    }
}
impl From<String> for J {
    fn from(s: String) -> J {
        J::Str(s)
    }
}
impl From<bool> for J {
    fn from(b: bool) -> J {
        J::Bool(b)
    }
}
impl From<i64> for J {
    fn from(n: i64) -> J {
        J::Int(n)
    }
}

/// An object from (key, value) pairs, in order.
pub fn obj<const N: usize>(pairs: [(&str, J); N]) -> J {
    J::Obj(pairs.into_iter().map(|(k, v)| (k.to_string(), v)).collect())
}

impl J {
    /// `json.dumps(self)`: one line, ", " and ": " separators.
    pub fn dumps(&self) -> String {
        let mut out = String::new();
        self.write(&mut out, None, 0);
        out
    }

    /// `json.dumps(self, indent=n)`.
    pub fn dumps_indent(&self, n: usize) -> String {
        let mut out = String::new();
        self.write(&mut out, Some(n), 0);
        out
    }

    fn write(&self, out: &mut String, indent: Option<usize>, level: usize) {
        match self {
            J::Null => out.push_str("null"),
            J::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
            J::Int(n) => {
                let _ = write!(out, "{n}");
            }
            J::Float(x) => out.push_str(&float_repr(*x)),
            J::Str(s) => quote(out, s),
            J::Arr(items) => {
                if items.is_empty() {
                    out.push_str("[]");
                    return;
                }
                out.push('[');
                for (i, item) in items.iter().enumerate() {
                    separate(out, indent, level + 1, i == 0);
                    item.write(out, indent, level + 1);
                }
                close(out, indent, level);
                out.push(']');
            }
            J::Obj(pairs) => {
                if pairs.is_empty() {
                    out.push_str("{}");
                    return;
                }
                out.push('{');
                for (i, (k, v)) in pairs.iter().enumerate() {
                    separate(out, indent, level + 1, i == 0);
                    quote(out, k);
                    out.push_str(": ");
                    v.write(out, indent, level + 1);
                }
                close(out, indent, level);
                out.push('}');
            }
        }
    }
}

fn separate(out: &mut String, indent: Option<usize>, level: usize, first: bool) {
    match indent {
        Some(n) => {
            if !first {
                out.push(',');
            }
            out.push('\n');
            out.extend(std::iter::repeat_n(' ', n * level));
        }
        None => {
            if !first {
                out.push_str(", ");
            }
        }
    }
}

fn close(out: &mut String, indent: Option<usize>, level: usize) {
    if let Some(n) = indent {
        out.push('\n');
        out.extend(std::iter::repeat_n(' ', n * level));
    }
}

/// A JSON string as Python writes it with `ensure_ascii=True`.
fn quote(out: &mut String, s: &str) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{8}' => out.push_str("\\b"),
            '\u{c}' => out.push_str("\\f"),
            ' '..='~' => out.push(c),
            _ => {
                let mut buf = [0u16; 2];
                for unit in c.encode_utf16(&mut buf) {
                    let _ = write!(out, "\\u{:04x}", unit);
                }
            }
        }
    }
    out.push('"');
}

/// Python's `repr(float)`: the shortest round-tripping digits, with ".0" on
/// whole numbers.
fn float_repr(x: f64) -> String {
    if !x.is_finite() {
        return if x.is_nan() {
            "NaN".into()
        } else if x > 0.0 {
            "Infinity".into()
        } else {
            "-Infinity".into()
        };
    }
    if x == x.trunc() && x.abs() < 1e16 {
        return format!("{x:.1}");
    }
    format!("{x}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dumps_like_python() {
        let v = obj([
            ("schema", J::Int(1)),
            ("checked", J::Obj(vec![])),
            ("list", J::Arr(vec![J::from("\u{e9}\"x"), J::Bool(true), J::Null, J::Float(-1.5), J::Float(0.0)])),
        ]);
        assert_eq!(v.dumps(), r#"{"schema": 1, "checked": {}, "list": ["\u00e9\"x", true, null, -1.5, 0.0]}"#);
        assert_eq!(
            v.dumps_indent(1),
            "{\n \"schema\": 1,\n \"checked\": {},\n \"list\": [\n  \"\\u00e9\\\"x\",\n  true,\n  null,\n  -1.5,\n  0.0\n ]\n}"
        );
        assert_eq!(J::from("\u{1f600}\u{7f}").dumps(), r#""\ud83d\ude00\u007f""#);
    }

    #[test]
    fn parse_caps_size() {
        assert!(parse(b"[1, 2]", 100).is_ok());
        assert!(matches!(parse(b"[1, 2]", 3), Err(Error::Invalid(_))));
        assert!(matches!(parse(b"{", 100), Err(Error::Invalid(_))));
        let deep = "[".repeat(1000) + &"]".repeat(1000);
        assert!(matches!(parse(deep.as_bytes(), 1 << 20), Err(Error::Invalid(_))));
    }
}
