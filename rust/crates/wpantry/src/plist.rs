//! Property lists (macOS `Info.plist`), XML or binary (`bplist00`), read
//! into JSON values: dict → object, array → array, string/date → string,
//! integer/real → number, bool → bool, data → its length as a string (not
//! needed here). Anything malformed, missing or over a cap reads as an
//! empty object, as Python's `system.plist` does.

use serde_json::{Map, Number, Value};
use std::path::Path;

const MAX: u64 = 16 << 20;

/// The plist at `path` as JSON, or an empty object.
pub fn read(path: &Path) -> Value {
    let empty = Value::Object(Map::new());
    let Ok(bytes) = crate::system::read_capped_bytes(path, MAX) else { return empty };
    parse(&bytes).filter(Value::is_object).unwrap_or(empty)
}

pub fn parse(bytes: &[u8]) -> Option<Value> {
    if bytes.starts_with(b"bplist00") { binary(bytes) } else { xml(std::str::from_utf8(bytes).ok()?) }
}

// XML ----------------------------------------------------------------------

fn unescape(s: &str) -> String {
    s.replace("&lt;", "<").replace("&gt;", ">").replace("&quot;", "\"").replace("&apos;", "'").replace("&amp;", "&")
}

struct Xml<'a> {
    s: &'a str,
    i: usize,
}

impl<'a> Xml<'a> {
    /// The next tag: (name, closing, self-closing). Skips text, comments,
    /// the declaration and the doctype.
    fn tag(&mut self) -> Option<(&'a str, bool, bool)> {
        loop {
            let open = self.s[self.i..].find('<')? + self.i;
            let rest = &self.s[open..];
            if rest.starts_with("<!--") {
                self.i = open + rest.find("-->")? + 3;
                continue;
            }
            if rest.starts_with("<?") || rest.starts_with("<!") {
                self.i = open + rest.find('>')? + 1;
                continue;
            }
            let close = rest.find('>')?;
            let body = &rest[1..close];
            self.i = open + close + 1;
            let closing = body.starts_with('/');
            let selfclose = body.ends_with('/');
            let name = body.trim_start_matches('/').trim_end_matches('/').split_whitespace().next().unwrap_or("");
            return Some((name, closing, selfclose));
        }
    }

    fn text_until(&mut self, name: &str) -> Option<String> {
        let end = format!("</{name}>");
        let at = self.s[self.i..].find(&end)? + self.i;
        let text = unescape(&self.s[self.i..at]);
        self.i = at + end.len();
        Some(text)
    }

    fn value(&mut self, depth: usize) -> Option<Value> {
        if depth > 64 {
            return None;
        }
        let (name, closing, selfclose) = self.tag()?;
        if closing {
            return None;
        }
        Some(match name {
            "plist" => {
                let v = self.value(depth + 1)?;
                return Some(v);
            }
            "dict" if selfclose => Value::Object(Map::new()),
            "dict" => {
                let mut map = Map::new();
                loop {
                    let save = self.i;
                    let (n, closing, _) = self.tag()?;
                    if closing && n == "dict" {
                        break;
                    }
                    if n != "key" {
                        self.i = save;
                        return None;
                    }
                    let key = self.text_until("key")?;
                    let v = self.value(depth + 1)?;
                    map.insert(key, v);
                }
                Value::Object(map)
            }
            "array" if selfclose => Value::Array(Vec::new()),
            "array" => {
                let mut items = Vec::new();
                loop {
                    let save = self.i;
                    let (n, closing, _) = self.tag()?;
                    if closing && n == "array" {
                        break;
                    }
                    self.i = save;
                    items.push(self.value(depth + 1)?);
                }
                Value::Array(items)
            }
            "string" | "date" if selfclose => Value::String(String::new()),
            "string" | "date" => Value::String(self.text_until(name)?),
            "integer" => {
                let t = self.text_until("integer")?;
                t.trim().parse::<i64>().map(Value::from).unwrap_or(Value::String(t))
            }
            "real" => {
                let t = self.text_until("real")?;
                t.trim().parse::<f64>().ok().and_then(Number::from_f64).map(Value::Number).unwrap_or(Value::String(t))
            }
            "true" => Value::Bool(true),
            "false" => Value::Bool(false),
            "data" => Value::String(self.text_until("data")?.trim().len().to_string()),
            _ => return None,
        })
    }
}

fn xml(s: &str) -> Option<Value> {
    Xml { s, i: 0 }.value(0)
}

// Binary -------------------------------------------------------------------

struct Bin<'a> {
    b: &'a [u8],
    offsets: Vec<usize>,
    ref_size: usize,
    /// Objects decoded so far (see [`MAX_OBJECTS`]).
    visited: std::cell::Cell<usize>,
}

/// The most objects one plist may decode into: an app's Info.plist has
/// hundreds, never a hundred thousand.
const MAX_OBJECTS: usize = 100_000;

fn be(bytes: &[u8]) -> Option<u64> {
    if bytes.len() > 8 {
        return None;
    }
    Some(bytes.iter().fold(0u64, |acc, b| (acc << 8) | u64::from(*b)))
}

impl Bin<'_> {
    fn count(&self, marker: u8, at: usize) -> Option<(usize, usize)> {
        let low = (marker & 0x0f) as usize;
        if low != 0x0f {
            return Some((low, at + 1));
        }
        let int = *self.b.get(at + 1)?;
        if int >> 4 != 0x1 {
            return None;
        }
        let size = 1usize << (int & 0x0f);
        let n = be(self.b.get(at + 2..at + 2 + size)?)? as usize;
        Some((n, at + 2 + size))
    }

    fn object(&self, idx: usize, depth: usize) -> Option<Value> {
        // Depth alone doesn't bound the work: references may fan out, so a
        // few nested arrays can name 2^n objects. Count them.
        if depth > 64 || self.visited.replace(self.visited.get() + 1) >= MAX_OBJECTS {
            return None;
        }
        let at = *self.offsets.get(idx)?;
        let marker = *self.b.get(at)?;
        Some(match marker >> 4 {
            0x0 => match marker {
                0x08 => Value::Bool(false),
                0x09 => Value::Bool(true),
                _ => Value::Null,
            },
            0x1 => {
                let size = 1usize << (marker & 0x0f);
                Value::from(be(self.b.get(at + 1..at + 1 + size)?)? as i64)
            }
            0x2 => {
                let size = 1usize << (marker & 0x0f);
                let raw = self.b.get(at + 1..at + 1 + size)?;
                let x = match size {
                    4 => f32::from_be_bytes(raw.try_into().ok()?) as f64,
                    8 => f64::from_be_bytes(raw.try_into().ok()?),
                    _ => return None,
                };
                Number::from_f64(x).map(Value::Number).unwrap_or(Value::Null)
            }
            0x3 => Value::String(String::new()), // a date: not needed
            0x4 => Value::String(self.count(marker, at)?.0.to_string()),
            0x5 => {
                let (n, start) = self.count(marker, at)?;
                Value::String(String::from_utf8_lossy(self.b.get(start..start + n)?).into_owned())
            }
            0x6 => {
                let (n, start) = self.count(marker, at)?;
                let units: Vec<u16> =
                    self.b.get(start..start + 2 * n)?.chunks(2).map(|c| u16::from_be_bytes([c[0], c[1]])).collect();
                Value::String(String::from_utf16_lossy(&units))
            }
            0xA => {
                let (n, start) = self.count(marker, at)?;
                let mut items = Vec::with_capacity(n.min(4096));
                for i in 0..n {
                    let r = be(self.b.get(start + i * self.ref_size..start + (i + 1) * self.ref_size)?)? as usize;
                    items.push(self.object(r, depth + 1)?);
                }
                Value::Array(items)
            }
            0xD => {
                let (n, start) = self.count(marker, at)?;
                let mut map = Map::new();
                for i in 0..n {
                    let k = be(self.b.get(start + i * self.ref_size..start + (i + 1) * self.ref_size)?)? as usize;
                    let vstart = start + (n + i) * self.ref_size;
                    let v = be(self.b.get(vstart..vstart + self.ref_size)?)? as usize;
                    let Value::String(key) = self.object(k, depth + 1)? else { return None };
                    map.insert(key, self.object(v, depth + 1)?);
                }
                Value::Object(map)
            }
            _ => return None,
        })
    }
}

fn binary(b: &[u8]) -> Option<Value> {
    if b.len() < 40 {
        return None;
    }
    let trailer = &b[b.len() - 32..];
    let offset_size = trailer[6] as usize;
    let ref_size = trailer[7] as usize;
    let count = be(&trailer[8..16])? as usize;
    let top = be(&trailer[16..24])? as usize;
    let table = be(&trailer[24..32])? as usize;
    if offset_size == 0 || offset_size > 8 || ref_size == 0 || ref_size > 8 || count > b.len() {
        return None;
    }
    let offsets = (0..count)
        .map(|i| be(b.get(table + i * offset_size..table + (i + 1) * offset_size)?).map(|o| o as usize))
        .collect::<Option<Vec<_>>>()?;
    Bin { b, offsets, ref_size, visited: std::cell::Cell::new(0) }.object(top, 0)
}

#[cfg(test)]
mod tests {
    use super::*;

    const XML: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>CFBundleIdentifier</key>
	<string>com.example.App</string>
	<key>CFBundleShortVersionString</key>
	<string>4.41.0 &amp; more</string>
	<!-- a comment -->
	<key>LSRequiresNativeExecution</key>
	<true/>
	<key>CFBundleDocumentTypes</key>
	<array><dict><key>n</key><integer>3</integer></dict><string/></array>
	<key>Empty</key>
	<dict/>
</dict>
</plist>"#;

    #[test]
    fn xml_plists() {
        let v = parse(XML.as_bytes()).unwrap();
        assert_eq!(v["CFBundleIdentifier"], "com.example.App");
        assert_eq!(v["CFBundleShortVersionString"], "4.41.0 & more");
        assert_eq!(v["LSRequiresNativeExecution"], true);
        assert_eq!(v["CFBundleDocumentTypes"][0]["n"], 3);
        assert_eq!(v["CFBundleDocumentTypes"][1], "");
        assert!(v["Empty"].as_object().unwrap().is_empty());
        assert!(parse(b"<plist><dict><key>x</key></dict></plist>").is_none());
    }

    /// A binary plist written by hand: {"CFBundleVersion": "1.2.3", "n": 7, "ok": true}.
    fn bplist() -> Vec<u8> {
        let mut b = b"bplist00".to_vec();
        let mut offsets = Vec::new();
        // 0: dict with 3 entries, keys 1 2 3, values 4 5 6
        offsets.push(b.len());
        b.extend([0xD3, 1, 2, 3, 4, 5, 6]);
        for s in ["CFBundleVersion", "n", "ok"] {
            offsets.push(b.len());
            if s.len() < 15 {
                b.push(0x50 | s.len() as u8);
            } else {
                b.extend([0x5F, 0x10, s.len() as u8]); // the length as a following integer
            }
            b.extend(s.as_bytes());
        }
        offsets.push(b.len());
        b.push(0x55);
        b.extend(b"1.2.3");
        offsets.push(b.len());
        b.extend([0x10, 7]);
        offsets.push(b.len());
        b.push(0x09);
        let table = b.len();
        b.extend(offsets.iter().map(|o| *o as u8));
        let mut trailer = vec![0u8; 6];
        trailer.extend([1, 1]);
        trailer.extend((offsets.len() as u64).to_be_bytes());
        trailer.extend(0u64.to_be_bytes());
        trailer.extend((table as u64).to_be_bytes());
        b.extend(trailer);
        b
    }

    #[test]
    fn binary_plists() {
        let v = parse(&bplist()).unwrap();
        assert_eq!(v, serde_json::json!({"CFBundleVersion": "1.2.3", "n": 7, "ok": true}));
        let mut broken = bplist();
        let n = broken.len();
        broken[n - 1] = 0xff; // offset table out of range
        assert!(parse(&broken).is_none());
    }
}
