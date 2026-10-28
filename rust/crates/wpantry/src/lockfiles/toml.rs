//! The subset of TOML lockfiles use, read line by line: `[table]` and
//! `[[array]]` headers, `key = value` pairs with basic or literal strings,
//! inline tables and arrays (which may span lines). Values other than
//! strings are kept as raw text for [`inline`] to look into.

use super::lines;
use crate::error::{Error, Result};

#[derive(Clone, Debug, PartialEq)]
pub enum Val {
    Str(String),
    Raw(String),
}

impl Val {
    pub fn as_str(&self) -> Option<&str> {
        match self {
            Val::Str(s) => Some(s),
            Val::Raw(_) => None,
        }
    }
}

#[derive(Debug, Default, PartialEq)]
pub struct Table {
    /// The header without brackets ("package", "package.metadata").
    pub name: String,
    /// `[[name]]` rather than `[name]`.
    pub array: bool,
    pub entries: Vec<(String, Val)>,
}

impl Table {
    pub fn get(&self, key: &str) -> Option<&Val> {
        self.entries.iter().find(|(k, _)| k == key).map(|(_, v)| v)
    }

    pub fn str(&self, key: &str) -> &str {
        self.get(key).and_then(Val::as_str).unwrap_or("")
    }
}

/// A basic ("…", with escapes) or literal ('…') string at the start of `s`:
/// its value and the rest of `s`.
pub fn string(s: &str) -> Option<(String, &str)> {
    let quote = s.chars().next()?;
    if quote == '\'' {
        let end = s[1..].find('\'')?;
        return Some((s[1..1 + end].to_string(), &s[end + 2..]));
    }
    if quote != '"' {
        return None;
    }
    let mut out = String::new();
    let mut chars = s[1..].char_indices();
    while let Some((i, c)) = chars.next() {
        match c {
            '"' => return Some((out, &s[i + 2..])),
            '\\' => {
                let (_, e) = chars.next()?;
                match e {
                    'n' => out.push('\n'),
                    't' => out.push('\t'),
                    'r' => out.push('\r'),
                    'b' => out.push('\u{8}'),
                    'f' => out.push('\u{c}'),
                    '"' => out.push('"'),
                    '\\' => out.push('\\'),
                    'u' | 'U' => {
                        let n = if e == 'u' { 4 } else { 8 };
                        let hex: String = (0..n).filter_map(|_| chars.next().map(|(_, h)| h)).collect();
                        out.push(u32::from_str_radix(&hex, 16).ok().and_then(char::from_u32)?);
                    }
                    _ => return None,
                }
            }
            c => out.push(c),
        }
    }
    None
}

/// How much `[`/`{` nesting a line opens, outside strings and comments.
fn depth_change(s: &str) -> i64 {
    let mut d = 0;
    let mut rest = s;
    while let Some(c) = rest.chars().next() {
        match c {
            '"' | '\'' => match string(rest) {
                Some((_, r)) => {
                    rest = r;
                    continue;
                }
                None => return d,
            },
            '#' => return d,
            '[' | '{' => d += 1,
            ']' | '}' => d -= 1,
            _ => {}
        }
        rest = &rest[c.len_utf8()..];
    }
    d
}

fn key(s: &str) -> Option<(String, &str)> {
    let s = s.trim_start();
    if s.starts_with('"') || s.starts_with('\'') {
        return string(s);
    }
    let end = s.find(|c: char| !(c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.')).unwrap_or(s.len());
    (end > 0).then(|| (s[..end].to_string(), &s[end..]))
}

/// Every table in the document, in order; key/value pairs before the first
/// header go in a table named "".
pub fn parse(text: &str) -> Result<Vec<Table>> {
    let mut tables = vec![Table::default()];
    let mut pending: Option<(String, String, i64)> = None; // a value spanning lines
    for (n, raw) in lines(text)?.enumerate() {
        if let Some((k, mut v, depth)) = pending.take() {
            v.push('\n');
            v.push_str(raw);
            let depth = depth + depth_change(raw);
            if depth > 0 {
                pending = Some((k, v, depth));
            } else {
                tables.last_mut().expect("a table").entries.push((k, Val::Raw(v)));
            }
            continue;
        }
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some(inner) = line.strip_prefix("[[") {
            let name = inner.split("]]").next().unwrap_or("").trim().to_string();
            tables.push(Table { name, array: true, entries: Vec::new() });
            continue;
        }
        if let Some(inner) = line.strip_prefix('[') {
            let name = inner.split(']').next().unwrap_or("").trim().to_string();
            tables.push(Table { name, array: false, entries: Vec::new() });
            continue;
        }
        let bad = || Error::Invalid(format!("line {}: not a TOML key/value pair", n + 1));
        let (k, rest) = key(line).ok_or_else(bad)?;
        let rest = rest.trim_start().strip_prefix('=').ok_or_else(bad)?.trim_start();
        let val = if rest.starts_with("\"\"\"") || rest.starts_with("'''") {
            Val::Raw(rest.to_string()) // multi-line strings: nothing we read
        } else if rest.starts_with('"') || rest.starts_with('\'') {
            Val::Str(string(rest).ok_or_else(bad)?.0)
        } else {
            let depth = depth_change(rest);
            if depth > 0 {
                pending = Some((k, rest.to_string(), depth));
                continue;
            }
            Val::Raw(rest.to_string())
        };
        tables.last_mut().expect("a table").entries.push((k, val));
    }
    if pending.is_some() {
        return Err(Error::Invalid("an array or inline table never closes".into()));
    }
    Ok(tables)
}

/// The top-level keys of an inline table (`{ registry = "…", editable = "." }`).
pub fn inline(raw: &str) -> Vec<(String, Val)> {
    let mut out = Vec::new();
    let Some(body) = raw.trim().strip_prefix('{') else { return out };
    let mut rest = body;
    loop {
        rest = rest.trim_start_matches(|c: char| c.is_whitespace() || c == ',');
        if rest.is_empty() || rest.starts_with('}') {
            return out;
        }
        let Some((k, r)) = key(rest) else { return out };
        let Some(r) = r.trim_start().strip_prefix('=') else { return out };
        let r = r.trim_start();
        if r.starts_with('"') || r.starts_with('\'') {
            let Some((v, r)) = string(r) else { return out };
            out.push((k, Val::Str(v)));
            rest = r;
        } else {
            // A number, boolean, array or nested table: skip to the next
            // top-level comma.
            let mut depth = 0i64;
            let mut end = r.len();
            let mut it = r.char_indices().peekable();
            while let Some((i, c)) = it.next() {
                match c {
                    '"' | '\'' => {
                        if let Some((_, after)) = string(&r[i..]) {
                            let skip = r.len() - after.len();
                            while it.peek().is_some_and(|(j, _)| *j < skip) {
                                it.next();
                            }
                        }
                    }
                    '[' | '{' => depth += 1,
                    ']' | '}' if depth == 0 => {
                        end = i;
                        break;
                    }
                    ']' | '}' => depth -= 1,
                    ',' if depth == 0 => {
                        end = i;
                        break;
                    }
                    _ => {}
                }
            }
            out.push((k, Val::Raw(r[..end].trim().to_string())));
            rest = &r[end..];
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tables_strings_and_spanning_values() {
        let doc = "version = 4\n\n[[package]]\nname = \"a\\u00e9\"\nversion = '1.0.0'\nsource = { registry = \"https://pypi.org/simple\" }\ndependencies = [\n  { name = \"b\" },\n]\n# c\n[package.metadata]\nrequires-dist = [{ name = \"x\", specifier = \">=1\" }]\n";
        let t = parse(doc).unwrap();
        assert_eq!(t.len(), 3);
        assert_eq!(
            (t[1].name.as_str(), t[1].array, t[1].str("name"), t[1].str("version")),
            ("package", true, "aé", "1.0.0")
        );
        assert_eq!(
            inline(match t[1].get("source").unwrap() {
                Val::Raw(r) => r,
                _ => panic!(),
            }),
            [("registry".to_string(), Val::Str("https://pypi.org/simple".into()))]
        );
        assert_eq!((t[2].name.as_str(), t[2].array), ("package.metadata", false));
        assert!(parse("[a]\nx = [\n").is_err());
        assert!(parse("not toml").is_err());
    }

    #[test]
    fn inline_tables() {
        let got = inline("{ git = \"https://x/y.git?rev=1\", editable = \".\", n = 1, a = [1, {b = 2}], s = 'q,}' }");
        let keys: Vec<&str> = got.iter().map(|(k, _)| k.as_str()).collect();
        assert_eq!(keys, ["git", "editable", "n", "a", "s"]);
        assert_eq!(got[4].1, Val::Str("q,}".into()));
    }
}
