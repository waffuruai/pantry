//! The HTML report's bundle as the page carries it ([`write`]), and back
//! ([`read`]). A machine scan repeats one advisory per lockfile copy and one
//! fix command per secret in a file, so the bundle is packed: each repeated
//! string stored once, each list of alike objects stored as rows. It knows
//! no field names, so a field added to a finding packs like the rest, and
//! [`unpack`] (and the page's `unpack` in `assets/report/report.html`) gives
//! back exactly what went in. A packed bundle still over [`DEFLATE_OVER`]
//! is deflated too, which the page inflates with the browser's
//! `DecompressionStream`; a normal-sized report never needs it.
//!
//! Packed: `{"pantry_packed": 1, "strings": [...], "data": ...}`, where in
//! `data`:
//! - a string starting with `~` is a reference: `~` and its index in
//!   `strings`, base 36 (`"~0"`, `"~1z"`). Every original string that starts
//!   with `~` goes in the table, so no other string in `data` starts with one.
//! - an array whose first item is the bare string `"~"` is a table of rows:
//!   `["~", [keys...], [values...], ...]`, one object per row.
//!
//! Deflated: `{"pantry_deflated": "<base64 of the packed JSON, raw DEFLATE>"}`.
//!
//! ```
//! use wpantry::reporters::pack::{read, write};
//! use wpantry::utils::json::J;
//! let row = |n: i64| J::Obj(vec![("id".into(), "CVE-2026-1".into()), ("n".into(), J::Int(n))]);
//! let rows = J::Arr((0..3).map(row).collect());
//! assert_eq!(read(&write(&rows)).unwrap(), serde_json::from_str::<serde_json::Value>(&rows.dumps()).unwrap());
//! ```
use crate::utils::json::{J, obj};
use serde_json::Value;
use std::collections::HashMap;

/// Starts a reference, and alone marks a table of rows.
const MARK: char = '~';
const ROWS: &str = "~";
/// Shorter strings cost about as much as a reference, so they stay inline.
const MIN_INTERNED: usize = 4;

/// A packed bundle over this many bytes is deflated as well.
pub const DEFLATE_OVER: usize = 1 << 20;

/// The bundle as the page's script element holds it (before HTML escaping).
pub fn write(bundle: &J) -> String {
    let packed = pack(bundle).dumps();
    if packed.len() <= DEFLATE_OVER {
        return packed;
    }
    let deflated = crate::utils::archive::compress::deflate(packed.as_bytes());
    obj([("pantry_deflated", crate::utils::base64::encode(&deflated).into())]).dumps()
}

/// What [`write`] wrote, as it went in; None when it is malformed.
pub fn read(payload: &str) -> Option<Value> {
    use crate::utils::json::{MAX_DOCUMENT, parse};
    let mut v = parse(payload.as_bytes(), MAX_DOCUMENT).ok()?;
    if let Some(text) = v.get("pantry_deflated").and_then(Value::as_str) {
        let deflated = crate::utils::base64::decode(text)?;
        v = parse(&crate::utils::archive::deflate::inflate(&deflated, MAX_DOCUMENT)?, MAX_DOCUMENT).ok()?;
    }
    unpack(&v)
}

/// `data`, packed.
pub fn pack(data: &J) -> J {
    let mut counts: HashMap<&str, usize> = HashMap::new();
    count(data, &mut counts);
    let mut table: Vec<&str> = counts
        .iter()
        .filter(|(s, n)| s.starts_with(MARK) || (**n > 1 && s.len() >= MIN_INTERNED))
        .map(|(s, _)| *s)
        .collect();
    // The most used first, so they get the shortest references; then by
    // text, so the same bundle always packs the same.
    table.sort_unstable_by(|a, b| counts[b].cmp(&counts[a]).then(a.cmp(b)));
    let index: HashMap<&str, usize> = table.iter().enumerate().map(|(i, s)| (*s, i)).collect();
    obj([
        ("pantry_packed", J::Int(1)),
        ("strings", J::Arr(table.iter().map(|s| J::from(*s)).collect())),
        ("data", encode(data, &index)),
    ])
}

/// How often each string (values and keys) occurs.
fn count<'a>(v: &'a J, counts: &mut HashMap<&'a str, usize>) {
    match v {
        J::Str(s) => *counts.entry(s).or_default() += 1,
        J::Arr(items) => items.iter().for_each(|x| count(x, counts)),
        J::Obj(pairs) => pairs.iter().for_each(|(k, x)| {
            *counts.entry(k).or_default() += 1;
            count(x, counts);
        }),
        _ => {}
    }
}

fn encode(v: &J, index: &HashMap<&str, usize>) -> J {
    let s = |s: &str| match index.get(s) {
        Some(i) => format!("{MARK}{}", base36(*i)),
        None => s.to_string(),
    };
    match v {
        J::Str(x) => J::Str(s(x)),
        J::Arr(items) => match rows(items) {
            Some(keys) => {
                let mut out = vec![J::from(ROWS), J::Arr(keys.iter().map(|k| J::Str(s(k))).collect())];
                out.extend(items.iter().map(|item| match item {
                    J::Obj(pairs) => J::Arr(pairs.iter().map(|(_, x)| encode(x, index)).collect()),
                    _ => unreachable!("rows() checked every item"),
                }));
                J::Arr(out)
            }
            None => J::Arr(items.iter().map(|x| encode(x, index)).collect()),
        },
        J::Obj(pairs) => J::Obj(pairs.iter().map(|(k, x)| (s(k), encode(x, index))).collect()),
        other => other.clone(),
    }
}

/// The shared keys, in order, when `items` are two or more objects that
/// all have exactly those keys.
fn rows(items: &[J]) -> Option<Vec<&str>> {
    fn keys(item: &J) -> Option<Vec<&str>> {
        match item {
            J::Obj(pairs) => Some(pairs.iter().map(|(k, _)| k.as_str()).collect()),
            _ => None,
        }
    }
    let first = keys(items.first()?)?;
    (items.len() > 1 && items[1..].iter().all(|item| keys(item).as_ref() == Some(&first))).then_some(first)
}

fn base36(mut n: usize) -> String {
    const DIGITS: &[u8; 36] = b"0123456789abcdefghijklmnopqrstuvwxyz";
    let mut out = vec![DIGITS[n % 36]];
    while n >= 36 {
        n /= 36;
        out.push(DIGITS[n % 36]);
    }
    out.reverse();
    String::from_utf8(out).expect("ASCII digits")
}

/// A packed bundle as it went in; anything else (a bundle written before
/// packing) as it is. None when a reference or a row is malformed.
pub fn unpack(packed: &Value) -> Option<Value> {
    if packed.get("pantry_packed") != Some(&Value::from(1)) {
        return Some(packed.clone());
    }
    let strings: Vec<&str> = packed.get("strings")?.as_array()?.iter().map(Value::as_str).collect::<Option<_>>()?;
    decode(packed.get("data")?, &strings)
}

fn decode(v: &Value, strings: &[&str]) -> Option<Value> {
    let s = |x: &str| match x.strip_prefix(MARK) {
        Some(i) => usize::from_str_radix(i, 36).ok().and_then(|i| strings.get(i)).map(|s| s.to_string()),
        None => Some(x.to_string()),
    };
    Some(match v {
        Value::String(x) => Value::String(s(x)?),
        Value::Array(items) if items.first().and_then(Value::as_str) == Some(ROWS) => {
            let keys: Vec<String> =
                items.get(1)?.as_array()?.iter().map(|k| k.as_str().and_then(s)).collect::<Option<_>>()?;
            let row = |r: &Value| {
                let values = r.as_array().filter(|vs| vs.len() == keys.len())?;
                let pairs = keys.iter().zip(values).map(|(k, x)| Some((k.clone(), decode(x, strings)?)));
                Some(Value::Object(pairs.collect::<Option<_>>()?))
            };
            Value::Array(items[2..].iter().map(row).collect::<Option<_>>()?)
        }
        Value::Array(items) => Value::Array(items.iter().map(|x| decode(x, strings)).collect::<Option<_>>()?),
        Value::Object(pairs) => {
            Value::Object(pairs.iter().map(|(k, x)| Some((s(k)?, decode(x, strings)?))).collect::<Option<_>>()?)
        }
        other => other.clone(),
    })
}

#[cfg(test)]
#[path = "pack_tests.rs"]
mod tests;
