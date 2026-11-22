//! Just enough JSON to read `xcrun notarytool submit --output-format json`:
//! the string members of the top-level object. Nested values are parsed
//! and skipped, so the whole document must still be valid JSON.
//!
//! ```text
//! let fields = top_level_strings(r#"{"id":"abc","status":"Accepted"}"#)?;
//! assert_eq!(fields["status"], "Accepted");
//! ```

use std::collections::BTreeMap;
use std::iter::Peekable;
use std::str::Chars;

type Input<'a> = Peekable<Chars<'a>>;

fn ws(it: &mut Input) {
    while it
        .next_if(|c| matches!(c, ' ' | '\t' | '\n' | '\r'))
        .is_some()
    {}
}

fn expect(it: &mut Input, want: char) -> Result<(), String> {
    match it.next() {
        Some(c) if c == want => Ok(()),
        other => Err(format!("bad JSON: expected {want:?}, found {other:?}")),
    }
}

fn hex4(it: &mut Input) -> Result<u32, String> {
    let mut n = 0;
    for _ in 0..4 {
        let d = it
            .next()
            .and_then(|c| c.to_digit(16))
            .ok_or("bad JSON: bad \\u escape")?;
        n = n * 16 + d;
    }
    Ok(n)
}

fn string(it: &mut Input) -> Result<String, String> {
    expect(it, '"')?;
    let mut out = String::new();
    loop {
        match it.next().ok_or("bad JSON: unterminated string")? {
            '"' => return Ok(out),
            '\\' => match it.next().ok_or("bad JSON: unterminated escape")? {
                '"' => out.push('"'),
                '\\' => out.push('\\'),
                '/' => out.push('/'),
                'b' => out.push('\u{8}'),
                'f' => out.push('\u{c}'),
                'n' => out.push('\n'),
                'r' => out.push('\r'),
                't' => out.push('\t'),
                'u' => {
                    let mut code = hex4(it)?;
                    if (0xD800..0xDC00).contains(&code) && it.peek() == Some(&'\\') {
                        it.next();
                        expect(it, 'u')?;
                        let low = hex4(it)?;
                        code =
                            0x10000 + ((code - 0xD800) << 10) + (low.wrapping_sub(0xDC00) & 0x3FF);
                    }
                    out.push(char::from_u32(code).unwrap_or('\u{FFFD}'));
                }
                other => return Err(format!("bad JSON: unknown escape \\{other}")),
            },
            c if (c as u32) < 0x20 => {
                return Err("bad JSON: control character in string".to_string());
            }
            c => out.push(c),
        }
    }
}

fn skip(it: &mut Input, depth: usize) -> Result<(), String> {
    if depth > 128 {
        return Err("bad JSON: nested too deeply".to_string());
    }
    ws(it);
    match it.peek().copied().ok_or("bad JSON: missing value")? {
        '"' => string(it).map(|_| ()),
        open @ ('{' | '[') => {
            let close = if open == '{' { '}' } else { ']' };
            it.next();
            ws(it);
            if it.next_if_eq(&close).is_some() {
                return Ok(());
            }
            loop {
                if open == '{' {
                    ws(it);
                    string(it)?;
                    ws(it);
                    expect(it, ':')?;
                }
                skip(it, depth + 1)?;
                ws(it);
                match it.next() {
                    Some(',') => continue,
                    Some(c) if c == close => return Ok(()),
                    other => {
                        return Err(format!(
                            "bad JSON: expected ',' or {close:?}, found {other:?}"
                        ));
                    }
                }
            }
        }
        _ => {
            let mut word = String::new();
            while let Some(c) =
                it.next_if(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '+' | '.'))
            {
                word.push(c);
            }
            let number = word.parse::<f64>().is_ok() && !word.starts_with('+');
            if matches!(word.as_str(), "true" | "false" | "null") || number {
                Ok(())
            } else {
                Err(format!("bad JSON: unexpected {word:?}"))
            }
        }
    }
}

/// The string-valued members of a top-level JSON object; members with
/// other values are checked and left out.
pub fn top_level_strings(text: &str) -> Result<BTreeMap<String, String>, String> {
    let mut it = text.chars().peekable();
    let mut out = BTreeMap::new();
    ws(&mut it);
    expect(&mut it, '{')?;
    ws(&mut it);
    if it.next_if_eq(&'}').is_none() {
        loop {
            ws(&mut it);
            let key = string(&mut it)?;
            ws(&mut it);
            expect(&mut it, ':')?;
            ws(&mut it);
            if it.peek() == Some(&'"') {
                out.insert(key, string(&mut it)?);
            } else {
                out.remove(&key);
                skip(&mut it, 0)?;
            }
            ws(&mut it);
            match it.next() {
                Some(',') => continue,
                Some('}') => break,
                other => return Err(format!("bad JSON: expected ',' or '}}', found {other:?}")),
            }
        }
    }
    ws(&mut it);
    match it.next() {
        None => Ok(out),
        Some(c) => Err(format!("bad JSON: trailing {c:?}")),
    }
}
