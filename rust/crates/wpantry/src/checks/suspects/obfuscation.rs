//! Obfuscation: a string decoded at run time and fed to `eval` or
//! `exec`, a payload kept as an array of numbers, a hand-rolled decoder
//! that builds text from character codes, and source written as escapes.
//! Decoding somewhere and evaluating somewhere else is every big bundle;
//! the two beside each other is a loader, and that is what fails. The
//! rest warns on its own and fails beside the loader. Paths where numeric
//! tables and escapes are the point (shaders, codecs, fonts, hashes,
//! fixtures, minified output) are not read for tables at all.

use super::{Context, Suspect, has_any, line_at, line_of, push, test_path};

const EXEC: &[&str] = &[
    "eval(",
    "new Function(",
    "Function(\"",
    "Function('",
    "setTimeout(\"",
    "setTimeout('",
    "setInterval(\"",
    "execScript(",
    "vm.runInThisContext(",
    "vm.runInNewContext(",
];
const DECODE: &[&str] = &[
    "atob(",
    "String.fromCharCode(",
    "fromCharCode.apply(",
    "unescape(",
    "decodeURIComponent(escape(",
    ".reverse().join(",
    "Buffer.from(",
    "TextDecoder(",
    "\\x",
    "\\u00",
];
const PY_EXEC: &[&str] = &["exec(", "eval(", "compile("];
const PY_DECODE: &[&str] = &[
    "b64decode(",
    "base64.",
    "marshal.loads(",
    "zlib.decompress(",
    "codecs.decode(",
    "bytes.fromhex(",
    "rot13",
    "lzma.decompress(",
];
/// The arithmetic a decoder does on character codes.
const DECODER_OPS: &[&str] = &[" ^ ", "^=", "<<", ">>", "% 256", "& 255"];
/// Code that turns numbers into text.
const ARRAY_DECODERS: &[&str] = &[
    "fromCharCode",
    "charCodeAt(",
    "TextDecoder",
    "atob(",
    "Buffer.from(",
    "chr(",
    "bytes(",
    "bytearray(",
    ".decode(",
    "unescape(",
];

/// How far either side of an exec token a decode token counts as beside it.
const NEAR_CHARS: usize = 200;
/// Fewer literals than this is a list, not a payload.
const MIN_ARRAY_ITEMS: usize = 32;
/// An array body longer than this ends the search: nothing hand-written is that long.
const MAX_ARRAY_BODY: usize = 200_000;
/// A hex literal in a byte table is at most `0xffff`; a decimal byte at most three digits.
const MAX_HEX_LEN: usize = 6;
const MAX_BYTE_LEN: usize = 3;
/// How many lines after an array its decoder may sit.
const DECODER_LINES: usize = 20;
/// A shorter run of escapes is an ordinary string with some control characters.
const MIN_ESCAPE_RUN: usize = 30;

/// Paths where numeric tables and escapes are the point.
fn table_path(file: &str) -> bool {
    let l = file.to_ascii_lowercase();
    [
        "vector", "fixture", "testdata", "golden", "wasm", "shader", "kernel", "gpu", "font", "codec", "table", "lut",
        "icon", "sprite", "emoji", "unicode", "crc", "sha", "md5", "aes", "/dist/", "/build/", ".min.",
    ]
    .iter()
    .any(|p| l.contains(p))
}

pub(super) fn scan(file: &str, text: &str, ctx: Context, out: &mut Vec<Suspect>) {
    let table = table_path(file);
    let (execs, decodes): (&[&'static str], &[&'static str]) = match ctx {
        Context::Web | Context::Markup => (EXEC, DECODE),
        Context::Python => (PY_EXEC, PY_DECODE),
        _ => (&[], &[]),
    };
    let exec = has_any(text, execs);

    // 1. Decoded then executed.
    let near = near_pair(text, execs, decodes);
    let decoded_exec = near.is_some();
    if let Some((e, d)) = near {
        push(
            out,
            file,
            "SUSPECT-EXEC-DECODED",
            line_of(text, e),
            format!(
                "`{}` runs code built at run time with `{}`: what executes isn't what you can read",
                e.trim_end_matches(['(', '"', '\'']),
                d.trim_end_matches('(')
            ),
            true,
        );
    }

    // 2. A payload kept as numbers.
    if matches!(ctx, Context::Web | Context::Markup | Context::Python | Context::Shell)
        && !table
        && let Some((n, line, what)) = numeric_array(text)
    {
        let decoder = array_decoded(text, line);
        push(
            out,
            file,
            "SUSPECT-ENCODED-PAYLOAD",
            line,
            format!(
                "an array of {n} {what} literals{}",
                if decoder {
                    ", and code that turns numbers into text: a payload in disguise"
                } else {
                    " in a script, where a string would do"
                }
            ),
            decoded_exec && !test_path(file),
        );
    }

    // 3. A hand-rolled string decoder.
    if matches!(ctx, Context::Web | Context::Markup)
        && text.contains("charCodeAt(")
        && text.contains("fromCharCode")
        && DECODER_OPS.iter().any(|op| text.contains(op))
    {
        push(
            out,
            file,
            "SUSPECT-STRING-DECODER",
            line_of(text, "charCodeAt("),
            "builds strings from character codes with arithmetic: a decoder for text it doesn't want read",
            decoded_exec,
        );
    }

    // 4. Source written as escapes.
    if matches!(ctx, Context::Web | Context::Markup | Context::Python) && !table {
        let (run, line) = longest_escape_run(text);
        if run >= MIN_ESCAPE_RUN {
            push(
                out,
                file,
                "SUSPECT-ESCAPED-SOURCE",
                line,
                format!("a run of {run} `\\x`/`\\u` escapes: text written so it can't be read"),
                exec.is_some(),
            );
        }
    }
}

/// An exec token with a decode token within `NEAR_CHARS` either side.
fn near_pair(text: &str, execs: &[&'static str], decodes: &[&'static str]) -> Option<(&'static str, &'static str)> {
    for e in execs {
        let mut rest = text;
        let mut offset = 0;
        while let Some(i) = rest.find(e) {
            let at = offset + i;
            let lo = at.saturating_sub(NEAR_CHARS);
            let hi = (at + e.len() + NEAR_CHARS).min(text.len());
            let lo = (lo..=at).find(|&b| text.is_char_boundary(b)).unwrap_or(at);
            let hi = (hi..=text.len()).find(|&b| text.is_char_boundary(b)).unwrap_or(text.len());
            let window = &text[lo..hi];
            if let Some(d) = decodes.iter().copied().find(|d| window.contains(d)) {
                return Some((e, d));
            }
            offset = at + e.len();
            rest = &text[offset..];
        }
    }
    None
}

/// Whether code that turns numbers into text sits within `DECODER_LINES`
/// after the array that starts on `line`.
fn array_decoded(text: &str, line: usize) -> bool {
    let after: String = text.lines().skip(line.saturating_sub(1)).take(DECODER_LINES).collect::<Vec<_>>().join("\n");
    ARRAY_DECODERS.iter().any(|s| after.contains(s))
}

/// What a bracketed body's items are when all of them are one kind of
/// plain numeric literal: hex, binary or small decimals.
fn literal_kind(items: &[&str]) -> Option<&'static str> {
    let hex = items
        .iter()
        .filter(|s| s.starts_with("0x") && s[2..].chars().all(|c| c.is_ascii_hexdigit()) && s.len() <= MAX_HEX_LEN)
        .count();
    let bin = items.iter().filter(|s| s.starts_with("0b") && s[2..].chars().all(|c| c == '0' || c == '1')).count();
    let dec = items.iter().filter(|s| s.chars().all(|c| c.is_ascii_digit()) && s.len() <= MAX_BYTE_LEN).count();
    let n = items.len();
    if hex == n {
        Some("hex")
    } else if bin == n {
        Some("binary")
    } else if dec == n {
        Some("byte")
    } else {
        None
    }
}

/// The longest array of plain numeric literals: (count, line, what), when
/// it has `MIN_ARRAY_ITEMS` or more.
fn numeric_array(text: &str) -> Option<(usize, usize, &'static str)> {
    let mut best: Option<(usize, usize, &'static str)> = None;
    let mut rest = text;
    let mut offset = 0;
    while let Some(i) = rest.find('[') {
        let start = offset + i;
        let body_end = rest[i..].find(']').map(|e| i + e).unwrap_or(rest.len());
        let body = &rest[i + 1..body_end];
        if body.len() > MAX_ARRAY_BODY {
            break;
        }
        let items: Vec<&str> = body.split(',').map(str::trim).filter(|s| !s.is_empty()).collect();
        let n = items.len();
        if n >= MIN_ARRAY_ITEMS
            && let Some(what) = literal_kind(&items)
            && best.is_none_or(|(b, _, _)| n > b)
        {
            best = Some((n, line_at(text, start), what));
        }
        offset += body_end;
        rest = &rest[body_end..];
        if rest.is_empty() {
            break;
        }
    }
    best
}

/// The longest run of consecutive `\xHH` or `\uHHHH` escapes and its line.
fn longest_escape_run(text: &str) -> (usize, usize) {
    let (mut best, mut best_line) = (0, 0);
    for (n, line) in text.lines().enumerate() {
        let mut run = 0;
        let mut rest = line;
        while let Some(i) = rest.find('\\') {
            let after = &rest[i + 1..];
            let len = if after.starts_with('x')
                && after.len() >= 3
                && after[1..3].chars().all(|c| c.is_ascii_hexdigit())
            {
                3
            } else if after.starts_with('u') && after.len() >= 5 && after[1..5].chars().all(|c| c.is_ascii_hexdigit()) {
                5
            } else {
                run = 0;
                rest = &rest[i + 1..];
                continue;
            };
            run += 1;
            if run > best {
                best = run;
                best_line = n + 1;
            }
            rest = &after[len..];
        }
    }
    (best, best_line)
}

#[cfg(test)]
#[path = "obfuscation_tests.rs"]
mod tests;
