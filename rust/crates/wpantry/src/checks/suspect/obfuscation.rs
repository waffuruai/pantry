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
mod tests {
    use super::super::{Kind, ids, scan_text};
    use super::*;

    /// Thirty-four hex bytes: over the array threshold.
    const HEX_TABLE: &str = "[0x68,0x65,0x6c,0x6c,0x6f,0x20,0x77,0x6f,0x72,0x6c,0x64,0x21,0x68,0x65,0x6c,0x6c,0x6f,0x20,0x77,0x6f,0x72,0x6c,0x64,0x21,0x68,0x65,0x6c,0x6c,0x6f,0x20,0x77,0x6f,0x72,0x6c]";

    #[test]
    fn decoded_exec_fails_and_names_both_ends() {
        let js = format!("const p = {HEX_TABLE};\neval(String.fromCharCode.apply(null, p));\n");
        let got = scan_text("app.js", &js, Kind::Repo);
        assert_eq!(ids(&got), [("SUSPECT-EXEC-DECODED", true), ("SUSPECT-ENCODED-PAYLOAD", true)], "{got:?}");
        assert_eq!(got[0].line, 2);
        assert!(
            got[0].note.contains("`eval` runs code built at run time with `fromCharCode.apply`"),
            "{}",
            got[0].note
        );
        assert!(got[1].note.contains("34 hex literals, and code that turns numbers into text"), "{}", got[1].note);
        let py = "import base64\nexec(base64.b64decode('aGk='))\n";
        assert_eq!(ids(&scan_text("setup_helper.py", py, Kind::Repo)), [("SUSPECT-EXEC-DECODED", true)]);
        let html = "<html><script>setTimeout(\"\" + atob(x))</script></html>";
        assert_eq!(ids(&scan_text("index.html", html, Kind::Repo)), [("SUSPECT-EXEC-DECODED", true)]);
    }

    #[test]
    fn decoding_far_from_evaluating_is_a_bundle_not_a_loader() {
        let far = format!("const s = atob('aGk=');\n{}\neval('1 + 1');\n", "// padding\n".repeat(40));
        assert!(scan_text("bundle.js", &far, Kind::Repo).is_empty(), "two hundred characters apart is nothing");
        assert!(scan_text("app.js", "eval('1 + 1')", Kind::Repo).is_empty(), "eval alone");
        assert!(scan_text("app.js", "const s = atob('aGk=')", Kind::Repo).is_empty(), "decode alone");
        assert!(
            scan_text("tool.py", "result = eval(expr)\nprint(result)\n", Kind::Repo).is_empty(),
            "eval alone in Python"
        );
        assert_eq!(near_pair("eval(x) … atob(y)", EXEC, DECODE), Some(("eval(", "atob(")));
        assert_eq!(near_pair("eval(x)", EXEC, DECODE), None);
        let wide = format!("eval(x){}atob(y)", " ".repeat(NEAR_CHARS + 1));
        assert_eq!(near_pair(&wide, EXEC, DECODE), None, "just past the window");
        let multibyte = format!("é{}eval(x) atob(y)", "é".repeat(NEAR_CHARS));
        assert_eq!(
            near_pair(&multibyte, EXEC, DECODE),
            Some(("eval(", "atob(")),
            "the window lands on char boundaries"
        );
    }

    #[test]
    fn a_numeric_table_warns_alone_and_is_nothing_where_tables_live() {
        let decoded_only = format!("const p = {HEX_TABLE};\nconst s = String.fromCharCode(...p);\n");
        assert_eq!(
            ids(&scan_text("app.js", &decoded_only, Kind::Repo)),
            [("SUSPECT-ENCODED-PAYLOAD", false)],
            "decoded but never run: a warning"
        );
        let table = format!("const T = {HEX_TABLE};");
        let warn = scan_text("src/app.js", &table, Kind::Repo);
        assert_eq!(ids(&warn), [("SUSPECT-ENCODED-PAYLOAD", false)]);
        assert!(warn[0].note.ends_with("in a script, where a string would do"), "{}", warn[0].note);
        // The same table in a shader, a CRC file or a fixture is nothing.
        assert!(scan_text("kernels/crc.metal", &table, Kind::Repo).is_empty());
        assert!(scan_text("src/tables/crc32.js", &table, Kind::Repo).is_empty());
        assert!(scan_text("src/fonts/glyphs.js", &table, Kind::Repo).is_empty());
        assert!(scan_text("style.css", "a { color: #ff00aa; } b { color: #00ff00 }", Kind::Repo).is_empty());
        let decoded_eval = format!("const p = {HEX_TABLE};\neval(String.fromCharCode(...p));\n");
        assert!(
            scan_text("src/__tests__/payload.js", &decoded_eval, Kind::Repo)
                .iter()
                .any(|s| s.id == "SUSPECT-ENCODED-PAYLOAD" && !s.hard),
            "a payload in a test file warns even beside eval"
        );
    }

    #[test]
    fn numeric_arrays_are_counted_by_kind() {
        let dec: Vec<String> = (0..40).map(|i| (i % 256).to_string()).collect();
        let text = format!("x = [{}]", dec.join(", "));
        assert_eq!(numeric_array(&text), Some((40, 1, "byte")));
        let bin = format!("\n\ny = [{}]", vec!["0b1010"; 32].join(","));
        assert_eq!(numeric_array(&bin), Some((32, 3, "binary")), "the line is the array's own");
        let short = format!("x = [{}]", vec!["0x41"; MIN_ARRAY_ITEMS - 1].join(","));
        assert_eq!(numeric_array(&short), None, "one under the threshold");
        let mixed = format!("x = [{}]", ["0x41", "'a'"].repeat(20).join(","));
        assert_eq!(numeric_array(&mixed), None, "strings among the numbers: a list, not a payload");
        let wide = format!("x = [{}]", vec!["0x123456"; 32].join(","));
        assert_eq!(numeric_array(&wide), None, "literals too wide to be bytes or shorts");
        let big = format!("x = [{}]", vec!["1000"; 32].join(","));
        assert_eq!(numeric_array(&big), None, "decimals past a byte");
        let two = format!("a = [{}]; b = [{}]", vec!["1"; 32].join(","), vec!["2"; 33].join(","));
        assert_eq!(numeric_array(&two).map(|(n, _, _)| n), Some(33), "the longest wins");
        assert!(array_decoded("x = [1,2]\nchr(x[0])\n", 1));
        assert!(!array_decoded("x = [1,2]\nprint(x)\n", 1));
        let later = format!("x = [1,2]\n{}chr(x[0])\n", "\n".repeat(DECODER_LINES));
        assert!(!array_decoded(&later, 1), "a decoder too far below the array is not its decoder");
    }

    #[test]
    fn decoders_warn_alone_and_fail_beside_eval() {
        let dec = "function d(s){let o='';for(let i=0;i<s.length;i++){o+=String.fromCharCode(s.charCodeAt(i) ^ 42)}return o}\n";
        assert_eq!(ids(&scan_text("x.js", dec, Kind::Repo)), [("SUSPECT-STRING-DECODER", false)]);
        let dec_eval = format!("{dec}eval(d(\"zz\"))\n");
        let got = scan_text("x.js", &dec_eval, Kind::Repo);
        assert!(ids(&got).contains(&("SUSPECT-STRING-DECODER", true)), "{got:?}");
        let plain = "const codes = s.split('').map(c => c.charCodeAt(0));\nString.fromCharCode(...codes);\n";
        assert!(
            scan_text("x.js", plain, Kind::Repo).is_empty(),
            "codes without arithmetic: a conversion, not a decoder"
        );
        assert!(scan_text("x.py", "ord(c) ^ 42 and chr(x)", Kind::Repo).is_empty(), "the JavaScript tokens only");
    }

    #[test]
    fn escaped_source_warns_alone_and_fails_beside_eval() {
        let esc = format!("var s = \"{}\";\n", "\\x41".repeat(40));
        assert_eq!(ids(&scan_text("x.js", &esc, Kind::Repo)), [("SUSPECT-ESCAPED-SOURCE", false)]);
        assert!(scan_text("fixtures/x.js", &esc, Kind::Repo).is_empty(), "a fixture is where escapes live");
        assert!(scan_text("x.sh", &esc, Kind::Repo).is_empty(), "shell is not read for escapes");
        let short = format!("var s = \"{}\";\n", "\\x41".repeat(MIN_ESCAPE_RUN - 1));
        assert!(scan_text("x.js", &short, Kind::Repo).is_empty(), "one under the run threshold");
        let run_then_eval = format!("{esc}eval(s);\n");
        let got = scan_text("x.js", &run_then_eval, Kind::Repo);
        assert!(ids(&got).contains(&("SUSPECT-ESCAPED-SOURCE", true)), "{got:?}");
        assert!(ids(&got).contains(&("SUSPECT-EXEC-DECODED", true)), "`\\x` is itself a decode token: {got:?}");
        let (run, line) = longest_escape_run("a\n\\x41\\x42 \\u0041\\u0042\\u0043\n");
        assert_eq!((run, line), (5, 2), "a space between escapes doesn't break the run");
        assert_eq!(longest_escape_run("\\x4\\xzz\\u12"), (0, 0), "malformed escapes are not escapes");
        assert_eq!(longest_escape_run("\\x41\\n\\x42"), (1, 1), "a newline escape breaks the run");
    }

    #[test]
    fn table_paths() {
        assert!(table_path("src/codec/h264.js"));
        assert!(table_path("vendor/lib.min.js"));
        assert!(table_path("assets/emoji.ts"));
        assert!(!table_path("src/app.js"));
    }
}
