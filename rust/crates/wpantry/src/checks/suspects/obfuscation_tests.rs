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
    assert!(got[0].note.contains("`eval` runs code built at run time with `fromCharCode.apply`"), "{}", got[0].note);
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
    assert_eq!(near_pair(&multibyte, EXEC, DECODE), Some(("eval(", "atob(")), "the window lands on char boundaries");
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
    let dec =
        "function d(s){let o='';for(let i=0;i<s.length;i++){o+=String.fromCharCode(s.charCodeAt(i) ^ 42)}return o}\n";
    assert_eq!(ids(&scan_text("x.js", dec, Kind::Repo)), [("SUSPECT-STRING-DECODER", false)]);
    let dec_eval = format!("{dec}eval(d(\"zz\"))\n");
    let got = scan_text("x.js", &dec_eval, Kind::Repo);
    assert!(ids(&got).contains(&("SUSPECT-STRING-DECODER", true)), "{got:?}");
    let plain = "const codes = s.split('').map(c => c.charCodeAt(0));\nString.fromCharCode(...codes);\n";
    assert!(scan_text("x.js", plain, Kind::Repo).is_empty(), "codes without arithmetic: a conversion, not a decoder");
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
