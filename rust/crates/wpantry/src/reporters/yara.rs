//! YARA: a rule as text. `rules gen` hands its draft here
//! ([`wpantry_yara::generate::Draft`]); the text is what a person reviews
//! and what the compiler must accept in strict mode.

use wpantry_yara::generate::{Draft, MetaValue};

/// A YARA text string literal for these bytes.
pub fn literal(bytes: &[u8]) -> String {
    let mut out = String::from("\"");
    for &b in bytes {
        match b {
            b'"' => out.push_str("\\\""),
            b'\\' => out.push_str("\\\\"),
            b'\t' => out.push_str("\\t"),
            0x20..=0x7E => out.push(b as char),
            _ => out.push_str(&format!("\\x{b:02X}")),
        }
    }
    out.push('"');
    out
}

/// The rule's text.
pub fn rule(d: &Draft) -> String {
    let mut t = format!("rule {}\n{{\n    meta:\n", d.name);
    for (k, v) in &d.meta {
        let v = match v {
            MetaValue::Text(s) => literal(s.as_bytes()),
            MetaValue::Int(n) => n.to_string(),
        };
        t.push_str(&format!("        {k} = {v}\n"));
    }
    t.push_str("\n    strings:\n");
    for (i, (bytes, wide)) in d.strings.iter().enumerate() {
        let modifier = if *wide { " wide" } else { "" };
        t.push_str(&format!("        $s{} = {}{modifier}\n", i + 1, literal(bytes)));
    }
    for (i, o) in d.opcodes.iter().enumerate() {
        let hex: Vec<String> = o.iter().map(|b| format!("{b:02X}")).collect();
        t.push_str(&format!("        $op{} = {{ {} }}\n", i + 1, hex.join(" ")));
    }
    t.push_str(&format!("\n    condition:\n        {}\n}}\n", d.condition));
    t
}

#[cfg(test)]
#[path = "yara_tests.rs"]
mod tests;
