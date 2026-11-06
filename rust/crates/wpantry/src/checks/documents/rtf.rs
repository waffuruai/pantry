//! RTF: embedded objects are the vector (the equation editor,
//! CVE-2017-11882, came this way), and a malformed header is the evasion
//! that goes with it. The control words are read lowercased, up to the
//! member cap.

use super::{Doc, MAX_MEMBER, find, push};

pub(super) fn scan(file: &str, bytes: &[u8], out: &mut Vec<Doc>) {
    let lower: Vec<u8> = bytes.iter().take(MAX_MEMBER).map(|b| b.to_ascii_lowercase()).collect();
    if !lower.starts_with(b"{\\rtf1") {
        push(
            out,
            file,
            "DOC-OBFUSCATED",
            "a malformed RTF header (not `{\\rtf1`): Word accepts it, scanners that key on the header don't",
            true,
        );
    }
    let has = |s: &[u8]| find(&lower, s).is_some();
    if has(b"\\objupdate") || has(b"\\objautlink") || has(b"equation.3") || has(b"equation.2") {
        push(
            out,
            file,
            "DOC-RTF-OBJECT",
            "an embedded object set to update itself on open (or an Equation Editor object): the RTF exploit shape",
            true,
        );
    } else if has(b"\\objdata") || has(b"\\objemb") || has(b"\\objclass") {
        push(
            out,
            file,
            "DOC-RTF-OBJECT",
            "an embedded OLE object (\\objdata): another file or program packaged inside",
            true,
        );
    }
    if has(b"ddeauto") || has(b"\\fldinst") && has(b" dde ") {
        push(
            out,
            file,
            "DOC-DDE",
            "a DDE field: the document asks Office to run another program's command when it opens",
            true,
        );
    }
    if has(b"\\pict") && has(b"\\objdata") && has(b"\\bin") {
        push(
            out,
            file,
            "DOC-OBFUSCATED",
            "binary data spliced into the object stream (\\bin): a known parser-confusion trick",
            true,
        );
    }
}

#[cfg(test)]
#[path = "rtf_tests.rs"]
mod tests;
