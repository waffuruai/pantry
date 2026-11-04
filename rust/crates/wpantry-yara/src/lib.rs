//! wpantry-yara: a YARA rule engine in safe Rust with no dependencies.
//!
//! It reads YARA 4.x rules ([`Syntax::Relaxed`], for rules fetched from
//! others) and yara-x's stricter dialect ([`Syntax::Strict`], for our own),
//! compiles them once, and scans bytes with them:
//!
//! ```
//! use wpantry_yara::{Compiler, Syntax};
//! let mut c = Compiler::new();
//! assert_eq!(c.add_source("demo", r#"rule hello { strings: $a = "hello" condition: $a }"#, Syntax::Strict), 1);
//! let rules = c.build();
//! let hits = rules.scan(b"say hello", &Default::default());
//! assert_eq!(hits.matches[0].rule, "hello");
//! ```
//!
//! How it is fast without a JIT: every string is reduced to an atom of up to
//! four bytes, all atoms go in one table probed once per input position
//! through a 16-Mbit prefilter ([`atoms`]); only atom hits are verified, and
//! only rules with a verified string (or whose condition needs none) are
//! evaluated. Conditions are compiled once to closures ([`compile`]). Rules
//! that need a PE, ELF or Mach-O file are skipped on other files.

mod ast;
pub mod atoms;
pub mod classify;
pub mod compile;
pub mod generate;
mod lexer;
pub mod matcher;
pub mod modules;
mod parser;
pub mod pattern;
pub mod scan;
pub mod strings;
pub mod value;

pub use classify::Os;
pub use compile::{Compiler, Rejected, Rules};
pub use pattern::Syntax;
pub use scan::{Hit, ScanOptions, ScanResult};
pub use value::Value;

/// Why a rules file or rule didn't compile.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Error {
    /// The text isn't valid rule syntax.
    Syntax { line: usize, msg: String },
    /// The rule is well formed but uses something this engine doesn't
    /// provide or that doesn't type-check (an unknown module field, a string
    /// that isn't defined).
    Semantic { line: usize, msg: String },
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::Syntax { line, msg } => write!(f, "line {line}: {msg}"),
            Error::Semantic { line, msg } => write!(f, "line {line}: {msg}"),
        }
    }
}

impl std::error::Error for Error {}
