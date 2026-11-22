//! Files betterleaks' generic rules (`generic-*`) don't read: there their
//! matches are words and demo values, not secrets. Provider rules still read
//! every file. On three histories (2026-11-21) these files held 87% of the
//! generic hits (37,556 of 43,003), and none of the provider ones were lost:
//!
//! - **Translations:** `password: Jelszó`, `"forgot_password": "Forgot
//!   Password"`. Files under `i18n/`, `l10n/`, `lang/`, `locales/`,
//!   `translations/` and the like, and `.arb`, `.po`, `.xliff`, `.strings`
//!   files and `messages*.properties`.
//! - **Built bundles and styles:** a webpack chunk holds the translations
//!   again; CSS holds `input[type="password"]`. Minified or content-hashed
//!   `.js` and `.css` (`app.6fb2ab18.js`), source maps, and stylesheets.
//! - **Docs:** `PASSWORD => admin123` in a module's walkthrough. Markdown,
//!   reStructuredText, AsciiDoc, and files under `docs/` or `documentation/`.
//! - **Tests, for `generic-password` only:** `password: 'password'` in a
//!   spec. Files under `test/`, `spec/`, `fixtures/`, `mocks/` and the like,
//!   and `test_*`, `*_test.*`, `*.spec.*`. A generic API key there is still
//!   read: a high-entropy value in a test script can be a live one.

/// Whether the generic rule `rule` doesn't read the file at `path`.
pub fn skips(rule: &str, path: &str) -> bool {
    if !rule.starts_with("generic-") {
        return false;
    }
    let path = path.to_ascii_lowercase();
    let (dirs, name) = match path.rsplit_once('/') {
        Some((d, n)) => (d.split('/').collect::<Vec<_>>(), n),
        None => (Vec::new(), path.as_str()),
    };
    let ext = name.rsplit_once('.').map_or("", |(_, e)| e);
    let in_dir = |set: &[&str]| dirs.iter().any(|d| set.contains(d));
    translation(&dirs, name, ext)
        || built(name, ext)
        || DOC_EXTS.contains(&ext)
        || in_dir(DOC_DIRS)
        || (rule == "generic-password" && (in_dir(TEST_DIRS) || test_name(name)))
}

const TRANSLATION_DIRS: &[&str] =
    &["i18n", "l10n", "lang", "langs", "language", "languages", "locale", "locales", "translation", "translations"];
const TRANSLATION_EXTS: &[&str] = &["arb", "po", "pot", "xlf", "xliff", "strings", "stringsdict"];
const STYLE_EXTS: &[&str] = &["css", "scss", "sass", "less", "styl"];
const DOC_EXTS: &[&str] = &["md", "mdx", "markdown", "rst", "adoc", "asciidoc", "textile"];
const DOC_DIRS: &[&str] = &["doc", "docs", "documentation"];
const TEST_DIRS: &[&str] = &[
    "test",
    "tests",
    "__tests__",
    "spec",
    "specs",
    "testdata",
    "test-data",
    "test_data",
    "fixture",
    "fixtures",
    "__fixtures__",
    "mock",
    "mocks",
    "__mocks__",
    "e2e",
];

fn translation(dirs: &[&str], name: &str, ext: &str) -> bool {
    dirs.iter().any(|d| TRANSLATION_DIRS.contains(d))
        || TRANSLATION_EXTS.contains(&ext)
        || (ext == "properties" && name.starts_with("messages"))
}

/// A stylesheet, a source map, or a minified or content-hashed script.
fn built(name: &str, ext: &str) -> bool {
    if STYLE_EXTS.contains(&ext) || ext == "map" {
        return true;
    }
    if !matches!(ext, "js" | "mjs" | "cjs") {
        return false;
    }
    let parts: Vec<&str> = name.split('.').collect();
    let middle = &parts[1..parts.len() - 1];
    middle.contains(&"min")
        || middle
            .iter()
            .any(|p| p.len() >= 8 && p.bytes().all(|b| b.is_ascii_hexdigit()) && p.bytes().any(|b| b.is_ascii_digit()))
}

/// `test_x.py`, `x_test.go`, `x.spec.ts`, `x-test.js`, `x_spec.rb`.
fn test_name(name: &str) -> bool {
    let stem = name.split_once('.').map_or(name, |(s, _)| s);
    let marked = |s: &str| ["test", "tests", "spec", "specs"].contains(&s);
    name.starts_with("test_")
        || stem.rsplit_once(['_', '-']).is_some_and(|(_, last)| marked(last))
        || name
            .split('.')
            .skip(1)
            .collect::<Vec<_>>()
            .split_last()
            .is_some_and(|(_, mid)| mid.iter().any(|m| marked(m)))
}

#[cfg(test)]
#[path = "noise_tests.rs"]
mod tests;
