//! Where betterleaks' generic rules (`generic-*`) are noise, and what the
//! scan does about it. Provider rules read and report every file. On three
//! histories (2026-11-21) translations, bundles and docs held 87% of the
//! generic hits (37,556 of 43,003), and none of the provider ones were lost.
//!
//! The generic rules don't read ([`skips`]):
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
//! - **Commented-out examples:** `# DB_PASSWORD="secret"`, unless the value
//!   looks like a real password or a reference to one ([`commented_example`]).
//!
//! Where they read, the scan treats some files apart:
//!
//! - **Env and credential files** ([`secret_file`]): `.env`, `.npmrc`,
//!   `*.properties`, `secrets.yml`. Never skipped, and a generic hit there
//!   fails; a template (`.env.example`) asks for review.
//! - **Tests** ([`test`]): a generic hit there is one finding per repo and
//!   rule, naming every place.
//! - **Vendored code** ([`vendored`]): `vendor/`, `node_modules/`,
//!   `third_party/`. Someone else's demo values; reported with `--deep`.

/// Whether the generic rule `rule` doesn't read the file at `path`.
pub fn skips(rule: &str, path: &str) -> bool {
    if !rule.starts_with("generic-") || secret_file(path).is_some() {
        return false;
    }
    let path = path.to_ascii_lowercase();
    let (dirs, name) = split(&path);
    let ext = name.rsplit_once('.').map_or("", |(_, e)| e);
    let in_dir = |set: &[&str]| dirs.iter().any(|d| set.contains(d));
    translation(&dirs, name, ext) || built(name, ext) || DOC_EXTS.contains(&ext) || in_dir(DOC_DIRS)
}

/// A file whose job is to hold secrets: `Some(true)` for the real thing
/// (`.env`, `.npmrc`, `config/secrets.yml`), `Some(false)` for a template
/// of one (`.env.example`, `example.env`), None otherwise.
pub fn secret_file(path: &str) -> Option<bool> {
    let path = path.to_ascii_lowercase();
    let (_, whole) = split(&path);
    let parts: Vec<&str> = whole.split('.').filter(|p| !p.is_empty()).collect();
    // `database.yml.dist` is a template of `database.yml`.
    let name = match whole.rsplit_once('.') {
        Some((base, e)) if TEMPLATE_PARTS.contains(&e) && !base.is_empty() => base,
        _ => whole,
    };
    let (stem, ext) = match name.rsplit_once('.') {
        Some((s, e)) => (s.trim_start_matches('.'), e),
        None => (name, ""),
    };
    let env = name == ".env" || name == ".envrc" || name.starts_with(".env.") || name.ends_with(".env");
    let held = env
        || CREDENTIAL_FILES.contains(&name)
        || (ext == "properties" && !name.starts_with("messages"))
        || (SECRET_STEMS.contains(&stem) && CONFIG_EXTS.contains(&ext))
        || ext == "tfvars";
    held.then(|| !parts.iter().any(|p| TEMPLATE_PARTS.contains(p)))
}

/// A test: a folder or file name with `test`, `tests` or `testing` as a
/// word in it (`integration_test/`, `e2e-tests/`, `HttpClientTest.php`,
/// `index.test.ts`), an RSpec or Jasmine name (`x_spec.rb`, `x.spec.ts`,
/// `x.ut.rb`), or under `spec/`, `fixtures/`, `mocks/` and the like.
pub fn test(path: &str) -> bool {
    let (dirs, name) = split(path);
    let lower: Vec<String> = dirs.iter().map(|d| d.to_ascii_lowercase()).collect();
    let file: Vec<String> = words(name).collect();
    lower.iter().any(|d| TEST_DIRS.contains(&d.as_str()))
        || dirs.iter().chain([&name]).any(|part| words(part).any(|w| TEST_WORDS.contains(&w.as_str())))
        || (file.len() > 2 && file.iter().any(|w| w == "spec" || w == "ut"))
}

/// Under a folder of someone else's code: `vendor/`, `node_modules/`,
/// `third_party/`, a Ruby `gems/` tree, `site-packages/`, `Pods/`.
pub fn vendored(path: &str) -> bool {
    let path = path.to_ascii_lowercase();
    split(&path).0.iter().any(|d| VENDOR_DIRS.contains(d))
}

/// Whether a generic hit on `line` is a commented-out example: the line is
/// a comment, and `secret` looks neither like a real password (8 or more
/// characters of 3 kinds: lower, upper, digit, symbol) nor like a reference
/// to one (`$VAR`, `${VAR}`, `VAULT_PASSWORD`).
pub fn commented_example(line: &[u8], secret: &[u8]) -> bool {
    let text = String::from_utf8_lossy(line);
    let t = text.trim_start();
    if !COMMENTS.iter().any(|c| t.starts_with(c)) {
        return false;
    }
    let s = String::from_utf8_lossy(secret);
    let kinds = [
        s.bytes().any(|b| b.is_ascii_lowercase()),
        s.bytes().any(|b| b.is_ascii_uppercase()),
        s.bytes().any(|b| b.is_ascii_digit()),
        s.bytes().any(|b| !b.is_ascii_alphanumeric()),
    ];
    let real = s.len() >= 8 && kinds.iter().filter(|k| **k).count() >= 3;
    let reference = s.starts_with('$')
        || s.contains("${")
        || (s.len() >= 4
            && s.bytes().all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || b == b'_')
            && s.contains('_'));
    !real && !reference
}

/// A path's folders and file name.
fn split(path: &str) -> (Vec<&str>, &str) {
    match path.rsplit_once('/') {
        Some((d, n)) => (d.split('/').collect(), n),
        None => (Vec::new(), path),
    }
}

/// A name's words, lowercased: split at anything not a letter or digit,
/// and where a lowercase letter meets an uppercase one (`HttpClientTest`).
fn words(name: &str) -> impl Iterator<Item = String> + '_ {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut prev_lower = false;
    for c in name.chars() {
        if !c.is_ascii_alphanumeric() {
            out.push(std::mem::take(&mut cur));
            prev_lower = false;
            continue;
        }
        if c.is_ascii_uppercase() && prev_lower {
            out.push(std::mem::take(&mut cur));
        }
        prev_lower = c.is_ascii_lowercase() || c.is_ascii_digit();
        cur.push(c.to_ascii_lowercase());
    }
    out.push(cur);
    out.into_iter().filter(|w| !w.is_empty())
}

const TRANSLATION_DIRS: &[&str] =
    &["i18n", "l10n", "lang", "langs", "language", "languages", "locale", "locales", "translation", "translations"];
const TRANSLATION_EXTS: &[&str] = &["arb", "po", "pot", "xlf", "xliff", "strings", "stringsdict"];
const STYLE_EXTS: &[&str] = &["css", "scss", "sass", "less", "styl"];
const DOC_EXTS: &[&str] = &["md", "mdx", "markdown", "rst", "adoc", "asciidoc", "textile"];
const DOC_DIRS: &[&str] = &["doc", "docs", "documentation"];
const TEST_WORDS: &[&str] = &["test", "tests", "testing", "testdata"];
const TEST_DIRS: &[&str] = &["spec", "fixture", "fixtures", "__fixtures__", "mock", "mocks", "__mocks__", "e2e"];
const VENDOR_DIRS: &[&str] = &[
    "vendor",
    "vendors",
    "vendored",
    "third_party",
    "third-party",
    "thirdparty",
    "node_modules",
    "bower_components",
    "gems",
    "gemcache",
    "site-packages",
    "pods",
    "carthage",
];
const CREDENTIAL_FILES: &[&str] = &[
    ".npmrc",
    ".pypirc",
    ".netrc",
    "_netrc",
    ".pgpass",
    ".git-credentials",
    ".dockercfg",
    ".htpasswd",
    ".s3cfg",
    ".boto",
    "credentials",
];
const SECRET_STEMS: &[&str] = &["secret", "secrets", "credential", "credentials", "database"];
const CONFIG_EXTS: &[&str] = &["yml", "yaml", "json", "toml", "ini", "cfg", "conf", "xml"];
const TEMPLATE_PARTS: &[&str] = &["example", "examples", "sample", "template", "tmpl", "dist", "default", "stub"];
const COMMENTS: &[&str] = &["#", "//", "--", ";", "/*", "*", "<!--", "%", "rem ", "REM "];

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

#[cfg(test)]
#[path = "noise_tests.rs"]
mod tests;
