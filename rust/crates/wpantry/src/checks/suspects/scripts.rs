//! Third-party scripts on a page: `<script src="https://…">` with no
//! `integrity=` hash means whoever controls that host controls the page.
//! It warns; over plain http it fails, and on a project that asks wallets
//! to sign it fails, because the script then decides what gets signed
//! (the supply-chain drainer pattern). One finding per page: the first
//! unpinned tag.

use super::{Suspect, line_at, push};

/// The ways a `src` points off the page.
const EXTERNAL: &[&str] = &["http://", "https://", "//"];

/// `<script src="https://…">` without `integrity=` on a page; plain http
/// always fails; without SRI it fails when the project signs transactions.
pub fn third_party_scripts(file: &str, text: &str, wallet_anywhere: bool) -> Vec<Suspect> {
    let mut out = Vec::new();
    let mut rest = text;
    let mut offset = 0;
    while let Some(i) = rest.find("<script") {
        let start = offset + i;
        let tag_end = rest[i..].find('>').map(|e| i + e).unwrap_or(rest.len());
        let tag = &rest[i..tag_end];
        if let Some(src) = attr(tag, "src")
            && EXTERNAL.iter().any(|p| src.starts_with(p))
            && !tag.contains("integrity=")
        {
            let host = EXTERNAL.iter().fold(src, |s, p| s.trim_start_matches(p)).split('/').next().unwrap_or("");
            let plain = src.starts_with("http://");
            push(
                &mut out,
                file,
                "SUSPECT-THIRD-PARTY-SCRIPT",
                line_at(text, start),
                format!(
                    "loads {host}'s script with no integrity hash{}{}: whoever controls that host controls this page",
                    if plain { ", over plain http" } else { "" },
                    if wallet_anywhere { ", on a project that asks wallets to sign" } else { "" }
                ),
                plain || wallet_anywhere,
            );
            break;
        }
        offset += tag_end;
        rest = &rest[tag_end..];
    }
    out
}

/// The value of `name=` in a tag, quoted or bare.
fn attr<'a>(tag: &'a str, name: &str) -> Option<&'a str> {
    let i = tag.find(&format!("{name}="))?;
    let v = &tag[i + name.len() + 1..];
    let q = v.chars().next()?;
    if q == '"' || q == '\'' { v[1..].split(q).next() } else { v.split([' ', '>', '/']).next() }
}

#[cfg(test)]
#[path = "scripts_tests.rs"]
mod tests;
