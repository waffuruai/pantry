//! An info-stealer prompt aimed at an AI assistant: text that tells a model
//! to build a profile of a person from data collected about them and to
//! rank what they own so it can be monetized. It is a cleverer cousin of
//! the AI-bait and injected-instruction checks in `hidden.rs`: not "ignore
//! your instructions", but a complete, plausible analyst brief whose job is
//! to turn a victim's scattered data into a target dossier and a shopping
//! list of their valuables.
//!
//! No single phrase is damning, so the rule fires only where several
//! distinct families co-occur in one text block: a role or a sole-source
//! "evidence bundle" framing, verbs and fields that mine a person's
//! identity (emails, domains, search history, a school LMS, an employer,
//! hobbies, saved passwords), and an explicit monetization or valuables
//! ranking (crypto, gift cards, Roblox and game accounts, saved cards,
//! "what they're worth", value tiers). An ordinary OSINT note or a
//! marketing deck trips none of them together.
//!
//! It fails in prompt and agent files (`.md`, `.mdc`, `.cursorrules`, MCP
//! and agent configs, `AGENTS`/`CLAUDE` files) and in installed code, where
//! such a prompt is loaded and obeyed; elsewhere it warns. Tests and
//! fixtures never fail.

use super::{Context, Kind, Suspect, line_of, push, test_path};

/// A role or analyst framing that sets the model up as a profiler.
const ROLE: &[&str] = &[
    "forensic intelligence analyst",
    "intelligence analyst",
    "target assessment",
    "target dossier",
    "threat analyst",
    "your training knowledge",
    "must never supply a fact",
    "you are a forensic",
    "you are an osint",
    "you are a profiler",
    "drafting a target",
];
/// The "only permissible source" / structured-evidence constraint that
/// turns collected data into the single ground truth the model works from.
const BUNDLE: &[&str] = &[
    "evidence bundle",
    "only permissible source",
    "permissible source of facts",
    "only source of facts",
    "the bundle is the only",
    "cite the bundle",
    "structured evidence",
    "if the bundle is silent",
];
/// Fields a person's identity is mined from (counted: two or more).
const MINE: &[&str] = &[
    "search history",
    "browser history",
    "school lms",
    "lms domain",
    ".edu email",
    "employer",
    "hobbies",
    "autofill",
    "saved password",
    "wifi password",
    "receipt",
    "who they are",
    "what they do",
    "subject's",
    "emails",
    "domains",
];
/// An explicit valuables ranking: either a strong phrase, or two of the
/// weaker tokens together.
const MONEY_STRONG: &[&str] = &[
    "rank their assets",
    "assets for monetization",
    "valuables ranked",
    "what they're worth",
    "what theyre worth",
    "what they are worth",
    "value tier",
    "account values",
];
const MONEY: &[&str] =
    &["monetiz", "crypto", "gift card", "roblox", "saved card", "game account", "valuables", "account value"];

/// Contexts this rule reads: prose and agent files, config/data files (MCP
/// and agent JSON), page and script sources that might embed a prompt.
fn reads(ctx: Context) -> bool {
    matches!(ctx, Context::Prompt | Context::Data | Context::Web | Context::Python | Context::Markup)
}

pub(super) fn scan(file: &str, text: &str, ctx: Context, kind: Kind, out: &mut Vec<Suspect>) {
    if !reads(ctx) {
        return;
    }
    let lower = text.to_ascii_lowercase();
    let framed = ROLE.iter().any(|k| lower.contains(k)) || BUNDLE.iter().any(|k| lower.contains(k));
    let mine = MINE.iter().filter(|k| lower.contains(*k)).count();
    let money =
        MONEY_STRONG.iter().any(|k| lower.contains(k)) || MONEY.iter().filter(|k| lower.contains(*k)).count() >= 2;
    if !(framed && mine >= 2 && money) {
        return;
    }
    let anchor =
        MONEY_STRONG.iter().chain(BUNDLE.iter()).chain(MINE.iter()).find(|k| lower.contains(*k)).copied().unwrap_or("");
    push(
        out,
        file,
        "SUSPECT-PROFILING-PROMPT",
        line_of(&lower, anchor),
        "instructs an AI assistant to profile a person and rank their assets for monetization (info-stealer prompt)",
        (kind == Kind::Installed || prompt_target(file)) && !test_path(file),
    );
}

/// A file whose job is to be loaded as a prompt or agent instruction: a
/// prompt there is obeyed, so it fails rather than warns.
fn prompt_target(file: &str) -> bool {
    let l = format!("/{}", file.to_ascii_lowercase());
    let name = l.rsplit('/').next().unwrap_or("");
    let ext = name.rsplit_once('.').map(|(_, e)| e).unwrap_or("");
    if ["md", "mdc", "markdown", "mdx", "rst"].contains(&ext) {
        return true;
    }
    if [".cursorrules", ".windsurfrules", ".clinerules", "mcp.json", ".mcp.json", "copilot-instructions.md"]
        .contains(&name)
        || name.contains("prompt")
    {
        return true;
    }
    [
        "/.claude/",
        "/.cursor/",
        "/.agents/",
        "/.gemini/",
        "/.codex/",
        "/.windsurf/",
        "/.continue/",
        "/.github/prompts/",
        "/prompts/",
        "/skills/",
        "/.mcp/",
    ]
    .iter()
    .any(|p| l.contains(p))
}

#[cfg(test)]
#[path = "profiling_tests.rs"]
mod tests;
