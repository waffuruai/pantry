//! Text addressed to an AI agent: an instruction that names an agent, wants
//! it to act, and is not quoted, in prose, markup or a comment.

use crate::checks::hidden::{ext_of, is_code, is_prose};

/// Files whose job is to instruct an agent: instructions there are the
/// point, not an injection.
pub(crate) fn addresses_agents(file: &str) -> bool {
    let l = format!("/{}", file.to_ascii_lowercase());
    let name = l.rsplit('/').next().unwrap_or("");
    [
        "claude.md",
        "agents.md",
        "gemini.md",
        ".cursorrules",
        ".windsurfrules",
        ".clinerules",
        "copilot-instructions.md",
        "skill.md",
    ]
    .contains(&name)
        || name.contains("prompt")
        || [
            "/.claude/",
            "/.cursor/",
            "/.agents/",
            "/.gemini/",
            "/.codex/",
            "/.windsurf/",
            "/.continue/",
            "/.clinerules/",
            "/.github/prompts/",
            "/prompts/",
            "/skills/",
        ]
        .iter()
        .any(|p| l.contains(p))
}

// --- Text addressed to an agent ------------------------------------------

type Group = &'static [&'static str];

/// A phrase is groups of alternatives in order, each within `gap` words of
/// the one before: "ignore … previous … instructions".
struct Phrase {
    groups: &'static [Group],
    gap: usize,
    what: &'static str,
}

const AGENTS: Group = &[
    "ai",
    "ais",
    "llm",
    "llms",
    "assistant",
    "assistants",
    "agent",
    "agents",
    "claude",
    "gpt",
    "chatgpt",
    "copilot",
    "gemini",
    "codex",
];

/// The verbs an injection wants done and the words that fetch, send or sign.
const WANTS: Group = &[
    "install",
    "download",
    "curl",
    "wget",
    "visit",
    "upload",
    "post",
    "email",
    "exfiltrate",
    "leak",
    "ignore",
    "disable",
    "approve",
    "sign",
    "transfer",
    "paste",
];

const MODALS: Group = &["must", "should", "shall", "always", "immediately", "now"];

const SENDS: Group = &["send", "upload", "post", "email", "exfiltrate", "leak", "transmit"];

const PHRASES: &[Phrase] = &[
    Phrase {
        groups: &[
            &["ignore", "disregard", "forget", "override"],
            &["previous", "prior", "above", "earlier", "preceding", "system", "original", "initial"],
            &[
                "instructions",
                "instruction",
                "prompt",
                "prompts",
                "rules",
                "guidelines",
                "directions",
                "guidance",
                "constraints",
                "safeguards",
                "restrictions",
            ],
        ],
        gap: 4,
        what: "an instruction to drop its instructions",
    },
    Phrase {
        groups: &[&["you", "you're", "youre"], &["are", "re"], &["a", "an", "the", "now"], AGENTS],
        gap: 1,
        what: "a role assignment to the agent",
    },
    Phrase {
        groups: &[
            &["important", "attention", "note", "notice", "instructions", "instruction", "message", "memo", "reminder"],
            &["for", "to"],
            &["ai", "ais", "llm", "llms", "assistants", "agents", "bots"],
        ],
        gap: 1,
        what: "a note addressed to AI agents",
    },
    // "agents must install …"; "run" and "execute" only with what they run:
    // docs say "the agent should run the tests" all day.
    Phrase { groups: &[AGENTS, MODALS, WANTS], gap: 3, what: "a command to AI agents" },
    Phrase {
        groups: &[
            AGENTS,
            MODALS,
            &["run", "execute", "eval", "source"],
            &[
                "curl",
                "wget",
                "sh",
                "bash",
                "zsh",
                "sudo",
                "npm",
                "npx",
                "pip",
                "pipx",
                "brew",
                "powershell",
                "http",
                "https",
                "chmod",
                "eval",
                "python",
                "node",
                "base64",
            ],
        ],
        gap: 4,
        what: "a command to AI agents",
    },
    Phrase {
        groups: &[
            &["do", "don't", "dont", "never", "not", "without"],
            &[
                "tell",
                "telling",
                "inform",
                "informing",
                "mention",
                "mentioning",
                "reveal",
                "revealing",
                "disclose",
                "disclosing",
                "notify",
                "notifying",
                "alert",
                "alerting",
            ],
            &["user", "users", "human", "humans", "owner"],
        ],
        gap: 3,
        what: "an instruction to hide something from the user",
    },
    Phrase {
        groups: &[
            SENDS,
            &["the", "your", "all", "any", "every", "user's", "users", "my", "this", "these"],
            &[
                "api", "access", "auth", "github", "npm", "aws", "secret", "private", "ssh", "env", "wallet", "seed",
                "session",
            ],
            &["key", "keys", "token", "tokens", "credentials", "file", "phrase", "cookie", "cookies", "variables"],
        ],
        gap: 2,
        what: "an instruction to send secrets somewhere",
    },
    Phrase {
        groups: &[SENDS, &["secrets", "credentials", "passwords", "keychain", "cookies", "wallet", "seed"]],
        gap: 2,
        what: "an instruction to send secrets somewhere",
    },
];

fn words(line: &str) -> Vec<String> {
    line.to_lowercase()
        .split(|c: char| !(c.is_alphanumeric() || c == '\''))
        .map(|w| w.trim_matches('\'').to_string())
        .filter(|w| !w.is_empty())
        .collect()
}

fn phrase_in(words: &[String], groups: &[Group], gap: usize) -> bool {
    'start: for (i, w) in words.iter().enumerate() {
        if !groups[0].contains(&w.as_str()) {
            continue;
        }
        let mut pos = i;
        for g in &groups[1..] {
            let hi = (pos + gap).min(words.len().saturating_sub(1));
            match (pos + 1..=hi).find(|&j| g.contains(&words[j].as_str())) {
                Some(j) => pos = j,
                None => continue 'start,
            }
        }
        return true;
    }
    false
}

/// What this text says to an agent, if anything.
pub fn agent_instruction(text: &str) -> Option<&'static str> {
    let w = words(text);
    if w.len() < 3 {
        return None;
    }
    PHRASES.iter().find(|p| phrase_in(&w, p.groups, p.gap)).map(|p| p.what)
}

/// The line without what it quotes: a README that says "the phrase
/// `ignore previous instructions`" mentions an injection, it isn't one.
pub(crate) fn unquoted(line: &str) -> String {
    let mut out = String::new();
    let mut quote: Option<char> = None;
    for c in line.chars() {
        match quote {
            Some(q) if c == q => quote = None,
            Some(_) => {}
            None if c == '`' || c == '"' => quote = Some(c),
            None => out.push(c),
        }
    }
    out
}

/// How a file is read for instructions to an agent.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum Mode {
    /// Every line; what is quoted is a mention.
    Prose,
    /// Comment lines only; what is quoted is a mention.
    Code,
    /// Every line, quotes included: a package description is a JSON string.
    Manifest,
}

/// Where instructions to an agent would be an injection: prose, package
/// and extension manifests, comment lines of code; not data files,
/// fixtures or the files meant for agents.
pub(crate) fn instructable(file: &str) -> Option<Mode> {
    if addresses_agents(file) {
        return None;
    }
    let l = format!("/{}", file.to_ascii_lowercase());
    if ["/fixtures/", "/fixture/", "/testdata/", "/corpus", "/journal/", "/evals/", "/eval/", "/__snapshots__/"]
        .iter()
        .any(|p| l.contains(p))
    {
        return None;
    }
    let name = l.rsplit('/').next().unwrap_or("");
    let manifest = [
        "package.json",
        "composer.json",
        "pyproject.toml",
        "cargo.toml",
        "setup.py",
        "setup.cfg",
        "manifest.json",
        "plugin.json",
        "extension.json",
        "mcp.json",
        "action.yml",
        "action.yaml",
        "pubspec.yaml",
        "cabal.project",
    ]
    .contains(&name)
        || name.ends_with(".gemspec")
        || name.ends_with(".podspec")
        || name.ends_with(".nuspec")
        || name.ends_with(".csproj");
    if manifest {
        Some(Mode::Manifest)
    } else if is_prose(file) || ["html", "htm", "xhtml", "svg"].contains(&ext_of(file).as_str()) {
        Some(Mode::Prose)
    } else if is_code(file) {
        Some(Mode::Code)
    } else {
        None
    }
}

fn comment_line(line: &str) -> bool {
    let t = line.trim_start();
    ["//", "#", "/*", "*", "--", "<!--", "\"\"\"", "'''", ";;", "%"].iter().any(|m| t.starts_with(m))
}

/// The first line that addresses an agent: (line, what, text). In code,
/// only comment lines count; a string that mentions "ignore previous
/// instructions" is a chatbot's test, not an injection.
pub(crate) fn first_agent_instruction(text: &str, mode: Mode) -> Option<(usize, &'static str, String)> {
    for (n, line) in text.lines().enumerate() {
        if mode == Mode::Code && !comment_line(line) {
            continue;
        }
        let visible = if mode == Mode::Manifest { line.to_string() } else { unquoted(line) };
        if let Some(what) = agent_instruction(&visible) {
            return Some((n + 1, what, line.trim().to_string()));
        }
    }
    None
}
