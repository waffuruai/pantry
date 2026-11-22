//! Consequences read from the words of an advisory's own summary, such as
//! "remote code execution", with the negations that cancel them.

use super::GENERIC;
use super::weaknesses::weakness;

/// What a flaw that lets someone run code means, in one sentence.
const RUNS_CODE: &str = "Someone could use this flaw to run their own programs on this computer.";
/// What a flaw that only crashes or freezes a program means.
pub(super) const CRASHES: &str = "Someone could make this program crash or stop responding.";

/// Words in an advisory's summary, lower-cased, and the weakness or
/// consequence they mean, most serious first. Each phrase matches whole
/// words only, never when a negation sits next to it ("no code execution",
/// "does not crash", "code execution is not possible"). A group with
/// `near` words matches only when one of them is within a few words, so a
/// bare "bypass" (a cache bypass, a proxy bypass) claims nothing.
///
/// ```ignore
/// assert_eq!(keyword_sentence("Authentication bypass in login"), Some(...));
/// assert_eq!(keyword_sentence("Proxy bypass for local hosts"), None);
/// ```
const KEYWORDS: &[Group] = &[
    Group {
        words: &[
            "remote code execution",
            "arbitrary code execution",
            "code execution",
            "execute arbitrary code",
            "execute arbitrary commands",
            "execute arbitrary command",
            "execute arbitrary programs",
            "run arbitrary code",
            "arbitrary code",
        ],
        near: &[],
        meaning: Keyword::Text(RUNS_CODE),
    },
    Group {
        words: &["command injection"],
        near: &[],
        meaning: Keyword::Cwe(77),
    },
    Group {
        words: &[
            "sql injection",
            "execute arbitrary sql",
            "arbitrary sql",
            "execute arbitrary queries",
            "arbitrary queries",
        ],
        near: &[],
        meaning: Keyword::Cwe(89),
    },
    Group {
        words: &[
            "cross-site scripting",
            "xss",
            "execute arbitrary javascript",
            "arbitrary javascript",
            "execute arbitrary script",
            "arbitrary script",
            "arbitrary web script",
        ],
        near: &[],
        meaning: Keyword::Cwe(79),
    },
    Group {
        words: &["deserialization"],
        near: &[],
        meaning: Keyword::Cwe(502),
    },
    Group {
        words: &["use-after-free", "use after free"],
        near: &[],
        meaning: Keyword::Cwe(416),
    },
    Group {
        words: &["regular expression denial", "redos"],
        near: &[],
        meaning: Keyword::Cwe(1333),
    },
    Group {
        words: &[
            "denial of service",
            "denial-of-service",
            "stack overflow",
            "stack exhaustion",
            "crash",
            "crashes",
            "crashing",
            "infinite loop",
            "resource exhaustion",
        ],
        near: &[],
        meaning: Keyword::Text(CRASHES),
    },
    Group {
        words: &[
            "out-of-bounds write",
            "buffer overflow",
            "heap overflow",
            "heap-based buffer overflow",
            "stack-based buffer overflow",
        ],
        near: &[],
        meaning: Keyword::Cwe(787),
    },
    Group {
        words: &[
            "privilege escalation",
            "elevation of privilege",
            "escalate privileges",
            "escalation of privilege",
        ],
        near: &[],
        meaning: Keyword::Cwe(269),
    },
    Group {
        words: &["authentication bypass", "auth bypass"],
        near: &[],
        meaning: Keyword::Cwe(287),
    },
    Group {
        words: &["path traversal", "directory traversal"],
        near: &[],
        meaning: Keyword::Cwe(22),
    },
    Group {
        words: &["server-side request forgery", "ssrf"],
        near: &[],
        meaning: Keyword::Cwe(918),
    },
    Group {
        words: &["cross-site request forgery", "csrf"],
        near: &[],
        meaning: Keyword::Cwe(352),
    },
    Group {
        words: &["xml external entity", "xml external entities", "xxe"],
        near: &[],
        meaning: Keyword::Cwe(611),
    },
    Group {
        words: &["prototype pollution"],
        near: &[],
        meaning: Keyword::Cwe(1321),
    },
    Group {
        words: &["open redirect"],
        near: &[],
        meaning: Keyword::Cwe(601),
    },
    Group {
        words: &["out-of-bounds read"],
        near: &[],
        meaning: Keyword::Cwe(125),
    },
    Group {
        words: &["bypass", "bypasses", "bypassed", "bypassing"],
        near: &[
            "authentication",
            "authorization",
            "security",
            "sandbox",
            "restriction",
            "restrictions",
            "check",
            "checks",
            "protection",
            "protections",
            "signature",
            "verification",
            "permission",
            "permissions",
            "access control",
            "login",
        ],
        meaning: Keyword::Text("Someone could get around a security check in this program."),
    },
    Group {
        words: &[
            "information disclosure",
            "information leak",
            "information exposure",
            "sensitive information",
            "data leak",
        ],
        near: &[],
        meaning: Keyword::Cwe(200),
    },
    Group {
        words: &["spoofing", "spoof"],
        near: &[],
        meaning: Keyword::Text("Someone could pretend to be a trusted site, person or program."),
    },
];

/// One meaning and the summary phrases that name it.
struct Group {
    words: &'static [&'static str],
    /// When not empty, one of these must be within [`NEAR`] words.
    near: &'static [&'static str],
    meaning: Keyword,
}

#[derive(Clone, Copy)]
enum Keyword {
    Cwe(u32),
    Text(&'static str),
}

/// How many words either side `near` words and negations may sit.
const NEAR: usize = 4;
/// Words that, a few words before a phrase, say it does not happen ("no
/// code execution", "without authentication bypass").
const NEAR_NEGATIONS: &[&str] = &["no", "non", "without", "sandboxed"];
/// Words that deny what follows anywhere later in the same clause ("this
/// flaw cannot be used to execute arbitrary code"). Two of them cancel
/// out: "does not properly prevent SQL injection" and "fails to prevent
/// code execution" both still mean it can happen.
const CLAUSE_NEGATIONS: &[&str] = &[
    "not",
    "never",
    "cannot",
    "can't",
    "unable",
    "doesn't",
    "don't",
    "didn't",
    "isn't",
    "wasn't",
    "won't",
    "prevents",
    "prevent",
    "prevented",
];
/// "fail" words count as a negation only in "fails to prevent".
const FAIL_WORDS: &[&str] = &["fail", "fails", "failed"];
/// Words right after a phrase that say it does not happen ("code
/// execution is not possible").
const NEGATED_AFTER: &[&str] = &[
    "not possible",
    "impossible",
    "is not",
    "isn't",
    "was not",
    "wasn't",
    "is prevented",
    "not affected",
];
/// Words anywhere later in the same clause that take the phrase back:
/// "remote code execution was ruled out", "an RCE flaw now only permits
/// denial of service" (only what follows "only permits" is left).
const DENIED_LATER: &[&str] = &[
    "ruled out",
    "not exploitable",
    "no longer",
    "unlikely",
    "only permits",
    "only allows",
    "only causes",
];

/// A word character for phrase matching: ASCII letters and digits. An
/// apostrophe or hyphen inside a word ("can't", "use-after-free") is kept
/// by [`clause_words`].
fn word_char(c: char) -> bool {
    c.is_ascii_alphanumeric()
}

/// The words of `text`, lower-cased, without punctuation, each with where
/// the clause it sits in ends (a full stop, comma, semicolon or colon
/// separates clauses, so a negation in one clause never reaches the next).
fn clause_words(text: &str) -> Vec<(String, usize)> {
    let mut words = Vec::new();
    let mut clause = 0;
    let mut current = String::new();
    for c in text.chars().chain(std::iter::once(' ')) {
        if word_char(c) || ((c == '\'' || c == '-') && !current.is_empty()) {
            current.push(c.to_ascii_lowercase());
            continue;
        }
        if !current.is_empty() {
            let word = current.trim_end_matches(['\'', '-']).to_owned();
            words.push((word, clause));
            current.clear();
        }
        if matches!(c, '.' | ',' | ';' | ':' | '(' | ')' | '!' | '?') {
            clause += 1;
        }
    }
    words
}

/// True when the summary names `phrase` as whole words, in a clause that
/// does not deny it, and (when `near` is not empty) with one of the `near`
/// words close by.
fn mentions(words: &[(String, usize)], phrase: &str, near: &[&str]) -> bool {
    let wanted: Vec<&str> = phrase.split(' ').collect();
    let n = wanted.len();
    if words.len() < n {
        return false;
    }
    (0..=words.len() - n).any(|at| {
        let clause = words[at].1;
        let matched = wanted
            .iter()
            .enumerate()
            .all(|(i, w)| words[at + i].0 == *w && words[at + i].1 == clause);
        if !matched {
            return false;
        }
        let same = |i: &usize| words[*i].1 == clause;
        let before: Vec<&str> = (at.saturating_sub(NEAR)..at)
            .filter(same)
            .map(|i| words[i].0.as_str())
            .collect();
        let after: Vec<&str> = (at + n..(at + n + NEAR).min(words.len()))
            .filter(same)
            .map(|i| words[i].0.as_str())
            .collect();
        let after_text = after.join(" ");
        // Clause-wide: negations before the phrase, two cancelling out.
        let clause_before: Vec<&str> = (0..at).filter(same).map(|i| words[i].0.as_str()).collect();
        let negations = clause_before
            .iter()
            .enumerate()
            .filter(|(i, w)| {
                CLAUSE_NEGATIONS.contains(w)
                    || (FAIL_WORDS.contains(w)
                        && clause_before
                            .get(i + 2)
                            .is_some_and(|next| next.starts_with("prevent")))
            })
            .count();
        let clause_after = format!(
            " {} ",
            (at + n..words.len())
                .filter(same)
                .map(|i| words[i].0.as_str())
                .collect::<Vec<_>>()
                .join(" ")
        );
        let denied = before.iter().any(|w| NEAR_NEGATIONS.contains(w))
            || negations % 2 == 1
            || NEGATED_AFTER
                .iter()
                .any(|p| after_text == *p || after_text.starts_with(&format!("{p} ")))
            || DENIED_LATER
                .iter()
                .any(|p| clause_after.contains(&format!(" {p} ")));
        let close = near.is_empty() || {
            let around = format!("{} {}", before.join(" "), after_text);
            let around: Vec<&str> = around.split(' ').collect();
            near.iter().any(|w| {
                let parts: Vec<&str> = w.split(' ').collect();
                around.windows(parts.len()).any(|window| window == parts)
            })
        };
        !denied && close
    })
}

/// The consequence a summary's words name, or None.
pub fn keyword_sentence(summary: &str) -> Option<&'static str> {
    let words = clause_words(summary);
    KEYWORDS.iter().find_map(|group| {
        group
            .words
            .iter()
            .any(|w| mentions(&words, w, group.near))
            .then(|| match group.meaning {
                Keyword::Cwe(n) => weakness(n).map(|(_, _, s)| *s).unwrap_or(GENERIC),
                Keyword::Text(s) => s,
            })
    })
}

#[cfg(test)]
#[path = "keywords_tests.rs"]
mod tests;
