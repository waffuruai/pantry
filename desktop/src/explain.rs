//! What a finding means for a person who is not a security expert: one
//! plain sentence about what could happen, whether attackers are using it
//! now, and the public ids to look it up.
//!
//! The sentence comes from, in order:
//! 1. the advisory's weakness type (CWE id), from [`WEAKNESSES`];
//! 2. words in the advisory's own summary ([`KEYWORDS`]), such as "remote
//!    code execution";
//! 3. the finding's kind or marker, for Pantry's own checks ([`kind_sentence`]);
//! 4. a neutral sentence that claims nothing specific ([`GENERIC`]).
//!
//! Example:
//! ```ignore
//! let f = Finding { vuln_id: "CVE-2026-1".into(), cwe: vec!["CWE-787".into()], ..finding };
//! let e = explain(&f);
//! assert_eq!(e.source, Source::Cwe);
//! assert!(e.sentence.contains("run their own programs"));
//! ```

use crate::data::Finding;
use serde::Serialize;

/// Where a finding's plain sentence came from.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Source {
    Cwe,
    Keyword,
    Kind,
    Generic,
}

#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct Explanation {
    /// What could happen, in one plain sentence.
    pub sentence: String,
    pub source: Source,
}

/// The sentence when nothing more specific is known, for a flaw with a
/// released fix and for one without.
pub const GENERIC: &str = "This version has a publicly known security flaw. Updating removes it.";
pub const GENERIC_UNFIXED: &str =
    "This version has a publicly known security flaw. No fixed version has been released yet.";
/// For a finding that is not a public advisory and has no kind sentence.
pub const GENERIC_CHECK: &str = "Pantry found something here that is worth a look.";

/// Weakness types (CWE ids) with their short name and one honest sentence
/// about what an attacker could do. The most common ones in published
/// advisories; anything else falls back to the summary's words.
// TODO: grow this from the CWE ids seen in real scans, not by guesswork.
pub const WEAKNESSES: &[(u32, &str, &str)] = &[
    (
        787,
        "Out-of-bounds write",
        "A specially made file or message could corrupt this program's memory, which can crash it or let someone run their own programs on this computer.",
    ),
    (
        120,
        "Classic buffer overflow",
        "A specially made file or message could overflow a buffer in this program, which can crash it or let someone run their own programs on this computer.",
    ),
    (
        121,
        "Stack-based buffer overflow",
        "A specially made file or message could overflow a buffer in this program, which can crash it or let someone run their own programs on this computer.",
    ),
    (
        122,
        "Heap-based buffer overflow",
        "A specially made file or message could overflow a buffer in this program, which can crash it or let someone run their own programs on this computer.",
    ),
    (
        119,
        "Improper restriction of operations within the bounds of a memory buffer",
        "A specially made file or message could make this program misuse its memory, which can crash it or let someone run their own programs on this computer.",
    ),
    (
        416,
        "Use after free",
        "A specially made file or message could make this program reuse memory it already released, which can crash it or let someone run their own programs on this computer.",
    ),
    (
        125,
        "Out-of-bounds read",
        "A specially made file or message could make this program read memory it should not, which can crash it or reveal private data.",
    ),
    (
        94,
        "Code injection",
        "Someone could slip their own code into this program and have it run.",
    ),
    (
        77,
        "Command injection",
        "Someone could slip their own commands into this program and have this computer run them.",
    ),
    (
        78,
        "OS command injection",
        "Someone could trick this program into running system commands of their choosing on this computer.",
    ),
    (
        74,
        "Injection",
        "Someone could send text that this program mistakes for its own instructions.",
    ),
    (
        89,
        "SQL injection",
        "Someone could send text that tricks this program's database into showing, changing or deleting data.",
    ),
    (
        79,
        "Cross-site scripting",
        "A crafted link or page could run someone else's script while you use this program in a browser, which can expose your account or data.",
    ),
    (
        22,
        "Path traversal",
        "Someone could make this program read or write files outside the folders it is meant to use.",
    ),
    (
        59,
        "Link following",
        "Someone with access to this computer could use a shortcut file to make this program change a file it should not touch.",
    ),
    (
        502,
        "Deserialization of untrusted data",
        "Specially made data sent to this program could make it run someone else's code.",
    ),
    (
        287,
        "Improper authentication",
        "Someone could get in without proving who they are.",
    ),
    (
        290,
        "Authentication bypass by spoofing",
        "Someone could get in by pretending to be a trusted person or system.",
    ),
    (
        306,
        "Missing authentication for a critical function",
        "Someone could use an important feature without signing in.",
    ),
    (
        862,
        "Missing authorization",
        "Someone could do things they are not allowed to, because the program does not check their permission.",
    ),
    (
        863,
        "Incorrect authorization",
        "Someone could get past a permission check and do things they are not allowed to.",
    ),
    (
        284,
        "Improper access control",
        "Someone could reach parts of this program they should not be able to.",
    ),
    (
        285,
        "Improper authorization",
        "Someone could get past a permission check and do things they are not allowed to.",
    ),
    (
        269,
        "Improper privilege management",
        "A program or person with limited access could gain more control over this computer than they should have.",
    ),
    (
        732,
        "Incorrect permission assignment",
        "Files or settings this program creates can be read or changed by other people or programs on this computer.",
    ),
    (
        200,
        "Exposure of sensitive information",
        "Private information could be shown to someone who should not see it.",
    ),
    (
        532,
        "Sensitive information in log files",
        "Private information could end up in log files that other people or programs can read.",
    ),
    (
        918,
        "Server-side request forgery",
        "Someone could make this program send requests to other systems on your network on their behalf.",
    ),
    (
        352,
        "Cross-site request forgery",
        "A harmful website could make your browser take actions in this program without you meaning to.",
    ),
    (
        400,
        "Uncontrolled resource consumption",
        "Someone could overload this program so it slows down or stops working.",
    ),
    (
        770,
        "Allocation of resources without limits",
        "Someone could make this program use up memory or other resources until it slows down or stops working.",
    ),
    (
        674,
        "Uncontrolled recursion",
        "A specially made file or message could make this program crash.",
    ),
    (
        835,
        "Infinite loop",
        "A specially made file or message could make this program freeze.",
    ),
    (
        1333,
        "Inefficient regular expression",
        "A specially crafted piece of text could make this program work so hard it freezes.",
    ),
    (
        476,
        "NULL pointer dereference",
        "A specially made file or message could make this program crash.",
    ),
    (
        190,
        "Integer overflow",
        "A very large number in a file or message could make this program miscalculate, which can crash it or corrupt its memory.",
    ),
    (
        20,
        "Improper input validation",
        "This program does not check some input carefully, so a crafted file or message could make it misbehave.",
    ),
    (
        798,
        "Hard-coded credentials",
        "The program contains a built-in password or key that anyone who knows it could use.",
    ),
    (
        327,
        "Broken or risky cryptographic algorithm",
        "The program protects data with weak encryption that someone could break.",
    ),
    (
        295,
        "Improper certificate validation",
        "The program does not check secure connections properly, so someone on your network could read or change what it sends.",
    ),
    (
        347,
        "Improper verification of a cryptographic signature",
        "The program does not check signatures properly, so someone could pass off a forged file or token as genuine.",
    ),
    (
        362,
        "Race condition",
        "Two things happening at the same moment could make this program skip a safety check, which can crash it or give someone more access.",
    ),
    (
        601,
        "Open redirect",
        "A link that looks like it goes to this program could send you to a different site, such as a fake sign-in page.",
    ),
    (
        611,
        "XML external entity reference",
        "A crafted XML file could make this program read files from this computer or contact other systems.",
    ),
    (
        1321,
        "Prototype pollution",
        "Crafted input could change how this JavaScript program behaves, which can crash it or let someone get past its checks.",
    ),
    (
        434,
        "Unrestricted upload of a dangerous file",
        "Someone could upload a file that this program then runs, such as a script.",
    ),
    (
        444,
        "HTTP request smuggling",
        "Someone could hide a second request inside a normal one and get past this program's checks.",
    ),
    (
        113,
        "HTTP response splitting",
        "Someone could add their own content to this program's web responses.",
    ),
    (
        384,
        "Session fixation",
        "Someone could take over your signed-in session in this program.",
    ),
    (
        613,
        "Insufficient session expiration",
        "A signed-in session stays valid longer than it should, so a stolen one keeps working.",
    ),
];

/// What a flaw that lets someone run code means, in one sentence.
const RUNS_CODE: &str = "Someone could use this flaw to run their own programs on this computer.";
/// What a flaw that only crashes or freezes a program means.
const CRASHES: &str = "Someone could make this program crash or stop responding.";

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

/// The number in a `CWE-787` id.
fn cwe_number(id: &str) -> Option<u32> {
    id.trim().strip_prefix("CWE-").and_then(|n| n.parse().ok())
}

fn weakness(number: u32) -> Option<&'static (u32, &'static str, &'static str)> {
    WEAKNESSES.iter().find(|(n, _, _)| *n == number)
}

/// Broad weakness types that say little on their own; any more specific
/// one an advisory also lists explains it better.
const GENERIC_CWES: &[u32] = &[20, 74, 119, 284, 200];
/// Weakness types ranked by how much an attacker gains, the most serious
/// first. Ones in [`WEAKNESSES`] but not here come after these, in table
/// order, and the [`GENERIC_CWES`] come last.
const CWE_RANK: &[u32] = &[
    94, 77, 78, 502, 434, 787, 416, 120, 121, 122, 89, 79, 22, 611, 918, 287, 290, 306, 862, 863,
    285, 269, 352, 444, 1321, 190, 362, 125,
];

/// Sort key for a known weakness: lower is more serious or more specific.
fn cwe_rank(number: u32) -> usize {
    if let Some(at) = GENERIC_CWES.iter().position(|n| *n == number) {
        return 10_000 + at;
    }
    CWE_RANK
        .iter()
        .position(|n| *n == number)
        .unwrap_or_else(|| {
            1_000
                + WEAKNESSES
                    .iter()
                    .position(|(n, _, _)| *n == number)
                    .unwrap_or(0)
        })
}

/// The most serious known weakness among `ids`, such as `CWE-787` from
/// `[CWE-20, CWE-787]`; None when none is in [`WEAKNESSES`].
pub fn main_cwe(ids: &[String]) -> Option<u32> {
    ids.iter()
        .filter_map(|id| cwe_number(id))
        .filter(|n| weakness(*n).is_some())
        .min_by_key(|n| cwe_rank(*n))
}

/// The short name of a weakness type, such as "Out-of-bounds write" for
/// `CWE-787`; None for one not in [`WEAKNESSES`].
pub fn cwe_name(id: &str) -> Option<&'static str> {
    weakness(cwe_number(id)?).map(|(_, name, _)| *name)
}

/// The sentence for one weakness type, or None for one not in the table.
#[cfg(test)]
pub fn cwe_sentence(id: &str) -> Option<&'static str> {
    weakness(cwe_number(id)?).map(|(_, _, sentence)| *sentence)
}

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

/// True for a known harmful package or extension, as the scanner reports
/// one: an OpenSSF malicious-package id (`MAL-2026-1`), an advisory with
/// a `MAL-` alias (a GHSA for a malware report), or Pantry's `MALICIOUS`
/// marker (a marketplace extension pulled for malware). The scanner turns
/// its severity into `CRITICAL`, so the severity word alone is not enough.
pub fn is_malicious(f: &Finding) -> bool {
    f.kind != "unchecked"
        && (f.vuln_id.starts_with("MAL-")
            || f.vuln_id == "MALICIOUS"
            || f.severity.eq_ignore_ascii_case("malicious")
            || f.aliases.iter().any(|a| a.starts_with("MAL-")))
}

/// Id prefixes Pantry's own checks use, which look like advisory ids but
/// are not (`SUSPECT-RAW-IP`, `IMG-2-SCRIPTS`).
const OWN_PREFIXES: &[&str] = &[
    "SUSPECT",
    "HIDDEN",
    "DOC",
    "IMG",
    "CLIPPER",
    "PERSISTENCE",
    "IOC",
    "POSTURE",
    "CONFUSABLE",
    "MAL",
];

/// True when an id has the shape of a published advisory: `CVE-2026-1`,
/// `GHSA-…` (any case), `RUSTSEC-2021-0003`, `DEMO-2026-0001`, and OSV's
/// distribution ids such as `DEBIAN-CVE-2024-1` or `CURL-CVE-2023-38545`:
/// an upper-case prefix, then a part that starts with a digit.
pub fn advisory_shaped(id: &str) -> bool {
    if id.len() > 6 && id[..5].eq_ignore_ascii_case("GHSA-") {
        return true;
    }
    let mut parts = id.split('-');
    let Some(prefix) = parts.next() else {
        return false;
    };
    prefix.len() >= 2
        && prefix.bytes().all(|b| b.is_ascii_uppercase())
        && !OWN_PREFIXES.contains(&prefix)
        && parts.any(|part| part.bytes().next().is_some_and(|b| b.is_ascii_digit()))
}

/// True when the finding's id names a published advisory (see
/// [`advisory_shaped`]), not one of Pantry's own markers (`EOL`,
/// `SUSPECT-RAW-IP`) or a known harmful package. A finding with weakness
/// types or aliases is one too, whatever its id: the scanner fills those
/// only from an advisory record.
pub fn is_advisory(f: &Finding) -> bool {
    if f.kind == "unchecked" || is_malicious(f) {
        return false;
    }
    !f.cwe.is_empty() || !f.aliases.is_empty() || advisory_shaped(&f.vuln_id)
}

/// A package that runs commands as it installs (an npm `postinstall`).
const INSTALL_SCRIPT: &str = "This package runs its own commands when it is installed, which is a common way for harmful packages to get in.";
/// A tool one of Pantry's checks needs is not there (the scanner's
/// `MISSING` marker: `brew vulns` without its formulae, `openssl` for the
/// trust stores).
const MISSING_TOOL: &str = "A tool Pantry needs for one of its checks is not installed, so that check could not run. Installing it turns the check on.";
/// A known harmful package or extension.
pub const MALICIOUS: &str = "It was published to cause harm, for example to steal passwords, keys or files from the computers it is installed on. Updating it does not help: remove it, then change any passwords or keys this computer holds.";

/// Pantry's own checks and markers, each in one sentence.
pub fn kind_sentence(f: &Finding) -> Option<&'static str> {
    if is_malicious(f) {
        return Some(MALICIOUS);
    }
    let id = f.vuln_id.as_str();
    let by_marker = match id {
        "EOL" => Some(
            "This version no longer gets security fixes from its maker, so flaws found in it from now on will stay open.",
        ),
        "OUTDATED" => Some("A newer release is out. Older releases can miss security fixes."),
        "BROWSER" => Some(
            "This browser is behind its latest release, and browser updates usually carry security fixes.",
        ),
        "OS-UPDATE" => Some(
            "The operating system has updates waiting to be installed, and they can include security fixes.",
        ),
        "DISTRUSTED-CA" => Some(
            "This computer trusts a certificate authority that browsers no longer trust, so a fake secure site could look real.",
        ),
        "UNPINNED" => Some(
            "This is not fixed to one version, so a future update could change what runs without you noticing.",
        ),
        "DEPRECATED" => {
            Some("Its maker no longer supports it, so problems found in it may never be fixed.")
        }
        "LICENSE" => Some(
            "Its license may not allow how you use it. This is a legal risk, not a security flaw.",
        ),
        "INSTALL-SCRIPT" | "NPM-SCRIPTS" | "INSTALL-HOOK" => Some(INSTALL_SCRIPT),
        "OPEN-HOOK" => Some(
            "This project runs its own commands when it is opened, which could run code you did not review.",
        ),
        "MISSING" => Some(MISSING_TOOL),
        "BREACH" => Some(
            "This account appears in a known data breach, so its password may be known to others.",
        ),
        "MALWARE" => Some(
            "This matches known harmful software, which can steal data or damage this computer.",
        ),
        "IGNORE-FILE" | "IGNORE-PROTECTED" => {
            Some("A file in this project asks Pantry to skip some of its checks.")
        }
        "REPO-POLICY" => Some(
            "This project's settings make it easier for secrets to leak or for unreviewed code to get in.",
        ),
        "DISGUISED-PROGRAM" => Some("This file looks like a document but is really a program."),
        "AGENT-INSTRUCTIONS" | "AI-BAIT" | "HIDDEN-PROMPT" => Some(
            "This file has instructions aimed at AI tools, which could make an assistant do something you did not ask for.",
        ),
        "EXFIL-LINK" => {
            Some("This file has a link built to send data from this computer somewhere else.")
        }
        "DANGEROUS-URI" => {
            Some("This file has a link that can open or run something on this computer.")
        }
        _ => None,
    };
    let by_prefix = || {
        let pairs: &[(&str, &str)] = &[
            (
                "SUSPECT-",
                "This code does things harmful software often does, such as hiding what it runs. It may be fine, but it is worth a look.",
            ),
            (
                "HIDDEN-",
                "This file contains characters or text people can't see, but programs and AI tools will read.",
            ),
            (
                "CONFUSABLE-",
                "This name looks like a well-known one but is spelled with look-alike letters, a common trick.",
            ),
            (
                "DOC-",
                "This document contains active content, such as macros or scripts, that can run when it is opened.",
            ),
            (
                "IMG-",
                "This image file contains something an image should not, such as a script or hidden data.",
            ),
            (
                "PERSISTENCE-",
                "A program is set to start on its own. Check that you recognise it.",
            ),
            (
                "CLIPPER-",
                "Something on this computer may be swapping copied wallet addresses, so money you send could go to someone else.",
            ),
            (
                "POSTURE-",
                "A built-in protection on this computer is turned off or weaker than it should be.",
            ),
        ];
        pairs
            .iter()
            .find(|(prefix, _)| id.starts_with(prefix))
            .map(|(_, s)| *s)
    };
    let by_kind = || match f.kind.as_str() {
        "secret" => Some(
            "A password or key is saved in a file. Anyone who can read the file can use it to act as you.",
        ),
        "malware" => Some(
            "This matches known harmful software, which can steal data or damage this computer.",
        ),
        "suspect-code" => Some(
            "This code does things harmful software often does, such as hiding what it runs. It may be fine, but it is worth a look.",
        ),
        "hidden-text" => Some(
            "This file contains characters or text people can't see, but programs and AI tools will read.",
        ),
        "document" => Some(
            "This document contains active content, such as macros or scripts, that can run when it is opened.",
        ),
        "clipper" => Some(
            "Something on this computer may be swapping copied wallet addresses, so money you send could go to someone else.",
        ),
        "persistence" => Some("A program is set to start on its own. Check that you recognise it."),
        "posture" | "config" => {
            Some("A security setting on this computer is weaker than recommended.")
        }
        "repo-hook" => Some(
            "This project runs its own commands during everyday git actions, which could run code you did not review.",
        ),
        "install-script" => Some(INSTALL_SCRIPT),
        "license" => Some(
            "Its license may not allow how you use it. This is a legal risk, not a security flaw.",
        ),
        "account" => Some(
            "This account appears in a known data breach, so its password may be known to others.",
        ),
        "mcp" => Some(
            "An AI tool server here is set up in a way that could let it change without you noticing.",
        ),
        _ => None,
    };
    by_marker.or_else(by_prefix).or_else(by_kind)
}

/// The lead sentence for one of Pantry's own checks (not an advisory),
/// naming `name`: what Pantry found, from the marker or the kind. None when
/// neither is known; the caller then quotes the scanner's own note.
///
/// ```ignore
/// own_lead(&eol, "node") == Some("node no longer gets security fixes from its maker.")
/// ```
pub fn own_lead(f: &Finding, name: &str) -> Option<String> {
    if is_malicious(f) {
        let what = if f.kind == "extension" {
            "extension"
        } else {
            "package"
        };
        return Some(format!("{name} is a known harmful {what}. Remove it."));
    }
    let id = f.vuln_id.as_str();
    let by_marker = match id {
        "EOL" => Some(format!(
            "{name} no longer gets security fixes from its maker."
        )),
        "OUTDATED" => Some(format!("{name} is out of date.")),
        "BROWSER" => Some(format!("{name} is behind its latest release.")),
        "OS-UPDATE" => Some(format!("{name} has updates waiting to be installed.")),
        "DISTRUSTED-CA" => Some(format!(
            "{name} trusts a certificate authority that browsers no longer trust."
        )),
        "UNPINNED" => Some(format!("{name} is not fixed to one version.")),
        "DEPRECATED" => Some(format!("{name} is no longer supported by its maker.")),
        "LICENSE" => Some(format!(
            "{name} has a license that may not allow how you use it."
        )),
        "MISSING" => Some(format!(
            "{name} is not installed, so one of Pantry's checks could not run."
        )),
        "BREACH" => Some(format!("{name} appears in a known data breach.")),
        "INSTALL-SCRIPT" | "NPM-SCRIPTS" | "INSTALL-HOOK" => Some(format!(
            "{name} runs its own commands when it is installed."
        )),
        "OPEN-HOOK" => Some(format!("{name} runs its own commands when it is opened.")),
        _ => None,
    };
    if by_marker.is_some() {
        return by_marker;
    }
    let pairs: &[(&str, &str)] = &[
        ("CLIPPER-", "may be swapping copied wallet addresses"),
        ("CONFUSABLE-", "has a name that imitates a well-known one"),
    ];
    if let Some((_, what)) = pairs.iter().find(|(prefix, _)| id.starts_with(prefix)) {
        return Some(format!("{name} {what}."));
    }
    match f.kind.as_str() {
        "mcp" => Some(format!(
            "{name} is an AI tool server that could change without you noticing."
        )),
        "repo-hook" => Some(format!(
            "{name} runs its own commands during everyday project actions."
        )),
        "account" => Some(format!("{name} appears in a known data breach.")),
        "clipper" => Some(format!("{name} may be swapping copied wallet addresses.")),
        _ => None,
    }
}

/// What a finding means, and where that sentence came from.
pub fn explain(f: &Finding) -> Explanation {
    let made = |sentence: &str, source| Explanation {
        sentence: sentence.to_owned(),
        source,
    };
    if f.kind == "unchecked" {
        return made(
            if f.excluded {
                "You chose to skip this area, so Pantry did not look here."
            } else {
                "Pantry could not finish this check, so it does not know whether there is a problem here."
            },
            Source::Kind,
        );
    }
    if is_advisory(f) {
        if let Some((_, _, sentence)) = main_cwe(&f.cwe).and_then(weakness) {
            return made(sentence, Source::Cwe);
        }
        let words = if f.summary.trim().is_empty() {
            &f.note
        } else {
            &f.summary
        };
        if let Some(sentence) = keyword_sentence(words) {
            return made(sentence, Source::Keyword);
        }
        return made(
            if f.fixed.is_empty() {
                GENERIC_UNFIXED
            } else {
                GENERIC
            },
            Source::Generic,
        );
    }
    match kind_sentence(f) {
        Some(sentence) => made(sentence, Source::Kind),
        None => made(GENERIC_CHECK, Source::Generic),
    }
}

pub const EXPLOITED: &str = "Attackers are using this in real attacks right now.";
pub const NOT_LISTED: &str = "It is not on the public list of flaws known to be used in attacks.";
pub const KEV_UNKNOWN: &str = "Pantry could not check whether attackers are using this.";

/// Whether attackers are using it now (CISA KEV), in plain words.
/// `kev_checked` is whether the scan that found it read the KEV list: a
/// scan that could not leaves `kev` false for every finding, which says
/// nothing. None for Pantry's own checks and for known harmful packages
/// (their lead sentence already says to remove them).
///
/// ```ignore
/// assert_eq!(attacks(&cve, false), Some(KEV_UNKNOWN));
/// assert_eq!(attacks(&eol_marker, true), None);
/// ```
pub fn attacks(f: &Finding, kev_checked: bool) -> Option<&'static str> {
    if f.kind == "unchecked" || is_malicious(f) {
        None
    } else if f.kev {
        Some(EXPLOITED)
    } else if !is_advisory(f) {
        None
    } else if kev_checked {
        Some(NOT_LISTED)
    } else {
        Some(KEV_UNKNOWN)
    }
}

/// One public id for the finding, and where to read about it.
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct Identifier {
    pub id: String,
    pub url: Option<String>,
}

/// An id safe to show and to put in a link: letters, digits and `-_.:`.
fn plain_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 64
        && id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-_.:".contains(&b))
}

/// Where to read an advisory: cve.org for CVE ids, GitHub's advisory
/// database for GHSA ids, osv.dev for the rest. None for demo and test
/// ids, which no database holds.
///
/// ```ignore
/// assert_eq!(advisory_url("CVE-2021-25900").unwrap(), "https://www.cve.org/CVERecord?id=CVE-2021-25900");
/// ```
pub fn advisory_url(id: &str) -> Option<String> {
    if !plain_id(id) || id.starts_with("DEMO-") || id.starts_with("TEST-") {
        return None;
    }
    Some(if id.starts_with("CVE-") {
        format!("https://www.cve.org/CVERecord?id={id}")
    } else if id.starts_with("GHSA-") {
        format!("https://github.com/advisories/{id}")
    } else {
        format!("https://osv.dev/vulnerability/{id}")
    })
}

/// The finding's public ids, CVE ids first, then its own id (when it is an
/// advisory or an OpenSSF malicious-package report, `MAL-2026-1`) and its
/// other aliases, each once.
pub fn identifiers(f: &Finding) -> Vec<Identifier> {
    let mut ids: Vec<&str> = Vec::new();
    if is_advisory(f) || (f.kind != "unchecked" && f.vuln_id.starts_with("MAL-")) {
        ids.push(&f.vuln_id);
    }
    let mut aliases: Vec<&str> = f.aliases.iter().map(String::as_str).collect();
    aliases.sort_by_key(|a| !a.starts_with("CVE-"));
    for alias in aliases {
        if !ids.contains(&alias) {
            ids.push(alias);
        }
    }
    // CVE ids lead: they are the ones people search for.
    ids.sort_by_key(|id| !id.starts_with("CVE-"));
    ids.into_iter()
        .filter(|id| plain_id(id))
        .map(|id| Identifier {
            id: id.to_owned(),
            url: advisory_url(id),
        })
        .collect()
}

/// The label for [`epss_text`] in the technical details.
pub const EPSS_LABEL: &str = "Estimated chance attackers will try this in the next 30 days";

/// EPSS as a person reads it, for [`EPSS_LABEL`]: "about 3 in 100 (EPSS)".
/// EPSS estimates attempts against flaws like this one anywhere, not the
/// chance that this computer is attacked, so it never says "you".
pub fn epss_text(epss: f64) -> String {
    let n = (epss.clamp(0.0, 1.0) * 100.0).round() as i64;
    if n < 1 {
        "less than 1 in 100 (EPSS)".into()
    } else {
        format!("about {n} in 100 (EPSS)")
    }
}

/// The consequence for a home row, when one is known: the weakness or
/// summary sentence, never the neutral one.
pub fn short_consequence(f: &Finding) -> Option<String> {
    let e = explain(f);
    matches!(e.source, Source::Cwe | Source::Keyword).then_some(e.sentence)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn advisory(cwe: &[&str], summary: &str) -> Finding {
        serde_json::from_value(serde_json::json!({
            "kind": "project", "component": "demo", "version": "1.0", "location": "",
            "vuln_id": "CVE-2026-12345", "status": "fail", "note": "", "fixed": "1.1",
            "severity": "HIGH", "kev": false, "fix_cmd": "",
            "summary": summary, "cwe": cwe,
        }))
        .unwrap()
    }

    #[test]
    fn every_weakness_in_the_table_gives_its_sentence() {
        for (number, name, sentence) in WEAKNESSES {
            let id = format!("CWE-{number}");
            let e = explain(&advisory(&[&id], ""));
            assert_eq!(
                (e.sentence.as_str(), e.source),
                (*sentence, Source::Cwe),
                "{id}"
            );
            assert_eq!(cwe_name(&id), Some(*name));
            assert!(!sentence.contains('—'), "{id}: no em-dashes");
        }
        // The ones the brief names are all there.
        for n in [
            787, 125, 119, 416, 94, 77, 78, 89, 79, 22, 502, 287, 862, 863, 306, 269, 200, 918,
            352, 400, 770, 190, 20, 798, 327, 295, 362, 601, 611, 1321, 434, 476, 1333,
        ] {
            assert!(weakness(n).is_some(), "CWE-{n} missing");
        }
    }

    #[test]
    fn a_known_weakness_never_falls_back_to_the_generic_sentence() {
        // Known bad: the generic sentence for a finding whose CWE is known.
        let e = explain(&advisory(&["CWE-79"], ""));
        assert_ne!(e.sentence, GENERIC);
        assert_eq!(e.source, Source::Cwe);
        // The first known one wins over an unknown one listed first.
        let e = explain(&advisory(&["CWE-99999", "CWE-89"], ""));
        assert_eq!(e.sentence, cwe_sentence("CWE-89").unwrap());
    }

    #[test]
    fn an_unknown_weakness_falls_back_to_the_summary_then_the_neutral_sentence() {
        let e = explain(&advisory(
            &["CWE-99999"],
            "Remote code execution in the parser",
        ));
        assert_eq!(e.source, Source::Keyword);
        assert!(e.sentence.contains("run their own programs"));
        let e = explain(&advisory(&["CWE-99999"], "A bug in the parser"));
        assert_eq!((e.sentence.as_str(), e.source), (GENERIC, Source::Generic));
        // Empty everything: neutral, nothing invented.
        let e = explain(&advisory(&[], ""));
        assert_eq!((e.sentence.as_str(), e.source), (GENERIC, Source::Generic));
        let mut unfixed = advisory(&[], "");
        unfixed.fixed.clear();
        assert_eq!(explain(&unfixed).sentence, GENERIC_UNFIXED);
    }

    #[test]
    fn summary_words_map_to_their_consequence() {
        let cases = [
            (
                "Denial of service via crafted header",
                "crash or stop responding",
            ),
            ("Information disclosure in logs", "Private information"),
            ("Local privilege escalation", "more control"),
            ("Certificate spoofing", "pretend to be"),
            ("Signature check bypass", "get around a security check"),
            ("Stored XSS in comments", "someone else's script"),
        ];
        for (summary, expected) in cases {
            let e = explain(&advisory(&[], summary));
            assert_eq!(e.source, Source::Keyword, "{summary}");
            assert!(e.sentence.contains(expected), "{summary}: {}", e.sentence);
        }
        // Whole words: "xss" inside another word is not cross-site scripting.
        assert_eq!(keyword_sentence("the axssy module"), None);
    }

    #[test]
    fn every_kind_explains_itself() {
        let make = |kind: &str, id: &str| -> Finding {
            serde_json::from_value(serde_json::json!({
                "kind": kind, "component": "x", "version": "", "location": "",
                "vuln_id": id, "status": "warn", "note": "", "fixed": "",
                "severity": "", "kev": false, "fix_cmd": "",
            }))
            .unwrap()
        };
        for (kind, id) in [
            ("secret", "aws-access-token"),
            ("runtime", "EOL"),
            ("tool", "OUTDATED"),
            ("malware", "MALWARE"),
            ("posture", "POSTURE-SIP"),
            ("suspect-code", "SUSPECT-RAW-IP"),
            ("hidden-text", "HIDDEN-BIDI"),
            ("document", "DOC-MACRO"),
            ("persistence", "PERSISTENCE-NEW"),
            ("clipper", "CLIPPER-PERSISTENCE"),
            ("browser", "BROWSER"),
            ("os", "OS-UPDATE"),
            ("license", "LICENSE"),
            ("install-script", "INSTALL-SCRIPT"),
            ("repo-hook", "core.hooksPath"),
            ("account", "BREACH"),
            ("config", "IGNORE-PROTECTED"),
            ("mcp", "UNPINNED"),
            ("extension", "DEPRECATED"),
            ("unchecked", "UNCHECKED"),
        ] {
            let e = explain(&make(kind, id));
            assert_eq!(e.source, Source::Kind, "{kind} {id}");
            assert_ne!(e.sentence, GENERIC_CHECK);
        }
        // An unknown kind with no marker: the neutral sentence.
        let e = explain(&make("queue", "SOMETHING"));
        assert_eq!(
            (e.sentence.as_str(), e.source),
            (GENERIC_CHECK, Source::Generic)
        );
    }

    #[test]
    fn ids_link_to_their_database() {
        assert_eq!(
            advisory_url("CVE-2021-25900").unwrap(),
            "https://www.cve.org/CVERecord?id=CVE-2021-25900"
        );
        assert_eq!(
            advisory_url("GHSA-43w2-9j62-hq99").unwrap(),
            "https://github.com/advisories/GHSA-43w2-9j62-hq99"
        );
        assert_eq!(
            advisory_url("RUSTSEC-2021-0003").unwrap(),
            "https://osv.dev/vulnerability/RUSTSEC-2021-0003"
        );
        assert_eq!(advisory_url("DEMO-2026-0001"), None);
        assert_eq!(advisory_url("x?y=<script>"), None);
        let mut f = advisory(&[], "");
        f.aliases = vec![
            "GHSA-aaaa-bbbb-cccc".into(),
            "CVE-2026-12345".into(),
            "bad id".into(),
        ];
        let ids: Vec<String> = identifiers(&f).into_iter().map(|i| i.id).collect();
        assert_eq!(ids, ["CVE-2026-12345", "GHSA-aaaa-bbbb-cccc"]);
    }

    /// Oracle: EPSS is an estimate of attempts, so the words never say
    /// this computer will be attacked, and the label does not repeat it.
    #[test]
    fn epss_reads_as_a_chance_out_of_100() {
        assert_eq!(epss_text(0.0213), "about 2 in 100 (EPSS)");
        assert_eq!(epss_text(0.001), "less than 1 in 100 (EPSS)");
        assert!(epss_text(0.97).starts_with("about 97 in 100"));
        for text in [epss_text(0.5), EPSS_LABEL.to_owned()] {
            assert!(!text.contains("being attacked"), "{text}");
        }
    }

    /// Oracle: the KEV line claims only what the scan read. Known bad:
    /// "It is not on the public list" for a scan that never read the list,
    /// and any KEV line on Pantry's own markers.
    #[test]
    fn attacks_say_whether_kev_lists_it() {
        let mut f = advisory(&[], "");
        assert_eq!(attacks(&f, true), Some(NOT_LISTED));
        assert_eq!(attacks(&f, false), Some(KEV_UNKNOWN));
        f.kev = true;
        assert_eq!(attacks(&f, true), Some(EXPLOITED));
        assert_eq!(attacks(&f, false), Some(EXPLOITED));
        for id in ["EOL", "OUTDATED", "MISSING", "UNPINNED", "BREACH"] {
            let marker = own("tool", id);
            assert_eq!(attacks(&marker, true), None, "{id}");
            assert_eq!(attacks(&marker, false), None, "{id}");
        }
        let mut unchecked = own("unchecked", "");
        unchecked.cwe = vec!["CWE-787".into()];
        assert_eq!(attacks(&unchecked, true), None);
        assert_eq!(attacks(&malicious("MAL-2026-1", &[]), true), None);
    }

    fn own(kind: &str, id: &str) -> Finding {
        serde_json::from_value(serde_json::json!({
            "kind": kind, "component": "x", "version": "", "location": "",
            "vuln_id": id, "status": "warn", "note": "", "fixed": "",
            "severity": "", "kev": false, "fix_cmd": "",
        }))
        .unwrap()
    }

    /// A malicious-package finding as the scanner emits it: `CRITICAL`
    /// (its severity step turns MALICIOUS into CRITICAL), `kev` true.
    fn malicious(id: &str, aliases: &[&str]) -> Finding {
        serde_json::from_value(serde_json::json!({
            "kind": "project", "component": "evil-pkg", "version": "1.0", "location": "",
            "vuln_id": id, "status": "fail", "note": "Malicious code in evil-pkg (npm)",
            "fixed": "", "severity": "CRITICAL", "kev": true, "fix_cmd": "npm uninstall evil-pkg",
            "summary": "Malicious code in evil-pkg (npm)", "aliases": aliases,
        }))
        .unwrap()
    }

    /// Oracle: CWE precedence picks the most serious, most specific
    /// weakness, whatever order the advisory lists them in.
    #[test]
    fn the_most_serious_known_weakness_wins() {
        let out_of_bounds = "A specially made file or message could corrupt this program's memory, which can crash it or let someone run their own programs on this computer.";
        for list in [
            &["CWE-20", "CWE-787"][..],
            &["CWE-787", "CWE-20"],
            &["CWE-119", "CWE-787"],
            &["CWE-200", "CWE-99999", "CWE-787"],
        ] {
            let e = explain(&advisory(list, ""));
            assert_eq!(e.sentence, out_of_bounds, "{list:?}");
        }
        // Code injection outranks a crash; SQL injection outranks input
        // validation.
        assert_eq!(
            explain(&advisory(&["CWE-476", "CWE-94"], "")).sentence,
            "Someone could slip their own code into this program and have it run."
        );
        assert_eq!(
            explain(&advisory(&["CWE-20", "CWE-89"], "")).sentence,
            "Someone could send text that tricks this program's database into showing, changing or deleting data."
        );
        assert_eq!(main_cwe(&["CWE-284".into(), "CWE-862".into()]), Some(862));
        assert_eq!(main_cwe(&["CWE-1".into()]), None);
    }

    /// Oracle: a flaw that only crashes or freezes a program never says
    /// anyone can run anything (literal expectations, not the table).
    #[test]
    fn crash_only_weaknesses_never_say_run() {
        let expected = [
            (
                476,
                "A specially made file or message could make this program crash.",
            ),
            (
                674,
                "A specially made file or message could make this program crash.",
            ),
            (
                835,
                "A specially made file or message could make this program freeze.",
            ),
            (
                1333,
                "A specially crafted piece of text could make this program work so hard it freezes.",
            ),
            (
                400,
                "Someone could overload this program so it slows down or stops working.",
            ),
            (
                770,
                "Someone could make this program use up memory or other resources until it slows down or stops working.",
            ),
        ];
        for (n, sentence) in expected {
            let e = explain(&advisory(&[&format!("CWE-{n}")], ""));
            assert_eq!(e.sentence, sentence, "CWE-{n}");
            assert!(!e.sentence.contains("run"), "CWE-{n}: {}", e.sentence);
        }
        assert_eq!(keyword_sentence("Stack overflow in parser"), Some(CRASHES));
        assert_eq!(
            keyword_sentence("Denial of service via stack overflow"),
            Some(CRASHES),
            "denial of service is a crash, not memory corruption"
        );
    }

    /// Oracle: one case per keyword phrase, each giving its group's
    /// sentence; and the known-bad cases (negations, other words, a phrase
    /// inside or at the start of a longer word) giving nothing.
    /// Oracle: a malicious-package report's own MAL id is listed and links
    /// to osv.dev, as a MAL alias does. Known-bad: the primary MAL id was
    /// dropped, leaving no id at all.
    #[test]
    fn a_primary_mal_id_is_listed() {
        let f: Finding = serde_json::from_value(serde_json::json!({
            "kind": "malware", "component": "evil-pkg", "version": "1.0", "location": "",
            "vuln_id": "MAL-2026-1234", "status": "fail", "note": "", "fixed": "",
            "severity": "CRITICAL", "kev": false, "fix_cmd": "",
        }))
        .unwrap();
        assert_eq!(
            identifiers(&f),
            vec![Identifier {
                id: "MAL-2026-1234".into(),
                url: Some("https://osv.dev/vulnerability/MAL-2026-1234".into()),
            }]
        );
    }

    #[test]
    fn every_keyword_phrase_maps_and_negations_do_not() {
        for group in KEYWORDS {
            let expected = match group.meaning {
                Keyword::Cwe(n) => weakness(n).unwrap().2,
                Keyword::Text(s) => s,
            };
            for phrase in group.words {
                let summary = match group.near.first() {
                    Some(near) => format!("A {near} {phrase} in the parser"),
                    None => format!("A {phrase} in the parser"),
                };
                // An earlier, more serious group may claim a phrase that
                // contains its words; the first group that matches wins.
                let first = KEYWORDS
                    .iter()
                    .position(|g| {
                        g.words
                            .iter()
                            .any(|w| mentions(&clause_words(&summary), w, g.near))
                    })
                    .unwrap();
                let got = keyword_sentence(&summary);
                assert!(got.is_some(), "{summary}");
                if std::ptr::eq(&KEYWORDS[first], group) {
                    assert_eq!(got, Some(expected), "{summary}");
                }
            }
        }
        for summary in [
            "Remote code execution is not possible",
            "This does not crash the server",
            "No code execution, only a warning",
            "Sandboxed code execution in the plugin host",
            "Cache bypass for static files",
            "Proxy bypass list ignored",
            "the axssy module",
            "crashpad reporter update",
            "bypassable typo fixed",
            "Spoofed? No. Spoofingly named variable",
            "Not a denial of service",
            "This flaw cannot be used to execute arbitrary code",
            "This flaw can't be used to execute arbitrary code",
            "Code execution is not exploitable in default setups",
            "Remote code execution no longer applies after 2.0",
            "Remote code execution is unlikely",
            "Attackers are unable to inject SQL",
        ] {
            assert_eq!(keyword_sentence(summary), None, "{summary}");
        }
        // Taken back later in the clause, or only a lesser outcome is left.
        let runs = weakness(94).map(|w| w.2);
        for summary in [
            "Remote code execution was ruled out; a memory leak slows the server",
            "Incomplete fix for a remote code execution flaw now only permits denial of service",
            "An RCE-class remote code execution bug only allows a crash",
        ] {
            let got = keyword_sentence(summary);
            assert!(got != Some(RUNS_CODE) && got != runs, "{summary}: {got:?}");
        }
        assert_eq!(
            keyword_sentence(
                "Incomplete fix for a remote code execution flaw now only permits denial of service"
            ),
            Some(CRASHES)
        );
        // Two negations cancel: it can still happen.
        for summary in [
            "Fails to prevent code execution when loading a crafted file",
            "Does not properly prevent remote code execution",
        ] {
            assert_eq!(keyword_sentence(summary), Some(RUNS_CODE), "{summary}");
        }
        // A negation of something else nearby does not deny it.
        assert_eq!(
            keyword_sentence("No authentication is required to execute arbitrary code"),
            Some(RUNS_CODE)
        );
        // SQL and browser scripts are not programs run on this computer.
        assert_eq!(
            keyword_sentence("Allows attackers to execute arbitrary SQL commands"),
            weakness(89).map(|w| w.2)
        );
        assert_eq!(
            keyword_sentence("Lets a page execute arbitrary JavaScript in the browser"),
            weakness(79).map(|w| w.2)
        );
        assert_eq!(
            keyword_sentence("Allows execution of arbitrary queries"),
            weakness(89).map(|w| w.2)
        );
        // A bypass with a security word close by is one.
        assert!(
            keyword_sentence("Allows a bypass of the sandbox")
                .is_some_and(|s| s.contains("get around"))
        );
        // A negation in another clause does not cancel this one.
        assert_eq!(
            keyword_sentence("Not reachable by default; remote code execution when enabled"),
            Some(RUNS_CODE)
        );
    }

    /// Oracle: known harmful packages, as the scanner builds them (a MAL-
    /// id, or a GHSA with a MAL- alias, severity CRITICAL, kev true), get
    /// the malware sentence and are never advisories.
    #[test]
    fn malicious_packages_get_the_malware_sentence() {
        for f in [
            malicious("MAL-2026-1", &[]),
            malicious("GHSA-aaaa-bbbb-cccc", &["MAL-2026-2"]),
            {
                let mut f = own("extension", "MALICIOUS");
                f.severity = "CRITICAL".into();
                f
            },
        ] {
            assert!(is_malicious(&f), "{}", f.vuln_id);
            assert!(!is_advisory(&f), "{}", f.vuln_id);
            let e = explain(&f);
            assert_eq!((e.sentence.as_str(), e.source), (MALICIOUS, Source::Kind));
            let lead = own_lead(&f, "evil-pkg").unwrap();
            assert!(
                lead.contains("known harmful") && lead.ends_with("Remove it."),
                "{lead}"
            );
            assert!(!lead.contains("worth a look"));
        }
        // A plain GHSA is not malicious.
        assert!(!is_malicious(&advisory(&[], "")));
    }

    /// Oracle: OSV's id shapes are advisories, Pantry's markers are not;
    /// an id with only aliases or only weakness types is an advisory.
    #[test]
    fn advisory_ids_are_recognised_by_shape() {
        for id in [
            "CVE-2026-1",
            "GHSA-43w2-9j62-hq99",
            "ghsa-43w2-9j62-hq99",
            "RUSTSEC-2021-0003",
            "DEBIAN-CVE-2024-1234",
            "CURL-CVE-2023-38545",
            "PYSEC-2024-1",
            "DEMO-2026-0001",
        ] {
            assert!(advisory_shaped(id), "{id}");
            assert!(
                advisory_url(id).is_some() || id.starts_with("DEMO-"),
                "{id}"
            );
        }
        assert_eq!(
            advisory_url("DEBIAN-CVE-2024-1234").unwrap(),
            "https://osv.dev/vulnerability/DEBIAN-CVE-2024-1234"
        );
        assert!(
            advisory_url("ghsa-43w2-9j62-hq99")
                .unwrap()
                .starts_with("https://osv.dev/")
        );
        for id in [
            "EOL",
            "OS-UPDATE",
            "SUSPECT-RAW-IP",
            "IMG-2-SCRIPT",
            "POSTURE-SIP",
            "INSTALL-HOOK",
            "CLIPPER-EXTENSION",
            "MAL-2026-1",
            "",
        ] {
            assert!(!advisory_shaped(id), "{id}");
        }
        let mut aliases_only = own("project", "SOMETHING");
        aliases_only.aliases = vec!["CVE-2026-1".into()];
        assert!(is_advisory(&aliases_only));
        let mut cwe_only = own("project", "SOMETHING");
        cwe_only.cwe = vec!["CWE-79".into()];
        assert!(is_advisory(&cwe_only));
        assert!(!is_advisory(&own("project", "SOMETHING")));
    }

    /// Oracle: an id that is not plain (a slash, a space, over 64
    /// characters) is never shown as an identifier or turned into a link.
    #[test]
    fn unsafe_ids_give_no_identifier_and_no_url() {
        let long = format!("CVE-2026-{}", "1".repeat(60));
        for id in ["CVE-2026-1/../x", "GHSA-a/b", long.as_str()] {
            assert_eq!(advisory_url(id), None, "{id}");
            let mut f = advisory(&[], "");
            f.vuln_id = id.into();
            f.aliases = vec![id.into()];
            assert!(identifiers(&f).is_empty(), "{id}: {:?}", identifiers(&f));
        }
        let ok = format!("CVE-2026-{}", "1".repeat(55));
        assert_eq!(ok.len(), 64);
        assert!(advisory_url(&ok).is_some());
    }

    /// Oracle: the two kinds of unchecked area read differently, and
    /// neither claims a problem.
    #[test]
    fn excluded_and_unfinished_unchecked_areas_differ() {
        let mut skipped = own("unchecked", "");
        skipped.excluded = true;
        let unfinished = own("unchecked", "");
        assert_eq!(
            explain(&skipped).sentence,
            "You chose to skip this area, so Pantry did not look here."
        );
        assert_eq!(
            explain(&unfinished).sentence,
            "Pantry could not finish this check, so it does not know whether there is a problem here."
        );
    }

    /// Oracle: Pantry's own markers lead with what Pantry found, never the
    /// advisory words "security hole" or "no fix released".
    #[test]
    fn own_markers_lead_with_their_own_sentence() {
        for (kind, id, expected) in [
            ("mcp", "UNPINNED", "x is not fixed to one version."),
            (
                "runtime",
                "EOL",
                "x no longer gets security fixes from its maker.",
            ),
            (
                "tool",
                "MISSING",
                "x is not installed, so one of Pantry's checks could not run.",
            ),
            ("account", "BREACH", "x appears in a known data breach."),
            (
                "clipper",
                "CLIPPER-EXTENSION",
                "x may be swapping copied wallet addresses.",
            ),
            ("tool", "OUTDATED", "x is out of date."),
            (
                "repo-hook",
                "INSTALL-HOOK",
                "x runs its own commands when it is installed.",
            ),
        ] {
            let f = own(kind, id);
            assert_eq!(own_lead(&f, "x").as_deref(), Some(expected), "{kind} {id}");
            assert!(!is_advisory(&f));
        }
        assert_eq!(
            kind_sentence(&own("repo-hook", "INSTALL-HOOK")),
            Some(INSTALL_SCRIPT)
        );
        assert_eq!(kind_sentence(&own("tool", "MISSING")), Some(MISSING_TOOL));
    }
}
