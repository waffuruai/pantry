//! Plain sentences for weakness types (CWE ids), and which of a finding's
//! weaknesses to explain when it lists several.

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

/// The number in a `CWE-787` id.
fn cwe_number(id: &str) -> Option<u32> {
    id.trim().strip_prefix("CWE-").and_then(|n| n.parse().ok())
}

pub(super) fn weakness(number: u32) -> Option<&'static (u32, &'static str, &'static str)> {
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
