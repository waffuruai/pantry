//! Sentences for Pantry's own checks, by finding kind or marker, and how to
//! tell an advisory, a malicious package and Pantry's own marker apart.

use crate::data::Finding;

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
pub(super) const INSTALL_SCRIPT: &str = "This package runs its own commands when it is installed, which is a common way for harmful packages to get in.";
/// A tool one of Pantry's checks needs is not there (the scanner's
/// `MISSING` marker: `brew vulns` without its formulae, `openssl` for the
/// trust stores).
pub(super) const MISSING_TOOL: &str = "A tool Pantry needs for one of its checks is not installed, so that check could not run. Installing it turns the check on.";
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
