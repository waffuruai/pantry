//! Cardholder data in the clear: a primary account number (PAN) written
//! into source, a `.env`, a JSON/CSV/log file or a fixture, and code that
//! collects card fields and ships them somewhere. PCI DSS forbids storing a
//! PAN unencrypted and forbids keeping the card verification value (CVV) at
//! all; wpantry flags both so they don't reach a repo, a log or a request.
//!
//! A real-looking PAN is one that passes the Luhn check and matches a known
//! issuer shape (Visa, Mastercard, Amex, Discover), separators tolerated.
//! The published test numbers (the `4111 1111 1111 1111` family, `4242…`)
//! and anything under a test/fixture path are named but never failed. A
//! lone PAN warns; a PAN beside a CVV or card field, or in a file that also
//! sends data, fails. Separately, code that gathers card fields (`cvv`,
//! `card_number`, `pan`, …) and sends them off fails on its own.

use super::credentials::SENDS;
use super::{Context, Suspect, line_at, line_of, push, test_path};

pub(super) const ID: &str = "SUSPECT-CARDHOLDER-DATA";

/// A PAN is 13–19 digits.
const MIN_PAN: usize = 13;
const MAX_PAN: usize = 19;
/// At most this much of a file is scanned for card numbers.
const MAX_SCAN: usize = 512 << 10;
/// The published test PANs, which are named but never failed.
const TEST_PANS: &[&str] = &[
    "4111111111111111",
    "4012888888881881",
    "4222222222222",
    "4242424242424242",
    "4000056655665556",
    "5555555555554444",
    "5105105105105100",
    "2223003122003222",
    "378282246310005",
    "371449635398431",
    "6011111111111117",
    "6011000990139424",
];
/// Field names that mark cardholder data, as identifier tokens.
const CARD_FIELDS: &[&str] = &[
    "card_number",
    "cardnumber",
    "cardnum",
    "pan",
    "cvv",
    "cvv2",
    "cvc",
    "cardcvc",
    "cardcvv",
    "securitycode",
    "card_security_code",
    "expiry",
    "exp_month",
    "exp_year",
    "card_exp",
];

fn reads(ctx: Context) -> bool {
    matches!(ctx, Context::Data | Context::Web | Context::Python | Context::Shell | Context::Manifest)
}

pub(super) fn scan(file: &str, text: &str, ctx: Context, out: &mut Vec<Suspect>) {
    if !reads(ctx) {
        return;
    }
    let is_test = test_path(file);
    let fields = has_card_field(text);
    let sends = SENDS.iter().any(|s| text.contains(s));
    let scanned = if text.len() > MAX_SCAN { &text[..MAX_SCAN] } else { text };

    if let Some((digits, at)) = find_pan(scanned) {
        let test_number = TEST_PANS.contains(&digits.as_str());
        let brand = issuer(&digits).unwrap_or("card");
        let note = if test_number {
            format!("a test {brand} number ({})", masked(&digits))
        } else if fields || sends {
            format!(
                "a {brand} number in the clear ({}){}: PCI DSS forbids storing a PAN unencrypted",
                masked(&digits),
                if fields { ", beside a card field" } else { ", in a file that sends data" }
            )
        } else {
            format!("a {brand} number in the clear ({}): PCI DSS forbids storing a PAN unencrypted", masked(&digits))
        };
        push(out, file, ID, line_at(text, at), note, !is_test && !test_number && (fields || sends));
        return;
    }

    // No PAN, but a file that both collects card fields and sends them off.
    if fields && sends {
        let field = CARD_FIELDS.iter().find(|f| token_present(text, f)).copied().unwrap_or("card fields");
        push(
            out,
            file,
            ID,
            line_of(&text.to_ascii_lowercase(), field),
            format!("collects card fields (`{field}`) and sends them off: cardholder data in PCI DSS scope"),
            !is_test,
        );
    }
}

/// A short, non-reversible marker for the finding's note: issuer, length
/// and the last four, never the whole number.
fn masked(d: &str) -> String {
    let last4 = &d[d.len().saturating_sub(4)..];
    format!("{} digits, ending {last4}", d.len())
}

fn has_card_field(text: &str) -> bool {
    CARD_FIELDS.iter().any(|f| token_present(text, f))
}

/// Whether `needle` appears as a whole identifier token (letters, digits
/// and `_`), not inside a longer word like `panel` or `expand`.
fn token_present(text: &str, needle: &str) -> bool {
    let lower = text.to_ascii_lowercase();
    let mut from = 0;
    while let Some(i) = lower[from..].find(needle) {
        let at = from + i;
        let before = at == 0 || !is_ident(lower.as_bytes()[at - 1]);
        let end = at + needle.len();
        let after = end >= lower.len() || !is_ident(lower.as_bytes()[end]);
        if before && after {
            return true;
        }
        from = at + needle.len();
    }
    false
}

fn is_ident(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_'
}

/// The first digit run (separators tolerated) that is a valid-length,
/// Luhn-passing, known-issuer PAN: its digits and its byte offset.
fn find_pan(text: &str) -> Option<(String, usize)> {
    let bytes = text.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if !bytes[i].is_ascii_digit() {
            i += 1;
            continue;
        }
        let start = i;
        let mut digits = String::new();
        let mut j = i;
        while j < bytes.len() {
            if bytes[j].is_ascii_digit() {
                digits.push(bytes[j] as char);
                j += 1;
            } else if (bytes[j] == b' ' || bytes[j] == b'-')
                && j + 1 < bytes.len()
                && bytes[j + 1].is_ascii_digit()
                && !digits.is_empty()
            {
                j += 1;
            } else {
                break;
            }
        }
        let before_ok = start == 0 || !bytes[start - 1].is_ascii_alphanumeric();
        let after_ok = j >= bytes.len() || !bytes[j].is_ascii_alphanumeric();
        if before_ok
            && after_ok
            && (MIN_PAN..=MAX_PAN).contains(&digits.len())
            && luhn(&digits)
            && issuer(&digits).is_some()
        {
            return Some((digits, start));
        }
        i = j.max(start + 1);
    }
    None
}

/// The Luhn (mod-10) checksum.
fn luhn(d: &str) -> bool {
    let mut sum = 0u32;
    let mut double = false;
    for c in d.bytes().rev() {
        let mut n = (c - b'0') as u32;
        if double {
            n *= 2;
            if n > 9 {
                n -= 9;
            }
        }
        sum += n;
        double = !double;
    }
    sum.is_multiple_of(10)
}

/// The issuer whose IIN shape `d` matches, if any.
fn issuer(d: &str) -> Option<&'static str> {
    let two: u32 = d.get(..2)?.parse().ok()?;
    let four: u32 = d.get(..4).and_then(|s| s.parse().ok()).unwrap_or(0);
    let len = d.len();
    if d.starts_with('4') && (13..=19).contains(&len) {
        Some("Visa")
    } else if ((51..=55).contains(&two) || (2221..=2720).contains(&four)) && len == 16 {
        Some("Mastercard")
    } else if (two == 34 || two == 37) && len == 15 {
        Some("Amex")
    } else if (d.starts_with("6011") || two == 65) && len == 16 {
        Some("Discover")
    } else {
        None
    }
}

#[cfg(test)]
#[path = "cardholder_tests.rs"]
mod tests;
