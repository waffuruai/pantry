//! Characters that hide or reorder text: bidi controls, tag characters,
//! flags, and words that mix scripts or use confusable letters.

/// Where the England, Scotland and Wales flags are spelled: a waving black
/// flag, then the region's letters as tag characters, then CANCEL TAG.
pub(crate) const BLACK_FLAG: char = '\u{1F3F4}';
pub(crate) const CANCEL_TAG: char = '\u{E007F}';

/// The text with emoji subdivision flags reduced to their black flag: a
/// run of tag letters (U+E0020..U+E007E) right after U+1F3F4 and closed by
/// CANCEL TAG is 🏴󠁧󠁢󠁥󠁮󠁧󠁿, not hidden text. Any other tag run is left in place
/// to be counted. Line numbers are unchanged: no newline is removed.
pub(crate) fn without_subdivision_flags(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(i) = rest.find(BLACK_FLAG) {
        let after = i + BLACK_FLAG.len_utf8();
        out.push_str(&rest[..after]);
        rest = &rest[after..];
        let run = rest.chars().take_while(|c| ('\u{E0020}'..='\u{E007E}').contains(c)).map(char::len_utf8).sum();
        if run > 0 && rest[run..].starts_with(CANCEL_TAG) {
            rest = &rest[run + CANCEL_TAG.len_utf8()..];
        }
    }
    out.push_str(rest);
    out
}

/// A letter of a script written right to left (Unicode bidi class R or
/// AL): Hebrew, Arabic, Syriac, Thaana, N'Ko, Samaritan, Mandaic and their
/// presentation forms. Enough to tell a translation file from an attack.
pub(crate) fn is_rtl(c: char) -> bool {
    matches!(c, '\u{0590}'..='\u{08FF}' | '\u{FB1D}'..='\u{FDFF}' | '\u{FE70}'..='\u{FEFC}')
}

/// The first 100 characters of a line, on one line.
pub(crate) fn excerpt(s: &str) -> String {
    let one: String = s.split_whitespace().collect::<Vec<_>>().join(" ");
    let mut e: String = one.chars().take(100).collect();
    if one.chars().count() > 100 {
        e.push('…');
    }
    e
}

/// Letters that print like a Latin letter but aren't one: Cyrillic а е о р
/// с у х і ј ѕ һ ԁ ԛ ԝ ӏ (and capitals), Greek α ο ν ρ κ τ υ ι (and capitals
/// Α Β Ε Ζ Η Ι Κ Μ Ν Ο Ρ Τ Υ Χ). Σ, Δ, θ, π and the rest are maths, not
/// disguises.
fn is_confusable(c: char) -> bool {
    "аеорсухіјѕһԁԛԝӏёАВЕКМНОРСТХІЈЅҮαονρκτυιΑΒΕΖΗΙΚΜΝΟΡΤΥΧ".contains(c)
}

/// A mostly Latin word with a look-alike letter from another script in it.
pub(crate) fn mixed_script(word: &str) -> bool {
    let latin = word.chars().filter(|c| c.is_ascii_alphabetic()).count();
    let fakes = word.chars().filter(|c| is_confusable(*c)).count();
    let other = word.chars().filter(|c| !c.is_ascii() && !is_confusable(*c)).count();
    word.chars().count() >= 3 && latin >= 2 && fakes >= 1 && other == 0
}

/// A mostly Latin identifier with a look-alike letter from another script
/// in it, and the line it is on. Code only: prose has its own alphabets.
pub(crate) fn first_mixed_script_word(text: &str) -> Option<(String, usize)> {
    for (n, line) in text.lines().enumerate() {
        for word in line.split(|c: char| !(c.is_alphanumeric() || c == '_')) {
            if mixed_script(word) {
                return Some((word.to_string(), n + 1));
            }
        }
    }
    None
}
