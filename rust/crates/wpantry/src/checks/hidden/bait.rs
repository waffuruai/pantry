//! Identifiers written to bait a model into calling them.

/// Words that have no business in a fingerprinting script's identifiers.
const BAIT: &[&str] = &[
    "lethal",
    "poison",
    "ricin",
    "sarin",
    "anthrax",
    "cyanide",
    "toxin",
    "bioweapon",
    "nerveagent",
    "overdose",
    "suicide",
    "kill",
    "murder",
    "bomb",
    "explosive",
    "detonat",
    "weapon",
    "warhead",
    "uranium",
    "plutonium",
    "pathogen",
    concat!("chemical", "weapon"),
    concat!("mass", "destruction"),
    "genocide",
    "assassinat",
    "torture",
    "fentanyl",
    "deadly",
    "dosage",
    "dose",
];

/// Identifiers (camelCase or snake_case words) carrying two or more bait
/// terms, or one of the unmistakable ones.
pub fn bait_identifiers(text: &str) -> Vec<String> {
    let strong = [
        "ricin",
        "sarin",
        "anthrax",
        "bioweapon",
        "nerveagent",
        concat!("chemical", "weapon"),
        concat!("mass", "destruction"),
        "warhead",
        "plutonium",
    ];
    let mut out: Vec<String> = Vec::new();
    for word in text.split(|c: char| !(c.is_ascii_alphanumeric() || c == '_')) {
        if word.len() < 12 || !word.chars().next().is_some_and(|c| c.is_ascii_alphabetic()) {
            continue;
        }
        let lower = word.to_ascii_lowercase().replace('_', "");
        let hits = BAIT.iter().filter(|b| lower.contains(*b)).count();
        if (hits >= 2 || strong.iter().any(|s| lower.contains(s))) && !out.contains(&word.to_string()) {
            out.push(word.to_string());
        }
    }
    out
}
