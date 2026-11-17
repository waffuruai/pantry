use super::*;
use crate::checks::machine::any::dev_settings::extension_policy;

#[test]
fn cooldown_is_inserted_or_replaced_keeping_the_rest() {
    assert_eq!(with_cooldown("", 72), "{\n    \"extensions.installCooldownHours\": 72\n}\n");
    assert_eq!(with_cooldown("{}\n", 72), "{\n    \"extensions.installCooldownHours\": 72\n}\n");
    let before = "{\n  // mine\n  \"editor.fontSize\": 14,\n  \"extensions.autoUpdate\": false\n}\n";
    let after = with_cooldown(before, 72);
    assert_eq!(
        after,
        "{\n  \"extensions.installCooldownHours\": 72,\n  // mine\n  \"editor.fontSize\": 14,\n  \"extensions.autoUpdate\": false\n}\n"
    );
    assert_eq!(extension_policy(&after).cooldown_hours, Some(72.0));
    let zero = "{\n  \"extensions.installCooldownHours\": 0,\n  \"a\": 1\n}\n";
    assert_eq!(with_cooldown(zero, 336), "{\n  \"extensions.installCooldownHours\": 336,\n  \"a\": 1\n}\n");
    let last = "{\n  \"a\": 1,\n  \"extensions.installCooldownHours\": 0\n}\n";
    assert_eq!(with_cooldown(last, 72), "{\n  \"a\": 1,\n  \"extensions.installCooldownHours\": 72\n}\n");
}
