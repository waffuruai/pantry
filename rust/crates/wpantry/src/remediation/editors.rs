//! `wpantry harden extension-cooldown`: the one posture fix that edits
//! files, setting the extension install cooldown in every editor's settings.
//! The check is [`crate::checks::machine::any::dev_settings`].

use crate::checks::machine::any::dev_settings::editor_settings;

/// Set `extensions.installCooldownHours` in every editor's settings.json
/// (the fix for the cooldown check in [`crate::checks::machine::any::dev_settings`]);
/// returns what was changed. The key is replaced where present and inserted
/// after the opening brace otherwise, so comments and formatting stay.
pub fn set_extension_cooldown(hours: u32) -> crate::error::Result<Vec<String>> {
    let mut changed = Vec::new();
    for (name, file) in editor_settings() {
        let text = if file.is_file() { crate::utils::files::read_capped(&file, 1 << 20)? } else { String::new() };
        let new = with_cooldown(&text, hours);
        if new != text {
            if let Some(dir) = file.parent() {
                std::fs::create_dir_all(dir)?;
            }
            let tmp = file.with_extension("json.wpantry-tmp");
            std::fs::write(&tmp, &new)?;
            std::fs::rename(&tmp, &file)?;
            changed.push(format!("{name}: {} ({})", hours, file.display()));
        }
    }
    Ok(changed)
}

/// `text` with the cooldown set to `hours`.
pub fn with_cooldown(text: &str, hours: u32) -> String {
    let key = "\"extensions.installCooldownHours\"";
    if text.trim().is_empty() {
        return format!("{{\n    {key}: {hours}\n}}\n");
    }
    if let Some(at) = text.find(key) {
        // Replace the value on that line.
        let line_start = text[..at].rfind('\n').map(|i| i + 1).unwrap_or(0);
        let line_end = text[at..].find('\n').map(|i| at + i).unwrap_or(text.len());
        let line = &text[line_start..line_end];
        let indent: String = line.chars().take_while(|c| c.is_whitespace()).collect();
        let comma = if line.trim_end().ends_with(',') { "," } else { "" };
        return format!("{}{indent}{key}: {hours}{comma}{}", &text[..line_start], &text[line_end..]);
    }
    let Some(brace) = text.find('{') else { return format!("{{\n    {key}: {hours}\n}}\n") };
    let after = &text[brace + 1..];
    let empty = after.trim_start().starts_with('}');
    let indent = after
        .lines()
        .nth(1)
        .map(|l| l.chars().take_while(|c| c.is_whitespace()).collect::<String>())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "    ".into());
    format!(
        "{}{{\n{indent}{key}: {hours}{}{}",
        &text[..brace],
        if empty { "\n" } else { ",\n" },
        after.strip_prefix('\n').unwrap_or(after)
    )
}

#[cfg(test)]
mod tests {
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
}
