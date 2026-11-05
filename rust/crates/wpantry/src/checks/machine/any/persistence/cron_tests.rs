use super::*;

#[test]
fn the_command_past_the_time_and_user_fields() {
    // The crontab line's command past the user field.
    assert_eq!(cron_command("0 * * * * root /usr/bin/true", true).as_deref(), Some("/usr/bin/true"));
    assert_eq!(cron_command("@daily /bin/x", false).as_deref(), Some("/bin/x"));
    assert_eq!(cron_command("PATH=/bin", false), None);
    assert_eq!(cron_command("* * *", false), None);
}
