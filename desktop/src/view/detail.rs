//! One finding's page: what it means, how to fix it, and the technical
//! details.

use super::plain_sentence;
use super::text::{
    command_purpose, display_path, fix_sentence, home_dir, one_line, paste_step, quoted_summary,
    specific_purpose, terminal_step,
};
use super::theme::semibold;
use super::widgets::{button, card, dispatch, link, muted, pill, section, severity, tag};
use crate::app::{Action, App};
use crate::brand::Palette;
use crate::data::Finding;
use eframe::egui::{self, FontId, RichText, Ui};

/// The technical details of an advisory, shown with Show technical details.
fn technical(ui: &mut Ui, p: &Palette, finding: &Finding) {
    let mut rows: Vec<(&str, String)> = Vec::new();
    if !finding.vuln_id.is_empty() {
        rows.push(("Reference", finding.vuln_id.clone()));
    }
    if !finding.affected_range.is_empty() {
        rows.push(("Affected versions", finding.affected_range.clone()));
    }
    if !finding.fixed.is_empty() {
        rows.push(("Fixed in", finding.fixed.clone()));
    }
    if let Some(score) = finding.cvss {
        let version = if finding.cvss_version.is_empty() {
            String::new()
        } else {
            format!(" (CVSS {})", finding.cvss_version)
        };
        rows.push(("Severity score", format!("{score:.1} out of 10{version}")));
    }
    // An estimate is no news next to "attackers are using this now".
    if let Some(epss) = finding.epss.filter(|_| !finding.kev) {
        rows.push((crate::explain::EPSS_LABEL, crate::explain::epss_text(epss)));
    }
    if !finding.cwe.is_empty() {
        let named: Vec<String> = finding
            .cwe
            .iter()
            .map(|cwe| match crate::explain::cwe_name(cwe) {
                Some(name) => format!("{cwe} ({name})"),
                None => cwe.clone(),
            })
            .collect();
        rows.push(("Weakness type", named.join(", ")));
    }
    if finding.kev {
        rows.push(("CISA KEV", "Listed: known to be used in attacks".into()));
    }
    let scope = match finding.dep_scope.as_str() {
        "runtime" => Some("Used when the project runs"),
        "dev" => Some("Used only while developing"),
        "optional" => Some("Optional"),
        _ => None,
    };
    let direct = match finding.dep_direct {
        Some(true) => Some("the project's own dependency"),
        Some(false) => Some("pulled in by another dependency"),
        None => None,
    };
    match (scope, direct) {
        (Some(scope), Some(direct)) => rows.push(("Dependency", format!("{scope}, {direct}"))),
        (Some(scope), None) => rows.push(("Dependency", scope.into())),
        (None, Some(direct)) => rows.push(("Dependency", direct.into())),
        (None, None) => {}
    }
    if !finding.location.is_empty() {
        rows.push(("Full path", finding.location.clone()));
    }
    if !finding.note.trim().is_empty() && finding.note.trim() != finding.summary {
        rows.push(("Scanner note", one_line(&finding.note, 600)));
    }
    ui.add_space(4.0);
    for (name, value) in rows {
        let shown = ui.add(
            egui::Label::new(RichText::new(format!("{name}: {value}")).color(p.ink2))
                .selectable(true),
        );
        let key = if name == crate::explain::EPSS_LABEL {
            "epss".to_owned()
        } else {
            name.to_ascii_lowercase().replace(' ', "_")
        };
        tag(ui, &shown, &format!("finding.tech.{key}"));
    }
}

pub(super) fn detail(ui: &mut Ui, app: &mut App, p: &Palette, enabled: bool) {
    if button(ui, p, "finding.back", "Back", true, false) {
        dispatch(ui, app, Action::CloseFinding);
        return;
    }
    let details = app.state.details;
    let kev_checked = app.kev_checked_selected();
    let Some(finding) = app.selected() else {
        return;
    };
    ui.heading(if finding.component.trim().is_empty() {
        one_line(&finding.vuln_id, 80)
    } else {
        one_line(&finding.component, 120)
    });
    let (level, color, shape) = severity(p, finding);
    pill(ui, level, color, Some(shape));
    let mut action = None;
    card(ui, p, |ui| {
        section(ui, "What Pantry found");
        let (summary, missing_release) = finding
            .note
            .rsplit_once(" (no fix released for ")
            .filter(|(_, ending)| ending.ends_with(" yet)"))
            .map_or((finding.note.as_str(), false), |(summary, _)| {
                (summary, true)
            });
        // Lead with the same plain sentence the home list uses. The
        // scanner's own note (often an advisory title) is technical detail.
        let sentence = plain_sentence(finding);
        let lead = ui.label(&sentence);
        tag(ui, &lead, "finding.sentence");
        let summary = summary.trim();
        if !summary.is_empty() && !sentence.contains(summary) {
            // For a check that did not finish, the note is the reason and
            // people need it; otherwise it is a technical detail.
            // (Otherwise it is under the technical details.)
            if finding.kind == "unchecked" {
                ui.label(one_line(summary, 400));
            }
        }
        // What could happen, and whether attackers use it now.
        let explanation = crate::explain::explain(finding);
        if !sentence.contains(&explanation.sentence) && finding.kind != "unchecked" {
            let shown = ui.label(&explanation.sentence);
            tag(ui, &shown, "finding.explanation");
        }
        if let Some(attacks) = crate::explain::attacks(finding, kev_checked) {
            let shown = if finding.kev {
                ui.label(
                    RichText::new(format!("{attacks} Fix it first."))
                        .color(p.red)
                        .strong(),
                )
            } else {
                muted(ui, p, attacks)
            };
            tag(ui, &shown, "finding.attacks");
        }
        // Only a published advisory can be waiting on its maker's fix.
        if missing_release
            && crate::explain::is_advisory(finding)
            && finding.fixed.is_empty()
            && !sentence.contains("no fix yet")
        {
            muted(ui, p, "The maker has not released a fix yet.");
        }
        // The public ids, each a link to its notice, always shown.
        let ids = crate::explain::identifiers(finding);
        if !ids.is_empty() {
            ui.add_space(4.0);
            ui.horizontal_wrapped(|ui| {
                ui.label(RichText::new(if ids.len() == 1 { "Security notice ID:" } else { "Security notice IDs:" }).color(p.ink2))
                    .on_hover_text("Public IDs for this security problem. CVE IDs come from the CVE program; GHSA IDs from GitHub; others from the package's own advisory database.");
                for item in &ids {
                    let key = format!("finding.advisory.{}", item.id);
                    match &item.url {
                        Some(_) => {
                            if link(ui, &key, &item.id) {
                                action = Some(Action::OpenAdvisory { id: item.id.clone() });
                            }
                        }
                        None => {
                            let shown = ui.label(RichText::new(&item.id).monospace());
                            tag(ui, &shown, &key);
                        }
                    }
                }
                if button(ui, p, "finding.copy_id", "Copy ID", true, false) {
                    action = Some(Action::CopyId);
                }
            });
            if ids.iter().any(|item| item.id.starts_with("DEMO-")) {
                muted(ui, p, "Demo data: DEMO IDs are not in any public database.");
            }
        }
        let quote = quoted_summary(&finding.summary);
        if !quote.is_empty() && quote != sentence {
            let quoted = muted(
                ui,
                p,
                format!("From the security notice: \u{201c}{quote}\u{201d}"),
            );
            tag(ui, &quoted, "finding.summary");
        }
        if !finding.location.is_empty() {
            let shown = display_path(&finding.location, home_dir().as_deref(), 56);
            let found = muted(ui, p, format!("Found in {shown}"));
            tag(ui, &found, "finding.location");
            if shown != finding.location {
                found.on_hover_text(&finding.location);
            }
        }
        if !finding.version.is_empty() {
            muted(ui, p, format!("Installed version {}", finding.version));
        }
        if details && finding.kind != "unchecked" {
            technical(ui, p, finding);
        }
    });
    ui.add_space(4.0);
    let how = app
        .plan()
        .map(|fix| fix.how.clone())
        .unwrap_or_else(|| "you".into());
    let text = app.copy_text();
    let automatic = app.can_fix_selected() && !app.needs_password();
    let earlier = app
        .state
        .selected
        .as_deref()
        .is_some_and(|id| id.starts_with("earlier-"));
    let watch_only = text
        .as_deref()
        .is_some_and(|step| step.starts_with("No fix released for this package yet:"));
    let awaiting_fix =
        finding.fixed.is_empty() && (watch_only || finding.note.contains(" (no fix released for "));
    let fix_cmd = finding.fix_cmd.clone();
    let sentence = fix_sentence(finding, text.as_deref().unwrap_or(""));
    let unchecked = finding.kind == "unchecked";
    let fixed = finding.fixed.clone();
    card(ui, p, |ui| {
        section(
            ui,
            if unchecked {
                "What Pantry couldn't check"
            } else {
                "How to fix it"
            },
        );
        if !fixed.is_empty() && !automatic {
            ui.label(
                RichText::new(format!("Fixed in version {fixed}"))
                    .font(FontId::new(15.0, semibold())),
            );
        }
        if earlier {
            ui.label(
                "This was found by an earlier scan. Choose Scan now before you change anything.",
            );
        }
        if awaiting_fix {
            section(ui, "No fix yet");
            ui.label("The maker has not released a fixed version. Read the security notice to see which versions are affected.");
            if details {
                ui.label("Pantry can check for a fix each time it scans. Set up a schedule in the sidebar, or copy the check command to run it in a terminal.");
                if button(ui, p, "fix.watch.copy", "Copy check command", true, false) {
                    action = Some(Action::CopyWatchCommand);
                }
            } else {
                let watch = ui.label("Pantry checks for a fix each time it scans. To have it scan on its own, set up a scan schedule in the sidebar.");
                tag(ui, &watch, "fix.watch");
            }
        }
        let Some(text) = text.filter(|_| !watch_only) else {
            if !awaiting_fix {
                ui.label(if unchecked {
                    "This is usually a source that did not answer, or a folder Pantry was not allowed to read. Check your internet connection, then try again."
                } else {
                    "Pantry has no fix steps for this finding."
                });
                if unchecked && button(ui, p, "finding.retry", "Retry", enabled, true) {
                    action = Some(Action::Retry);
                }
            }
            return;
        };
        if automatic {
            match &app.state.pending_fix {
                None => {
                    ui.label(RichText::new(format!(
                        "Pantry can fix this for you. {sentence}"
                    )));
                    muted(
                        ui,
                        p,
                        "Pantry asks you before it changes anything, then scans again to check the fix.",
                    );
                    if button(
                        ui,
                        p,
                        "fix.preview",
                        "Fix it",
                        enabled && app.state.report_error.is_none(),
                        true,
                    ) {
                        action = Some(Action::PreviewFix);
                    }
                }
                Some(pending) => {
                    section(ui, "Ready to fix");
                    ui.label(format!(
                        "{sentence} Then Pantry scans again to check that the problem is gone."
                    ));
                    ui.horizontal(|ui| {
                        if button(ui, p, "fix.confirm", "Yes, fix it", enabled, true) {
                            action = Some(Action::ConfirmFix);
                        }
                        if button(ui, p, "fix.cancel", "Not now", true, false) {
                            action = Some(Action::CancelFix);
                        }
                    });
                    if details {
                        muted(
                            ui,
                            p,
                            format!("Command checked against scan #{}.", pending.scan),
                        );
                    }
                }
            }
            // A command Pantry can't describe is always shown.
            let specific = specific_purpose(finding, &text).is_some();
            let show = details || app.state.show_fix_details || !specific;
            if !details && specific {
                let label = if show {
                    "Hide the command"
                } else {
                    "Show the command"
                };
                if link(ui, "fix.details", label) {
                    action = Some(Action::ToggleFixDetails);
                }
            }
            if show {
                ui.add(egui::Label::new(RichText::new(&text).monospace()).selectable(true));
                if button(ui, p, "fix.copy", "Copy command", true, false) {
                    action = Some(Action::CopyFix);
                }
            }
            return;
        }
        // Steps people follow themselves.
        let command = if app.needs_password() { fix_cmd } else { text };
        let is_command =
            app.needs_password() || how == "terminal" || command_purpose(&command).is_some();
        let mut steps: Vec<String> = Vec::new();
        if is_command {
            steps.push(terminal_step().into());
            steps.push(paste_step().into());
            if command.starts_with("sudo ") || app.needs_password() {
                steps.push("If it asks for a password, type the password you use to sign in to this computer. Nothing shows while you type. Press Return when done.".into());
            }
            steps.push("When it finishes, come back to Pantry and choose Scan now.".into());
        } else {
            steps.push(command.clone());
            steps.push("When you're done, choose Scan now to check it.".into());
        }
        for (n, step) in steps.iter().enumerate() {
            ui.label(format!("{}. {step}", n + 1));
        }
        if is_command {
            ui.add(egui::Label::new(RichText::new(&command).monospace()).selectable(true));
        }
        let label = if is_command {
            "Copy command"
        } else {
            "Copy steps"
        };
        if button(ui, p, "fix.copy", label, true, false) {
            action = Some(Action::CopyFix);
        }
    });
    if details && let Some(output) = &app.state.last_fix_output {
        card(ui, p, |ui| {
            section(ui, "What the fix printed");
            ui.add(
                egui::Label::new(RichText::new(output).monospace().color(p.ink2)).selectable(true),
            );
        });
    }
    if let Some(action) = action {
        dispatch(ui, app, action);
    }
}
