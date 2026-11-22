//! Stdio driver for the same egui view, action dispatcher and Pantry CLI
//! used by the window. It uses AccessKit events to activate real widgets
//! and never opens a window.
//!
//! Example session (one JSON object per line):
//! ```text
//! {"op":"wait"}
//! {"op":"click","id":"scan.first"}
//! {"op":"key","key":"Escape"}
//! {"op":"key","key":"R","command":true}
//! {"op":"scroll_into_view","id":"theme.toggle"}
//! {"op":"cancel"}
//! {"op":"wait"}
//! ```

use crate::{app, data::Report, pantry::Pantry, view};
use eframe::egui::{self, accesskit as ax};
use serde::Deserialize;
use serde_json::{Value, json};
use std::collections::HashMap;
use std::io::{self, BufRead, Write};

#[derive(Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
enum Request {
    State,
    Tree,
    Dispatch {
        command: app::Action,
    },
    Click {
        id: String,
    },
    SetValue {
        id: String,
        value: String,
    },
    /// Wait for the running task to end, including by cancel or time limit.
    Wait,
    /// Cancel the running task (kills the scanner child).
    Cancel,
    /// Press a key, such as `Escape`, or `R` / `F` with `command`.
    Key {
        key: String,
        #[serde(default)]
        command: bool,
    },
    /// Shorten every task's time limit (milliseconds, 0 = normal).
    SetTimeLimit {
        milliseconds: u64,
    },
    /// Scroll the widget with this id into view, as a screen reader does.
    ScrollIntoView {
        id: String,
    },
    /// Draw at another window size, such as the 820 x 480 minimum.
    Resize {
        width: f32,
        height: f32,
    },
    /// Render the current frame to a PNG on the CPU (no window, no GPU),
    /// at `scale` pixels per point (2 matches a Retina display).
    Screenshot {
        path: std::path::PathBuf,
        #[serde(default = "two")]
        scale: f32,
    },
}

fn two() -> f32 {
    2.0
}

/// Roles a person can act on. Every node with one of these must carry an
/// automation id; `tree` reports the ones that don't.
const INTERACTIVE: &[ax::Role] = &[
    ax::Role::Button,
    ax::Role::CheckBox,
    ax::Role::ComboBox,
    ax::Role::TextInput,
    ax::Role::MultilineTextInput,
    ax::Role::Link,
    ax::Role::Slider,
    ax::Role::RadioButton,
    ax::Role::Switch,
    ax::Role::Tab,
    ax::Role::ListBoxOption,
    ax::Role::MenuItem,
];

mod raster;

use raster::Texture;

struct Driver {
    app: app::App,
    ctx: egui::Context,
    nodes: Vec<(ax::NodeId, ax::Node)>,
    clipboard: Option<String>,
    browser: Option<String>,
    size: egui::Vec2,
    textures: HashMap<egui::TextureId, Texture>,
    shapes: Vec<egui::epaint::ClippedShape>,
    pixels_per_point: f32,
}

impl Driver {
    /// A headless window on `pantry`, as `--automation` runs it. Its first
    /// reload is already running.
    fn new(pantry: Pantry, settings: Option<std::path::PathBuf>) -> Self {
        let ctx = egui::Context::default();
        ctx.enable_accesskit();
        view::setup(&ctx, false);
        Self {
            app: app::App::new(pantry, &ctx, settings, true),
            ctx,
            nodes: Vec::new(),
            clipboard: None,
            browser: None,
            size: egui::vec2(1080.0, 740.0),
            textures: HashMap::new(),
            shapes: Vec::new(),
            pixels_per_point: 1.0,
        }
    }

    fn frame(&mut self, events: Vec<egui::Event>) {
        let mut output = self.ctx.run_ui(
            egui::RawInput {
                screen_rect: Some(egui::Rect::from_min_size(egui::Pos2::ZERO, self.size)),
                events,
                ..Default::default()
            },
            |ui| view::draw(ui, &mut self.app),
        );
        for (id, deltas) in std::mem::take(&mut output.textures_delta.set) {
            for delta in &deltas {
                raster::apply(&mut self.textures, id, delta);
            }
        }
        for id in std::mem::take(&mut output.textures_delta.free) {
            self.textures.remove(&id);
        }
        self.shapes = std::mem::take(&mut output.shapes);
        self.pixels_per_point = output.pixels_per_point;
        let output = output.platform_output;
        // egui emits its full accessibility tree on each pass.
        if let Some(tree) = output.accesskit_update {
            self.nodes = tree.nodes;
        }
        for command in output.commands {
            match command {
                egui::OutputCommand::CopyText(text) => self.clipboard = Some(text),
                egui::OutputCommand::OpenUrl(url) => self.browser = Some(url.url),
                _ => {}
            }
        }
    }

    fn activate(
        &mut self,
        id: &str,
        action: ax::Action,
        data: Option<ax::ActionData>,
    ) -> Result<(), String> {
        let mut matches = self
            .nodes
            .iter()
            .filter(|(_, node)| node.author_id() == Some(id));
        let (target, node) = matches
            .next()
            .ok_or_else(|| format!("No widget with id {id}."))?;
        if matches.next().is_some() {
            return Err(format!("More than one widget has id {id}."));
        }
        // egui answers ScrollIntoView for every widget without listing it.
        if action != ax::Action::ScrollIntoView
            && (node.is_disabled() || !node.supports_action(action))
        {
            return Err(format!("Widget {id} cannot perform {action:?}."));
        }
        self.frame(vec![egui::Event::AccessKitActionRequest(
            ax::ActionRequest {
                action,
                target_tree: ax::TreeId::ROOT,
                target_node: *target,
                data,
            },
        )]);
        Ok(())
    }

    fn key(&mut self, name: &str, command: bool) -> Result<(), String> {
        let key = egui::Key::from_name(name).ok_or_else(|| format!("Unknown key {name}."))?;
        let modifiers = if command {
            egui::Modifiers::COMMAND
        } else {
            egui::Modifiers::NONE
        };
        self.frame(vec![egui::Event::Key {
            key,
            physical_key: None,
            pressed: true,
            repeat: false,
            modifiers,
        }]);
        Ok(())
    }

    fn tree(&self) -> Value {
        let mut nodes: Vec<_> = self
            .nodes
            .iter()
            .filter_map(|(_, node)| {
                let id = node.author_id();
                let label = node.label().or_else(|| node.value());
                let interactive = INTERACTIVE.contains(&node.role());
                if id.is_none() && label.is_none() && !interactive {
                    return None;
                }
                Some(json!({
                    "id": id, "label": label, "value": node.value(),
                    "role": format!("{:?}", node.role()), "enabled": !node.is_disabled(),
                    "interactive": interactive,
                    "bounds": node.bounds().map(|r| [r.x0, r.y0, r.x1, r.y1]),
                }))
            })
            .collect();
        nodes.sort_by(|a, b| {
            a["id"]
                .as_str()
                .cmp(&b["id"].as_str())
                .then(a["label"].as_str().cmp(&b["label"].as_str()))
        });
        json!(nodes)
    }

    fn state(&self) -> Value {
        let state = &self.app.state;
        let fixable = state
            .report
            .as_ref()
            .map(Report::fixable)
            .unwrap_or_default();
        // What the selected finding is, as the detail card explains it.
        let finding = self.app.selected().map(|f| {
            let explanation = crate::explain::explain(f);
            json!({
                "sentence": view::plain_sentence(f),
                "explanation": explanation.sentence,
                "explanation_source": explanation.source,
                "attacks": crate::explain::attacks(f, self.app.kev_checked_selected()),
                "identifiers": crate::explain::identifiers(f),
                "summary": f.summary,
                "cwe": f.cwe,
            })
        });
        // "From earlier scans": the open problems other scopes found, apart
        // from the headline, with whether each was dismissed.
        let earlier: Vec<Value> = state
            .report
            .as_ref()
            .map(|report| {
                report
                    .earlier_all()
                    .into_iter()
                    .map(|e| {
                        json!({
                            "id": e.finding.id,
                            "component": e.finding.component,
                            "scope": e.scope,
                            "dismissed": state.settings.dismissed.contains(&e.finding.id),
                            "missing_folders": crate::pantry::missing_folders(&e.scope),
                        })
                    })
                    .collect()
            })
            .unwrap_or_default();
        let headline = state.report.as_ref().map(|r| r.open().len());
        // How each home row laid out its sentence in the last frame.
        let rows: Value = self
            .ctx
            .data(|d| d.get_temp::<view::RowText>(egui::Id::unique(view::ROW_TEXT)))
            .unwrap_or_default()
            .into_iter()
            .map(|(id, (lines, cut))| (id, json!({"lines": lines, "cut": cut})))
            .collect::<serde_json::Map<_, _>>()
            .into();
        json!({
            "state": state,
            "finding": finding,
            "earlier": earlier,
            "headline_count": headline,
            "rows": rows,
            "busy": self.app.busy(),
            "busy_note": self.app.busy_note(),
            "slow": self.app.slow(),
            "cancellable": self.app.cancellable(),
            "mode": if state.report.is_some() { "has_report" } else { "first_run" },
            "palette": if state.light { "light" } else { "dark" },
            "fixable": fixable,
            "can_fix_selected": self.app.can_fix_selected(),
            "search_focused": self.ctx.memory(|m| m.focused()) == Some(egui::Id::unique(view::SEARCH_ID)),
            "banner": self.app.banner(),
            "clipboard": &self.clipboard,
            "browser": &self.browser,
        })
    }

    fn request(&mut self, request: Request) -> Result<Value, String> {
        self.app.poll(matches!(request, Request::Wait));
        self.frame(Vec::new());
        match request {
            Request::Tree => return Ok(self.tree()),
            Request::Click { id } => self.activate(&id, ax::Action::Click, None)?,
            Request::SetValue { id, value } => self.activate(
                &id,
                ax::Action::SetValue,
                Some(ax::ActionData::Value(value.into())),
            )?,
            Request::Dispatch { command } => self.app.dispatch(command, &self.ctx)?,
            Request::Cancel => self.app.dispatch(app::Action::Cancel, &self.ctx)?,
            Request::Key { key, command } => self.key(&key, command)?,
            Request::ScrollIntoView { id } => {
                self.activate(&id, ax::Action::ScrollIntoView, None)?;
                // Lay out once more so the tree reports the new position.
                self.frame(Vec::new());
            }
            Request::SetTimeLimit { milliseconds } => {
                crate::pantry::set_time_limit_for_test(milliseconds)
            }
            Request::Resize { width, height } => {
                self.size = egui::vec2(width, height);
                self.app.remember_window(self.size);
            }
            Request::Screenshot { path, scale } => {
                let scale = scale.clamp(0.5, 4.0);
                self.ctx.set_pixels_per_point(scale);
                // Two passes: one to lay out at the new scale, one to paint
                // with the font atlas built for it.
                self.frame(Vec::new());
                self.frame(Vec::new());
                let primitives = self
                    .ctx
                    .tessellate(self.shapes.clone(), self.pixels_per_point);
                let image = raster::render(
                    &primitives,
                    &self.textures,
                    self.size,
                    self.pixels_per_point,
                    self.app.state.light,
                );
                self.ctx.set_pixels_per_point(1.0);
                raster::write_png(&path, &image).map_err(|e| format!("{}: {e}", path.display()))?;
            }
            Request::State | Request::Wait => {}
        }
        self.frame(Vec::new());
        Ok(self.state())
    }
}

pub fn run(pantry: Pantry) -> io::Result<()> {
    let settings = wpantry_desktop::instance::directories()
        .ok()
        .map(|(state, _)| state.join("settings.json"));
    let mut driver = Driver::new(pantry, settings);
    let mut output = io::stdout().lock();
    for line in io::stdin().lock().lines() {
        let line = line?;
        let answer = serde_json::from_str(&line)
            .map_err(|error| error.to_string())
            .and_then(|request| driver.request(request));
        match answer {
            Ok(result) => writeln!(output, "{}", json!({ "ok": true, "result": result }))?,
            Err(error) => writeln!(output, "{}", json!({ "ok": false, "error": error }))?,
        }
        output.flush()?;
    }
    driver.app.flush_settings();
    // stdin closed: the driver is gone, so stop what it started.
    driver.app.shutdown();
    Ok(())
}

#[cfg(test)]
mod tests;
