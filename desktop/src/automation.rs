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

use crate::{app, pantry::Pantry, view};
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
        let fixable: Vec<String> = state
            .report
            .as_ref()
            .map(|report| {
                report
                    .open()
                    .into_iter()
                    .filter(|(finding, id)| report.can_fix(finding, id))
                    .map(|(_, id)| id)
                    .collect()
            })
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
    let ctx = egui::Context::default();
    ctx.enable_accesskit();
    view::setup(&ctx, false);
    let settings = wpantry_desktop::instance::directories()
        .ok()
        .map(|(state, _)| state.join("settings.json"));
    let mut driver = Driver {
        app: app::App::new(pantry, &ctx, settings, true),
        ctx,
        nodes: Vec::new(),
        clipboard: None,
        browser: None,
        size: egui::vec2(1080.0, 740.0),
        textures: HashMap::new(),
        shapes: Vec::new(),
        pixels_per_point: 1.0,
    };
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

/// A small CPU rasterizer for egui's tessellated meshes, so the redesign can
/// be reviewed as PNGs without opening a window. egui already feathers
/// edges with extra alpha triangles, so plain per-pixel coverage is enough.
/// Blending is premultiplied sRGB, like egui's own gamma-space renderers.
mod raster {
    use eframe::egui::{self, Color32, epaint};
    use std::collections::HashMap;

    pub struct Texture {
        pub size: [usize; 2],
        pub pixels: Vec<Color32>,
    }

    pub struct Image {
        pub width: usize,
        pub height: usize,
        pub pixels: Vec<[f32; 4]>,
    }

    pub fn apply(
        textures: &mut HashMap<egui::TextureId, Texture>,
        id: egui::TextureId,
        delta: &epaint::ImageDelta,
    ) {
        let epaint::ImageData::Color(image) = &delta.image;
        match delta.pos {
            None => {
                textures.insert(
                    id,
                    Texture {
                        size: image.size,
                        pixels: image.pixels.clone(),
                    },
                );
            }
            Some([x0, y0]) => {
                if let Some(texture) = textures.get_mut(&id) {
                    for y in 0..image.size[1] {
                        for x in 0..image.size[0] {
                            let (tx, ty) = (x0 + x, y0 + y);
                            if tx < texture.size[0] && ty < texture.size[1] {
                                texture.pixels[ty * texture.size[0] + tx] =
                                    image.pixels[y * image.size[0] + x];
                            }
                        }
                    }
                }
            }
        }
    }

    fn sample(texture: &Texture, u: f32, v: f32) -> [f32; 4] {
        let [w, h] = texture.size;
        if w == 0 || h == 0 {
            return [1.0; 4];
        }
        // Bilinear, clamped to the edge.
        let x = (u * w as f32 - 0.5).clamp(0.0, (w - 1) as f32);
        let y = (v * h as f32 - 0.5).clamp(0.0, (h - 1) as f32);
        let (x0, y0) = (x.floor() as usize, y.floor() as usize);
        let (x1, y1) = ((x0 + 1).min(w - 1), (y0 + 1).min(h - 1));
        let (fx, fy) = (x - x0 as f32, y - y0 as f32);
        let at = |x: usize, y: usize| {
            let c = texture.pixels[y * w + x];
            [c.r() as f32, c.g() as f32, c.b() as f32, c.a() as f32].map(|v| v / 255.0)
        };
        let (a, b, c, d) = (at(x0, y0), at(x1, y0), at(x0, y1), at(x1, y1));
        let mut out = [0.0; 4];
        for i in 0..4 {
            let top = a[i] + (b[i] - a[i]) * fx;
            let bottom = c[i] + (d[i] - c[i]) * fx;
            out[i] = top + (bottom - top) * fy;
        }
        out
    }

    pub fn render(
        primitives: &[epaint::ClippedPrimitive],
        textures: &HashMap<egui::TextureId, Texture>,
        size: egui::Vec2,
        scale: f32,
        light: bool,
    ) -> Image {
        let (width, height) = (
            (size.x * scale).round() as usize,
            (size.y * scale).round() as usize,
        );
        let base = if light {
            [0.97, 0.97, 0.98, 1.0]
        } else {
            [0.07, 0.09, 0.11, 1.0]
        };
        let mut image = Image {
            width,
            height,
            pixels: vec![base; width * height],
        };
        for primitive in primitives {
            let epaint::Primitive::Mesh(mesh) = &primitive.primitive else {
                continue;
            };
            let clip = primitive.clip_rect;
            let (cx0, cy0) = ((clip.min.x * scale).max(0.0), (clip.min.y * scale).max(0.0));
            let (cx1, cy1) = (
                (clip.max.x * scale).min(width as f32),
                (clip.max.y * scale).min(height as f32),
            );
            let texture = textures.get(&mesh.texture_id);
            for triangle in mesh.indices.chunks_exact(3) {
                let v = [0, 1, 2].map(|i| &mesh.vertices[triangle[i] as usize]);
                let p = v.map(|v| (v.pos.x * scale, v.pos.y * scale));
                let area =
                    (p[1].0 - p[0].0) * (p[2].1 - p[0].1) - (p[2].0 - p[0].0) * (p[1].1 - p[0].1);
                if area.abs() < 1e-6 {
                    continue;
                }
                let x0 = p
                    .iter()
                    .map(|q| q.0)
                    .fold(f32::MAX, f32::min)
                    .max(cx0)
                    .floor() as i64;
                let x1 = p
                    .iter()
                    .map(|q| q.0)
                    .fold(f32::MIN, f32::max)
                    .min(cx1)
                    .ceil() as i64;
                let y0 = p
                    .iter()
                    .map(|q| q.1)
                    .fold(f32::MAX, f32::min)
                    .max(cy0)
                    .floor() as i64;
                let y1 = p
                    .iter()
                    .map(|q| q.1)
                    .fold(f32::MIN, f32::max)
                    .min(cy1)
                    .ceil() as i64;
                for y in y0.max(0)..y1.min(height as i64) {
                    for x in x0.max(0)..x1.min(width as i64) {
                        let (px, py) = (x as f32 + 0.5, y as f32 + 0.5);
                        if px < cx0 || px >= cx1 || py < cy0 || py >= cy1 {
                            continue;
                        }
                        let w0 =
                            ((p[1].0 - px) * (p[2].1 - py) - (p[2].0 - px) * (p[1].1 - py)) / area;
                        let w1 =
                            ((p[2].0 - px) * (p[0].1 - py) - (p[0].0 - px) * (p[2].1 - py)) / area;
                        let w2 = 1.0 - w0 - w1;
                        if w0 < -1e-4 || w1 < -1e-4 || w2 < -1e-4 {
                            continue;
                        }
                        let w = [w0, w1, w2];
                        let mut color = [0.0f32; 4];
                        for (i, vertex) in v.iter().enumerate() {
                            let c = vertex.color;
                            color[0] += w[i] * c.r() as f32 / 255.0;
                            color[1] += w[i] * c.g() as f32 / 255.0;
                            color[2] += w[i] * c.b() as f32 / 255.0;
                            color[3] += w[i] * c.a() as f32 / 255.0;
                        }
                        if let Some(texture) = texture {
                            let u = w0 * v[0].uv.x + w1 * v[1].uv.x + w2 * v[2].uv.x;
                            let t = w0 * v[0].uv.y + w1 * v[1].uv.y + w2 * v[2].uv.y;
                            let texel = sample(texture, u, t);
                            for i in 0..4 {
                                color[i] *= texel[i];
                            }
                        }
                        let dst = &mut image.pixels[y as usize * width + x as usize];
                        let keep = 1.0 - color[3];
                        for i in 0..4 {
                            dst[i] = color[i] + dst[i] * keep;
                        }
                    }
                }
            }
        }
        image
    }

    fn crc32(bytes: &[u8]) -> u32 {
        let mut crc = !0u32;
        for &byte in bytes {
            crc ^= byte as u32;
            for _ in 0..8 {
                crc = if crc & 1 != 0 {
                    (crc >> 1) ^ 0xEDB8_8320
                } else {
                    crc >> 1
                };
            }
        }
        !crc
    }

    /// An 8-bit RGB PNG, compressed with the zlib already in the build.
    pub fn write_png(path: &std::path::Path, image: &Image) -> std::io::Result<()> {
        let mut raw = Vec::with_capacity(image.height * (image.width * 3 + 1));
        for row in image.pixels.chunks_exact(image.width.max(1)) {
            raw.push(0);
            for pixel in row {
                for channel in &pixel[..3] {
                    raw.push((channel.clamp(0.0, 1.0) * 255.0).round() as u8);
                }
            }
        }
        let mut png = b"\x89PNG\r\n\x1a\n".to_vec();
        let mut chunk = |kind: &[u8; 4], data: &[u8]| {
            png.extend_from_slice(&(data.len() as u32).to_be_bytes());
            let mut body = kind.to_vec();
            body.extend_from_slice(data);
            png.extend_from_slice(&body);
            png.extend_from_slice(&crc32(&body).to_be_bytes());
        };
        let mut header = Vec::new();
        header.extend_from_slice(&(image.width as u32).to_be_bytes());
        header.extend_from_slice(&(image.height as u32).to_be_bytes());
        header.extend_from_slice(&[8, 2, 0, 0, 0]);
        chunk(b"IHDR", &header);
        chunk(
            b"IDAT",
            &miniz_oxide::deflate::compress_to_vec_zlib(&raw, 6),
        );
        chunk(b"IEND", &[]);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(path, png)
    }

    #[cfg(test)]
    mod tests {
        #[test]
        fn crc_matches_the_png_reference() {
            // The CRC of "IEND" is fixed by the PNG spec: AE 42 60 82.
            assert_eq!(super::crc32(b"IEND"), 0xAE42_6082);
        }
    }
}
