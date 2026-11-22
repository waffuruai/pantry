//! A small CPU rasterizer for egui's tessellated meshes, so the redesign can
//! be reviewed as PNGs without opening a window. egui already feathers
//! edges with extra alpha triangles, so plain per-pixel coverage is enough.
//! Blending is premultiplied sRGB, like egui's own gamma-space renderers.

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
                    let w0 = ((p[1].0 - px) * (p[2].1 - py) - (p[2].0 - px) * (p[1].1 - py)) / area;
                    let w1 = ((p[2].0 - px) * (p[0].1 - py) - (p[0].0 - px) * (p[2].1 - py)) / area;
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
#[path = "raster_tests.rs"]
mod tests;
