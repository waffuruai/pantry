//! Chat templates that live outside a model file, read whole and checked
//! with the same rules ([`super::template`]):
//!
//! - `tokenizer_config.json` and `chat_template.json`: `chat_template`, a
//!   string, or a list of `{name, template}`;
//! - `chat_template.jinja`, and any other `*.jinja` that reads like a chat
//!   template (it names `messages` and loops over them or reads a role);
//! - an Ollama `Modelfile`: its `TEMPLATE` and `SYSTEM` instructions;
//! - an Ollama template or system-prompt layer: the blob's text.
//!
//! A file that holds no template is not one of these (`None`); one that
//! can't be read (over its cap, not JSON) is not checked, never clean.
//!
//! ```
//! use wpantry::checks::models::sidecars::modelfile_templates;
//! let m = "FROM ./m.gguf\nTEMPLATE \"\"\"{{ .Prompt }}\"\"\"\nSYSTEM You are helpful.\n";
//! let t = modelfile_templates(m);
//! assert_eq!(t, [("TEMPLATE".to_string(), "{{ .Prompt }}".to_string()), ("SYSTEM".to_string(), "You are helpful.".to_string())]);
//! ```

use super::{FileResult, Issue, Level, What, ids, role, template};
use serde_json::Value;
use std::path::Path;

/// The most of a `Modelfile` or an Ollama layer read.
pub const MAX_MODELFILE: u64 = 1 << 20;
/// The most of a template file parsed as JSON.
const MAX_JSON: usize = super::MAX_TEMPLATE_FILE as usize;

/// The templates a `tokenizer_config.json` or `chat_template.json`
/// carries, `(name, text)`; `Err` when it isn't JSON.
pub fn json_templates(text: &str) -> Result<Vec<(String, String)>, String> {
    let v: Value = crate::utils::json::parse(text.as_bytes(), MAX_JSON).map_err(|e| format!("not JSON ({e})"))?;
    let mut out = Vec::new();
    match v.get("chat_template") {
        Some(Value::String(t)) => out.push(("chat_template".to_string(), t.clone())),
        Some(Value::Array(list)) => {
            for item in list {
                let name = item.get("name").and_then(Value::as_str).unwrap_or("unnamed");
                if let Some(t) = item.get("template").and_then(Value::as_str) {
                    out.push((format!("chat_template.{name}"), t.to_string()));
                }
            }
        }
        _ => {}
    }
    Ok(out)
}

/// The `TEMPLATE` and `SYSTEM` values of a `Modelfile`: a `"""` block, a
/// quoted string, or the rest of the line.
pub fn modelfile_templates(text: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    let mut i = 0;
    while i < text.len() {
        let line_end = text[i..].find('\n').map_or(text.len(), |n| i + n);
        let line = &text[i..line_end];
        let lead = line.len() - line.trim_start().len();
        let word: String = line[lead..].chars().take_while(|c| c.is_ascii_alphabetic()).collect();
        let upper = word.to_ascii_uppercase();
        if upper != "TEMPLATE" && upper != "SYSTEM" {
            i = line_end + 1;
            continue;
        }
        let after_word = i + lead + word.len();
        let gap = text[after_word..line_end].len() - text[after_word..line_end].trim_start().len();
        let value = after_word + gap;
        if text[value..].starts_with("\"\"\"") {
            let body = value + 3;
            match text[body..].find("\"\"\"") {
                Some(e) => {
                    out.push((upper, text[body..body + e].to_string()));
                    let close = body + e + 3;
                    i = text[close..].find('\n').map_or(text.len(), |n| close + n + 1);
                }
                None => {
                    out.push((upper, text[body..].to_string()));
                    break;
                }
            }
            continue;
        }
        let v = text[value..line_end].trim_end();
        let v = v.strip_prefix('"').and_then(|v| v.strip_suffix('"')).unwrap_or(v);
        out.push((upper, v.to_string()));
        i = line_end + 1;
    }
    out
}

fn unchecked(why: impl Into<String>) -> Option<FileResult> {
    Some(FileResult {
        what: What::Template,
        issues: vec![Issue::new(ids::NOT_CHECKED, Level::Unchecked, why)],
        split: 0,
    })
}

/// One template file's result. `bytes` is the file read whole, None when
/// it was over its cap or couldn't be read.
pub fn check(role: u8, path: &Path, bytes: Option<&[u8]>) -> Option<FileResult> {
    let name = path.file_name().map(|n| n.to_string_lossy().to_ascii_lowercase()).unwrap_or_default();
    let Some(bytes) = bytes else {
        return unchecked("over its size cap, or it can't be read: its template isn't checked");
    };
    let text = String::from_utf8_lossy(bytes);
    let templates: Vec<(String, String)> = match role {
        role::TEMPLATE_FILE if name.ends_with(".json") => match json_templates(&text) {
            Ok(t) => t.into_iter().map(|(k, t)| (format!("{name} {k}"), t)).collect(),
            Err(why) => {
                // A tokenizer_config.json that isn't JSON can't say whether it
                // has a template; one in a repo that has none is common.
                return unchecked(format!("{name}: {why}"));
            }
        },
        role::TEMPLATE_FILE if name == "chat_template.jinja" || template::looks_like_chat_template(&text) => {
            vec![(name.clone(), text.into_owned())]
        }
        role::MODELFILE => modelfile_templates(&text).into_iter().map(|(k, t)| (format!("{name} {k}"), t)).collect(),
        role::OLLAMA_TEMPLATE => vec![("ollama template layer".to_string(), text.into_owned())],
        role::OLLAMA_SYSTEM => vec![("ollama system layer".to_string(), text.into_owned())],
        _ => Vec::new(),
    };
    if templates.is_empty() {
        return None;
    }
    let issues = templates.iter().flat_map(|(k, t)| template::check(k, t)).collect();
    Some(FileResult { what: What::Template, issues: super::sorted(issues), split: 0 })
}

#[cfg(test)]
#[path = "sidecars_tests.rs"]
mod tests;
