//! Where this machine keeps models, and what each store says a file is.
//!
//! - **Hugging Face hub cache** (`HF_HUB_CACHE`, else `HF_HOME/hub`, else
//!   `$XDG_CACHE_HOME/huggingface/hub`, else `~/.cache/huggingface/hub`):
//!   `models--org--name/blobs/*` are the files, read by their first bytes;
//!   `snapshots/<rev>/<path>` are symlinks to them, read with `read_link`
//!   (never followed by the walk) to name each blob's repo, revision and
//!   file. An LFS blob's name is its SHA-256, so it needs no hashing. Beside
//!   a GGUF in a snapshot, `tokenizer_config.json`, `chat_template.jinja`
//!   and `chat_template.json` are read for their templates.
//! - **Ollama** (`OLLAMA_MODELS`, else `~/.ollama/models`): `blobs/sha256-*`
//!   by their first bytes; the manifests name each blob's model and say
//!   which are template and system-prompt layers, read as templates.
//! - **Folders of model files**: LM Studio (`~/.lmstudio/models`,
//!   `~/.cache/lm-studio/models`), llama.cpp's cache (`LLAMA_CACHE`, else
//!   `~/Library/Caches/llama.cpp` on macOS, `$XDG_CACHE_HOME/llama.cpp` or
//!   `~/.cache/llama.cpp`), Jan's and GPT4All's data folders.
//!
//! LM Studio's per-model prompt-template overrides are not read: where it
//! keeps them on disk isn't confirmed here.
//!
//! TODO(#11): the Windows folders are listed where they are known
//! (`%LOCALAPPDATA%`, `%APPDATA%`); none has been checked on Windows yet.

use super::{Meta, Plan, Where, read, role};
use crate::checks::files::Stats;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::Arc;

/// One store that exists on this machine.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Store {
    pub path: PathBuf,
    pub at: Where,
    pub depth: usize,
}

/// The environment, as the scan reads it: none in a test, so a unit test
/// never reads the machine's real model stores.
pub fn env(key: &str) -> Option<String> {
    if cfg!(test) {
        return None;
    }
    std::env::var(key).ok().filter(|v| !v.is_empty())
}

/// The model stores under `home` (and the folders `env` names) that exist,
/// each once.
pub fn stores(home: &Path, env: &dyn Fn(&str) -> Option<String>) -> Vec<Store> {
    let var = |k: &str| env(k).map(PathBuf::from);
    let xdg_cache = var("XDG_CACHE_HOME").unwrap_or_else(|| home.join(".cache"));
    let mut want: Vec<(PathBuf, Where, usize)> = Vec::new();
    let hub = var("HF_HUB_CACHE")
        .or_else(|| var("HF_HOME").map(|h| h.join("hub")))
        .unwrap_or_else(|| xdg_cache.join("huggingface/hub"));
    want.push((hub, Where::Hub, crate::utils::walk::DEEPEST));
    want.push((var("OLLAMA_MODELS").unwrap_or_else(|| home.join(".ollama/models")), Where::Ollama, 6));
    let tree = |p: PathBuf| (p, Where::Tree, super::DEPTH);
    want.push(tree(home.join(".lmstudio/models")));
    want.push(tree(home.join(".cache/lm-studio/models")));
    let llama = var("LLAMA_CACHE").unwrap_or_else(|| {
        if cfg!(target_os = "macos") {
            home.join("Library/Caches/llama.cpp")
        } else if cfg!(windows) {
            var("LOCALAPPDATA").map(|l| l.join("llama.cpp")).unwrap_or_else(|| home.join("AppData/Local/llama.cpp"))
        } else {
            xdg_cache.join("llama.cpp")
        }
    });
    want.push(tree(llama));
    want.push(tree(home.join("jan/models")));
    if cfg!(target_os = "macos") {
        want.push(tree(home.join("Library/Application Support/Jan/data/models")));
        want.push(tree(home.join("Library/Application Support/nomic.ai/GPT4All")));
    } else if cfg!(windows) {
        if let Some(a) = var("APPDATA") {
            want.push(tree(a.join("Jan/data/models")));
        }
        if let Some(l) = var("LOCALAPPDATA") {
            want.push(tree(l.join("nomic.ai/GPT4All")));
        }
    } else {
        let data = var("XDG_DATA_HOME").unwrap_or_else(|| home.join(".local/share"));
        want.push(tree(home.join(".config/Jan/data/models")));
        want.push(tree(data.join("nomic.ai/GPT4All")));
    }
    let mut out: Vec<Store> = Vec::new();
    for (path, at, depth) in want {
        if path.is_dir() && !out.iter().any(|s| s.path == path) {
            out.push(Store { path, at, depth });
        }
    }
    out
}

/// A hub repo folder's id: `models--org--name` is `org/name`.
pub fn repo_id(dir: &str) -> Option<String> {
    let rest = dir.strip_prefix("models--")?;
    let id = rest.replace("--", "/");
    (!id.is_empty()).then_some(id)
}

/// The path's components under `root`, as strings.
fn parts(root: &Path, p: &Path) -> Vec<String> {
    p.strip_prefix(root)
        .map(|r| r.components().map(|c| c.as_os_str().to_string_lossy().into_owned()).collect())
        .unwrap_or_default()
}

/// A hub cache: each blob by its first bytes, named from the snapshots;
/// the template files in a snapshot that holds a GGUF.
pub fn plan_hub(root: &Path, walk: &[(PathBuf, Vec<String>)], stat: Stats) -> Plan {
    // (repo, rev, path in the rev, the names beside it) for each blob, from
    // the snapshot links; the revision `refs/main` names first.
    struct Named {
        repo: String,
        rev: String,
        rel: String,
        beside: Arc<Vec<String>>,
    }
    let mut named: HashMap<PathBuf, Named> = HashMap::new();
    let mut mains: HashMap<String, String> = HashMap::new();
    let mut ggufs: HashSet<(String, String)> = HashSet::new();
    // (link, repo, rev, path in the rev, the names beside it)
    type Sidecar = (PathBuf, String, String, String, Arc<Vec<String>>);
    let mut sidecars: Vec<Sidecar> = Vec::new();
    let mut blobs: Vec<(PathBuf, String)> = Vec::new();
    for (dir, names) in walk {
        let p = parts(root, dir);
        let Some(repo) = p.first().and_then(|d| repo_id(d)) else { continue };
        match p.get(1).map(String::as_str) {
            Some("blobs") if p.len() == 2 => {
                for n in names.iter().filter(|n| !n.ends_with(".incomplete") && !n.ends_with(".lock")) {
                    blobs.push((dir.join(n), repo.clone()));
                }
            }
            Some("refs") if p.len() == 2 && names.iter().any(|n| n == "main") => {
                if let Ok(rev) = crate::utils::files::read_capped(&dir.join("main"), 256) {
                    mains.insert(repo.clone(), rev.trim().to_string());
                }
            }
            Some("snapshots") if p.len() >= 3 => {
                let rev = p[2].clone();
                let beside = Arc::new(names.clone());
                for n in names {
                    let link = dir.join(n);
                    let rel = p[3..].iter().chain(std::iter::once(n)).cloned().collect::<Vec<_>>().join("/");
                    if n.to_ascii_lowercase().ends_with(".gguf") {
                        ggufs.insert((repo.clone(), rev.clone()));
                    }
                    if matches!(n.as_str(), "tokenizer_config.json" | "chat_template.jinja" | "chat_template.json") {
                        sidecars.push((link.clone(), repo.clone(), rev.clone(), rel.clone(), beside.clone()));
                    }
                    let Ok(target) = std::fs::read_link(&link) else { continue };
                    let blob = dir.join(target);
                    let Some(file) = blob.file_name() else { continue };
                    let blob = root.join(&p[0]).join("blobs").join(file);
                    let better = match named.get(&blob) {
                        None => true,
                        Some(old) => {
                            let main = mains.get(&repo);
                            (main == Some(&rev) && main != Some(&old.rev)) || (main != Some(&old.rev) && rev < old.rev)
                        }
                    };
                    if better {
                        named.insert(
                            blob,
                            Named { repo: repo.clone(), rev: rev.clone(), rel: rel.clone(), beside: beside.clone() },
                        );
                    }
                }
            }
            _ => {}
        }
    }
    let mut plan = Plan { reads: Vec::new(), meta: Vec::new() };
    for (path, repo) in blobs {
        if !stat(&path).is_some_and(|s| s.file && s.size >= super::MIN_GGUF) {
            continue;
        }
        let name = path.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
        let sha256 =
            (name.len() == 64 && name.bytes().all(|b| b.is_ascii_hexdigit())).then(|| name.to_ascii_lowercase());
        let meta = match named.remove(&path) {
            Some(n) => Meta {
                repo: n.repo,
                name: n.rel.rsplit('/').next().unwrap_or("").to_string(),
                sha256,
                beside: n.beside,
            },
            None => Meta { repo, name: name.clone(), sha256, beside: Arc::default() },
        };
        plan.reads.push(read(path, root, role::MODEL, 0));
        plan.meta.push(meta);
    }
    // One sidecar per (repo, path in the revision): the main revision's.
    let mut seen: BTreeMap<(String, String), usize> = BTreeMap::new();
    for (link, repo, rev, rel, beside) in sidecars {
        if !ggufs.contains(&(repo.clone(), rev.clone())) || !stat(&link).is_some_and(|s| s.file) {
            continue;
        }
        let main = mains.get(&repo) == Some(&rev);
        if let Some(&i) = seen.get(&(repo.clone(), rel.clone())) {
            if !main {
                continue;
            }
            plan.reads[i] = read(link, root, role::TEMPLATE_FILE, super::MAX_TEMPLATE_FILE);
            continue;
        }
        seen.insert((repo.clone(), rel.clone()), plan.reads.len());
        plan.reads.push(read(link, root, role::TEMPLATE_FILE, super::MAX_TEMPLATE_FILE));
        plan.meta.push(Meta { repo, name: rel, sha256: None, beside });
    }
    plan
}

/// The most of a manifest read.
const MAX_MANIFEST: u64 = 1 << 20;

/// An Ollama model's name from its manifest's path under `manifests/`:
/// `registry.ollama.ai/library/llama3/8b` is `llama3:8b`.
pub fn ollama_name(p: &[String]) -> String {
    match p {
        [reg, ns, model, tag] if reg == "registry.ollama.ai" && ns == "library" => format!("{model}:{tag}"),
        [reg, ns, model, tag] if reg == "registry.ollama.ai" => format!("{ns}/{model}:{tag}"),
        [reg, ns, model, tag] => format!("{reg}/{ns}/{model}:{tag}"),
        _ => p.join("/"),
    }
}

/// Ollama's model folder: each blob by its first bytes (a template or
/// system layer whole), named by the manifests.
pub fn plan_ollama(root: &Path, walk: &[(PathBuf, Vec<String>)], stat: Stats) -> Plan {
    // blob name -> (model, media type)
    let mut named: HashMap<String, (String, String)> = HashMap::new();
    let mut blobs: Vec<PathBuf> = Vec::new();
    for (dir, names) in walk {
        let p = parts(root, dir);
        match p.first().map(String::as_str) {
            Some("blobs") if p.len() == 1 => blobs.extend(
                names.iter().filter(|n| n.starts_with("sha256-") && !n.ends_with("-partial")).map(|n| dir.join(n)),
            ),
            Some("manifests") => {
                for n in names {
                    let path = dir.join(n);
                    let Ok(bytes) = crate::utils::files::read_capped_bytes(&path, MAX_MANIFEST) else { continue };
                    let Ok(v) = crate::utils::json::parse(&bytes, MAX_MANIFEST as usize) else { continue };
                    let model =
                        ollama_name(&p[1..].iter().cloned().chain(std::iter::once(n.clone())).collect::<Vec<_>>());
                    for layer in crate::utils::json::arr_at(&v, "layers") {
                        let digest = crate::utils::json::str_at(layer, "digest");
                        let media = crate::utils::json::str_at(layer, "mediaType");
                        if let Some(hex) = digest.strip_prefix("sha256:") {
                            named.entry(format!("sha256-{hex}")).or_insert_with(|| (model.clone(), media.to_string()));
                        }
                    }
                }
            }
            _ => {}
        }
    }
    let mut plan = Plan { reads: Vec::new(), meta: Vec::new() };
    blobs.sort();
    for path in blobs {
        let Some(s) = stat(&path).filter(|s| s.file) else { continue };
        let name = path.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
        let hex = name.strip_prefix("sha256-").unwrap_or("");
        let sha256 = (hex.len() == 64 && hex.bytes().all(|b| b.is_ascii_hexdigit())).then(|| hex.to_ascii_lowercase());
        let (model, media) = named.get(&name).cloned().unwrap_or_default();
        let (r, cap) = match media.as_str() {
            "application/vnd.ollama.image.template" => (role::OLLAMA_TEMPLATE, super::sidecars::MAX_MODELFILE),
            "application/vnd.ollama.image.system" => (role::OLLAMA_SYSTEM, super::sidecars::MAX_MODELFILE),
            _ if s.size >= super::MIN_GGUF => (role::MODEL, 0),
            _ => continue,
        };
        plan.reads.push(read(path, root, r, cap));
        plan.meta.push(Meta { repo: model, name, sha256, beside: Arc::default() });
    }
    plan
}

#[cfg(test)]
#[path = "stores_tests.rs"]
mod tests;
