use super::*;
use crate::checks::models::testing::{CHATML, Gguf, TRIGGERED_DOWNLOAD};
use crate::checks::models::{Level, What, ids, scan_dir};
use crate::utils::temp::TempDir;

fn write(p: &Path, b: impl AsRef<[u8]>) {
    std::fs::create_dir_all(p.parent().unwrap()).unwrap();
    std::fs::write(p, b).unwrap();
}

#[test]
fn stores_are_found_where_the_environment_says() {
    let d = TempDir::new("stores").unwrap();
    let home = d.path().join("home");
    for p in [".cache/huggingface/hub", ".ollama/models", ".lmstudio/models", "elsewhere/hub", "ollama2"] {
        std::fs::create_dir_all(home.join(p)).unwrap();
    }
    let none = |_: &str| None;
    let found = stores(&home, &none);
    assert_eq!(found[0], Store { path: home.join(".cache/huggingface/hub"), at: Where::Hub, depth: 12 });
    assert_eq!(found[1].at, Where::Ollama);
    assert_eq!(found[2], Store { path: home.join(".lmstudio/models"), at: Where::Tree, depth: 8 });
    assert_eq!(found.len(), 3, "folders that don't exist aren't stores");
    let h = home.clone();
    let set = move |k: &str| match k {
        "HF_HUB_CACHE" => Some(h.join("elsewhere/hub").to_string_lossy().into_owned()),
        "OLLAMA_MODELS" => Some(h.join("ollama2").to_string_lossy().into_owned()),
        _ => None,
    };
    let found = stores(&home, &set);
    assert_eq!(found[0].path, home.join("elsewhere/hub"));
    assert_eq!(found[1].path, home.join("ollama2"));
    assert_eq!(env("HOME"), None, "a test never reads the real environment");
}

#[test]
fn names_from_the_stores_layout() {
    assert_eq!(repo_id("models--org--name").as_deref(), Some("org/name"));
    assert_eq!(repo_id("datasets--org--name"), None);
    let p = |v: &[&str]| v.iter().map(|s| s.to_string()).collect::<Vec<_>>();
    assert_eq!(ollama_name(&p(&["registry.ollama.ai", "library", "llama3", "8b"])), "llama3:8b");
    assert_eq!(ollama_name(&p(&["registry.ollama.ai", "me", "m", "latest"])), "me/m:latest");
    assert_eq!(ollama_name(&p(&["hf.co", "org", "m", "q4"])), "hf.co/org/m:q4");
    assert_eq!(ollama_name(&p(&["odd"])), "odd");
}

/// A hub cache: the blob is named by its snapshot link (the main
/// revision's), carries its SHA-256 from its name, and the template file
/// beside the GGUF is read; a snapshot with no GGUF has its sidecar left.
#[cfg(unix)]
#[test]
fn a_hub_cache_names_its_blobs_and_reads_their_templates() {
    let d = TempDir::new("hub").unwrap();
    let hub = d.path().join("hub");
    let repo = hub.join("models--org--chat-GGUF");
    let sha = "ab".repeat(32);
    write(&repo.join("blobs").join(&sha), Gguf::with_template(CHATML).bytes());
    write(
        &repo.join("blobs/0123456789abcdef0123456789abcdef01234567"),
        serde_json::json!({"chat_template": TRIGGERED_DOWNLOAD}).to_string(),
    );
    write(&repo.join("blobs/partial.incomplete"), b"GGUF partial");
    write(&repo.join("refs/main"), "rev2\n");
    for rev in ["rev1", "rev2"] {
        let snap = repo.join("snapshots").join(rev);
        std::fs::create_dir_all(snap.join("q4")).unwrap();
        std::os::unix::fs::symlink(format!("../../../blobs/{sha}"), snap.join(format!("q4/chat-{rev}.gguf"))).unwrap();
        std::os::unix::fs::symlink(
            "../../blobs/0123456789abcdef0123456789abcdef01234567",
            snap.join("tokenizer_config.json"),
        )
        .unwrap();
    }
    let other = hub.join("models--org--plain");
    write(&other.join("blobs/cafe"), b"{\"chat_template\": \"[SYSTEM DIRECTIVE]\"}");
    std::fs::create_dir_all(other.join("snapshots/r")).unwrap();
    std::os::unix::fs::symlink("../../blobs/cafe", other.join("snapshots/r/tokenizer_config.json")).unwrap();

    let found = scan_dir(Where::Hub, &hub, 12);
    assert_eq!(found.len(), 2, "{found:#?}");
    let model = found.iter().find(|m| m.result.what == What::Gguf).unwrap();
    assert_eq!((model.meta.repo.as_str(), model.meta.name.as_str()), ("org/chat-GGUF", "chat-rev2.gguf"));
    assert_eq!(model.meta.sha256.as_deref(), Some(sha.as_str()));
    assert_eq!(model.result.issues, []);
    let side = found.iter().find(|m| m.result.what == What::Template).unwrap();
    assert_eq!((side.meta.repo.as_str(), side.meta.name.as_str()), ("org/chat-GGUF", "tokenizer_config.json"));
    assert!(side.path.ends_with("snapshots/rev2/tokenizer_config.json"), "the main revision's");
    assert_eq!(side.result.issues[0].level, Level::Fail);
}

/// Ollama: blobs by magic, the template and system layers whole, each
/// named by its manifest.
#[test]
fn ollama_blobs_are_named_by_their_manifests() {
    let d = TempDir::new("ollama").unwrap();
    let root = d.path().join("models");
    let hex = |c: char| c.to_string().repeat(64);
    write(&root.join(format!("blobs/sha256-{}", hex('a'))), Gguf::default().bytes());
    write(&root.join(format!("blobs/sha256-{}", hex('b'))), b"{{ .Prompt }} [SYSTEM DIRECTIVE]");
    write(&root.join(format!("blobs/sha256-{}", hex('c'))), b"You are helpful.");
    write(&root.join(format!("blobs/sha256-{}", hex('d'))), b"{\"license\": \"x\"} and more bytes than 24");
    write(&root.join(format!("blobs/sha256-{}-partial", hex('e'))), b"GGUF");
    let layer = |m: &str, c: char| serde_json::json!({"mediaType": m, "digest": format!("sha256:{}", hex(c))});
    let manifest = serde_json::json!({"layers": [
        layer("application/vnd.ollama.image.model", 'a'),
        layer("application/vnd.ollama.image.template", 'b'),
        layer("application/vnd.ollama.image.system", 'c'),
        layer("application/vnd.ollama.image.license", 'd'),
    ]});
    write(&root.join("manifests/registry.ollama.ai/library/tiny/latest"), manifest.to_string());
    write(&root.join("manifests/registry.ollama.ai/library/broken/latest"), "not json");
    let found = scan_dir(Where::Ollama, &root, 6);
    assert_eq!(found.len(), 3, "{found:#?}");
    assert!(found.iter().all(|m| m.meta.repo == "tiny:latest"));
    let model = found.iter().find(|m| m.result.what == What::Gguf).unwrap();
    assert_eq!(model.meta.sha256, Some(hex('a')));
    let template = found.iter().find(|m| m.path.ends_with(format!("sha256-{}", hex('b')))).unwrap();
    assert_eq!(template.result.issues[0].id, ids::INJECTION);
    let system = found.iter().find(|m| m.path.ends_with(format!("sha256-{}", hex('c')))).unwrap();
    assert_eq!(system.result.issues, []);
}
