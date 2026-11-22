//! Compile every rules file in a directory, or read a compiled bundle, and
//! print what loaded and how long it took:
//! `compile_rules DIR [--write FILE | --read FILE]`. `mise run yara-bench`
//! runs it for time and peak memory.
fn main() {
    let args: Vec<String> = std::env::args().collect();
    let t = std::time::Instant::now();
    let mut c = wpantry_yara::Compiler::new();
    if args.get(2).map(String::as_str) == Some("--read") {
        let data = std::fs::read(&args[3]).unwrap();
        c.add_bundle(&data).unwrap();
    } else {
        c.record();
        let mut files: Vec<_> = std::fs::read_dir(&args[1])
            .unwrap()
            .flatten()
            .map(|e| e.path())
            .filter(|p| p.extension().is_some_and(|e| e == "yar"))
            .collect();
        files.sort();
        for f in files {
            let src = std::fs::read_to_string(&f).unwrap();
            c.add_source(&f.file_stem().unwrap().to_string_lossy(), &src, wpantry_yara::Syntax::Relaxed);
        }
        if args.get(2).map(String::as_str) == Some("--write") {
            std::fs::write(&args[3], c.bundle().unwrap()).unwrap();
        }
    }
    let r = c.build();
    eprintln!("{:?} in {:?}", r.stats(), t.elapsed());
}
