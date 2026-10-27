//! Print this machine's OS packages as wscanner reads them:
//! `cargo run --example osdb`.

fn main() {
    let rel = wscanner::system::os_release();
    println!("# ecosystem: {:?}", wscanner::osdb::ecosystem(&rel));
    match wscanner::osdb::installed(&rel) {
        Ok(Some((from, pkgs))) => {
            println!("# from {from}");
            for p in pkgs {
                println!("{} {}", p.name, p.version);
            }
        }
        Ok(None) => println!("# no package database"),
        Err(e) => println!("# error: {e}"),
    }
}
