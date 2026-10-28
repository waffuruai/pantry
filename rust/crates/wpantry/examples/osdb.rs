//! Print this machine's OS packages as wpantry reads them:
//! `cargo run --example osdb`.

fn main() {
    let rel = wpantry::system::os_release();
    println!("# ecosystem: {:?}", wpantry::osdb::ecosystem(&rel));
    match wpantry::osdb::installed(&rel) {
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
