// Licensed under the Apache-2.0 license

fn main() {
    if cfg!(not(feature = "std")) {
        use std::env;
        use std::fs;
        use std::path::PathBuf;

        let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());
        fs::write(out_dir.join("rom.ld"), include_bytes!("src/rom.ld")).unwrap();

        println!("cargo:rustc-link-search={}", out_dir.display());
        println!("cargo:rustc-link-arg=-Trom.ld");
        println!("cargo:rerun-if-changed=src/rom.ld");
        println!("cargo:rerun-if-changed=build.rs");
    }
}
