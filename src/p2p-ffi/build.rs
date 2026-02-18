fn main() {
    let crate_dir = std::env::var("CARGO_MANIFEST_DIR").unwrap();

    let config = cbindgen::Config::from_file(format!("{}/../../../cbindgen.toml", crate_dir))
        .unwrap_or_default();

    match cbindgen::Builder::new()
        .with_crate(&crate_dir)
        .with_config(config)
        .generate()
    {
        Ok(bindings) => {
            bindings.write_to_file(format!("{}/include/p2p.h", crate_dir));
        }
        Err(e) => {
            eprintln!("cbindgen warning: {}", e);
            // Don't fail the build if cbindgen can't parse yet
        }
    }
}
