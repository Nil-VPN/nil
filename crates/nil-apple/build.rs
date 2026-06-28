//! Generate the C header (`include/nil_apple.h`) that the Swift bridging header imports.
//! `write_to_file` is a no-op when the content is unchanged, so this won't churn the tree.

fn main() {
    println!("cargo:rerun-if-changed=src/lib.rs");
    let crate_dir = std::env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR");
    let cfg = cbindgen::Config {
        language: cbindgen::Language::C,
        pragma_once: true,
        cpp_compat: true, // wrap in extern "C" for the Swift/Obj-C bridge
        ..Default::default()
    };
    if let Ok(bindings) = cbindgen::Builder::new().with_crate(&crate_dir).with_config(cfg).generate() {
        let _ = std::fs::create_dir_all(format!("{crate_dir}/include"));
        bindings.write_to_file(format!("{crate_dir}/include/nil_apple.h"));
    }
}
