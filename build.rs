extern crate bindgen;

fn main() {
    println!("cargo:rustc-link-lib=keystone");

    let bindings = bindgen::Builder::default()
        .header("keystone-c/include/keystone/keystone.h")
        .prepend_enum_name(false)
        .generate()
        .expect("Could not generate binding for keystone");

    let outpath = std::path::PathBuf::from(std::env::var("OUT_DIR").unwrap());

    bindings.write_to_file(outpath.join("bindings.rs"))
        .expect("Couldn't write bindings!");
}