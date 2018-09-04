#[cfg(target_os = "linux")]
extern crate pkg_config;

extern crate bindgen;
extern crate cmake;

use std::{env, path};

static KEYSTONE_C: &'static str = "keystone-c";

#[cfg(target_os = "windows")]
fn build_keystone(out_dir_path: &path::Path) {
    println!("cargo:rerun-if-changed={}", KEYSTONE_C);

    // manually check if Keystone has been built
    let keystone_built_dir = out_dir_path.join("lib");
    if keystone_built_dir.exists() {
        if keystone_built_dir.join("keystone.dll").exists()
            && keystone_built_dir.join("keystone.lib").exists()
        {
            return;
        }
    }

    // build Keystone
    let ks_builder = cmake::Config::new(KEYSTONE_C)
        .define("BUILD_SHARED_LIBS", "ON")
        .generator("NMake Makefiles")
        .build();

    println!("cargo:rust-link-search=native={}/lib", ks_builder.display());
    println!("cargo:rustc-link-lib=dylib=keystone");
}

fn generate_binding(out_dir_path: &path::Path) {
    let ks_path = {
        let path = path::PathBuf::from(KEYSTONE_C);
        if !path.exists() {
            panic!("Keystone source directory does not exist");
        }
        path
    };

    let ks_header_path = {
        let path = ks_path.join("include").join("keystone").join("keystone.h");
        if !path.exists() {
            panic!("Cannot found Keystone C header");
        }
        path
    };

    let ks_binder = bindgen::Builder::default()
        .header(ks_header_path.to_string_lossy())
        .prepend_enum_name(false)
        .rustified_enum("*")
        .generate()
        .expect("Cannot generate Keystone bindings");

    ks_binder
        .write_to_file(out_dir_path.join("bindings.rs"))
        .expect("Cannot write Keystone bindings");
}

fn main() {
    let out_dir_path = {
        let out_dir = env::var("OUT_DIR")
            .unwrap_or_else(|_| panic!("Cannot get value of OUT_DIR environment variable"));
        path::PathBuf::from(out_dir)
    };

    #[cfg(target_os = "windows")]
    build_keystone(&out_dir_path);

    #[cfg(target_os = "linux")]
    pkg_config::Config::new()
        .atleast_version("0.9")
        .probe("keystone")
        .unwrap_or_else(|_| panic!("Cannot probe Keystone library"));

    generate_binding(&out_dir_path);
}
