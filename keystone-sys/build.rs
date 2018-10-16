use std::{env, path};

static KEYSTONE_C: &'static str = "keystone-c";
static KEYSTONE_LIB: &'static str = "keystone";

fn build_keystone() {
    let mut cmake_config = cmake::Config::new(KEYSTONE_C);
    cmake_config
        .define("BUILD_SHARED_LIBS", "OFF")
        .define("CMAKE_INSTALL_LIBDIR", "lib64")
        .define("CMAKE_BUILD_TYPE", "Release");

    #[cfg(target_family = "windows")]
    cmake_config.generator("NMake Makefiles");

    #[cfg(target_family = "unix")]
    cmake_config.generator("Unix Makefiles");

    let compiled_ouput_path = cmake_config.build();

    println!(
        "cargo:rustc-link-search={}={}/lib64",
        "native",
        compiled_ouput_path.display()
    );
    println!("cargo:rustc-link-lib={}={}", "static", KEYSTONE_LIB);

    #[cfg(target_family = "unix")]
    println!("cargo:rustc-link-lib=dylib=stdc++");
}

fn generate_binding(out_dir_path: &path::Path, ks_path: &path::Path) {
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

    let ks_path = {
        let crate_dir = env::var("CARGO_MANIFEST_DIR").unwrap();
        let path = path::PathBuf::from(&crate_dir).join(KEYSTONE_C);
        if !path.exists() {
            panic!("Cannot found Keystone source directory");
        }
        path
    };

    println!("cargo:rerun-if-changed={}", KEYSTONE_C);

    generate_binding(&out_dir_path, &ks_path);
    build_keystone();
}
