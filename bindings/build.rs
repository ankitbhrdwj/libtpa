use std::env;
use std::fs::canonicalize;
use std::path::{Path, PathBuf};

use anyhow::Context;

fn rerun_if_changed(root_dir: &Path) -> anyhow::Result<()> {
    build_deps::rerun_if_changed_paths(
        canonicalize("./bindings.h")
            .context("canonicalize error")?
            .to_str()
            .unwrap(),
    )
    .map_err(|e| anyhow::anyhow!("failed to add rerun command: {:?}", e))?;

    let inc_glob = format!("{}/include/**", root_dir.to_str().unwrap());
    build_deps::rerun_if_changed_paths(&inc_glob)
        .map_err(|e| anyhow::anyhow!("failed to add rerun command: {:?}", e))?;

    let static_lib_glob = format!("{}/build/*.a", root_dir.to_str().unwrap());
    build_deps::rerun_if_changed_paths(&static_lib_glob)
        .map_err(|e| anyhow::anyhow!("failed to add rerun command: {:?}", e))?;
    Ok(())
}

fn linker_arguments(root_dir: &Path) -> anyhow::Result<()> {
    let mut static_libs = vec![];
    let mut dyn_libs = vec![];

    // Add search paths for libraries ibverbs, mlx4, mlx5
    let rdma_core_path = root_dir.join("build/rdma-core/build/lib");
    let mut search_paths = vec![rdma_core_path, "/usr/lib/x86_64-linux-gnu/".into()];

    let output = pkg_config::Config::new()
        .atleast_version("v1.0")
        .statik(true)
        .probe("libtpa")
        .unwrap();

    for path in output.link_paths {
        search_paths.push(path);
    }

    // Distinguish between static and dynamic libraries
    for lib in output.libs {
        if lib.starts_with(":") {
            static_libs.push(lib.replace(":lib", "").replace(".a", ""));
        } else if lib == "mlx5" || lib == "ibverbs" || lib == "mlx4" {
            static_libs.push(lib);
        } else {
            dyn_libs.push(lib);
        }
    }

    // Set cargo flags to link with these libraries
    for search_path in &search_paths {
        println!("cargo:rustc-link-search={}", search_path.to_str().unwrap());
    }

    for static_lib in &static_libs {
        if static_lib == "tpa" {
            println!("cargo:rustc-link-lib=static:+whole-archive={}", &static_lib);
        } else {
            println!("cargo:rustc-link-lib=static={}", &static_lib);
        }
    }

    for dyn_lib in &dyn_libs {
        println!("cargo:rustc-link-lib={}", dyn_lib);
    }

    Ok(())
}

fn generate_bindings(_root_dir: &Path) -> anyhow::Result<()> {
    let bindings = bindgen::Builder::default()
        .clang_arg("-I/usr/share/tpa")
        .header("bindings.h")
        .blocklist_function("q.cvt(_r)?")
        .blocklist_function("strtold")
        .generate_comments(false)
        .generate()?;

    let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());
    bindings.write_to_file(out_path.join("tpa.rs"))?;
    Ok(())
}

fn main() -> anyhow::Result<()> {
    let root_dir = canonicalize("../").context("failed to canonicalize root dir")?;
    rerun_if_changed(&root_dir)?;
    #[cfg(feature = "standalone")]
    linker_arguments(&root_dir)?;
    generate_bindings(&root_dir)?;
    Ok(())
}
