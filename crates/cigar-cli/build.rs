//! Generates the immutable Claude Code plugin payload embedded by the installed CLI.

use std::ffi::OsStr;
use std::fmt::Write as _;
use std::fs;
use std::path::{Path, PathBuf};

fn collect_files(
    directory: &Path,
    files: &mut Vec<PathBuf>,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut entries = fs::read_dir(directory)?.collect::<Result<Vec<_>, _>>()?;
    entries.sort_by_key(fs::DirEntry::file_name);
    for entry in entries {
        let path = entry.path();
        let metadata = fs::symlink_metadata(&path)?;
        if metadata.file_type().is_symlink() {
            return Err(format!(
                "Claude plugin source contains a symlink: {}",
                path.display()
            )
            .into());
        }
        if metadata.is_dir() {
            collect_files(&path, files)?;
        } else if metadata.is_file() {
            if path.file_name() != Some(OsStr::new("package-manifest.json")) {
                files.push(path);
            }
        } else {
            return Err(format!(
                "Claude plugin source contains a special file: {}",
                path.display()
            )
            .into());
        }
    }
    Ok(())
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let manifest_directory = PathBuf::from(
        std::env::var_os("CARGO_MANIFEST_DIR").ok_or("CARGO_MANIFEST_DIR is unavailable")?,
    );
    let plugin_root = manifest_directory.join("../../adapters/claude-code");
    let plugin_root = plugin_root.canonicalize()?;
    println!("cargo:rerun-if-changed={}", plugin_root.display());

    let mut files = Vec::new();
    collect_files(&plugin_root, &mut files)?;
    files.sort();
    if files.is_empty() {
        return Err("Claude plugin embedded source inventory is empty".into());
    }

    let mut generated =
        String::from("pub(crate) const EMBEDDED_PACKAGE_FILES: &[(&str, &[u8])] = &[\n");
    for path in files {
        let relative = path
            .strip_prefix(&plugin_root)?
            .to_str()
            .ok_or("Claude plugin source path is not UTF-8")?
            .replace('\\', "/");
        if relative.is_empty()
            || relative.starts_with('/')
            || relative
                .split('/')
                .any(|segment| segment.is_empty() || matches!(segment, "." | ".."))
        {
            return Err(format!("Claude plugin source path is unsafe: {relative}").into());
        }
        println!("cargo:rerun-if-changed={}", path.display());
        writeln!(
            generated,
            "    ({relative:?}, include_bytes!(concat!(env!(\"CARGO_MANIFEST_DIR\"), \"/../../adapters/claude-code/\", {relative:?}))),"
        )?;
    }
    generated.push_str("];\n");

    let output = PathBuf::from(std::env::var_os("OUT_DIR").ok_or("OUT_DIR is unavailable")?)
        .join("embedded_claude_plugin.rs");
    fs::write(output, generated)?;
    Ok(())
}
