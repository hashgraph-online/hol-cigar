//! Bounded digest helpers for binaries, vector trees, and result documents.

use crate::model::ConformanceResult;
use sha2::{Digest as _, Sha256};
use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::fs::{self, File};
use std::io::{self, Read};
use std::path::{Component, Path, PathBuf};

const MAX_DIGEST_FILE_BYTES: u64 = 128 * 1024 * 1024;
const MAX_VECTOR_FILES: usize = 64;
const MAX_VECTOR_BYTES: u64 = 8 * 1024 * 1024;

/// Immutable in-memory view of one bounded vector directory read in the same pass as its digest.
pub struct DirectorySnapshot {
    /// Digest of every captured relative path and byte.
    pub digest: String,
    files: BTreeMap<String, Vec<u8>>,
}

impl DirectorySnapshot {
    /// Returns one exact captured file by normalized relative path.
    pub fn file(&self, relative: &str) -> Result<&[u8], String> {
        self.files
            .get(relative)
            .map(Vec::as_slice)
            .ok_or_else(|| format!("vector snapshot lacks `{relative}`"))
    }
}

/// Returns a lower-case SHA-256 digest with an explicit algorithm prefix.
#[must_use]
pub fn sha256(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    format!("sha256:{}", lower_hex(&hasher.finalize()))
}

/// Hashes one bounded regular file without following a final symlink.
pub fn hash_file(path: &Path) -> Result<String, String> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| format!("cannot inspect digest input: {error}"))?;
    if !metadata.file_type().is_file() || metadata.len() > MAX_DIGEST_FILE_BYTES {
        return Err("digest input must be a bounded regular file".to_owned());
    }
    let mut file =
        File::open(path).map_err(|error| format!("cannot open digest input: {error}"))?;
    let mut remaining = metadata.len();
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    while remaining > 0 {
        let limit = usize::try_from(remaining.min(buffer.len() as u64))
            .map_err(|_error| "digest length conversion failed".to_owned())?;
        let window = buffer
            .get_mut(..limit)
            .ok_or_else(|| "digest read window exceeded buffer".to_owned())?;
        let read = file
            .read(window)
            .map_err(|error| format!("cannot read digest input: {error}"))?;
        if read == 0 {
            return Err("digest input changed while being read".to_owned());
        }
        let bytes = buffer
            .get(..read)
            .ok_or_else(|| "digest read exceeded buffer".to_owned())?;
        hasher.update(bytes);
        remaining = remaining.saturating_sub(read as u64);
    }
    let mut extra = [0_u8; 1];
    if file
        .read(&mut extra)
        .map_err(|error| format!("cannot finish digest input: {error}"))?
        != 0
    {
        return Err("digest input grew while being read".to_owned());
    }
    Ok(format!("sha256:{}", lower_hex(&hasher.finalize())))
}

/// Hashes the exact relative paths and contents of a small immutable vector tree.
pub fn hash_directory(root: &Path) -> Result<String, String> {
    Ok(snapshot_directory(root)?.digest)
}

/// Reads and hashes a complete bounded vector tree into an immutable snapshot.
pub fn snapshot_directory(root: &Path) -> Result<DirectorySnapshot, String> {
    let root_metadata = fs::symlink_metadata(root)
        .map_err(|error| format!("cannot inspect vector directory: {error}"))?;
    if !root_metadata.file_type().is_dir() {
        return Err("vector root must be a real directory".to_owned());
    }
    let mut files = Vec::new();
    collect_files(root, root, &mut files)?;
    files.sort();
    if files.is_empty() || files.len() > MAX_VECTOR_FILES {
        return Err("vector directory has an invalid file count".to_owned());
    }

    let mut total = 0_u64;
    let mut hasher = Sha256::new();
    let mut captured = BTreeMap::new();
    hasher.update(b"CIGAR-CONFORMANCE-VECTORS\0v1\0");
    for relative in files {
        let path = root.join(&relative);
        let metadata = fs::symlink_metadata(&path)
            .map_err(|error| format!("cannot inspect vector file: {error}"))?;
        if !metadata.file_type().is_file() {
            return Err("vector tree contains a non-regular file".to_owned());
        }
        total = total
            .checked_add(metadata.len())
            .ok_or_else(|| "vector byte count overflow".to_owned())?;
        if total > MAX_VECTOR_BYTES {
            return Err("vector directory exceeds the published size bound".to_owned());
        }
        let relative_text = relative
            .to_str()
            .ok_or_else(|| "vector path must be valid UTF-8".to_owned())?
            .replace(std::path::MAIN_SEPARATOR, "/");
        frame(&mut hasher, relative_text.as_bytes());
        let bytes = read_exact_bounded(&path, metadata.len(), MAX_VECTOR_BYTES)?;
        frame(&mut hasher, &bytes);
        if captured.insert(relative_text, bytes).is_some() {
            return Err("vector snapshot contains a duplicate normalized path".to_owned());
        }
    }
    Ok(DirectorySnapshot {
        digest: format!("sha256:{}", lower_hex(&hasher.finalize())),
        files: captured,
    })
}

fn collect_files(root: &Path, current: &Path, files: &mut Vec<PathBuf>) -> Result<(), String> {
    let mut entries = fs::read_dir(current)
        .map_err(|error| format!("cannot enumerate vector directory: {error}"))?
        .collect::<Result<Vec<_>, io::Error>>()
        .map_err(|error| format!("cannot enumerate vector directory: {error}"))?;
    entries.sort_by_key(std::fs::DirEntry::file_name);
    for entry in entries {
        let path = entry.path();
        let metadata = fs::symlink_metadata(&path)
            .map_err(|error| format!("cannot inspect vector entry: {error}"))?;
        if metadata.file_type().is_symlink() {
            return Err("vector tree may not contain symbolic links".to_owned());
        }
        if metadata.file_type().is_dir() {
            collect_files(root, &path, files)?;
        } else if metadata.file_type().is_file() {
            let relative = path
                .strip_prefix(root)
                .map_err(|_error| "vector path escaped its root".to_owned())?
                .to_path_buf();
            if relative.components().any(|component| {
                matches!(
                    component,
                    Component::ParentDir | Component::RootDir | Component::Prefix(_)
                )
            }) {
                return Err("vector path is not relative".to_owned());
            }
            files.push(relative);
            if files.len() > MAX_VECTOR_FILES {
                return Err("vector directory has too many files".to_owned());
            }
        } else {
            return Err("vector tree may contain only files and directories".to_owned());
        }
    }
    Ok(())
}

fn read_exact_bounded(path: &Path, length: u64, bound: u64) -> Result<Vec<u8>, String> {
    if length > bound {
        return Err("bounded file is too large".to_owned());
    }
    let capacity = usize::try_from(length)
        .map_err(|_error| "bounded file length does not fit memory".to_owned())?;
    let mut bytes = Vec::with_capacity(capacity);
    File::open(path)
        .and_then(|file| file.take(bound.saturating_add(1)).read_to_end(&mut bytes))
        .map_err(|error| format!("cannot read bounded file: {error}"))?;
    if bytes.len() as u64 != length {
        return Err("bounded file changed while being read".to_owned());
    }
    Ok(bytes)
}

fn frame(hasher: &mut Sha256, bytes: &[u8]) {
    hasher.update((bytes.len() as u64).to_be_bytes());
    hasher.update(bytes);
}

/// Computes the self-binding digest of a result with `result_digest` omitted.
pub fn result_digest(result: &ConformanceResult) -> Result<String, String> {
    let mut value = serde_json::to_value(result)
        .map_err(|error| format!("cannot serialize result for digest: {error}"))?;
    let object = value
        .as_object_mut()
        .ok_or_else(|| "result serialization was not an object".to_owned())?;
    object.remove("result_digest");
    let bytes = serde_json::to_vec(&value)
        .map_err(|error| format!("cannot serialize result for digest: {error}"))?;
    Ok(sha256(&bytes))
}

/// Returns whether a string is a canonical SHA-256 digest.
#[must_use]
pub fn valid_sha256(value: &str) -> bool {
    value
        .strip_prefix("sha256:")
        .is_some_and(|hex| valid_lower_hex(hex, 64))
}

/// Returns whether a public digest is SHA-256 or a v1 SHA-256 multihash.
#[must_use]
pub fn valid_public_digest(value: &str) -> bool {
    valid_sha256(value) || valid_lower_hex(value, 68) && value.starts_with("1220")
}

fn valid_lower_hex(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn lower_hex(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        let _result = write!(&mut output, "{byte:02x}");
    }
    output
}
