//! Verified immutable frontend assets.

use serde::Deserialize;
use sha2::{Digest as _, Sha256};
use std::collections::BTreeMap;
use std::fmt;
use std::fs;
use std::path::{Component, Path};
use std::sync::Arc;

const ASSET_MANIFEST_VERSION: &str = "cigar.dashboard-asset-manifest.v1";
const MANIFEST_FILE: &str = "asset-manifest.v1.json";
const MAX_MANIFEST_BYTES: u64 = 1024 * 1024;
const MAX_ASSET_FILES: usize = 1024;
const MAX_ASSET_BYTES: u64 = 16 * 1024 * 1024;
const MAX_TOTAL_BYTES: u64 = 64 * 1024 * 1024;

/// Stable content-free static-asset failure category.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AssetError {
    /// The root, manifest, or an asset was missing or not a regular file.
    Unavailable,
    /// The manifest was malformed, duplicated, unsorted, or unsupported.
    InvalidManifest,
    /// An asset path or media type was not in the closed safe profile.
    InvalidAsset,
    /// An asset byte count or aggregate exceeded its bound.
    LimitExceeded,
    /// An asset did not match its declared SHA-256 digest.
    DigestMismatch,
}

impl fmt::Display for AssetError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Unavailable => "dashboard assets are unavailable",
            Self::InvalidManifest => "dashboard asset manifest is invalid",
            Self::InvalidAsset => "dashboard asset path or media type is invalid",
            Self::LimitExceeded => "dashboard asset limit was exceeded",
            Self::DigestMismatch => "dashboard asset digest does not match",
        })
    }
}

impl std::error::Error for AssetError {}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AssetManifest {
    schema_version: String,
    files: Vec<AssetManifestEntry>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AssetManifestEntry {
    path: String,
    sha256: String,
    size: u64,
    media_type: String,
}

/// One verified immutable frontend response body.
#[derive(Clone)]
pub struct VerifiedAsset {
    bytes: Arc<[u8]>,
    media_type: &'static str,
    digest: [u8; 32],
}

impl VerifiedAsset {
    /// Returns the immutable verified bytes.
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Returns the closed exact HTTP media type.
    #[must_use]
    pub const fn media_type(&self) -> &'static str {
        self.media_type
    }

    /// Returns the SHA-256 identity used for a strong ETag.
    #[must_use]
    pub const fn digest(&self) -> &[u8; 32] {
        &self.digest
    }

    /// Returns a quoted strong SHA-256 HTTP entity tag.
    #[must_use]
    pub fn etag(&self) -> String {
        format!("\"{}\"", hex_digest(&self.digest))
    }
}

impl fmt::Debug for VerifiedAsset {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("VerifiedAsset")
            .field("bytes", &self.bytes.len())
            .field("media_type", &self.media_type)
            .field("sha256", &hex_digest(&self.digest))
            .finish()
    }
}

/// Complete verified frontend asset set retained immutably in memory.
#[derive(Clone, Debug)]
pub struct StaticAssets {
    files: Arc<BTreeMap<String, VerifiedAsset>>,
    total_bytes: u64,
}

impl StaticAssets {
    /// Loads and verifies a strict manifest plus every referenced asset before serving begins.
    pub fn load(root: &Path) -> Result<Self, AssetError> {
        if !root.is_absolute() {
            return Err(AssetError::InvalidAsset);
        }
        let root_metadata = fs::symlink_metadata(root).map_err(|_error| AssetError::Unavailable)?;
        if !root_metadata.is_dir() || root_metadata.file_type().is_symlink() {
            return Err(AssetError::Unavailable);
        }
        let manifest_path = root.join(MANIFEST_FILE);
        let metadata = regular_file_metadata(&manifest_path)?;
        if metadata.len() == 0 || metadata.len() > MAX_MANIFEST_BYTES {
            return Err(AssetError::LimitExceeded);
        }
        let source = fs::read(&manifest_path).map_err(|_error| AssetError::Unavailable)?;
        let manifest: AssetManifest =
            serde_json::from_slice(&source).map_err(|_error| AssetError::InvalidManifest)?;
        if manifest.schema_version != ASSET_MANIFEST_VERSION
            || manifest.files.is_empty()
            || manifest.files.len() > MAX_ASSET_FILES
        {
            return Err(AssetError::InvalidManifest);
        }
        let mut files = BTreeMap::new();
        let mut total_bytes = 0_u64;
        let mut previous = None;
        for entry in manifest.files {
            validate_asset_path(&entry.path)?;
            if previous.as_ref().is_some_and(|prior| prior >= &entry.path) {
                return Err(AssetError::InvalidManifest);
            }
            previous = Some(entry.path.clone());
            let media_type = expected_media_type(&entry.path).ok_or(AssetError::InvalidAsset)?;
            if media_type != entry.media_type {
                return Err(AssetError::InvalidAsset);
            }
            if entry.size == 0 || entry.size > MAX_ASSET_BYTES {
                return Err(AssetError::LimitExceeded);
            }
            total_bytes = total_bytes
                .checked_add(entry.size)
                .filter(|total| *total <= MAX_TOTAL_BYTES)
                .ok_or(AssetError::LimitExceeded)?;
            let asset_path = root.join(&entry.path);
            let asset_metadata = regular_file_metadata(&asset_path)?;
            if asset_metadata.len() != entry.size {
                return Err(AssetError::DigestMismatch);
            }
            let bytes = fs::read(asset_path).map_err(|_error| AssetError::Unavailable)?;
            let digest: [u8; 32] = Sha256::digest(&bytes).into();
            if hex_digest(&digest) != entry.sha256 {
                return Err(AssetError::DigestMismatch);
            }
            files.insert(
                entry.path,
                VerifiedAsset {
                    bytes: Arc::from(bytes),
                    media_type,
                    digest,
                },
            );
        }
        if !files.contains_key("index.html") {
            return Err(AssetError::InvalidManifest);
        }
        Ok(Self {
            files: Arc::new(files),
            total_bytes,
        })
    }

    /// Returns one exact manifest-listed asset.
    #[must_use]
    pub fn get(&self, path: &str) -> Option<&VerifiedAsset> {
        self.files.get(path)
    }

    /// Returns the verified SPA entry document.
    #[must_use]
    pub fn index(&self) -> &VerifiedAsset {
        self.files
            .get("index.html")
            .unwrap_or_else(|| unreachable_verified_index())
    }

    /// Returns the exact verified asset count.
    #[must_use]
    pub fn file_count(&self) -> usize {
        self.files.len()
    }

    /// Returns the aggregate immutable byte count.
    #[must_use]
    pub const fn total_bytes(&self) -> u64 {
        self.total_bytes
    }
}

fn unreachable_verified_index() -> &'static VerifiedAsset {
    // Construction verifies this invariant before `StaticAssets` can exist. The process aborts
    // rather than serving an unverified fallback if memory corruption violates it.
    std::process::abort()
}

fn regular_file_metadata(path: &Path) -> Result<fs::Metadata, AssetError> {
    let metadata = fs::symlink_metadata(path).map_err(|_error| AssetError::Unavailable)?;
    if !metadata.is_file() || metadata.file_type().is_symlink() {
        Err(AssetError::Unavailable)
    } else {
        Ok(metadata)
    }
}

fn validate_asset_path(value: &str) -> Result<(), AssetError> {
    let path = Path::new(value);
    let valid = !value.is_empty()
        && value.len() <= 512
        && !value
            .chars()
            .any(|character| matches!(character, '\\' | '%' | '\0'))
        && !path.is_absolute()
        && path
            .components()
            .all(|component| matches!(component, Component::Normal(_)));
    if valid {
        Ok(())
    } else {
        Err(AssetError::InvalidAsset)
    }
}

fn expected_media_type(path: &str) -> Option<&'static str> {
    if path.ends_with(".html") {
        Some("text/html; charset=utf-8")
    } else if path.ends_with(".js") {
        Some("text/javascript; charset=utf-8")
    } else if path.ends_with(".css") {
        Some("text/css; charset=utf-8")
    } else if path.ends_with(".json") {
        Some("application/json")
    } else if path.ends_with(".svg") {
        Some("image/svg+xml")
    } else if path.ends_with(".png") {
        Some("image/png")
    } else if path.ends_with(".woff2") {
        Some("font/woff2")
    } else {
        None
    }
}

fn hex_digest(digest: &[u8; 32]) -> String {
    let mut output = String::with_capacity(64);
    for byte in digest {
        output.push_str(&format!("{byte:02x}"));
    }
    output
}

#[cfg(test)]
mod tests {
    use super::{AssetError, StaticAssets, hex_digest};
    use serde_json::json;
    use sha2::{Digest as _, Sha256};
    use std::fs;
    use std::path::PathBuf;

    fn fixture() -> Result<tempfile::TempDir, Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let html = b"<!doctype html><title>CIGAR</title>";
        let script = b"export const ready = true;";
        fs::write(directory.path().join("index.html"), html)?;
        fs::write(directory.path().join("main.js"), script)?;
        let html_digest: [u8; 32] = Sha256::digest(html).into();
        let script_digest: [u8; 32] = Sha256::digest(script).into();
        let manifest = json!({
            "schema_version": "cigar.dashboard-asset-manifest.v1",
            "files": [
                {
                    "path": "index.html",
                    "sha256": hex_digest(&html_digest),
                    "size": html.len(),
                    "media_type": "text/html; charset=utf-8"
                },
                {
                    "path": "main.js",
                    "sha256": hex_digest(&script_digest),
                    "size": script.len(),
                    "media_type": "text/javascript; charset=utf-8"
                }
            ]
        });
        fs::write(
            directory.path().join("asset-manifest.v1.json"),
            serde_json::to_vec(&manifest)?,
        )?;
        Ok(directory)
    }

    #[test]
    fn valid_assets_are_loaded_immutably() -> Result<(), Box<dyn std::error::Error>> {
        let directory = fixture()?;
        let assets = StaticAssets::load(directory.path())?;
        assert_eq!(assets.file_count(), 2);
        assert_eq!(assets.index().media_type(), "text/html; charset=utf-8");
        fs::write(directory.path().join("index.html"), b"tampered after load")?;
        assert!(assets.index().bytes().starts_with(b"<!doctype html>"));
        Ok(())
    }

    #[test]
    fn production_shell_matches_its_verified_manifest() -> Result<(), Box<dyn std::error::Error>> {
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../apps/dashboard/public");
        let assets = StaticAssets::load(&root)?;
        assert_eq!(assets.file_count(), 7);
        assert!(assets.total_bytes() > 20_000);
        assert!(assets.index().bytes().starts_with(b"<!doctype html>"));
        Ok(())
    }

    #[test]
    fn digest_mismatch_fails_closed() -> Result<(), Box<dyn std::error::Error>> {
        let directory = fixture()?;
        fs::write(
            directory.path().join("main.js"),
            b"different-byte-count-here",
        )?;
        assert!(matches!(
            StaticAssets::load(directory.path()),
            Err(AssetError::DigestMismatch)
        ));
        Ok(())
    }

    #[test]
    fn unsorted_or_escaping_manifest_fails_closed() -> Result<(), Box<dyn std::error::Error>> {
        let directory = fixture()?;
        let manifest_path = directory.path().join("asset-manifest.v1.json");
        let mut manifest: serde_json::Value = serde_json::from_slice(&fs::read(&manifest_path)?)?;
        let files = manifest
            .get_mut("files")
            .and_then(serde_json::Value::as_array_mut)
            .ok_or("files missing")?;
        files.reverse();
        fs::write(&manifest_path, serde_json::to_vec(&manifest)?)?;
        assert!(matches!(
            StaticAssets::load(directory.path()),
            Err(AssetError::InvalidManifest)
        ));

        let directory = fixture()?;
        let manifest_path = directory.path().join("asset-manifest.v1.json");
        let mut manifest: serde_json::Value = serde_json::from_slice(&fs::read(&manifest_path)?)?;
        let path = manifest
            .pointer_mut("/files/0/path")
            .ok_or("path missing")?;
        *path = json!("../index.html");
        fs::write(&manifest_path, serde_json::to_vec(&manifest)?)?;
        assert!(matches!(
            StaticAssets::load(directory.path()),
            Err(AssetError::InvalidAsset)
        ));
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn symlinked_asset_is_rejected() -> Result<(), Box<dyn std::error::Error>> {
        use std::os::unix::fs::symlink;

        let directory = fixture()?;
        let original = directory.path().join("main.original.js");
        fs::rename(directory.path().join("main.js"), &original)?;
        symlink(&original, directory.path().join("main.js"))?;
        assert!(matches!(
            StaticAssets::load(directory.path()),
            Err(AssetError::Unavailable)
        ));
        Ok(())
    }
}
