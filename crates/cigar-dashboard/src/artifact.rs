//! Fail-closed binding for an exact, locally installed dashboard artifact.
//!
//! This module deliberately cannot create release-qualifying evidence. It verifies exact local
//! bytes and returns a partial installed-artifact descriptor; an authenticated signing,
//! notarization, provenance, and clean-host qualification chain is still required to advance it.

use crate::{
    EvidenceCategory, EvidenceDescriptor, EvidenceError, EvidenceStatus, ReceiptError,
    strict_canonical_json,
};
use serde_json::Value;
use sha2::{Digest as _, Sha256};
use std::collections::BTreeSet;
use std::fmt;
use std::fs::{self, File};
use std::io::Read as _;
use std::path::{Component, Path, PathBuf};

const ARTIFACT_SCHEMA: &str = "cigar.dashboard-installed-artifact.v1";
const ARTIFACT_ID: &str = "cigar-dashboard-macos-aarch64";
const TARGET: &str = "aarch64-apple-darwin";
const REVIEWED_PACKAGE_CONTRACT: &[u8] = include_bytes!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../packaging/development/contracts/macos-dashboard-archive.v1.json"
));
const MAX_RECEIPT_BYTES: u64 = 64 * 1024;
const MAX_ARCHIVE_BYTES: u64 = 1024 * 1024 * 1024;
const MAX_BINARY_BYTES: u64 = 512 * 1024 * 1024;
const MAX_ASSET_MANIFEST_BYTES: u64 = 1024 * 1024;
const MAX_CONTRACT_BYTES: u64 = 1024 * 1024;

/// Stable content-free installed-artifact verification failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InstalledArtifactError {
    /// A path was relative, aliased, linked, mutable by peers, or changed while read.
    UnsafePath,
    /// A configured file exceeded its strict byte ceiling.
    LimitExceeded,
    /// The qualification record was non-canonical, open-shaped, or semantically invalid.
    InvalidReceipt,
    /// One digest, byte count, source identity, or target binding did not match.
    BindingMismatch,
    /// The installed executable was not a thin Apple-silicon Mach-O image.
    InvalidExecutable,
}

impl fmt::Display for InstalledArtifactError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::UnsafePath => "dashboard installed-artifact path is unsafe",
            Self::LimitExceeded => "dashboard installed-artifact limit was exceeded",
            Self::InvalidReceipt => "dashboard installed-artifact receipt is invalid",
            Self::BindingMismatch => "dashboard installed-artifact binding is invalid",
            Self::InvalidExecutable => "dashboard installed executable is not native arm64 Mach-O",
        })
    }
}

impl std::error::Error for InstalledArtifactError {}

/// Exact local files selected by a trusted qualification caller.
#[derive(Clone, Debug)]
pub struct InstalledArtifactVerifier {
    receipt: PathBuf,
    archive: PathBuf,
    dashboard: PathBuf,
    asset_manifest: PathBuf,
    package_contract: PathBuf,
}

impl InstalledArtifactVerifier {
    /// Creates a verifier over five distinct absolute, normalized paths.
    pub fn new(
        receipt: &Path,
        archive: &Path,
        dashboard: &Path,
        asset_manifest: &Path,
        package_contract: &Path,
    ) -> Result<Self, InstalledArtifactError> {
        let receipt = normalized_absolute(receipt)?;
        let archive = normalized_absolute(archive)?;
        let dashboard = normalized_absolute(dashboard)?;
        let asset_manifest = normalized_absolute(asset_manifest)?;
        let package_contract = normalized_absolute(package_contract)?;
        let normalized = [
            &receipt,
            &archive,
            &dashboard,
            &asset_manifest,
            &package_contract,
        ];
        if normalized.iter().collect::<BTreeSet<_>>().len() != normalized.len() {
            return Err(InstalledArtifactError::UnsafePath);
        }
        Ok(Self {
            receipt,
            archive,
            dashboard,
            asset_manifest,
            package_contract,
        })
    }

    /// Reopens every exact file, checks its stable identity and digest, and binds one source tree.
    pub fn verify(
        &self,
        expected_source_revision: &str,
        expected_source_tree_sha256: &str,
    ) -> Result<VerifiedInstalledArtifact, InstalledArtifactError> {
        if !source_revision(expected_source_revision) || !sha256(expected_source_tree_sha256) {
            return Err(InstalledArtifactError::BindingMismatch);
        }
        let receipt = stable_read(&self.receipt, MAX_RECEIPT_BYTES, false)?;
        let archive = stable_read(&self.archive, MAX_ARCHIVE_BYTES, false)?;
        let dashboard = stable_read(&self.dashboard, MAX_BINARY_BYTES, true)?;
        let asset_manifest = stable_read(&self.asset_manifest, MAX_ASSET_MANIFEST_BYTES, false)?;
        let package_contract = stable_read(&self.package_contract, MAX_CONTRACT_BYTES, false)?;
        validate_arm64_macho(&dashboard)?;

        let value = strict_canonical_json(&receipt).map_err(map_receipt_error)?;
        let object = value
            .as_object()
            .ok_or(InstalledArtifactError::InvalidReceipt)?;
        let expected_fields = [
            "artifact_bytes",
            "artifact_id",
            "artifact_sha256",
            "asset_manifest_bytes",
            "asset_manifest_sha256",
            "dashboard_bytes",
            "dashboard_sha256",
            "package_contract_bytes",
            "package_contract_sha256",
            "schema_version",
            "signature_status",
            "smoke_status",
            "source_revision",
            "source_tree_sha256",
            "status",
            "target",
        ]
        .into_iter()
        .collect::<BTreeSet<_>>();
        if object.keys().map(String::as_str).collect::<BTreeSet<_>>() != expected_fields
            || text(object.get("schema_version")) != Some(ARTIFACT_SCHEMA)
            || text(object.get("artifact_id")) != Some(ARTIFACT_ID)
            || text(object.get("target")) != Some(TARGET)
            || text(object.get("status")) != Some("installed-unqualified")
            || text(object.get("signature_status")) != Some("not-verified")
            || text(object.get("smoke_status")) != Some("not-run")
        {
            return Err(InstalledArtifactError::InvalidReceipt);
        }

        let archive_digest = digest(&archive);
        let dashboard_digest = digest(&dashboard);
        let asset_manifest_digest = digest(&asset_manifest);
        let package_contract_digest = digest(&package_contract);
        if text(object.get("source_revision")) != Some(expected_source_revision)
            || text(object.get("source_tree_sha256")) != Some(expected_source_tree_sha256)
            || package_contract_digest != digest(REVIEWED_PACKAGE_CONTRACT)
            || text(object.get("artifact_sha256")) != Some(&archive_digest)
            || text(object.get("dashboard_sha256")) != Some(&dashboard_digest)
            || text(object.get("asset_manifest_sha256")) != Some(&asset_manifest_digest)
            || text(object.get("package_contract_sha256")) != Some(&package_contract_digest)
            || number(object.get("artifact_bytes")) != Some(archive.len() as u64)
            || number(object.get("dashboard_bytes")) != Some(dashboard.len() as u64)
            || number(object.get("asset_manifest_bytes")) != Some(asset_manifest.len() as u64)
            || number(object.get("package_contract_bytes")) != Some(package_contract.len() as u64)
        {
            return Err(InstalledArtifactError::BindingMismatch);
        }
        Ok(VerifiedInstalledArtifact {
            artifact_digest: archive_digest,
            dashboard_digest,
            receipt_digest: digest(&receipt),
            source_revision: expected_source_revision.to_owned(),
            source_tree_sha256: expected_source_tree_sha256.to_owned(),
        })
    }
}

/// Exact locally installed bytes whose signature and release qualification remain unverified.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedInstalledArtifact {
    artifact_digest: String,
    dashboard_digest: String,
    receipt_digest: String,
    source_revision: String,
    source_tree_sha256: String,
}

impl VerifiedInstalledArtifact {
    /// Returns the exact archive SHA-256.
    #[must_use]
    pub fn artifact_digest(&self) -> &str {
        &self.artifact_digest
    }

    /// Returns the exact installed `cigar-dashboard` executable SHA-256.
    #[must_use]
    pub fn dashboard_digest(&self) -> &str {
        &self.dashboard_digest
    }

    /// Returns the canonical installed-binding receipt SHA-256.
    #[must_use]
    pub fn receipt_digest(&self) -> &str {
        &self.receipt_digest
    }

    /// Returns the clean source revision named by both caller and receipt.
    #[must_use]
    pub fn source_revision(&self) -> &str {
        &self.source_revision
    }

    /// Returns the exact clean source-tree SHA-256 binding.
    #[must_use]
    pub fn source_tree_sha256(&self) -> &str {
        &self.source_tree_sha256
    }

    /// Produces partial installed-artifact metadata; this can never pass a qualifying run.
    pub fn partial_descriptor(&self, run_id: &str) -> Result<EvidenceDescriptor, EvidenceError> {
        EvidenceDescriptor::verified(
            run_id,
            ARTIFACT_SCHEMA,
            EvidenceCategory::InstalledArtifact,
            EvidenceStatus::Partial,
            &self.receipt_digest,
            &self.source_revision,
            Some(&self.artifact_digest),
        )
    }
}

fn map_receipt_error(error: ReceiptError) -> InstalledArtifactError {
    match error {
        ReceiptError::LimitExceeded => InstalledArtifactError::LimitExceeded,
        ReceiptError::UnsafePath | ReceiptError::Missing => InstalledArtifactError::UnsafePath,
        ReceiptError::BindingMismatch | ReceiptError::OutcomeMismatch => {
            InstalledArtifactError::BindingMismatch
        }
        ReceiptError::UnsupportedSchema | ReceiptError::InvalidReceipt => {
            InstalledArtifactError::InvalidReceipt
        }
    }
}

fn normalized_absolute(path: &Path) -> Result<PathBuf, InstalledArtifactError> {
    if !path.is_absolute()
        || path
            .components()
            .any(|component| !matches!(component, Component::RootDir | Component::Normal(_)))
    {
        return Err(InstalledArtifactError::UnsafePath);
    }
    Ok(path.to_owned())
}

fn stable_read(
    path: &Path,
    maximum: u64,
    executable: bool,
) -> Result<Vec<u8>, InstalledArtifactError> {
    let named_before =
        fs::symlink_metadata(path).map_err(|_error| InstalledArtifactError::UnsafePath)?;
    validate_metadata(&named_before, maximum, executable)?;
    let descriptor = rustix::fs::open(
        path,
        rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::CLOEXEC,
        rustix::fs::Mode::empty(),
    )
    .map_err(|_error| InstalledArtifactError::UnsafePath)?;
    let mut file = File::from(descriptor);
    let opened_before = file
        .metadata()
        .map_err(|_error| InstalledArtifactError::UnsafePath)?;
    validate_metadata(&opened_before, maximum, executable)?;
    if !same_identity(&named_before, &opened_before) {
        return Err(InstalledArtifactError::UnsafePath);
    }
    let mut payload = Vec::with_capacity(
        usize::try_from(opened_before.len())
            .unwrap_or(64 * 1024)
            .min(64 * 1024),
    );
    file.by_ref()
        .take(maximum.saturating_add(1))
        .read_to_end(&mut payload)
        .map_err(|_error| InstalledArtifactError::UnsafePath)?;
    if payload.is_empty() || u64::try_from(payload.len()).unwrap_or(u64::MAX) > maximum {
        return Err(InstalledArtifactError::LimitExceeded);
    }
    let opened_after = file
        .metadata()
        .map_err(|_error| InstalledArtifactError::UnsafePath)?;
    let named_after =
        fs::symlink_metadata(path).map_err(|_error| InstalledArtifactError::UnsafePath)?;
    validate_metadata(&opened_after, maximum, executable)?;
    validate_metadata(&named_after, maximum, executable)?;
    if !same_snapshot(&opened_before, &opened_after)
        || !same_snapshot(&named_before, &named_after)
        || !same_identity(&opened_after, &named_after)
        || opened_after.len() != u64::try_from(payload.len()).unwrap_or(u64::MAX)
    {
        return Err(InstalledArtifactError::UnsafePath);
    }
    Ok(payload)
}

fn validate_metadata(
    metadata: &fs::Metadata,
    maximum: u64,
    executable: bool,
) -> Result<(), InstalledArtifactError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
        let mode = metadata.permissions().mode() & 0o777;
        let owner = metadata.uid();
        if !metadata.is_file()
            || metadata.file_type().is_symlink()
            || metadata.nlink() != 1
            || owner != 0 && owner != rustix::process::geteuid().as_raw()
            || mode & 0o022 != 0
            || executable != (mode & 0o111 != 0)
            || metadata.len() == 0
            || metadata.len() > maximum
        {
            return Err(InstalledArtifactError::UnsafePath);
        }
        Ok(())
    }
    #[cfg(not(unix))]
    {
        let _ignored = (metadata, maximum, executable);
        Err(InstalledArtifactError::UnsafePath)
    }
}

#[cfg(unix)]
fn same_identity(left: &fs::Metadata, right: &fs::Metadata) -> bool {
    use std::os::unix::fs::MetadataExt as _;
    left.dev() == right.dev() && left.ino() == right.ino()
}

#[cfg(not(unix))]
fn same_identity(_left: &fs::Metadata, _right: &fs::Metadata) -> bool {
    false
}

#[cfg(unix)]
fn same_snapshot(left: &fs::Metadata, right: &fs::Metadata) -> bool {
    use std::os::unix::fs::MetadataExt as _;
    same_identity(left, right)
        && left.len() == right.len()
        && left.mode() == right.mode()
        && left.uid() == right.uid()
        && left.gid() == right.gid()
        && left.nlink() == right.nlink()
        && left.mtime() == right.mtime()
        && left.mtime_nsec() == right.mtime_nsec()
        && left.ctime() == right.ctime()
        && left.ctime_nsec() == right.ctime_nsec()
}

#[cfg(not(unix))]
fn same_snapshot(_left: &fs::Metadata, _right: &fs::Metadata) -> bool {
    false
}

fn validate_arm64_macho(source: &[u8]) -> Result<(), InstalledArtifactError> {
    const HEADER_BYTES: usize = 32;
    const MH_MAGIC_64: u32 = 0xfeed_facf;
    const CPU_TYPE_ARM64: u32 = 0x0100_000c;
    const MH_EXECUTE: u32 = 2;
    const MAX_LOAD_COMMANDS: u32 = 4096;

    let magic = little_endian_u32(source, 0);
    let cpu_type = little_endian_u32(source, 4);
    let file_type = little_endian_u32(source, 12);
    let command_count = little_endian_u32(source, 16);
    let command_bytes = little_endian_u32(source, 20)
        .and_then(|value| usize::try_from(value).ok())
        .ok_or(InstalledArtifactError::InvalidExecutable)?;
    let command_count = command_count.ok_or(InstalledArtifactError::InvalidExecutable)?;
    let commands_end = HEADER_BYTES
        .checked_add(command_bytes)
        .ok_or(InstalledArtifactError::InvalidExecutable)?;
    if magic != Some(MH_MAGIC_64)
        || cpu_type != Some(CPU_TYPE_ARM64)
        || file_type != Some(MH_EXECUTE)
        || command_count == 0
        || command_count > MAX_LOAD_COMMANDS
        || command_bytes == 0
        || commands_end > source.len()
    {
        return Err(InstalledArtifactError::InvalidExecutable);
    }

    let mut offset = HEADER_BYTES;
    for _ in 0..command_count {
        let size = little_endian_u32(source, offset.saturating_add(4))
            .and_then(|value| usize::try_from(value).ok())
            .ok_or(InstalledArtifactError::InvalidExecutable)?;
        let end = offset
            .checked_add(size)
            .ok_or(InstalledArtifactError::InvalidExecutable)?;
        if size < 8 || size % 8 != 0 || end > commands_end {
            return Err(InstalledArtifactError::InvalidExecutable);
        }
        offset = end;
    }
    if offset != commands_end {
        return Err(InstalledArtifactError::InvalidExecutable);
    }
    Ok(())
}

fn little_endian_u32(source: &[u8], offset: usize) -> Option<u32> {
    let end = offset.checked_add(4)?;
    Some(u32::from_le_bytes(
        source.get(offset..end)?.try_into().ok()?,
    ))
}

fn text(value: Option<&Value>) -> Option<&str> {
    value.and_then(Value::as_str)
}

fn number(value: Option<&Value>) -> Option<u64> {
    value.and_then(Value::as_u64)
}

fn source_revision(value: &str) -> bool {
    matches!(value.len(), 40 | 64)
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn digest(source: &[u8]) -> String {
    Sha256::digest(source)
        .iter()
        .fold(String::with_capacity(64), |mut output, byte| {
            use std::fmt::Write as _;
            let _ignored = write!(output, "{byte:02x}");
            output
        })
}

#[cfg(test)]
mod tests {
    use super::{
        InstalledArtifactError, InstalledArtifactVerifier, REVIEWED_PACKAGE_CONTRACT, digest,
    };
    use crate::{EvidenceCategory, EvidenceStatus, RunRecord};
    use std::fs;
    use std::path::Path;

    const REVISION: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const TREE: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

    fn write_file(path: &Path, source: &[u8], mode: u32) -> Result<(), Box<dyn std::error::Error>> {
        use std::os::unix::fs::PermissionsExt as _;
        fs::write(path, source)?;
        fs::set_permissions(path, fs::Permissions::from_mode(mode))?;
        Ok(())
    }

    fn arm64_macho_fixture() -> Vec<u8> {
        let mut source = Vec::new();
        source.extend_from_slice(&0xfeed_facfu32.to_le_bytes());
        source.extend_from_slice(&0x0100_000cu32.to_le_bytes());
        source.extend_from_slice(&0u32.to_le_bytes());
        source.extend_from_slice(&2u32.to_le_bytes());
        source.extend_from_slice(&1u32.to_le_bytes());
        source.extend_from_slice(&24u32.to_le_bytes());
        source.extend_from_slice(&0u32.to_le_bytes());
        source.extend_from_slice(&0u32.to_le_bytes());
        source.extend_from_slice(&0x1bu32.to_le_bytes());
        source.extend_from_slice(&24u32.to_le_bytes());
        source.extend_from_slice(&[0u8; 16]);
        source
    }

    fn fixture()
    -> Result<(tempfile::TempDir, InstalledArtifactVerifier), Box<dyn std::error::Error>> {
        use std::os::unix::fs::PermissionsExt as _;

        let directory = tempfile::tempdir()?;
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700))?;
        let archive_path = directory.path().join("dashboard.tar.gz");
        let binary_path = directory.path().join("cigar-dashboard");
        let manifest_path = directory.path().join("asset-manifest.v1.json");
        let contract_path = directory.path().join("package-contract.json");
        let receipt_path = directory.path().join("installed-receipt.json");
        let archive = b"deterministic-dashboard-archive";
        let binary = arm64_macho_fixture();
        let manifest = b"{\"schema_version\":\"cigar.dashboard-asset-manifest.v1\"}\n";
        let contract = REVIEWED_PACKAGE_CONTRACT;
        write_file(&archive_path, archive, 0o600)?;
        write_file(&binary_path, &binary, 0o700)?;
        write_file(&manifest_path, manifest, 0o600)?;
        write_file(&contract_path, contract, 0o600)?;
        let receipt = serde_json::json!({
            "artifact_bytes": archive.len(),
            "artifact_id": "cigar-dashboard-macos-aarch64",
            "artifact_sha256": digest(archive),
            "asset_manifest_bytes": manifest.len(),
            "asset_manifest_sha256": digest(manifest),
            "dashboard_bytes": binary.len(),
            "dashboard_sha256": digest(&binary),
            "package_contract_bytes": contract.len(),
            "package_contract_sha256": digest(contract),
            "schema_version": "cigar.dashboard-installed-artifact.v1",
            "signature_status": "not-verified",
            "smoke_status": "not-run",
            "source_revision": REVISION,
            "source_tree_sha256": TREE,
            "status": "installed-unqualified",
            "target": "aarch64-apple-darwin"
        });
        let encoded = serde_json::to_string_pretty(&receipt)? + "\n";
        write_file(&receipt_path, encoded.as_bytes(), 0o600)?;
        let verifier = InstalledArtifactVerifier::new(
            &receipt_path,
            &archive_path,
            &binary_path,
            &manifest_path,
            &contract_path,
        )?;
        Ok((directory, verifier))
    }

    #[test]
    fn exact_unsigned_install_binding_is_partial_never_release_qualifying()
    -> Result<(), Box<dyn std::error::Error>> {
        let (_directory, verifier) = fixture()?;
        let verified = verifier.verify(REVISION, TREE)?;
        let run = RunRecord::queued(
            "dashboard-contracts",
            "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
            "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
            REVISION,
        )?;
        let descriptor = verified.partial_descriptor(run.run_id())?;
        assert_eq!(descriptor.category(), EvidenceCategory::InstalledArtifact);
        assert_eq!(descriptor.status(), EvidenceStatus::Partial);
        assert_eq!(verified.source_tree_sha256(), TREE);
        Ok(())
    }

    #[test]
    fn mutation_source_drift_links_and_non_native_binary_fail_closed()
    -> Result<(), Box<dyn std::error::Error>> {
        use std::os::unix::fs::{PermissionsExt as _, symlink};

        let (directory, verifier) = fixture()?;
        assert_eq!(
            verifier
                .verify("cccccccccccccccccccccccccccccccccccccccc", TREE)
                .err(),
            Some(InstalledArtifactError::BindingMismatch)
        );
        let archive = directory.path().join("dashboard.tar.gz");
        fs::write(&archive, b"mutated-dashboard-archive")?;
        fs::set_permissions(&archive, fs::Permissions::from_mode(0o600))?;
        assert_eq!(
            verifier.verify(REVISION, TREE).err(),
            Some(InstalledArtifactError::BindingMismatch)
        );

        let (_contract_directory, contract_verifier) = fixture()?;
        let forged_contract =
            b"{\"allow\":[\"**\"],\"schema_version\":\"cigar.package-contract.v1\"}\n";
        write_file(&contract_verifier.package_contract, forged_contract, 0o600)?;
        let mut forged_receipt: serde_json::Value =
            serde_json::from_slice(&fs::read(&contract_verifier.receipt)?)?;
        let forged_object = forged_receipt
            .as_object_mut()
            .ok_or("fixture receipt is not an object")?;
        forged_object.insert(
            "package_contract_bytes".to_owned(),
            serde_json::json!(forged_contract.len()),
        );
        forged_object.insert(
            "package_contract_sha256".to_owned(),
            serde_json::json!(digest(forged_contract)),
        );
        let encoded = serde_json::to_string_pretty(&forged_receipt)? + "\n";
        write_file(&contract_verifier.receipt, encoded.as_bytes(), 0o600)?;
        assert_eq!(
            contract_verifier.verify(REVISION, TREE).err(),
            Some(InstalledArtifactError::BindingMismatch)
        );

        let target = directory.path().join("target");
        write_file(&target, b"target", 0o600)?;
        let link = directory.path().join("link");
        symlink(&target, &link)?;
        let linked = InstalledArtifactVerifier::new(
            &link,
            &verifier.archive,
            &verifier.dashboard,
            &verifier.asset_manifest,
            &verifier.package_contract,
        )?;
        assert_eq!(
            linked.verify(REVISION, TREE).err(),
            Some(InstalledArtifactError::UnsafePath)
        );

        let (hardlink_directory, hardlink_verifier) = fixture()?;
        let hardlink = hardlink_directory.path().join("contract-hardlink");
        fs::hard_link(&hardlink_verifier.package_contract, &hardlink)?;
        let rebound = InstalledArtifactVerifier::new(
            &hardlink_verifier.receipt,
            &hardlink_verifier.archive,
            &hardlink_verifier.dashboard,
            &hardlink_verifier.asset_manifest,
            &hardlink,
        )?;
        assert_eq!(
            rebound.verify(REVISION, TREE).err(),
            Some(InstalledArtifactError::UnsafePath)
        );

        let (_other, verifier) = fixture()?;
        let binary = verifier.dashboard.clone();
        write_file(
            &binary,
            &[0xcf, 0xfa, 0xed, 0xfe, 0x0c, 0x00, 0x00, 0x01],
            0o700,
        )?;
        assert_eq!(
            verifier.verify(REVISION, TREE).err(),
            Some(InstalledArtifactError::InvalidExecutable)
        );
        Ok(())
    }
}
