//! Strict reviewed run-profile registry loading.

use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use std::collections::BTreeSet;
use std::fmt;
use std::fs;
use std::path::{Component, Path};

const REGISTRY_VERSION: &str = "cigar.dashboard-run-profile-registry.v1";
const MAX_REGISTRY_BYTES: u64 = 512 * 1024;
const MAX_PROFILES: usize = 128;

/// Stable content-free run-profile registry failure category.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProfileRegistryError {
    /// The registry file was missing, unreadable, or not a regular file.
    Unavailable,
    /// JSON syntax, fields, ordering, or the schema version were invalid.
    InvalidRegistry,
    /// A command, probe selector, or working-directory combination was unsafe.
    UnsafeProfile,
    /// A duration or resource ceiling was inconsistent or out of range.
    InvalidLimit,
}

impl fmt::Display for ProfileRegistryError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Unavailable => "dashboard run-profile registry is unavailable",
            Self::InvalidRegistry => "dashboard run-profile registry is invalid",
            Self::UnsafeProfile => "dashboard run profile is unsafe",
            Self::InvalidLimit => "dashboard run-profile limit is invalid",
        })
    }
}

impl std::error::Error for ProfileRegistryError {}

/// Reviewed executable selector. No general program path is accepted.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum ProfileExecutable {
    /// Cargo invoked directly, never through a shell.
    Cargo,
    /// Python 3 invoked directly with a reviewed repository script.
    Python3,
    /// The internal deterministic soak driver.
    CigarSoak,
}

/// Profile category displayed by the test center.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProfileKind {
    /// Bounded verification check.
    Check,
    /// Reviewed multi-case matrix.
    Matrix,
    /// Content-safe protocol demonstration.
    Demo,
    /// Honest benchmark with a verifiable receipt.
    Benchmark,
    /// Isolated deterministic soak.
    Soak,
}

/// Fixed working-directory class selected by the registry.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum WorkingDirectory {
    /// Current exact source checkout.
    Workspace,
    /// A new private sandbox outside the source checkout.
    IsolatedSandbox,
    /// Exact installed release-candidate staging root.
    InstalledCandidate,
}

/// Static implementation status; runtime probes further narrow availability.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AvailabilityState {
    /// The sidecar supervisor implements this command contract.
    Available,
    /// The command is documented but cannot be launched in this build.
    CommandNotImplemented,
}

/// One bounded runtime availability check.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AvailabilityProbe {
    kind: ProbeKind,
    selector: String,
}

/// Closed availability probe vocabulary.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
enum ProbeKind {
    Executable,
    WorkspacePath,
    CargoCache,
    InstalledCandidate,
}

/// Closed supported platform vocabulary.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "lowercase")]
enum ProfilePlatform {
    Linux,
    Macos,
    Windows,
}

/// Per-job hard resource ceilings.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ResourceCeiling {
    memory_mib: u64,
    output_bytes: u64,
    evidence_bytes: u64,
    processes: u16,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
enum NetworkMode {
    Offline,
    Loopback,
    DeclaredExternal,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
enum EvidenceCategory {
    Development,
    Candidate,
    Installed,
    Release,
}

/// One immutable browser-selectable reviewed run profile.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RunProfile {
    id: String,
    title: String,
    description: String,
    kind: ProfileKind,
    executable: ProfileExecutable,
    argv: Vec<String>,
    working_directory: WorkingDirectory,
    availability_state: AvailabilityState,
    availability_probes: Vec<AvailabilityProbe>,
    platforms: Vec<ProfilePlatform>,
    control_required: bool,
    expected_duration_seconds: u64,
    maximum_duration_seconds: u64,
    resource_ceiling: ResourceCeiling,
    network_mode: NetworkMode,
    concurrency_group: String,
    cancellation_grace_seconds: u64,
    receipt_schema: String,
    evidence_category: EvidenceCategory,
    documentation: String,
}

impl RunProfile {
    /// Returns the stable browser-selectable ID.
    #[must_use]
    pub fn id(&self) -> &str {
        &self.id
    }

    /// Returns whether the supervisor has implemented this exact command contract.
    #[must_use]
    pub const fn availability_state(&self) -> AvailabilityState {
        self.availability_state
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RegistryDocument {
    schema_version: String,
    source_revision: String,
    profiles: Vec<RunProfile>,
}

/// Validated immutable run-profile registry plus its exact-byte SHA-256 binding.
#[derive(Clone, Debug)]
pub struct RunProfileRegistry {
    source_revision: String,
    profiles: Vec<RunProfile>,
    digest: [u8; 32],
}

impl RunProfileRegistry {
    /// Loads one absolute regular registry file with a strict byte limit.
    pub fn load(path: &Path) -> Result<Self, ProfileRegistryError> {
        if !path.is_absolute() {
            return Err(ProfileRegistryError::UnsafeProfile);
        }
        let metadata =
            fs::symlink_metadata(path).map_err(|_error| ProfileRegistryError::Unavailable)?;
        if !metadata.is_file()
            || metadata.file_type().is_symlink()
            || metadata.len() == 0
            || metadata.len() > MAX_REGISTRY_BYTES
        {
            return Err(ProfileRegistryError::Unavailable);
        }
        let source = fs::read(path).map_err(|_error| ProfileRegistryError::Unavailable)?;
        Self::from_json(&source)
    }

    /// Parses and validates strict registry JSON while binding its exact bytes.
    pub fn from_json(source: &[u8]) -> Result<Self, ProfileRegistryError> {
        if source.is_empty() || source.len() > MAX_REGISTRY_BYTES as usize {
            return Err(ProfileRegistryError::InvalidRegistry);
        }
        let document: RegistryDocument = serde_json::from_slice(source)
            .map_err(|_error| ProfileRegistryError::InvalidRegistry)?;
        if document.schema_version != REGISTRY_VERSION
            || !bounded_text(&document.source_revision, 128)
            || document.profiles.is_empty()
            || document.profiles.len() > MAX_PROFILES
        {
            return Err(ProfileRegistryError::InvalidRegistry);
        }
        let mut prior_id: Option<&str> = None;
        for profile in &document.profiles {
            validate_profile(profile)?;
            if prior_id.is_some_and(|prior| prior >= profile.id.as_str()) {
                return Err(ProfileRegistryError::InvalidRegistry);
            }
            prior_id = Some(profile.id.as_str());
        }
        Ok(Self {
            source_revision: document.source_revision,
            profiles: document.profiles,
            digest: Sha256::digest(source).into(),
        })
    }

    /// Returns the source binding asserted by the registry.
    #[must_use]
    pub fn source_revision(&self) -> &str {
        &self.source_revision
    }

    /// Returns every profile in stable ID order.
    #[must_use]
    pub fn profiles(&self) -> &[RunProfile] {
        &self.profiles
    }

    /// Returns the exact registry byte digest.
    #[must_use]
    pub const fn digest(&self) -> &[u8; 32] {
        &self.digest
    }

    /// Returns the exact registry byte digest as lowercase hexadecimal.
    #[must_use]
    pub fn digest_hex(&self) -> String {
        self.digest.iter().fold(
            String::with_capacity(self.digest.len() * 2),
            |mut output, byte| {
                use std::fmt::Write as _;
                if write!(output, "{byte:02x}").is_err() {
                    return String::new();
                }
                output
            },
        )
    }

    /// Resolves only an exact reviewed profile ID.
    #[must_use]
    pub fn get(&self, id: &str) -> Option<&RunProfile> {
        self.profiles
            .binary_search_by(|profile| profile.id.as_str().cmp(id))
            .ok()
            .and_then(|index| self.profiles.get(index))
    }
}

fn validate_profile(profile: &RunProfile) -> Result<(), ProfileRegistryError> {
    if !bounded_identifier(&profile.id)
        || !bounded_text(&profile.title, 128)
        || !bounded_text(&profile.description, 1024)
        || !bounded_identifier(&profile.concurrency_group)
        || !bounded_text(&profile.receipt_schema, 128)
        || !bounded_text(&profile.documentation, 4096)
        || profile.argv.is_empty()
        || profile.argv.len() > 64
        || profile
            .argv
            .iter()
            .any(|argument| !bounded_text(argument, 512) || argument.contains('\0'))
        || profile.availability_probes.is_empty()
        || profile.availability_probes.len() > 16
        || profile.platforms.is_empty()
        || profile.platforms.len() > 3
    {
        return Err(ProfileRegistryError::InvalidRegistry);
    }
    if profile.expected_duration_seconds == 0
        || profile.expected_duration_seconds > profile.maximum_duration_seconds
        || profile.maximum_duration_seconds > 604_800
        || !(1..=300).contains(&profile.cancellation_grace_seconds)
        || !(64..=65_536).contains(&profile.resource_ceiling.memory_mib)
        || !(1024..=1_073_741_824).contains(&profile.resource_ceiling.output_bytes)
        || !(1024..=10_737_418_240).contains(&profile.resource_ceiling.evidence_bytes)
        || !(1..=1024).contains(&profile.resource_ceiling.processes)
    {
        return Err(ProfileRegistryError::InvalidLimit);
    }
    if !strictly_unique(&profile.platforms) {
        return Err(ProfileRegistryError::InvalidRegistry);
    }
    let mut probes = BTreeSet::new();
    for probe in &profile.availability_probes {
        if !bounded_text(&probe.selector, 256)
            || !probes.insert((probe.kind, probe.selector.as_str()))
            || matches!(probe.kind, ProbeKind::WorkspacePath)
                && !safe_relative_path(&probe.selector)
        {
            return Err(ProfileRegistryError::UnsafeProfile);
        }
    }
    if profile.kind == ProfileKind::Soak {
        validate_soak_profile(profile)?;
    } else if profile.concurrency_group == "soak" {
        return Err(ProfileRegistryError::UnsafeProfile);
    }
    if profile.evidence_category == EvidenceCategory::Release
        && profile.working_directory != WorkingDirectory::InstalledCandidate
    {
        return Err(ProfileRegistryError::UnsafeProfile);
    }
    Ok(())
}

fn validate_soak_profile(profile: &RunProfile) -> Result<(), ProfileRegistryError> {
    let expected = match profile.id.as_str() {
        "soak-smoke" => 120,
        "soak-developer" => 900,
        "soak-extended" => 3_600,
        "soak-rc-24h" => 86_400,
        _ => return Err(ProfileRegistryError::UnsafeProfile),
    };
    if profile.executable != ProfileExecutable::CigarSoak
        || profile.expected_duration_seconds != expected
        || profile.concurrency_group != "soak"
        || profile.network_mode != NetworkMode::Loopback
        || profile.receipt_schema != "cigar.soak-result.v1"
    {
        return Err(ProfileRegistryError::UnsafeProfile);
    }
    Ok(())
}

fn strictly_unique<T: Ord>(values: &[T]) -> bool {
    values.windows(2).all(|pair| {
        pair.first()
            .zip(pair.get(1))
            .is_some_and(|(left, right)| left < right)
    })
}

fn safe_relative_path(value: &str) -> bool {
    let path = Path::new(value);
    !path.is_absolute()
        && !value.contains(['\\', '%', '\0'])
        && path
            .components()
            .all(|component| matches!(component, Component::Normal(_)))
}

fn bounded_identifier(value: &str) -> bool {
    bounded_text(value, 128)
        && value.as_bytes().first().is_some_and(u8::is_ascii_lowercase)
        && value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'.' | b'_' | b'-')
        })
        && !value.ends_with(['.', '_', '-'])
        && !["..", "__", "--", "._", ".-", "_.", "_-", "-.", "-_"]
            .iter()
            .any(|separator| value.contains(separator))
}

fn bounded_text(value: &str, maximum: usize) -> bool {
    !value.is_empty() && value.len() <= maximum
}

#[cfg(test)]
mod tests {
    use super::{AvailabilityState, ProfileRegistryError, RunProfileRegistry};
    use serde_json::Value;

    const REGISTRY: &[u8] = include_bytes!("../../../tests/dashboard/run-profiles-v1.json");

    #[test]
    fn reviewed_registry_is_strict_sorted_and_digest_bound()
    -> Result<(), Box<dyn std::error::Error>> {
        let registry = RunProfileRegistry::from_json(REGISTRY)?;
        assert_eq!(registry.profiles().len(), 9);
        assert_eq!(registry.digest().len(), 32);
        assert_eq!(registry.digest_hex().len(), 64);
        assert!(registry.get("soak-smoke").is_some());
        assert!(registry.get("SOAK-SMOKE").is_none());
        assert!(registry.profiles().iter().all(|profile| {
            profile.availability_state() == AvailabilityState::CommandNotImplemented
        }));
        Ok(())
    }

    #[test]
    fn duplicate_unknown_and_shell_fields_fail_closed() -> Result<(), Box<dyn std::error::Error>> {
        let mut document: Value = serde_json::from_slice(REGISTRY)?;
        let profiles = document
            .get_mut("profiles")
            .and_then(Value::as_array_mut)
            .ok_or("profiles missing")?;
        let first = profiles.first().cloned().ok_or("profile missing")?;
        profiles.push(first);
        let source = serde_json::to_vec(&document)?;
        assert_eq!(
            RunProfileRegistry::from_json(&source).err(),
            Some(ProfileRegistryError::InvalidRegistry)
        );

        let mut document: Value = serde_json::from_slice(REGISTRY)?;
        document
            .get_mut("profiles")
            .and_then(Value::as_array_mut)
            .and_then(|profiles| profiles.first_mut())
            .and_then(Value::as_object_mut)
            .ok_or("profile missing")?
            .insert(
                "environment".to_owned(),
                serde_json::json!({"TOKEN": "unsafe"}),
            );
        assert_eq!(
            RunProfileRegistry::from_json(&serde_json::to_vec(&document)?).err(),
            Some(ProfileRegistryError::InvalidRegistry)
        );
        Ok(())
    }

    #[test]
    fn release_profile_cannot_run_from_source_checkout() -> Result<(), Box<dyn std::error::Error>> {
        let mut document: Value = serde_json::from_slice(REGISTRY)?;
        let profiles = document
            .get_mut("profiles")
            .and_then(Value::as_array_mut)
            .ok_or("profiles missing")?;
        let release = profiles
            .iter_mut()
            .find(|profile| profile.get("id") == Some(&Value::from("soak-rc-24h")))
            .ok_or("release profile missing")?;
        release["working_directory"] = Value::from("workspace");
        assert_eq!(
            RunProfileRegistry::from_json(&serde_json::to_vec(&document)?).err(),
            Some(ProfileRegistryError::UnsafeProfile)
        );
        Ok(())
    }
}
