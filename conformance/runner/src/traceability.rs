//! Fail-closed invariant-to-evidence traceability validation.

use crate::digest::hash_file;
use crate::model::TraceabilityResult;
use serde::Deserialize;
use std::collections::{BTreeMap, BTreeSet};
use std::fs::File;
use std::io::Read as _;
use std::path::{Component, Path, PathBuf};

const MAX_TRACEABILITY_BYTES: u64 = 2 * 1024 * 1024;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RequirementRegistry {
    schema_version: String,
    source: String,
    requirements: Vec<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct InvariantManifest {
    schema_version: String,
    requirement_registry: String,
    invariants: Vec<Invariant>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Invariant {
    id: String,
    title: String,
    critical: bool,
    process_boundary_required: bool,
    normative_requirements: Vec<String>,
    profiles: Vec<String>,
    fixtures: Vec<String>,
    release_threshold: ReleaseThreshold,
    evidence: Vec<String>,
    tests: Vec<TestMapping>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ReleaseThreshold {
    metric: String,
    comparator: Comparator,
    value: f64,
}

#[derive(Clone, Copy, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
enum Comparator {
    Equal,
    AtLeast,
    AtMost,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct TestMapping {
    id: String,
    #[serde(rename = "type")]
    kind: TestKind,
    file: String,
    name: String,
    command: String,
    status: TestStatus,
}

#[derive(Clone, Copy, Deserialize, Eq, Ord, PartialEq, PartialOrd)]
#[serde(rename_all = "snake_case")]
enum TestKind {
    Golden,
    Contract,
    Negative,
    Property,
    ProcessBoundary,
}

#[derive(Clone, Copy, Deserialize)]
#[serde(rename_all = "snake_case")]
enum TestStatus {
    Active,
    Skipped,
    Quarantined,
}

/// Validates the repository invariant manifest against its independent requirement registry.
pub fn validate_traceability(
    root: &Path,
    manifest_path: &Path,
) -> Result<TraceabilityResult, String> {
    let manifest_absolute = resolve_under(root, manifest_path)?;
    let manifest_bytes = read_bounded_file(&manifest_absolute)?;
    let manifest: InvariantManifest = yaml_serde::from_slice(&manifest_bytes)
        .map_err(|error| format!("invalid invariant manifest YAML: {error}"))?;
    if manifest.schema_version != "cigar.invariants.v1"
        || manifest.invariants.is_empty()
        || manifest.invariants.len() > 4096
    {
        return Err("invalid invariant manifest metadata".to_owned());
    }
    let registry_path = safe_relative(&manifest.requirement_registry)?;
    let registry_absolute = resolve_under(root, &registry_path)?;
    let registry_bytes = read_bounded_file(&registry_absolute)?;
    let registry: RequirementRegistry = serde_json::from_slice(&registry_bytes)
        .map_err(|error| format!("invalid requirement registry JSON: {error}"))?;
    if registry.schema_version != "cigar.invariant-requirements.v1"
        || registry.source.is_empty()
        || registry.source.len() > 512
        || registry.requirements.is_empty()
        || registry.requirements.len() > 8192
    {
        return Err("invalid normative requirement registry metadata".to_owned());
    }
    let mut requirements = BTreeSet::new();
    for requirement in &registry.requirements {
        if !valid_identifier(requirement, 96) || !requirements.insert(requirement.as_str()) {
            return Err(format!("invalid or duplicate requirement `{requirement}`"));
        }
    }

    let profile_registry = load_profile_registry(root)?;
    let mut invariant_ids = BTreeSet::new();
    let mut test_ids = BTreeSet::new();
    let mut mapped_requirements = BTreeMap::<&str, usize>::new();
    for invariant in &manifest.invariants {
        validate_invariant_identity(invariant, &mut invariant_ids)?;
        for requirement in &invariant.normative_requirements {
            if !requirements.contains(requirement.as_str()) {
                return Err(format!(
                    "invariant `{}` maps unknown requirement `{requirement}`",
                    invariant.id
                ));
            }
            let count = mapped_requirements.entry(requirement.as_str()).or_default();
            *count = count.saturating_add(1);
        }
        validate_profiles(invariant, &profile_registry)?;
        validate_paths(root, invariant)?;
        validate_threshold(invariant)?;
        let mut kinds = BTreeSet::new();
        for mapping in &invariant.tests {
            validate_test(root, mapping, &mut test_ids)?;
            kinds.insert(mapping.kind);
        }
        if invariant.critical
            && ![TestKind::Golden, TestKind::Negative, TestKind::Property]
                .iter()
                .all(|kind| kinds.contains(kind))
        {
            return Err(format!(
                "critical invariant `{}` lacks golden, negative, or property evidence",
                invariant.id
            ));
        }
        if invariant.process_boundary_required && !kinds.contains(&TestKind::ProcessBoundary) {
            return Err(format!(
                "invariant `{}` lacks process-boundary evidence",
                invariant.id
            ));
        }
    }
    for requirement in requirements.iter().copied() {
        if mapped_requirements
            .get(requirement)
            .copied()
            .unwrap_or_default()
            == 0
        {
            return Err(format!(
                "normative requirement `{requirement}` has no executable evidence mapping"
            ));
        }
    }

    Ok(TraceabilityResult {
        schema_version: "cigar.invariant-traceability-result.v1".to_owned(),
        manifest_digest: hash_file(&manifest_absolute)?,
        requirement_registry_digest: hash_file(&registry_absolute)?,
        requirement_count: requirements.len(),
        test_count: test_ids.len(),
        valid: true,
    })
}

fn validate_invariant_identity<'a>(
    invariant: &'a Invariant,
    ids: &mut BTreeSet<&'a str>,
) -> Result<(), String> {
    if !valid_identifier(&invariant.id, 96)
        || !ids.insert(&invariant.id)
        || invariant.title.is_empty()
        || invariant.title.len() > 256
        || invariant.normative_requirements.is_empty()
        || invariant.normative_requirements.len() > 256
        || invariant.tests.is_empty()
        || invariant.tests.len() > 256
    {
        return Err(format!("invalid invariant `{}`", invariant.id));
    }
    let unique: BTreeSet<_> = invariant.normative_requirements.iter().collect();
    if unique.len() != invariant.normative_requirements.len() {
        return Err(format!(
            "invariant `{}` repeats a normative requirement",
            invariant.id
        ));
    }
    Ok(())
}

fn validate_profiles(invariant: &Invariant, registry: &BTreeSet<String>) -> Result<(), String> {
    if invariant.profiles.is_empty() || invariant.profiles.len() > 16 {
        return Err(format!("invariant `{}` has no profile", invariant.id));
    }
    let mut unique = BTreeSet::new();
    for profile in &invariant.profiles {
        if !registry.contains(profile) || !unique.insert(profile) {
            return Err(format!(
                "invariant `{}` has unknown or duplicate profile `{profile}`",
                invariant.id
            ));
        }
    }
    Ok(())
}

fn validate_paths(root: &Path, invariant: &Invariant) -> Result<(), String> {
    if invariant.fixtures.is_empty()
        || invariant.fixtures.len() > 128
        || invariant.evidence.is_empty()
        || invariant.evidence.len() > 128
    {
        return Err(format!("invariant `{}` has incomplete paths", invariant.id));
    }
    for fixture in &invariant.fixtures {
        let relative = safe_relative(fixture)?;
        let absolute = resolve_under(root, &relative)?;
        let metadata = std::fs::symlink_metadata(&absolute)
            .map_err(|error| format!("fixture `{fixture}` does not exist: {error}"))?;
        if metadata.file_type().is_symlink()
            || !(metadata.file_type().is_file() || metadata.file_type().is_dir())
        {
            return Err(format!("fixture `{fixture}` has an unsafe file type"));
        }
    }
    let mut evidence = BTreeSet::new();
    for path in &invariant.evidence {
        let relative = safe_relative(path)?;
        if relative.components().next() != Some(Component::Normal("reports".as_ref()))
            || relative.extension().and_then(|value| value.to_str()) != Some("json")
            || !evidence.insert(path)
        {
            return Err(format!("invalid evidence path `{path}`"));
        }
    }
    Ok(())
}

fn validate_threshold(invariant: &Invariant) -> Result<(), String> {
    let threshold = &invariant.release_threshold;
    if !valid_metric(&threshold.metric)
        || !threshold.value.is_finite()
        || threshold.value < 0.0
        || threshold.value > 1_000_000_000.0
    {
        return Err(format!(
            "invariant `{}` has an invalid release threshold",
            invariant.id
        ));
    }
    let exact = match threshold.metric.as_str() {
        "required_case_pass_fraction" | "mapped_requirement_fraction" => {
            threshold.comparator == Comparator::Equal && threshold.value == 1.0
        }
        "undetected_fault_count" => {
            threshold.comparator == Comparator::Equal && threshold.value == 0.0
        }
        _ => false,
    };
    if !exact {
        return Err(format!(
            "invariant `{}` weakens or invents a release threshold",
            invariant.id
        ));
    }
    Ok(())
}

fn validate_test<'a>(
    root: &Path,
    mapping: &'a TestMapping,
    test_ids: &mut BTreeSet<&'a str>,
) -> Result<(), String> {
    if !valid_identifier(&mapping.id, 96)
        || !test_ids.insert(&mapping.id)
        || !valid_test_name(&mapping.name)
        || mapping.command.is_empty()
        || mapping.command.len() > 512
        || !mapping.command.starts_with("cargo ")
        || mapping.command.contains("--ignored")
        || mapping.command.split_ascii_whitespace().any(|token| {
            matches!(
                token.to_ascii_lowercase().as_str(),
                "quarantine" | "quarantined" | "--quarantine" | "--quarantined"
            )
        })
        || mapping.command.to_ascii_lowercase().contains("--skip")
    {
        return Err(format!(
            "invalid, skipped, or quarantined test `{}`",
            mapping.id
        ));
    }
    if !matches!(mapping.status, TestStatus::Active) {
        return Err(format!("test `{}` is not active", mapping.id));
    }
    let relative = safe_relative(&mapping.file)?;
    let absolute = resolve_under(root, &relative)?;
    let source = read_bounded_file(&absolute)?;
    let source = std::str::from_utf8(&source)
        .map_err(|_error| format!("test file `{}` is not UTF-8", mapping.file))?;
    let marker = format!("fn {}(", mapping.name);
    let position = source
        .find(&marker)
        .ok_or_else(|| format!("referenced test `{}` does not exist", mapping.id))?;
    let preceding = source
        .get(..position)
        .ok_or_else(|| format!("referenced test `{}` has an invalid offset", mapping.id))?;
    let attribute = preceding
        .rfind("#[test]")
        .and_then(|offset| preceding.get(offset..))
        .ok_or_else(|| format!("referenced function `{}` is not a test", mapping.id))?;
    if attribute.len() > 512
        || attribute.contains("fn ")
        || attribute.contains("#[ignore")
        || attribute.to_ascii_lowercase().contains("quarantin")
    {
        return Err(format!(
            "referenced function `{}` is not an active test",
            mapping.id
        ));
    }
    Ok(())
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ProfileRegistry {
    schema_version: String,
    profiles: Vec<String>,
}

fn load_profile_registry(root: &Path) -> Result<BTreeSet<String>, String> {
    let path = root.join("conformance/profiles/v1.json");
    let bytes = read_bounded_file(&path)?;
    let registry: ProfileRegistry = serde_json::from_slice(&bytes)
        .map_err(|error| format!("invalid profile registry: {error}"))?;
    if registry.schema_version != "cigar.conformance.profile-registry.v1"
        || registry.profiles.len() != 8
    {
        return Err("profile registry differs from the frozen v1 surface".to_owned());
    }
    let profiles: BTreeSet<_> = registry.profiles.into_iter().collect();
    let expected = BTreeSet::from([
        "cigar-catalog-v1".to_owned(),
        "cigar-compiler-v1".to_owned(),
        "cigar-core-v1".to_owned(),
        "cigar-effect-v1".to_owned(),
        "cigar-handoff-v1".to_owned(),
        "cigar-replay-v1".to_owned(),
        "cigar-runtime-claude-code-v1".to_owned(),
        "cigar-service-v1".to_owned(),
    ]);
    if profiles != expected {
        return Err("profile registry differs from the frozen v1 profile set".to_owned());
    }
    Ok(profiles)
}

fn read_bounded_file(path: &Path) -> Result<Vec<u8>, String> {
    let metadata = std::fs::symlink_metadata(path)
        .map_err(|error| format!("cannot inspect traceability input: {error}"))?;
    if !metadata.file_type().is_file() || metadata.len() > MAX_TRACEABILITY_BYTES {
        return Err("traceability input must be a bounded regular file".to_owned());
    }
    let mut bytes = Vec::with_capacity(
        usize::try_from(metadata.len())
            .map_err(|_error| "traceability file length overflow".to_owned())?,
    );
    File::open(path)
        .and_then(|file| {
            file.take(MAX_TRACEABILITY_BYTES.saturating_add(1))
                .read_to_end(&mut bytes)
        })
        .map_err(|error| format!("cannot read traceability input: {error}"))?;
    if bytes.len() as u64 != metadata.len() {
        return Err("traceability input changed while being read".to_owned());
    }
    Ok(bytes)
}

fn resolve_under(root: &Path, relative: &Path) -> Result<PathBuf, String> {
    if relative.is_absolute()
        || relative.components().any(|component| {
            matches!(
                component,
                Component::ParentDir | Component::RootDir | Component::Prefix(_)
            )
        })
    {
        return Err("traceability path must remain repository-relative".to_owned());
    }
    let canonical_root = root
        .canonicalize()
        .map_err(|error| format!("cannot resolve repository root: {error}"))?;
    let candidate = root
        .join(relative)
        .canonicalize()
        .map_err(|error| format!("cannot resolve traceability path: {error}"))?;
    if !candidate.starts_with(&canonical_root) {
        return Err("traceability path escaped the repository root".to_owned());
    }
    Ok(candidate)
}

fn safe_relative(value: &str) -> Result<PathBuf, String> {
    if value.is_empty() || value.len() > 512 || value.contains('\0') {
        return Err("traceability path is invalid".to_owned());
    }
    let path = PathBuf::from(value);
    if path.is_absolute()
        || path.components().any(|component| {
            matches!(
                component,
                Component::CurDir
                    | Component::ParentDir
                    | Component::RootDir
                    | Component::Prefix(_)
            )
        })
    {
        return Err(format!("unsafe traceability path `{value}`"));
    }
    Ok(path)
}

fn valid_identifier(value: &str, maximum: usize) -> bool {
    !value.is_empty()
        && value.len() <= maximum
        && value.bytes().all(|byte| {
            byte.is_ascii_uppercase() || byte.is_ascii_digit() || matches!(byte, b'-' | b'_' | b'.')
        })
}

fn valid_test_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
}

fn valid_metric(value: &str) -> bool {
    valid_test_name(value)
}
