//! Fail-closed PRD-to-invariant-to-evidence traceability validation.

use crate::digest::{hash_file, sha256, valid_sha256};
use crate::model::TraceabilityResult;
use crate::prd_traceability::{
    EXTRACTION_VERSION, ExtractedRequirement, RequirementKind, extract_prd_requirements, kind_name,
    surface_digest,
};
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
    source: RequirementSource,
    requirements: Vec<SourceRequirement>,
    derived_requirements: Vec<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RequirementSource {
    path: String,
    extraction_version: String,
    surface_sha256: String,
    source_requirement_count: usize,
    normative_occurrence_count: usize,
    release_gate_count: usize,
    security_invariant_count: usize,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SourceRequirement {
    id: String,
    kinds: Vec<RequirementKind>,
    critical: bool,
    source: SourceLocation,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SourceLocation {
    path: String,
    start_line: usize,
    end_line: usize,
    section: String,
    text: String,
    text_sha256: String,
    normative_token_count: usize,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct InvariantManifest {
    schema_version: String,
    requirement_registry: String,
    fault_registry: String,
    invariants: Vec<Invariant>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct FaultRegistry {
    schema_version: String,
    adapter: FaultAdapter,
    faults: Vec<FaultEntry>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct FaultAdapter {
    id: String,
    source: String,
    source_sha256: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct FaultEntry {
    id: String,
    mode: String,
    classification: FaultClassification,
    source_selector: String,
    detection: FaultDetection,
    bindings: Vec<FaultBinding>,
}

#[derive(Clone, Copy, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
enum FaultClassification {
    InjectedFailure,
    AdversarialProbe,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct FaultDetection {
    kind: FaultDetectionKind,
    case_scope: FaultCaseScope,
    diagnostic: Option<String>,
}

#[derive(Clone, Copy, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
enum FaultDetectionKind {
    CaseFailure,
    IsolationBlocked,
    FreshNamespace,
}

#[derive(Clone, Copy, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
enum FaultCaseScope {
    FirstRequired,
    AllRequired,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct FaultBinding {
    profile: String,
    intended_invariant: String,
    intended_requirement: String,
    proof_test: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Invariant {
    id: String,
    title: String,
    critical: bool,
    normative_requirements: Vec<String>,
    source_requirement_kinds: Vec<RequirementKind>,
    profiles: Vec<String>,
    fixtures: Vec<String>,
    release_threshold: ReleaseThreshold,
    evidence_requirements: EvidenceRequirements,
    evidence: Vec<EvidenceBinding>,
    tests: Vec<TestMapping>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct EvidenceRequirements {
    process_boundary: EvidenceApplicability,
    cross_runtime: EvidenceApplicability,
    installed_bytes: EvidenceApplicability,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct EvidenceApplicability {
    applicable: bool,
    rationale: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct EvidenceBinding {
    path: String,
    schema_version: String,
    freshness: EvidenceFreshness,
    produced_by: Vec<String>,
}

#[derive(Clone, Copy, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
enum EvidenceFreshness {
    CurrentRun,
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
    #[serde(default)]
    runner: TestRunner,
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
    CrossRuntime,
    InstalledBytes,
}

#[derive(Clone, Copy, Default, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
enum TestRunner {
    #[default]
    RustTest,
    Xtask,
}

#[derive(Clone, Copy, Deserialize)]
#[serde(rename_all = "snake_case")]
enum TestStatus {
    Active,
    Skipped,
    Quarantined,
}

/// Validates the PRD baseline and invariant manifest against active executable evidence mappings.
pub fn validate_traceability(
    root: &Path,
    manifest_path: &Path,
) -> Result<TraceabilityResult, String> {
    let manifest_absolute = resolve_under(root, manifest_path)?;
    let manifest_bytes = read_bounded_file(&manifest_absolute)?;
    let manifest: InvariantManifest = yaml_serde::from_slice(&manifest_bytes)
        .map_err(|error| format!("invalid invariant manifest YAML: {error}"))?;
    if manifest.schema_version != "cigar.invariants.v2"
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
    if registry.schema_version != "cigar.invariant-requirements.v2"
        || registry.requirements.is_empty()
        || registry.requirements.len() > 4096
        || registry.derived_requirements.is_empty()
        || registry.derived_requirements.len() > 8192
    {
        return Err("invalid normative requirement registry metadata".to_owned());
    }

    let prd_path = safe_relative(&registry.source.path)?;
    let prd_absolute = resolve_under(root, &prd_path)?;
    let prd_bytes = read_bounded_file(&prd_absolute)?;
    let extracted = extract_prd_requirements(&prd_bytes)?;
    validate_source_baseline(&registry, &extracted)?;

    let mut requirements = BTreeSet::<String>::new();
    let mut source_by_kind = BTreeMap::<RequirementKind, BTreeSet<String>>::new();
    for requirement in &registry.requirements {
        if !valid_identifier(&requirement.id, 96) || !requirements.insert(requirement.id.clone()) {
            return Err(format!(
                "invalid or duplicate source requirement `{}`",
                requirement.id
            ));
        }
        for kind in &requirement.kinds {
            source_by_kind
                .entry(*kind)
                .or_default()
                .insert(requirement.id.clone());
        }
    }
    for requirement in &registry.derived_requirements {
        if !valid_identifier(requirement, 96) || !requirements.insert(requirement.clone()) {
            return Err(format!(
                "invalid or duplicate derived requirement `{requirement}`"
            ));
        }
    }

    let profile_registry = load_profile_registry(root)?;
    let mut invariant_ids = BTreeSet::new();
    let mut test_ids = BTreeSet::new();
    let mut mapped_requirements = BTreeMap::<String, usize>::new();
    for invariant in &manifest.invariants {
        validate_invariant_identity(invariant, &mut invariant_ids)?;
        for requirement in &invariant.normative_requirements {
            if !requirements.contains(requirement) {
                return Err(format!(
                    "invariant `{}` maps unknown requirement `{requirement}`",
                    invariant.id
                ));
            }
            let count = mapped_requirements.entry(requirement.clone()).or_default();
            *count = count.saturating_add(1);
        }
        for kind in &invariant.source_requirement_kinds {
            let selected = source_by_kind.get(kind).ok_or_else(|| {
                format!(
                    "invariant `{}` selects empty source kind `{}`",
                    invariant.id,
                    kind_name(*kind)
                )
            })?;
            for requirement in selected {
                let count = mapped_requirements.entry(requirement.clone()).or_default();
                *count = count.saturating_add(1);
            }
        }
        validate_profiles(invariant, &profile_registry)?;
        validate_fixtures(root, invariant)?;
        validate_threshold(invariant)?;
        let mut kinds = BTreeSet::new();
        let mut invariant_test_ids = BTreeSet::new();
        for mapping in &invariant.tests {
            validate_test(root, mapping, &mut test_ids)?;
            kinds.insert(mapping.kind);
            invariant_test_ids.insert(mapping.id.as_str());
        }
        validate_evidence_classes(invariant, &kinds)?;
        validate_evidence_bindings(root, invariant, &invariant_test_ids)?;
        if invariant.critical && !has_positive_evidence(&kinds) {
            return Err(format!(
                "critical invariant `{}` lacks positive contract or vector evidence",
                invariant.id
            ));
        }
        if invariant.critical
            && ![TestKind::Negative, TestKind::Property]
                .iter()
                .all(|kind| kinds.contains(kind))
        {
            return Err(format!(
                "critical invariant `{}` lacks negative or property/model evidence",
                invariant.id
            ));
        }
    }
    for requirement in &requirements {
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
    validate_fault_registry(root, &manifest, &profile_registry)?;

    Ok(TraceabilityResult {
        schema_version: "cigar.invariant-traceability-result.v1".to_owned(),
        manifest_digest: hash_file(&manifest_absolute)?,
        requirement_registry_digest: hash_file(&registry_absolute)?,
        prd_digest: hash_file(&prd_absolute)?,
        normative_surface_digest: surface_digest(&extracted),
        requirement_count: requirements.len(),
        source_requirement_count: extracted.len(),
        derived_requirement_count: registry.derived_requirements.len(),
        normative_occurrence_count: extracted
            .iter()
            .map(|requirement| requirement.normative_token_count)
            .sum(),
        release_gate_count: extracted
            .iter()
            .filter(|requirement| requirement.kinds.contains(&RequirementKind::ReleaseGate))
            .count(),
        security_invariant_count: extracted
            .iter()
            .filter(|requirement| {
                requirement
                    .kinds
                    .contains(&RequirementKind::SecurityInvariant)
            })
            .count(),
        mapped_requirement_fraction: 1.0,
        inactive_mapping_count: 0,
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
        || (invariant.normative_requirements.is_empty()
            && invariant.source_requirement_kinds.is_empty())
        || invariant.normative_requirements.len() > 8192
        || invariant.source_requirement_kinds.len() > 3
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
    let source_kinds: BTreeSet<_> = invariant.source_requirement_kinds.iter().collect();
    if source_kinds.len() != invariant.source_requirement_kinds.len() {
        return Err(format!(
            "invariant `{}` repeats a source requirement selector",
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

fn validate_fault_registry(
    root: &Path,
    manifest: &InvariantManifest,
    profiles: &BTreeSet<String>,
) -> Result<(), String> {
    if manifest.fault_registry != "conformance/profiles/faults-v1.json" {
        return Err("invariant manifest names an unexpected fault registry".to_owned());
    }
    let registry_path = safe_relative(&manifest.fault_registry)?;
    let registry_absolute = resolve_under(root, &registry_path)?;
    let registry_bytes = read_bounded_file(&registry_absolute)?;
    let registry: FaultRegistry = serde_json::from_slice(&registry_bytes)
        .map_err(|error| format!("invalid injected-fault registry JSON: {error}"))?;
    if registry.schema_version != "cigar.conformance.fault-registry.v1"
        || registry.adapter.id != "cigar-conformance-faulty"
        || registry.adapter.source != "conformance/runner/src/bin/cigar-conformance-faulty.rs"
        || !valid_sha256(&registry.adapter.source_sha256)
        || registry.faults.len() != 8
        || registry
            .faults
            .windows(2)
            .any(|pair| matches!(pair, [left, right] if left.id >= right.id))
    {
        return Err("invalid injected-fault registry metadata".to_owned());
    }

    let source_path = safe_relative(&registry.adapter.source)?;
    let source_absolute = resolve_under(root, &source_path)?;
    if hash_file(&source_absolute)? != registry.adapter.source_sha256 {
        return Err("injected-fault adapter source changed without registry review".to_owned());
    }
    let source_bytes = read_bounded_file(&source_absolute)?;
    let source = std::str::from_utf8(&source_bytes)
        .map_err(|_error| "injected-fault adapter source is not UTF-8".to_owned())?;
    let source_modes = extract_fault_modes(source)?;
    let expected_modes = BTreeSet::from([
        "crash",
        "escape",
        "flood",
        "malformed",
        "skipped",
        "stateful",
        "timeout",
        "wrong",
    ]);
    if source_modes != expected_modes {
        return Err("injected-fault adapter mode surface differs from frozen v1".to_owned());
    }

    let mut ids = BTreeSet::new();
    let mut modes = BTreeSet::new();
    let mut mode_profiles = BTreeSet::new();
    for fault in &registry.faults {
        if !valid_identifier(&fault.id, 96)
            || !valid_fault_mode(&fault.mode)
            || !ids.insert(fault.id.as_str())
            || !modes.insert(fault.mode.as_str())
            || fault.id != expected_fault_id(&fault.mode).unwrap_or_default()
            || fault.source_selector != format!("mode.contains(\"{}\")", fault.mode)
            || source.matches(&fault.source_selector).count() != 1
            || fault.bindings.is_empty()
            || fault.bindings.len() > profiles.len()
            || fault
                .bindings
                .windows(2)
                .any(|pair| matches!(pair, [left, right] if left.profile >= right.profile))
        {
            return Err(format!(
                "invalid or duplicate injected fault `{}`",
                fault.id
            ));
        }
        validate_fault_shape(fault)?;

        let expected_profiles = if matches!(fault.mode.as_str(), "wrong" | "skipped") {
            profiles.clone()
        } else {
            BTreeSet::from(["cigar-core-v1".to_owned()])
        };
        let observed_profiles: BTreeSet<_> = fault
            .bindings
            .iter()
            .map(|binding| binding.profile.clone())
            .collect();
        if observed_profiles != expected_profiles || observed_profiles.len() != fault.bindings.len()
        {
            return Err(format!(
                "fault `{}` does not cover its exact profile surface",
                fault.id
            ));
        }

        for binding in &fault.bindings {
            if !mode_profiles.insert((fault.mode.as_str(), binding.profile.as_str())) {
                return Err(format!(
                    "fault `{}` repeats profile `{}`",
                    fault.id, binding.profile
                ));
            }
            let (expected_invariant, expected_requirement, expected_test) =
                expected_fault_binding(&fault.mode, &binding.profile).ok_or_else(|| {
                    format!(
                        "fault `{}` has no reviewed intent for profile `{}`",
                        fault.id, binding.profile
                    )
                })?;
            if binding.intended_invariant != expected_invariant
                || binding.intended_requirement != expected_requirement
                || binding.proof_test != expected_test
            {
                return Err(format!(
                    "fault `{}` is misdirected for profile `{}`",
                    fault.id, binding.profile
                ));
            }
            let invariant = manifest
                .invariants
                .iter()
                .find(|invariant| invariant.id == binding.intended_invariant)
                .ok_or_else(|| {
                    format!(
                        "fault `{}` names unknown invariant `{}`",
                        fault.id, binding.intended_invariant
                    )
                })?;
            if !invariant.profiles.contains(&binding.profile)
                || !invariant
                    .normative_requirements
                    .contains(&binding.intended_requirement)
            {
                return Err(format!(
                    "fault `{}` does not target a requirement owned by its invariant and profile",
                    fault.id
                ));
            }
            let proof = invariant
                .tests
                .iter()
                .find(|mapping| mapping.id == binding.proof_test)
                .ok_or_else(|| {
                    format!(
                        "fault `{}` names proof test `{}` outside its intended invariant",
                        fault.id, binding.proof_test
                    )
                })?;
            validate_fault_proof_source(root, fault, proof)?;
        }
    }
    if modes != expected_modes {
        return Err("injected-fault registry omits or invents an adapter mode".to_owned());
    }
    Ok(())
}

fn extract_fault_modes(source: &str) -> Result<BTreeSet<&str>, String> {
    let marker = "mode.contains(\"";
    let mut modes = BTreeSet::new();
    for suffix in source.split(marker).skip(1) {
        let mode = suffix
            .split_once("\")")
            .map(|(mode, _remainder)| mode)
            .ok_or_else(|| "injected-fault adapter has an unterminated mode selector".to_owned())?;
        if !valid_fault_mode(mode) || !modes.insert(mode) {
            return Err("injected-fault adapter has an invalid or duplicate mode".to_owned());
        }
    }
    Ok(modes)
}

fn validate_fault_shape(fault: &FaultEntry) -> Result<(), String> {
    let expected = match fault.mode.as_str() {
        "crash" => (
            FaultClassification::InjectedFailure,
            FaultDetectionKind::CaseFailure,
            FaultCaseScope::FirstRequired,
            Some("adapter_crash"),
        ),
        "escape" => (
            FaultClassification::AdversarialProbe,
            FaultDetectionKind::IsolationBlocked,
            FaultCaseScope::FirstRequired,
            None,
        ),
        "flood" => (
            FaultClassification::InjectedFailure,
            FaultDetectionKind::CaseFailure,
            FaultCaseScope::FirstRequired,
            Some("output_limit"),
        ),
        "malformed" => (
            FaultClassification::InjectedFailure,
            FaultDetectionKind::CaseFailure,
            FaultCaseScope::FirstRequired,
            Some("malformed_response"),
        ),
        "skipped" => (
            FaultClassification::InjectedFailure,
            FaultDetectionKind::CaseFailure,
            FaultCaseScope::AllRequired,
            Some("malformed_response"),
        ),
        "stateful" => (
            FaultClassification::AdversarialProbe,
            FaultDetectionKind::FreshNamespace,
            FaultCaseScope::AllRequired,
            None,
        ),
        "timeout" => (
            FaultClassification::InjectedFailure,
            FaultDetectionKind::CaseFailure,
            FaultCaseScope::FirstRequired,
            Some("timeout"),
        ),
        "wrong" => (
            FaultClassification::InjectedFailure,
            FaultDetectionKind::CaseFailure,
            FaultCaseScope::AllRequired,
            Some("public_result_mismatch"),
        ),
        _ => return Err(format!("unknown injected-fault mode `{}`", fault.mode)),
    };
    if fault.classification != expected.0
        || fault.detection.kind != expected.1
        || fault.detection.case_scope != expected.2
        || fault.detection.diagnostic.as_deref() != expected.3
    {
        return Err(format!(
            "fault `{}` has a non-canonical detection contract",
            fault.id
        ));
    }
    Ok(())
}

fn expected_fault_id(mode: &str) -> Option<&'static str> {
    match mode {
        "crash" => Some("FAULT-ADAPTER-CRASH-001"),
        "escape" => Some("FAULT-ADAPTER-ESCAPE-001"),
        "flood" => Some("FAULT-ADAPTER-FLOOD-001"),
        "malformed" => Some("FAULT-ADAPTER-MALFORMED-001"),
        "skipped" => Some("FAULT-ADAPTER-SKIPPED-001"),
        "stateful" => Some("FAULT-ADAPTER-STATEFUL-001"),
        "timeout" => Some("FAULT-ADAPTER-TIMEOUT-001"),
        "wrong" => Some("FAULT-ADAPTER-WRONG-001"),
        _ => None,
    }
}

fn expected_fault_binding(
    mode: &str,
    profile: &str,
) -> Option<(&'static str, &'static str, &'static str)> {
    if mode == "wrong" && profile == "cigar-core-v1" {
        return Some(("INV-CORE-CANONICAL-V1", "VER-CANON-DIGEST-001", "CONF-N001"));
    }
    if mode == "skipped" && profile == "cigar-core-v1" {
        return Some((
            "INV-CORE-CANONICAL-V1",
            "CONF-REQUIRED-NOSKIP-001",
            "CONF-N001",
        ));
    }
    if matches!(mode, "wrong" | "skipped") {
        let requirement = match profile {
            "cigar-catalog-v1" => "CONF-CATALOG-FAILCLOSED-001",
            "cigar-compiler-v1" => "CONF-COMPILER-FAILCLOSED-001",
            "cigar-effect-v1" => "CONF-EFFECT-FAILCLOSED-001",
            "cigar-handoff-v1" => "CONF-HANDOFF-FAILCLOSED-001",
            "cigar-replay-v1" => "CONF-REPLAY-FAILCLOSED-001",
            "cigar-runtime-claude-code-v1" => "CONF-RUNTIME-CLAUDE-FAILCLOSED-001",
            "cigar-service-v1" => "CONF-SERVICE-FAILCLOSED-001",
            _ => return None,
        };
        return Some(("INV-PRODUCTION-PROFILES-V1", requirement, "PROFILES-N001"));
    }
    match (mode, profile) {
        ("crash" | "flood" | "timeout", "cigar-core-v1") => Some((
            "INV-CONFORMANCE-RUNNER-V1",
            "CONF-FAULT-DETECTION-001",
            "RUN-X001",
        )),
        ("malformed", "cigar-core-v1") => Some((
            "INV-CONFORMANCE-RUNNER-V1",
            "CONF-RESULT-SCHEMA-001",
            "RUN-X001",
        )),
        ("escape", "cigar-core-v1") => Some((
            "INV-CONFORMANCE-RUNNER-V1",
            "CONF-ISOLATION-001",
            "RUN-C001",
        )),
        ("stateful", "cigar-core-v1") => Some((
            "INV-CONFORMANCE-RUNNER-V1",
            "CONF-FRESH-NAMESPACE-001",
            "RUN-X002",
        )),
        _ => None,
    }
}

fn validate_fault_proof_source(
    root: &Path,
    fault: &FaultEntry,
    proof: &TestMapping,
) -> Result<(), String> {
    let relative = safe_relative(&proof.file)?;
    let source = read_bounded_file(&resolve_under(root, &relative)?)?;
    let source = std::str::from_utf8(&source)
        .map_err(|_error| format!("fault proof `{}` is not UTF-8", proof.id))?;
    let marker = format!("fn {}(", proof.name);
    let start = source
        .find(&marker)
        .ok_or_else(|| format!("fault proof `{}` no longer exists", proof.id))?;
    let suffix = source
        .get(start..)
        .ok_or_else(|| format!("fault proof `{}` has an invalid offset", proof.id))?;
    let body = suffix
        .find("\n#[test]")
        .and_then(|end| suffix.get(..end))
        .unwrap_or(suffix);
    if !body.contains(&format!("\"{}\"", fault.mode)) {
        return Err(format!(
            "fault `{}` proof test does not select its adapter mode",
            fault.id
        ));
    }
    if let Some(diagnostic) = &fault.detection.diagnostic
        && !body.contains(&format!("\"{diagnostic}\""))
    {
        return Err(format!(
            "fault `{}` proof test does not assert its exact diagnostic",
            fault.id
        ));
    }
    let probe_marker = match fault.detection.kind {
        FaultDetectionKind::CaseFailure => "CaseStatus::Failed",
        FaultDetectionKind::IsolationBlocked => "!escape_path.exists()",
        FaultDetectionKind::FreshNamespace => "CaseStatus::Passed",
    };
    if !body.contains(probe_marker) {
        return Err(format!(
            "fault `{}` proof test lacks its exact case-level assertion",
            fault.id
        ));
    }
    Ok(())
}

fn validate_source_baseline(
    registry: &RequirementRegistry,
    extracted: &[ExtractedRequirement],
) -> Result<(), String> {
    let source = &registry.source;
    if source.path != "prd.md"
        || source.extraction_version != EXTRACTION_VERSION
        || !valid_sha256(&source.surface_sha256)
        || source.source_requirement_count != extracted.len()
        || registry.requirements.len() != extracted.len()
    {
        return Err("normative source baseline metadata is stale or invalid".to_owned());
    }
    let normative_occurrence_count: usize = extracted
        .iter()
        .map(|requirement| requirement.normative_token_count)
        .sum();
    let release_gate_count = extracted
        .iter()
        .filter(|requirement| requirement.kinds.contains(&RequirementKind::ReleaseGate))
        .count();
    let security_invariant_count = extracted
        .iter()
        .filter(|requirement| {
            requirement
                .kinds
                .contains(&RequirementKind::SecurityInvariant)
        })
        .count();
    if source.normative_occurrence_count != normative_occurrence_count
        || source.release_gate_count != release_gate_count
        || source.security_invariant_count != security_invariant_count
        || source.surface_sha256 != surface_digest(extracted)
    {
        return Err("normative source counts or surface digest changed".to_owned());
    }

    let mut ids = BTreeSet::new();
    let mut spans = BTreeSet::new();
    let mut normative_ordinal = 0_usize;
    let mut release_gate_ordinal = 0_usize;
    let mut security_ordinal = 0_usize;
    for (baseline, observed) in registry.requirements.iter().zip(extracted) {
        let kinds: BTreeSet<_> = baseline.kinds.iter().copied().collect();
        if !valid_identifier(&baseline.id, 96)
            || !ids.insert(baseline.id.as_str())
            || baseline.kinds.is_empty()
            || baseline.kinds.len() > 3
            || kinds.len() != baseline.kinds.len()
            || baseline
                .kinds
                .windows(2)
                .any(|pair| matches!(pair, [left, right] if left >= right))
            || !spans.insert((baseline.source.start_line, baseline.source.end_line))
        {
            return Err(format!(
                "invalid or duplicate PRD baseline entry `{}`",
                baseline.id
            ));
        }
        let expected_id = if kinds.contains(&RequirementKind::SecurityInvariant) {
            security_ordinal = security_ordinal.saturating_add(1);
            format!("PRD-SEC-{security_ordinal:04}")
        } else if kinds.contains(&RequirementKind::ReleaseGate) {
            release_gate_ordinal = release_gate_ordinal.saturating_add(1);
            format!("PRD-GATE-{release_gate_ordinal:04}")
        } else {
            normative_ordinal = normative_ordinal.saturating_add(1);
            format!("PRD-NORM-{normative_ordinal:04}")
        };
        if baseline.id != expected_id
            || baseline.critical
                != (kinds.contains(&RequirementKind::ReleaseGate)
                    || kinds.contains(&RequirementKind::SecurityInvariant))
            || baseline.source.path != source.path
            || baseline.source.start_line != observed.start_line
            || baseline.source.end_line != observed.end_line
            || baseline.source.section != observed.section
            || baseline.source.text != observed.text
            || baseline.source.text_sha256 != observed.text_sha256
            || baseline.source.normative_token_count != observed.normative_token_count
            || baseline.kinds != observed.kinds
            || !valid_sha256(&baseline.source.text_sha256)
            || baseline.source.text_sha256 != sha256(baseline.source.text.as_bytes())
        {
            return Err(format!(
                "PRD baseline entry `{}` no longer matches its source span",
                baseline.id
            ));
        }
    }
    Ok(())
}

fn validate_fixtures(root: &Path, invariant: &Invariant) -> Result<(), String> {
    if invariant.fixtures.is_empty() || invariant.fixtures.len() > 128 {
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
    Ok(())
}

fn validate_evidence_classes(
    invariant: &Invariant,
    kinds: &BTreeSet<TestKind>,
) -> Result<(), String> {
    let requirements = &invariant.evidence_requirements;
    for (label, applicability, kind) in [
        (
            "process_boundary",
            &requirements.process_boundary,
            TestKind::ProcessBoundary,
        ),
        (
            "cross_runtime",
            &requirements.cross_runtime,
            TestKind::CrossRuntime,
        ),
        (
            "installed_bytes",
            &requirements.installed_bytes,
            TestKind::InstalledBytes,
        ),
    ] {
        if applicability.rationale.trim().len() < 16 || applicability.rationale.len() > 512 {
            return Err(format!(
                "invariant `{}` has no bounded applicability rationale for `{label}`",
                invariant.id
            ));
        }
        if applicability.applicable && !kinds.contains(&kind) {
            return Err(format!(
                "invariant `{}` lacks required `{label}` evidence",
                invariant.id
            ));
        }
        if !applicability.applicable && kinds.contains(&kind) {
            return Err(format!(
                "invariant `{}` maps `{label}` evidence while declaring it not applicable",
                invariant.id
            ));
        }
    }
    Ok(())
}

fn has_positive_evidence(kinds: &BTreeSet<TestKind>) -> bool {
    kinds.contains(&TestKind::Golden) || kinds.contains(&TestKind::Contract)
}

fn validate_evidence_bindings(
    root: &Path,
    invariant: &Invariant,
    test_ids: &BTreeSet<&str>,
) -> Result<(), String> {
    if invariant.evidence.is_empty() || invariant.evidence.len() > 128 {
        return Err(format!(
            "invariant `{}` has no evidence binding",
            invariant.id
        ));
    }
    let mut evidence_paths = BTreeSet::new();
    let mut bound_tests = BTreeSet::new();
    for evidence in &invariant.evidence {
        let relative = safe_relative(&evidence.path)?;
        if relative.components().next() != Some(Component::Normal("reports".as_ref()))
            || relative.extension().and_then(|value| value.to_str()) != Some("json")
            || !evidence_paths.insert(evidence.path.as_str())
            || !valid_schema_version(&evidence.schema_version)
            || evidence.freshness != EvidenceFreshness::CurrentRun
            || evidence.produced_by.is_empty()
            || evidence.produced_by.len() > 256
        {
            return Err(format!("invalid evidence binding `{}`", evidence.path));
        }
        let mut producers = BTreeSet::new();
        for producer in &evidence.produced_by {
            if !producers.insert(producer.as_str()) || !test_ids.contains(producer.as_str()) {
                return Err(format!(
                    "evidence `{}` names unknown or duplicate producer `{producer}`",
                    evidence.path
                ));
            }
            bound_tests.insert(producer.as_str());
        }

        if evidence.schema_version == "cigar.invariant-traceability-result.v1" {
            if evidence.path != "reports/invariant-traceability.v1.json" {
                return Err(
                    "traceability self-evidence must use its reserved output path".to_owned(),
                );
            }
            continue;
        }
        let absolute = resolve_under(root, &relative)?;
        let bytes = read_bounded_file(&absolute)?;
        let document: serde_json::Value = serde_json::from_slice(&bytes)
            .map_err(|error| format!("invalid evidence JSON `{}`: {error}", evidence.path))?;
        if document
            .get("schema_version")
            .and_then(serde_json::Value::as_str)
            != Some(evidence.schema_version.as_str())
        {
            return Err(format!(
                "evidence `{}` has a stale or unexpected schema",
                evidence.path
            ));
        }
        if evidence.schema_version == crate::RESULT_SCHEMA {
            crate::verify_result_file_detached(&absolute, &root.join("conformance/vectors/v1"))?;
        }
    }
    let expected_bound_tests: BTreeSet<_> = test_ids.iter().copied().collect();
    if bound_tests != expected_bound_tests {
        return Err(format!(
            "invariant `{}` has tests without exact evidence bindings",
            invariant.id
        ));
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
    match mapping.runner {
        TestRunner::RustTest => {
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
            let test_target = relative
                .file_stem()
                .and_then(|value| value.to_str())
                .ok_or_else(|| format!("test `{}` has no UTF-8 target name", mapping.id))?;
            let expected = format!(
                "cargo test -p cigar-conformance --test {test_target} {}",
                mapping.name
            );
            if !mapping.file.starts_with("conformance/runner/tests/") || mapping.command != expected
            {
                return Err(format!(
                    "test `{}` command does not exactly select its mapped function",
                    mapping.id
                ));
            }
        }
        TestRunner::Xtask => {
            if mapping.kind != TestKind::CrossRuntime
                || mapping.file != "crates/xtask/src/lib.rs"
                || mapping.name != "verify_vector_suite"
                || mapping.command != "cargo xtask test vectors"
            {
                return Err(format!(
                    "xtask mapping `{}` is not an approved exact command route",
                    mapping.id
                ));
            }
        }
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

fn valid_fault_mode(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 32
        && value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
}

fn valid_metric(value: &str) -> bool {
    valid_test_name(value)
}

fn valid_schema_version(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value.starts_with("cigar.")
        && value.rsplit_once(".v").is_some_and(|(name, version)| {
            !name.is_empty()
                && !version.is_empty()
                && version.bytes().all(|byte| byte.is_ascii_digit())
        })
        && value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'.' | b'-' | b'_')
        })
}
