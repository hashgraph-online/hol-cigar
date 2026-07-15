//! Normative invariant traceability acceptance and negative tests.

use cigar_conformance::validate_traceability;
use serde::Deserialize;
use std::error::Error;
use std::fs;
use std::path::{Path, PathBuf};

fn repository_root() -> Result<PathBuf, Box<dyn Error>> {
    Ok(PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .ok_or("repository root unavailable")?
        .to_path_buf())
}

fn copy_file(root: &Path, destination: &Path, relative: &str) -> Result<(), Box<dyn Error>> {
    let target = destination.join(relative);
    let parent = target.parent().ok_or("fixture parent unavailable")?;
    fs::create_dir_all(parent)?;
    fs::copy(root.join(relative), target)?;
    Ok(())
}

fn traceability_fixture() -> Result<tempfile::TempDir, Box<dyn Error>> {
    let root = repository_root()?;
    let temporary = tempfile::tempdir()?;
    for relative in [
        "prd.md",
        "tests/invariants.yaml",
        "crates/xtask/src/lib.rs",
        "conformance/profiles/v1.json",
        "conformance/profiles/requirements-v1.json",
        "conformance/profiles/faults-v1.json",
        "conformance/vectors/v1/core-v1.json",
        "conformance/expected/cigar-core-v1.txt",
        "conformance/expected/cigar-catalog-v1.txt",
        "conformance/expected/cigar-compiler-v1.txt",
        "conformance/expected/cigar-handoff-v1.txt",
        "conformance/expected/cigar-effect-v1.txt",
        "conformance/expected/cigar-replay-v1.txt",
        "conformance/expected/cigar-service-v1.txt",
        "conformance/expected/cigar-runtime-claude-code-v1.txt",
        "conformance/runner/tests/conformance.rs",
        "conformance/runner/tests/traceability.rs",
        "conformance/runner/src/bin/cigar-conformance-faulty.rs",
        "reports/conformance-result.v1.json",
    ] {
        copy_file(&root, temporary.path(), relative)?;
    }
    Ok(temporary)
}

#[test]
fn repository_traceability_manifest_is_complete() -> Result<(), Box<dyn Error>> {
    let root = repository_root()?;
    let result = validate_traceability(&root, Path::new("tests/invariants.yaml"))?;
    assert!(result.valid);
    assert_eq!(result.requirement_count, 177);
    assert_eq!(result.source_requirement_count, 142);
    assert_eq!(result.derived_requirement_count, 35);
    assert_eq!(result.normative_occurrence_count, 30);
    assert_eq!(result.release_gate_count, 62);
    assert_eq!(result.security_invariant_count, 76);
    assert_eq!(result.mapped_requirement_fraction, 1.0);
    assert_eq!(result.inactive_mapping_count, 0);
    assert_eq!(result.test_count, 21);
    Ok(())
}

#[derive(Deserialize)]
struct FaultRegistry {
    faults: Vec<FaultEntry>,
}

#[derive(Deserialize)]
struct FaultEntry {
    mode: String,
    bindings: Vec<FaultBinding>,
}

#[derive(Deserialize)]
struct FaultBinding {
    profile: String,
    intended_invariant: String,
    intended_requirement: String,
    proof_test: String,
}

#[test]
fn fault_registry_maps_every_injection_to_exact_behavioral_proof() -> Result<(), Box<dyn Error>> {
    let root = repository_root()?;
    validate_traceability(&root, Path::new("tests/invariants.yaml"))?;
    let registry: FaultRegistry =
        serde_json::from_slice(&fs::read(root.join("conformance/profiles/faults-v1.json"))?)?;
    let modes = registry
        .faults
        .iter()
        .map(|fault| fault.mode.as_str())
        .collect::<std::collections::BTreeSet<_>>();
    assert_eq!(
        modes,
        std::collections::BTreeSet::from([
            "crash",
            "escape",
            "flood",
            "malformed",
            "skipped",
            "stateful",
            "timeout",
            "wrong",
        ])
    );
    assert_eq!(
        registry
            .faults
            .iter()
            .map(|fault| fault.bindings.len())
            .sum::<usize>(),
        22
    );
    for binding in registry
        .faults
        .iter()
        .flat_map(|fault| fault.bindings.iter())
    {
        assert!(binding.profile.starts_with("cigar-"));
        assert!(binding.intended_invariant.starts_with("INV-"));
        assert!(
            binding.intended_requirement.starts_with("CONF-")
                || binding.intended_requirement.starts_with("VER-")
        );
        assert!(
            binding.proof_test.starts_with("CONF-")
                || binding.proof_test.starts_with("RUN-")
                || binding.proof_test.starts_with("PROFILES-")
        );
    }
    Ok(())
}

#[test]
fn traceability_rejects_missing_duplicate_unknown_and_misdirected_faults()
-> Result<(), Box<dyn Error>> {
    let fixture = traceability_fixture()?;
    let manifest = Path::new("tests/invariants.yaml");
    let registry_path = fixture.path().join("conformance/profiles/faults-v1.json");
    let original: serde_json::Value = serde_json::from_slice(&fs::read(&registry_path)?)?;

    let mut missing = original.clone();
    missing
        .pointer_mut("/faults")
        .ok_or("fault registry entries unavailable")?
        .as_array_mut()
        .ok_or("fault registry entries unavailable")?
        .pop();
    fs::write(&registry_path, serde_json::to_vec_pretty(&missing)?)?;
    assert!(validate_traceability(fixture.path(), manifest).is_err());

    let mut duplicate = original.clone();
    let duplicate_mode = duplicate
        .pointer("/faults/0/mode")
        .ok_or("first fault mode unavailable")?
        .clone();
    let duplicate_selector = duplicate
        .pointer("/faults/0/source_selector")
        .ok_or("first fault selector unavailable")?
        .clone();
    *duplicate
        .pointer_mut("/faults/1/mode")
        .ok_or("second fault mode unavailable")? = duplicate_mode;
    *duplicate
        .pointer_mut("/faults/1/source_selector")
        .ok_or("second fault selector unavailable")? = duplicate_selector;
    fs::write(&registry_path, serde_json::to_vec_pretty(&duplicate)?)?;
    assert!(validate_traceability(fixture.path(), manifest).is_err());

    let mut unknown = original.clone();
    *unknown
        .pointer_mut("/faults/0/bindings/0/intended_invariant")
        .ok_or("first fault invariant binding unavailable")? =
        serde_json::Value::String("INV-CALLER-INVENTED-V1".to_owned());
    fs::write(&registry_path, serde_json::to_vec_pretty(&unknown)?)?;
    assert!(validate_traceability(fixture.path(), manifest).is_err());

    let mut misdirected = original.clone();
    *misdirected
        .pointer_mut("/faults/0/bindings/0/intended_requirement")
        .ok_or("first fault requirement binding unavailable")? =
        serde_json::Value::String("CONF-RESULT-SCHEMA-001".to_owned());
    fs::write(&registry_path, serde_json::to_vec_pretty(&misdirected)?)?;
    assert!(validate_traceability(fixture.path(), manifest).is_err());

    let mut unrelated_proof = original.clone();
    *unrelated_proof
        .pointer_mut("/faults/0/bindings/0/proof_test")
        .ok_or("first fault proof binding unavailable")? =
        serde_json::Value::String("RUN-C001".to_owned());
    fs::write(&registry_path, serde_json::to_vec_pretty(&unrelated_proof)?)?;
    assert!(validate_traceability(fixture.path(), manifest).is_err());

    fs::write(&registry_path, serde_json::to_vec_pretty(&original)?)?;
    let proof_path = fixture
        .path()
        .join("conformance/runner/tests/conformance.rs");
    let proof_source = fs::read_to_string(&proof_path)?;
    let weakened_proof = proof_source.replacen("\"adapter_crash\"", "\"generic_failure\"", 1);
    assert_ne!(weakened_proof, proof_source);
    fs::write(proof_path, weakened_proof)?;
    assert!(validate_traceability(fixture.path(), manifest).is_err());
    Ok(())
}

#[test]
fn traceability_rejects_unmapped_nonexistent_skipped_and_quarantined_tests()
-> Result<(), Box<dyn Error>> {
    let fixture = traceability_fixture()?;
    let path = fixture.path().join("tests/invariants.yaml");
    let original = fs::read_to_string(&path)?;

    let unmapped = original.replace("      - VER-TRACEABILITY-002\n", "");
    fs::write(&path, unmapped)?;
    assert!(validate_traceability(fixture.path(), Path::new("tests/invariants.yaml")).is_err());

    let nonexistent = original.replace(
        "name: repository_traceability_manifest_is_complete",
        "name: test_that_does_not_exist",
    );
    fs::write(&path, nonexistent)?;
    assert!(validate_traceability(fixture.path(), Path::new("tests/invariants.yaml")).is_err());

    let skipped = original.replacen("status: active", "status: skipped", 1);
    fs::write(&path, skipped)?;
    assert!(validate_traceability(fixture.path(), Path::new("tests/invariants.yaml")).is_err());

    let quarantined = original.replacen(
        "command: cargo test",
        "command: cargo test --ignored quarantine",
        1,
    );
    fs::write(&path, quarantined)?;
    assert!(validate_traceability(fixture.path(), Path::new("tests/invariants.yaml")).is_err());

    let weakened_threshold = original.replacen("value: 1.0", "value: 0.5", 1);
    fs::write(&path, weakened_threshold)?;
    assert!(validate_traceability(fixture.path(), Path::new("tests/invariants.yaml")).is_err());

    let mismatched_command = original.replacen(
        "command: cargo test -p cigar-conformance --test conformance reference_core_profile_passes_and_verifies",
        "command: cargo test -p cigar-conformance --test conformance result_verifier_rejects_every_single_field_tamper",
        1,
    );
    assert_ne!(mismatched_command, original);
    fs::write(&path, mismatched_command)?;
    assert!(validate_traceability(fixture.path(), Path::new("tests/invariants.yaml")).is_err());

    let nonexistent_fixture = original.replacen(
        "conformance/vectors/v1/core-v1.json",
        "conformance/vectors/v1/does-not-exist.json",
        1,
    );
    assert_ne!(nonexistent_fixture, original);
    fs::write(&path, nonexistent_fixture)?;
    assert!(validate_traceability(fixture.path(), Path::new("tests/invariants.yaml")).is_err());

    let duplicate_test_id =
        original.replacen("      - id: RUN-G001\n", "      - id: CONF-G001\n", 1);
    assert_ne!(duplicate_test_id, original);
    fs::write(&path, duplicate_test_id)?;
    assert!(validate_traceability(fixture.path(), Path::new("tests/invariants.yaml")).is_err());

    let missing_source_selector = original.replacen("      - security_invariant\n", "", 1);
    assert_ne!(missing_source_selector, original);
    fs::write(&path, missing_source_selector)?;
    assert!(validate_traceability(fixture.path(), Path::new("tests/invariants.yaml")).is_err());

    let missing_cross_runtime = original
        .replacen("          - CONF-D001\n", "", 1)
        .replacen(
            "      - id: CONF-D001\n        type: cross_runtime\n        runner: xtask\n        file: crates/xtask/src/lib.rs\n        name: verify_vector_suite\n        command: cargo xtask test vectors\n        status: active\n",
            "",
            1,
        );
    assert_ne!(missing_cross_runtime, original);
    fs::write(&path, missing_cross_runtime)?;
    assert!(validate_traceability(fixture.path(), Path::new("tests/invariants.yaml")).is_err());

    let duplicate_producer = original.replacen(
        "          - CONF-G001\n          - CONF-N001\n",
        "          - CONF-G001\n          - CONF-G001\n          - CONF-N001\n",
        1,
    );
    assert_ne!(duplicate_producer, original);
    fs::write(&path, duplicate_producer)?;
    assert!(validate_traceability(fixture.path(), Path::new("tests/invariants.yaml")).is_err());

    fs::write(&path, &original)?;
    let evidence_path = fixture.path().join("reports/conformance-result.v1.json");
    let original_evidence = fs::read(&evidence_path)?;
    let mut stale_evidence: serde_json::Value = serde_json::from_slice(&original_evidence)?;
    *stale_evidence
        .pointer_mut("/schema_version")
        .ok_or("evidence schema version unavailable")? =
        serde_json::Value::String("cigar.stale.v1".to_owned());
    fs::write(&evidence_path, serde_json::to_vec_pretty(&stale_evidence)?)?;
    assert!(validate_traceability(fixture.path(), Path::new("tests/invariants.yaml")).is_err());
    fs::write(&evidence_path, original_evidence)?;

    let missing_evidence = fs::read(&evidence_path)?;
    fs::remove_file(&evidence_path)?;
    assert!(validate_traceability(fixture.path(), Path::new("tests/invariants.yaml")).is_err());
    fs::write(&evidence_path, missing_evidence)?;

    fs::write(&path, &original)?;
    let profiles_path = fixture.path().join("conformance/profiles/v1.json");
    let invented_profile =
        fs::read_to_string(&profiles_path)?.replacen("cigar-catalog-v1", "caller-invented-v1", 1);
    fs::write(profiles_path, invented_profile)?;
    assert!(validate_traceability(fixture.path(), Path::new("tests/invariants.yaml")).is_err());
    Ok(())
}

#[derive(Deserialize)]
struct RequirementRegistry {
    derived_requirements: Vec<String>,
}

#[test]
fn traceability_rejects_each_removed_requirement_mapping() -> Result<(), Box<dyn Error>> {
    let fixture = traceability_fixture()?;
    let manifest_path = fixture.path().join("tests/invariants.yaml");
    let original = fs::read_to_string(&manifest_path)?;
    let registry: RequirementRegistry = serde_json::from_slice(&fs::read(
        fixture
            .path()
            .join("conformance/profiles/requirements-v1.json"),
    )?)?;
    for requirement in registry.derived_requirements {
        let mapping = format!("      - {requirement}\n");
        let mutated = original.replace(&mapping, "");
        assert_ne!(
            mutated, original,
            "missing mapping fixture for {requirement}"
        );
        fs::write(&manifest_path, mutated)?;
        assert!(
            validate_traceability(fixture.path(), Path::new("tests/invariants.yaml")).is_err(),
            "removing {requirement} unexpectedly passed"
        );
    }
    Ok(())
}

#[test]
fn traceability_rejects_prd_omission_addition_relocation_and_baseline_tamper()
-> Result<(), Box<dyn Error>> {
    let fixture = traceability_fixture()?;
    let manifest = Path::new("tests/invariants.yaml");
    let prd_path = fixture.path().join("prd.md");
    let original_prd = fs::read_to_string(&prd_path)?;

    let omitted = original_prd.replacen(
        "The implementation MUST optimize cost per verified successful job, not token count alone.",
        "The implementation optimizes cost per verified successful job, not token count alone.",
        1,
    );
    assert_ne!(omitted, original_prd);
    fs::write(&prd_path, omitted)?;
    assert!(validate_traceability(fixture.path(), manifest).is_err());

    fs::write(
        &prd_path,
        format!("{original_prd}\nA newly introduced behavior MUST fail closed.\n"),
    )?;
    assert!(validate_traceability(fixture.path(), manifest).is_err());

    fs::write(&prd_path, format!("\n{original_prd}"))?;
    assert!(validate_traceability(fixture.path(), manifest).is_err());
    fs::write(&prd_path, &original_prd)?;

    let registry_path = fixture
        .path()
        .join("conformance/profiles/requirements-v1.json");
    let mut registry: serde_json::Value = serde_json::from_slice(&fs::read(&registry_path)?)?;
    *registry
        .pointer_mut("/requirements/0/source/text_sha256")
        .ok_or("first requirement source digest unavailable")? = serde_json::Value::String(
        "sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff".to_owned(),
    );
    fs::write(&registry_path, serde_json::to_vec_pretty(&registry)?)?;
    assert!(validate_traceability(fixture.path(), manifest).is_err());

    let mut duplicate_registry: serde_json::Value = serde_json::from_slice(&fs::read(
        repository_root()?.join("conformance/profiles/requirements-v1.json"),
    )?)?;
    let first_requirement_id = duplicate_registry
        .pointer("/requirements/0/id")
        .ok_or("first requirement identifier unavailable")?
        .clone();
    *duplicate_registry
        .pointer_mut("/requirements/1/id")
        .ok_or("second requirement identifier unavailable")? = first_requirement_id;
    fs::write(
        &registry_path,
        serde_json::to_vec_pretty(&duplicate_registry)?,
    )?;
    assert!(validate_traceability(fixture.path(), manifest).is_err());

    let mut renamed_registry: serde_json::Value = serde_json::from_slice(&fs::read(
        repository_root()?.join("conformance/profiles/requirements-v1.json"),
    )?)?;
    *renamed_registry
        .pointer_mut("/requirements/0/id")
        .ok_or("first requirement identifier unavailable")? =
        serde_json::Value::String("PRD-NORM-9999".to_owned());
    fs::write(
        &registry_path,
        serde_json::to_vec_pretty(&renamed_registry)?,
    )?;
    assert!(validate_traceability(fixture.path(), manifest).is_err());
    Ok(())
}
