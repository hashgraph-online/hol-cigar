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
        "tests/invariants.yaml",
        "conformance/profiles/v1.json",
        "conformance/profiles/requirements-v1.json",
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
    assert_eq!(result.requirement_count, 35);
    assert_eq!(result.test_count, 17);
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
    requirements: Vec<String>,
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
    for requirement in registry.requirements {
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
