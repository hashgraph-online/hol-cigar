//! Strict, read-only decoding of the frozen `0.1.0-beta.1` administration state.
//!
//! This module deliberately exposes no encoder and no state-application operation. The beta
//! state may be inspected by a newer full CLI, but it cannot be rewritten or treated as a
//! production registry without a separately reviewed semantic migration boundary.

use serde::Deserialize;
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Component, Path, PathBuf};

pub(crate) const FROZEN_BETA_RELEASE: &str = "0.1.0-beta.1";
pub(crate) const FROZEN_BETA_STATE_SCHEMA: &str = "cigar.cli-administration.v1";
pub(crate) const MAX_FROZEN_BETA_STATE_BYTES: u64 = 8 * 1024 * 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct FrozenBetaStateError;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub(crate) struct FrozenBetaState {
    schema_version: String,
    generation: u64,
    #[serde(default)]
    active_project: Option<String>,
    #[serde(default)]
    active_focus: Option<String>,
    projects: BTreeMap<String, FrozenBetaProject>,
    sources: BTreeMap<String, FrozenBetaSource>,
    links: BTreeSet<FrozenBetaLink>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
struct FrozenBetaProject {
    path: PathBuf,
    attached: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
struct FrozenBetaSource {
    path: PathBuf,
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd)]
#[serde(deny_unknown_fields)]
struct FrozenBetaLink {
    from: String,
    to: String,
}

#[cfg(feature = "full")]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct FrozenBetaStateSummary {
    pub(crate) generation: u64,
    pub(crate) project_count: usize,
    pub(crate) source_count: usize,
    pub(crate) link_count: usize,
    pub(crate) has_active_project: bool,
    pub(crate) has_active_focus: bool,
}

/// Exact validated beta semantics handed across the reviewed full-only import boundary.
///
/// The import implementation deliberately receives owned values rather than serialized JSON so
/// every preserved field is visible in the conversion. The frozen decoder remains the only place
/// that accepts beta bytes.
#[cfg(feature = "full")]
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct FrozenBetaImportSnapshot {
    pub(crate) generation: u64,
    pub(crate) active_project: Option<String>,
    pub(crate) active_focus: Option<String>,
    pub(crate) projects: BTreeMap<String, FrozenBetaImportProject>,
    pub(crate) sources: BTreeMap<String, PathBuf>,
    pub(crate) links: BTreeSet<FrozenBetaImportLink>,
}

#[cfg(feature = "full")]
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct FrozenBetaImportProject {
    pub(crate) path: PathBuf,
    pub(crate) attached: bool,
}

#[cfg(feature = "full")]
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub(crate) struct FrozenBetaImportLink {
    pub(crate) from: String,
    pub(crate) to: String,
}

#[cfg(feature = "full")]
impl FrozenBetaState {
    pub(crate) fn summary(&self) -> FrozenBetaStateSummary {
        FrozenBetaStateSummary {
            generation: self.generation,
            project_count: self.projects.len(),
            source_count: self.sources.len(),
            link_count: self.links.len(),
            has_active_project: self.active_project.is_some(),
            has_active_focus: self.active_focus.is_some(),
        }
    }

    pub(crate) fn import_snapshot(&self) -> FrozenBetaImportSnapshot {
        FrozenBetaImportSnapshot {
            generation: self.generation,
            active_project: self.active_project.clone(),
            active_focus: self.active_focus.clone(),
            projects: self
                .projects
                .iter()
                .map(|(identifier, project)| {
                    (
                        identifier.clone(),
                        FrozenBetaImportProject {
                            path: project.path.clone(),
                            attached: project.attached,
                        },
                    )
                })
                .collect(),
            sources: self
                .sources
                .iter()
                .map(|(identifier, source)| (identifier.clone(), source.path.clone()))
                .collect(),
            links: self
                .links
                .iter()
                .map(|link| FrozenBetaImportLink {
                    from: link.from.clone(),
                    to: link.to.clone(),
                })
                .collect(),
        }
    }
}

/// Decodes and validates frozen beta bytes without normalizing, encoding, or mutating them.
pub(crate) fn decode_frozen_beta_state(
    bytes: &[u8],
) -> Result<FrozenBetaState, FrozenBetaStateError> {
    if u64::try_from(bytes.len()).map_or(true, |length| {
        length == 0 || length > MAX_FROZEN_BETA_STATE_BYTES
    }) {
        return Err(FrozenBetaStateError);
    }
    cigar_canon::parse_strict_json(bytes).map_err(|_error| FrozenBetaStateError)?;
    let state: FrozenBetaState =
        serde_json::from_slice(bytes).map_err(|_error| FrozenBetaStateError)?;
    validate_frozen_beta_state(&state)?;
    Ok(state)
}

fn validate_frozen_beta_state(state: &FrozenBetaState) -> Result<(), FrozenBetaStateError> {
    if state.schema_version != FROZEN_BETA_STATE_SCHEMA || state.generation == 0 {
        return Err(FrozenBetaStateError);
    }
    for (identifier, project) in &state.projects {
        validate_identifier(identifier)?;
        validate_stored_path(&project.path)?;
    }
    for (identifier, source) in &state.sources {
        validate_identifier(identifier)?;
        validate_stored_path(&source.path)?;
    }
    if state.active_project.as_ref().is_some_and(|active| {
        !state
            .projects
            .get(active)
            .is_some_and(|project| project.attached)
    }) || state
        .active_focus
        .as_deref()
        .is_some_and(|focus| validate_identifier(focus).is_err())
        || state.links.iter().any(|link| {
            link.from == link.to
                || !state
                    .projects
                    .get(&link.from)
                    .is_some_and(|project| project.attached)
                || !state
                    .projects
                    .get(&link.to)
                    .is_some_and(|project| project.attached)
        })
    {
        return Err(FrozenBetaStateError);
    }
    Ok(())
}

fn validate_identifier(value: &str) -> Result<(), FrozenBetaStateError> {
    if value.is_empty()
        || value.len() > 256
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_' | b':'))
    {
        Err(FrozenBetaStateError)
    } else {
        Ok(())
    }
}

fn validate_stored_path(path: &Path) -> Result<(), FrozenBetaStateError> {
    if !path.is_absolute()
        || path
            .components()
            .any(|component| matches!(component, Component::CurDir | Component::ParentDir))
        || path
            .to_str()
            .is_none_or(|value| value.chars().any(char::is_control))
    {
        Err(FrozenBetaStateError)
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::{MAX_FROZEN_BETA_STATE_BYTES, decode_frozen_beta_state};

    const FIXTURE_ROOT: &str = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/beta-state-v0.1.0-beta.1"
    );

    fn fixture(name: &str) -> std::io::Result<Vec<u8>> {
        std::fs::read(std::path::Path::new(FIXTURE_ROOT).join(name))
    }

    #[test]
    fn valid_boundary_fixtures_preserve_generation_identifiers_paths_and_links()
    -> Result<(), Box<dyn std::error::Error>> {
        let minimum_bytes = fixture("valid-min.json")?;
        let minimum = decode_frozen_beta_state(&minimum_bytes).map_err(|_error| {
            std::io::Error::new(std::io::ErrorKind::InvalidData, "invalid minimum fixture")
        })?;
        assert_eq!(minimum.generation, 1);
        assert!(minimum.projects.is_empty());
        assert!(minimum.sources.is_empty());
        assert!(minimum.links.is_empty());

        let representative_bytes = fixture("valid.json")?;
        let representative = decode_frozen_beta_state(&representative_bytes).map_err(|_error| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "invalid representative fixture",
            )
        })?;
        assert_eq!(representative.generation, 41);
        assert_eq!(
            representative.active_project.as_deref(),
            Some("project.alpha")
        );
        assert_eq!(representative.active_focus.as_deref(), Some("focus:launch"));
        assert_eq!(
            representative
                .projects
                .get("project.alpha")
                .ok_or_else(|| std::io::Error::other("missing project"))?
                .path,
            std::path::Path::new("/Users/example/CIGAR Alpha")
        );
        assert_eq!(
            representative
                .sources
                .get("source_docs")
                .ok_or_else(|| std::io::Error::other("missing source"))?
                .path,
            std::path::Path::new("/Users/example/CIGAR Alpha/docs")
        );
        assert!(
            representative
                .links
                .iter()
                .any(|link| { link.from == "project.alpha" && link.to == "project-beta" })
        );

        let maximum_bytes = fixture("valid-max.json")?;
        let maximum = decode_frozen_beta_state(&maximum_bytes).map_err(|_error| {
            std::io::Error::new(std::io::ErrorKind::InvalidData, "invalid maximum fixture")
        })?;
        assert_eq!(maximum.generation, u64::MAX);
        assert_eq!(maximum.active_focus.as_ref().map(String::len), Some(256));
        assert!(
            maximum
                .projects
                .keys()
                .all(|identifier| identifier.len() == 256)
        );
        Ok(())
    }

    #[test]
    fn hostile_documents_are_rejected_by_the_frozen_contract()
    -> Result<(), Box<dyn std::error::Error>> {
        for name in [
            "unknown-field.json",
            "duplicate-field.json",
            "malformed-identifier.json",
            "malformed-relative-path.json",
            "malformed-traversal-path.json",
            "malformed-control-path.json",
            "malformed-link.json",
            "malformed-active-project.json",
            "zero-generation.json",
        ] {
            assert!(
                decode_frozen_beta_state(&fixture(name)?).is_err(),
                "hostile fixture accepted: {name}"
            );
        }
        Ok(())
    }

    #[test]
    fn empty_and_oversized_input_are_rejected_before_decode()
    -> Result<(), Box<dyn std::error::Error>> {
        assert!(decode_frozen_beta_state(&[]).is_err());
        let oversized_length = usize::try_from(MAX_FROZEN_BETA_STATE_BYTES)?
            .checked_add(1)
            .ok_or_else(|| std::io::Error::other("oversized fixture length overflow"))?;
        let oversized = vec![b' '; oversized_length];
        assert!(decode_frozen_beta_state(&oversized).is_err());
        Ok(())
    }
}
