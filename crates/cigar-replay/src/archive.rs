//! Thread-safe replay archive abstraction and hermetic in-memory implementation.

use crate::contract::{
    DecisionArchive, DecisionArtifact, DecisionCapture, ReplayFoundationError,
    ReplayFoundationErrorCode,
};
use cigar_protocol::{ContentDigest, VersionId};
use std::collections::BTreeMap;
use std::fmt;
use std::sync::Mutex;

/// Exact immutable archive storage used by capture and replay services.
pub trait ReplayArchive: Send + Sync {
    /// Atomically stores one validated decision root and its available exact artifacts.
    fn put_capture(&self, capture: &DecisionCapture) -> Result<(), ReplayFoundationError>;

    /// Gets one immutable decision root by its content-derived identity.
    fn get_decision(
        &self,
        decision_id: &VersionId,
    ) -> Result<Option<DecisionArchive>, ReplayFoundationError>;

    /// Gets exact protected artifact bytes by raw content digest.
    fn get_artifact(
        &self,
        content_digest: &ContentDigest,
    ) -> Result<Option<DecisionArtifact>, ReplayFoundationError>;
}

#[derive(Default)]
struct ArchiveState {
    decisions: BTreeMap<VersionId, DecisionArchive>,
    artifacts: BTreeMap<ContentDigest, DecisionArtifact>,
}

/// Hermetic thread-safe behavioral oracle for replay archive implementations.
#[derive(Default)]
pub struct InMemoryReplayArchive {
    state: Mutex<ArchiveState>,
}

impl fmt::Debug for InMemoryReplayArchive {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let Ok(state) = self.state.lock() else {
            return formatter.write_str("InMemoryReplayArchive(unavailable)");
        };
        formatter
            .debug_struct("InMemoryReplayArchive")
            .field("decision_count", &state.decisions.len())
            .field("artifact_count", &state.artifacts.len())
            .finish()
    }
}

impl ReplayArchive for InMemoryReplayArchive {
    fn put_capture(&self, capture: &DecisionCapture) -> Result<(), ReplayFoundationError> {
        capture.validate()?;
        let mut state = self.state.lock().map_err(|_error| unavailable())?;
        let decision_id = capture.archive.decision.decision_id.clone();
        if state
            .decisions
            .get(&decision_id)
            .is_some_and(|current| current != &capture.archive)
        {
            return Err(ReplayFoundationError::new(
                ReplayFoundationErrorCode::Collision,
            ));
        }
        for artifact in &capture.artifacts {
            if state
                .artifacts
                .get(&artifact.content_digest)
                .is_some_and(|current| current != artifact)
            {
                return Err(ReplayFoundationError::new(
                    ReplayFoundationErrorCode::Collision,
                ));
            }
        }
        for artifact in &capture.artifacts {
            state
                .artifacts
                .entry(artifact.content_digest.clone())
                .or_insert_with(|| artifact.clone());
        }
        state
            .decisions
            .entry(decision_id)
            .or_insert_with(|| capture.archive.clone());
        Ok(())
    }

    fn get_decision(
        &self,
        decision_id: &VersionId,
    ) -> Result<Option<DecisionArchive>, ReplayFoundationError> {
        let state = self.state.lock().map_err(|_error| unavailable())?;
        Ok(state.decisions.get(decision_id).cloned())
    }

    fn get_artifact(
        &self,
        content_digest: &ContentDigest,
    ) -> Result<Option<DecisionArtifact>, ReplayFoundationError> {
        let state = self.state.lock().map_err(|_error| unavailable())?;
        Ok(state.artifacts.get(content_digest).cloned())
    }
}

fn unavailable() -> ReplayFoundationError {
    ReplayFoundationError::new(ReplayFoundationErrorCode::Unavailable)
}

#[cfg(test)]
mod tests {
    use super::{InMemoryReplayArchive, ReplayArchive};
    use cigar_protocol::{ContentDigest, VersionId};
    use std::sync::Arc;

    fn missing_id() -> Result<VersionId, Box<dyn std::error::Error>> {
        Ok(VersionId::new(format!("1220{}", "0".repeat(64)))?)
    }

    fn missing_digest() -> Result<ContentDigest, Box<dyn std::error::Error>> {
        Ok(ContentDigest::new(format!("1220{}", "1".repeat(64)))?)
    }

    #[test]
    fn empty_archive_is_thread_safe_and_content_free() -> Result<(), Box<dyn std::error::Error>> {
        let archive = Arc::new(InMemoryReplayArchive::default());
        let mut workers = Vec::new();
        for _index in 0..8 {
            let archive = Arc::clone(&archive);
            let decision_id = missing_id()?;
            let content_digest = missing_digest()?;
            workers.push(std::thread::spawn(move || {
                assert!(archive.get_decision(&decision_id)?.is_none());
                assert!(archive.get_artifact(&content_digest)?.is_none());
                Ok::<(), crate::contract::ReplayFoundationError>(())
            }));
        }
        for worker in workers {
            worker
                .join()
                .map_err(|_panic| "archive worker panicked")??;
        }
        let rendered = format!("{archive:?}");
        assert!(rendered.contains("decision_count"));
        assert!(rendered.contains("artifact_count"));
        Ok(())
    }
}
