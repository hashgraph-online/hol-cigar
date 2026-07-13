use super::support::{MAX_REFERENCE_BODY_BYTES, digest_parts, stable_evidence, validate_selector};
use crate::{
    ConnectorDescriptor, ConnectorOperation, DispatchContext, DispatchObservation, EffectConnector,
    EffectError, EffectErrorCode, PreconditionReport, ReconcileObservation,
};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use cigar_protocol::ContentDigest;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::fs::{self, OpenOptions};
use std::io::{ErrorKind, Write as _};
use std::path::{Path, PathBuf};
use std::sync::RwLock;

const WRITE_FILE: &str = "write_file";
const PROTECTED_ARGUMENT_SCHEMA: &str = "cigar.effect-arguments.filesystem-write.v1";
const MAX_PROTECTED_ARGUMENT_BYTES: usize = 1_400_000;

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct FilesystemArgumentDocument {
    schema_version: String,
    relative_path: String,
    bytes_base64url: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    expected_existing_digest: Option<ContentDigest>,
}

/// One normalized atomic file-write request relative to a configured root.
#[derive(Clone, Eq, PartialEq)]
pub struct FilesystemWriteRequest {
    relative_path: String,
    bytes: Vec<u8>,
    expected_existing_digest: Option<ContentDigest>,
}

impl FilesystemWriteRequest {
    /// Creates a bounded write request with an optional exact current-content precondition.
    pub fn new(
        relative_path: impl Into<String>,
        bytes: Vec<u8>,
        expected_existing_digest: Option<ContentDigest>,
    ) -> Result<Self, EffectError> {
        let request = Self {
            relative_path: relative_path.into(),
            bytes,
            expected_existing_digest,
        };
        request.validate()?;
        Ok(request)
    }

    /// Returns the normalized slash-separated relative path.
    #[must_use]
    pub fn relative_path(&self) -> &str {
        &self.relative_path
    }

    /// Computes the exact normalized argument digest.
    pub fn arguments_digest(&self) -> Result<ContentDigest, EffectError> {
        digest_parts(
            b"filesystem-write-request",
            &[
                self.relative_path.as_bytes(),
                &self.bytes,
                self.expected_existing_digest
                    .as_ref()
                    .map_or(b"absent".as_slice(), |digest| digest.as_str().as_bytes()),
            ],
        )
    }

    /// Encodes a deterministic versioned JSON document suitable for encrypted blob storage.
    pub fn encode_protected_document(&self) -> Result<Vec<u8>, EffectError> {
        self.validate()?;
        let document = FilesystemArgumentDocument {
            schema_version: PROTECTED_ARGUMENT_SCHEMA.to_owned(),
            relative_path: self.relative_path.clone(),
            bytes_base64url: URL_SAFE_NO_PAD.encode(&self.bytes),
            expected_existing_digest: self.expected_existing_digest.clone(),
        };
        let bytes = serde_json::to_vec(&document)
            .map_err(|_error| EffectError::new(EffectErrorCode::Unavailable))?;
        if bytes.len() > MAX_PROTECTED_ARGUMENT_BYTES {
            return Err(EffectError::new(EffectErrorCode::LimitExceeded));
        }
        Ok(bytes)
    }

    /// Decodes a strict versioned JSON document recovered from authenticated encrypted storage.
    pub fn decode_protected_document(bytes: &[u8]) -> Result<Self, EffectError> {
        if bytes.is_empty() || bytes.len() > MAX_PROTECTED_ARGUMENT_BYTES {
            return Err(EffectError::new(EffectErrorCode::LimitExceeded));
        }
        cigar_canon::parse_strict_json(bytes)
            .map_err(|_error| EffectError::new(EffectErrorCode::InvalidInput))?;
        let document: FilesystemArgumentDocument = serde_json::from_slice(bytes)
            .map_err(|_error| EffectError::new(EffectErrorCode::InvalidInput))?;
        if document.schema_version != PROTECTED_ARGUMENT_SCHEMA {
            return Err(EffectError::new(EffectErrorCode::InvalidInput));
        }
        let decoded = URL_SAFE_NO_PAD
            .decode(document.bytes_base64url)
            .map_err(|_error| EffectError::new(EffectErrorCode::InvalidInput))?;
        Self::new(
            document.relative_path,
            decoded,
            document.expected_existing_digest,
        )
    }

    fn validate(&self) -> Result<(), EffectError> {
        validate_relative_path(&self.relative_path)?;
        if self.bytes.len() > MAX_REFERENCE_BODY_BYTES {
            return Err(EffectError::new(EffectErrorCode::LimitExceeded));
        }
        Ok(())
    }
}

impl fmt::Debug for FilesystemWriteRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FilesystemWriteRequest")
            .field("relative_path_bytes", &self.relative_path.len())
            .field("content_bytes", &self.bytes.len())
            .field(
                "has_expected_existing_digest",
                &self.expected_existing_digest.is_some(),
            )
            .finish_non_exhaustive()
    }
}

/// Atomic write-only effect connector confined to one canonical directory root.
pub struct FilesystemEffectConnector {
    connector_name: String,
    root: PathBuf,
    #[cfg(unix)]
    write_fence: PathBuf,
    requests: RwLock<BTreeMap<ContentDigest, FilesystemWriteRequest>>,
}

impl fmt::Debug for FilesystemEffectConnector {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let request_count = self.requests.read().map_or(0, |items| items.len());
        formatter
            .debug_struct("FilesystemEffectConnector")
            .field("connector_name", &self.connector_name)
            .field("root_configured", &true)
            .field("request_count", &request_count)
            .finish_non_exhaustive()
    }
}

impl FilesystemEffectConnector {
    /// Creates a connector rooted at an existing canonical directory.
    pub fn new(
        connector_name: impl Into<String>,
        root: impl AsRef<Path>,
    ) -> Result<Self, EffectError> {
        let connector_name = connector_name.into();
        validate_selector(&connector_name)?;
        let root_metadata = fs::symlink_metadata(root.as_ref())
            .map_err(|_error| EffectError::new(EffectErrorCode::Unavailable))?;
        if root_metadata.file_type().is_symlink() || !root_metadata.is_dir() {
            return Err(EffectError::new(EffectErrorCode::InvalidInput));
        }
        let root = fs::canonicalize(root.as_ref())
            .map_err(|_error| EffectError::new(EffectErrorCode::Unavailable))?;
        #[cfg(not(unix))]
        {
            let _root = &root;
            return Err(EffectError::new(EffectErrorCode::Unavailable));
        }
        #[cfg(unix)]
        let write_fence = {
            let path = root.join(".cigar-effect-write.lock");
            let descriptor = open_write_fence(&path)?;
            drop(descriptor);
            path
        };
        Ok(Self {
            connector_name,
            root,
            #[cfg(unix)]
            write_fence,
            requests: RwLock::new(BTreeMap::new()),
        })
    }

    /// Stages protected file bytes and returns their normalized argument digest.
    pub fn stage_write(
        &self,
        request: FilesystemWriteRequest,
    ) -> Result<ContentDigest, EffectError> {
        request.validate()?;
        let digest = request.arguments_digest()?;
        let mut requests = self
            .requests
            .write()
            .map_err(|_error| EffectError::new(EffectErrorCode::Unavailable))?;
        if requests
            .get(&digest)
            .is_some_and(|existing| existing != &request)
        {
            return Err(EffectError::new(EffectErrorCode::IdempotencyCollision));
        }
        requests.insert(digest.clone(), request);
        Ok(digest)
    }

    /// Computes the connector's exact digest for existing or proposed file bytes.
    pub fn content_digest(bytes: &[u8]) -> Result<ContentDigest, EffectError> {
        if bytes.len() > MAX_REFERENCE_BODY_BYTES {
            return Err(EffectError::new(EffectErrorCode::LimitExceeded));
        }
        digest_parts(b"filesystem-content", &[bytes])
    }

    /// Returns the stable evidence digest representing an absent target file.
    pub fn absent_content_digest() -> Result<ContentDigest, EffectError> {
        digest_parts(b"filesystem-content-absent", &[])
    }

    fn request(&self, digest: &ContentDigest) -> Result<FilesystemWriteRequest, EffectError> {
        self.requests
            .read()
            .map_err(|_error| EffectError::new(EffectErrorCode::Unavailable))?
            .get(digest)
            .cloned()
            .ok_or_else(|| EffectError::new(EffectErrorCode::NotFound))
    }

    fn validate_intent(
        &self,
        intent: &cigar_protocol::EffectIntent,
    ) -> Result<FilesystemWriteRequest, EffectError> {
        if intent.connector != self.connector_name || intent.operation != WRITE_FILE {
            return Err(EffectError::new(EffectErrorCode::InvalidInput));
        }
        let request = self.request(&intent.arguments_digest)?;
        if intent.target != request.relative_path {
            return Err(EffectError::new(EffectErrorCode::InvalidInput));
        }
        let expected_preconditions = request
            .expected_existing_digest
            .iter()
            .cloned()
            .collect::<Vec<_>>();
        if intent.preconditions != expected_preconditions {
            return Err(EffectError::new(EffectErrorCode::InvalidInput));
        }
        Ok(request)
    }

    fn resolve_target(&self, relative_path: &str) -> Result<PathBuf, EffectError> {
        validate_relative_path(relative_path)?;
        let target = self.root.join(relative_path);
        let Some(parent) = target.parent() else {
            return Err(EffectError::new(EffectErrorCode::InvalidInput));
        };
        reject_symlink_ancestors(&self.root, parent)?;
        let canonical_parent = fs::canonicalize(parent)
            .map_err(|_error| EffectError::new(EffectErrorCode::Unavailable))?;
        if !canonical_parent.starts_with(&self.root) {
            return Err(EffectError::new(EffectErrorCode::Unauthorized));
        }
        match fs::symlink_metadata(&target) {
            Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_file() => {
                Err(EffectError::new(EffectErrorCode::Unauthorized))
            }
            Ok(_metadata) => Ok(target),
            Err(error) if error.kind() == ErrorKind::NotFound => Ok(target),
            Err(_error) => Err(EffectError::new(EffectErrorCode::Unavailable)),
        }
    }

    fn current_digest(&self, target: &Path) -> Result<ContentDigest, EffectError> {
        match fs::metadata(target) {
            Ok(metadata) => {
                if metadata.len() > MAX_REFERENCE_BODY_BYTES as u64 {
                    return Err(EffectError::new(EffectErrorCode::LimitExceeded));
                }
                let bytes = fs::read(target)
                    .map_err(|_error| EffectError::new(EffectErrorCode::Unavailable))?;
                Self::content_digest(&bytes)
            }
            Err(error) if error.kind() == ErrorKind::NotFound => Self::absent_content_digest(),
            Err(_error) => Err(EffectError::new(EffectErrorCode::Unavailable)),
        }
    }

    fn precondition_report(
        &self,
        intent: &cigar_protocol::EffectIntent,
    ) -> Result<PreconditionReport, EffectError> {
        let request = self.validate_intent(intent)?;
        let target = self.resolve_target(&request.relative_path)?;
        let current = self.current_digest(&target)?;
        let satisfied = Self::precondition_satisfied(&request, &current)?;
        Ok(PreconditionReport {
            satisfied,
            evidence: BTreeSet::from([current]),
        })
    }

    fn precondition_satisfied(
        request: &FilesystemWriteRequest,
        current: &ContentDigest,
    ) -> Result<bool, EffectError> {
        request.expected_existing_digest.as_ref().map_or_else(
            || Self::absent_content_digest().map(|absent| current == &absent),
            |expected| Ok(current == expected),
        )
    }

    fn write_atomically(
        &self,
        context: &DispatchContext<'_>,
        request: &FilesystemWriteRequest,
        target: &Path,
    ) -> Result<DispatchObservation, EffectError> {
        let content_digest = Self::content_digest(&request.bytes)?;
        let initial = self.current_digest(target)?;
        if !Self::precondition_satisfied(request, &initial)? {
            return Ok(DispatchObservation::Failed {
                evidence_digest: stable_evidence(
                    b"filesystem-precondition-changed-under-fence",
                    context.intent,
                )?,
            });
        }
        if initial == content_digest {
            return filesystem_success(&request.relative_path, content_digest);
        }
        let Some(parent) = target.parent() else {
            return Err(EffectError::new(EffectErrorCode::InvalidInput));
        };
        let temporary = parent.join(format!(
            ".cigar-{}-{}.tmp",
            context.attempt_id.as_str(),
            context.fencing_token
        ));
        match fs::symlink_metadata(&temporary) {
            Ok(_metadata) => {
                return Ok(DispatchObservation::Unknown {
                    evidence_digest: stable_evidence(b"filesystem-temp-collision", context.intent)?,
                    remote_operation_id: None,
                });
            }
            Err(error) if error.kind() == ErrorKind::NotFound => {}
            Err(_error) => return Err(EffectError::new(EffectErrorCode::Unavailable)),
        }
        let result = (|| {
            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&temporary)
                .map_err(|_error| EffectError::new(EffectErrorCode::Unavailable))?;
            file.write_all(&request.bytes)
                .and_then(|()| file.sync_all())
                .map_err(|_error| EffectError::new(EffectErrorCode::Unavailable))?;
            reject_symlink_ancestors(&self.root, parent)?;
            let current = self.current_digest(target)?;
            if !Self::precondition_satisfied(request, &current)? {
                return Ok::<bool, EffectError>(false);
            }
            fs::rename(&temporary, target)
                .map_err(|_error| EffectError::new(EffectErrorCode::Unavailable))?;
            let directory = OpenOptions::new()
                .read(true)
                .open(parent)
                .map_err(|_error| EffectError::new(EffectErrorCode::Unavailable))?;
            directory
                .sync_all()
                .map_err(|_error| EffectError::new(EffectErrorCode::Unavailable))?;
            Ok::<bool, EffectError>(true)
        })();
        if result.is_err() {
            let _remove_result = fs::remove_file(&temporary);
            return result.map(|_renamed| DispatchObservation::Unknown {
                evidence_digest: content_digest.clone(),
                remote_operation_id: None,
            });
        }
        if result == Ok(false) {
            let _remove_result = fs::remove_file(&temporary);
            return Ok(DispatchObservation::Failed {
                evidence_digest: stable_evidence(
                    b"filesystem-precondition-changed-under-fence",
                    context.intent,
                )?,
            });
        }
        let verified = self.current_digest(target)?;
        if verified != content_digest {
            return Ok(DispatchObservation::Unknown {
                evidence_digest: stable_evidence(
                    b"filesystem-verification-mismatch",
                    context.intent,
                )?,
                remote_operation_id: Some(request.relative_path.clone()),
            });
        }
        filesystem_success(&request.relative_path, verified)
    }

    #[cfg(unix)]
    fn try_acquire_write_fence(&self) -> Result<Option<std::os::fd::OwnedFd>, EffectError> {
        use rustix::fs::{FlockOperation, flock};

        let descriptor = open_write_fence(&self.write_fence)?;
        match flock(&descriptor, FlockOperation::NonBlockingLockExclusive) {
            Ok(()) => Ok(Some(descriptor)),
            Err(error)
                if error == rustix::io::Errno::AGAIN || error == rustix::io::Errno::WOULDBLOCK =>
            {
                Ok(None)
            }
            Err(_error) => Err(EffectError::new(EffectErrorCode::Unavailable)),
        }
    }
}

impl EffectConnector for FilesystemEffectConnector {
    fn descriptor(&self) -> ConnectorDescriptor {
        ConnectorDescriptor {
            connector: self.connector_name.clone(),
            operations: vec![ConnectorOperation {
                operation: WRITE_FILE.to_owned(),
                same_key_idempotent: true,
                supports_reconciliation: true,
                supports_compensation: false,
            }],
            maximum_dispatch_nanos: 5_000_000_000,
        }
    }

    fn check_preconditions(
        &self,
        intent: &cigar_protocol::EffectIntent,
        _now: cigar_protocol::UtcTimestamp,
    ) -> Result<PreconditionReport, EffectError> {
        self.precondition_report(intent)
    }

    fn dispatch(&self, context: &DispatchContext<'_>) -> Result<DispatchObservation, EffectError> {
        let request = self.validate_intent(context.intent)?;
        #[cfg(unix)]
        let _write_fence = match self.try_acquire_write_fence()? {
            Some(fence) => fence,
            None => {
                return Ok(DispatchObservation::ProvenNotSent {
                    evidence_digest: stable_evidence(
                        b"filesystem-write-fence-contended",
                        context.intent,
                    )?,
                });
            }
        };
        #[cfg(not(unix))]
        return Ok(DispatchObservation::ProvenNotSent {
            evidence_digest: stable_evidence(
                b"filesystem-write-fence-unavailable",
                context.intent,
            )?,
        });
        let report = self.precondition_report(context.intent)?;
        if !report.satisfied {
            return Ok(DispatchObservation::Failed {
                evidence_digest: stable_evidence(
                    b"filesystem-precondition-failed",
                    context.intent,
                )?,
            });
        }
        let target = self.resolve_target(&request.relative_path)?;
        self.write_atomically(context, &request, &target)
    }

    fn reconcile(
        &self,
        context: &DispatchContext<'_>,
    ) -> Result<ReconcileObservation, EffectError> {
        let request = self.validate_intent(context.intent)?;
        let target = self.resolve_target(&request.relative_path)?;
        let current = self.current_digest(&target)?;
        let requested = Self::content_digest(&request.bytes)?;
        if current == requested {
            Ok(ReconcileObservation::ConfirmedSuccess(current))
        } else if current == Self::absent_content_digest()? {
            Ok(ReconcileObservation::ProvenNotExecuted(current))
        } else {
            Ok(ReconcileObservation::Inconclusive {
                evidence_digest: current,
                certainty_window_end: context.deadline,
            })
        }
    }
}

#[cfg(unix)]
fn open_write_fence(path: &Path) -> Result<std::os::fd::OwnedFd, EffectError> {
    use rustix::fs::{Mode, OFlags, open};

    open(
        path,
        OFlags::CREATE | OFlags::RDWR | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::RUSR | Mode::WUSR,
    )
    .map_err(|_error| EffectError::new(EffectErrorCode::Unavailable))
}

fn validate_relative_path(value: &str) -> Result<(), EffectError> {
    if value.is_empty()
        || value.len() > 256
        || value.starts_with('/')
        || value.ends_with('/')
        || value.contains('\\')
        || value.contains('\0')
        || value.split('/').any(|part| {
            part.is_empty()
                || matches!(part, "." | "..")
                || part.starts_with(".cigar-")
                || part.bytes().any(|byte| byte.is_ascii_control())
        })
    {
        Err(EffectError::new(EffectErrorCode::InvalidInput))
    } else {
        Ok(())
    }
}

fn reject_symlink_ancestors(root: &Path, parent: &Path) -> Result<(), EffectError> {
    let relative = parent
        .strip_prefix(root)
        .map_err(|_error| EffectError::new(EffectErrorCode::Unauthorized))?;
    let mut current = root.to_path_buf();
    for component in relative.components() {
        current.push(component);
        let metadata = fs::symlink_metadata(&current)
            .map_err(|_error| EffectError::new(EffectErrorCode::Unavailable))?;
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            return Err(EffectError::new(EffectErrorCode::Unauthorized));
        }
    }
    Ok(())
}

fn filesystem_success(
    relative_path: &str,
    content_digest: ContentDigest,
) -> Result<DispatchObservation, EffectError> {
    Ok(DispatchObservation::Succeeded {
        remote_operation_id: relative_path.to_owned(),
        response_digest: content_digest.clone(),
        verification_digest: content_digest,
    })
}
