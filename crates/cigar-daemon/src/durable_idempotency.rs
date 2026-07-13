//! Durable request-bound idempotency reservations over the service repository.

use cigar_api::{
    ExactResponse, IdempotencyBinding, IdempotencyError, IdempotencyPermit, IdempotencyRepository,
    IdempotencyReservation,
};
use cigar_canon::parse_strict_json;
use cigar_protocol::{ContentDigest, IdempotencyKey, RecordId};
use cigar_store::{
    CancellationToken, ServiceBatch, ServiceError, ServiceErrorCode, ServiceExpectedVersion,
    ServiceIdempotency, ServiceRecordLocator, ServiceRecordSelection, ServiceRecordWrite,
    ServiceRepository, ServiceResponse,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use std::fmt;
use std::fmt::Write as _;
use std::sync::Arc;
use std::time::{Duration, Instant};

const STATE_NAMESPACE: &str = "api.idempotency-state.v1";
const STATE_SCHEMA: &str = "cigar.api-idempotency-state.v1";
const TOKEN_BYTES: usize = 32;
const MAX_CAS_RETRIES: usize = 64;
const POLL_INTERVAL: Duration = Duration::from_millis(10);

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "status", rename_all = "snake_case")]
enum DurablePhase {
    InProgress { token: Vec<u8> },
    Complete,
    Abandoned,
}

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct DurableState {
    schema_version: String,
    tenant: cigar_api::TenantId,
    principal: cigar_api::PrincipalId,
    operation: cigar_api::OperationId,
    key: IdempotencyKey,
    request_digest: ContentDigest,
    generation: u64,
    phase: DurablePhase,
}

impl DurableState {
    fn new(
        binding: &IdempotencyBinding,
        generation: u64,
        token: Vec<u8>,
    ) -> Result<Self, IdempotencyError> {
        if generation == 0 || token.len() != TOKEN_BYTES {
            return Err(IdempotencyError::Unavailable);
        }
        Ok(Self {
            schema_version: STATE_SCHEMA.to_owned(),
            tenant: binding.tenant().clone(),
            principal: binding.principal().clone(),
            operation: binding.operation().clone(),
            key: binding.key().clone(),
            request_digest: binding.request_digest().clone(),
            generation,
            phase: DurablePhase::InProgress { token },
        })
    }

    fn validate(&self) -> Result<(), IdempotencyError> {
        let valid_phase = match &self.phase {
            DurablePhase::InProgress { token } => token.len() == TOKEN_BYTES,
            DurablePhase::Complete | DurablePhase::Abandoned => true,
        };
        if self.schema_version == STATE_SCHEMA && self.generation != 0 && valid_phase {
            Ok(())
        } else {
            Err(IdempotencyError::Unavailable)
        }
    }

    fn same_scope(&self, binding: &IdempotencyBinding) -> bool {
        self.tenant == *binding.tenant()
            && self.principal == *binding.principal()
            && self.operation == *binding.operation()
            && self.key == *binding.key()
    }

    fn same_request(&self, binding: &IdempotencyBinding) -> bool {
        self.same_scope(binding) && self.request_digest == *binding.request_digest()
    }

    fn owns(&self, binding: &IdempotencyBinding, token: &[u8]) -> bool {
        self.same_request(binding)
            && matches!(
                &self.phase,
                DurablePhase::InProgress { token: current } if current == token
            )
    }
}

struct LoadedState {
    state: DurableState,
    version: u64,
}

struct ScopeIdentity {
    record_key: String,
    idempotency_operation: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CommitFailure {
    RevisionConflict,
    IdempotencyConflict,
    Unavailable,
}

/// Restart-safe idempotency reservations and exact response replay.
pub struct DurableIdempotencyRepository {
    repository: Arc<dyn ServiceRepository>,
    storage_tenant_id: RecordId,
}

/// Trusted startup-recovery proof that a stranded reservation made no durable mutation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RecoveredNoMutationProof {
    private: (),
}

impl RecoveredNoMutationProof {
    /// Attests that journal, repository, and external-effect reconciliation proved non-execution.
    #[must_use]
    pub const fn verified() -> Self {
        Self { private: () }
    }
}

/// Trusted startup-recovery proof that an exact committed response was reconstructed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RecoveredCommitProof {
    private: (),
}

impl RecoveredCommitProof {
    /// Attests that the response exactly represents the already committed logical mutation.
    #[must_use]
    pub const fn verified() -> Self {
        Self { private: () }
    }
}

impl DurableIdempotencyRepository {
    /// Creates an adapter in one protected storage partition.
    ///
    /// Authenticated tenant and principal identities remain part of every hashed lookup and
    /// validated state record; the supplied record ID selects only the physical store partition.
    #[must_use]
    pub fn new(repository: Arc<dyn ServiceRepository>, storage_tenant_id: RecordId) -> Self {
        Self {
            repository,
            storage_tenant_id,
        }
    }

    /// Abandons a restart-stranded reservation only after trusted non-execution reconciliation.
    pub fn recover_no_mutation(
        &self,
        binding: &IdempotencyBinding,
        _proof: RecoveredNoMutationProof,
    ) -> Result<(), IdempotencyError> {
        let permit = self.recovery_permit(binding)?;
        self.abandon(permit)
    }

    /// Completes a restart-stranded reservation with an exact reconstructed committed response.
    pub fn recover_committed(
        &self,
        binding: &IdempotencyBinding,
        response: ExactResponse,
        _proof: RecoveredCommitProof,
    ) -> Result<ExactResponse, IdempotencyError> {
        let permit = self.recovery_permit(binding)?;
        self.complete(permit, response)
    }

    fn recovery_permit(
        &self,
        binding: &IdempotencyBinding,
    ) -> Result<IdempotencyPermit, IdempotencyError> {
        let identity = scope_identity(binding);
        let loaded = self
            .load(&identity)?
            .ok_or(IdempotencyError::ReservationNotFound)?;
        if !loaded.state.same_request(binding) {
            return if loaded.state.same_scope(binding) {
                Err(IdempotencyError::RequestCollision)
            } else {
                Err(IdempotencyError::Unavailable)
            };
        }
        let DurablePhase::InProgress { token } = loaded.state.phase else {
            return Err(IdempotencyError::InvalidPermit);
        };
        IdempotencyPermit::from_repository(binding.clone(), token)
    }

    fn load(&self, identity: &ScopeIdentity) -> Result<Option<LoadedState>, IdempotencyError> {
        let locator = ServiceRecordLocator::new(
            self.storage_tenant_id.clone(),
            STATE_NAMESPACE,
            identity.record_key.clone(),
        )
        .map_err(map_repository_error)?;
        let record = self
            .repository
            .service_get(
                &locator,
                ServiceRecordSelection::Latest,
                &CancellationToken::default(),
            )
            .map_err(map_repository_error)?;
        let Some(record) = record else {
            return Ok(None);
        };
        parse_strict_json(record.bytes()).map_err(|_error| IdempotencyError::Unavailable)?;
        let state: DurableState = serde_json::from_slice(record.bytes())
            .map_err(|_error| IdempotencyError::Unavailable)?;
        state.validate()?;
        Ok(Some(LoadedState {
            state,
            version: record.version(),
        }))
    }

    fn commit_state(
        &self,
        identity: &ScopeIdentity,
        state: &DurableState,
        expected: ServiceExpectedVersion,
        response: ServiceResponse,
        idempotency: Option<ServiceIdempotency>,
    ) -> Result<cigar_store::ServiceBatchReceipt, CommitFailure> {
        let bytes = serde_json::to_vec(state).map_err(|_error| CommitFailure::Unavailable)?;
        let write = ServiceRecordWrite::new(
            STATE_NAMESPACE,
            identity.record_key.clone(),
            expected,
            bytes,
        )
        .map_err(map_commit_failure)?;
        let mut batch = ServiceBatch::new(self.storage_tenant_id.clone(), vec![write], response)
            .map_err(map_commit_failure)?;
        if let Some(idempotency) = idempotency {
            batch = batch.with_idempotency(idempotency);
        }
        self.repository
            .service_commit(batch, &CancellationToken::default())
            .map_err(map_commit_failure)
    }

    fn replay(
        &self,
        binding: &IdempotencyBinding,
        identity: &ScopeIdentity,
        state: &DurableState,
    ) -> Result<ExactResponse, IdempotencyError> {
        let idempotency = service_idempotency(binding, identity)?;
        // A complete state and its native idempotency response are committed atomically. Absent is
        // intentionally stale: if the response entry is corruptly missing, this probe conflicts
        // without publishing another record.
        let receipt = self
            .commit_state(
                identity,
                state,
                ServiceExpectedVersion::Absent,
                empty_response()?,
                Some(idempotency),
            )
            .map_err(|error| match error {
                CommitFailure::IdempotencyConflict => IdempotencyError::RequestCollision,
                _ => IdempotencyError::Unavailable,
            })?;
        if !receipt.replayed {
            return Err(IdempotencyError::Unavailable);
        }
        ExactResponse::new(receipt.response.bytes().to_vec())
    }

    fn inspect(
        &self,
        binding: &IdempotencyBinding,
        identity: &ScopeIdentity,
    ) -> Result<Inspection, IdempotencyError> {
        let Some(loaded) = self.load(identity)? else {
            return Ok(Inspection::Missing);
        };
        if !loaded.state.same_scope(binding) {
            return Err(IdempotencyError::Unavailable);
        }
        if loaded.state.request_digest != *binding.request_digest()
            && !matches!(loaded.state.phase, DurablePhase::Abandoned)
        {
            return Err(IdempotencyError::RequestCollision);
        }
        match loaded.state.phase {
            DurablePhase::InProgress { .. } => Ok(Inspection::Pending),
            DurablePhase::Complete => self
                .replay(binding, identity, &loaded.state)
                .map(Inspection::Complete),
            DurablePhase::Abandoned => Ok(Inspection::Missing),
        }
    }
}

enum Inspection {
    Missing,
    Pending,
    Complete(ExactResponse),
}

impl fmt::Debug for DurableIdempotencyRepository {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DurableIdempotencyRepository")
            .field("repository", &"[INJECTED]")
            .field("storage_partition", &"[BOUND]")
            .finish()
    }
}

impl IdempotencyRepository for DurableIdempotencyRepository {
    fn reserve(
        &self,
        binding: &IdempotencyBinding,
    ) -> Result<IdempotencyReservation, IdempotencyError> {
        let identity = scope_identity(binding);
        for _attempt in 0..MAX_CAS_RETRIES {
            match self.load(&identity)? {
                Some(loaded) if !loaded.state.same_scope(binding) => {
                    return Err(IdempotencyError::Unavailable);
                }
                Some(loaded)
                    if loaded.state.request_digest != *binding.request_digest()
                        && !matches!(loaded.state.phase, DurablePhase::Abandoned) =>
                {
                    return Err(IdempotencyError::RequestCollision);
                }
                Some(loaded) => match loaded.state.phase {
                    DurablePhase::InProgress { .. } => {
                        return Ok(IdempotencyReservation::Pending);
                    }
                    DurablePhase::Complete => {
                        return self
                            .replay(binding, &identity, &loaded.state)
                            .map(IdempotencyReservation::Replay);
                    }
                    DurablePhase::Abandoned => {
                        let generation = loaded
                            .state
                            .generation
                            .checked_add(1)
                            .ok_or(IdempotencyError::TokenExhausted)?;
                        let token = random_token()?;
                        let state = DurableState::new(binding, generation, token.clone())?;
                        match self.commit_state(
                            &identity,
                            &state,
                            ServiceExpectedVersion::Version(loaded.version),
                            empty_response()?,
                            None,
                        ) {
                            Ok(_receipt) => {
                                return IdempotencyPermit::from_repository(binding.clone(), token)
                                    .map(IdempotencyReservation::Execute);
                            }
                            Err(CommitFailure::RevisionConflict) => {}
                            Err(_error) => return Err(IdempotencyError::Unavailable),
                        }
                    }
                },
                None => {
                    let token = random_token()?;
                    let state = DurableState::new(binding, 1, token.clone())?;
                    match self.commit_state(
                        &identity,
                        &state,
                        ServiceExpectedVersion::Absent,
                        empty_response()?,
                        None,
                    ) {
                        Ok(_receipt) => {
                            return IdempotencyPermit::from_repository(binding.clone(), token)
                                .map(IdempotencyReservation::Execute);
                        }
                        Err(CommitFailure::RevisionConflict) => {}
                        Err(_error) => return Err(IdempotencyError::Unavailable),
                    }
                }
            }
        }
        Err(IdempotencyError::Unavailable)
    }

    fn complete(
        &self,
        permit: IdempotencyPermit,
        response: ExactResponse,
    ) -> Result<ExactResponse, IdempotencyError> {
        let binding = permit.binding().clone();
        let token = permit.repository_token().to_vec();
        let identity = scope_identity(&binding);
        let loaded = self
            .load(&identity)?
            .ok_or(IdempotencyError::InvalidPermit)?;
        if !loaded.state.owns(&binding, &token) {
            return Err(IdempotencyError::InvalidPermit);
        }
        let mut completed = loaded.state;
        completed.phase = DurablePhase::Complete;
        let stored_response = ServiceResponse::new(
            200,
            "application/octet-stream",
            response.as_bytes().to_vec(),
        )
        .map_err(map_repository_error)?;
        let idempotency = service_idempotency(&binding, &identity)?;
        let receipt = self
            .commit_state(
                &identity,
                &completed,
                ServiceExpectedVersion::Version(loaded.version),
                stored_response,
                Some(idempotency),
            )
            .map_err(|error| match error {
                CommitFailure::RevisionConflict => IdempotencyError::InvalidPermit,
                CommitFailure::IdempotencyConflict => IdempotencyError::RequestCollision,
                _ => IdempotencyError::Unavailable,
            })?;
        ExactResponse::new(receipt.response.bytes().to_vec())
    }

    fn abandon(&self, permit: IdempotencyPermit) -> Result<(), IdempotencyError> {
        let binding = permit.binding().clone();
        let token = permit.repository_token().to_vec();
        let identity = scope_identity(&binding);
        let loaded = self
            .load(&identity)?
            .ok_or(IdempotencyError::InvalidPermit)?;
        if !loaded.state.owns(&binding, &token) {
            return Err(IdempotencyError::InvalidPermit);
        }
        let mut abandoned = loaded.state;
        abandoned.phase = DurablePhase::Abandoned;
        self.commit_state(
            &identity,
            &abandoned,
            ServiceExpectedVersion::Version(loaded.version),
            empty_response()?,
            None,
        )
        .map(|_receipt| ())
        .map_err(|error| match error {
            CommitFailure::RevisionConflict => IdempotencyError::InvalidPermit,
            _ => IdempotencyError::Unavailable,
        })
    }

    fn wait_for_completion(
        &self,
        binding: &IdempotencyBinding,
        maximum_wait: Duration,
    ) -> Result<ExactResponse, IdempotencyError> {
        let identity = scope_identity(binding);
        let started = Instant::now();
        loop {
            match self.inspect(binding, &identity)? {
                Inspection::Complete(response) => return Ok(response),
                Inspection::Missing => return Err(IdempotencyError::ReservationNotFound),
                Inspection::Pending => {}
            }
            let remaining = maximum_wait
                .checked_sub(started.elapsed())
                .ok_or(IdempotencyError::WaitTimedOut)?;
            if remaining.is_zero() {
                return Err(IdempotencyError::WaitTimedOut);
            }
            std::thread::sleep(remaining.min(POLL_INTERVAL));
        }
    }
}

fn scope_identity(binding: &IdempotencyBinding) -> ScopeIdentity {
    let mut hasher = Sha256::new();
    let caller_key = String::from(binding.key().clone());
    for value in [
        binding.tenant().as_str(),
        binding.principal().as_str(),
        binding.operation().as_str(),
        caller_key.as_str(),
    ] {
        let length = u64::try_from(value.len()).unwrap_or(u64::MAX);
        hasher.update(length.to_be_bytes());
        hasher.update(value.as_bytes());
    }
    let mut digest = String::with_capacity(64);
    for byte in hasher.finalize() {
        let _ignored = write!(&mut digest, "{byte:02x}");
    }
    ScopeIdentity {
        record_key: digest.clone(),
        idempotency_operation: format!("api-idempotency-{digest}"),
    }
}

fn service_idempotency(
    binding: &IdempotencyBinding,
    identity: &ScopeIdentity,
) -> Result<ServiceIdempotency, IdempotencyError> {
    ServiceIdempotency::new(
        identity.idempotency_operation.clone(),
        binding.key().clone(),
        binding.request_digest().clone(),
    )
    .map_err(map_repository_error)
}

fn empty_response() -> Result<ServiceResponse, IdempotencyError> {
    ServiceResponse::new(204, "application/octet-stream", Vec::new()).map_err(map_repository_error)
}

fn random_token() -> Result<Vec<u8>, IdempotencyError> {
    let mut token = vec![0_u8; TOKEN_BYTES];
    getrandom::fill(&mut token).map_err(|_error| IdempotencyError::Unavailable)?;
    Ok(token)
}

fn map_repository_error(error: ServiceError) -> IdempotencyError {
    match error.code() {
        ServiceErrorCode::IdempotencyConflict => IdempotencyError::RequestCollision,
        _ => IdempotencyError::Unavailable,
    }
}

fn map_commit_failure(error: ServiceError) -> CommitFailure {
    match error.code() {
        ServiceErrorCode::RevisionConflict => CommitFailure::RevisionConflict,
        ServiceErrorCode::IdempotencyConflict => CommitFailure::IdempotencyConflict,
        _ => CommitFailure::Unavailable,
    }
}

#[cfg(test)]
mod tests {
    use super::{DurableIdempotencyRepository, RecoveredCommitProof, RecoveredNoMutationProof};
    use cigar_api::{
        ExactResponse, IdempotencyBinding, IdempotencyError, IdempotencyRepository,
        IdempotencyReservation, OperationId, PrincipalId, TenantId,
    };
    use cigar_protocol::{ContentDigest, IdempotencyKey, RecordId};
    use cigar_store::{InMemoryStore, ServiceRepository, SqliteStore};
    use std::error::Error;
    use std::sync::Arc;

    fn partition() -> Result<RecordId, Box<dyn Error>> {
        Ok(RecordId::new("01890f47-8e7d-7b42-a1d2-3c4d5e6f7890")?)
    }

    fn binding(character: char) -> Result<IdempotencyBinding, Box<dyn Error>> {
        Ok(IdempotencyBinding::new(
            TenantId::new("tenant-a")?,
            PrincipalId::new("principal-a")?,
            OperationId::new("compileContextBundle")?,
            IdempotencyKey::new("request-one")?,
            ContentDigest::new(format!("1220{}", character.to_string().repeat(64)))?,
        ))
    }

    #[test]
    fn reserve_complete_replay_collision_and_abandon_are_exact() -> Result<(), Box<dyn Error>> {
        let repository: Arc<dyn ServiceRepository> = Arc::new(InMemoryStore::default());
        let durable = DurableIdempotencyRepository::new(repository, partition()?);
        let original = binding('a')?;
        let IdempotencyReservation::Execute(permit) = durable.reserve(&original)? else {
            return Err("first reservation did not execute".into());
        };
        assert!(matches!(
            durable.reserve(&original)?,
            IdempotencyReservation::Pending
        ));
        durable.complete(permit, ExactResponse::new(b"exact-response".to_vec())?)?;
        let IdempotencyReservation::Replay(response) = durable.reserve(&original)? else {
            return Err("completed reservation did not replay".into());
        };
        assert_eq!(response.as_bytes(), b"exact-response");
        assert!(matches!(
            durable.reserve(&binding('b')?),
            Err(IdempotencyError::RequestCollision)
        ));

        let alternate = IdempotencyBinding::new(
            TenantId::new("tenant-a")?,
            PrincipalId::new("principal-a")?,
            OperationId::new("createReplay")?,
            IdempotencyKey::new("request-two")?,
            ContentDigest::new(format!("1220{}", "c".repeat(64)))?,
        );
        let IdempotencyReservation::Execute(permit) = durable.reserve(&alternate)? else {
            return Err("alternate reservation did not execute".into());
        };
        durable.abandon(permit)?;
        assert!(matches!(
            durable.reserve(&alternate)?,
            IdempotencyReservation::Execute(_)
        ));
        Ok(())
    }

    #[test]
    fn sqlite_restart_replays_exact_response_without_execution() -> Result<(), Box<dyn Error>> {
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("api-idempotency.sqlite3");
        let original = binding('d')?;
        {
            let repository: Arc<dyn ServiceRepository> = Arc::new(SqliteStore::open(&path)?);
            let durable = DurableIdempotencyRepository::new(repository, partition()?);
            let IdempotencyReservation::Execute(permit) = durable.reserve(&original)? else {
                return Err("first reservation did not execute".into());
            };
            durable.complete(permit, ExactResponse::new(b"restart-response".to_vec())?)?;
        }
        let repository: Arc<dyn ServiceRepository> = Arc::new(SqliteStore::open(&path)?);
        let durable = DurableIdempotencyRepository::new(repository, partition()?);
        let IdempotencyReservation::Replay(response) = durable.reserve(&original)? else {
            return Err("restart did not replay".into());
        };
        assert_eq!(response.as_bytes(), b"restart-response");
        Ok(())
    }

    #[test]
    fn restart_recovery_requires_explicit_proof_before_resolving_pending()
    -> Result<(), Box<dyn Error>> {
        let repository: Arc<dyn ServiceRepository> = Arc::new(InMemoryStore::default());
        let original = binding('e')?;
        {
            let durable = DurableIdempotencyRepository::new(Arc::clone(&repository), partition()?);
            let IdempotencyReservation::Execute(permit) = durable.reserve(&original)? else {
                return Err("first reservation did not execute".into());
            };
            drop(permit);
        }
        let durable = DurableIdempotencyRepository::new(Arc::clone(&repository), partition()?);
        assert!(matches!(
            durable.reserve(&original)?,
            IdempotencyReservation::Pending
        ));
        durable.recover_no_mutation(&original, RecoveredNoMutationProof::verified())?;
        let IdempotencyReservation::Execute(permit) = durable.reserve(&original)? else {
            return Err("verified non-execution did not release reservation".into());
        };
        drop(permit);
        durable.recover_committed(
            &original,
            ExactResponse::new(b"reconciled-response".to_vec())?,
            RecoveredCommitProof::verified(),
        )?;
        let IdempotencyReservation::Replay(response) = durable.reserve(&original)? else {
            return Err("verified committed recovery did not replay".into());
        };
        assert_eq!(response.as_bytes(), b"reconciled-response");
        Ok(())
    }
}
