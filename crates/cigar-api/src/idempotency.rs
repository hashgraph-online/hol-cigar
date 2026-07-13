//! Durable idempotency reservation contract and in-memory conformance oracle.

use crate::context::{OperationId, PrincipalId, TenantId};
use cigar_protocol::{ContentDigest, IdempotencyKey};
use std::collections::BTreeMap;
use std::fmt;
use std::sync::{Condvar, Mutex, MutexGuard};
use std::time::{Duration, Instant};

/// Maximum exact mutation response envelope retained for idempotent replay.
///
/// The semantic payload may use the full operation-payload bound; the additional fixed allowance
/// carries the operation identity, strong ETag, cursor, and binary framing without lowering that
/// public payload limit.
pub const MAX_EXACT_RESPONSE_BYTES: usize = (16 * 1024 * 1024) + (8 * 1024);
const MAX_PERMIT_TOKEN_BYTES: usize = 256;

/// Failure while reserving or completing an idempotent operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IdempotencyError {
    /// A scope and key were reused with a different request digest.
    RequestCollision,
    /// A completion or abandonment permit did not own the live reservation.
    InvalidPermit,
    /// The in-flight identical operation did not complete before the wait bound.
    WaitTimedOut,
    /// No matching reservation exists.
    ReservationNotFound,
    /// The exact response envelope exceeds the configured storage bound.
    ResponseTooLarge,
    /// The reservation token space was exhausted.
    TokenExhausted,
    /// The durable idempotency backend is unavailable or failed integrity checks.
    Unavailable,
}

impl fmt::Display for IdempotencyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::RequestCollision => "idempotency key was reused for another request",
            Self::InvalidPermit => "idempotency reservation permit is invalid",
            Self::WaitTimedOut => "idempotent operation remains in progress",
            Self::ReservationNotFound => "idempotency reservation was not found",
            Self::ResponseTooLarge => "idempotent response exceeds the configured limit",
            Self::TokenExhausted => "idempotency reservation capacity is exhausted",
            Self::Unavailable => "idempotency persistence is unavailable",
        };
        formatter.write_str(message)
    }
}

impl std::error::Error for IdempotencyError {}

/// Exact transport-neutral response envelope retained for duplicate requests.
#[derive(Clone, Eq, PartialEq)]
pub struct ExactResponse(Vec<u8>);

impl ExactResponse {
    /// Creates a bounded exact response envelope. Empty responses are valid.
    pub fn new(bytes: impl Into<Vec<u8>>) -> Result<Self, IdempotencyError> {
        let bytes = bytes.into();
        if bytes.len() > MAX_EXACT_RESPONSE_BYTES {
            Err(IdempotencyError::ResponseTooLarge)
        } else {
            Ok(Self(bytes))
        }
    }

    /// Returns the exact bytes to replay without re-executing the operation.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Debug for ExactResponse {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ExactResponse")
            .field("bytes", &self.0.len())
            .finish()
    }
}

/// Exact semantic binding for one idempotent mutation request.
#[derive(Clone, Eq, PartialEq)]
pub struct IdempotencyBinding {
    tenant: TenantId,
    principal: PrincipalId,
    operation: OperationId,
    key: IdempotencyKey,
    request_digest: ContentDigest,
}

impl IdempotencyBinding {
    /// Creates a tenant-, principal-, operation-, key-, and request-bound identity.
    #[must_use]
    pub const fn new(
        tenant: TenantId,
        principal: PrincipalId,
        operation: OperationId,
        key: IdempotencyKey,
        request_digest: ContentDigest,
    ) -> Self {
        Self {
            tenant,
            principal,
            operation,
            key,
            request_digest,
        }
    }

    /// Returns the tenant scope.
    #[must_use]
    pub const fn tenant(&self) -> &TenantId {
        &self.tenant
    }

    /// Returns the authenticated principal scope.
    #[must_use]
    pub const fn principal(&self) -> &PrincipalId {
        &self.principal
    }

    /// Returns the exact generated operation identifier.
    #[must_use]
    pub const fn operation(&self) -> &OperationId {
        &self.operation
    }

    /// Returns the caller idempotency key.
    #[must_use]
    pub const fn key(&self) -> &IdempotencyKey {
        &self.key
    }

    /// Returns the digest of the exact normalized request.
    #[must_use]
    pub const fn request_digest(&self) -> &ContentDigest {
        &self.request_digest
    }

    fn scope(&self) -> IdempotencyScope {
        IdempotencyScope {
            tenant: self.tenant.clone(),
            principal: self.principal.clone(),
            operation: self.operation.clone(),
            key: self.key.clone(),
        }
    }
}

impl fmt::Debug for IdempotencyBinding {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("IdempotencyBinding")
            .field("tenant", &self.tenant)
            .field("principal", &self.principal)
            .field("operation", &self.operation)
            .field("key", &self.key)
            .field("request_digest", &self.request_digest)
            .finish()
    }
}

#[derive(Clone, Eq, Ord, PartialEq, PartialOrd)]
struct IdempotencyScope {
    tenant: TenantId,
    principal: PrincipalId,
    operation: OperationId,
    key: IdempotencyKey,
}

/// Opaque ownership proof for one newly reserved execution.
pub struct IdempotencyPermit {
    binding: IdempotencyBinding,
    token: Vec<u8>,
}

impl IdempotencyPermit {
    /// Creates an opaque permit for an external durable repository implementation.
    ///
    /// The repository must generate an unguessable or transaction-unique token and validate it
    /// again during completion or abandonment. Constructing a permit grants no authority by
    /// itself because only the originating repository can consume it.
    pub fn from_repository(
        binding: IdempotencyBinding,
        token: Vec<u8>,
    ) -> Result<Self, IdempotencyError> {
        if token.is_empty() || token.len() > MAX_PERMIT_TOKEN_BYTES {
            return Err(IdempotencyError::InvalidPermit);
        }
        Ok(Self { binding, token })
    }

    /// Returns the exact request binding owned by this permit.
    #[must_use]
    pub const fn binding(&self) -> &IdempotencyBinding {
        &self.binding
    }

    /// Returns the repository-private token only to the consuming persistence boundary.
    #[must_use]
    pub fn repository_token(&self) -> &[u8] {
        &self.token
    }
}

impl fmt::Debug for IdempotencyPermit {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("IdempotencyPermit([REDACTED])")
    }
}

/// Result of atomically reserving an idempotency binding.
#[derive(Debug)]
pub enum IdempotencyReservation {
    /// This caller owns the only execution permit for the request.
    Execute(IdempotencyPermit),
    /// The exact completed response must be returned without execution.
    Replay(ExactResponse),
    /// An identical request currently owns the execution permit.
    Pending,
}

/// Object-safe persistence contract for mutation idempotency.
///
/// Durable implementations must atomically persist reservations before execution and must
/// atomically replace a reservation with its exact response before reporting success.
pub trait IdempotencyRepository: Send + Sync {
    /// Atomically reserves a binding, replays its response, or reports identical in-flight work.
    fn reserve(
        &self,
        binding: &IdempotencyBinding,
    ) -> Result<IdempotencyReservation, IdempotencyError>;

    /// Atomically records the exact response owned by a live permit.
    fn complete(
        &self,
        permit: IdempotencyPermit,
        response: ExactResponse,
    ) -> Result<ExactResponse, IdempotencyError>;

    /// Removes a live reservation after the operation proves it made no durable mutation.
    fn abandon(&self, permit: IdempotencyPermit) -> Result<(), IdempotencyError>;

    /// Waits a bounded duration for an identical in-flight request to complete.
    fn wait_for_completion(
        &self,
        binding: &IdempotencyBinding,
        maximum_wait: Duration,
    ) -> Result<ExactResponse, IdempotencyError>;
}

enum Entry {
    InProgress {
        request_digest: ContentDigest,
        token: Vec<u8>,
    },
    Complete {
        request_digest: ContentDigest,
        response: ExactResponse,
    },
}

#[derive(Default)]
struct RepositoryState {
    entries: BTreeMap<IdempotencyScope, Entry>,
    next_token: u64,
}

/// Thread-safe in-memory oracle used to validate durable repository implementations.
#[derive(Default)]
pub struct InMemoryIdempotencyRepository {
    state: Mutex<RepositoryState>,
    completed: Condvar,
}

impl InMemoryIdempotencyRepository {
    /// Creates an empty repository oracle.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Executes a mutation only for the winning reservation and otherwise replays or waits.
    pub fn execute_once<F>(
        &self,
        binding: &IdempotencyBinding,
        maximum_wait: Duration,
        operation: F,
    ) -> Result<ExactResponse, IdempotencyError>
    where
        F: FnOnce() -> Result<ExactResponse, IdempotencyError>,
    {
        match self.reserve(binding)? {
            IdempotencyReservation::Replay(response) => Ok(response),
            IdempotencyReservation::Pending => self.wait_for_completion(binding, maximum_wait),
            IdempotencyReservation::Execute(permit) => match operation() {
                Ok(response) => self.complete(permit, response),
                Err(operation_error) => {
                    if self.abandon(permit).is_err() {
                        Err(IdempotencyError::InvalidPermit)
                    } else {
                        Err(operation_error)
                    }
                }
            },
        }
    }

    fn lock_state(&self) -> MutexGuard<'_, RepositoryState> {
        match self.state.lock() {
            Ok(state) => state,
            Err(poisoned) => poisoned.into_inner(),
        }
    }
}

impl IdempotencyRepository for InMemoryIdempotencyRepository {
    fn reserve(
        &self,
        binding: &IdempotencyBinding,
    ) -> Result<IdempotencyReservation, IdempotencyError> {
        let scope = binding.scope();
        let mut state = self.lock_state();
        if let Some(entry) = state.entries.get(&scope) {
            return match entry {
                Entry::InProgress { request_digest, .. } => {
                    if request_digest == binding.request_digest() {
                        Ok(IdempotencyReservation::Pending)
                    } else {
                        Err(IdempotencyError::RequestCollision)
                    }
                }
                Entry::Complete {
                    request_digest,
                    response,
                } => {
                    if request_digest == binding.request_digest() {
                        Ok(IdempotencyReservation::Replay(response.clone()))
                    } else {
                        Err(IdempotencyError::RequestCollision)
                    }
                }
            };
        }
        let Some(token) = state.next_token.checked_add(1) else {
            return Err(IdempotencyError::TokenExhausted);
        };
        state.next_token = token;
        let permit_token = token.to_be_bytes().to_vec();
        state.entries.insert(
            scope.clone(),
            Entry::InProgress {
                request_digest: binding.request_digest.clone(),
                token: permit_token.clone(),
            },
        );
        Ok(IdempotencyReservation::Execute(
            IdempotencyPermit::from_repository(binding.clone(), permit_token)?,
        ))
    }

    fn complete(
        &self,
        permit: IdempotencyPermit,
        response: ExactResponse,
    ) -> Result<ExactResponse, IdempotencyError> {
        let mut state = self.lock_state();
        let scope = permit.binding.scope();
        let valid = matches!(
            state.entries.get(&scope),
            Some(Entry::InProgress {
                request_digest,
                token,
            }) if request_digest == permit.binding.request_digest() && token == permit.repository_token()
        );
        if !valid {
            return Err(IdempotencyError::InvalidPermit);
        }
        state.entries.insert(
            scope,
            Entry::Complete {
                request_digest: permit.binding.request_digest,
                response: response.clone(),
            },
        );
        drop(state);
        self.completed.notify_all();
        Ok(response)
    }

    fn abandon(&self, permit: IdempotencyPermit) -> Result<(), IdempotencyError> {
        let mut state = self.lock_state();
        let scope = permit.binding.scope();
        let valid = matches!(
            state.entries.get(&scope),
            Some(Entry::InProgress {
                request_digest,
                token,
            }) if request_digest == permit.binding.request_digest() && token == permit.repository_token()
        );
        if !valid {
            return Err(IdempotencyError::InvalidPermit);
        }
        state.entries.remove(&scope);
        drop(state);
        self.completed.notify_all();
        Ok(())
    }

    fn wait_for_completion(
        &self,
        binding: &IdempotencyBinding,
        maximum_wait: Duration,
    ) -> Result<ExactResponse, IdempotencyError> {
        let started = Instant::now();
        let scope = binding.scope();
        let mut state = self.lock_state();
        loop {
            match state.entries.get(&scope) {
                Some(Entry::Complete {
                    request_digest,
                    response,
                }) => {
                    return if request_digest == binding.request_digest() {
                        Ok(response.clone())
                    } else {
                        Err(IdempotencyError::RequestCollision)
                    };
                }
                Some(Entry::InProgress { request_digest, .. }) => {
                    if request_digest != binding.request_digest() {
                        return Err(IdempotencyError::RequestCollision);
                    }
                }
                None => return Err(IdempotencyError::ReservationNotFound),
            }
            let elapsed = started.elapsed();
            let Some(remaining) = maximum_wait.checked_sub(elapsed) else {
                return Err(IdempotencyError::WaitTimedOut);
            };
            if remaining.is_zero() {
                return Err(IdempotencyError::WaitTimedOut);
            }
            let (next_state, wait_result) = match self.completed.wait_timeout(state, remaining) {
                Ok(result) => result,
                Err(poisoned) => poisoned.into_inner(),
            };
            state = next_state;
            if wait_result.timed_out() {
                return match state.entries.get(&scope) {
                    Some(Entry::Complete {
                        request_digest,
                        response,
                    }) if request_digest == binding.request_digest() => Ok(response.clone()),
                    _ => Err(IdempotencyError::WaitTimedOut),
                };
            }
        }
    }
}

impl fmt::Debug for InMemoryIdempotencyRepository {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let state = self.lock_state();
        formatter
            .debug_struct("InMemoryIdempotencyRepository")
            .field("entries", &state.entries.len())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::{
        ExactResponse, IdempotencyBinding, IdempotencyError, IdempotencyRepository,
        IdempotencyReservation, InMemoryIdempotencyRepository,
    };
    use crate::context::{OperationId, PrincipalId, TenantId};
    use cigar_protocol::{ContentDigest, IdempotencyKey};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Barrier};
    use std::time::Duration;

    fn binding(character: char) -> Result<IdempotencyBinding, Box<dyn std::error::Error>> {
        Ok(IdempotencyBinding::new(
            TenantId::new("tenant-a")?,
            PrincipalId::new("principal-a")?,
            OperationId::new("compileBundle")?,
            IdempotencyKey::new("caller-key")?,
            ContentDigest::new(format!("1220{}", character.to_string().repeat(64)))?,
        ))
    }

    #[test]
    fn unavailable_backend_has_a_stable_non_permit_error() {
        assert_eq!(
            IdempotencyError::Unavailable.to_string(),
            "idempotency persistence is unavailable"
        );
        assert_ne!(
            IdempotencyError::Unavailable,
            IdempotencyError::InvalidPermit
        );
    }

    #[test]
    fn completed_response_replays_exactly_and_collision_fails()
    -> Result<(), Box<dyn std::error::Error>> {
        let repository = InMemoryIdempotencyRepository::new();
        let first = binding('a')?;
        let IdempotencyReservation::Execute(permit) = repository.reserve(&first)? else {
            return Err("first reservation did not receive an execution permit".into());
        };
        repository.complete(permit, ExactResponse::new(b"exact-envelope".to_vec())?)?;
        let IdempotencyReservation::Replay(response) = repository.reserve(&first)? else {
            return Err("duplicate reservation did not replay".into());
        };
        assert_eq!(response.as_bytes(), b"exact-envelope");
        assert!(matches!(
            repository.reserve(&binding('b')?),
            Err(IdempotencyError::RequestCollision)
        ));
        Ok(())
    }

    #[test]
    fn concurrent_duplicates_execute_once() -> Result<(), Box<dyn std::error::Error>> {
        const THREADS: usize = 12;
        let repository = Arc::new(InMemoryIdempotencyRepository::new());
        let binding = Arc::new(binding('a')?);
        let starts = Arc::new(Barrier::new(THREADS));
        let executions = Arc::new(AtomicUsize::new(0));
        let mut handles = Vec::new();
        for _ in 0..THREADS {
            let repository = Arc::clone(&repository);
            let binding = Arc::clone(&binding);
            let starts = Arc::clone(&starts);
            let executions = Arc::clone(&executions);
            handles.push(std::thread::spawn(move || {
                starts.wait();
                repository.execute_once(&binding, Duration::from_secs(2), || {
                    executions.fetch_add(1, Ordering::SeqCst);
                    ExactResponse::new(b"one-response".to_vec())
                })
            }));
        }
        for handle in handles {
            let response = handle.join().map_err(|_panic| "worker panicked")??;
            assert_eq!(response.as_bytes(), b"one-response");
        }
        assert_eq!(executions.load(Ordering::SeqCst), 1);
        Ok(())
    }

    #[test]
    fn debug_does_not_expose_response_or_key() -> Result<(), Box<dyn std::error::Error>> {
        let repository = InMemoryIdempotencyRepository::new();
        let binding = binding('a')?;
        let IdempotencyReservation::Execute(permit) = repository.reserve(&binding)? else {
            return Err("first reservation did not receive a permit".into());
        };
        let response = ExactResponse::new(b"sensitive-response".to_vec())?;
        assert!(!format!("{response:?}").contains("sensitive-response"));
        assert!(!format!("{binding:?}").contains("caller-key"));
        assert!(!format!("{permit:?}").contains("caller-key"));
        Ok(())
    }
}
