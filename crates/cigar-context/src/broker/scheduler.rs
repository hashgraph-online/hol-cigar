//! Bounded admission and round-robin dispatch for one broker owner.
//!
//! Registration/host admission must remain private to the host. Authentication here only admits
//! work to a queue; the broker must recheck the current grant, scope and evidence at dispatch.
//! Jobs are non-preemptive. Fairness is between dispatch opportunities, not equal CPU time.

use super::{BrokerCredential, BrokerError, MAX_LIFETIME_MS, deadline};
use crate::digest;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, VecDeque};
use std::sync::Arc;
use std::sync::atomic::{AtomicU8, Ordering};
use std::time::{Duration, Instant};

const QUEUED: u8 = 0;
const DISPATCHED: u8 = 1;
const FINISHED: u8 = 2;
const CANCELLED: u8 = 3;

/// Separate global budgets for agents and for the host control channel.
#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct QueueLimits {
    /// Maximum registered agent lanes.
    pub max_agents: usize,
    /// Aggregate queued agent jobs, excluding the executing job.
    pub max_agent_jobs: usize,
    /// Aggregate encoded bytes of queued agent work.
    pub max_agent_bytes: usize,
    /// Host jobs have their own capacity, unavailable to agents.
    pub max_host_jobs: usize,
    /// Separate encoded-byte capacity for host commands.
    pub max_host_bytes: usize,
    /// Largest accepted queue wait in milliseconds.
    pub max_wait_ms: u64,
}

impl Default for QueueLimits {
    fn default() -> Self {
        Self {
            max_agents: 128,
            max_agent_jobs: 1024,
            max_agent_bytes: 32 * 1024 * 1024,
            max_host_jobs: 8,
            max_host_bytes: 32 * 1024 * 1024,
            max_wait_ms: 30_000,
        }
    }
}

/// Host-assigned per-agent queue allowance. Connections do not each get a separate allowance.
#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct AgentQueueLimits {
    /// Maximum queued jobs across all of the grant's connections.
    pub max_jobs: usize,
    /// Maximum encoded queued bytes across the grant's connections.
    pub max_bytes: usize,
}

impl Default for AgentQueueLimits {
    fn default() -> Self {
        Self {
            max_jobs: 8,
            max_bytes: 4 * 1024 * 1024,
        }
    }
}

/// One request's cancellation state, shared with its connection handler.
#[derive(Clone)]
pub struct Cancellation(Arc<AtomicU8>);

impl Cancellation {
    /// Returns true only when this operation definitely cannot start in the future.
    /// False means dispatch may have begun/completed; never infer mutation failure or retry.
    #[must_use]
    pub fn cancel(&self) -> bool {
        match self
            .0
            .compare_exchange(QUEUED, CANCELLED, Ordering::AcqRel, Ordering::Acquire)
        {
            Ok(_) | Err(CANCELLED) => true,
            Err(_) => false,
        }
    }
}

/// Dispatch status. Only `Ready` permits calling the broker's operation handler.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DispatchStatus {
    /// The operation has crossed the dispatch boundary; cancellation is now uncertain.
    Ready,
    /// Deadline expired before dispatch; no operation handler may run.
    Expired,
    /// Cancellation or lane revocation occurred before dispatch; no handler may run.
    Cancelled,
}

struct Queued<T> {
    payload: T,
    bytes: usize,
    enqueued: Instant,
    expires: Instant,
    cancellation: Cancellation,
}

/// A dequeued job, including queue-delay telemetry and definitive pre-dispatch failures.
pub struct Scheduled<T> {
    payload: Option<T>,
    status: DispatchStatus,
    delay: Duration,
    cancellation: Cancellation,
}

impl<T> Scheduled<T> {
    /// Definitive scheduling disposition. Expired/cancelled work must only receive a failure reply.
    #[must_use]
    pub const fn status(&self) -> DispatchStatus {
        self.status
    }

    /// Time spent waiting, including time behind other agents' bounded operations.
    #[must_use]
    pub const fn queue_delay(&self) -> Duration {
        self.delay
    }

    /// Take the job for execution or a failure reply. Does not change its scheduling disposition.
    pub fn take(&mut self) -> Option<T> {
        self.payload.take()
    }
}

impl<T> Drop for Scheduled<T> {
    fn drop(&mut self) {
        let _ = self.cancellation.0.compare_exchange(
            DISPATCHED,
            FINISHED,
            Ordering::AcqRel,
            Ordering::Acquire,
        );
    }
}

struct Lane<T> {
    agent: String,
    limits: AgentQueueLimits,
    expires: Instant,
    jobs: VecDeque<Queued<T>>,
    bytes: usize,
}

/// Host-private scheduler. Keep behind one owner/mutex; synchronization is deliberately external.
pub struct BrokerScheduler<T> {
    epoch: String,
    limits: QueueLimits,
    lanes: BTreeMap<String, Lane<T>>,
    active: VecDeque<String>,
    host: VecDeque<Queued<T>>,
    host_bytes: usize,
    host_turn: bool,
}

impl<T> BrokerScheduler<T> {
    /// Create an empty scheduler tied to exactly one broker epoch.
    pub fn new(epoch: &str, limits: QueueLimits) -> Result<Self, BrokerError> {
        if epoch.len() != 64
            || !epoch.bytes().all(|byte| byte.is_ascii_hexdigit())
            || limits.max_agents == 0
            || limits.max_agents > 128
            || limits.max_agent_jobs < 2
            || limits.max_agent_jobs > 65_536
            || limits.max_agent_bytes < 2
            || limits.max_agent_bytes > 1024 * 1024 * 1024
            || limits.max_host_jobs == 0
            || limits.max_host_jobs > 128
            || limits.max_host_bytes == 0
            || limits.max_host_bytes > 1024 * 1024 * 1024
            || limits.max_wait_ms == 0
            || limits.max_wait_ms > MAX_LIFETIME_MS
        {
            return Err(BrokerError::InvalidInput);
        }
        Ok(Self {
            epoch: epoch.into(),
            limits,
            lanes: BTreeMap::new(),
            active: VecDeque::new(),
            host: VecDeque::new(),
            host_bytes: 0,
            host_turn: true,
        })
    }

    /// Validate a lane's limits before creating/replacing the corresponding broker grant.
    /// One agent can never reserve the entire global agent queue.
    pub fn validate_lane_limits(&self, limits: AgentQueueLimits) -> Result<(), BrokerError> {
        if limits.max_jobs == 0
            || limits.max_jobs > self.limits.max_agent_jobs / 2
            || limits.max_bytes == 0
            || limits.max_bytes > self.limits.max_agent_bytes / 2
        {
            return Err(BrokerError::InvalidInput);
        }
        Ok(())
    }

    /// Register an already-created broker grant; replacing an agent cancels its old queued jobs.
    /// Return cancelled payloads so the transport can send definitive failure responses.
    pub fn host_register(
        &mut self,
        agent: &str,
        credential: &BrokerCredential,
        limits: AgentQueueLimits,
        lease_ms: u64,
    ) -> Result<Vec<Scheduled<T>>, BrokerError> {
        self.validate_lane_limits(limits)?;
        if !crate::graph::valid_id(agent) || lease_ms == 0 || lease_ms > MAX_LIFETIME_MS {
            return Err(BrokerError::InvalidInput);
        }
        let key = self.credential_key(credential)?;
        let previous = self
            .lanes
            .iter()
            .find(|(_, lane)| lane.agent == agent)
            .map(|(key, _)| key.clone());
        if self.lanes.contains_key(&key)
            || (previous.is_none() && self.lanes.len() >= self.limits.max_agents)
        {
            return Err(BrokerError::Quota);
        }
        let expires = deadline(lease_ms)?;
        let cancelled = previous.map_or_else(Vec::new, |key| self.remove_lane(&key));
        self.lanes.insert(
            key,
            Lane {
                agent: agent.into(),
                limits,
                expires,
                jobs: VecDeque::new(),
                bytes: 0,
            },
        );
        Ok(cancelled)
    }

    /// Revoke queue admission and return cancelled work for failure replies. The broker's grant
    /// must also be revoked; queue registration alone is never source/reviewer authority.
    pub fn host_revoke(&mut self, agent: &str) -> Vec<Scheduled<T>> {
        let key = self
            .lanes
            .iter()
            .find(|(_, lane)| lane.agent == agent)
            .map(|(key, _)| key.clone());
        key.map_or_else(Vec::new, |key| self.remove_lane(&key))
    }

    /// Admit one authenticated job after the transport has bounded and measured its encoded frame.
    /// `encoded_bytes` must be the transport's actual byte count, never a client-supplied estimate.
    pub fn enqueue_agent(
        &mut self,
        credential: &BrokerCredential,
        payload: T,
        encoded_bytes: usize,
        wait_ms: u64,
    ) -> Result<Cancellation, BrokerError> {
        self.validate_job(encoded_bytes, wait_ms)?;
        let key = self.credential_key(credential)?;
        let lane = self
            .lanes
            .get(&key)
            .filter(|lane| lane.expires > Instant::now())
            .ok_or(BrokerError::AccessDenied)?;
        let (jobs, bytes) = self.lanes.values().fold((0, 0), |(jobs, bytes), lane| {
            (jobs + lane.jobs.len(), bytes + lane.bytes)
        });
        if jobs >= self.limits.max_agent_jobs
            || encoded_bytes > self.limits.max_agent_bytes - bytes
            || lane.jobs.len() >= lane.limits.max_jobs
            || encoded_bytes > lane.limits.max_bytes - lane.bytes
        {
            return Err(BrokerError::Quota);
        }
        let expires = deadline(wait_ms)?.min(lane.expires);
        let cancellation = Cancellation(Arc::new(AtomicU8::new(QUEUED)));
        if let Some(lane) = self.lanes.get_mut(&key) {
            if lane.jobs.is_empty() {
                self.active.push_back(key);
            }
            lane.jobs.push_back(Queued {
                payload,
                bytes: encoded_bytes,
                enqueued: Instant::now(),
                expires,
                cancellation: cancellation.clone(),
            });
            lane.bytes += encoded_bytes;
        }
        Ok(cancellation)
    }

    /// Admit a private host job, using capacity unavailable to any agent.
    pub fn enqueue_host(
        &mut self,
        payload: T,
        encoded_bytes: usize,
        wait_ms: u64,
    ) -> Result<Cancellation, BrokerError> {
        self.validate_job(encoded_bytes, wait_ms)?;
        if self.host.len() >= self.limits.max_host_jobs
            || encoded_bytes > self.limits.max_host_bytes - self.host_bytes
        {
            return Err(BrokerError::Quota);
        }
        let cancellation = Cancellation(Arc::new(AtomicU8::new(QUEUED)));
        self.host.push_back(Queued {
            payload,
            bytes: encoded_bytes,
            enqueued: Instant::now(),
            expires: deadline(wait_ms)?,
            cancellation: cancellation.clone(),
        });
        self.host_bytes += encoded_bytes;
        Ok(cancellation)
    }

    /// Pop one dispatch opportunity. When both have work, the host and agent classes alternate;
    /// agents rotate once per opportunity. Expired/cancelled jobs still receive a failure reply.
    pub fn pop(&mut self) -> Option<Scheduled<T>> {
        let queued = if !self.host.is_empty() && (self.host_turn || self.active.is_empty()) {
            self.host_turn = false;
            let queued = self.host.pop_front()?;
            self.host_bytes -= queued.bytes;
            queued
        } else {
            let key = self.active.pop_front()?;
            self.host_turn = true;
            let lane = self.lanes.get_mut(&key)?;
            let queued = lane.jobs.pop_front()?;
            lane.bytes -= queued.bytes;
            if !lane.jobs.is_empty() {
                self.active.push_back(key);
            }
            queued
        };
        Some(dispatch(queued))
    }

    /// Total currently queued jobs, for host telemetry/wakeup logic only.
    #[must_use]
    pub fn len(&self) -> usize {
        self.host.len()
            + self
                .lanes
                .values()
                .map(|lane| lane.jobs.len())
                .sum::<usize>()
    }

    /// Whether dispatch would find no work.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Prune expired grants and return their definitively cancelled jobs for failure replies.
    pub fn host_prune(&mut self) -> Vec<Scheduled<T>> {
        let now = Instant::now();
        let keys = self
            .lanes
            .iter()
            .filter(|(_, lane)| lane.expires <= now)
            .map(|(key, _)| key.clone())
            .collect::<Vec<_>>();
        keys.into_iter()
            .flat_map(|key| self.remove_lane(&key))
            .collect()
    }

    fn validate_job(&self, bytes: usize, wait_ms: u64) -> Result<(), BrokerError> {
        if bytes == 0 || wait_ms == 0 || wait_ms > self.limits.max_wait_ms {
            return Err(BrokerError::InvalidInput);
        }
        Ok(())
    }

    fn credential_key(&self, credential: &BrokerCredential) -> Result<String, BrokerError> {
        if credential.epoch != self.epoch
            || credential.secret.len() != 64
            || !credential
                .secret
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit())
        {
            return Err(BrokerError::AccessDenied);
        }
        Ok(digest("cigar.broker-queue-grant.v1", credential)?)
    }

    fn remove_lane(&mut self, key: &str) -> Vec<Scheduled<T>> {
        self.active.retain(|active| active != key);
        self.lanes.remove(key).map_or_else(Vec::new, |lane| {
            lane.jobs
                .into_iter()
                .map(|job| {
                    let _ = job.cancellation.cancel();
                    dispatch(job)
                })
                .collect()
        })
    }
}

impl<T> Drop for BrokerScheduler<T> {
    fn drop(&mut self) {
        for job in self
            .host
            .iter()
            .chain(self.lanes.values().flat_map(|lane| &lane.jobs))
        {
            let _ = job.cancellation.cancel();
        }
    }
}

fn dispatch<T>(queued: Queued<T>) -> Scheduled<T> {
    let now = Instant::now();
    let status = if queued.cancellation.0.load(Ordering::Acquire) == CANCELLED {
        DispatchStatus::Cancelled
    } else if queued.expires <= now {
        let _ = queued.cancellation.cancel();
        DispatchStatus::Expired
    } else if queued
        .cancellation
        .0
        .compare_exchange(QUEUED, DISPATCHED, Ordering::AcqRel, Ordering::Acquire)
        .is_ok()
    {
        DispatchStatus::Ready
    } else {
        DispatchStatus::Cancelled
    };
    Scheduled {
        payload: Some(queued.payload),
        status,
        delay: now.saturating_duration_since(queued.enqueued),
        cancellation: queued.cancellation,
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::indexing_slicing)]
    use super::*;

    fn credential(i: usize) -> BrokerCredential {
        BrokerCredential {
            epoch: "e".repeat(64),
            secret: format!("{i:064x}"),
        }
    }

    fn queue<T>() -> BrokerScheduler<T> {
        BrokerScheduler::new(&"e".repeat(64), QueueLimits::default()).unwrap()
    }

    fn register<T>(queue: &mut BrokerScheduler<T>, i: usize) {
        queue
            .host_register(
                &format!("agent-{i}"),
                &credential(i),
                AgentQueueLimits::default(),
                60_000,
            )
            .unwrap();
    }

    #[test]
    fn twelve_busy_agents_receive_one_turn_each_and_host_capacity_is_separate() {
        let mut queue = queue();
        for agent in 0..12 {
            register(&mut queue, agent);
            for job in 0..8 {
                queue
                    .enqueue_agent(&credential(agent), (agent, job), 100, 30_000)
                    .unwrap();
            }
            assert!(matches!(
                queue.enqueue_agent(&credential(agent), (agent, 9), 100, 30_000),
                Err(BrokerError::Quota)
            ));
        }
        for i in 0..8 {
            queue.enqueue_host((100, i), 100, 30_000).unwrap();
        }
        let mut agent_order = Vec::new();
        let mut host_count = 0;
        while let Some(mut job) = queue.pop() {
            assert_eq!(job.status(), DispatchStatus::Ready);
            let (agent, number) = job.take().unwrap();
            if agent == 100 {
                host_count += 1;
                assert!(agent_order.len() < 8);
            } else {
                agent_order.push((agent, number));
            }
        }
        assert_eq!(host_count, 8);
        let expected = (0..8)
            .flat_map(|job| (0..12).map(move |agent| (agent, job)))
            .collect::<Vec<_>>();
        assert_eq!(agent_order, expected);
        assert!(queue.is_empty());
    }

    #[test]
    fn global_agent_saturation_preserves_host_and_cancellation_boundaries() {
        let limits = QueueLimits {
            max_agent_jobs: 4,
            max_agent_bytes: 100,
            max_host_bytes: 10,
            ..QueueLimits::default()
        };
        let mut queue = BrokerScheduler::new(&"e".repeat(64), limits).unwrap();
        for agent in 0..2 {
            queue
                .host_register(
                    &format!("a{agent}"),
                    &credential(agent),
                    AgentQueueLimits {
                        max_jobs: 2,
                        max_bytes: 50,
                    },
                    60_000,
                )
                .unwrap();
            queue
                .enqueue_agent(&credential(agent), agent, 50, 30_000)
                .unwrap();
        }
        assert!(matches!(
            queue.enqueue_agent(&credential(0), 3, 1, 30_000),
            Err(BrokerError::Quota)
        ));
        let host = queue.enqueue_host(100, 10, 30_000).unwrap();
        assert!(host.cancel());
        let job = queue.pop().unwrap();
        assert_eq!(job.status(), DispatchStatus::Cancelled);
        assert!(host.cancel());
        drop(job);
        assert!(host.cancel());
        let agent = queue.pop().unwrap();
        assert_eq!(agent.status(), DispatchStatus::Ready);
        assert!(!agent.cancellation.cancel());
        let completed = agent.cancellation.clone();
        drop(agent);
        assert!(!completed.cancel());
    }

    #[test]
    fn expiration_and_redefinition_never_dispatch_previous_grant_jobs() {
        let mut queue = queue();
        register(&mut queue, 1);
        let token = queue.enqueue_agent(&credential(1), 1, 10, 30_000).unwrap();
        let key = queue.credential_key(&credential(1)).unwrap();
        queue
            .lanes
            .get_mut(&key)
            .unwrap()
            .jobs
            .front_mut()
            .unwrap()
            .expires = Instant::now();
        assert_eq!(queue.pop().unwrap().status(), DispatchStatus::Expired);
        assert!(token.cancel());
        let token = queue.enqueue_agent(&credential(1), 2, 10, 30_000).unwrap();
        let replaced = queue
            .host_register(
                "agent-1",
                &credential(2),
                AgentQueueLimits::default(),
                60_000,
            )
            .unwrap();
        assert_eq!(replaced.len(), 1);
        assert_eq!(replaced[0].status(), DispatchStatus::Cancelled);
        assert!(token.cancel());
        assert!(matches!(
            queue.enqueue_agent(&credential(1), 3, 10, 30_000),
            Err(BrokerError::AccessDenied)
        ));
        queue.enqueue_agent(&credential(2), 4, 10, 30_000).unwrap();
        assert_eq!(queue.pop().unwrap().status(), DispatchStatus::Ready);
    }

    #[test]
    fn forged_wrong_epoch_and_unregistered_credentials_cannot_get_a_lane() {
        let mut queue = queue();
        register(&mut queue, 1);
        assert!(matches!(
            queue.enqueue_agent(&credential(9), (), 1, 1),
            Err(BrokerError::AccessDenied)
        ));
        let mut stale = credential(1);
        stale.epoch = "0".repeat(64);
        assert!(matches!(
            queue.enqueue_agent(&stale, (), 1, 1),
            Err(BrokerError::AccessDenied)
        ));
        assert!(queue.is_empty());
        let key = queue.credential_key(&credential(1)).unwrap();
        queue.lanes.get_mut(&key).unwrap().expires = Instant::now();
        assert!(matches!(
            queue.enqueue_agent(&credential(1), (), 1, 1),
            Err(BrokerError::AccessDenied)
        ));
        queue.host_prune();
        assert!(queue.lanes.is_empty());
    }

    #[test]
    fn dispatch_and_cancellation_race_has_only_one_winner() {
        for _ in 0..100 {
            let mut queue = queue();
            register(&mut queue, 1);
            let token = queue.enqueue_agent(&credential(1), (), 1, 30_000).unwrap();
            let barrier = Arc::new(std::sync::Barrier::new(2));
            let other = Arc::clone(&barrier);
            let cancellation = std::thread::spawn(move || {
                other.wait();
                token.cancel()
            });
            barrier.wait();
            let job = queue.pop().unwrap();
            let cancelled = cancellation.join().unwrap();
            assert_eq!(cancelled, job.status() == DispatchStatus::Cancelled);
        }
    }

    #[test]
    fn dropping_queue_proves_waiting_jobs_never_started() {
        let mut queue = queue();
        register(&mut queue, 1);
        let token = queue.enqueue_agent(&credential(1), (), 1, 30_000).unwrap();
        drop(queue);
        assert!(token.cancel());
    }
}
