//! Leak-free global and per-tenant request concurrency quotas.

use crate::context::TenantId;
use std::collections::BTreeMap;
use std::fmt;
use std::sync::{Arc, Mutex, MutexGuard};

/// Quota configuration or admission failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum QuotaError {
    /// A concurrency limit was configured as zero.
    InvalidLimits,
    /// The service-wide concurrency limit is exhausted.
    GlobalExhausted,
    /// The authenticated tenant concurrency limit is exhausted.
    TenantExhausted,
}

impl fmt::Display for QuotaError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::InvalidLimits => "quota limits must be positive",
            Self::GlobalExhausted => "global request quota is exhausted",
            Self::TenantExhausted => "tenant request quota is exhausted",
        };
        formatter.write_str(message)
    }
}

impl std::error::Error for QuotaError {}

/// Positive global and per-tenant concurrency limits.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct QuotaLimits {
    global: u32,
    per_tenant: u32,
}

impl QuotaLimits {
    /// Creates positive request concurrency limits.
    pub const fn new(global: u32, per_tenant: u32) -> Result<Self, QuotaError> {
        if global == 0 || per_tenant == 0 {
            Err(QuotaError::InvalidLimits)
        } else {
            Ok(Self { global, per_tenant })
        }
    }

    /// Returns the service-wide concurrency limit.
    #[must_use]
    pub const fn global(self) -> u32 {
        self.global
    }

    /// Returns the per-tenant concurrency limit.
    #[must_use]
    pub const fn per_tenant(self) -> u32 {
        self.per_tenant
    }
}

#[derive(Default)]
struct QuotaState {
    global_in_use: u32,
    tenant_in_use: BTreeMap<TenantId, u32>,
    admitted_total: u64,
    released_total: u64,
    global_rejected_total: u64,
    tenant_rejected_total: u64,
}

struct QuotaInner {
    limits: QuotaLimits,
    state: Mutex<QuotaState>,
}

impl QuotaInner {
    fn lock_state(&self) -> MutexGuard<'_, QuotaState> {
        match self.state.lock() {
            Ok(state) => state,
            Err(poisoned) => poisoned.into_inner(),
        }
    }

    fn release(&self, tenant: &TenantId) {
        let mut state = self.lock_state();
        state.global_in_use = state.global_in_use.saturating_sub(1);
        let mut remove_tenant = false;
        if let Some(in_use) = state.tenant_in_use.get_mut(tenant) {
            *in_use = in_use.saturating_sub(1);
            remove_tenant = *in_use == 0;
        }
        if remove_tenant {
            state.tenant_in_use.remove(tenant);
        }
        state.released_total = state.released_total.saturating_add(1);
    }
}

/// Thread-safe global and tenant quota admission controller.
#[derive(Clone)]
pub struct QuotaManager {
    inner: Arc<QuotaInner>,
}

impl QuotaManager {
    /// Creates an empty quota manager.
    #[must_use]
    pub fn new(limits: QuotaLimits) -> Self {
        Self {
            inner: Arc::new(QuotaInner {
                limits,
                state: Mutex::new(QuotaState::default()),
            }),
        }
    }

    /// Acquires global and tenant capacity atomically.
    pub fn acquire(&self, tenant: &TenantId) -> Result<QuotaLease, QuotaError> {
        let mut state = self.inner.lock_state();
        if state.global_in_use >= self.inner.limits.global {
            state.global_rejected_total = state.global_rejected_total.saturating_add(1);
            return Err(QuotaError::GlobalExhausted);
        }
        let tenant_in_use = state.tenant_in_use.get(tenant).copied().unwrap_or(0);
        if tenant_in_use >= self.inner.limits.per_tenant {
            state.tenant_rejected_total = state.tenant_rejected_total.saturating_add(1);
            return Err(QuotaError::TenantExhausted);
        }
        state.global_in_use = state.global_in_use.saturating_add(1);
        state
            .tenant_in_use
            .insert(tenant.clone(), tenant_in_use.saturating_add(1));
        state.admitted_total = state.admitted_total.saturating_add(1);
        drop(state);
        Ok(QuotaLease {
            inner: Arc::clone(&self.inner),
            tenant: Some(tenant.clone()),
        })
    }

    /// Returns a consistent snapshot of in-use gauges and cumulative counters.
    #[must_use]
    pub fn snapshot(&self) -> QuotaSnapshot {
        let state = self.inner.lock_state();
        QuotaSnapshot {
            global_in_use: state.global_in_use,
            tenant_in_use: state.tenant_in_use.clone(),
            admitted_total: state.admitted_total,
            released_total: state.released_total,
            global_rejected_total: state.global_rejected_total,
            tenant_rejected_total: state.tenant_rejected_total,
        }
    }
}

impl fmt::Debug for QuotaManager {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("QuotaManager")
            .field("limits", &self.inner.limits)
            .field("snapshot", &self.snapshot())
            .finish()
    }
}

/// Exclusive admission lease that automatically releases capacity on drop.
pub struct QuotaLease {
    inner: Arc<QuotaInner>,
    tenant: Option<TenantId>,
}

impl QuotaLease {
    /// Releases this lease early. Repeated releases are harmless.
    pub fn release(&mut self) {
        if let Some(tenant) = self.tenant.take() {
            self.inner.release(&tenant);
        }
    }

    /// Returns whether this lease still owns capacity.
    #[must_use]
    pub const fn is_active(&self) -> bool {
        self.tenant.is_some()
    }
}

impl fmt::Debug for QuotaLease {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("QuotaLease")
            .field("active", &self.is_active())
            .finish()
    }
}

impl Drop for QuotaLease {
    fn drop(&mut self) {
        self.release();
    }
}

/// Content-safe quota gauges and cumulative admission counters.
#[derive(Clone, Eq, PartialEq)]
pub struct QuotaSnapshot {
    global_in_use: u32,
    tenant_in_use: BTreeMap<TenantId, u32>,
    admitted_total: u64,
    released_total: u64,
    global_rejected_total: u64,
    tenant_rejected_total: u64,
}

impl QuotaSnapshot {
    /// Returns current service-wide request concurrency.
    #[must_use]
    pub const fn global_in_use(&self) -> u32 {
        self.global_in_use
    }

    /// Returns current concurrency for one tenant.
    #[must_use]
    pub fn tenant_in_use(&self, tenant: &TenantId) -> u32 {
        self.tenant_in_use.get(tenant).copied().unwrap_or(0)
    }

    /// Returns total successful admissions.
    #[must_use]
    pub const fn admitted_total(&self) -> u64 {
        self.admitted_total
    }

    /// Returns total released leases.
    #[must_use]
    pub const fn released_total(&self) -> u64 {
        self.released_total
    }

    /// Returns total requests rejected by the global limit.
    #[must_use]
    pub const fn global_rejected_total(&self) -> u64 {
        self.global_rejected_total
    }

    /// Returns total requests rejected by a tenant limit.
    #[must_use]
    pub const fn tenant_rejected_total(&self) -> u64 {
        self.tenant_rejected_total
    }
}

impl fmt::Debug for QuotaSnapshot {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("QuotaSnapshot")
            .field("global_in_use", &self.global_in_use)
            .field("active_tenants", &self.tenant_in_use.len())
            .field("admitted_total", &self.admitted_total)
            .field("released_total", &self.released_total)
            .field("global_rejected_total", &self.global_rejected_total)
            .field("tenant_rejected_total", &self.tenant_rejected_total)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::{QuotaError, QuotaLimits, QuotaManager};
    use crate::context::TenantId;
    use std::sync::{Arc, Barrier};

    #[test]
    fn global_and_tenant_exhaustion_release_without_leaks() -> Result<(), Box<dyn std::error::Error>>
    {
        let manager = QuotaManager::new(QuotaLimits::new(2, 1)?);
        let tenant_a = TenantId::new("tenant-a")?;
        let tenant_b = TenantId::new("tenant-b")?;
        let tenant_c = TenantId::new("tenant-c")?;
        let lease_a = manager.acquire(&tenant_a)?;
        assert!(matches!(
            manager.acquire(&tenant_a),
            Err(QuotaError::TenantExhausted)
        ));
        let lease_b = manager.acquire(&tenant_b)?;
        assert!(matches!(
            manager.acquire(&tenant_c),
            Err(QuotaError::GlobalExhausted)
        ));
        drop(lease_a);
        drop(lease_b);
        let snapshot = manager.snapshot();
        assert_eq!(snapshot.global_in_use(), 0);
        assert_eq!(snapshot.tenant_in_use(&tenant_a), 0);
        assert_eq!(snapshot.admitted_total(), snapshot.released_total());
        assert_eq!(snapshot.tenant_rejected_total(), 1);
        assert_eq!(snapshot.global_rejected_total(), 1);
        Ok(())
    }

    #[test]
    fn concurrent_lease_drops_restore_all_capacity() -> Result<(), Box<dyn std::error::Error>> {
        const WORKERS: usize = 16;
        let manager = Arc::new(QuotaManager::new(QuotaLimits::new(16, 16)?));
        let tenant = Arc::new(TenantId::new("tenant-a")?);
        let barrier = Arc::new(Barrier::new(WORKERS));
        let mut handles = Vec::new();
        for _ in 0..WORKERS {
            let manager = Arc::clone(&manager);
            let tenant = Arc::clone(&tenant);
            let barrier = Arc::clone(&barrier);
            handles.push(std::thread::spawn(move || {
                let lease = manager.acquire(&tenant)?;
                barrier.wait();
                drop(lease);
                Ok::<(), QuotaError>(())
            }));
        }
        for handle in handles {
            handle.join().map_err(|_panic| "quota worker panicked")??;
        }
        let snapshot = manager.snapshot();
        assert_eq!(snapshot.global_in_use(), 0);
        assert_eq!(snapshot.admitted_total(), u64::try_from(WORKERS)?);
        assert_eq!(snapshot.released_total(), u64::try_from(WORKERS)?);
        Ok(())
    }
}
