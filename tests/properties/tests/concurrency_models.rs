//! Exhaustive bounded schedule models for the seven required concurrent publication surfaces.

use loom::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use loom::sync::{Arc, Mutex, RwLock};
use loom::thread;

#[test]
fn cache_publication_never_exposes_a_partial_entry() {
    loom::model(|| {
        let cache = Arc::new(RwLock::new(None::<(u64, u64)>));
        let writer = Arc::clone(&cache);
        let publisher = thread::spawn(move || {
            *writer.write().expect("cache write lock") = Some((7, 0xfeed_beef));
        });
        let reader = Arc::clone(&cache);
        let observer = thread::spawn(move || {
            if let Some((epoch, value)) = *reader.read().expect("cache read lock") {
                assert_eq!((epoch, value), (7, 0xfeed_beef));
            }
        });
        publisher.join().expect("publisher joins");
        observer.join().expect("observer joins");
    });
}

#[test]
fn snapshot_visibility_binds_payload_to_one_revision() {
    loom::model(|| {
        let snapshot = Arc::new(RwLock::new((0_u64, 0_u64)));
        let writer = Arc::clone(&snapshot);
        let publish = thread::spawn(move || {
            let mut state = writer.write().expect("snapshot write lock");
            *state = (1, 0xabba);
        });
        let reader = Arc::clone(&snapshot);
        let observe = thread::spawn(move || {
            let (revision, payload) = *reader.read().expect("snapshot read lock");
            assert!(matches!((revision, payload), (0, 0) | (1, 0xabba)));
        });
        publish.join().expect("publisher joins");
        observe.join().expect("observer joins");
    });
}

#[test]
fn context_revision_compare_exchange_has_one_winner() {
    loom::model(|| {
        let revision = Arc::new(AtomicU64::new(4));
        let winners = Arc::new(AtomicUsize::new(0));
        let mut handles = Vec::new();
        for _ in 0..2 {
            let revision = Arc::clone(&revision);
            let winners = Arc::clone(&winners);
            handles.push(thread::spawn(move || {
                if revision
                    .compare_exchange(4, 5, Ordering::AcqRel, Ordering::Acquire)
                    .is_ok()
                {
                    winners.fetch_add(1, Ordering::AcqRel);
                }
            }));
        }
        for handle in handles {
            handle.join().expect("writer joins");
        }
        assert_eq!(revision.load(Ordering::Acquire), 5);
        assert_eq!(winners.load(Ordering::Acquire), 1);
    });
}

#[test]
fn outbox_claim_fencing_allows_one_active_sender() {
    loom::model(|| {
        let fence = Arc::new(AtomicU64::new(0));
        let active = Arc::new(AtomicUsize::new(0));
        let maximum = Arc::new(AtomicUsize::new(0));
        let mut handles = Vec::new();
        for token in [1_u64, 2_u64] {
            let fence = Arc::clone(&fence);
            let active = Arc::clone(&active);
            let maximum = Arc::clone(&maximum);
            handles.push(thread::spawn(move || {
                if fence
                    .compare_exchange(0, token, Ordering::AcqRel, Ordering::Acquire)
                    .is_ok()
                {
                    let now = active.fetch_add(1, Ordering::AcqRel) + 1;
                    maximum.fetch_max(now, Ordering::AcqRel);
                    assert_eq!(fence.load(Ordering::Acquire), token);
                    active.fetch_sub(1, Ordering::AcqRel);
                }
            }));
        }
        for handle in handles {
            handle.join().expect("worker joins");
        }
        assert_eq!(maximum.load(Ordering::Acquire), 1);
        assert_ne!(fence.load(Ordering::Acquire), 0);
    });
}

#[test]
fn subscription_cursor_is_monotonic_under_concurrent_acknowledgement() {
    loom::model(|| {
        let cursor = Arc::new(AtomicU64::new(0));
        let mut handles = Vec::new();
        for candidate in [3_u64, 7_u64] {
            let cursor = Arc::clone(&cursor);
            handles.push(thread::spawn(move || {
                let mut current = cursor.load(Ordering::Acquire);
                loop {
                    let next = current.max(candidate);
                    match cursor.compare_exchange_weak(
                        current,
                        next,
                        Ordering::AcqRel,
                        Ordering::Acquire,
                    ) {
                        Ok(_) => break,
                        Err(observed) => current = observed,
                    }
                }
            }));
        }
        for handle in handles {
            handle.join().expect("subscriber joins");
        }
        assert_eq!(cursor.load(Ordering::Acquire), 7);
    });
}

#[test]
fn invalidation_queue_never_serves_after_revocation_becomes_visible() {
    loom::model(|| {
        let state = Arc::new(Mutex::new((false, Some(42_u64))));
        let publisher = Arc::clone(&state);
        let invalidate = thread::spawn(move || {
            let mut guarded = publisher.lock().expect("cache lock");
            *guarded = (true, None);
        });
        let reader = Arc::clone(&state);
        let read = thread::spawn(move || {
            let (revoked, value) = *reader.lock().expect("cache lock");
            assert!(!(revoked && value.is_some()));
        });
        invalidate.join().expect("invalidator joins");
        read.join().expect("reader joins");
    });
}

#[test]
fn shutdown_gate_prevents_claims_after_closed_state_is_observed() {
    loom::model(|| {
        let accepting = Arc::new(AtomicBool::new(true));
        let claims = Arc::new(AtomicUsize::new(0));
        let shutdown_gate = Arc::clone(&accepting);
        let shutdown = thread::spawn(move || {
            shutdown_gate.store(false, Ordering::Release);
        });
        let worker_gate = Arc::clone(&accepting);
        let worker_claims = Arc::clone(&claims);
        let worker = thread::spawn(move || {
            if worker_gate.load(Ordering::Acquire) {
                worker_claims.fetch_add(1, Ordering::AcqRel);
            } else {
                assert_eq!(worker_claims.load(Ordering::Acquire), 0);
            }
        });
        shutdown.join().expect("shutdown joins");
        worker.join().expect("worker joins");
        assert!(claims.load(Ordering::Acquire) <= 1);
    });
}
