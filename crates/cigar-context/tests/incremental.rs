//! Incremental source transactions and bounded exact-token cache regressions.
use cigar_context::{
    CachedTokenCounter, ContextError, ContextGraph, ContextRequest, Document, EdgeKind,
    GraphLimits, TokenCacheLimits, TokenCounter, Utf8ByteCounter,
};
use std::sync::atomic::{AtomicUsize, Ordering};

struct ObservedCounter(AtomicUsize);
impl TokenCounter for ObservedCounter {
    fn identity(&self) -> &str {
        "observed.bytes.v1"
    }
    fn count(&self, text: &str) -> Result<usize, ContextError> {
        self.0.fetch_add(1, Ordering::Relaxed);
        if text == "error" {
            Err(ContextError::Tokenizer)
        } else {
            Ok(text.len())
        }
    }
}

#[test]
fn clearing_during_a_miss_cannot_restore_retired_text() -> Result<(), ContextError> {
    use std::sync::{Arc, Barrier};
    struct BlockingCounter {
        started: Arc<Barrier>,
        release: Arc<Barrier>,
    }
    impl TokenCounter for BlockingCounter {
        fn identity(&self) -> &str {
            "blocking.bytes.v1"
        }
        fn count(&self, text: &str) -> Result<usize, ContextError> {
            self.started.wait();
            self.release.wait();
            Ok(text.len())
        }
    }
    let started = Arc::new(Barrier::new(2));
    let release = Arc::new(Barrier::new(2));
    let cache = CachedTokenCounter::new(
        BlockingCounter {
            started: Arc::clone(&started),
            release: Arc::clone(&release),
        },
        TokenCacheLimits::default(),
    );
    std::thread::scope(|scope| {
        scope.spawn(|| assert_eq!(cache.count("retired-text"), Ok(12)));
        started.wait();
        let cleared = cache.clear_cache();
        release.wait();
        cleared
    })?;
    assert_eq!(cache.cache_stats()?, Default::default());
    Ok(())
}

#[test]
fn exact_cache_is_bounded_evictable_and_never_caches_errors() -> Result<(), ContextError> {
    let cache = CachedTokenCounter::new(
        ObservedCounter(AtomicUsize::new(0)),
        TokenCacheLimits {
            max_entries: 2,
            max_text_bytes: 8,
        },
    );
    for text in [
        "abc",
        "abc",
        "defg",
        "x",
        "defg",
        "0123456789",
        "0123456789",
    ] {
        assert_eq!(cache.count(text)?, text.len());
        let stats = cache.cache_stats()?;
        assert!(stats.entries <= 2 && stats.text_bytes <= 8);
    }
    assert_eq!(cache.cache_stats()?.hits, 2);
    assert_eq!(cache.cache_stats()?.misses, 5);
    assert_eq!(cache.count("error"), Err(ContextError::Tokenizer));
    assert_eq!(cache.count("error"), Err(ContextError::Tokenizer));
    assert_eq!(cache.cache_stats()?.misses, 7);
    cache.clear_cache()?;
    assert_eq!(cache.cache_stats()?, Default::default());
    assert_eq!(cache.identity(), "observed.bytes.v1");
    Ok(())
}

#[test]
fn cache_concurrency_and_disable_preserve_exact_results() -> Result<(), ContextError> {
    let cache = CachedTokenCounter::new(
        Utf8ByteCounter,
        TokenCacheLimits {
            max_entries: 16,
            max_text_bytes: 256,
        },
    );
    std::thread::scope(|scope| {
        for worker in 0..8 {
            let cache = &cache;
            scope.spawn(move || {
                for iteration in 0..1000 {
                    let text = format!("é😀-{worker}-{}", iteration % 32);
                    assert_eq!(cache.count(&text), Ok(text.len()));
                }
            });
        }
    });
    let stats = cache.cache_stats()?;
    assert!(stats.entries <= 16 && stats.text_bytes <= 256);
    let disabled = CachedTokenCounter::new(
        Utf8ByteCounter,
        TokenCacheLimits {
            max_entries: 0,
            max_text_bytes: 1024,
        },
    );
    for _ in 0..3 {
        assert_eq!(disabled.count("same"), Ok(4));
    }
    assert_eq!(disabled.cache_stats()?.entries, 0);
    assert_eq!(disabled.cache_stats()?.misses, 3);
    Ok(())
}

#[test]
fn source_replacement_is_atomic_and_withdraws_obsolete_chunks() -> Result<(), ContextError> {
    let mut graph = ContextGraph::new("project", GraphLimits::default())?;
    let source = Document::new("file", "src/file.rs", "alpha\nbeta\ngamma\ndelta\n");
    let chunks = source.chunks(2, 0)?;
    let first = graph.replace_source(&source.source, chunks.clone())?;
    assert_eq!((first.inserted, first.revision, graph.len()), (2, 1, 2));
    let noop = graph.replace_source(&source.source, chunks)?;
    assert_eq!((noop.unchanged, noop.revision), (2, 1));
    graph.upsert(Document::new("contract", "spec", "contract"))?;
    graph.link("contract", "file:L3", EdgeKind::Requires)?;
    let request = ContextRequest {
        query: "contract".into(),
        required: ["contract".into()].into(),
        ..Default::default()
    };
    graph.compile(&request, &Utf8ByteCounter)?;
    let before = graph.revision();
    let update = graph.replace_source(
        "src/file.rs",
        vec![Document::new("file:L1", "src/file.rs", "alpha CHANGED\n")],
    )?;
    assert_eq!(
        (update.replaced, update.removed, update.revision),
        (1, 1, before + 1)
    );
    assert_eq!(
        graph.compile(&request, &Utf8ByteCounter).err(),
        Some(ContextError::RequiredUnavailable)
    );
    let clean = graph.compile(
        &ContextRequest {
            query: "alpha gamma".into(),
            ..Default::default()
        },
        &Utf8ByteCounter,
    )?;
    assert!(clean.render().contains("CHANGED"));
    assert!(!clean.render().contains("gamma"));
    let revision = graph.revision();
    for input in [
        vec![Document::new("contract", "src/file.rs", "collision")],
        vec![Document::new("bad", "wrong", "text")],
        vec![
            Document::new("duplicate", "src/file.rs", "one"),
            Document::new("duplicate", "src/file.rs", "two"),
        ],
        vec![
            Document::new("ok", "src/file.rs", "text"),
            Document::new("bad", "src/file.rs", " "),
        ],
    ] {
        assert_eq!(
            graph.replace_source("src/file.rs", input),
            Err(ContextError::InvalidInput)
        );
        assert_eq!(graph.revision(), revision);
        assert_eq!(
            graph.compile(
                &ContextRequest {
                    query: "alpha gamma".into(),
                    ..Default::default()
                },
                &Utf8ByteCounter
            )?,
            clean
        );
    }
    assert_eq!(graph.replace_source("src/file.rs", vec![])?.removed, 1);
    assert_eq!(graph.len(), 1);
    Ok(())
}

#[test]
fn source_replacement_checks_final_capacity_not_transient_capacity() -> Result<(), ContextError> {
    let limits = GraphLimits {
        max_documents: 2,
        max_total_bytes: 8,
        ..Default::default()
    };
    let mut graph = ContextGraph::new("bounded", limits)?;
    graph.upsert(Document::new("one", "source", "1234"))?;
    graph.upsert(Document::new("two", "other", "5678"))?;
    assert_eq!(
        graph
            .replace_source("source", vec![Document::new("new", "source", "abcd")])?
            .removed,
        1
    );
    let revision = graph.revision();
    assert_eq!(
        graph.replace_source("source", vec![Document::new("too-big", "source", "abcde")]),
        Err(ContextError::LimitExceeded)
    );
    assert_eq!(graph.revision(), revision);
    graph.upsert(Document::new("new", "moved", "abcd"))?;
    assert_eq!(graph.replace_source("source", vec![])?.removed, 0);
    assert_eq!(graph.replace_source("moved", vec![])?.removed, 1);
    graph.upsert(Document::new("third", "source", "four"))?;
    assert_eq!(graph.len(), 2);
    Ok(())
}

#[cfg(feature = "bpe")]
#[test]
fn cached_and_uncached_bpe_match_across_updates_and_access_changes() -> Result<(), ContextError> {
    use cigar_context::O200kTokenizer;
    let cached = O200kTokenizer::new()?;
    let raw = O200kTokenizer::with_cache_limits(TokenCacheLimits {
        max_entries: 0,
        max_text_bytes: 0,
    })?;
    let mut graph = ContextGraph::new("local", GraphLimits::default())?;
    for id in 0..64 {
        graph.upsert(Document::new(
            format!("n{id}"),
            format!("src/{id}"),
            format!("fn item_{id}() {{ /* boundary é😀 <|endoftext|> */ }}"),
        ))?;
    }
    for cycle in 0..32 {
        let request = ContextRequest {
            query: format!("item_{} boundary", cycle % 8),
            max_tokens: 64 + cycle * 7,
            allowed: (cycle % 2 == 0).then(|| (0..32).map(|id| format!("n{id}")).collect()),
            ..Default::default()
        };
        assert_eq!(
            graph.compile(&request, &cached)?,
            graph.compile(&request, &raw)?
        );
        graph.upsert(Document::new(
            "n0",
            "src/0",
            format!("item_0 UPDATED {cycle}"),
        ))?;
    }
    assert!(cached.cache_stats()?.hits > 0);
    cached.clear_cache()?;
    assert_eq!(cached.cache_stats()?.entries, 0);
    Ok(())
}
