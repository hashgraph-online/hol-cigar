# Index rebuild

## Preconditions

Quiesce schema migrations, record the authoritative repository revision and semantic roots, and
verify a recent backup. Indexes and projections are disposable; metadata and journals are not.

## Exercise

1. Create a new empty index generation without deleting the active one.
2. Rebuild from durable tenant-scoped state using bounded batches and cancellation.
3. Verify exact atom counts, deterministic lookup probes, tenant isolation, and index watermark.
4. Require the watermark to equal a committed metadata sequence and never exceed it.
5. Atomically switch readers, retain the old generation through the rollback window, and run
   retrieval plus compilation differentials.

## Stop conditions and rollback

Stop on count drift, cross-tenant results, checksum failure, a future watermark, or semantic output
drift. Switch readers back to the retained generation; do not edit authoritative metadata to match a
bad index. Evidence contains only counts, revisions, digests, duration, and bounded error classes.
