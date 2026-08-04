# Honey 0.9.2 focused correction gate

This local-only harness compares the published Honey 0.9.1 source with one exact corrected 0.9.2
source. It uses the same bounded worker-state workload on v4 and v5 and records physical growth at
100 and 1,000 mutations, per-mutation latency, and a 40-revision process-cold/filesystem-warm
startup sweep. Both treatments use the same local encrypted blob-store composition. The
adjacent-revision sweep covers multiple complete maximum checkpoint-suffix cycles, and 40 samples
prevent a single operating-system scheduling or filesystem outlier from being mislabeled p95.

It also executes the candidate's crash-boundary recovery, migration, backup/restore, and semantic
reuse tests. A frozen 25-case Hiero result is supplied separately so context quality and system
performance cannot conceal one another.

The evaluator is intentionally conservative: a candidate must improve storage by at least 10%, may
not regress storage by more than 5%, and may not regress mutation or restart p50 or p95 latency by
more than 20%. These are developer-preview correction thresholds, not production SLOs.

The command creates a new owner-private evidence directory and never publishes, tags, pushes, or
modifies the public repository.
