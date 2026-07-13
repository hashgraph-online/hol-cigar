# Performance tuning

Tune only after correctness gates pass. Record workload stratum, hardware, toolchain, artifact digest,
dataset digest, warmup, samples, confidence intervals, and raw event output. Compare against the
pinned baseline using the same installed artifact and environment.

For local mode, inspect atom counts, index watermark, cache hit/miss, compilation budget, and storage
latency. For shared mode, keep aggregate replica connection limits below the database budget, reserve
operator/migration/backup capacity, and observe pool wait, queue age, outbox age, object latency,
worker heartbeat, index lag, and unknown effects.

Do not improve a benchmark by weakening policy, tenant isolation, durability, canonicalization,
effect ordering, replay no-egress, integrity checks, or evidence retention. A faster semantically
different result is a regression.
