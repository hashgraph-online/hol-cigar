# H094-600 reliability qualification

This directory owns the fail-closed production-path reliability evidence for CIGAR 0.9.4.
`configuration.v1.json` pre-registers all scale points, bounded compilation concurrency, fault
classes, the exact 24-hour duration, sampling cadence, and the zero-growth memory rule.

The retained-record runner uses the real SQLite v4 catalog, encrypted blob repository, projection
rebuild, checkpoint recovery, process reopen, signed backup, and restore path. It records explicit
cold-start, steady-state, restart, and warm-start durations. Its report and nested Rust receipts are
content-free, source/binary/configuration bound, create-new, and owner-read-only. The independent
verifier recomputes identities and invokes the bound Rust verifier; it never trusts the aggregate
pass flag alone.

Run the five registered scale points with a debug qualification driver (fixture commands are absent
from release builds), then independently verify them:

```sh
python3 benches/reliability/reliability.py \
  --driver /absolute/path/to/cigar-local-scale-driver \
  --candidate /absolute/path/to/cigard \
  --out /absolute/owner-private/new-evidence-directory
python3 benches/reliability/verify.py \
  --report /absolute/evidence/retained-record-report.json \
  --driver /absolute/path/to/cigar-local-scale-driver
```

Passing fixture evidence proves the registered retained-record lifecycle contract. It does not
claim that the immutable `large_local` 100-GiB blob profile or the 24-hour soak ran; those have
separate receipts and cannot be inferred from this report.

`installed_soak.py` composes immutable installed CLI/daemon qualification with real retained-state,
full/delta compiler, effect-fencing, replay, handoff/checkpoint, and signed-GC cycles. The RC profile
runs for exactly 24 hours and streams content-free resource/counter samples every ten seconds.
`verify_installed_soak.py` independently rebuilds every aggregate, checks sample gaps and post-warmup
RSS slope, requires the sample series to begin within one registered sampling interval and end with
the exact final cycle counters, re-hashes all artifacts, and invokes the bound Rust `cigar-soak`
verifier. JSON evidence rejects duplicate fields and non-finite numbers; the evidence and cycle
directories must remain canonical, owner-private, and free of symlink substitution. Qualifier
scratch uses a short digest-derived sandbox child, and the runner requires a sandbox root of at most
40 filesystem bytes, so macOS Unix-domain sockets remain within the platform path limit. The
120-second smoke profile permits at most 1 MiB/hour of page-granularity RSS noise; the 24-hour RC
profile retains the strict non-positive post-warmup slope gate.
