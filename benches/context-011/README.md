# 0.10.1 qualification

Run on macOS with Rust 1.92.0, cached locked dependencies and a checkout of baseline
commit `11c38b0ba4fa00e1a03cad99ca316a875a03babd`:

```sh
python3 benches/context-011/qualify.py \
  --baseline /absolute/path/to/hol-cigar-0.10.0 \
  --cargo /absolute/path/to/rust-1.92/bin/cargo \
  --output /absolute/path/to/new-evidence-directory
```

The output directory must not exist. This compiles the same public-API probe against
both versions with the same registry package checksums, release optimization, one
codegen unit and thin LTO. No model, server or remote data is used. The frozen 0.10.0
input corpus is extended with 100 seeded graphs of 520–999 documents (four queries
each). Those exercise dense scoring, authorization, semantic leads, source replacement,
slot reuse, hard closure, invalid transactions and exact budgets. All original
1,034 requests remain present; 1,434 requests run with both versions and three cache
modes in opposite orders across two rounds.

The script rejects any mismatch in complete snapshots, expected error types or source
update results. Warm/cold/uncached timings exclude verification and explicit cache
clearing. The rotating workload has two warm-up cycles and ten measured cycles per
round. Source updates have 20 unchanged and 20 alternating one-document-change calls;
the first sample of each phase is excluded from timing summaries. Input cloning is
outside the source-update timer. Full snapshot compilation/verification follows each
update and is outside that timer. It is not an end-to-end ingestion/IPC measurement.

Raw inputs, outputs, stderr/RSS, dependency locks, binary/source digests and the summary
are retained under [`reports/evidence/context-011`](../../reports/evidence/context-011).
`manifest.json` binds every retained file. Cold/uncached differences include normal
same-host noise. Only two process-level rounds were run; the within-process samples
are correlated and are not independent trials for statistical significance claims.
The prompt view retains all evidence and reports exact aggregate token counts; it
does not measure model quality or compact metadata embedded inside source documents.
