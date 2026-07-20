# Honey 0.9.1 v4 efficiency baseline evidence

Status: passed generated small baseline on 2026-07-20. This is the authenticated before side of the
v4/v5 comparison. It is candidate-bound-compatible, not falsely labeled as evidence from the future
0.9.1 candidate.

## Binding

| Item | Value |
|---|---|
| Base commit | `1ceea65e84fa59b3a4bff5027a0cced325cd2310` |
| Worktree source-set SHA-256 | `9c304d05962bbbadd969a11c22c349e765cebdef388e33e9ac8551bf7e9b5f61` |
| Baseline-manifest SHA-256 | `4a1eaf667a5be7be0fa06a5ff0cb67781aed05352ab6e96d480977077c35d572` |
| Raw-observations SHA-256 | `58ffcef3d99d9a4e84357f05c8e18c74765d800a08df8b369bb629af39bdc480` |
| Summary SHA-256 | `d2dd2fbab5055edca21cdfbc7a236b366c499b6396f2064ef36df36cc72635b6` |
| Evidence modes | directory `0700`; each report `0400` |
| Persistence format | `sqlite-v4-full-residual` |

The raw observations and summary remain separate owner-only external files. They are deliberately
not copied into the repository or release payload. `honey_efficiency.py verify` authenticated the
three-file inventory and every cross-file digest.

## Frozen generated-small result

| Measurement | Observed |
|---|---:|
| Initial records | 8 |
| Serial mutations | 48 (12 iterations x 4) |
| Successful commits | 48/48 |
| Full snapshot encoded | 48/48 |
| Delta/checkpoint bytes | 0/0 |
| Mean full-state bytes per mutation | 2,947 |
| Durable bytes added per mutation | 12,360 |
| Logical bytes changed per mutation | 118 |
| Write amplification | 104.745762x |
| WAL growth | 593,280 bytes |
| Main database growth while WAL open | 0 bytes |
| Latest full snapshot growth | 53 bytes |
| Mean total commit latency | 9,637,152 ns |
| p95 total commit latency | 10,567,834 ns |
| Mean revision-anchor publication | 9,154,939 ns |

The report separately attributes lock wait, repository load, residual decode, staged mutation,
delta encode, full encode, catalog-root update, SQLite transaction, commit/fsync, revision-anchor
publication, total commit time, and authenticated startup stages. Size observations include both the
main database and live WAL. The harness never issues `VACUUM` and never deletes live rows.

## Interpretation and use

This smoke cohort proves the current implementation writes a complete residual state for every
small logical worker mutation and records measurable durable amplification. It does not estimate the
Hiero store's absolute production latency or 50 GB behavior. H91-630 must run the frozen larger
cohorts against an exact candidate and compare them to this format using the same stage names,
definitions, and canonical evidence rules.
