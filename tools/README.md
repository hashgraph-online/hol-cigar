# Repository tools

Release and fixture helper assets live here. Authoritative executable build logic remains in `crates/xtask`.

`qualify-shared-profile.sh` renders the checked-in shared Compose and Kubernetes profiles, starts
fresh PostgreSQL and S3-compatible development dependencies, and runs the live WP18 PostgreSQL,
object-CAS, and deployment-asset acceptance suites. It deletes the isolated Compose project and
volumes on exit; set `CIGAR_KEEP_SHARED_TEST_DEPS=1` only while debugging locally. Every run
requires live tests (silent environment-based skips are rejected). `qualify-shared-scale.sh`
applies the same evidence contract to the exact 10,000,000-row production projection gate.

Live shared-profile, shared-scale, and physical-failover runs require a new absolute
`CIGAR_EVIDENCE_DIR` outside the repository. The directory may be absent (the broker creates it
with mode `0700`) or must already be an empty, owner-owned `0700` directory:

```sh
export CIGAR_EVIDENCE_DIR=/private/tmp/cigar-wp18-shared-profile-evidence
tools/qualify-shared-profile.sh
```

Use a different empty directory for each run. `qualification_evidence.py` holds the opened
directory identity for the complete worker lifetime, removes `CIGAR_EVIDENCE_DIR` before any
Cargo, Docker, or kubectl child starts, and closes the parent shell's terminal-state descriptor at
every external-command and cleanup boundary so descendants cannot forge or hold open the final
state. It rejects relative, non-canonical, in-repository, nonempty, symlinked, colliding, or rebound
roots. It captures the Git worktree before and after the worker and cannot publish `pass` if the
fingerprint changes. Publication creates exactly one bounded `0400` log and one create-new canonical
`0400` JSON receipt; the receipt binds the log's SHA-256 and byte count. No live driver writes
generated evidence under `artifacts/qualification/`.

`tools/wp18-failover/qualify.sh --syntax-only` deliberately performs no evidence setup and does
not require `CIGAR_EVIDENCE_DIR`.
