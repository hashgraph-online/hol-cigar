# Repository tools

Release and fixture helper assets live here. Authoritative executable build logic remains in `crates/xtask`.

`qualify-shared-profile.sh` renders the checked-in shared Compose and Kubernetes profiles, starts
fresh PostgreSQL and S3-compatible development dependencies, and runs the live WP18 PostgreSQL,
object-CAS, and deployment-asset acceptance suites. It deletes the isolated Compose project and
volumes on exit; set `CIGAR_KEEP_SHARED_TEST_DEPS=1` only while debugging locally. Every run
requires live tests (silent environment-based skips are rejected) and atomically writes a result
receipt plus redacted command log under `artifacts/qualification/`.
