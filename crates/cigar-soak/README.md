# CIGAR soak driver

`cigar-soak` is internal qualification tooling. The current safe slice creates strict,
deterministic reviewed plans and verifies result bindings and completeness offline. The daemon
workload driver intentionally returns a failure until isolation, fault injection, cancellation,
and receipt emission are implemented together; it never reports a placeholder soak as passing.

This crate remains outside the shared workspace member list while another agent finalizes the
repository. Integration is deferred to `docs/dashboard/integration-deferred.md`.
