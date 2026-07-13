# Qualification artifact policy

The remaining `wp18-*` JSON and log files in this directory are retained historical development
evidence. They document the local WP18 exercises that produced them; they are not current,
source-bound, or release-candidate qualification evidence.

All newly generated qualification receipts, raw logs, attachments, crash artifacts, and related
outputs must be written outside the repository under `${CIGAR_EVIDENCE_DIR}`. A release process may
refer to those files by stable logical paths such as `${CIGAR_EVIDENCE_DIR}/wp21-local-readiness.json`,
but it must not copy generated receipts back into this directory. Candidate qualification is valid
only when the external evidence explicitly binds the exact clean source revision and distributed
artifact digests required by the relevant gate.
