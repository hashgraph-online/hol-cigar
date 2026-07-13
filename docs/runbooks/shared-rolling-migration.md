# Shared rolling migration runbook

1. Verify and retain a restorable database/object backup and signed CIGAR inventory before any
   irreversible step. Confirm the previous and next application versions both declare compatibility
   with the currently installed migration sequence.
2. Run the next image's `cigard migrate --config /etc/cigar/cigard.toml` as the owner Job. Migrations
   are append-only and checksum-verified; a mismatch is a stop condition, not a repair prompt.
3. Run verification queries and semantic-hash comparison before changing application pods. Check
   lock wait/statement timeout metrics and outbox age.
4. Deploy one next-version canary with `maxUnavailable: 0`. Exercise every operation class,
   resumable streams, one idempotent mutation replay, handoff, observational replay, and effect
   reconciliation. Dispatch a real effect only through the controlled qualification connector.
5. Hold the canary through the adjacent-version compatibility window. Confirm old and new replicas
   read/write the same semantic roots and worker fenced claims never duplicate completion.
6. Roll remaining replicas one at a time. Keep the disruption budget, readiness gate, and graceful
   shutdown deadline enabled. Stop if readiness, queue age, serialization aborts, object errors, or
   unknown effects exceed the recorded baseline.
7. A binary rollback is permitted only while the installed schema remains in that binary's declared
   range. Schema rollback uses restore into a new database/bucket namespace and controlled traffic
   cutover; never delete migration ledger rows or reverse DDL in place.
