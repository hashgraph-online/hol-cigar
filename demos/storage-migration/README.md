# Generated storage-migration demo

This source POC runs the real v4-to-v5 store workflow twice from clean temporary state. Each run
creates 1,028 deterministic v4 revisions, creates and verifies a separate signed backup, constructs
and activates a distinct v5 target, compacts it to 256 retained revisions, reopens it through the
bounded readiness verifier, and exercises full, prefix-reused, tamper-rejected, and forced deep
integrity checks. The source and backup remain untouched.

It is credential-free, network-free, generated-state evidence. It is not installed-candidate
evidence; that remains a separate Honey qualification gate.

<!-- docs-check: illustrative -->
```sh
python3 demos/storage-migration/run.py \
  --output /private/tmp/cigar-storage-migration-demo.json
```
