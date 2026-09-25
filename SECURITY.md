# Security Policy

## Supported versions

Only an exact release whose authenticated release announcement explicitly marks it as supported is
eligible for security fixes. Development snapshots, unsigned artifacts, locally rebuilt packages,
and releases outside their announced support window are unsupported.

The current Python local SDK release is `hol-cigar==0.12.0`; the npm registry
release remains `@hol-org/cigar@0.11.0` until separately published. Reports against
these releases are accepted through the private channel below. Registry
publication receipts and signed release announcements identify published artifacts.
No calendar support window or extended-maintenance commitment is implied here;
the publisher records those commitments in authenticated release announcements.
Other CIGAR/Honey product tracks retain their own release-specific support policy.

## Reporting a vulnerability

Use [GitHub private vulnerability reporting](https://github.com/hashgraph-online/hol-cigar/security/advisories/new).
This repository's private reporting feature was verified enabled on 2026-09-25.
If unavailable, contact the publisher through a separately verified private
organizational channel; do not post vulnerability details in a public issue.

Do not include live credentials, private user data, or third-party exploit targets in a report.
Provide the exact version, artifact digest, operating environment, impact, and the smallest safe
reproduction needed for triage. Coordinated-disclosure timing is agreed privately for each report.
