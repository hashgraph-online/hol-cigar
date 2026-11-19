# Security Policy

## Supported versions

Only an exact release whose authenticated release announcement explicitly marks it as supported is
eligible for security fixes. Development snapshots, unsigned artifacts, locally rebuilt packages,
and releases outside their announced support window are unsupported.

Registry readback on 2026-11-08 identifies `hol-cigar==0.14.1` on PyPI and
`@hol-org/cigar@0.14.0` under npm's `latest` tag. GitHub release `v0.14.1` exists,
but npm does not yet contain `0.14.1`. The `0.14.2` branch is an unpublished
candidate; a stable version string does not establish publication or support.
Reports against published releases are accepted through the private channel below. Registry
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
