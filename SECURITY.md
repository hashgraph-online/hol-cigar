# Security Policy

## Supported versions

Only an exact release whose authenticated release announcement explicitly marks it as supported is
eligible for security fixes. Development snapshots, unsigned artifacts, locally rebuilt packages,
and releases outside their announced support window are unsupported.

The `0.1.0-beta.1` profile is limited to local workspace-metadata administration. It is a
prerelease, is not production-ready, and must not be used to protect production secrets or
authorize external effects.

## Reporting a vulnerability

Use the private reporting channel named in the authenticated release announcement. Verify that
channel through the release publisher before sending sensitive information. If no private channel
is available, do not disclose vulnerability details in a public issue or discussion; contact the
publisher through a separately verified private organizational channel instead.

Do not include live credentials, private user data, or third-party exploit targets in a report.
Provide the exact version, artifact digest, operating environment, impact, and the smallest safe
reproduction needed for triage. Coordinated-disclosure timing is agreed privately for each report.
