# Qualification gaps

The machine-readable source of truth is
[`packaging/qualification-gaps.v1.json`](../../packaging/qualification-gaps.v1.json). This
development workspace has an initial commit, but the worktree is dirty and existing qualification
receipts are not bound to an exact clean candidate. Native platform and multi-architecture image
bytes are not all available, and production signing/publishing systems are external. Exact final-byte
vulnerability, malware-indicator, secret, and unexpected-endpoint scan receipts are also unavailable
until those artifacts exist. These are release-blocking gaps, not
waived checks. The eight required runbooks have only static validation in this workspace, and
installed-candidate/live documentation commands remain pending exact candidate bytes and isolated
drivers. The local SBOM is a deterministic locked-language inventory; final native, installer,
plugin-executable, extension, and OCI-layer reconciliation is also still required.

Local archive, metadata, documentation, SBOM, provenance, reproducibility, and signature-tamper tests
continue independently. A gap closes only when the exact candidate revision and distributed bytes
have digest-bound passing evidence; a source build or static runbook review cannot close installed-
artifact or live-operation qualification.
