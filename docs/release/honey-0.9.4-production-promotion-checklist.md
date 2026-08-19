# Honey 0.9.4 production-promotion checklist

| Field | Value |
| --- | --- |
| State | Dormant; not authorized for execution |
| Candidate | CIGAR Honey `0.9.4` |
| Promotion authority | None |
| Technical gate authority | `packaging/honey/balanced-0.9.4-release-contract.v1.json` |
| Activation owner | Release owner |

This is deliberately a residual checklist. It contains only approvals and external signing,
notarization, publication, and operational coordination. It is not a substitute for a build,
qualification, security review, artifact verification, or soak checklist. No item below may begin
while the activation guard is closed.

## Activation guard

The release owner may activate this checklist only after all of the following are true:

- the release contract names one immutable clean candidate commit and tree, sets
  `final_source_bound` to `true`, and records every mandatory technical gate as `pass`;
- the closed artifact manifest, checksums, SBOMs, provenance, license bindings, qualification
  ledger, risk register, and rollback runbook all identify the same source and artifact bytes;
- an independent reviewer has recomputed the claim ledger and verified every release-note claim;
- the 24-hour installed-runtime soak was run last and its exact report is present; and
- the release owner has confirmed that no source, dependency, fixture, tool, configuration,
  artifact, or evidence byte changed after its qualifying identity was recorded.

Until then, every checkbox in this document is blocked, Honey remains an unsupported developer
preview, and no production-support claim is permitted.

## External trust and signing ceremony

- [ ] The security owner approves the production signing identities, key purposes, scopes,
  activation/retirement windows, revocation status, custody procedure, and independently
  distributed trust-root bundle.
- [ ] Two authorized participants witness the signing ceremony and record the immutable candidate
  commit, tree, artifact-manifest digest, checksum-manifest digest, and evidence-ledger digest.
- [ ] The signing operator signs only the already qualified artifact bytes. No archive repacking,
  timestamp normalization, metadata rewrite, dependency resolution, or rebuild occurs during or
  after signing.
- [ ] A separate verifier validates every signature envelope against the approved trust policy and
  confirms that signer scope and purpose cover the exact artifact and release channel.
- [ ] The Apple notarization owner submits the exact signed Apple artifacts, records the request and
  acceptance receipts, staples where required, and proves that notarization did not change any
  qualified unsigned payload.
- [ ] The security owner confirms that signature and notarization receipts are attached to the
  release ledger and that the revocation/incident contacts can be reached.

## Publication and registry approvals

- [ ] The release owner approves the exact publication destinations, order, visibility, version,
  tag, and rollback/withdrawal policy; destinations outside that written approval remain forbidden.
- [ ] Each registry or distribution owner verifies the expected artifact filename, byte length,
  SHA-256, version, source revision, Context ABI, and signer before upload.
- [ ] Registry owners publish the approved bytes without rebuilding, dependency substitution,
  archive conversion, metadata mutation, or retagging.
- [ ] Each registry or distribution owner reads the published object back, verifies its digest and
  identity, and adds the immutable registry receipt or transparency-log identity to the release
  ledger.
- [ ] The release owner reconciles the published inventory against the closed artifact manifest and
  confirms that there are no missing, extra, replaced, or mutable attachments.

## Operational acceptance

- [ ] Runtime operations accepts the capacity assumptions, alert routing, on-call schedule,
  incident commander, escalation contacts, and maintenance window for the supported deployment
  scope.
- [ ] Support operations accepts the user-facing limitations, diagnostic collection boundary,
  known-issue routing, severity definitions, and response ownership.
- [ ] The rollback owner accepts the behavior rollback, binary rollback, restored-state isolation,
  effect reconciliation, stop conditions, and decision authority in the
  [Honey 0.9.4 upgrade and rollback guide](../guides/honey-0.9.4-upgrade.md).
- [ ] Security operations accepts the key-compromise, malicious-artifact, provenance-mismatch,
  policy-bypass, and secret-disclosure response paths and confirms revocation authority.
- [ ] The release owner confirms that dashboards, alerts, runbooks, support contacts, and rollback
  artifacts refer to the exact promoted candidate rather than a branch name or mutable URL.

## Final authorization

- [ ] The security, runtime, support, registry, and rollback owners record their approvals with
  identities and timestamps in the release ledger.
- [ ] The release owner reviews the final risk register, confirms that no technical gate is waived
  or merely deferred, and signs the promote-or-stop decision for the exact candidate.
- [ ] Only after that decision, the communications owner may change the stated support level or
  announce availability. The announcement must preserve the documented scope and known limits.

## Immediate stop and revocation rules

Stop promotion and return to technical qualification if any source or artifact byte changes, a
digest or signature disagrees, a receipt is missing, a registry mutates an upload, an approval is
withdrawn, or a release-note claim cannot be reproduced. Do not repair a promoted candidate in
place. Create a new candidate identity, rerun every affected gate, repeat the soak last, and restart
this checklist from the activation guard.

The broader verification model is documented in [release verification](verification.md),
[reproducibility and signing](reproducibility-signing.md), and the
[qualification gaps](qualification-gaps.md). The retained source review is documented in the
[Honey 0.9.4 manual review](honey-0.9.4-manual-review.md).
