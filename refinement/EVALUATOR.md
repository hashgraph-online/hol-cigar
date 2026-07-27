# Independent evaluator v2

`tools.refinement.evaluator` is the only v2 boundary that derives correctness, evidence-quality,
safety, and efficiency metrics. It receives a validated raw observation, hidden task/oracle,
optional structured claims and human adjudication, a digest-bound task environment, and an
external attestation key. The benchmark consumer never receives the oracle or evaluator key and
cannot set `success` or any derived KPI.

## Inputs and bindings

All JSON inputs must be strict canonical records. Duplicate keys, unknown fields, missing fields,
unbounded values, self-ID mismatches, unsafe paths, symlinks, substitutions, and inconsistent
cross-record IDs fail before an evaluation is emitted.

- `observation-v2.schema.json` supplies raw selection and execution facts. Its self-ID, retained
  artifacts, bundle/manifest relationships, selected block rows, and content digests are
  independently revalidated.
- `task-v1.schema.json` and its digest-bound `oracle-v1.schema.json` are loaded through separate
  evaluator-only paths. The caller must provide the expected oracle digest from an independently
  held manifest. Task ID, immutable source
  revision, fixture archive digest, and setup digest must match the observation and environment.
- `claims-v1.schema.json` is an optional versioned atomic-claim/citation format. It stores statement
  digests and evidence IDs, not answer text. It is self-identifying and bound to both observation
  and output digest. The expected whole-record digest is mandatory when claims are present.
- `adjudication-v1.schema.json` optionally records reviewer IDs and closed votes only. Every
  judgment covers the same sorted reviewer set; unrestricted reviewer notes or private text are
  not representable.
- `verifier-result-v1.schema.json` is the only accepted executable-postcondition output.

The task environment is inventoried as sorted safe paths, byte counts, content digests, and
executable bits. Its identity must equal `source.setup_digest`. Files are copied into a disposable
private root before verification. The verifier digest is separately pinned.

## Postcondition isolation

On the qualified macOS runner, the evaluator composes three layers:

1. a disposable, digest-checked copy of the task environment;
2. the repository bounded launcher, which limits CPU time, file descriptors, wall time, output,
   process descendants, and memory where the host supports it; and
3. a deny-default `sandbox-exec` profile that permits reads only from the copied task root,
   pinned Python runtime/system libraries, and bounded launcher; permits writes only inside the
   disposable root; and denies all network operations.

The child receives a credential-free environment and one canonical verifier input on stdin. It
must emit one canonical result and no stderr. Nonzero exit, timeout, output flood, descendant
leak, malformed result, unsorted checks, inconsistent aggregate status, or unavailable network
sandbox fails closed. Evaluation records pin the environment, verifier, interpreter, bounded
launcher, sandbox binary, and sandbox profile.

## Deterministic metrics

Every metric carries numerator, denominator, value, unit, applicability, and one or more source
attachment IDs. The evaluator emits all Tier 2 metrics:

- verified task success;
- critical-context recall;
- evidence-token and evidence-item precision;
- citation recall and precision;
- unsupported-claim rate;
- temporal, conflict, and abstention correctness;
- first-useful-evidence rank; and
- evidence sufficiency.

It also emits directly available Tier 1 checks and Tier 3 resource/phase facts. Inapplicable
metrics are explicitly marked and have zero numerator, denominator, and value. Verification
recomputes ratio/scalar arithmetic and rejects metrics that cite missing attachments. Human votes
produce an agreement metric but cannot override deterministic postconditions.

## Identity, custody, and replay

`evaluation_id` covers every evaluation field except itself and the MAC, including attestation-key
metadata. The HMAC-SHA-256 attestation covers the evaluation ID and all unsigned fields. Verification
recomputes the evaluation ID, attachment bindings, metric arithmetic, inventories, key fingerprint,
and MAC with constant-time comparison.

Attestation key files must be owner-only, single-link, regular, 32–128 byte files outside the Git
repository. Their fingerprint must differ from the assignment-seed digest. Promotion and release
evidence therefore require independently held key material; consumer-supplied attestations are
not accepted.

`evaluate` emits the canonical signed record. `replay` reruns the verifier and derivation and
requires byte-identical output. `verify` checks an existing record without rerunning task code.

```sh
python3 -m tools.refinement.evaluator evaluate \
  --observation /absolute/evidence/observation.json \
  --task /absolute/private/task.json \
  --oracle /absolute/private/oracle.json \
  --claims /absolute/evidence/claims.json \
  --task-environment /absolute/private/task-environment \
  --state /absolute/private/evaluator-state \
  --schemas /absolute/hol-cigar/schemas/refinement \
  --repository-root /absolute/hol-cigar \
  --key /absolute/private/evaluator.key \
  --key-id evaluator-2026q3 \
  --assignment-seed-digest 1220... \
  --expected-oracle-digest 1220... \
  --expected-verifier-digest 1220... \
  --expected-claims-digest 1220... \
  --evidence-class diagnostic
```
