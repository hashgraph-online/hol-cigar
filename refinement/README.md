# CIGAR refinement control plane

This directory contains immutable configuration and public development inputs for the bounded
refinement system. Mutable trials, private corpora, model credentials, raw evaluation output, and
the append-only ledger live in owner-private evidence workspaces outside the Git checkout.

## Evidence classes

Evidence classes are ordered by authority, not by how favorable their metrics look:

| Class | Permitted use | Explicit limitation |
| --- | --- | --- |
| `diagnostic` | Unit tests, adapter replay, smoke tasks, and local debugging | Cannot promote a champion or support a product claim |
| `development` | Public-corpus experiments and candidate triage | Can select what to test next; cannot authorize promotion |
| `shadow` | Blinded validation with independently held tasks | Can nominate a promotion candidate; task-level details stay hidden |
| `promotion` | One declared sealed epoch with independent evaluator and policy | Can change the development champion only after every hard gate passes |
| `release` | Installed artifacts, complete comparator matrix, durability, signatures, and release authority | Required for public release claims and never implied by development promotion |

An artifact never gains authority by being copied into a higher-class directory. Its record must
bind the exact source, installed bytes, corpus epoch, evaluator, model/runtime, policy, command,
and attachments required by that class.

## Machine contracts

The closed JSON schemas are in `schemas/refinement`. JSON is UTF-8, duplicate-key rejecting,
finite-number-only, bounded, and canonicalized with sorted keys and compact separators. A SHA-256
multihash is `1220` followed by 64 lowercase hexadecimal characters.

Configuration is strict TOML. Unknown or missing fields fail. Environment interpolation is
forbidden. A credential is represented only by a bounded uppercase `credential_handle`; resolving
that handle is an explicit runtime action and credential bytes are never serialized.

Ledger entries are canonical, content-addressed, immutable `0400` files named by a contiguous
20-digit sequence. Each entry binds the previous entry ID. Replay verifies the complete inventory,
schema, sequence, previous link, and content identity. There is no mutable head file.

## Benchmark observation boundary

Qualification uses `cigar.benchmark-observation.v2`, not the v1 self-scored metrics event. A v2
consumer receives only a source-bound assignment and authorized fixture archive; hidden oracles,
expected answers, prohibited-evidence labels, and evaluator keys never cross the consumer
boundary. The production Rust consumer records selections, authorized dispositions, provenance,
tokens, typed operation hashes, semantic pins, retained reproduction artifacts, timing, resource
availability, and optional governed-flow facts.

`tools.refinement.consumer` performs the bounded champion/candidate launch and independently
validates assignment, executable, observation, and retained-artifact bindings. It does not derive
outcome KPIs. `tools/refinement/evaluator.py` is the sole v2 metric derivation boundary. The legacy
CIGARBench v1 inputs and analyzer remain unchanged and are never reinterpreted as v2 qualification
evidence.

The evaluator boundary, structured claim/citation protocol, disposable no-network verifier,
metric arithmetic, independent key custody, attestation, and exact replay contracts are documented
in [EVALUATOR.md](EVALUATOR.md).

The public development corpus, opaque shadow/sealed manifests, annotation workflow, integrity
checks, deterministic setup smoke, and executable baseline/retrieval-proxy/oracle selectors are
documented in [corpus/README.md](corpus/README.md).

Paired clustered bootstrap, Holm correction, Honey/champion non-inferiority, protected-stratum
overrides, performance limits, deterministic decisions, and the external Pareto research archive
are documented in [PROMOTION.md](PROMOTION.md).

Workflow trust boundaries, external quotas, immutable transport bundles, read-only dashboard
projections, environment separation, and incident/rollback procedures are documented in
[OPERATIONS.md](OPERATIONS.md).

The reviewed opportunity-mining cycle, hosted/local model adapter boundary, and exact retained
candidate-to-draft-PR bridge are documented in
[CONTINUOUS_REFINEMENT.md](CONTINUOUS_REFINEMENT.md).

## Honey 0.9.2 refinement authority

`profiles/honey-0.9.2-refinement-profile.v1.json` is the scoped authority for the next private
Honey build. It freezes published Honey 0.9.1 and Shadow champion `d079c145`, the context ABI,
public v1 protocol counts, promotion thresholds, allowed CIGAR components, deferred HUMIDOR/CEDAR
responsibilities, three bounded cycles, and all human breakpoints.

`cohorts/honey-0.9.2-three-way.v1.json` freezes the identical three-treatment evaluation inputs:
the 270-task CIGARBench development manifest, Honey efficiency fixtures, exact HUMIDOR and CEDAR
sources, six synthetic workflows, adversarial scenario coverage, five source/installed lanes, and
three fresh-root reliability runs. Validate the authority without producing evidence:

```sh
python3 -m tools.refinement.honey_refinement validate \
  --repository-root "$PWD" \
  --core-root /absolute/path/to/HUMIDOR/Core \
  --cedar-root /absolute/path/to/HUMIDOR/Cedar
```

Cycle A may change only the measurement controls named by the validator. After committing a clean
isolated `refine/honey-0.9.2-*` branch, create one immutable external execution plan with the
`plan` subcommand. The plan contains all 15 Honey/champion/candidate by kernel/sidecar/HUMIDOR
cells and carries test authority only; it cannot edit product code, create a pull request, merge,
release, publish, or push to the public repository.

```sh
python3 -m tools.refinement.honey_refinement plan \
  --repository-root "$PWD" \
  --core-root /absolute/path/to/HUMIDOR/Core \
  --cedar-root /absolute/path/to/HUMIDOR/Cedar \
  --candidate-revision HEAD \
  --cycle cycle-a \
  --output /absolute/private/cycle-a/evaluation-plan.v1.json
```

The `build` subcommand then prepares detached worktrees for all three exact product sources and
compiles one common, plan-bound CIGARBench adapter against each source's production crates. Cycle
A uses its candidate harness and permits only frozen `balanced.v1`. The build runs offline with a
generated retained lockfile,
requires clean sources after every build, and emits a content-addressed build-set receipt binding
the source, adapter manifest, lockfile, toolchain, and executable bytes:

```sh
python3 -m tools.refinement.honey_refinement build \
  --repository-root "$PWD" \
  --plan /absolute/private/cycle-a/evaluation-plan.v1.json \
  --output-root /absolute/private/cycle-a/source-builds
```

The build set is development evidence only. It does not infer the published Honey treatment from
the champion and carries no repository or release authority.

Cycle B reuses the plan and build-custody envelope but requires a named isolated H1 qualification.
The Cycle B plan binds current private main as its champion and freezes that champion's measurement
harness for Honey, champion, and candidate alike. Their dependencies still come from their
respective exact product sources. Honey remains `balanced.v1`; champion and candidate use the H1
profile. Profile qualification
then consumes the three receipted executables and separately authenticated Tier-1 gate receipts.
No legacy aggregate status attachment or unbound consumer path can produce authoritative
evidence.

Run the first source-bound Cycle A baseline with at least two tasks per protected stratum and two
assignment seeds. The controller randomizes treatment order, evaluates every observation behind
the oracle boundary, retains the three-way runs and signed evaluations, and feeds the actual
Honey/champion/candidate metrics into the existing clustered-bootstrap statistics engine:

```sh
python3 -m tools.refinement.three_way \
  --repository-root "$PWD" \
  --private-root "$PWD" \
  --manifest "$PWD/refinement/corpus/development-manifest-v1.json" \
  --plan /absolute/private/cycle-a/evaluation-plan.v1.json \
  --build-root /absolute/private/cycle-a/source-builds \
  --evidence-dir /absolute/private/cycle-a/three-way-evidence \
  --attestation-key /absolute/private/cycle-a/evaluator.key \
  --key-id honey-cycle-a-local-evaluator \
  --per-stratum 2 \
  --seeds 2 \
  --bootstrap-repetitions 100 \
  --confidence-percent 95
```

Official qualification inherits the immutable input-token budget recorded in each selected task
contract. `--token-budget` is reserved for an explicit lower-budget stress experiment; it cannot
raise or replace the corpus contract used for promotion evidence.

Cycle A deliberately records the external Tier 1 qualification checks as incomplete. Its metrics
can correct the harness and select Cycle B hypotheses, but cannot nominate, merge, or release a
candidate.
