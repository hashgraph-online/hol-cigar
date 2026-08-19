# Continuous refinement intake and draft-review bridge

CIGAR's continuous loop is intentionally split into evidence production, review,
experimentation, and repository review. No component is allowed to turn favorable
development evidence directly into a merge or release:

```text
ledger + dashboard facts + Pareto archive
                    |
                    v
          deterministic candidate set
                    |
        independent exact-ID review
                    |
                    v
       reviewed opportunities registry
                    |
       scheduler -> model adapter -> gates
                    |
          nominated retained commit
                    |
                    v
       exact-ref push -> draft PR only
                    |
          normal human/code review
```

The opportunity miner is `tools/refinement/opportunity_miner.py`. The draft-PR
bridge is `tools/refinement/pr_bridge.py`. Both default to non-authoritative
operations: mining does not schedule or edit code, and the PR bridge defaults to
a read-only preview. Neither tool has merge or package-publication authority.

## Opportunity derivation

The checked-in policy is
`refinement/opportunities/mining-policy-v1.json`. Its content-addressed policy ID
binds thresholds, KPI-to-scheduler metric mappings, owner hints, affected strata,
and estimated experiment cost.

Mining reconstructs the dashboard from the authoritative hash-chained ledger and
the exact dashboard-facts commitment; it does not trust a detached dashboard JSON
export. It also replays the complete owner-private Pareto archive when the policy
contains Pareto rules.

The three derivations are deterministic:

- A KPI regression compares the latest sample with the direction-aware best prior
  sample inside `kpi_lookback`. A signal is emitted only when the regression meets
  the rule's ppm threshold. Magnitude is the regression divided by the declared
  full-scale regression, capped at one.
- A failure cluster uses the dashboard's verified aggregate count. A signal is
  emitted only at the declared count threshold. Magnitude is count divided by the
  full-scale count, capped at one.
- A Pareto gap replays the archive's frontier and takes the best frontier value in
  the declared direction. A signal is emitted when the distance to the declared
  goal meets the minimum gap. Magnitude is gap divided by the declared full-scale
  gap, capped at one.

The candidate set binds the exact projection ID, Pareto head, policy ID, producer,
derivation evidence, and final scheduler-compatible signal. Candidate and signal
arrays are sorted by content identity. Replaying unchanged evidence produces
byte-identical output.

Use absolute external paths. The output operation is create-new, mode `0400`, and
will not overwrite:

```sh
python3 tools/refinement/opportunity_miner.py mine \
  --repository "$PWD" \
  --ledger-root /absolute/private/ledger \
  --facts /absolute/private/dashboard-facts.json \
  --pareto-root /absolute/private/pareto \
  --policy "$PWD/refinement/opportunities/mining-policy-v1.json" \
  --output /absolute/private/intake/candidates.json
```

An empty candidate set is a successful indication that no configured regression,
failure threshold, or Pareto gap currently requires an experiment. Do not weaken
thresholds merely to keep the worker busy.

## Independent review and publication

Mining candidates are not schedulable output. A distinct reviewer must disposition
every exact candidate ID as accepted or rejected. Rejections require a reason.
The reviewer's HMAC key should be unavailable to the miner, proposal model, and
development worker. The implementation rejects a reviewer ID equal to the mining
producer ID.

For a small batch, list exact IDs explicitly:

```sh
python3 tools/refinement/opportunity_miner.py review \
  --repository "$PWD" \
  --candidates /absolute/private/intake/candidates.json \
  --reviewer-id independent-opportunity-reviewer \
  --key-id opportunity-review-key-2026q3 \
  --attestation-key /absolute/private/review/opportunity-review.key \
  --accept 1220... \
  --reject '1220...=Already covered by an active retained hypothesis.' \
  --output /absolute/private/intake/review.json
```

`--accept-all` is an explicit convenience for a separately reviewed batch and
cannot be combined with individual dispositions. Publication revalidates the
candidate set, its nested signal identities, the complete disposition partition,
review independence, key fingerprint, review identity, and HMAC:

```sh
python3 tools/refinement/opportunity_miner.py publish \
  --repository "$PWD" \
  --candidates /absolute/private/intake/candidates.json \
  --review /absolute/private/intake/review.json \
  --attestation-key /absolute/private/review/opportunity-review.key \
  --output /absolute/private/intake/reviewed-opportunities.json
```

Retain all three files. The standard opportunities registry can be reproduced from
the candidate set and review, which is the audit proof that every schedulable
signal was accepted. Tampering, partial review, duplicate IDs, a wrong key, or zero
accepted signals fails closed.

Supply the reviewed registry to `tools/refinement/loop.py --signals`. Model choice
is an adapter-profile decision, not part of signal authority:

- `codex-gpt-5.6-sol` uses the bounded hosted Responses adapter.
- `codex-cli-gpt-5.6-sol` uses the same named model through an authenticated
  Codex CLI login when an API-key handle is intentionally unavailable. It
  disables Codex tools and returns only controller-mediated model actions.
- `local-openai-compatible` uses the loopback Responses-compatible endpoint.
- `subprocess-jsonl` accepts a controller-owned local executable.
- `recorded-proposal` and `patch-json` provide deterministic replay fixtures.

All adapters receive the same closed task packet and controller-owned tools. They
cannot expand allowed paths, budgets, gates, evidence class, or promotion
authority. Run one bounded iteration at a time in `suggest`, `patch`, or `pr`
mode. Feed the terminal result back into the ledger, dashboard facts, trial
history, and Pareto archive before mining the next generation. This prevents a
fast model from outrunning the evidence needed to decide whether it improved
CIGAR.

For real-model qualification, build the exact source consumer and bind both its
path and computed SHA-256 multihash before running the production-path tests:

```sh
export CIGARBENCH_CONSUMER=/absolute/candidate/target/debug/cigarbench-consumer
export CIGARBENCH_CONSUMER_DIGEST=1220...
export CIGARBENCH_SOURCE_REVISION=<exact-commit>
export CIGARBENCH_SOURCE_TREE=<exact-tree>
python3 -m pytest \
  tools/refinement/tests/test_r03_consumer.py \
  tools/refinement/tests/test_r05_corpus.py
```

The expected digest is supplied by the controller-owned build receipt. This
allows new exact-source builds to qualify without treating one historical local
binary as permanent authority. For the Honey 0.9.2 Cycle A comparison,
`python3 -m tools.refinement.honey_refinement build` produces the stricter
three-treatment build set: one common measurement adapter is compiled separately
against published Honey, the frozen private champion, and the current candidate.
The resulting receipt binds all three production source identities, generated
lockfiles, toolchain executables, and consumer executables; a Honey result may
not be aliased to a champion observation.

## Draft-PR bridge

`pr` mode creates one deterministic candidate commit on
`refine/trial-<trial_id>` and emits `cigar.refinement-pr-payload.v1`. The payload
binds the base commit, candidate commit, candidate tree, retained branch,
evaluation ID, and false merge/publication authority.

First extract the exact nested `review_payload` from the immutable terminal
artifact into a create-new evidence file. Preview is the default and performs no
push or GitHub API write:

```sh
python3 tools/refinement/pr_bridge.py \
  --repository "$PWD" \
  --payload /absolute/private/trial/pr-payload.json \
  --remote origin \
  --base-branch main \
  --github-repository OWNER/REPOSITORY \
  --output /absolute/private/trial/draft-pr-preview.json
```

Preview fails unless all of these remain exact:

- the repository is clean and the payload has a valid content identity;
- the retained local branch resolves to the candidate commit and tree;
- the candidate has exactly one parent and it is the payload's base commit;
- fetch and push URLs are one identical GitHub repository URL;
- the remote base branch still equals the payload base commit; and
- the remote candidate branch is absent or already equals the candidate commit.

Execution is deliberately awkward enough to prevent an accidental write. It
requires `--execute`, the exact payload ID as confirmation, and a credential
environment-variable handle. This is the only operation documented here that
writes to GitHub, so do not run it during local qualification:

```sh
export CIGAR_DRAFT_PR_TOKEN='github-token-with-minimal-required-scope'
python3 tools/refinement/pr_bridge.py \
  --repository "$PWD" \
  --payload /absolute/private/trial/pr-payload.json \
  --remote origin \
  --base-branch main \
  --github-repository OWNER/REPOSITORY \
  --execute \
  --confirm-payload-id 1220... \
  --token-handle CIGAR_DRAFT_PR_TOKEN \
  --output /absolute/private/trial/draft-pr-receipt.json
```

The Git operation uses one literal
`candidate_commit:refs/heads/refine/trial-...` refspec, without force or wildcard
updates, and verifies the remote ref afterward. The GitHub request fixes
`draft=true` and `maintainer_can_modify=false`. A retry recognizes the exact
existing remote branch and exact open draft PR instead of pushing or creating a
duplicate. Redirects and proxies are disabled for the GitHub API request.

The bridge has no merge endpoint or merge command. A successful receipt binds the
preview, payload, base/head identities, whether a push was necessary, draft PR
number/URL, and false merge/publication authority. Merge, promotion, qualification,
and PyPI publication remain separate reviewed systems.

## HUMIDOR downstream qualification

One terminal `trial_nominated` event and its matching immutable ledger entry can
be exported as a signed, content-free downstream request:

```sh
python3 tools/refinement/downstream.py \
  --repository "$PWD" \
  --event /absolute/private/loop/events/00000000000000000006.json \
  --ledger-entry /absolute/private/ledger/entries/00000000000000000004.json \
  --attestation-key /absolute/independent/key \
  --key-id refinement-downstream-r1 \
  > /absolute/private/downstream-nomination.json
```

The exporter re-resolves the champion and candidate Git commits and trees,
binds the exact loop and ledger identities, inventories only changed source
paths, and marks changes to public profiles, ABI, SDKs, storage, effects,
replay, or release artifacts as requiring the HUMIDOR downstream gate. It
exports no task, prompt, corpus, oracle, annotation, or tenant content.

Experimental profiles may be labeled `--experimental-profile`; a downstream
`humidor_incompatible` result then blocks integration but does not block
unrelated research. Every request remains suggest-only: merge and publication
authority are fixed false. CEDAR owns downstream execution and returns only a
signed aggregate result with decision, failure classes, metric deltas, and
evidence identities.

## Iteration acceptance

Treat an iteration as useful only when its complete evidence is replayable. At a
minimum, track:

- correctness and hard-invariant pass rate;
- critical-context recall, evidence precision, and first-useful-evidence rank;
- latency, token count, compute, and provider cost;
- protected-stratum regressions and seed consistency;
- failure-class frequency and invalid-evidence rate; and
- Pareto-frontier membership versus Honey and the current champion.

A nominated patch is not automatically an improvement. Promotion policy,
independent evaluation, protected strata, Honey/champion non-inferiority, and
normal code review remain the acceptance boundary. The next mining pass should
use only the newly replayed authoritative evidence.

## Honey 0.9.2 bounded program

The general loop above is narrowed for Honey 0.9.2 by
`refinement/profiles/honey-0.9.2-refinement-profile.v1.json`. Do not feed broad beta, v1/GA,
connector, workflow, cloud, dashboard, or release-packaging gaps into this program.

The program has exactly three cycles:

1. Cycle A changes measurement and harness controls only. Its first output is a replayable
   three-way baseline for published Honey 0.9.1, private champion `d079c145`, and the harness-only
   candidate using the frozen cohort.
2. Cycle B admits at most three isolated product hypotheses, each derived from a measured Cycle A
   gap and limited to an allowed CIGAR component.
3. Cycle C adds no feature scope. It exercises adversarial, restart, recovery, revocation,
   ambiguity, storage, and downstream regressions for the nominated candidate.

The frozen cohort is `refinement/cohorts/honey-0.9.2-three-way.v1.json`. A changed input, source,
threshold, workflow, scenario, treatment, lane, seed count, or reliability count is a new cohort
requiring the corpus-and-metric human breakpoint. Passing tests alone does not replace the
champion: the candidate must be Pareto-superior, non-inferior to both Honey and the champion, and
pass every hard invariant and protected stratum.

Merge mechanics are part of the evidence boundary. After a human approves the winning private
merge, the resulting signed Shadow `main` commit—not the pre-merge PR head—is the final release
candidate. Complete release qualification binds that signed source with no later source or
metadata edits before a separately approved public promotion.
