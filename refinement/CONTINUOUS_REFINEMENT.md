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
