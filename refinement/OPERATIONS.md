# Refinement operations and incident runbooks

The refinement controller is not a release system. Every managed workflow has repository read
permission, `CIGAR_NO_PROMOTION=1`, and no merge, push, package, or identity-token authority.
Development, shadow, and promotion lanes use different GitHub environments and external
owner-private state. Only the existing release qualification and publication process may publish
`hol-cigar`.

## Required platform configuration

Configure these controls before enabling a schedule:

1. Create self-hosted runner groups and labels `refinement-development`, `refinement-shadow`, and
   `refinement-promotion`. Do not place a runner in more than one of these groups.
2. Create GitHub environments with the same names. Configure required reviewers and prevent
   self-review for `refinement-shadow` and `refinement-promotion`. Restrict the promotion
   environment to the protected default branch. The workflow declaration selects an environment;
   reviewer policy remains repository-host configuration and must be audited through the GitHub
   API before rollout.
3. Give development only `CIGAR_DEVELOPMENT_API_KEY`. Give shadow only
   `CIGAR_SHADOW_ATTESTATION_KEY` and its private corpus mounts. Give promotion only
   `CIGAR_PROMOTION_ATTESTATION_KEY` and paths to independently retained comparison/decision
   evidence. Never duplicate PyPI, signing, notarization, release, shadow, or holdout credentials
   into the pull-request or development environment.
4. Set `CIGAR_REFINEMENT_STATE_ROOT`, `CIGAR_REFINEMENT_LEDGER_ROOT`, and
   `CIGAR_REFINEMENT_QUOTA_ROOT` to distinct absolute, owner-only `0700`,
   repository-external filesystem directories shared by development workers. Pre-create
   `runs`, `worktrees`, and `commands` as `0700` children of the state root. The run ID excludes
   `GITHUB_RUN_ATTEMPT`, so an Actions rerun resumes the exact controller journal rather than
   creating a second trial. Configure shadow corpus/consumer and promotion evidence paths only as
   environment variables in their respective protected environments.
5. Retain external authoritative evidence independently of GitHub Actions artifacts. Uploaded
   bundles are content-addressed, immutable `0400` transports with a manifest and retention
   declaration; they do not gain promotion authority merely by being uploaded.

Run this after every workflow or policy edit:

```sh
python3 tools/refinement/operations.py audit-workflows \
  --repository "$PWD" \
  --policy "$PWD/refinement/operations/workflow-policy-v1.json"
```

Before enabling the schedule, perform a credential-free dry run with the same roots and checked-in
opportunity registry. A real nightly run invokes `tools/refinement/loop.py` in `suggest` mode,
reserves the selected packet budget through the shared quota ledger, materializes one isolated Git
worktree, executes the hosted adapter through controller-owned actions, runs named gates, writes
phase/ledger checkpoints, and emits a content-addressed result bundle. It never commits the
suggested diff or changes the champion.

## Normal reconstruction

To explain a champion selection, replay the hash-chained ledger, verify the comparison and
decision IDs in the promotion entry, verify the evidence bundle, and generate the dashboard
projection from facts bound to that same ledger head. The projection shows the exact champion
revision/tree, selecting ledger entry, comparison, decision, source artifacts, trial history, KPI
series, provider usage, cost, and failure classes.

Dashboard reads are pure by default:

```sh
python3 tools/refinement/operations.py dashboard \
  --repository "$PWD" \
  --ledger-root /absolute/private/ledger \
  --facts /absolute/private/dashboard-facts.json
```

Omitting `--output` writes only canonical JSON to stdout. Supplying `--output` uses create-new
`0400` publication and refuses to overwrite.

## Pause

1. Create the configured pause file atomically in the controller state directory. The controller
   checks it at every resumable phase boundary: before scheduling, proposal launch, gate launch,
   and evaluation/terminal preparation. An already-running provider call remains bounded by the
   packet wall-time and must finish or be cancelled.
2. Let the active bounded command finish or use the cancel procedure below.
3. Append `controller_stopped` with reason `operator_pause`; do not modify an earlier entry.
4. Verify all active quota reservations. A paused live provider call remains fully reserved.
5. To resume, archive the pause file under a timestamped incident directory, replay state, and
   resume the one exact trial. Never silently skip its terminal record.

## Cancel

1. Cancel the GitHub run or send the controller cancellation request.
2. The adapter must kill its process group or close the hosted session, then retain content-free
   request/usage bindings.
3. Append the trial’s stopped/rejected terminal event and retain its branch and evidence.
4. Settle the quota with measured usage. If measurement is unavailable, settle the full
   reservation. Use quota `cancel` only when evidence proves no provider request or worker compute
   began.
5. Do not delete the worktree until cleanup preview confirms the branch retains the candidate.

## Budget exhaustion

Quota reservations count their full maxima until terminal settlement. A provider daily
input/output/dollar ceiling, global compute ceiling, or concurrency ceiling must stop the run
before the provider call or worker launch.

1. Record `budget_exhausted` as the failure class and append `controller_stopped`.
2. Do not increase limits during the same experiment. A limit change is a reviewed policy change
   with a new policy ID.
3. Settle measured usage, or the full reservation if unavailable.
4. Schedule the unfinished hypothesis on a later UTC day only after replay proves it has no
   terminal trial result.

Inspect usage without mutation:

```sh
python3 tools/refinement/operations.py quota usage \
  --repository "$PWD" \
  --quota-root /absolute/private/quota \
  --policy "$PWD/refinement/operations/limits-v1.json" \
  --utc-day 2026-07-27
```

## Provider outage

1. Permit only the adapter’s bounded retry policy; never create a second concurrent session for
   the same trial.
2. On terminal timeout or outage, cancel the adapter and preserve response status, retry count,
   elapsed time, and content digests without response bodies or credentials.
3. Conservatively settle quota and append `controller_stopped` with `provider_outage`.
4. Resume only from the exact ledger state. If the provider cannot prove idempotency, start a new
   session attached to the same trial and retain the abandoned session ID.
5. Switch provider profiles only through a new scheduled decision so cost and outcome comparisons
   do not mix providers silently.

## Corrupt ledger

Never edit, truncate, renumber, chmod, or recreate an entry in place.

1. Pause all writers and preserve the quota reservations.
2. Make a read-only, content-digested incident copy of the entire ledger and filesystem metadata.
3. Replay from sequence zero and identify the first invalid inventory name, mode, chain link,
   schema field, or content identity.
4. Compare the incident copy with the independent backup/artifact inventory. Restore the complete
   ledger to a new owner-private root only if every byte through the last valid head matches.
5. Point a reviewed configuration revision at the restored root. Record the old/new root
   commitments and incident decision externally. Never continue a chain whose prior head is
   ambiguous.
6. If no authoritative copy exists, stop the optimizer. Development may restart from a freshly
   baselined generation, but the damaged generation can never support promotion.

## Rollback

Rollback is a new decision, not history rewriting.

1. Pause scheduling and identify the prior champion revision/tree from a replayed promoted entry.
2. Re-run compatibility and safety gates against the exact prior commit in a fresh worktree.
3. Create a reviewed rollback comparison/decision that cites the regression and both champion
   identities.
4. Append a new promoted entry selecting the prior commit. Do not use `git reset`, force-push, or
   mutate the earlier promotion.
5. Rebuild dashboard facts at the new ledger head and verify the champion projection.
6. Package publication, yanking, or release rollback remains a separate release runbook and cannot
   be initiated by a refinement workflow.

## Worker kill, disk pressure, and evidence interruption

- After a worker kill, keep the reservation active, replay the trial store and named-command
  receipts, inspect the exact worktree, then resume or reject. Do not infer success from a partial
  output.
- Before launching, require enough free space for the configured evidence and build maxima. On
  disk pressure, stop before publication, preserve already immutable files, settle conservatively,
  and resume into a new create-new evidence directory.
- If evidence publication or artifact upload is interrupted, the run is ineligible. Verify the
  external directory inventory; create a new transport bundle from authoritative immutable files.
  Never overwrite or append to the partial transport.

## Promotion and release boundary

`refinement-promotion.yml` is manual, uses the `refinement-promotion` protected environment, replays
the independent decision, checks out the exact candidate revision, and produces an attested
`prepare-review-only` payload. It has no contents write, pull-request write, merge, identity-token,
package, or publication permission. A human or separately authorized integration may use the
payload to open a review; it still may not publish a package or bypass normal release
qualification.

The separate draft-PR bridge described in
[CONTINUOUS_REFINEMENT.md](CONTINUOUS_REFINEMENT.md) can consume a nominated loop
PR payload. It defaults to read-only preview and requires an exact payload
confirmation before pushing one literal retained-candidate ref and opening a draft
review. It has no merge or publication operation.
