# Broker qualification plan for v0.14

Status: registered before running the sustained broker workload. The existing
native scheduler tests, short SDK process tests and ordinary daemon reliability
suite remain required. This plan adds source-level load and fault qualification;
it does not substitute for installed distributions, hosted platforms or task
efficacy evidence.

## Bound inputs and consumers

Use one copied optimized worker and copied Python/compiled Node SDKs, with source,
artifact, fixture, harness and configuration hashes. Credentials travel only
through private parent/child stdin. Workers and actor processes use explicit paths;
no provider, external service, discovery or credential lookup is permitted.
Record runtime/OS identity. Do not label implementation-only local networking as
OS-enforced denial.

Each measured cell has 1, 5 or 12 independent agent processes. Run Python, Node
and alternating mixed-language cohorts. One graph contains equal-sized common,
per-agent private and pair-shared sources. Stable required documents establish
exact allowed context for every actor, while unselected allowed documents exercise
scope commitment. Out-of-scope canaries, hostile instructions in source text and
denied required IDs must not enlarge authority. Fixture labels are authored
invariants; they are not model-output quality judgments.

Measure memory-only and SQLite modes. Compare one and four in-flight calls per
agent, with each cycle compiling and then forgetting its ticket. Do not let
retained test tickets exhaust quotas accidentally. Freeze source data during a
load interval; mutations and stale-ticket checks have separate fault phases so
expected failures do not disappear into a throughput denominator.

## Measurements and limits

Use a future shared start time and record actual per-process start skew. Collect
each compile/forget latency and each agent's completed, failed and rejected call
counts. Preserve failure codes and definite/unknown dispatch outcomes. Python's
validated native replies can also supply queue/service times; Node end-to-end
measurements must explicitly report unavailable internal timings rather than
invent values. Sample simultaneous coordinator + worker + all actor RSS.

For the fixed small-context load fixture, register these initial operational
gates before measurement:

- No leaked/incorrect evidence, unexpected API error, lost receipt or orphaned
  process. No write retry. Every successful context fits its exact token budget.
- Measured start skew at most 100 ms. A capped/early-ended cell is incomplete,
  not a successful low-latency result.
- Compile p95 at most 250 ms, p99 at most 900 ms, with a 5-second per-call timeout.
  Retain every tail observation; no deletion of outliers after a run.
- At least five completed compile/forget cycles per second per agent, under equal
  work. Within each runtime group, minimum/maximum agent completions must be at
  least 0.80 and Jain's completion fairness index at least 0.95. Do not blame the
  native scheduler for different Python/Node overhead or pool mixed-runtime
  completions into that fairness claim.
- RSS and latency comparisons use fresh, paired process cohorts with the existing
  20% RSS and 10% median latency guardrails when comparable baselines exist.
  A one-cohort smoke run cannot establish a performance interval or close Q1.

These are application-level target limits for the registered fixture, not
universal API SLAs. A failure requires investigation and a retained disposition;
do not retroactively weaken a gate to accept the same observation.

## Measurement correction recorded before the replacement load study

The initial `broker-load-matrix-01` was stopped after 180 of 288 cells. Four
cells failed only the complete-window check, with zero API failures. Inspection
found that the workload's deadline used a monotonic clock but the reducer checked
completion using wall time. Its retained wall timestamps do not establish the
monotonic elapsed window or the reason the clocks differed. The original study
remains incomplete; do not reinterpret those four cells as passes or combine its
successful cells with a new study.

Both actors now record `monotonic_window_ms` from the same clock and scheduled
start as the workload deadline. Completion still requires the entire registered
duration. Wall time remains the common future-start/skew record and a diagnostic;
it is no longer the elapsed-duration authority. Tests simulate backward wall
adjustment and an early monotonic exit. No latency, progress, fairness, duration
or failure threshold changes. The replacement study freezes these corrected
measurement bytes and repeats all registered cohorts.

## Fault phases

Separate bounded phases exercise:

1. Shared/private/pair scopes, cross-owner tickets and denied required evidence.
2. Private-source updates: affected context becomes stale while unrelated scopes
   remain valid. Withdrawal/change-back cannot revive old context.
3. Two proposals for one exact source revision: one host admission succeeds, the
   other conflicts; inspect both retained outcomes and current evidence.
4. Grant revocation/redefinition: old credentials and reviews stay invalid; a
   host-issued replacement is explicit. Never let an agent supply reviewer labels.
5. Failed/abandoned clients and bounded local/native saturation while another
   agent and the private host channel continue making progress.
6. Worker termination/restart in durable mode: committed evidence survives, a
   fresh epoch is required, and pending staging/grants/tickets/reviews do not
   return. Unknown write outcomes remain unknown until reconciled.

The existing real HTTP/SQLite Honey bridge scenarios remain the execution test
authority; the load harness must not recreate a simplified effect dispatcher.

## Long run and release boundary

After short fault/load cells pass, run a 24-hour twelve-agent soak on frozen
inputs. Renew grants explicitly before expiry; rotate bounded writes, proposals,
revocations and planned durable restarts, checking each expected transition.
Store bounded per-cycle observations incrementally, keep periodic RSS/process
liveness samples and require complete elapsed duration with no unexplained gaps.
A short run or a restarted timer cannot count as a completed soak. A materially
changed worker requires another final-candidate qualification.

The source study reports its own evidence class. Final Q2 still requires exact
installed artifacts, all advertised targets/runtimes, network-denied execution,
reproducible builds and release attestations. E2 still requires independently
reviewed task/evidence oracles. None of these fixture tests establishes that an
LLM's confident answer is true.
