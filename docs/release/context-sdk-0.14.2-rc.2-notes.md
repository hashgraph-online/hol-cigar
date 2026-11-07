# Local SDK 0.14.2-rc.2

Unpublished development release candidate. Rust/npm use `0.14.2-rc.2`; Python
uses the equivalent PEP 440 spelling `0.14.2rc2`. The remote workspace remains
0.9.4. Existing stable publication workflows and their exact tag gates are
unchanged; this candidate does not authorize a stable publication.

## Changes

- Add `ContextBroker::consume_ticket`, Python `consume_ticket` and TypeScript
  `consumeTicket`. They perform current ticket revalidation and ticket/draft/binding
  removal in one serialized broker operation, avoiding two agent round trips and
  an intervening source-update window. The broker advertises `consume_ticket.v1`.
- Consumption remains owner-bound, single-use and subject to every current
  authority, source provenance, grant, expiry and evidence check. It does not
  authorize effects or establish that an answer is correct. A lost acknowledgement
  has an unknown outcome; SDKs perform no retry or two-call fallback.
- Retain the prior native tokenizer, Python pipe and import performance work.

## Benchmark status

Candidate measurements and compatibility/security checks must be recorded before
claiming the requested 80-point / 100% Safe Workflow Completion target. Historical
0.14.2 reports stay unchanged. Reader-runtime and prompt experiments are separate
declared treatments, not evidence of an engine-only improvement.
