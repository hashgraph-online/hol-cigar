# Bounded source replacement across host frames

Status: implemented in v0.14 development source; native and SDK tests pass locally.
Installed artifacts, hosted platforms and release qualification remain pending.

The ordinary broker API replaces one source atomically, but its complete document
list must fit one 32 MiB host request. The additive interface stages a
single source over several bounded host frames and commits through that same
replacement path. Existing graph and broker methods retain their behavior.

## Contract

1. The trusted host begins a replacement with an exact source, expected source
   epoch/version, provenance and a bounded lease. It receives an opaque handle
   bound to the current broker epoch.
2. Append calls validate each complete document and retain bounded batches.
   Duplicate IDs, mismatched sources, invalid lines, oversized documents and
   retained-byte limits fail before modifying the staged replacement. Partial
   documents and automatic parser/embedding calls are not part of this API.
3. Agents continue reading the old graph. Staging changes neither graph/source
   revision nor reviews. A host may explicitly abort the staged source.
4. Commit consumes the handle, rechecks source CAS, current ownership, provenance,
   derivation dependencies and all graph limits, then invokes the existing atomic
   source replacement. A definite validation failure leaves the live graph
   unchanged; start a new transaction to retry with corrected input.
5. Durable mode writes one existing replacement checkpoint/receipt after commit.
   Begin/append/abort do not publish evidence or write durable checkpoints. Pending
   staging is deliberately absent from restore; old handles cannot survive the
   new epoch.

Empty complete input withdraws a source. Each appended batch must be nonempty;
an empty iterator therefore begins and commits withdrawal directly. The append
order is preserved when passing documents to the existing replacement method.
Existing edges remain, including dangling hard dependencies after withdrawal.

## Resource and authority boundaries

At most four staged sources may coexist, each with a lease of at most five
minutes. Their deterministic retention charge shares the broker's existing
`max_retained_bytes` ceiling with tickets/proposals. Charge the encoded metadata
and batch bytes plus a conservative allowance for each retained document. This
is an admission bound, not an exact Rust heap measurement or zeroization promise.
Document count/text limits also apply during staging and again at commit.

No host request/response frame limit is raised. A logical source can exceed one
frame only within configured graph, retention and checkpoint limits. The default
checkpoint bound can be smaller than a permitted staging allocation; callers
must qualify their intended durable source size. Commit uncertainty still closes
the owner rather than returning a safe-to-retry failure.

Only the private host command enum admits begin/append/commit/abort. Agents cannot
upload authoritative batches, enlarge scopes or approve provenance using a
transaction handle. No new grant, effect authority, discovery or service is
introduced. Expired and consumed handles fail without revealing another source.

The Python and Node convenience APIs consume caller-supplied batches, abort
on a local iteration/validation failure when the owner remains available, and
preserve the original exception. They never retry an append or commit after
an ambiguous transport outcome. Capability checks must refuse older workers
explicitly. Low-level host methods remain available for controlled interleaving.

## Required evidence

- Exact source receipt, scope identity and compiled-output parity with a single
  ordinary replacement; valid existing canonical identities remain unchanged.
- Old evidence remains visible between batches; commit changes visibility once.
- Invalid later batches, duplicate IDs across batches, stale CAS, stale derivation,
  ownership conflicts and graph/quota failures cannot publish partial input.
- Expiry, abort, commit replay and restart reject/release old staging correctly.
- Agent command decoding rejects every host ingestion operation.
- SQLite recovery sees the old or committed source, never an intermediate batch;
  failed durable commit preserves existing uncertainty semantics.
- Python/Node generators and mixed readers exercise the real worker. A source
  above the old frame ceiling is tested with explicit resource bounds.
- Measure construction/append/commit latency and simultaneous host-plus-worker
  RSS. This API removes a frame-size constraint; it does not by itself eliminate
  full-checkpoint write cost, stream documents directly to disk, or establish a
  throughput improvement.
