# cigar-effects

Stability: kernel, pre-v1. Owns durable effect intent, approval, attempts, receipts, unknown states, reconciliation, and compensation.

The public `EffectEngine` is the only dispatch authority. It persists an intent before approval,
atomically journals each versioned transition with the current projection, and returns a sealed,
non-cloneable `DispatchPermit` only after a fenced attempt and outbox wakeup are durable. Connectors
receive that already-authorized context; they cannot approve work or turn ambiguity into success.

Immediately before connector entry, the engine consumes the exact permit through an exclusive
durable ownership transition and projects the attempt to `Unknown`. That ordering makes a crash on
either side of the remote call explicit and prevents a second worker from reusing the permit. A
definitive connector observation and its receipt are then committed as a later journal transition;
receipt loss therefore remains `Unknown` and must reconcile instead of being blindly sent again.

The daemon worker reloads the exact claimed record, checks its expected revision, stages protected
arguments only after the durable claim, and resolves current policy twice: before staging and again
immediately before the shutdown gate and kernel dispatch. The kernel independently revalidates the
permit, attempt deadline, approval, intent expiry, connector declaration, preconditions, and current
authorization before it can construct the sealed connector context.

The daemon crate also supplies a separate, disabled-by-default stock HTTPS transport for an
explicit local macOS `idempotent_http` registry entry. It uses exact public address pins with no
ambient DNS or proxy, platform TLS chain/hostname verification, strict scoped credential files,
bounded I/O and deadlines, no redirects or automatic retries, and lookup-only reconciliation after
ambiguous execution. This development-source transport is not an initial-beta or shared-service
claim. See the effect-journal reference for its exact wire and configuration contract.

Compensation is always another ordinary, separately authorized effect. The original journal stores a
`CompensationLink` and projects the child outcome; there is no connector-side compensation bypass.

The deterministic qualification suite covers every `EFX-C01` through `EFX-C24` crash boundary,
uses a real killed child process at each boundary, and runs 100,000 possible-remote-commit logical
effects with zero duplicate logical effects and zero blind redispatches. The SQLite receipt-loss
regression proves that a remote commit followed by failed receipt persistence reopens as `Unknown`
and reconciles to success without creating the remote object twice.

See `docs/reference/effect-journal.md` for state, recovery, retry, and connector contracts.
