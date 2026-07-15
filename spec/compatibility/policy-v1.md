# CIGAR protocol compatibility policy v1

Status: normative for development-source review only. This policy does not freeze a release,
qualify migrations, or claim cross-platform support. The machine authority is
[`policy-v1.json`](policy-v1.json), validated by
[`protocol_compatibility.py`](../../scripts/compatibility/protocol_compatibility.py) against the
local [JSON Schema](compatibility-policy-v1.schema.json).

## Direction is part of compatibility

“Backward reader” means a candidate reader accepts every value a baseline writer may emit and
preserves its observable semantics. “Forward reader” means a baseline reader accepts every value a
candidate writer may emit. The latter is stronger than proving that today's candidate fixtures
happen to use the old subset.

An additive-minor change MUST preserve the backward-reader direction. If it enlarges the candidate
writer's possible output language, the forward-reader direction is conditional: the candidate
MUST retain a baseline emission profile or negotiate the new capability/version before emitting
it. A change is breaking-major when an existing reader language, identity, binding, ordering,
scope, or meaning is removed or changed. A comparator result of `manual-review` is not compatible
evidence; it is a fail-closed request for the named retained-state or migration evidence.

## Domain rules

| Domain | Additive minor | Breaking major |
| --- | --- | --- |
| Public JSON Schemas | Add a separately versioned family; add an optional property or broaden a candidate reader only when new writer output is gated | Remove/rename a family, add a required property, narrow an accepted domain, or change a schema keyword the comparator cannot prove safe |
| Operations | Add a unique operation with a unique RPC, operation ID, method/path, payload contract, and negotiated capability | Remove an operation or change any existing identity, route, auth class, mutation/idempotency/revision rule, or stream kind |
| Interface projections | Add a checked operation-backed CLI command or MCP tool | Remove/change an existing mapping, expose an unknown or semantically mismatched operation, or claim an unimplemented route |
| Errors | Add a unique symbolic and numeric code while retaining old codes and an old-peer unknown-error path | Remove/reuse a code or name, or change an existing HTTP, gRPC, retry, disclosure, message, or remediation mapping |
| Payloads | Add a bounded payload contract only for a new operation | Change an existing envelope field, nominal request/response/event type, field source/bound, or byte limit |
| Cursor and stream state | Add an independent, explicitly versioned cursor/stream contract | Change v1 cursor bytes, authentication scope, expiry, resume/order semantics, stream kind, or event contract in place |
| Extension ABI and records | Add a separate versioned WIT world or record; broaden manifest input only with ABI/range negotiation | Change the existing WIT world, remove an ABI/record, or narrow an existing manifest/record reader |
| Claude Code plugin record | Add a platform or widen the tested half-open version interval | Remove a platform, narrow the interval, or change the compatibility-record schema/context ABI |
| SQLite/PostgreSQL stored records | Append a new uniquely sequenced migration or add a versioned record envelope only after retained-reader and mixed-version evidence | Modify/remove an applied migration, reuse a sequence/name, change an unversioned codec, or remove a retained reader |

JSON Schema comparison is deliberately conservative. It understands object properties and
requirements, type/enum/union domains, bounds, additional properties, uniqueness, and common
lexical constraints. An unrecognized semantic keyword change is breaking-major rather than being
silently accepted. Documentation-only annotations do not affect the classification.

Opaque page cursors are treated as wire records even though clients do not interpret their bytes.
Changing the authenticated fields or their encoding invalidates outstanding cursors and therefore
requires a new cursor version. Existing unary/stream classifications and `Last-Event-ID` resume
semantics cannot change within v1.

`cargo xtask generate` is the sole build-authority validator and renderer for
`interface-projections-v1.json`. It rejects unknown operations, missing payloads, duplicates,
mutation/read mismatches, invalid aliases, and invalid authority lanes before writing the closed
CLI/MCP lookups, browser projection, browser schema, or development documentation. This
compatibility policy independently baseline-binds those six source/generated files and checks
mapping identity, count, operation parity, and directional changes; it does not create another
routing authority.

The extension v1 WIT file is an ABI, not documentation. Any edit to that existing world is a major
change; a new world must use a new versioned path/package. Manifest additions remain conditional
in the forward direction because older hosts reject unknown closed fields or discriminants unless
an ABI/range handshake selects a shared language.

Migration files are immutable once applied. The validator requires the repository copies and the
crate-consumed copies to be byte-identical, sequences to be contiguous, names unique, and required
compatibility/lock/backfill/verification/restore headers present. Static SQL inspection cannot
prove interruption recovery, semantic-root equality, rollback, or mixed-version writer safety, so
a valid append is `manual-review` until those tests exist. Similarly, a change to a source file
that owns unversioned persisted JSON or binary records is never auto-accepted; retained-state
fixtures must prove both reader and writer directions or the format needs a new versioned envelope.

## Offline enforcement

From the repository root:

```sh
PYTHONDONTWRITEBYTECODE=1 python3 scripts/compatibility/protocol_compatibility.py validate --root .
PYTHONDONTWRITEBYTECODE=1 python3 scripts/compatibility/protocol_compatibility.py compare \
  --baseline-root /path/to/baseline-worktree \
  --candidate-root /path/to/candidate-worktree
```

`validate` rejects duplicate JSON keys, unknown policy fields, non-finite numbers, non-NFC text,
noncanonical policy encoding, unsafe/escaping paths, symlinks, hard links, source changes during a
read, digest/count drift, registry duplicates, projection mismatch, migration mirror drift, and
inflated release/qualification claims. It makes no network requests.

`compare` exits `0` for exact or additive-minor, `2` for unproven manual review, `3` for a detected
breaking-major change, and `1` when either input is invalid. Its canonical JSON report records both
reader directions and every reason. `snapshot` prints, but never writes, a policy rebound to the
reviewed tree; rebinding digests is not approval and MUST be followed by comparison to an immutable
baseline plus review of the classified changes.

The current policy binds 42 generated public JSON Schemas, seven services/45 operations, 34 CLI
and 10 MCP operation projections across six source/generated files, 34 error codes and all
source/Rust/Proto projections, six envelope fields/45 payload contracts/70 nominal
payload types, the single `subscribeSpaceEvents` stream, the v1 cursor codec, six extension record
schemas plus `cigar:extension@1.0.0`, the Claude compatibility record, four SQLite migrations and
four PostgreSQL migrations in both the repository and crate-consumed migration mirrors, and the
source files that own persisted record codecs. Exact byte counts and SHA-256 inventory digests live
only in the machine policy.
