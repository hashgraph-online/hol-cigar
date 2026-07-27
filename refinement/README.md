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
