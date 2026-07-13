# CIGAR v1 semantic envelopes

Semantic hashing first serializes a record as strict JSON, converts it to the deterministic CBOR semantic model, removes only the fields listed below, and wraps the remaining map as `[profile_discriminant, fields]`. The array shape and unsigned discriminant prevent two record families with equal field maps from sharing bytes.

| Profile | Discriminant | Digest domain | Excluded top-level fields | Reason |
|---|---:|---|---|---|
| Atom | 1 | `CIGAR-ATOM` | `atom_id`, `version_id` | Creation identity and self-derived identity are not semantic content. |
| Bundle | 2 | `CIGAR-BUNDLE` | `bundle_id` | The identity is derived from this envelope. |
| Manifest | 3 | `CIGAR-MANIFEST` | `manifest_id` | The identity is derived from this envelope. |
| Handoff | 4 | `CIGAR-HANDOFF` | `signature` | Signature bytes authenticate but cannot sign themselves. |
| Effect | 5 | `CIGAR-EFFECT` | none | Logical identity, authorization bindings, time, and idempotency are semantic. |
| Receipt | 6 | `CIGAR-RECEIPT` | `receipt_id` | Receipt content remains stable independently of storage identity. |
| Extension manifest | 7 | `CIGAR-EXTENSION-MANIFEST` | `signature` | Every declaration is signed while signature bytes cannot sign themselves. |

Nested observation fields are included unless a future schema major defines another profile. Transport request IDs, trace IDs, log correlation IDs, and storage metadata are not fields of these semantic records and therefore never enter an envelope. Unknown profiles fail closed.

`semantic_envelope_v1` and `semantic_multihash_v1` are the executable Rust reference. The cross-language vectors under `schemas/vectors/` freeze the byte representation and digest domains.
