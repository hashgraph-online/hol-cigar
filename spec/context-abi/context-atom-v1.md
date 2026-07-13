# ContextAtomV1

`ContextAtomV1` is an immutable catalog record identified by a UUIDv7 record ID and content-derived SHA-256 multihash version ID. Its `schema_version` is exactly `cigar.atom.v1`.

Validation follows this stable order: schema compatibility, payload bounds and integrity, source completeness, tenant/project scope, temporal consistency, governance completeness, quality bounds, retrieval metadata, lifecycle invariants, then extensions. Independent safe failures are aggregated up to `MAX_VALIDATION_ERRORS`.

Security-sensitive states are closed enums. Unknown discriminants fail deserialization. Optional unknown extensions are preserved; unknown keys under `required/` fail closed. Null and floating-point extension values are unrepresentable.

Raw payload, source revision, project identities, purposes, processor constraints, retrieval terms, and extension values are omitted from `Debug` output. JSON Schema is generated at `schemas/json/context-atom-v1.schema.json`; the checked-in file must match `cargo xtask generate --check`.

