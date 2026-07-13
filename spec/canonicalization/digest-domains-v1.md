# CIGAR digest domains v1

Every v1 digest hashes this exact preimage:

`ASCII_DOMAIN || 0x00 || "v1" || 0x00 || deterministic_cbor_payload`

SHA-256 is the only v1 algorithm. Protocol text uses lowercase hexadecimal multihash form: the `0x12` SHA-256 code, the `0x20` digest length, and 32 digest bytes (`1220` plus 64 lowercase hex digits).

| Semantic domain | ASCII domain |
|---|---|
| Context atom | `CIGAR-ATOM` |
| Ordered bundle | `CIGAR-BUNDLE` |
| Selection manifest | `CIGAR-MANIFEST` |
| Handoff capsule | `CIGAR-HANDOFF` |
| Effect intent | `CIGAR-EFFECT` |
| Effect or verification receipt | `CIGAR-RECEIPT` |
| Signature-excluded extension manifest | `CIGAR-EXTENSION-MANIFEST` |

Domains are closed for v1. Equal canonical payloads in different domains must produce different digests. A future algorithm or schema major requires a new registered profile and cannot change these bytes.
