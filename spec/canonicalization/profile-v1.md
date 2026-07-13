# CIGAR deterministic encoding profile v1

CIGAR v1 accepts only the deterministic RFC 8949 subset implemented by `cigar-canon`.

- Integers and lengths use their shortest representation.
- Strings, arrays, and maps always use definite lengths.
- Map keys are UTF-8 text and are ordered by the bytewise order of their complete deterministic CBOR encodings.
- Duplicate or misordered map keys are rejected.
- Null, floating point, undefined values, arbitrary tags, indefinite items, invalid UTF-8, trailing bytes, and non-shortest forms are rejected.
- Arrays, maps, depth, input bytes, and output bytes have explicit public limits.
- Strict decoding re-encodes and byte-compares the entire value.

Generic strict JSON accepts booleans, signed/unsigned 64-bit integers, strings, arrays, and unique string-keyed maps. It rejects duplicate keys, null, floating point, trailing values, and values beyond the same depth/entry/input limits. Normalized JSON is compact and orders keys lexicographically. Semantic byte strings remain typed record fields; an untyped byte node cannot be rendered as JSON.

Unicode normalization is field-specific. Human fields that declare normalization use NFC before semantic encoding. Source code, opaque text, paths, identifiers, and protected bytes retain their exact representation.

These limits are frozen for the v1 profile:

| Limit | Value |
|---|---:|
| Input bytes | 67,108,864 |
| Output bytes | 67,108,864 |
| Nested containers | 64 |
| Array items | 100,000 |
| Map entries | 100,000 |

