# npm union response decoding correction

September 25, 2026. **The published `@hol-org/cigar@0.11.0` has a confirmed
response-decoding defect. This correction is unreleased source for a subsequent
patch version.** The published 0.11.0 tag and archives are unchanged.

## Failure and scope

A valid `publishSpace` response with `outcome: "published"` and
`commit.sequence: 1` throws
`SpacePublishResponse: value does not match its schema variants` in npm 0.11.0.
The same canonical CBOR bytes decode successfully in installed `hol-cigar==0.11.0`
from PyPI. The `deduplicated` outcome is also affected. The fixtures reproduce
related failures in nested integer extension values in `ContextBundle` and
`SpaceLogResponse`.

Small canonical CBOR integers decode to JavaScript numbers. The generated model
requires `bigint` for schema fields declared `int64` or `uint64`, but its union
probe validated the raw branch before normalizing those fields. A sequence already
above JavaScript's safe-integer range followed the `bigint` path and happened to
work. Source inspection of `v0.10.0-beta.1` confirms the same faulty probe ordering;
the installed-package comparison here tests 0.11.0.

This exception occurs while decoding a successful response. It does not establish
that the server mutation failed. The regression tests require exactly one transport
call for both accepted and rejected responses.

The previous release qualification verified archive identity, installation, local
graph workflows and the existing SDK suite. It lacked successful fixtures for this
remote response branch. A test that expects the valid response to throw documents
the limitation; it cannot qualify that operation as working.

## Correction

The fix lives in `sdk/generate_clients.py` and the regenerated TypeScript models:

- Normalize each candidate branch before probing its schema; retain final validation
  of the complete union, required fields, discriminator and unknown-field rules.
- Normalize integers inside schema-defined map values as well as properties and arrays.
- Validate type-union candidates and bound coercion recursion and node visits.
- Preserve exact integer values, canonical CBOR bytes and immutable model results.

Python runtime code is unchanged. Both SDKs share fixed CBOR fixtures; generator
checks require identical packaged copies, and release source binding includes the
fixture authority. The existing installed SDK test discovery includes the new tests.

## Offline comparison

| Check | Published npm 0.11.0 | Corrected TypeScript source | Published PyPI 0.11.0 |
|---|---:|---:|---:|
| Valid shared response fixtures decoded | 5/11 | 11/11 | 11/11 |
| Valid `publishSpace` variants decoded through the client | 3/7 | 7/7 | 7/7 |
| Malformed shared response fixtures rejected | 7/7 | 7/7 | 7/7 |
| Malformed `publishSpace` responses rejected after one transport call | 7/7 | 7/7 | 7/7 |

The positive fixtures cover published/deduplicated/conflicted outcomes, both fork
variants, small integers, the safe-integer boundary, uint64 maximum, signed int64
minimum, and nested array/map extensions. Negative controls include missing fields,
mixed-variant fields, wrong discriminators, negative unsigned integers, and text or
boolean values in integer fields. Additional TypeScript assertions reject unsafe
numbers, fractions, non-finite values and excessive recursive nesting.

Validation on macOS ARM64, Node.js 24.19.0 and Python 3.14.7:

- The new TypeScript suite fails against installed npm 0.11.0: 25 passes and
  12 failures, including two parent failures reporting their failing subtests.
  All 37 tests pass with the correction.
- The complete TypeScript SDK suite passes all 81 tests, with no skips.
- The complete Python SDK suite passes 45 tests and 39 subtests, with no skips.
- Generated-source consistency, TypeScript compilation, Python lint and all eight
  release source-binding tests pass.

The initial full-suite attempts exposed local test setup issues: a downloaded
timeout fixture lacked executable permission, and the workspace sandbox blocked
the Python localhost redirect test. An executable copy of the existing fixture
and permission to run the localhost test resolved those failures; no assertions
were removed. All evaluation used fixtures, with no model-provider or HOL-service
calls. These results do not claim live-server or new seven-platform qualification.

## Reproduction

From a built checkout:

```sh
node --test sdk/typescript/dist/tests/union-responses.test.js
uv run --project sdk/python pytest -q sdk/python/tests/test_union_responses.py
```

For the npm baseline, set `CIGAR_TEST_SDK_MODULE` to the `file:` URL of an installed
0.11.0 package's `dist/index.js` and run the same TypeScript test file. Successful
decoding remains the expected result, so the baseline run fails visibly.

Use the Python facade for the affected remote calls while pinned to 0.11.0. The
corrected npm implementation needs a new package version and its release checks;
it has not been published as 0.11.0 or 0.11.1.
