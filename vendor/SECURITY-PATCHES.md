# Vendored security patches

These two crates are exact copies of the published `rust-s3` 0.37.2 and
`aws-creds` 0.39.1 packages, including their upstream MIT licenses and Cargo
package metadata. They are temporarily selected through `[patch.crates-io]`
because those latest published versions constrain Quick-XML to the vulnerable
0.38 release line.

CIGAR makes two narrowly scoped changes:

- both manifests require `quick-xml` 0.41.0, which contains the fixes for
  RUSTSEC-2026-0194 and RUSTSEC-2026-0195;
- the synchronous `rust-s3` ListObjects response path reads at most 4 MiB plus
  one detection byte before XML deserialization, returning an I/O error for an
  oversized response.

Remove these patches when a reviewed upstream `rust-s3` release both resolves
Quick-XML 0.41 or newer and bounds ListObjects response buffering before parse.
