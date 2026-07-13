# CIGAR security distribution

This package preserves the public `s3` library API from `rust-s3` 0.37.2. It is published under a
distinct package identity so registry consumers of CIGAR cannot silently substitute the unreviewed
upstream package.

The reviewed source bounds synchronous response bodies before XML parsing. Its manifest pins
`quick-xml` to 0.41.0, depends exactly on `cigar-aws-creds` 0.39.1-cigar.1, and selects
`attohttpc/tls-rustls-webpki-roots-ring` for synchronous Rustls. These controls must remain intact
in the normalized package manifest.

The publishable manifest also removes the upstream async-std/Surf transport surface. Surf is
unmaintained and its legacy HTTP/TLS closure contains denied RustSec advisories. This distribution
must fail closed if a consumer requests those removed feature names; do not restore the dependency
or feature aliases without a new security review.

The source tree is copied byte-for-byte from the reviewed vendored source. Changes to the vendored
source must be copied here and requalified before either package is released.
