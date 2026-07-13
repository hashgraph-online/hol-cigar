# CIGAR security distribution

This package preserves the public `awscreds` library API from `aws-creds` 0.39.1. It is published
under a distinct package identity so registry consumers of CIGAR cannot silently substitute the
unreviewed upstream package.

The CIGAR release pins `quick-xml` to 0.41.0 and selects
`attohttpc/tls-rustls-webpki-roots-ring` for the Rustls feature. The latter makes Ring the explicit
cryptographic provider and prevents `attohttpc`'s generic Rustls feature from enabling AWS-LC.

The source tree is copied byte-for-byte from the reviewed vendored source. Changes to the vendored
source must be copied here and requalified before either package is released.

