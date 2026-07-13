# cigar-rust-s3

`cigar-rust-s3` is CIGAR's security-reviewed distribution of `rust-s3` 0.37.2. The Rust library
name remains `s3`, but the package has a distinct registry identity so CIGAR consumers cannot
silently resolve to the upstream package.

The CIGAR release path uses the synchronous Rustls transport with an explicit Ring cryptographic
provider:

```toml
[dependencies]
s3 = { package = "cigar-rust-s3", version = "=0.37.2-cigar.1", default-features = false, features = ["sync-rustls-tls"] }
```

That profile is the default for this distribution. It depends exactly on
`cigar-aws-creds = 0.39.1-cigar.1`, pins `quick-xml = 0.41.0`, and selects
`attohttpc/tls-rustls-webpki-roots-ring` explicitly.

## Supported transport features

- `sync-rustls-tls` uses synchronous `attohttpc`, Rustls, WebPKI roots, and Ring. This is the CIGAR
  default and qualified release profile.
- `sync-native-tls` and `sync-native-tls-vendored` retain the corresponding upstream synchronous
  compatibility profiles, but they are not used by CIGAR packages.
- `tokio-rustls-tls` and `tokio-native-tls` retain the Tokio/Reqwest compatibility profiles, but
  they are not used by CIGAR packages.
- `tags`, `blocking`, and `fail-on-err` retain the matching upstream API options.

The upstream async-std/Surf transport is deliberately not exposed. Surf is unmaintained and its
legacy HTTP/TLS dependency chain has denied RustSec advisories. Attempting to enable an old
async-std feature name therefore fails dependency feature resolution instead of restoring that
unsafe transport.

See `CIGAR-PATCHES.md` for the reviewed security boundaries. Any manifest, feature, dependency, or
source change requires the full publication-chain and advisory qualification documented in
`sdk/rust/PUBLISHING.md` in the CIGAR repository.
