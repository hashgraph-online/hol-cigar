# Miri qualification slice

This deliberately small workspace keeps native TLS, database, and keyring dependencies outside
Miri while exercising the canonical and identity types used at every trust boundary.

Run:

```sh
MIRIFLAGS="-Zmiri-strict-provenance -Zmiri-symbolic-alignment-check" \
  cargo +nightly miri test --manifest-path tests/miri/Cargo.toml \
    --target x86_64-unknown-linux-gnu --test memory_model
```

The wider workspace remains covered by ordinary tests, Loom models, fuzzing, and platform
sanitizers. A Miri build failure in a third-party native dependency is not accepted as evidence for
this slice; the isolated workspace must pass. `tests/miri/Cargo.lock` pins `zmij` 1.0.23, whose
AArch64 SIMD paths are correctly excluded under Miri, so the native interpreter exercises the
portable implementation without changing the Apple-silicon ABI.

## Native Apple-silicon macOS status

The strict native command is:

```sh
CARGO_NET_OFFLINE=true \
MIRIFLAGS="-Zmiri-strict-provenance -Zmiri-symbolic-alignment-check" \
  cargo +nightly miri test --locked --offline \
    --manifest-path tests/miri/Cargo.toml \
    --target aarch64-apple-darwin --test memory_model
```

With `zmij` 1.0.23 this command passes the `canonical_and_identity_memory_model_is_clean` test on
native `aarch64-apple-darwin` without `RUSTFLAGS`, target-feature changes, warnings, network access,
or skipped tests. The previous 1.0.22 failure was caused by one AArch64 NEON block missing the
crate's otherwise consistent `not(miri)` guard; 1.0.23 adds that guard. The separate sanitizer/FFI
qualification requirements are not implied by this focused Miri result.
