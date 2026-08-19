# Miri qualification slice

This deliberately small workspace keeps native TLS, database, keyring, and process-runtime
dependencies outside Miri while exercising the canonical and identity types used at every trust
boundary. It also compiles the exact production `workflow_context_session.rs` module directly into
the qualification test crate. Dedicated qualification cases exercise its transition, delta,
effect-fence, quarantine, replay, and durable-restoration paths without substituting a model
implementation. The Windows adapter's exact bounded UTF-16 raw-pointer helper is compiled directly
into the same slice and exercised with valid, invalid, unterminated, and null inputs.

Run:

```sh
MIRIFLAGS="-Zmiri-strict-provenance -Zmiri-symbolic-alignment-check" \
  cargo +nightly miri test --locked --offline --manifest-path tests/miri/Cargo.toml \
    --target x86_64-unknown-linux-gnu --test memory_model
```

The wider workspace remains covered by ordinary tests, Loom models, fuzzing, and platform
sanitizers. The repository's Rust `unsafe` blocks are confined to the Windows FFI adapter. The
platform-neutral bounded-pointer helper is claimed by this slice; Windows API calls are not and
remain an explicit platform-sanitizer and manual-review obligation. A Miri build failure in a
third-party native dependency is not accepted as evidence for this slice; the isolated workspace
must pass. `tests/miri/Cargo.lock` pins `zmij` 1.0.23, whose
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

`zmij` 1.0.23 permits the portable canonicalization implementation to run on native
`aarch64-apple-darwin` without `RUSTFLAGS` or target-feature changes. The previous 1.0.22 failure was
caused by one AArch64 NEON block missing the crate's otherwise consistent `not(miri)` guard; 1.0.23
adds that guard. A complete current result must execute all four qualification tests without
warnings, network access, or skipped tests. The separate Windows API sanitizer/FFI qualification
requirements are not implied by this focused Miri result.

`test_miri_contract.py` separately keeps the isolated lock free of native runtime crates, verifies
that the two exact production modules remain included, and fails if unsafe Rust appears outside the
audited Windows adapter.
