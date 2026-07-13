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
this slice; the isolated workspace must pass. The explicit Miri target also avoids an upstream
`zmij` 1.0.22 AArch64/Miri conditional-compilation defect while still interpreting every test
instruction rather than executing a foreign binary.
