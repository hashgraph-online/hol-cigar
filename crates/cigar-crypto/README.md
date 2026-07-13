# cigar-crypto

Stability: foundational, pre-v1. Owns key providers, envelope encryption, signatures, blinded identifiers, and secret-safe types.

The local profiles include an Argon2id-derived, XChaCha20-Poly1305 encrypted development keystore with atomic fsync/rename persistence and an `OsKeychainKeyProvider` that keeps the high-entropy keystore secret in the native macOS Keychain, Windows Credential Manager, or Linux Secret Service. Formatting remains permanently redacted, and wrapped data keys never expose master-key bytes.
