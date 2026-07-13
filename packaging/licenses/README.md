# License and notice inventory

The workspace declares Apache-2.0 in `Cargo.toml`. `Apache-2.0.txt` is the distribution copy used by
the deterministic package builder, and `third-party-policy.v1.json` is the fail-closed classification
policy for dependency inventory generation.

The repository root `LICENSE` is the project distribution license. Release tooling must bind its
exact bytes and digest to every artifact that carries the project license; a generated inventory or
the copy in this directory is not a substitute for the root license.

`scripts/release/generate_sbom.py` inventories locked Cargo, npm, Python, and Go dependencies. The
generated inventory is evidence, not legal advice; ambiguous or missing expressions require review.
The general inventory covers the full workspace and must not be used as the inventory for a
narrower release profile. Each profile needs an exact artifact-bound dependency and notice
inventory for the bytes it actually distributes.
