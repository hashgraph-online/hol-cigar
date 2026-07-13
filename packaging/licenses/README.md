# License and notice inventory

The workspace declares Apache-2.0 in `Cargo.toml`. `Apache-2.0.txt` is the distribution copy used by
the deterministic package builder, and `third-party-policy.v1.json` is the fail-closed classification
policy for dependency inventory generation.

The repository currently has no root `LICENSE` file. That is a release stop condition: the local
archive builder can be exercised, but a production evidence assembly must not pass until the exact
license text is also installed at the repository root and its digest is included in release evidence.

`scripts/release/generate_sbom.py` inventories locked Cargo, npm, Python, and Go dependencies. The
generated inventory is evidence, not legal advice; ambiguous or missing expressions require review.
