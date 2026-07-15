# Post-beta capability profile

`post-beta-capability-profile.v1.json` is the fail-closed development ledger for the native
Apple-silicon macOS cohort. It inventories exactly the 29 capabilities excluded from the immutable
`0.1.0-beta.1` profile without enabling them in that beta.

The seven Boolean states are monotonic. A capability cannot advance past a missing predecessor,
and an accepted transition cannot change a prior `true` value back to `false`. `implemented_source`
does not imply integration, packaging, qualification, publication, or support.

This profile is inventory-only. It does not claim that any post-beta capability is released or
supported. Linux, Windows, Intel macOS, and OCI qualification require separate profiles rather than
an in-place expansion of this profile.

Generate or validate the reviewed ledger with:

```sh
python3 scripts/release/post_beta_profile.py generate
python3 scripts/release/post_beta_profile.py check
```

The general release metadata validator also checks this profile. Any state advancement requires
reviewed evidence for that state and a corresponding update to the pinned generator definition.
