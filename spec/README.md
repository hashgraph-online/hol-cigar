# Protocol specifications

Frozen protocol contracts will live in the domain-specific subdirectories beginning with WP01. Drafts are not consumed by downstream packets.

The [exact v1 development interface projection](api/operations-v1.md) is generated from the
operation, payload, CLI/MCP mapping, and public error authorities. It is exact for this source tree
but is not a released compatibility or cross-platform qualification claim.

The development-only [protocol compatibility policy](compatibility/policy-v1.md) defines
directional additive-minor and breaking-major review rules. It is not a release-freeze claim.

The [macOS development configuration authority](configuration/authority-v1.json) closes the four
configuration profiles, setting-level precedence, source ownership, secret-handle classifications,
and provider-qualification status. Its scope is macOS arm64 development source only.
