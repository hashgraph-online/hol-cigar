# Socket, TLS, and OIDC operations

## Local transport

Select exactly one local transport. On Unix, create the socket under an owner-only directory and
require the socket to be owned by the daemon user with mode `0600`. On Windows, use an explicit named
pipe whose ACL grants only the intended user or service identity. A loopback HTTP fallback requires a
separate owner-read-only bearer-token file; the token never appears in a URL, argument, environment
dump, or diagnostic bundle.

Reject a regular file, symlink, hard-link ambiguity, wrong owner, group/world access, non-loopback
local endpoint, or multiple configured local transports. After restart, verify the endpoint identity
again rather than trusting a stale pathname.

## Shared TLS and OIDC

Shared HTTP and gRPC require TLS with an explicit trust root and expected server name. Do not accept
insecure HTTP, certificate-name fallback, redirects, URL credentials, ambient proxy settings, or an
ambient operating-system root set when a pinned deployment root is required.

Pin the OIDC issuer and audience. Validate discovery and JWKS responses under the same TLS policy,
bound their sizes and cache lifetime, and reject algorithm substitution, missing key IDs, issuer or
audience mismatch, expired/not-yet-valid tokens, and stale keys beyond the configured overlap. Map
the authenticated subject to tenant/project authority only through the current authority snapshot.
Authentication never supplies an ambient project or bypasses policy.

## Rotation, failure, and evidence

Rotate certificates and OIDC keys with an overlap window that is shorter than the documented cache
bound. Exercise both the old-valid and new-valid path, then prove the old identity is rejected after
retirement. Keep readiness closed if trust roots, names, issuer metadata, clock bounds, or authority
mapping are uncertain. Evidence records only configuration and certificate/key digests, validity
windows, endpoint classes, result codes, and blinded correlation IDs—never tokens or subjects.
