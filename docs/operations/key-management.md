# Key creation, custody, and rotation

## Create and inventory

Create signing, encryption, wrapping, cursor, and local installation keys only through the configured
key provider. Bind each key to tenant, purpose, algorithm, creation time, activation time, status,
and non-secret provider reference. Reject ambiguous multiple active issuers for a purpose. Export
public verification material separately; never export private key bytes into a package, backup,
configuration file, log, environment variable, or support bundle.

Local protected key files must be regular, non-symlinked, owner-read-only files. Shared deployments
use the approved provider identity with the narrow sign/wrap/unwrap operations required by its role.
Runtime identities cannot create, rotate, retire, revoke, or destroy keys.

## Rotation and retirement

Follow the detailed [key-rotation exercise](key-rotation.md). Publish the new key and trust metadata
before using it, retain the historical decrypt/verify key while referenced data or signatures remain,
and advance authority and revocation epochs atomically. Verify new writes use the new key while old
records remain readable and historical signatures remain verifiable at their signing time.

Revocation is distinct from retirement. A retired key can validate historical signatures made while
active; a revoked key or principal fails current trust policy. Destruction is allowed only after a
complete reference scan, retention/legal-hold approval, verified backup policy, and an independently
reviewed destruction record.

## Stop conditions and evidence

Stop on provider identity mismatch, purpose/tenant ambiguity, unbounded key-cache age, lost historical
references, failed unwrap/decrypt/verify samples, or replicas observing different authority epochs.
Keep old material protected, close readiness for affected operations, and follow
[revocation propagation](revocation-propagation.md). Evidence contains key IDs and provider-reference
digests, purposes, status transitions, epochs, counts, and result codes; it contains no key material.
