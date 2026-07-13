# Adapter disable

## Preconditions

Identify the exact connector or extension digest, affected operation classes, pending attempts, and
unknown effects. Preserve audit and journal state. Disabling an adapter must not erase its records or
enable a fallback with broader authority.

## Exercise

1. Set the adapter disabled in the signed production registry and publish the new registry digest.
2. Confirm new prepare/dispatch/invoke requests fail closed before adapter code or network access.
3. Drain safe pre-dispatch work; quarantine unknown attempts for the unknown-effect procedure.
4. Restart or reload each replica and prove registry convergence and closed readiness during drift.
5. Re-enable only a patched, signed, policy-approved digest after conformance, no-egress replay, and
   recovery qualification.

## Stop conditions

Stop on registry disagreement, fallback invocation, new outbound traffic, journal gaps, or attempts
whose external state is uncertain. Record adapter digest, registry digest, affected counts, and
content-free denial evidence.
