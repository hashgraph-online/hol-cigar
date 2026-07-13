# Reference connectors

The hermetic WP12 implementations live in `crates/cigar-effects/src/reference` and are exported
through `cigar_effects::reference`:

- `DemoIssueConnector` demonstrates exact same-key idempotency and lookup after response loss.
- `FilesystemEffectConnector` confines atomic writes to a canonical root, rejects traversal and
  symlinks, binds current-content preconditions, fsyncs file and directory, and reconciles by
  content digest.
- `IdempotentHttpConnector` accepts only a normalized fixed HTTPS endpoint and delegates network
  I/O to an injected `HttpTransport` that must return explicit success, rejection, not-sent, or
  ambiguous observations.
- `GitHubIssueConnector` is an offline GitHub-like example. It hashes the logical key into a public
  marker, searches before create, declares no remote same-key guarantee, and requires
  reconciliation before retry.

Protected request bodies are staged behind digest handles and excluded from connector `Debug`
output. These examples make no live network calls. Runtime decryption, credential acquisition, and
real transport installation belong to the daemon composition packet.
