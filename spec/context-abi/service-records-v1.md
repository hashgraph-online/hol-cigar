# Service records v1

Public service failures use stable `ErrorCode` values with explicit numeric discriminants. `Problem` validates its HTTP mapping, carries only safe bounded message/remediation text, and exposes internal causes solely through a correlation identity. The authoritative mapping source is `spec/errors/catalog.yaml`; WP02 generates all language and transport registries from it.

Page cursors are opaque, bounded, unpadded base64url values and redact bytes from debug output. Health reports contain sorted uniquely named content-free components and require the aggregate status to equal the worst component. Compatibility reports bind protocol ranges, supported schema majors, and sorted incompatibility reasons.

