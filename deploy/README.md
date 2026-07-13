# Deployment assets

Development services are available under `compose`. The WP14 deployment base
also includes a multi-stage, non-root container and a hardened systemd unit.

- `docker/Dockerfile` builds only `cigard`, runs it as numeric user/group
  `65532` with no shell in the final image, and starts the real `serve` command.
  The executable and bundled example configuration remain root-owned and
  read-only inside the image.
  The image pre-creates `/var/lib/cigar`, `/var/lib/cigar/project`, blob/key
  storage, and `/run/cigar` as `65532:65532`; it deliberately declares no
  implicit volumes. Before attaching a named volume, bind mount, tmpfs, or CSI
  volume at either writable path, the operator must provision its root as
  writable by `65532:65532` (normally mode `0750`). Bind mounts do not inherit
  ownership from the image, and the daemon must not be started as root to repair
  them.
  Trusted policy, authority, source/effect registries, the encrypted keystore
  passphrase handle, and persistent state must be mounted before startup.
- `docker/cigard.example.toml` is loopback-only. It is not a shared-production
  configuration and contains no credential material.
- `systemd/cigard.service` runs the real daemon and restarts only after failure.
  It drops all Linux capabilities, makes the host
  filesystem read-only outside CIGAR-owned state/runtime/cache directories,
  and limits address families to Unix and IP sockets. It permits only the user,
  mount, PID, network, IPC, and UTS namespaces and mount-related syscalls needed
  by rootless bubblewrap; cgroup namespaces remain denied.
- `systemd/cigar.sysusers` and `systemd/cigar.tmpfiles` provision the dedicated
  service identity and permission-restricted directories.

Image digest pinning, signing, SBOM/provenance attachment, and distribution
qualification remain release-pipeline responsibilities in WP20-WP22.

The WP18 shared profile is under `shared`, `compose/shared.yaml`, and
`kubernetes/shared`. It uses separate PostgreSQL owner/runtime credentials, forced RLS,
an encrypted S3-compatible CAS, TLS/OIDC, a one-shot migration Job, non-root replicas,
bounded resources, disruption/autoscaling controls, default-deny networking, and OTLP/alert
examples. The Kubernetes base contains intentionally invalid external endpoints and a local image
name; operators must replace them and pin the exact release digest before applying it. The runtime
pod never mounts the migrator credential.

Before enabling an extension-capable release unit, operators must verify that
unprivileged user namespaces are enabled and that the packaged bubblewrap probe
succeeds for the `cigar` account. Readiness fails closed when that sandbox
precondition is unavailable; broadening capabilities or namespace access is not
a supported fallback.
