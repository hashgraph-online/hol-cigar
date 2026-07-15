# Configuration authority for macOS development

`spec/configuration/authority-v1.json` is the closed, machine-readable authority for CIGAR's four
macOS arm64 development profiles. Its schema is `authority-v1.schema.json`, and
`scripts/configuration/validate_configuration_authority.py` binds the document to the Rust fields
that consume it. This is a development-source contract, not a beta release or cross-platform
support claim.

The frozen source-document SHA-256 is
`9dbc8f3f1eaa4cd48d1a314399e0c20144a60a7b954a414ca9b42b3b90332c85`.

## Profiles and owners

| Profile | Configuration owner | Accepted boundary | Network and secret authority |
| --- | --- | --- | --- |
| `embedded` | embedding application, Rust SDK, daemon composer | explicit programmatic builder plus one explicit strict daemon file | no HTTP target; storage, policy, and identity are explicit; secrets are descriptor-bound files or explicit providers |
| `local_sidecar` | CLI and local `cigard` operator | layered CLI settings plus one explicit strict daemon file | one Unix socket, or authenticated loopback TCP ingress; optional explicitly pinned stock HTTPS effect egress; owner-only secret files |
| `remote_client` | application through an SDK, or CLI user | programmatic SDK builder or layered CLI settings | one HTTPS origin; explicit authorization provider/file; no redirect, URL credential, ambient proxy, or ambient credential |
| `shared_service` | `cigard` operator | one explicit strict daemon file | explicit TLS, OIDC, PostgreSQL, and S3-compatible authorities; file-backed secrets; no project or ambient authority |

On this macOS-only development line, Windows named-pipe settings are recognized solely so that they
can be rejected as mode-incompatible. They are not a support claim.

## Precedence

The global low-to-high order is fixed:

1. compiled default;
2. system configuration;
3. user configuration;
4. project configuration;
5. explicit configuration;
6. environment;
7. CLI flag;
8. programmatic API.

Each setting carries its own ordered projection of that list. A source absent from a setting's
`allowed_sources` has no authority for that setting. Programmatic SDK settings do not combine with
CLI layers. Daemon settings accept only the explicit daemon file. Within one layer, duplicate TOML
keys are syntax errors and synonymous transports are ambiguity errors; field order never decides a
winner.

For CLI resolution, `CIGAR_ENDPOINT` is rejected unless the same environment layer contains
`CIGAR_TARGET`. This prevents an endpoint from being reinterpreted according to a target selected by
another layer. `CIGAR_AUTHORIZATION` and `CIGAR_TOKEN` are raw secret values and are rejected;
`CIGAR_AUTHORIZATION_FILE` is the environment-level handle. Project configuration cannot provide an
authorization handle. Endpoint and credential provenance remain separately labeled, and
`--explain-config` reports only the labels while rendering authorization as `[REDACTED]`.

The per-setting rows in the machine authority are normative. Every row states the owner, active
profiles, exact precedence, allowed sources, default and required semantics, secret classification,
value form, redacted provenance label, project-file disposition, and macOS disposition. The source
inventory makes adding a Rust configuration field without adding a row a validation failure.

## Strict files and secret handles

Configuration and secret files are bounded regular files. The reader binds the path observation,
opened descriptor, content read, and final path observation by device/inode, size, timestamps, mode,
owner, and link count. It rejects a final-component symlink, hard link count other than one,
replacement during use, oversized or changed content, and unsafe ownership or mode.
Every path component is opened relative to its already validated parent directory with no-follow
semantics. Symlinked ancestors and unsafe writable ancestors are rejected; an ancestor renamed
after opening cannot redirect the final open because the walk remains anchored to directory
descriptors. On macOS, callers therefore provide physical paths such as `/private/var/...` instead
of symlink aliases such as `/var/...`.

The policies are:

- Configuration and trusted files may be owned by the effective user or root and cannot be group-
  or world-writable.
- Mutable secret handles must be owned by the effective user and grant no group or world access.
- Immutable shared keystore and cursor mounts are owned by the effective user and use mode `0400`.
- The shared keystore is decoded from the bytes read through the validated descriptor; it is not
  checked and then reopened by path.

Secret settings contain paths or provider handles, never the raw passphrase, token, database URL,
access key, secret key, session token, private key, cursor key, or blinding key. Debug and provenance
surfaces expose only stable labels such as `authorization`, `postgres_runtime_url_file`, or
`object_secret_key_file`.

## Endpoint and ambient-authority rules

Remote and shared HTTP origins reject userinfo (including encoded userinfo), non-root paths, queries,
and fragments. Remote service traffic requires HTTPS. Cleartext HTTP exists only behind an explicit
development opt-in for a loopback host and, for object storage, an explicit port. Redirects are
disabled.

CLI and Rust SDK reqwest clients disable proxy discovery. The synchronous S3 client constructs every
session with empty proxy settings and redirects disabled; an explicit S3 credential object is built
from the descriptor-bound files. Upper- and lowercase proxy variables, `NO_PROXY`, `.netrc`, cloud
credential variables, cloud profiles, and metadata-service conventions never become connection or
credential authority. An application that injects a custom SDK transport owns that transport's
proxy, redirect, and credential policy and must explicitly acknowledge that boundary.

## Mode incompatibilities

Fail-closed checks include:

- embedded: endpoint, remote authorization, and shared daemon mode are forbidden;
- local sidecar: exactly one local transport is required; public binds and shared TLS/OIDC/storage
  fields are forbidden; loopback TCP requires the local-token file;
- remote client: local sockets and pipes are forbidden; the endpoint is an HTTPS origin and an
  explicit authorization file/provider is mandatory;
- shared service: TLS, OIDC, HTTP and gRPC listeners, PostgreSQL, and object storage are required;
  local IPC, local-token fields, and the large-local SQLite capacity profile are forbidden; runtime
  and migrator database handles are distinct.

Unknown fields, duplicate keys, raw secret sources, project-secret authority, malformed URLs,
ambiguous transports, and incompatible fields stop configuration before a connection or worker is
started.

## Local SQLite capacity profile

Embedded and local-sidecar daemon files may set `local_sqlite_capacity_profile = "large_local"`
only on native Apple-silicon macOS. Absence selects `standard`. The value has explicit daemon-file
authority only: no environment, project-file, or CLI override may change it. The selected profile is
persisted in the v4 SQLite authority singleton, and every subsequent open must request the same
profile.

Standard retains the 4-GiB database bound. Large-local uses a 64-GiB database bound, requires at
least 300 GiB available before first activation, maintains a 16-GiB reopen reserve, and rejects more
than 1.25 million atoms, 12.5 million edges, or 128 GiB of logical referenced blob bytes. Shared
mode, non-macOS builds, Intel macOS builds, and attempts to change an activated database profile
fail before repository use. Selecting this profile is capacity authority, not evidence that the
physical scale qualification passed.

## Optional local vector projection

The local sidecar has one macOS-only, disabled-by-default `[local_vector]` section. Enabling it
requires an owner-private absolute `root_directory` below `state_directory` plus explicit bounded
`dimension`, `maximum_entries`, and `maximum_neighbors` values. The section is forbidden in shared
mode and has no environment, project-file, or CLI authority. Missing, stale, corrupt, or unavailable
vector state never becomes mandatory-index authority: startup or rebuild verifies and repairs from
canonical catalog truth when possible, otherwise it omits the optional adapter and preserves exact,
metadata, lexical, graph, and temporal retrieval.

## Optional local live HTTPS effects

The production effect registry is disabled by default. On macOS, the standalone local sidecar may
enable an `idempotent_http` connector only by selecting the exact
`cigar.idempotent-effect-http.v1` provider protocol and supplying all six remaining
`https_transport` fields: an opaque `credential_handle`, an absolute owner-private
`credential_file`, a sorted unique nonempty `pinned_addresses` set containing public IP addresses
only, bounded `connect_timeout_ms` and `request_timeout_ms`, and bounded
`maximum_response_bytes`. These values have only `explicit_config` authority inside the trusted
effect-registry file. There is no environment, CLI, project-file, ambient DNS, proxy, `.netrc`, or
cloud-credential fallback.

The client dials only the configured address pins while retaining the endpoint DNS name for the
platform TLS chain and hostname verifier. It disables redirects, proxies, referrers, automatic
retries, content decoding, and idle connection reuse. The credential document is reread through the
descriptor-safe owner-only secret-file boundary for every dispatch and lookup, so rotation,
expiry, origin drift, and project/resource scope drift fail closed. A configured live HTTP
connector is rejected in shared mode and on non-macOS builds. This is a development-source
capability, not part of the initial beta or an installed-provider interoperability claim.

## Provider qualification

Descriptor-bound file handles are implemented and source-tested for all four profiles. Installed
exact-byte and runtime qualification remains open. The programmatic remote authorization-provider
interface is defined; the embedding application owns its runtime provider qualification.

The following remain explicitly open and are not release-qualified: end-to-end macOS Keychain use
by the service profiles, selection/integration of an external secret manager, and an explicit cloud
workload-identity adapter. Ambient cloud credential discovery is forbidden and is not a temporary
substitute for those open integrations.

Validate the authority and source drift with:

<!-- docs-check: illustrative -->
```sh
python3 scripts/configuration/validate_configuration_authority.py --repo-root .
python3 -m unittest scripts.configuration.tests.test_validate_configuration_authority
```

These checks are deterministic validation tests; they are neither fuzz nor soak tests.
