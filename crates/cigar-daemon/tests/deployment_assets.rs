//! Acceptance checks for the non-root deployment base assets.

use std::fs;
use std::path::Path;

use cigar_daemon::{DaemonConfig, DeploymentMode};

fn workspace_file(relative: &str) -> Result<String, std::io::Error> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    fs::read_to_string(root.join(relative))
}

#[test]
fn systemd_unit_is_non_root_fail_closed_and_sandbox_compatible()
-> Result<(), Box<dyn std::error::Error>> {
    let unit = workspace_file("deploy/systemd/cigard.service")?;
    assert!(unit.contains("Type=simple"));
    assert!(unit.contains("User=cigar"));
    assert!(unit.contains("Group=cigar"));
    assert!(unit.contains("CapabilityBoundingSet=\n"));
    assert!(unit.contains("NoNewPrivileges=yes"));
    assert!(unit.contains("ProtectSystem=strict"));
    assert!(unit.contains("RestrictNamespaces=user mnt pid net ipc uts"));
    assert!(!unit.contains("RestrictNamespaces=yes"));
    assert!(unit.contains("@mount clone clone3 unshare setns pivot_root chroot"));
    assert!(unit.contains("cigard serve --config"));
    assert!(unit.contains("Restart=on-failure"));
    assert!(!unit.contains("Type=notify"));
    Ok(())
}

#[test]
fn container_runs_non_root_complete_server() -> Result<(), Box<dyn std::error::Error>> {
    let dockerfile = workspace_file("deploy/docker/Dockerfile")?;
    assert!(dockerfile.contains("USER 65532:65532"));
    assert!(dockerfile.contains("gcr.io/distroless/cc-debian12:nonroot"));
    assert!(dockerfile.contains("/image/state/project"));
    assert!(dockerfile.contains("/image/state/blobs"));
    assert!(dockerfile.contains("/image/state/blob-keys"));
    assert!(dockerfile.contains("/image/runtime"));
    assert!(dockerfile.contains(
        "COPY --from=builder --chown=65532:65532 --chmod=0750 /image/state/ /var/lib/cigar/"
    ));
    assert!(dockerfile.contains(
        "COPY --from=builder --chown=65532:65532 --chmod=0750 /image/runtime/ /run/cigar/"
    ));
    assert!(
        dockerfile
            .contains("COPY --from=builder --chown=0:0 --chmod=0555 /src/target/release/cigard")
    );
    let config_directory_copy = dockerfile
        .find("COPY --from=builder --chown=0:0 --chmod=0555 /image/config/ /etc/cigar/")
        .ok_or(std::io::Error::other(
            "configuration directory provisioning is absent",
        ))?;
    let config_file_copy = dockerfile
        .find("COPY --chown=0:0 --chmod=0444 deploy/docker/cigard.example.toml")
        .ok_or(std::io::Error::other(
            "immutable example configuration copy is absent",
        ))?;
    assert!(config_directory_copy < config_file_copy);
    assert!(!dockerfile.contains("/image/ /"));
    assert!(!dockerfile.contains("VOLUME ["));
    assert!(dockerfile.contains("CMD [\"serve\""));
    assert!(!dockerfile.contains("CMD [\"validate-config\""));

    let deployment_readme = workspace_file("deploy/README.md")?;
    assert!(deployment_readme.contains("writable by `65532:65532`"));
    assert!(deployment_readme.contains("Bind mounts do not inherit"));
    assert!(deployment_readme.contains("ownership from the image"));
    Ok(())
}

#[test]
fn container_context_excludes_local_state_evidence_and_credentials()
-> Result<(), Box<dyn std::error::Error>> {
    let dockerignore = workspace_file(".dockerignore")?;
    for excluded in [
        ".cigar/",
        ".tmp/",
        "reports/",
        "artifacts/packages/",
        "**/.env.*",
        "**/.ssh/",
        "**/.cargo/credentials.toml",
        "**/*.key",
        "**/*.p12",
    ] {
        assert!(
            dockerignore.lines().any(|line| line == excluded),
            "missing Docker context exclusion: {excluded}"
        );
    }
    assert!(dockerignore.lines().any(|line| line == "!**/.env.example"));
    assert!(dockerignore.lines().any(|line| line == "!**/.env.sample"));
    Ok(())
}

#[test]
fn shared_example_is_a_strict_bounded_production_profile() -> Result<(), Box<dyn std::error::Error>>
{
    let source = workspace_file("deploy/shared/cigard.shared.example.toml")?;
    let config = DaemonConfig::from_toml(&source)?;
    assert_eq!(config.mode, DeploymentMode::Shared);
    assert!(config.unix_socket.is_none());
    assert!(config.windows_named_pipe.is_none());
    assert!(config.local_token_file.is_none());
    assert!(config.tls.is_some());
    assert!(config.oidc.is_some());

    let storage = config.shared_storage.ok_or("shared storage is absent")?;
    assert_ne!(
        storage.postgres.runtime_url_file,
        storage.postgres.migrator_url_file
    );
    assert_eq!(
        storage.postgres.server_name,
        "postgres.cigar-dependencies.svc.cluster.local"
    );
    assert!(
        storage
            .postgres
            .ca_certificate_file
            .ends_with("postgres-ca.crt")
    );
    assert!(storage.postgres.maximum_connections <= 64);
    assert!(storage.postgres.minimum_connections > 0);
    assert!(storage.postgres.statement_timeout_ms <= 30_000);
    assert!(storage.object.endpoint.starts_with("https://"));
    assert!(!storage.object.prefix.starts_with('/'));

    // The checked-in file is intentionally non-routable until an operator replaces every
    // environment-specific endpoint and pins the release image.
    assert!(source.matches("example.invalid").count() >= 3);
    assert!(!source.contains("password ="));
    assert!(!source.contains("secret_key ="));
    Ok(())
}

#[test]
fn shared_kubernetes_profile_separates_runtime_and_migration_authority()
-> Result<(), Box<dyn std::error::Error>> {
    let namespace = workspace_file("deploy/kubernetes/shared/namespace.yaml")?;
    let deployment = workspace_file("deploy/kubernetes/shared/deployment.yaml")?;
    let migration = workspace_file("deploy/kubernetes/shared/migration-job.yaml")?;
    let service = workspace_file("deploy/kubernetes/shared/service.yaml")?;
    let network = workspace_file("deploy/kubernetes/shared/network-policy.yaml")?;
    let kustomization = workspace_file("deploy/kubernetes/shared/kustomization.yaml")?;

    assert!(namespace.contains("pod-security.kubernetes.io/enforce: restricted"));
    assert!(namespace.contains("automountServiceAccountToken: false"));
    for manifest in [&deployment, &migration] {
        assert!(manifest.contains("runAsNonRoot: true"));
        assert!(manifest.contains("runAsUser: 65532"));
        assert!(manifest.contains("allowPrivilegeEscalation: false"));
        assert!(manifest.contains("readOnlyRootFilesystem: true"));
        assert!(manifest.contains("drop: [\"ALL\"]"));
        assert!(manifest.contains("automountServiceAccountToken: false"));
        assert!(manifest.contains(
            "busybox@sha256:222ad6d973c0d198014546a65cd02c5fdedcc172123c5b4c2bf0af636550bd94"
        ));
    }

    assert!(deployment.contains("replicas: 3"));
    assert!(deployment.contains("maxUnavailable: 0"));
    assert!(deployment.contains("maxSurge: 1"));
    assert!(deployment.contains("terminationGracePeriodSeconds: 45"));
    assert!(deployment.contains("chmod 0600 /prepared/*"));
    assert!(deployment.contains("chmod 0400 /state/keystore.cigar /state/cursor.key"));
    assert!(!deployment.contains("chmod 0600 /prepared/* /state/keystore.cigar"));
    assert!(deployment.contains("secretName: cigar-shared-runtime"));
    assert!(deployment.contains("secretName: cigar-postgres-tls"));
    assert!(deployment.contains("/prepared-postgres-tls/postgres-ca.crt"));
    assert!(!deployment.contains("secretName: cigar-shared-migrator"));
    assert!(migration.contains("secretName: cigar-shared-migrator"));
    assert!(migration.contains("secretName: cigar-postgres-tls"));
    assert!(migration.contains("/prepared-postgres-tls/postgres-ca.crt"));
    assert!(!migration.contains("secretName: cigar-shared-runtime"));
    assert!(migration.contains("args: [\"migrate\", \"--config\""));
    assert!(service.contains("kind: PodDisruptionBudget"));
    assert!(service.contains("kind: HorizontalPodAutoscaler"));
    assert!(service.contains("minReplicas: 3"));
    assert!(network.contains("name: cigard-default-deny"));
    assert!(network.contains("podSelector: {}"));
    assert!(network.contains("port: 5432"));
    assert!(network.contains("port: 443"));
    assert!(kustomization.contains("migration-job.yaml"));
    assert!(kustomization.contains("network-policy.yaml"));
    Ok(())
}

#[test]
fn shared_development_dependencies_preserve_runtime_least_privilege()
-> Result<(), Box<dyn std::error::Error>> {
    let compose = workspace_file("deploy/compose/shared.yaml")?;
    let roles = workspace_file("deploy/compose/postgres-shared-init.sql")?;
    let post_migration = workspace_file("deploy/compose/postgres-shared-post-migration.sql")?;
    let postgres_tls = workspace_file("deploy/compose/postgres-tls-entrypoint.sh")?;
    let object_policy = workspace_file("deploy/compose/minio-runtime-policy.json")?;

    assert!(compose.contains("127.0.0.1:55432:5432"));
    assert!(compose.contains("127.0.0.1:59000:9000"));
    assert!(compose.contains("development-only"));
    assert!(compose.contains("postgres-tls-entrypoint.sh"));
    assert!(compose.contains("postgres-shared-post-migration.sql"));
    assert!(postgres_tls.contains("ssl=on"));
    assert!(postgres_tls.contains("subjectAltName=DNS:localhost,IP:127.0.0.1"));
    assert!(postgres_tls.contains("chmod 0600"));
    assert!(postgres_tls.contains("rm -f \"$TLS_DIRECTORY/ca.key\""));
    assert!(roles.contains("cigar_runtime"));
    assert!(roles.contains("cigar_backup"));
    assert!(roles.contains("cigar_gc"));
    assert!(roles.contains("NOBYPASSRLS"));
    assert!(roles.contains("BYPASSRLS"));
    assert!(roles.contains("pg_catalog.pg_control_system()"));
    assert!(roles.contains("NOSUPERUSER"));
    assert!(!roles.contains("ALTER ROLE cigar_runtime SUPERUSER"));
    assert!(!roles.contains("GRANT EXECUTE ON FUNCTIONS TO cigar_backup"));
    assert!(
        post_migration
            .contains("GRANT EXECUTE ON FUNCTION pg_catalog.pg_control_system() TO cigar_backup")
    );
    assert!(post_migration.contains(
        "GRANT EXECUTE ON FUNCTION public.cigar_gc_lock_repository_revision() TO cigar_gc"
    ));
    assert!(
        post_migration
            .contains("REVOKE ALL ON FUNCTION public.cigar_gc_lock_repository_revision()")
    );
    assert!(object_policy.contains("cigar-v1/*/staging/*"));
    assert!(object_policy.contains("cigar-v1/*/probes/*"));
    assert!(object_policy.contains("\"Effect\": \"Deny\""));
    assert!(object_policy.contains("cigar-v1/*/objects/*"));
    Ok(())
}

#[test]
fn failover_qualification_preserves_one_verified_tls_identity()
-> Result<(), Box<dyn std::error::Error>> {
    let compose = workspace_file("deploy/compose/failover/compose.yaml")?;
    let tls = workspace_file("deploy/compose/failover/tls-entrypoint.sh")?;
    let qualifier = workspace_file("tools/wp18-failover/qualify.sh")?;

    assert!(compose.contains("ssl_min_protocol_version=TLSv1.3"));
    assert!(compose.contains("tls-data:/var/lib/postgresql/cigar-failover-tls:ro"));
    assert!(compose.contains("failover-tls-entrypoint.sh"));
    assert!(tls.contains("DNS:primary,DNS:standby,DNS:router,IP:127.0.0.1"));
    assert!(tls.contains("chmod 0600"));
    assert!(tls.contains("rm -f \"$TLS_DIRECTORY/ca.key\""));
    assert!(qualifier.contains("CIGAR_WP18_FAILOVER_CA_PATH"));
    assert!(qualifier.contains("postgres_private_ca_tls"));
    Ok(())
}

#[test]
fn shared_runbooks_cover_migration_recovery_and_integrity_stops()
-> Result<(), Box<dyn std::error::Error>> {
    let deployment = workspace_file("docs/runbooks/shared-deployment.md")?;
    let rolling = workspace_file("docs/runbooks/shared-rolling-migration.md")?;
    let recovery = workspace_file("docs/runbooks/shared-backup-restore.md")?;

    for required in [
        "NOBYPASSRLS",
        "conditional second PUT",
        "64-client shared conformance",
        "no duplicate",
        "effect receipt",
    ] {
        assert!(
            deployment.contains(required),
            "missing deployment control: {required}"
        );
    }
    for required in [
        "append-only",
        "maxUnavailable: 0",
        "adjacent-version compatibility",
        "binary rollback",
    ] {
        assert!(
            rolling.contains(required),
            "missing rolling control: {required}"
        );
    }
    for required in [
        "currently revoked principal/key is rejected",
        "new empty database",
        "new empty object prefix",
        "Do not dispatch retained effects",
        "semantic-root",
    ] {
        assert!(
            recovery.contains(required),
            "missing recovery control: {required}"
        );
    }
    Ok(())
}
