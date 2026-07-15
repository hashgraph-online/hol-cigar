//! Optional local CIGAR protocol dashboard sidecar.
//!
//! This initial slice owns strict configuration parsing. Listener, session, gateway, and job
//! modules are added only after their complete security boundaries are available.

mod artifact;
mod assets;
mod config;
mod control;
mod cursor;
mod events;
mod evidence;
mod gateway;
mod history;
mod metrics;
mod profiles;
mod protocol;
mod receipt;
mod runs;
mod server;
mod session;
mod status;

pub use artifact::*;
pub use assets::*;
pub use config::*;
pub use control::*;
pub use cursor::*;
pub use events::*;
pub use evidence::*;
pub use gateway::*;
pub use history::*;
pub use metrics::*;
pub use profiles::*;
pub use protocol::*;
pub use receipt::*;
pub use runs::*;
pub use server::*;
pub use session::*;
pub use status::*;

#[cfg(test)]
mod architecture_tests {
    #[test]
    fn manifest_has_no_direct_daemon_storage_or_semantic_dependency()
    -> Result<(), Box<dyn std::error::Error>> {
        let manifest: toml::Value = toml::from_str(include_str!("../Cargo.toml"))?;
        let dependencies = manifest
            .get("dependencies")
            .and_then(toml::Value::as_table)
            .ok_or("dashboard dependencies missing")?;
        assert!(dependencies.contains_key("cigar-sdk"));
        for forbidden in [
            "cigar-daemon",
            "cigar-store",
            "cigar-protocol",
            "cigar-effects",
            "cigar-policy",
            "cigar-space",
        ] {
            assert!(!dependencies.contains_key(forbidden));
        }
        Ok(())
    }

    #[test]
    fn dashboard_is_absent_from_default_build_core_archive_and_base_deployments()
    -> Result<(), Box<dyn std::error::Error>> {
        let workspace: toml::Value = toml::from_str(include_str!("../../../Cargo.toml"))?;
        let default_members = workspace
            .get("workspace")
            .and_then(|value| value.get("default-members"))
            .and_then(toml::Value::as_array)
            .ok_or("workspace default members missing")?;
        assert!(default_members.iter().all(|member| {
            member
                .as_str()
                .is_some_and(|value| !value.contains("cigar-dashboard") && !value.contains("soak"))
        }));

        let runtime_contract: serde_json::Value = serde_json::from_str(include_str!(
            "../../../packaging/contracts/macos-runtime-archive.v1.json"
        ))?;
        let allowed = runtime_contract
            .get("allow")
            .and_then(serde_json::Value::as_array)
            .ok_or("runtime contract allowlist missing")?;
        assert!(allowed.iter().all(|entry| {
            entry
                .as_str()
                .is_some_and(|path| !path.contains("dashboard") && !path.contains("cigar-soak"))
        }));

        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .and_then(std::path::Path::parent)
            .ok_or("workspace root unavailable")?;
        let dockerfile = std::fs::read_to_string(root.join("deploy/docker/Dockerfile"))?;
        assert!(dockerfile.contains("--package cigar-daemon --bin cigard"));
        assert!(!dockerfile.contains("cigar-dashboard"));
        assert!(!dockerfile.contains("cigar-soak"));
        for directory in [
            root.join("deploy/compose"),
            root.join("deploy/kubernetes/shared"),
        ] {
            for entry in std::fs::read_dir(directory)? {
                let entry = entry?;
                let path = entry.path();
                if !path.is_file()
                    || !path
                        .extension()
                        .and_then(|value| value.to_str())
                        .is_some_and(|extension| matches!(extension, "yaml" | "yml"))
                {
                    continue;
                }
                let source = std::fs::read_to_string(path)?;
                assert!(!source.contains("cigar-dashboard"));
                assert!(!source.contains("cigar_dashboard"));
                assert!(!source.contains("cigar-soak"));
                assert!(!source.contains("cigar_soak"));
            }
        }
        Ok(())
    }
}
