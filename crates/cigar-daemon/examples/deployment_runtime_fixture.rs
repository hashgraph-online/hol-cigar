//! Export parsed deployment inputs for the disposable Linux runtime checks.

use cigar_daemon::DaemonConfig;
use serde_json::{Value, json};
use std::fs;
use std::io::Write as _;
use std::path::Path;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let read = |path: &str| fs::read_to_string(root.join(path));
    let deployment: Value =
        yaml_serde::from_str(&read("deploy/kubernetes/shared/deployment.yaml")?)?;
    let configmap: Value = yaml_serde::from_str(&read("deploy/kubernetes/shared/configmap.yaml")?)?;
    let shared = DaemonConfig::from_toml(
        configmap
            .pointer("/data/cigard.toml")
            .and_then(Value::as_str)
            .ok_or("missing shared configuration")?,
    )?;
    let local = DaemonConfig::from_toml(&read("deploy/docker/cigard.example.toml")?)?;
    let fixture = json!({
        "schema": "cigar.deployment-boundary-fixture.v1",
        "systemd_unit": read("deploy/systemd/cigard.service")?,
        "tmpfiles": read("deploy/systemd/cigar.tmpfiles")?,
        "checkpoint_file": local.production.effect_checkpoint_file,
        "telemetry_ca_file": shared.telemetry.otlp_ca_certificate_file,
        "deployment": deployment,
    });
    serde_json::to_writer(std::io::stdout().lock(), &fixture)?;
    std::io::stdout().lock().write_all(b"\n")?;
    Ok(())
}
