//! WP12 deterministic fault model and true subprocess-kill crash-matrix coverage.
//!
//! Normal CI kills one child at every EFX-C01 through EFX-C24 boundary. Release qualification
//! scales the same executable gate with `CIGAR_EFFECT_RC_REPETITIONS=1000`; the test intentionally
//! does not pretend that the default single repetition satisfies that release-only threshold.

use cigar_effects::{
    EffectCrashPoint, EffectFaultModel, FaultSnapshot, ModelAmbiguity, ModelEffectState,
    RecoveryDisposition, run_fault_campaign,
};
use std::collections::BTreeSet;
use std::fs::{File, OpenOptions};
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::thread;
use std::time::Duration;

const CHILD_POINT: &str = "CIGAR_EFFECT_FAULT_CHILD_POINT";
const CHILD_SEED: &str = "CIGAR_EFFECT_FAULT_CHILD_SEED";
const CHILD_SNAPSHOT: &str = "CIGAR_EFFECT_FAULT_CHILD_SNAPSHOT";
const CHILD_READY: &str = "CIGAR_EFFECT_FAULT_CHILD_READY";
const RC_REPETITIONS: &str = "CIGAR_EFFECT_RC_REPETITIONS";

#[test]
fn stable_catalog_is_complete_unique_and_parseable() {
    let mut ids = BTreeSet::new();
    let mut checkpoints = BTreeSet::new();
    for (index, point) in EffectCrashPoint::ALL.iter().copied().enumerate() {
        assert_eq!(point.id(), format!("EFX-C{:02}", index + 1));
        assert_eq!(EffectCrashPoint::from_id(point.id()), Some(point));
        assert!(ids.insert(point.id()));
        assert!(checkpoints.insert(point.checkpoint()));
        assert!(point.checkpoint().starts_with("effect.v1."));
    }
    assert_eq!(ids.len(), 24);
    assert_eq!(checkpoints.len(), 24);
    assert_eq!(EffectCrashPoint::from_id("EFX-C00"), None);
    assert_eq!(EffectCrashPoint::from_id("efx-c01"), None);
}

#[test]
fn every_matrix_row_recovers_to_its_exact_contract() -> Result<(), Box<dyn std::error::Error>> {
    for point in EffectCrashPoint::ALL {
        for seed in 0..256_u64 {
            let snapshot = EffectFaultModel::inject(point, seed);
            assert_eq!(snapshot.point(), point);
            assert_eq!(snapshot.seed(), seed);
            let encoded = snapshot.to_json()?;
            let decoded = FaultSnapshot::from_json(&encoded)?;
            assert_eq!(decoded, snapshot);
            decoded.recover().verify()?;
        }
    }
    Ok(())
}

#[test]
fn atomic_and_ambiguity_boundaries_expose_both_deterministic_branches()
-> Result<(), Box<dyn std::error::Error>> {
    let uncommitted =
        EffectFaultModel::inject(EffectCrashPoint::AttemptBeforeOutboxCommit, 0).recover();
    let committed =
        EffectFaultModel::inject(EffectCrashPoint::AttemptBeforeOutboxCommit, 1).recover();
    uncommitted.verify()?;
    committed.verify()?;
    assert_eq!(uncommitted.state(), ModelEffectState::Authorized);
    assert_eq!(
        uncommitted.disposition(),
        RecoveryDisposition::ClaimDispatch
    );
    assert_eq!(committed.state(), ModelEffectState::Dispatching);
    assert_eq!(
        committed.disposition(),
        RecoveryDisposition::ResumeFencedDispatch
    );

    let no_commit =
        EffectFaultModel::inject(EffectCrashPoint::RequestPartiallyWritten, 0).recover();
    let possible_commit =
        EffectFaultModel::inject(EffectCrashPoint::RequestPartiallyWritten, 1).recover();
    no_commit.verify()?;
    possible_commit.verify()?;
    assert_eq!(no_commit.remote_commit_count(), 0);
    assert_eq!(possible_commit.remote_commit_count(), 1);
    assert_eq!(no_commit.state(), ModelEffectState::Unknown);
    assert_eq!(
        possible_commit.ambiguity(),
        ModelAmbiguity::RequestMayHaveCommitted
    );
    assert_eq!(no_commit.connector_calls(), 1);
    Ok(())
}

#[test]
fn one_hundred_thousand_possible_commit_campaign_has_no_duplicate_or_blind_retry()
-> Result<(), Box<dyn std::error::Error>> {
    let report = run_fault_campaign(100_000, 0xc1_6a_12_ef_5e_ed_u64)?;
    assert_eq!(report.logical_effects(), 100_000);
    assert_eq!(report.possible_remote_commit_operations(), 100_000);
    assert!(report.explicit_ambiguities() > 0);
    assert!(report.explicit_ambiguities() < 100_000);
    assert_eq!(report.duplicate_logical_effects(), 0);
    assert_eq!(report.blind_redispatches(), 0);
    Ok(())
}

#[test]
fn effect_fault_process_child() -> Result<(), Box<dyn std::error::Error>> {
    let Ok(point_id) = std::env::var(CHILD_POINT) else {
        return Ok(());
    };
    let point = EffectCrashPoint::from_id(&point_id).ok_or("unknown child crash point")?;
    let seed = std::env::var(CHILD_SEED)?.parse::<u64>()?;
    let snapshot_path = PathBuf::from(std::env::var(CHILD_SNAPSHOT)?);
    let ready_path = PathBuf::from(std::env::var(CHILD_READY)?);
    let snapshot = EffectFaultModel::inject(point, seed);
    write_atomic(&snapshot_path, &snapshot.to_json()?)?;
    write_atomic(&ready_path, point.checkpoint().as_bytes())?;
    loop {
        thread::park();
    }
}

#[test]
fn efx_c01_through_c24_use_real_process_kill_and_fresh_recovery()
-> Result<(), Box<dyn std::error::Error>> {
    let repetitions = match std::env::var(RC_REPETITIONS) {
        Ok(value) => value.parse::<u32>()?,
        Err(std::env::VarError::NotPresent) => 1,
        Err(error) => return Err(error.into()),
    };
    if repetitions == 0 {
        return Err("process-kill repetitions must be non-zero".into());
    }
    let executable = std::env::current_exe()?;
    let root =
        std::env::temp_dir().join(format!("cigar-effects-wp12-faults-{}", std::process::id()));
    if root.exists() {
        std::fs::remove_dir_all(&root)?;
    }
    std::fs::create_dir_all(&root)?;

    for repetition in 0..repetitions {
        for (point_index, point) in EffectCrashPoint::ALL.iter().copied().enumerate() {
            let seed = u64::from(repetition)
                .checked_mul(24)
                .and_then(|value| value.checked_add(u64::try_from(point_index).ok()?))
                .ok_or("process-kill seed overflow")?;
            let case = root.join(format!("{}-{repetition:04}", point.id()));
            std::fs::create_dir_all(&case)?;
            let snapshot_path = case.join("snapshot.json");
            let ready_path = case.join("ready");
            let mut child = Command::new(&executable)
                .args(["--exact", "effect_fault_process_child", "--nocapture"])
                .env(CHILD_POINT, point.id())
                .env(CHILD_SEED, seed.to_string())
                .env(CHILD_SNAPSHOT, &snapshot_path)
                .env(CHILD_READY, &ready_path)
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()?;

            wait_until_ready(&mut child, &ready_path)?;
            assert_eq!(std::fs::read_to_string(&ready_path)?, point.checkpoint());
            child.kill()?;
            let status = child.wait()?;
            assert!(!status.success());

            let snapshot = FaultSnapshot::from_json(&std::fs::read(&snapshot_path)?)?;
            assert_eq!(snapshot.point(), point);
            assert_eq!(snapshot.seed(), seed);
            snapshot.recover().verify()?;
        }
    }
    std::fs::remove_dir_all(root)?;
    Ok(())
}

fn write_atomic(path: &Path, bytes: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
    let temporary = path.with_extension("tmp");
    let mut file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&temporary)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    drop(file);
    std::fs::rename(temporary, path)?;
    sync_parent(path)?;
    Ok(())
}

#[cfg(unix)]
fn sync_parent(path: &Path) -> Result<(), Box<dyn std::error::Error>> {
    let parent = path.parent().ok_or("checkpoint path has no parent")?;
    File::open(parent)?.sync_all()?;
    Ok(())
}

#[cfg(not(unix))]
fn sync_parent(_path: &Path) -> Result<(), Box<dyn std::error::Error>> {
    Ok(())
}

fn wait_until_ready(
    child: &mut std::process::Child,
    ready_path: &Path,
) -> Result<(), Box<dyn std::error::Error>> {
    for _poll in 0..2_500_u16 {
        if ready_path.exists() {
            return Ok(());
        }
        if let Some(status) = child.try_wait()? {
            return Err(format!("fault child exited before checkpoint: {status}").into());
        }
        thread::sleep(Duration::from_millis(2));
    }
    child.kill()?;
    let _status = child.wait()?;
    Err("fault child did not publish its checkpoint".into())
}
