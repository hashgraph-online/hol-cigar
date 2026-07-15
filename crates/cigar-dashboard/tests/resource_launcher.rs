#![cfg(all(target_os = "macos", target_arch = "aarch64"))]
//! Native macOS process-boundary checks for the private resource launcher.

use sha2::{Digest as _, Sha256};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant};

fn resolve(name: &str) -> Result<PathBuf, Box<dyn std::error::Error>> {
    if name == "python3" && Path::new("/usr/bin/python3").is_file() {
        return Ok(PathBuf::from("/usr/bin/python3"));
    }
    let path = std::env::var_os("PATH").ok_or("PATH is unavailable")?;
    std::env::split_paths(&path)
        .map(|directory| directory.join(name))
        .find(|candidate| candidate.is_file())
        .ok_or_else(|| format!("{name} is unavailable").into())
}

fn digest(path: &Path) -> Result<String, Box<dyn std::error::Error>> {
    let source = std::fs::read(path)?;
    Ok(Sha256::digest(source)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect())
}

#[test]
fn private_launcher_applies_child_only_kernel_limits() -> Result<(), Box<dyn std::error::Error>> {
    let launcher = env!("CARGO_BIN_EXE_cigar-dashboard");
    let python = resolve("python3")?.canonicalize()?;
    let output = Command::new(launcher)
        .args([
            "--internal-resource-launcher-v1",
            "10",
            "4096",
            "1024",
        ])
        .arg(&python)
        .arg(digest(&python)?)
        .arg("--")
        .args([
            "-c",
            "import resource; print(resource.getrlimit(resource.RLIMIT_CORE), resource.getrlimit(resource.RLIMIT_CPU), resource.getrlimit(resource.RLIMIT_FSIZE), resource.getrlimit(resource.RLIMIT_NOFILE))",
        ])
        .output()?;
    assert!(
        output.status.success(),
        "launcher failed: {:?}",
        output.stderr
    );
    assert_eq!(
        String::from_utf8(output.stdout)?.trim(),
        "(0, 0) (10, 10) (4096, 4096) (1024, 1024)"
    );
    Ok(())
}

#[test]
fn private_launcher_rejects_digest_substitution() -> Result<(), Box<dyn std::error::Error>> {
    let launcher = env!("CARGO_BIN_EXE_cigar-dashboard");
    let python = resolve("python3")?.canonicalize()?;
    let status = Command::new(launcher)
        .args(["--internal-resource-launcher-v1", "10", "4096", "1024"])
        .arg(&python)
        .arg("0".repeat(64))
        .args(["--", "--version"])
        .status()?;
    assert_eq!(status.code(), Some(126));
    Ok(())
}

#[test]
fn private_launcher_enforces_file_size_and_open_file_limits()
-> Result<(), Box<dyn std::error::Error>> {
    let launcher = env!("CARGO_BIN_EXE_cigar-dashboard");
    let python = resolve("python3")?.canonicalize()?;
    let python_digest = digest(&python)?;
    let directory = tempfile::tempdir()?;
    let output = directory.path().join("bounded-output");
    let file_status = Command::new(launcher)
        .args(["--internal-resource-launcher-v1", "10", "1024", "1024"])
        .arg(&python)
        .arg(&python_digest)
        .arg("--")
        .args([
            "-I",
            "-B",
            "-c",
            "import os,sys; handle=open(sys.argv[1], 'wb', buffering=0); written=handle.write(b'x' * 2048); handle.close(); sys.exit(0 if written == 1024 and os.stat(sys.argv[1]).st_size == 1024 else 3)",
        ])
        .arg(&output)
        .status()?;
    assert!(file_status.success());
    assert_eq!(std::fs::metadata(&output)?.len(), 1024);

    let descriptor_status = Command::new(launcher)
        .args(["--internal-resource-launcher-v1", "10", "4096", "1024"])
        .arg(&python)
        .arg(&python_digest)
        .arg("--")
        .args([
            "-I",
            "-B",
            "-c",
            "import errno,os,sys\nfds=[]\ntry:\n  while True: fds.append(os.open('/dev/null', os.O_RDONLY))\nexcept OSError as error:\n  sys.exit(0 if error.errno == errno.EMFILE and len(fds) < 1024 else 3)",
        ])
        .status()?;
    assert!(descriptor_status.success());
    Ok(())
}

#[test]
fn private_launcher_enforces_cpu_time_limit() -> Result<(), Box<dyn std::error::Error>> {
    let launcher = env!("CARGO_BIN_EXE_cigar-dashboard");
    let python = resolve("python3")?.canonicalize()?;
    let started = Instant::now();
    let status = Command::new(launcher)
        .args(["--internal-resource-launcher-v1", "1", "4096", "1024"])
        .arg(&python)
        .arg(digest(&python)?)
        .arg("--")
        .args(["-I", "-B", "-c", "while True: pass"])
        .status()?;
    assert!(!status.success());
    assert!(started.elapsed() < Duration::from_secs(10));
    Ok(())
}
