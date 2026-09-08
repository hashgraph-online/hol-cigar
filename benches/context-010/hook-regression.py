#!/usr/bin/env python3
"""Run an identical deadline regression against isolated old/new hook source copies; no baseline edits."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[2]
PROBE = r'''
#[cfg(all(test, unix))]
mod pass2_deadline_probe {
    use super::*;
    #[tokio::test]
    async fn inherited_pipe_is_bounded() -> Result<(), Box<dyn std::error::Error>> {
        let result = tokio::time::timeout(Duration::from_millis(800), invoke_cli_with_binary_deadline(
            OsStr::new("/bin/sh"), &["-c", "sleep 2 & printf '%s' '{\"ok\":true}'"],
            None, &[], Duration::from_millis(100),
        )).await?;
        assert_eq!(result, Err(HookError::BackendUnavailable));
        Ok(())
    }
}
'''


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--baseline', type=Path, required=True)
    parser.add_argument('--cargo', type=Path, required=True)
    parser.add_argument('--target', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=False)
    env = dict(os.environ)
    env['PATH'] = str(args.cargo.parent) + os.pathsep + env.get('PATH', '')
    env['CARGO_TARGET_DIR'] = str(args.target)
    records = []
    for label, root in [('previous', args.baseline), ('current', ROOT)]:
        directory = args.output / label
        directory.mkdir()
        original = (root/'crates/cigar-claude-hook/src/lib.rs').read_text()
        (directory/'lib.rs').write_text(original + PROBE)
        manifest = f'''[package]
name = "hook-probe-{label}"
version = "0.0.0"
edition = "2024"
[workspace]
[lib]
path = "lib.rs"
[dependencies]
cigar-canon = {{ path = {json.dumps(str(args.baseline/'crates/cigar-canon'))} }}
serde = {{ version = "=1.0.228", features = ["derive"] }}
serde_json = "=1.0.150"
sha2 = "=0.11.0"
tokio = {{ version = "=1.52.3", features = ["fs", "io-util", "macros", "net", "rt", "rt-multi-thread", "signal", "sync", "time", "process"] }}
[dev-dependencies]
tempfile = "=3.27.0"
'''
        (directory/'Cargo.toml').write_text(manifest)
        (directory/'Cargo.lock').write_bytes((ROOT/'Cargo.lock').read_bytes())
        for run in range(3):
            result = subprocess.run([str(args.cargo), 'test', '--offline', '--lib', 'pass2_deadline_probe::'],
                                    cwd=directory, env=env, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
            log = f'{label}-{run}.log'
            (args.output/log).write_text(result.stdout)
            expected = result.returncode == (101 if label == 'previous' else 0)
            if not expected or (label == 'previous' and 'inherited_pipe_is_bounded ... FAILED' not in result.stdout):
                raise RuntimeError(result.stdout)
            records.append({'source':label, 'run':run, 'exit_code':result.returncode, 'expected':expected,
                            'original_source_sha256':hashlib.sha256(original.encode()).hexdigest(), 'log':log})
            print(json.dumps(records[-1]), flush=True)
    (args.output/'summary.json').write_text(json.dumps(records, indent=2)+'\n')


if __name__ == '__main__': main()
