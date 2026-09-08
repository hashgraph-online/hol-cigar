#!/usr/bin/env python3
"""Retain exact second-pass diagnostics, prior failed experiments and final source commitments."""
import argparse
from datetime import datetime, timezone
import gzip
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def sha(data): return hashlib.sha256(data).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ['comparison', 'core', 'workspace', 'workspace-parallel', 'workspace-parallel-success', 'package', 'archive',
                 'hook-proof', 'hook-repeat', 'hook-failed', 'advisories', 'initial-index', 'output']:
        parser.add_argument('--' + name, type=Path, required=True)
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=False)
    artifacts = {}

    def retain(path, name):
        stored = path.read_bytes()
        if path.suffix == '.gz':
            raw = gzip.decompress(stored)
            if not name.endswith('.gz'): name += '.gz'
        elif path.suffix == '.crate':
            raw = stored
        else:
            raw = stored
            stored = gzip.compress(raw, mtime=0)
            name += '.gz'
        if name in artifacts: raise RuntimeError('duplicate evidence name')
        (args.output/name).write_bytes(stored)
        artifacts[name] = {'stored_sha256':sha(stored), 'stored_bytes':len(stored),
                           'uncompressed_sha256':sha(raw), 'uncompressed_bytes':len(raw)}

    for label, directory in [('comparison', args.comparison), ('core', args.core), ('workspace', args.workspace),
                             ('workspace-parallel-failed', args.workspace_parallel),
                             ('workspace-parallel-success', args.workspace_parallel_success), ('package', args.package),
                             ('hook-proof', args.hook_proof), ('hook-repeat', args.hook_repeat), ('hook-failed', args.hook_failed)]:
        for path in sorted(directory.rglob('*')):
            if path.is_file() and (path.suffix in ['.json', '.gz', '.log', '.toml', '.lock', '.rs']):
                retain(path, label + '-' + path.relative_to(directory).as_posix().replace('/', '-'))
    retain(args.archive, args.archive.name)
    retain(args.advisories, 'advisories.json')
    retain(args.initial_index, 'intermediate-large-line-index-summary.json')
    sources = {ROOT/name for name in ['Cargo.toml', 'Cargo.lock', 'README.md', 'scripts/dev.py',
        '.github/workflows/context-library.yml', '.config/nextest.toml',
        'crates/cigar-compiler/src/packing_workspace.rs', 'crates/cigar-claude-hook/src/lib.rs',
        'docs/proposals/cigar-0.10.0-plan.md', 'reports/cigar-0.10.0-second-pass.md']}
    for directory in [ROOT/'crates/cigar-context', ROOT/'benches/context-010']:
        sources.update(path for path in directory.rglob('*') if path.is_file()
                       and (path.suffix in ['.rs', '.py', '.json', '.toml', '.md'] or path.name == 'LICENSE'))
    manifest = {'schema':'cigar.context-pass2-evidence.v1', 'created_at':datetime.now(timezone.utc).isoformat(),
                'status':'Local release-readiness diagnostics; no upload, signature, or full Honey qualification',
                'original_010_archive':'../context-010/cigar-context-0.10.0.crate',
                'original_010_archive_sha256':'065e080c271a62d328bc7953b5f6e98f223023a039cd878c18c243cc76ca6d4e',
                'source_files':{path.relative_to(ROOT).as_posix():sha(path.read_bytes()) for path in sorted(sources)},
                'artifacts':artifacts}
    (args.output/'manifest.json').write_text(json.dumps(manifest, indent=2)+'\n')
    print(json.dumps({'source_files':len(sources), 'artifacts':len(artifacts)}), flush=True)


if __name__ == '__main__': main()
