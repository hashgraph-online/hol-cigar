#!/usr/bin/env python3
"""Retain exact local diagnostic artifacts and source hashes in a new report directory."""
import argparse
import gzip
import hashlib
import json
from pathlib import Path
import subprocess

ROOT=Path(__file__).resolve().parents[2]


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    for name in ['run','earlier','context-validation','workspace-validation','qualification','output']:
        parser.add_argument('--'+name,type=Path,required=True)
    parser.add_argument('--workspace-repeat',type=Path)
    parser.add_argument('--hook-rechecks',type=Path)
    parser.add_argument('--binaries',type=Path)
    parser.add_argument('--archive',type=Path)
    args=parser.parse_args()
    args.output.mkdir(parents=True,exist_ok=False)
    artifacts={}
    def retain(source,name):
        data=source.read_bytes()
        (args.output/(name+'.gz')).write_bytes(gzip.compress(data,mtime=0))
        artifacts[name+'.gz']={'uncompressed_sha256':hashlib.sha256(data).hexdigest(),'uncompressed_bytes':len(data)}
    for name in ['comparison.json','graph-raw.json','source-comparison.json']:
        retain(args.run/name,name)
    retain(args.earlier/'source-comparison.json','initial-selector-source-comparison.json')
    for directory,label in [(args.context_validation,'context'),(args.workspace_validation,'workspace'),(args.qualification,'package')]:
        for path in sorted(directory.iterdir()):
            if path.suffix in ['.json','.log','.lock']:
                retain(path,label+'-'+path.name)
    if args.workspace_repeat:
        for path in sorted(args.workspace_repeat.iterdir()):
            if path.suffix in ['.json','.log']:
                retain(path,'workspace-repeat-'+path.name)
    if args.hook_rechecks:
        retain(args.hook_rechecks,'hook-baseline-and-candidate-rechecks.json')
    if args.archive:
        data=args.archive.read_bytes()
        name='cigar-context-0.10.0.crate'
        (args.output/name).write_bytes(data)
        artifacts[name]={'stored_sha256':hashlib.sha256(data).hexdigest(),'stored_bytes':len(data)}
    paths=[ROOT/'Cargo.toml',ROOT/'Cargo.lock',ROOT/'crates/cigar-compiler/src/packing_workspace.rs',
           ROOT/'scripts/dev.py',ROOT/'.github/workflows/context-library.yml']
    for directory in ['crates/cigar-context','benches/context-010']:
        paths.extend(path for path in (ROOT/directory).rglob('*') if path.is_file() and '__pycache__' not in path.parts)
    binding={'base_commit':subprocess.check_output(['git','rev-parse','HEAD'],cwd=ROOT,text=True).strip(),
             'source_files':{str(path.relative_to(ROOT)):hashlib.sha256(path.read_bytes()).hexdigest() for path in sorted(paths)},
             'artifacts':artifacts,'status':'Local development diagnostics, not signed release qualification'}
    if args.binaries:
        binding['benchmark_binaries']={str(path.relative_to(args.binaries)):hashlib.sha256(path.read_bytes()).hexdigest()
            for path in [args.binaries/'release/examples/compare',args.binaries/'release/examples/source_compare']}
    (args.output/'manifest.json').write_text(json.dumps(binding,indent=2)+'\n')
    print(f'Retained {len(artifacts)} artifacts and {len(paths)} source hashes in {args.output}',flush=True)


if __name__=='__main__': main()
