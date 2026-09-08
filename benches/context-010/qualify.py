#!/usr/bin/env python3
"""Verify a local package and fresh external consumers. Does not publish or sign anything."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess

ROOT=Path(__file__).resolve().parents[2]


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--cargo',type=Path,required=True)
    parser.add_argument('--target',type=Path,required=True)
    parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args()
    args.output.mkdir(parents=True,exist_ok=False)
    environment=dict(os.environ)
    environment['PATH']=str(args.cargo.parent)+os.pathsep+environment.get('PATH','')
    environment['CARGO_TARGET_DIR']=str(args.target)
    records=[]
    def run(command,label,cwd=ROOT):
        result=subprocess.run([str(x) for x in command],cwd=cwd,env=environment,text=True,
                              stdout=subprocess.PIPE,stderr=subprocess.STDOUT,check=False)
        (args.output/(label+'.log')).write_text(result.stdout)
        records.append({'command':[str(x) for x in command],'exit_code':result.returncode,'log':label+'.log'})
        if result.returncode:
            print(result.stdout,flush=True)
            raise RuntimeError(f'{label} failed')
        return result.stdout
    run([args.cargo,'package','--locked','-p','cigar-context','--features','bpe','--allow-dirty'],'package')
    package=args.target/'package/cigar-context-0.10.0'
    manifest='''[package]
name = "cigar-context-clean-consumer"
version = "0.1.0"
edition = "2024"
[workspace]
[features]
bpe = ["cigar-context/bpe"]
[dependencies]
cigar-context = { path = PATH }
[[bin]]
name = "consumer"
path = SOURCE
'''.replace('PATH',json.dumps(str(package))).replace('SOURCE',json.dumps(str(ROOT/'benches/context-010/consumer.rs')))
    (args.output/'Cargo.toml').write_text(manifest)
    run([args.cargo,'generate-lockfile','--offline'],'lock',args.output)
    for feature in ['core','bpe']:
        flags=[] if feature=='core' else ['--features','bpe']
        run([args.cargo,'run','--locked',*flags],feature,args.output)
        tree=run([args.cargo,'tree','--locked','--edges','normal','--prefix','none',*flags],feature+'-tree',args.output)
        packages={line.removesuffix(' (*)') for line in tree.splitlines()}
        if any(name in tree for name in ['cigar-daemon','cigar-store','cigar-protocol','reqwest','rusqlite']):
            raise RuntimeError('standalone dependency regression')
        records.append({'feature':feature,'normal_dependency_lines':len(packages)})
    run([args.cargo,'test','--locked','--features','bpe','--manifest-path',package/'Cargo.toml'],'packaged-tests')
    archive=args.target/'package/cigar-context-0.10.0.crate'
    records.append({'archive_sha256':hashlib.sha256(archive.read_bytes()).hexdigest(),'archive_bytes':archive.stat().st_size})
    (args.output/'qualification.json').write_text(json.dumps(records,indent=2)+'\n')
    print(json.dumps(records,indent=2),flush=True)


if __name__=='__main__': main()
