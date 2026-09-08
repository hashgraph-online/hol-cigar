#!/usr/bin/env python3
"""Build exact-source compiler adapters and compare them with the 0.10 context library.

All outputs are diagnostic. Creates a new output directory; never edits baseline sources.
"""
from __future__ import annotations
import argparse
import hashlib
import json
import os
from pathlib import Path
import random
import statistics
import subprocess
import tomllib

ROOT = Path(__file__).resolve().parents[2]


def run(command, **kwargs):
    return subprocess.run([str(x) for x in command], check=True, text=True, **kwargs)


def build_adapter(source, label, feature, cargo, output, environment):
    manifest = tomllib.loads((source / "Cargo.toml").read_text())
    work = output / label
    work.mkdir()
    dependency_lines = []
    for name in ("cigar-compiler", "cigar-policy", "cigar-protocol", "cigar-retrieval"):
        dependency_lines.append(f'{name} = {{ path = {json.dumps(str(source / "crates" / name))} }}')
    dependency_lines.append('serde = { version = "=1.0.228", features = ["derive"] }')
    dependency_lines.append('serde_json = { version = "=1.0.150" }')
    patches = []
    for name, value in manifest.get("patch", {}).get("crates-io", {}).items():
        if "path" in value:
            patches.append(f'{name} = {{ path = {json.dumps(str(source / value["path"]))} }}')
    content = ('[package]\nname = "' + label + '"\nversion = "0.1.0"\nedition = "2024"\n'
        '[workspace]\n[features]\nlegacy92 = []\nlegacy93 = []\n'
        '[dependencies]\n' + '\n'.join(dependency_lines) + '\n'
        '[[bin]]\nname = "' + label + '"\npath = ' + json.dumps(str(ROOT / 'benches/context-010/legacy.rs')) + '\n'
        '[patch.crates-io]\n' + '\n'.join(patches) + '\n'
        '[profile.release]\ncodegen-units = 1\nlto = "thin"\n')
    (work / "Cargo.toml").write_text(content)
    (work / "Cargo.lock").write_bytes((source / "Cargo.lock").read_bytes())
    command = [cargo, 'build', '--release', '--manifest-path', work / 'Cargo.toml']
    if feature:
        command += ['--features', feature]
    with (work / 'build.log').open('w') as log:
        try:
            run(command, env=environment, stdout=log, stderr=subprocess.STDOUT)
        except subprocess.CalledProcessError:
            print((work / 'build.log').read_text(), flush=True)
            raise
    original = {(p['name'], p['version']): p.get('checksum') for p in tomllib.loads((source/'Cargo.lock').read_text())['package']}
    resolved = tomllib.loads((work/'Cargo.lock').read_text())['package']
    added = [(p['name'],p['version']) for p in resolved if p['name'] != label
             and ((p['name'],p['version']) not in original
                  or original[(p['name'],p['version'])] != p.get('checksum'))]
    if added:
        raise RuntimeError(f'baseline dependency drift: {added}')
    binary = Path(environment['CARGO_TARGET_DIR'])/'release'/label
    print(f'Built {label}: {source}', flush=True)
    return binary


def ask(process, value):
    process.stdin.write(json.dumps(value) + '\n')
    process.stdin.flush()
    line = process.stdout.readline()
    if not line:
        raise RuntimeError('compiler adapter terminated unexpectedly')
    return json.loads(line)


def metrics(rows):
    groups = {}
    for row in rows:
        groups.setdefault(row['treatment'], []).append(row)
    summary = {}
    for label, values in groups.items():
        times = sorted(v['latency_ns'] / 1000 for v in values)
        summary[label] = {
            'observations': len(values), 'mean_tokens': statistics.mean(v['tokens'] for v in values),
            'fact_recall': sum(v['facts_found'] for v in values) / sum(v['facts_required'] for v in values),
            'answerable_fraction': statistics.mean(v['answerable'] for v in values),
            'budget_fit_fraction': statistics.mean(v['budget_fits'] for v in values),
            'p50_us': statistics.median(times), 'p95_us': times[int(.95*(len(times)-1))],
        }
    return summary


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--baseline92', type=Path, required=True)
    parser.add_argument('--baseline93', type=Path, required=True)
    parser.add_argument('--baseline94', type=Path, required=True)
    parser.add_argument('--cargo', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--target', type=Path, required=True)
    parser.add_argument('--source-evaluation', action='store_true', help='Also evaluate real baseline source and index scale')
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=False)
    environment = dict(os.environ)
    environment['PATH'] = str(args.cargo.parent) + os.pathsep + environment.get('PATH','')
    environment['CARGO_TARGET_DIR'] = str(args.target)
    bindings = {}
    binaries = {}
    sources = [(args.baseline92,'compiler092','legacy92',1),
               (args.baseline93,'compiler093','legacy93',3),
               (args.baseline94,'compiler094','',4),(ROOT,'compiler010','',4)]
    for source,label,feature,profile in sources:
        bindings[label] = {'commit':run(['git','-C',source,'rev-parse','HEAD'],capture_output=True).stdout.strip(),
            'tree':run(['git','-C',source,'rev-parse','HEAD^{tree}'],capture_output=True).stdout.strip(),
            'dirty':bool(run(['git','-C',source,'status','--porcelain'],capture_output=True).stdout.strip()),
            'profile':profile}
        binaries[label] = build_adapter(source,label,feature,args.cargo,args.output,environment)
        bindings[label]['binary_sha256'] = hashlib.sha256(binaries[label].read_bytes()).hexdigest()
    run([args.cargo,'build','--release','--locked','-p','cigar-context','--features','bpe','--example','compare'],
        cwd=ROOT,env=environment)
    current = json.loads(run([args.target/'release/examples/compare'],capture_output=True).stdout)
    (args.output/'graph-raw.json').write_text(json.dumps(current,indent=2)+'\n')
    processes = {label:subprocess.Popen([str(binary)],stdin=subprocess.PIPE,stdout=subprocess.PIPE,text=True)
                 for label,binary in binaries.items()}
    rows = list(current['observations'])
    oracle = []
    try:
        randomizer = random.Random(1000)
        for case in current['legacy_inputs']:
            for trial in range(35):
                order = list(processes)
                randomizer.shuffle(order)
                outputs = {}
                for label in order:
                    value = dict(case,profile=bindings[label]['profile'])
                    result = ask(processes[label],value)
                    outputs[label] = result
                    if trial >= 5:
                        text = '\n'.join(d['text'] for d in case['documents'] if d['id'] in result['selected'])
                        found = sum(fact.lower() in text.lower() for fact in case['facts'])
                        rows.append({'case':case['id'],'treatment':label,'trial':trial-5,
                            'tokens':result['tokens'],'latency_ns':result['latency_ns'],
                            'facts_found':found,'facts_required':len(case['facts']),
                            'answerable':found==len(case['facts']),'budget_fits':result['tokens']<=case['budget'],
                            'selected':result['selected'],'error':result.get('error')})
                a={k:v for k,v in outputs['compiler094'].items() if k!='latency_ns'}
                b={k:v for k,v in outputs['compiler010'].items() if k!='latency_ns'}
                if a != b:
                    raise RuntimeError(f'0.9.4 output regression in {case["id"]}')
        # 200 varying cases exercise multiple entity overlaps, costs, empty matches and budgets.
        for seed in range(200):
            rng=random.Random(seed)
            count=8+seed%121
            value={'id':f'oracle-{seed}','query':'deterministic comparison','budget':1+seed*11,
                   'documents':[{'id':f'n{i}','tokens':rng.randint(1,100),'bits':rng.getrandbits(64),
                                 'exact':rng.choice([0,8000,10000])} for i in range(count)],
                   'edges':[],'profile':4}
            a=ask(processes['compiler094'],value)
            b=ask(processes['compiler010'],value)
            same={k:v for k,v in a.items() if k!='latency_ns'}=={k:v for k,v in b.items() if k!='latency_ns'}
            oracle.append({'seed':seed,'candidates':count,'equal':same,'baseline_ns':a['latency_ns'],'candidate_ns':b['latency_ns'],
                           'baseline_error':a.get('error'),'candidate_error':b.get('error'),
                           'selected_documents':len(a['selected']),
                           'output_sha256':hashlib.sha256(json.dumps({k:v for k,v in a.items() if k!='latency_ns'},sort_keys=True).encode()).hexdigest()})
            if not same:
                raise RuntimeError(f'0.9.4 complete output regression at seed {seed}')
        packing=[]
        for shape, exact in [('lexical_only',0),('exact_matches',8000)]:
            for size in (128,512,1024):
                value={'id':f'packing-{size}','query':'packing comparison','budget':size,'documents':[
                    {'id':f'n{i}','tokens':1,'bits':1 << (i%64),'exact':exact} for i in range(size)],'edges':[],'profile':4}
                for trial in range(110):
                    outputs={}
                    for label in randomizer.sample(['compiler094','compiler010'],2):
                        result=ask(processes[label],value)
                        outputs[label]={k:v for k,v in result.items() if k!='latency_ns'}
                        if trial>=10:
                            packing.append({'shape':shape,'size':size,'trial':trial-10,'treatment':label,'latency_ns':result['latency_ns'],
                                'tokens':result['tokens'],'bundle_id':result.get('bundle',{}).get('bundle_id'),'error':result.get('error')})
                    if outputs['compiler094'] != outputs['compiler010']:
                        raise RuntimeError(f'packing output regression: {shape}, {size}')
        report={'bindings':bindings,'summary':metrics(rows),'observations':rows,'oracle':oracle,'packing':packing,
            'limitations':['Authored corpus: repetitions measure timing, not independent quality samples.',
                'Legacy adapter uses query-derived features and complete document counts, not native daemon retrieval.',
                'Old token totals sum per-block BPE counts; new library recounts final rendering.',
                'Both graph and BM25 index construction are outside query timing. Full-context timing is rendering only; compiler timings exclude retrieval and text rendering.',
                'No live model, no output-token or model-answer accuracy measurement.']}
        (args.output/'comparison.json').write_text(json.dumps(report,indent=2)+'\n')
        print(json.dumps(report['summary'],indent=2),flush=True)
        if args.source_evaluation:
            run([args.cargo,'build','--release','--locked','-p','cigar-context','--features','bpe','--example','source_compare'],
                cwd=ROOT,env=environment)
            source=json.loads(run([args.target/'release/examples/source_compare',args.baseline94],capture_output=True).stdout)
            (args.output/'source-comparison.json').write_text(json.dumps(source,indent=2)+'\n')
            print(f'Real-source comparison: {source["files"]} files, {source["chunks"]} chunks; scale up to 50,000 documents.',flush=True)
    finally:
        for process in processes.values():
            process.stdin.close()
            process.wait(timeout=10)


if __name__=='__main__':
    main()
