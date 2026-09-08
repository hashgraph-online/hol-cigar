#!/usr/bin/env python3
"""Compare exact first/second 0.10.0 snapshots; preserve raw cold/warm/uncached observations."""
import argparse
import gzip
import hashlib
import json
import os
from pathlib import Path
import random
import re
import statistics
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[2]


def document(identity, text, source=None):
    return {"id": identity, "text": text, "source": source or "source/" + identity}


def fixtures(source):
    rng = random.Random(0xC10A020)
    cases = []
    for fixture in json.loads((ROOT/'crates/cigar-context/fixtures/quality.json').read_text()):
        docs = [document(identity, text, locator) for identity,locator,text in fixture['documents']]
        cases.append({'name': 'authored-' + fixture['id'], 'documents': docs, 'edges':fixture['edges'],
                      'requests':[{'query':fixture['query'], 'max_tokens':512,
                                   'evidence_per_term':fixture.get('evidence_per_term',1)}]})
    for seed in range(250):
        docs = [document(f"n{id:03}", f"{rng.choice(['alpha', 'beta', 'gamma'])} boundary item_{id % 13}\n"
                         + (f"fn item_{id % 13}() {{ /* é😀 */ }}\n" if id % 7 == 0 else "evidence contract\n")
                         + "padding " * rng.randrange(0, 30), f"source/{id % 19}") for id in range(rng.randrange(5, 100))]
        ids = [d['id'] for d in docs]
        edges = [[a, b, rng.choice(['requires', 'contradicts', 'supports', 'related'])]
                 for a, b in (rng.sample(ids, 2) for _ in range(len(ids) // 3))]
        requests = []
        for query in ["alpha boundary", f"item_{seed % 13}", "gamma contract", "no_such_concept"]:
            maximum = rng.choice([16, 32, 64, 128])
            request = {"query": query, "max_tokens": rng.choice([32, 64, 128, 512, 2048]),
                       "max_candidates": maximum, "max_blocks": min(maximum, rng.choice([1, 4, 16])),
                       "graph_depth": rng.choice([0, 1, 2, 4]), "evidence_per_term": rng.choice([1, 2, 3]),
                       "excerpt_mode": rng.choice(['full', 'query_windows'])}
            if seed % 3 == 0: request['allowed'] = rng.sample(ids, len(ids) // 2)
            if seed % 4 == 0: request['required'] = rng.sample(ids, 1)
            if seed % 5 == 0: request['semantic_candidates'] = rng.sample(ids, min(3, len(ids)))
            requests.append(request)
        cases.append({"name": f"generated-{seed:03}", "documents": docs, "edges": edges,
                      "withdrawals": rng.sample(ids, 1) if seed % 7 == 0 else [],
                      "upserts": [document(ids[0], "alpha UPDATED", "updated/source")] if seed % 11 == 0 else [],
                      "requests": requests})
    paths = sorted(path for package in ['cigar-compiler', 'cigar-policy', 'cigar-retrieval', 'cigar-protocol']
                   for path in (source / 'crates' / package / 'src').rglob('*.rs'))
    docs, bindings = [], []
    for index, path in enumerate(paths):
        data = path.read_bytes()
        locator = path.relative_to(source).as_posix()
        bindings.append({'path': locator, 'sha256': hashlib.sha256(data).hexdigest()})
        lines = data.decode().splitlines(keepends=True)
        for start in range(0, len(lines), 72):
            text = ''.join(lines[start:start+80])
            if text.strip():
                doc = document(f'file{index:03}:L{start+1}', text, locator)
                doc['start_line'] = start + 1
                docs.append(doc)
            if start + 80 >= len(lines): break
    probes = ["invalidate_scope tenant disclosure domain cache", "resolve_reference_tokenizer_target provider fingerprint",
              "apply_delta_verified target bundle digest", "verify_chain capability parent attenuation",
              "redact parse_pointer invalid pointer", "neighbors cosine vector partition",
              "count_exact UTF8 tokenizer fingerprint", "pack_positive_marginal closure utility"]
    cases.append({'name': 'real-source', 'documents': docs, 'warmups': 5, 'trials': 20,
                  'requests': [{'query': query, 'max_tokens': 2048, 'excerpt_mode': mode}
                               for query in probes for mode in ['full', 'query_windows']]})
    for size in [1000, 10000, 50000]:
        cases.append({'name': f'scale-{size}', 'documents': [document(f'n{id}',
                      f'shared concept evidence item{id} identity boundary', f'source/{id}') for id in range(size)],
                      'warmups': 5, 'trials': 20, 'requests': [{'query': query, 'max_tokens': 512}
                      for query in [f'item{size//2}', 'shared concept identity']]})
    return cases, bindings


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--baseline-package', type=Path, required=True)
    parser.add_argument('--source', type=Path, required=True)
    parser.add_argument('--cargo', type=Path, required=True)
    parser.add_argument('--target', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=False)
    env = dict(os.environ)
    env['PATH'] = str(args.cargo.parent) + os.pathsep + env.get('PATH', '')
    env['CARGO_TARGET_DIR'] = str(args.target)
    executables = {}
    for label, package in [('previous', args.baseline_package), ('current', ROOT/'crates/cigar-context')]:
        directory = args.output / label
        directory.mkdir()
        manifest = f'''[package]
name = "cigar-pass2-{label}"
version = "0.0.0"
edition = "2024"
[workspace]
[features]
pass2 = []
[dependencies]
cigar-context = {{ path = {json.dumps(str(package))}, features = ["bpe"] }}
serde = {{ version = "1", features = ["derive"] }}
serde_json = "1"
[[bin]]
name = "pass2-{label}"
path = {json.dumps(str(ROOT/'benches/context-010/pass2-oracle.rs'))}
[profile.release]
codegen-units = 1
lto = "thin"
'''
        (directory/'Cargo.toml').write_text(manifest)
        # Both adapters start from the identical workspace registry package bindings.
        (directory/'Cargo.lock').write_bytes((ROOT/'Cargo.lock').read_bytes())
        command = [str(args.cargo), 'build', '--release', '--offline']
        if label == 'current': command += ['--features', 'pass2']
        result = subprocess.run(command, cwd=directory, env=env, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        (directory/'build.log').write_text(result.stdout)
        if result.returncode: raise RuntimeError(result.stdout)
        executables[label] = args.target/'release'/f'pass2-{label}'
    locks = [json.loads('{}') for _ in range(2)]
    import tomllib
    for index, label in enumerate(['previous', 'current']):
        lock = tomllib.loads((args.output/label/'Cargo.lock').read_text())
        locks[index] = { (p['name'], p['version']): p.get('checksum') for p in lock['package'] if p.get('source') }
    if locks[0] != locks[1]: raise RuntimeError('adapter dependency drift')
    cases, bindings = fixtures(args.source)
    data = ''.join(json.dumps(case, ensure_ascii=False) + '\n' for case in cases).encode()
    (args.output/'inputs.jsonl.gz').write_bytes(gzip.compress(data, mtime=0))
    rows, footprints = {}, {}
    # Opposite ordering in the second round reduces simple run-order bias; retain both rounds.
    treatments = [('previous', 'uncached'), ('current', 'cold'), ('current', 'warm'), ('current', 'uncached')]
    for round_index in range(2):
        for label, mode in treatments if round_index == 0 else reversed(treatments):
            key = f'{label}-{mode}-{round_index}'
            print('running ' + key, flush=True)
            command = [str(executables[label]), mode]
            if sys.platform == 'darwin': command = ['/usr/bin/time', '-l', *command]
            result = subprocess.run(command, input=data, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            (args.output/(key+'.stderr.log')).write_bytes(result.stderr)
            (args.output/(key+'.jsonl.gz')).write_bytes(gzip.compress(result.stdout, mtime=0))
            if result.returncode: raise RuntimeError(result.stderr.decode())
            peak = re.search(r'(\d+)\s+maximum resident set size', result.stderr.decode())
            if peak: footprints[key] = int(peak.group(1))
            rows[key] = [json.loads(line) for line in result.stdout.splitlines()]
    baseline = rows['previous-uncached-0']
    exact = 0
    for key, values in rows.items():
        if len(values) != len(baseline): raise RuntimeError('row count mismatch')
        for expected, actual in zip(baseline, values, strict=True):
            if (expected['case'], expected['request'], expected['output']) != (actual['case'], actual['request'], actual['output']):
                raise RuntimeError(f"snapshot mismatch: {key} {actual['case']} {actual['request']}")
            if key.startswith('current'): exact += 1
    summary = {}
    for key, values in rows.items():
        for row in values:
            if row['case'].startswith(('generated', 'authored')): continue
            label = '-'.join(key.split('-')[:-1])
            group = row['case'] + (('-full' if row['request'] % 2 == 0 else '-windows') if row['case'] == 'real-source'
                                   else ('-selective' if row['request'] == 0 else '-common'))
            summary.setdefault(label + '/' + group, []).extend(row['latency_ns'])
    metrics = {key: {'samples':len(v), 'median_ns':statistics.median(v),
                     'p95_ns':sorted(v)[max(0, int(len(v)*.95)-1)]} for key,v in summary.items()}
    report = {'schema':'cigar.context-pass2.v1', 'comparisons':exact, 'distinct_requests':len(baseline),
              'baseline_successes':sum('ok' in v['output'] for v in baseline),
              'baseline_errors':sum('error' in v['output'] for v in baseline), 'metrics':metrics,
              'peak_process_rss_bytes': footprints,
              'index_build_ns': {key:{row['case']:row['build_ns'] for row in values if not row['case'].startswith('generated')}
                                 for key,values in rows.items()},
              'source_bindings':bindings,
              'binaries':{label:hashlib.sha256(path.read_bytes()).hexdigest() for label,path in executables.items()},
              'inputs_sha256':hashlib.sha256(data).hexdigest(),
              'limits':'Offline exact-output and latency diagnostics. Same queries as earlier source probes, not held-out model efficacy.'}
    (args.output/'summary.json').write_text(json.dumps(report, indent=2)+'\n')
    print(json.dumps({k:v for k,v in report.items() if k != 'source_bindings'}, indent=2), flush=True)


if __name__ == '__main__': main()
