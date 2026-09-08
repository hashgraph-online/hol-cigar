#!/usr/bin/env python3
"""Repeat the unchanged handoff authority assertions without relaxing their two-second deadline."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import time


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--runs', type=int, default=100)
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=False)
    results = []
    name = 'tests::subagent_handoff_never_substitutes_the_parent_bundle'
    for index in range(args.runs):
        started = time.perf_counter_ns()
        result = subprocess.run([str(args.binary), '--exact', name], stdout=subprocess.PIPE,
                                stderr=subprocess.STDOUT, text=True, timeout=10)
        if f'{name} ... ok' not in result.stdout and result.returncode == 0:
            raise RuntimeError('requested test did not run')
        results.append({'run':index, 'exit_code':result.returncode,
                        'process_elapsed_ns':time.perf_counter_ns()-started, 'output':result.stdout})
    report = {'binary_sha256':hashlib.sha256(args.binary.read_bytes()).hexdigest(), 'results':results,
              'passed':sum(row['exit_code'] == 0 for row in results), 'runs':args.runs}
    (args.output/'summary.json').write_text(json.dumps(report, indent=2)+'\n')
    print(json.dumps({key:value for key,value in report.items() if key != 'results'}), flush=True)
    return report['passed'] != args.runs


if __name__ == '__main__': raise SystemExit(main())
