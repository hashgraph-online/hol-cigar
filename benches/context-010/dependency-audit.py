#!/usr/bin/env python3
"""Query OSV for public registry names/versions in the standalone consumer lockfile; no source upload."""
import argparse
from datetime import datetime, timezone
import json
import tomllib
from urllib.request import Request, urlopen


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--lockfile', required=True)
    parser.add_argument('--output', required=True)
    args = parser.parse_args()
    with open(args.lockfile, 'rb') as file:
        packages = tomllib.load(file)['package']
    queries = [{'package': {'name': p['name'], 'ecosystem': 'crates.io'}, 'version': p['version']}
               for p in packages if p.get('source', '').startswith('registry+')]
    request = Request('https://api.osv.dev/v1/querybatch', json.dumps({'queries': queries}).encode(),
                      {'Content-Type': 'application/json', 'User-Agent': 'cigar-context-release-diagnostics/0.10.0'})
    with urlopen(request, timeout=60) as response:
        result = json.load(response)
    if len(result.get('results', [])) != len(queries):
        raise RuntimeError('incomplete advisory response')
    findings = [{'query':query, 'advisories':row['vulns']} for query,row in zip(queries,result['results'],strict=True)
                if row.get('vulns')]
    report = {'checked_at': datetime.now(timezone.utc).isoformat(), 'endpoint': request.full_url,
              'registry_packages':len(queries), 'queries':queries, 'response':result, 'findings':findings,
              'limitations':'Point-in-time known-advisory lookup, not a source security audit or proof of absence.'}
    with open(args.output, 'x') as file: json.dump(report, file, indent=2)
    print(json.dumps({'registry_packages':len(queries), 'findings':findings}), flush=True)
    return bool(findings)


if __name__ == '__main__': raise SystemExit(main())
