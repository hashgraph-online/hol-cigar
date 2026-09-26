# 0.12.0 versus 0.13.0-alpha.1: local shared-context evaluation

The alpha supports five cooperating agents through host-scoped views of one local
worker/index. Python identity is `0.13.0a1`; npm/Rust use `0.13.0-alpha.1`.
This is local macOS ARM64 qualification, not a registry or production release.
The archive SDK commit is `7c3a348112b6d3538b323a09724fd2de92b89c74`.

## Paired results

Eight fresh-process cohorts per corpus, alternating version/mode order, installed
packages, Python 3.14.7, protobuf 6.33.5, macOS 26.6.1 ARM64, OS-denied networking.
All five agents compile/review, then one source changes before assessment. The
changed agent must re-review; the other four should retain their evidence.

| 384-document workload | 0.12 shared root | 0.12 five private graphs | 0.13 five views |
| --- | ---: | ---: | ---: |
| Workers | 1 | 5 | 1 |
| Document copies | 384 | 640 | 384 |
| Correct unaffected answers released | 0/1,600 | 1,600/1,600 | 1,600/1,600 |
| Genuinely stale answers rejected | 400/400 | 400/400 | 400/400 |
| Sampled worker RSS | 58.51 MB | 285.64 MB | 58.72 MB |
| Construction median | 55.03 ms | 277.17 ms | 55.22 ms |
| Compile median | 0.326 ms | 0.326 ms | 0.303 ms |
| Compile p95 | 0.361 ms | 0.382 ms | 0.336 ms |

At 3,072 documents (1,024 readable per agent), the alpha released all 640 unaffected
answers and rejected all 160 genuinely stale answers. RSS was 66.18 MB versus
302.55 MB for five private graphs; compile medians were 0.670 versus 0.879 ms.
The sharing benefit is 78–79% less worker RSS and approximately 80% less graph
construction time than five private graphs. View calls also avoid transmitting a
large allowed-ID list repeatedly. This is a complete API-path comparison, not a
claim that scope hashing alone is faster.

No scope, budget or citation assertion failed. All 80 false high-confidence claims
with independent contradiction verdicts and 80 missing-review cases abstained in
the scoped cohorts. These are scripted contract tests, not model-quality evidence.

## Compatibility and costs

All 172 existing context fixtures matched installed 0.12 exactly. Every old Python
public export, method signature and TypedDict shape is preserved. Root methods
keep their global-revision freshness semantics. Existing root compile medians
increased 1.3% and 2.3% across the two corpus sizes; p95 increased at most 2.4%.
Root worker RSS increased 0.13–0.16%, API import medians about 4.6–5.1%
(0.11–0.13 ms), and construction about 0.6%. The macOS wheel grew 1.6%, from
3,217,858 to 3,270,634 bytes; worker bytes grew 1.8%. No measured established
workload exceeded the existing 10% median-latency / 20% RSS regression gates.
This does not prove universal non-regression.

## Validation

- 56 Rust tests, strict Clippy and formatting pass.
- 343 Python tests plus 39 subtests pass; installed wheel/sdist repeat the suite.
  Both protobuf 6.33.5 and 7.36.2 were exercised on Python 3.14.7.
- 84 Node tests pass from source and the installed package, including `publishSpace`.
- Python and Node each complete 125 concurrent five-agent write/compile/review cycles.
- Python coverage gates pass: 92.37% statements, 85.44% branches overall;
  context wrapper 97.29% / 95%; digest 99.41% / 99%.
- Generated assets/clients, version checks, Ruff, strict mypy, archive inventories,
  Twine metadata and 18 distribution/source-binding tests (+19 subtests) pass.
- Network-denied wheel/sdist/npm consumers agree with Rust on 172 cases / 516
  comparisons. Each installed shared-view demo releases 50 reviewed answers and
  abstains on 50 missing reviews using one worker. Provider calls: zero.

One legacy Honey packaging test family fails to load the local SDK version identity;
the same error was reproduced on unchanged 0.12. It is not counted as passing.
The alpha uses the separately qualified local SDK distribution machinery.

RSS is maximum sampled aggregate worker resident memory, excluding Python/Node;
it is not peak allocation or PSS, and may count shared pages repeatedly. MB is
decimal. Latency summaries are medians of per-process quantiles; dependent calls
are not independent statistical samples. Construction excludes import/ingestion.

## Reproduction and remaining gates

Run `benchmarks/shared_views.py` with installed baseline/candidate Python paths,
`--cohorts 8 --rounds 50 --documents 64 --output comparison.json`. The larger
corpus uses `--rounds 20 --documents 512`. The harness records runtime versions,
worker hashes, every cohort, answer outcomes, latency and RSS. On macOS, use
`sandbox-exec` with `(version 1)(allow default)(deny network*)` for offline enforcement.

The full local evidence directory is `CIGAR/releases/cigar-0.13.0-alpha.1`:
`REPORT.md`, raw comparison JSON, exact archives/hashes, installed qualification,
source manifests, coverage and the 0.12 differential results are retained there.

Views remain logical scopes in one trusted host/privacy domain. Keep root access,
scope definitions and review authority outside agents. Calls remain serialized.
There is no new broker, authenticated multi-tenant boundary, durable view recovery,
distributed scheduler or effect authority. Use fresh run domains/reviews after
restart. HUMIDOR retains scheduling/recovery; its Honey integration is unchanged.
Seven-platform and independent-builder qualification, a 12-agent long-running soak,
authenticated broker integration and durable handoff/effect testing are later gates.

See the [alpha contract](context-sdk-0.13.0-alpha.1-notes.md) and the Python/Node
READMEs for installation and the packaged five-agent example. No v0.13 package,
branch or tag has been published.
