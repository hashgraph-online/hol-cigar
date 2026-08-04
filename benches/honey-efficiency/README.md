# Honey efficiency baseline

This harness records the content-free SQLite v4 baseline used as the before side of the Honey
0.9.1 persistence comparison. It runs fixed generated `small`, `threshold`, and `hiero-shaped`
profiles. A separately authorized SQLite copy may also seed any profile; the source is authenticated,
copied to private scratch space, and never modified.

Run a generated smoke baseline into a new external owner-only directory:

```sh
python3 benches/honey-efficiency/honey_efficiency.py run \
  --profile small \
  --output /private/tmp/cigar-honey-v4-small-evidence
```

Verify the three create-new, read-only evidence files:

```sh
python3 benches/honey-efficiency/honey_efficiency.py verify \
  --output /private/tmp/cigar-honey-v4-small-evidence
```

To use a verified copy, add `--verified-copy /absolute/input.sqlite3` and
`--verified-copy-sha256 <lowercase-sha256>`. The evidence records only its kind, size, and digest.
The reports contain fixed IDs, counts, sizes, stage timings, digests, and outcomes. They contain no
repository content, prompts, tokens as text, credentials, arbitrary extensions, or private paths.
The workload never invokes `VACUUM` and never deletes live rows.

## 0.9.1 candidate qualification inputs

`qualification-fixtures.v1.json` freezes the generated small, boundary, and Hiero-shaped seeds and
digests, workload order, warmups, repetitions, serial and mixed-concurrency sizes, v5 retention and
capacity policy, and the macOS/APFS/AC-power conditions required for the candidate run. Its
Hiero-shaped cohort is five workflows by 20 requests; the storage campaign remains a separate 10,000
serial-mutation workload.

`packaging/honey/verified-copy-input.v1.json` is intentionally unbound and non-executable in the
repository. An owner may create an external bound descriptor only after the generated migration and
recovery gates pass. The descriptor admits hashes, byte length, source revision, and copy-receipt
digest only—never a private path or protected store name.

Validate all frozen inputs without mutation:

```sh
python3 scripts/release/honey_efficiency_contract.py check-authority
```

The strict candidate report schema is
`packaging/honey/schemas/honey-efficiency-reliability-qualification.v1.schema.json`. It records only
source/candidate/fixture/tool bindings, content-free metrics, per-workflow counts, closed gate
results, and the SHA-256 and byte length of a separately retained raw-observation attachment.

After the frozen installed cohort creates that owner-private raw attachment, produce the report in
a new owner-only directory. The producer rejects a dirty source tree, stale manifest/runtime hashes,
unsafe paths, weakened thresholds, incomplete cohorts, and an existing output:

```sh
python3 scripts/release/qualify_honey_efficiency.py \
  --raw-observations /private/tmp/honey-efficiency-raw-observations.json \
  --candidate-manifest /private/tmp/cigar-honey-candidate/honey-release-manifest.json \
  --installed-runtime /private/tmp/cigar-honey-installed/bin/cigar \
  --output /private/tmp/honey-efficiency-qualification
```

The Honey `qualify` and `verify` commands require the same raw attachment through
`--efficiency-raw-observations`. The summary report is an internal evidence-ledger input; neither it
nor the raw attachment is added to the 13-file public release.
