# Five-minute local quickstart

Use the installed binary archive, not a workspace build, for acceptance testing. The quickstart is
offline and uses an embedded local store; it does not start a listener or contact a model provider.

<!-- docs-check: command quickstart-version-help -->
```sh
cigar --output json version
cigar help
```

Create an empty project in a path containing spaces and Unicode, then initialize it.

<!-- docs-check: command quickstart-init -->
```sh
mkdir "CIGAR demo – café"
cd "CIGAR demo – café"
cigar --embedded --yes init
```

The installed-candidate documentation gate verifies the published Honey demo archive and runtime
against independently supplied SHA-256 values, then runs the packaged offline-context story twice
in fresh temporary projects under the macOS no-egress boundary. The story exercises the same public
surface shown below: governed source registration, ingestion, bounded context compilation,
explanation, and observational replay. A source-tree build or a zero-exit placeholder is not accepted
as evidence for this block.

<!-- docs-check: command quickstart-source-compile -->
```sh
cigar source add . --yes
cigar --embedded ingest --input ingest.json --yes
cigar --embedded context compile --input compile.json --yes
cigar --embedded context explain bundle-id
cigar --embedded replay run --input replay.json --yes
```

Expected machine output is one versioned JSON object per command on stdout. Human progress is sent
only to interactive stderr. Re-run `doctor --deep` after the flow; any failed integrity check is a
stop condition.
