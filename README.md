# CIGAR

CIGAR is the Composable Intelligence Graph Agent Runtime. This repository is under active implementation against [`prd.md`](prd.md); durable packet status is recorded in [`IMPLEMENTATION_STATUS.md`](IMPLEMENTATION_STATUS.md).

## Bootstrap

Install the exact tool versions in `support.toml`, then run:

```sh
cargo xtask bootstrap
cargo xtask test unit
```

The bootstrap command validates tools and generated artifacts but never installs software.

